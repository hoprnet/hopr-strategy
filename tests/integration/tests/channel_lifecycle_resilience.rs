//! Resilience of the channel-lifecycle strategy to failing on-chain interaction.
//!
//! Every chain interaction the strategy makes can fail, time out, or complete
//! without the strategy ever learning about it:
//!
//! * the chain-event broadcast is lossy — it overflows rather than blocking, so
//!   a slow consumer silently loses the notification that an operation landed;
//! * a submitted transaction's confirmation may never resolve;
//! * a read (safe balance, channel list, ticket economics) may error or hang.
//!
//! None of these may leave the strategy permanently unable to act.  The tests
//! below inject each failure through [`ChainFaults`] while the strategy is
//! running, then assert that the strategy still converges once the fault clears.

use std::{sync::Arc, time::Duration};

use anyhow::Result;
use bytesize::ByteSize;
use hopr_api::types::{internal::prelude::ChannelStatus, primitive::prelude::HoprBalance};
use hopr_strategy::{
    channel_lifecycle::{ChannelLifecycleConfig, ChannelLifecycleStrategy},
    testing::{ChainOp, EventKind, Fault, LifecycleNode},
};
use hopr_strategy_integration_tests::{
    fixtures::{
        IntegrationFixture, ScenarioOpts, assert_channel_never, await_channel_where, integration_fixture as fixture,
    },
    task::StrategyTask,
};
use rstest::rstest;

/// One top-up, at the harness's default economics (ticket price 1 wxHOPR,
/// win_prob 1.0, assumed_hops 3): `ByteSize::b(1)` = 1 packet = 3 wxHOPR.
const TOPUP: &str = "3 wxHOPR";

/// Ticks fast enough that several passes fit inside the action timeout.
const TICK: Duration = Duration::from_millis(100);

/// Long enough that a lease cannot expire between two consecutive ticks by
/// accident, short enough to keep the tests fast.
const LEASE: Duration = Duration::from_millis(600);

/// Chain reads against the in-memory harness resolve in microseconds, so any
/// read that has not answered within a couple of ticks is one this test made
/// hang on purpose.
const READ_BUDGET: Duration = Duration::from_millis(200);

/// Config for a single channel that stays below the funding threshold no matter
/// how often it is topped up: the threshold is four top-ups wide, so a channel
/// starting at 1 wxHOPR is still under it after two or three top-ups.  Any
/// "did it fund again?" assertion is therefore about the strategy's willingness
/// to act, never about the channel having become healthy.
fn perpetually_underfunded_config(lease: Duration) -> ChannelLifecycleConfig {
    let mut cfg = ChannelLifecycleConfig {
        tick_interval: TICK,
        jitter: Duration::ZERO,
        ..Default::default()
    };
    cfg.population.min_open_channels = 1;
    cfg.population.target_open_channels = 1;
    cfg.funding.lower_capacity_threshold = ByteSize::b(4); // ~12 wxHOPR
    cfg.funding.topup_capacity = ByteSize::b(1); // ~3 wxHOPR per top-up
    cfg.funding.min_safe_capacity_required = ByteSize::b(0);
    cfg.proactive_funding.enabled = false;
    cfg.finalizer.enabled = false;
    cfg.concurrency.action_lease_timeout = lease;
    cfg.concurrency.chain_read_timeout = READ_BUDGET;
    cfg
}

/// The reported failure: the first round of funding works, and then the channel
/// is never topped up again.
///
/// `ChannelBalanceIncreased` is what releases the channel's in-flight funding
/// slot.  The broadcast that carries it drops events when a subscriber falls
/// behind, so it cannot be the only thing that releases the slot — otherwise one
/// lost event disables funding for that channel for the lifetime of the process.
#[rstest]
#[test_log::test(tokio::test)]
async fn funding_resumes_after_balance_increased_event_is_lost(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, destination] = fixture.claim_accounts::<2>();
    let scenario = fixture
        .open_channel_scenario(&source, &destination, ScenarioOpts::new("1 wxHOPR".parse()?)?)
        .await?;
    let initial = scenario.initial.balance;
    let topup: HoprBalance = TOPUP.parse()?;

    // The chain still applies every funding tx; only the notification is lost.
    scenario.connector.faults().withhold_event(EventKind::BalanceIncreased);

    let node = Arc::new(LifecycleNode::new(scenario.connector.clone()));
    let mut strategy = ChannelLifecycleStrategy::new(perpetually_underfunded_config(LEASE)).build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.action,
        "channel topped up a second time despite the lost event",
        move |channel| channel.balance >= initial + topup + topup,
    )
    .await?;

    assert!(!handle.is_finished(), "channel-lifecycle strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// The counterpart of the test above: reclaiming a stalled slot must not turn
/// into a funding storm.  While the lease is live and no confirmation has come
/// back, the channel must be topped up exactly once.
#[rstest]
#[test_log::test(tokio::test)]
async fn funding_is_not_repeated_while_the_lease_is_live(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, destination] = fixture.claim_accounts::<2>();
    let scenario = fixture
        .open_channel_scenario(&source, &destination, ScenarioOpts::new("1 wxHOPR".parse()?)?)
        .await?;
    let initial = scenario.initial.balance;
    let topup: HoprBalance = TOPUP.parse()?;

    let faults = scenario.connector.faults();
    faults.withhold_event(EventKind::BalanceIncreased);
    // Submission succeeds and the tx lands, but the outcome never comes back.
    faults.set_confirmation(ChainOp::FundChannel, Fault::Hang);

    let node = Arc::new(LifecycleNode::new(scenario.connector.clone()));
    // A lease far longer than the observation window: nothing may expire here.
    let mut strategy =
        ChannelLifecycleStrategy::new(perpetually_underfunded_config(Duration::from_secs(3600))).build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    // Establish that funding happens at all, so the "never twice" assertion
    // below cannot pass merely because the strategy did nothing.
    await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.action,
        "channel topped up once",
        move |channel| channel.balance >= initial + topup,
    )
    .await?;

    assert_channel_never(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.stable,
        "channel must not be funded twice while its lease is live",
        move |channel| channel.balance > initial + topup,
    )
    .await?;

    assert!(!handle.is_finished(), "channel-lifecycle strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// A funding transaction whose confirmation never resolves must not hold the
/// channel's funding slot forever.  Unlike a lost event, here the strategy's own
/// task is parked indefinitely — with the event withheld as well, nothing but a
/// deadline can release the slot.
#[rstest]
#[test_log::test(tokio::test)]
async fn funding_resumes_after_funding_confirmation_never_resolves(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, destination] = fixture.claim_accounts::<2>();
    let scenario = fixture
        .open_channel_scenario(&source, &destination, ScenarioOpts::new("1 wxHOPR".parse()?)?)
        .await?;
    let initial = scenario.initial.balance;
    let topup: HoprBalance = TOPUP.parse()?;

    let faults = scenario.connector.faults();
    faults.set_confirmation(ChainOp::FundChannel, Fault::Hang);
    faults.withhold_event(EventKind::BalanceIncreased);

    let node = Arc::new(LifecycleNode::new(scenario.connector.clone()));
    let mut strategy = ChannelLifecycleStrategy::new(perpetually_underfunded_config(LEASE)).build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    // The first top-up lands on-chain even though its confirmation is parked.
    await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.action,
        "first top-up applied on-chain",
        move |channel| channel.balance >= initial + topup,
    )
    .await?;

    // Chain interaction recovers; the strategy must resume funding the channel.
    // The event stays withheld: recovery may not depend on it.
    faults.clear(ChainOp::FundChannel);

    await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.action,
        "funding resumed after the stalled confirmation",
        move |channel| channel.balance >= initial + topup + topup,
    )
    .await?;

    assert!(!handle.is_finished(), "channel-lifecycle strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// The same stalled-operation failure on the finalize path.  Here the *submission*
/// never returns, so the transaction is never sent: the channel stays
/// `PendingToClose` while its finalize slot is held forever.  Without a deadline
/// the stake stays locked on-chain for the lifetime of the process.
#[rstest]
#[test_log::test(tokio::test)]
async fn finalization_resumes_after_close_submission_never_resolves(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, destination] = fixture.claim_accounts::<2>();
    let scenario = fixture
        .open_channel_scenario(&source, &destination, ScenarioOpts::new("1 wxHOPR".parse()?)?)
        .await?;

    scenario.initiate_closure().await?;
    await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.action,
        "channel closure deadline elapsed",
        |channel| matches!(channel.status, ChannelStatus::PendingToClose(deadline) if deadline.elapsed().is_ok()),
    )
    .await?;

    let faults = scenario.connector.faults();
    // The finalize call never returns, so no tx is ever submitted: the channel
    // is left `PendingToClose` and its finalize slot is held by a parked task.
    faults.set(ChainOp::CloseChannel, Fault::Hang);
    faults.withhold_event(EventKind::Closed);

    let mut cfg = perpetually_underfunded_config(LEASE);
    cfg.population.min_open_channels = 0;
    cfg.population.target_open_channels = 0;
    cfg.finalizer.enabled = true;
    cfg.finalizer.max_closure_overdue = Duration::ZERO;

    let node = Arc::new(LifecycleNode::new(scenario.connector.clone()));
    let mut strategy = ChannelLifecycleStrategy::new(cfg).build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    // Wait out the first, stalled finalize attempt, then let the chain recover.
    tokio::time::sleep(LEASE).await;
    faults.clear(ChainOp::CloseChannel);

    await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.action,
        "finalization retried after the stalled submission",
        |channel| channel.status == ChannelStatus::Closed,
    )
    .await?;

    assert!(!handle.is_finished(), "channel-lifecycle strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// In-flight slots are budgeted globally (`concurrency.max_concurrent_actions`),
/// so slots that are never released do not merely stall their own channel: once
/// enough of them accumulate, the strategy stops acting on *every* channel.
///
/// Here the first `max_concurrent_actions` channels have their funding
/// confirmations parked forever; a further channel, equally underfunded, must
/// still be funded.
#[rstest]
#[test_log::test(tokio::test)]
async fn stalled_leases_do_not_block_unrelated_channels(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, d1, d2, d3] = fixture.claim_accounts::<4>();
    let destinations = [d1, d2, d3];
    let scenario = fixture
        .open_channels_scenario(&source, &destinations, "1 wxHOPR".parse()?)
        .await?;
    let initial = scenario.initial[0].balance;
    let topup: HoprBalance = TOPUP.parse()?;

    let faults = scenario.connector.faults();
    // Each attempt lands on-chain but reports nothing back: neither the parked
    // confirmation nor the withheld event can release the slot it took.
    faults.set_confirmation(ChainOp::FundChannel, Fault::Hang);
    faults.withhold_event(EventKind::BalanceIncreased);

    let mut cfg = perpetually_underfunded_config(LEASE);
    cfg.population.min_open_channels = destinations.len();
    cfg.population.target_open_channels = destinations.len();
    // Two channels are enough to exhaust the action budget and strand it.
    cfg.concurrency.max_concurrent_actions = 2;

    let node = Arc::new(LifecycleNode::new(scenario.connector.clone()));
    let mut strategy = ChannelLifecycleStrategy::new(cfg).build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    // Every channel must be topped up at least once, even though the first
    // attempts stranded the whole action budget.
    for destination_addr in &scenario.destination_addrs {
        await_channel_where(
            &scenario.connector,
            scenario.source_addr,
            *destination_addr,
            timeouts.action,
            "every channel funded despite stranded action slots",
            move |channel| channel.balance >= initial + topup,
        )
        .await?;
    }

    assert!(!handle.is_finished(), "channel-lifecycle strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// A read that never answers must not wedge the strategy.  The pipeline runs on
/// the same task as the event loop, so an unbounded read stalls ticks *and*
/// event handling: without a deadline the strategy never recovers, even after
/// the chain does.
#[rstest]
#[test_log::test(tokio::test)]
async fn pipeline_recovers_from_hanging_safe_balance_read(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, destination] = fixture.claim_accounts::<2>();
    let scenario = fixture
        .open_channel_scenario(&source, &destination, ScenarioOpts::new("1 wxHOPR".parse()?)?)
        .await?;
    let initial = scenario.initial.balance;
    let topup: HoprBalance = TOPUP.parse()?;

    let faults = scenario.connector.faults();
    faults.set(ChainOp::SafeInfo, Fault::Hang);

    let node = Arc::new(LifecycleNode::new(scenario.connector.clone()));
    let mut strategy = ChannelLifecycleStrategy::new(perpetually_underfunded_config(LEASE)).build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    // Give the strategy time to enter the hanging read, then let it recover.
    tokio::time::sleep(TICK * 3).await;
    faults.clear(ChainOp::SafeInfo);

    await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.action,
        "funding resumed after the hanging safe read cleared",
        move |channel| channel.balance >= initial + topup,
    )
    .await?;

    assert!(!handle.is_finished(), "channel-lifecycle strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// As above, for the channel list — the one read every pass depends on.
#[rstest]
#[test_log::test(tokio::test)]
async fn pipeline_recovers_from_hanging_channel_stream(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, destination] = fixture.claim_accounts::<2>();
    let scenario = fixture
        .open_channel_scenario(&source, &destination, ScenarioOpts::new("1 wxHOPR".parse()?)?)
        .await?;
    let initial = scenario.initial.balance;
    let topup: HoprBalance = TOPUP.parse()?;

    let faults = scenario.connector.faults();
    faults.set(ChainOp::StreamChannels, Fault::Hang);

    let node = Arc::new(LifecycleNode::new(scenario.connector.clone()));
    let mut strategy = ChannelLifecycleStrategy::new(perpetually_underfunded_config(LEASE)).build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    tokio::time::sleep(TICK * 3).await;
    faults.clear(ChainOp::StreamChannels);

    await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.action,
        "funding resumed after the hanging channel stream cleared",
        move |channel| channel.balance >= initial + topup,
    )
    .await?;

    assert!(!handle.is_finished(), "channel-lifecycle strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// Reads that fail outright (rather than hang) must also be survivable: the
/// strategy keeps ticking and resumes as soon as the chain answers again.
#[rstest]
#[test_log::test(tokio::test)]
async fn pipeline_recovers_from_failing_reads(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, destination] = fixture.claim_accounts::<2>();
    let scenario = fixture
        .open_channel_scenario(&source, &destination, ScenarioOpts::new("1 wxHOPR".parse()?)?)
        .await?;
    let initial = scenario.initial.balance;
    let topup: HoprBalance = TOPUP.parse()?;

    let faults = scenario.connector.faults();
    for op in [
        ChainOp::SafeInfo,
        ChainOp::Balance,
        ChainOp::TicketPrice,
        ChainOp::WinProb,
        ChainOp::ResolutionTime,
        ChainOp::StreamChannels,
        ChainOp::StreamAccounts,
    ] {
        faults.set(op, Fault::Fail);
    }

    let node = Arc::new(LifecycleNode::new(scenario.connector.clone()));
    let mut strategy = ChannelLifecycleStrategy::new(perpetually_underfunded_config(LEASE)).build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    tokio::time::sleep(TICK * 3).await;
    assert!(
        !handle.is_finished(),
        "strategy must survive a chain that fails every read"
    );

    for op in [
        ChainOp::SafeInfo,
        ChainOp::Balance,
        ChainOp::TicketPrice,
        ChainOp::WinProb,
        ChainOp::ResolutionTime,
        ChainOp::StreamChannels,
        ChainOp::StreamAccounts,
    ] {
        faults.clear(op);
    }

    await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.action,
        "funding resumed after failing reads cleared",
        move |channel| channel.balance >= initial + topup,
    )
    .await?;

    handle.stop().await;
    Ok(())
}
