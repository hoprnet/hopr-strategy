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
        poll_until,
    },
    task::StrategyTask,
};
use rstest::rstest;

/// One top-up, at the harness's default economics (ticket price 1 wxHOPR,
/// win_prob 1.0, assumed_hops 3): 1 packet of capacity = 3 wxHOPR.
const TOPUP: &str = "3 wxHOPR";

/// Payload bytes per packet for the test transport, as
/// `PacketTransport::packet_payload_size()` reports it.
///
/// Capacity is rounded *up* to whole packets (`div_ceil`), so every `ByteSize`
/// from 1 byte to a full packet resolves to the same 3 wxHOPR — the multiple has
/// to be spelled out in packets for a threshold to be more than one top-up wide.
const PACKET: u64 = 1036;

/// Ticks fast enough that several passes fit inside the action timeout.
const TICK: Duration = Duration::from_millis(100);

/// Lease long enough to satisfy the knob's contract in this harness: it must
/// exceed the time an operation legitimately takes to report back, which here is
/// the simulated confirmation plus the connector's own view catching up (about a
/// second).  Undersize it and the lease reclaims slots from operations that are
/// still running, which shows up as duplicate transactions rather than as the
/// stalls these tests are about.
const LEASE: Duration = Duration::from_secs(2);

/// Chain reads against the in-memory harness resolve in microseconds, so any
/// read that has not answered within a couple of ticks is one this test made
/// hang on purpose.
const READ_BUDGET: Duration = Duration::from_millis(200);

/// Config for a single channel that stays below the funding threshold across
/// several top-ups: the threshold is 4 packets (12 wxHOPR) and each top-up adds
/// 1 packet (3 wxHOPR), so a channel starting at 1 wxHOPR is still under it at
/// 4, 7 and 10 wxHOPR.  Any "did it fund again?" assertion is therefore about
/// the strategy's willingness to act, never about the channel having become
/// healthy.
fn perpetually_underfunded_config(lease: Duration) -> ChannelLifecycleConfig {
    let mut cfg = ChannelLifecycleConfig {
        tick_interval: TICK,
        jitter: Duration::ZERO,
        ..Default::default()
    };
    cfg.population.min_open_channels = 1;
    cfg.population.target_open_channels = 1;
    cfg.funding.lower_capacity_threshold = ByteSize::b(PACKET * 4); // 12 wxHOPR
    cfg.funding.topup_capacity = ByteSize::b(1); // 1 packet → 3 wxHOPR per top-up
    cfg.funding.min_safe_capacity_required = ByteSize::b(0);
    cfg.proactive_funding.enabled = false;
    cfg.finalizer.enabled = false;
    cfg.concurrency.action_lease_timeout = lease;
    cfg.concurrency.chain_read_timeout = READ_BUDGET;
    cfg
}

/// Config that makes the strategy retire its only channel through the full
/// two-step closure.
///
/// The channel's stake sits below `close_when_drained_below`, so the close pass
/// selects it on the first tick without needing any probing history, and the
/// finalize pass follows the moment the notice period is up
/// (`max_closure_overdue = 0`).  Funding is switched off — an unaffordable safe
/// floor with `stop_when_unfunded` — so the fund pass cannot take the channel's
/// in-flight slot ahead of the close pass.
fn retire_channel_config(lease: Duration) -> ChannelLifecycleConfig {
    let mut cfg = ChannelLifecycleConfig {
        tick_interval: TICK,
        jitter: Duration::ZERO,
        ..Default::default()
    };
    // Nothing to keep open and nothing to open: only close and finalize run.
    cfg.population.min_open_channels = 0;
    cfg.population.target_open_channels = 0;
    cfg.restart.startup_close_grace_period = Duration::ZERO;
    cfg.closure.close_when_drained_below = "2 wxHOPR".parse().expect("valid balance");
    cfg.funding.stop_when_unfunded = true;
    cfg.funding.min_safe_capacity_required = ByteSize::b(u64::MAX);
    cfg.proactive_funding.enabled = false;
    cfg.finalizer.enabled = true;
    cfg.finalizer.max_closure_overdue = Duration::ZERO;
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

/// Releasing a channel's funding slot as soon as its confirmation resolves must
/// not fund the channel twice.
///
/// A confirmation lags the state it confirms, so once it resolves the new
/// balance is already readable and the next fund pass sizes against it.  This is
/// the risk that comes with not waiting for `ChannelBalanceIncreased`, so the
/// event is withheld for the whole test: the slot can only have been released by
/// the confirmation, and the channel — now at its threshold — must be left
/// alone from then on.
#[rstest]
#[test_log::test(tokio::test)]
async fn funding_stops_once_the_channel_is_funded_without_any_event(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, destination] = fixture.claim_accounts::<2>();
    let scenario = fixture
        .open_channel_scenario(&source, &destination, ScenarioOpts::new("1 wxHOPR".parse()?)?)
        .await?;
    let initial = scenario.initial.balance;
    let topup: HoprBalance = TOPUP.parse()?;

    scenario.connector.faults().withhold_event(EventKind::BalanceIncreased);

    // A threshold one top-up wide: 1 wxHOPR is under it, 1 + 3 wxHOPR is over.
    let mut cfg = perpetually_underfunded_config(LEASE);
    cfg.funding.lower_capacity_threshold = ByteSize::b(1); // 1 packet → 3 wxHOPR

    let node = Arc::new(LifecycleNode::new(scenario.connector.clone()));
    let mut strategy = ChannelLifecycleStrategy::new(cfg).build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.action,
        "channel topped up once",
        move |channel| channel.balance >= initial + topup,
    )
    .await?;

    // Watched for well beyond the point where the slot is released, so what
    // stops the strategy funding again can only be that it read the new balance.
    assert_channel_never(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.stable,
        "a funded channel must not be topped up again",
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

/// The full two-step closure, driven end to end by the strategy, with both of
/// its chain events withheld.
///
/// Closing a channel is two on-chain transactions, not one (RFC-0001 §3.1):
/// `close()` on an `Open` channel moves it to `PendingToClose` and starts the
/// notice period during which the destination can still redeem outstanding
/// tickets; only after that period has elapsed does a second `close()` move it
/// to `Closed` and release the stake.  The strategy issues the first from its
/// close pass and the second from its finalize pass, so each step takes — and
/// must give back — an in-flight slot.  With `ChannelClosureInitiated` and
/// `ChannelClosed` both lost, the slots can only be released by the operations'
/// own confirmations.
#[rstest]
#[test_log::test(tokio::test)]
async fn channel_closure_completes_both_steps_when_events_are_lost(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, destination] = fixture.claim_accounts::<2>();
    let scenario = fixture
        .open_channel_scenario(&source, &destination, ScenarioOpts::new("1 wxHOPR".parse()?)?)
        .await?;

    let faults = scenario.connector.faults();
    faults.withhold_event(EventKind::ClosureInitiated);
    faults.withhold_event(EventKind::Closed);

    let node = Arc::new(LifecycleNode::new(scenario.connector.clone()));
    let mut strategy = ChannelLifecycleStrategy::new(retire_channel_config(LEASE)).build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    // Step 1: the close pass initiates closure and the notice period starts.
    await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.action,
        "closure initiated by the close pass",
        |channel| matches!(channel.status, ChannelStatus::PendingToClose(_)),
    )
    .await?;

    // Step 2: once the notice period has elapsed, the finalize pass closes it.
    await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.action,
        "closure finalized by the finalize pass",
        |channel| channel.status == ChannelStatus::Closed,
    )
    .await?;

    assert!(!handle.is_finished(), "channel-lifecycle strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// A stalled *submission* on the second step of the closure.  The call never
/// returns, so no transaction is sent: the channel is stuck `PendingToClose`
/// with its finalize slot held by a parked task, and its stake stays locked
/// on-chain until the slot is reclaimed and the step retried.
#[rstest]
#[test_log::test(tokio::test)]
async fn finalization_resumes_after_the_second_close_stalls(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, destination] = fixture.claim_accounts::<2>();
    let scenario = fixture
        .open_channel_scenario(&source, &destination, ScenarioOpts::new("1 wxHOPR".parse()?)?)
        .await?;

    let faults = scenario.connector.faults();
    let node = Arc::new(LifecycleNode::new(scenario.connector.clone()));
    let mut strategy = ChannelLifecycleStrategy::new(retire_channel_config(LEASE)).build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    // Step 1 runs normally, leaving the channel in its notice period.
    await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.action,
        "closure initiated by the close pass",
        |channel| matches!(channel.status, ChannelStatus::PendingToClose(_)),
    )
    .await?;

    // Step 2 is made to stall before the notice period can elapse.
    faults.set(ChainOp::CloseChannel, Fault::Hang);
    faults.withhold_event(EventKind::Closed);

    // Wait for the finalize pass to actually attempt the second close — the
    // first call was step 1 — so the stall is exercised rather than skipped.
    poll_until("second close attempted and stalled", timeouts.action, TICK, || async {
        Ok((faults.calls(ChainOp::CloseChannel) >= 2).then_some(()))
    })
    .await?;

    // That attempt now holds the finalize slot with no way to report back.
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
///
/// The threshold is one top-up wide so that a channel drops out of the fund pass
/// once it has been topped up.  That keeps the test on the budget question: with
/// a wider threshold the stalled channels stay candidates and keep winning the
/// budget ahead of the third, which is fund-pass fairness — a separate concern.
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
    cfg.funding.lower_capacity_threshold = ByteSize::b(1); // 1 packet → 3 wxHOPR
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
