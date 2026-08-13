//! Concurrency of the operations the channel-lifecycle strategy performs.
//!
//! The strategy submits chain writes from background tasks, so several are
//! normally outstanding at once.  How many is not a free variable: it is bounded
//! globally by `concurrency.max_concurrent_actions`, per pass by
//! `closure.close_max_concurrent` and `finalizer.finalize_max_concurrent`, and
//! per channel to one operation of a kind at a time.
//!
//! Both directions matter.  Too little concurrency and a node with many channels
//! converges a tick at a time; too much and it floods the chain with
//! transactions, or issues two for the same channel and pays twice.  These tests
//! assert the *simultaneity* rather than the eventual outcome, reading the
//! watermarks [`ChainFaults`] records between a transaction's submission and its
//! confirmation.  Confirmations are parked (`Fault::Hang`) so every operation the
//! strategy starts stays outstanding and the watermark is observable.

use std::{sync::Arc, time::Duration};

use anyhow::Result;
use bytesize::ByteSize;
use hopr_api::{chain::ChainReadChannelOperations, types::internal::prelude::ChannelStatus};
use hopr_strategy::{
    channel_lifecycle::{ChannelLifecycleConfig, ChannelLifecycleStrategy},
    testing::{ChainOp, EventKind, Fault, LifecycleNode},
};
use hopr_strategy_integration_tests::{
    fixtures::{IntegrationFixture, ScenarioOpts, integration_fixture as fixture, poll_until},
    task::StrategyTask,
};
use rstest::rstest;

const TICK: Duration = Duration::from_millis(100);

/// Long enough that no lease expires mid-test: reclaiming a slot would let a
/// second operation start for the same channel, which is a different behaviour
/// from the one under test here.
const LEASE: Duration = Duration::from_secs(3600);

const READ_BUDGET: Duration = Duration::from_millis(200);

/// Base config for a set of channels that all want funding at once.
fn all_channels_underfunded(action_budget: usize) -> ChannelLifecycleConfig {
    let mut cfg = ChannelLifecycleConfig {
        tick_interval: TICK,
        jitter: Duration::ZERO,
        ..Default::default()
    };
    cfg.funding.lower_capacity_threshold = ByteSize::b(1); // 1 packet → 3 wxHOPR
    cfg.funding.topup_capacity = ByteSize::b(1);
    cfg.funding.min_safe_capacity_required = ByteSize::b(0);
    cfg.proactive_funding.enabled = false;
    cfg.finalizer.enabled = false;
    cfg.concurrency.max_concurrent_actions = action_budget;
    cfg.concurrency.action_lease_timeout = LEASE;
    cfg.concurrency.chain_read_timeout = READ_BUDGET;
    cfg
}

/// Funding runs in parallel up to the action budget, and never beyond it.
///
/// Asserting only the upper bound would be satisfied by a strategy that funded
/// one channel at a time, so the same watermark pins the lower bound: with more
/// underfunded channels than the budget allows, the budget must be filled.
#[rstest]
#[test_log::test(tokio::test)]
async fn strategy_should_fill_the_action_budget_and_never_exceed_it(fixture: IntegrationFixture) -> Result<()> {
    const BUDGET: usize = 3;

    let timeouts = fixture.timeouts();
    let [source, d1, d2, d3, d4, d5] = fixture.claim_accounts::<6>();
    let destinations = [d1, d2, d3, d4, d5];
    let scenario = fixture
        .open_channels_scenario(&source, &destinations, "1 wxHOPR".parse()?)
        .await?;

    let faults = scenario.connector.faults();
    // Every funding stays outstanding, so the watermark reflects everything the
    // strategy started rather than what it managed to finish.
    faults.set_confirmation(ChainOp::FundChannel, Fault::Hang);
    faults.withhold_event(EventKind::BalanceIncreased);

    let mut cfg = all_channels_underfunded(BUDGET);
    cfg.population.min_open_channels = destinations.len();
    cfg.population.target_open_channels = destinations.len();

    let node = Arc::new(LifecycleNode::new(scenario.connector.clone()));
    let mut strategy = ChannelLifecycleStrategy::new(cfg).build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    // The budget is filled: five channels want funding, three may proceed.
    let observed = faults.clone();
    poll_until("action budget filled", timeouts.action, TICK, || {
        let faults = observed.clone();
        async move { Ok((faults.peak_in_flight(ChainOp::FundChannel) >= BUDGET).then_some(())) }
    })
    .await?;

    // Several more ticks pass with the budget saturated and two channels still
    // waiting; nothing may slip past the cap.
    tokio::time::sleep(TICK * 5).await;
    assert_eq!(
        faults.peak_in_flight(ChainOp::FundChannel),
        BUDGET,
        "fundings in flight at once must never exceed max_concurrent_actions"
    );
    assert_eq!(
        faults.peak_in_flight_total(),
        BUDGET,
        "chain writes of all kinds in flight at once must never exceed max_concurrent_actions"
    );
    assert_eq!(
        faults.calls(ChainOp::FundChannel),
        BUDGET,
        "no further funding transactions may be submitted while the budget is saturated"
    );

    anyhow::ensure!(!handle.is_finished(), "channel-lifecycle strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// One channel never has two funding transactions in flight at the same time,
/// however often the strategy re-evaluates it.
///
/// The channel stays under its threshold while the first funding is outstanding,
/// so every tick in that window sees a fundable channel; only the per-channel
/// slot stops it from paying twice for the same shortfall.
#[rstest]
#[test_log::test(tokio::test)]
async fn strategy_should_not_fund_a_channel_twice_while_a_funding_is_in_flight(
    fixture: IntegrationFixture,
) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, destination] = fixture.claim_accounts::<2>();
    let scenario = fixture
        .open_channel_scenario(&source, &destination, ScenarioOpts::new("1 wxHOPR".parse()?)?)
        .await?;

    let faults = scenario.connector.faults();
    faults.set_confirmation(ChainOp::FundChannel, Fault::Hang);
    faults.withhold_event(EventKind::BalanceIncreased);

    let mut cfg = all_channels_underfunded(4);
    cfg.population.min_open_channels = 1;
    cfg.population.target_open_channels = 1;
    // Ticks far faster than the operation it starts, so many of them fall inside
    // the window where the first funding is still outstanding.
    cfg.tick_interval = Duration::from_millis(10);

    let node = Arc::new(LifecycleNode::new(scenario.connector.clone()));
    let mut strategy = ChannelLifecycleStrategy::new(cfg).build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    // Wait for the transaction to be outstanding, not merely called: submission
    // takes the harness's simulated confirmation time, and asserting before it
    // completes would read a watermark of zero whatever the strategy did.
    let observed = faults.clone();
    poll_until("first funding in flight", timeouts.action, TICK, || {
        let faults = observed.clone();
        async move { Ok((faults.peak_in_flight(ChainOp::FundChannel) >= 1).then_some(())) }
    })
    .await?;

    // Dozens of ticks over this window, all seeing the same underfunded channel.
    tokio::time::sleep(TICK * 5).await;
    assert_eq!(
        faults.peak_in_flight(ChainOp::FundChannel),
        1,
        "a channel must not have two funding transactions in flight at once"
    );
    assert_eq!(
        faults.calls(ChainOp::FundChannel),
        1,
        "the shortfall must be funded once, not once per tick"
    );

    anyhow::ensure!(!handle.is_finished(), "channel-lifecycle strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// The close pass has its own cap on top of the global budget, so a node that
/// decides to retire many channels at once still initiates closures gradually.
#[rstest]
#[test_log::test(tokio::test)]
async fn strategy_should_respect_the_close_pass_cap_when_many_channels_are_closable(
    fixture: IntegrationFixture,
) -> Result<()> {
    const CLOSE_CAP: usize = 2;

    let timeouts = fixture.timeouts();
    let [source, d1, d2, d3, d4] = fixture.claim_accounts::<5>();
    let destinations = [d1, d2, d3, d4];
    let scenario = fixture
        .open_channels_scenario(&source, &destinations, "1 wxHOPR".parse()?)
        .await?;

    let faults = scenario.connector.faults();
    faults.set_confirmation(ChainOp::CloseChannel, Fault::Hang);
    faults.withhold_event(EventKind::ClosureInitiated);

    // Every channel is drained below the closure threshold, so all four are
    // close candidates from the first tick.
    let mut cfg = all_channels_underfunded(CLOSE_CAP * 4);
    cfg.population.min_open_channels = 0;
    cfg.population.target_open_channels = 0;
    cfg.restart.startup_close_grace_period = Duration::ZERO;
    cfg.closure.close_when_drained_below = "2 wxHOPR".parse().expect("valid balance");
    cfg.closure.close_max_concurrent = CLOSE_CAP;
    // Funding off, so the fund pass cannot take slots the close pass needs.
    cfg.funding.stop_when_unfunded = true;
    cfg.funding.min_safe_capacity_required = ByteSize::b(u64::MAX);

    let node = Arc::new(LifecycleNode::new(scenario.connector.clone()));
    let mut strategy = ChannelLifecycleStrategy::new(cfg).build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    let observed = faults.clone();
    poll_until("close pass cap filled", timeouts.action, TICK, || {
        let faults = observed.clone();
        async move { Ok((faults.peak_in_flight(ChainOp::CloseChannel) >= CLOSE_CAP).then_some(())) }
    })
    .await?;

    tokio::time::sleep(TICK * 5).await;
    assert_eq!(
        faults.peak_in_flight(ChainOp::CloseChannel),
        CLOSE_CAP,
        "closures in flight at once must never exceed close_max_concurrent"
    );

    // The cap limits the rate of closing, not which channels close: the ones
    // that did get through must have moved on to their notice period.
    let mut closing = 0;
    for destination in &scenario.destination_addrs {
        let channel = scenario
            .connector
            .channel_by_parties(&scenario.source_addr, destination)?;
        if channel.is_some_and(|channel| matches!(channel.status, ChannelStatus::PendingToClose(_))) {
            closing += 1;
        }
    }
    assert_eq!(
        closing, CLOSE_CAP,
        "exactly the channels that took a close slot may have entered their notice period"
    );

    anyhow::ensure!(!handle.is_finished(), "channel-lifecycle strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}
