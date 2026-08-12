use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::Result;
use hopr_api::types::internal::prelude::ChannelStatus;
use hopr_strategy::{
    channel_finalizer::{ClosureFinalizerStrategy, ClosureFinalizerStrategyConfig},
    testing::ChainNode,
};
use hopr_strategy_integration_tests::{
    fixtures::{
        IntegrationFixture, ScenarioOpts, assert_channel_never, await_channel_where, integration_fixture as fixture,
    },
    task::StrategyTask,
};
use rstest::rstest;

/// Happy path: the strategy finalizes an outgoing `PendingToClose` channel once
/// its closure deadline has elapsed and it is still within `max_closure_overdue`.
#[rstest]
#[test_log::test(tokio::test)]
async fn closes_elapsed_channel(#[future(awt)] fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, destination] = fixture.claim_accounts::<2>();
    let scenario = fixture
        .open_channel_scenario(source, destination, ScenarioOpts::new("1 wxHOPR".parse()?)?)
        .await?;

    fixture
        .initiate_outgoing_channel_closure(source, destination, &scenario.source_safe.module_address)
        .await?;
    await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.action,
        "channel closure deadline elapsed",
        |channel| matches!(channel.status, ChannelStatus::PendingToClose(deadline) if deadline.elapsed().is_ok()),
    )
    .await?;

    let node = Arc::new(ChainNode(scenario.connector.clone()));
    let mut strategy = ClosureFinalizerStrategy::new(
        ClosureFinalizerStrategyConfig {
            max_closure_overdue: Duration::from_secs(3600),
        },
        Duration::from_secs(3600),
    )
    .build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.action,
        "channel finalized by strategy",
        |channel| channel.status == ChannelStatus::Closed,
    )
    .await?;
    assert!(!handle.is_finished(), "closure-finalizer strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// Overdue cutoff: a channel whose closure became finalizable longer ago than
/// `max_closure_overdue` falls outside the selector's time window and must be
/// left untouched (external intervention assumed).
#[rstest]
#[test_log::test(tokio::test)]
async fn skips_channel_overdue_beyond_max(#[future(awt)] fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, destination] = fixture.claim_accounts::<2>();
    let scenario = fixture
        .open_channel_scenario(source, destination, ScenarioOpts::new("1 wxHOPR".parse()?)?)
        .await?;

    fixture
        .initiate_outgoing_channel_closure(source, destination, &scenario.source_safe.module_address)
        .await?;
    // Wait for the closure deadline to elapse.
    await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.action,
        "channel closure deadline elapsed",
        |channel| matches!(channel.status, ChannelStatus::PendingToClose(deadline) if deadline.elapsed().is_ok()),
    )
    .await?;

    // With a 1s overdue budget, sleep past it so the channel is now beyond the
    // finalizer's `[now - max_overdue, now]` window before the strategy starts.
    let max_closure_overdue = Duration::from_secs(1);
    tokio::time::sleep(Duration::from_secs(5)).await;

    let node = Arc::new(ChainNode(scenario.connector.clone()));
    let mut strategy = ClosureFinalizerStrategy::new(
        ClosureFinalizerStrategyConfig { max_closure_overdue },
        Duration::from_secs(3600),
    )
    .build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    // The overdue channel must never be finalized.
    assert_channel_never(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.stable,
        "overdue channel must not be finalized",
        |channel| channel.status == ChannelStatus::Closed,
    )
    .await?;
    assert!(!handle.is_finished(), "closure-finalizer strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// Future-deadline skip: a `PendingToClose` channel whose deadline has not yet
/// elapsed is not finalizable, so the strategy must leave it alone until the
/// deadline passes. The observation window is derived from the actual on-chain
/// deadline so the test stays robust to the chain's closure notice period.
#[rstest]
#[test_log::test(tokio::test)]
async fn skips_channel_with_pending_deadline(#[future(awt)] fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, destination] = fixture.claim_accounts::<2>();
    let scenario = fixture
        .open_channel_scenario(source, destination, ScenarioOpts::new("1 wxHOPR".parse()?)?)
        .await?;

    fixture
        .initiate_outgoing_channel_closure(source, destination, &scenario.source_safe.module_address)
        .await?;
    // Read the pending-close deadline so we can bound the observation window to
    // just before it elapses.
    let pending = await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.action,
        "channel pending to close",
        |channel| matches!(channel.status, ChannelStatus::PendingToClose(_)),
    )
    .await?;
    let ChannelStatus::PendingToClose(deadline) = pending.status else {
        anyhow::bail!("channel not in PendingToClose after initiating closure");
    };

    // If the chain's notice period is negligible, there is no future-deadline
    // window to observe — nothing meaningful to assert.
    let Ok(remaining) = deadline.duration_since(SystemTime::now()) else {
        tracing::warn!("closure deadline already elapsed; skipping future-deadline assertion");
        return Ok(());
    };
    let window = remaining.saturating_sub(Duration::from_secs(2));
    if window < Duration::from_secs(2) {
        tracing::warn!(
            ?remaining,
            "closure notice period too short; skipping future-deadline assertion"
        );
        return Ok(());
    }

    let node = Arc::new(ChainNode(scenario.connector.clone()));
    let mut strategy = ClosureFinalizerStrategy::new(
        ClosureFinalizerStrategyConfig {
            max_closure_overdue: Duration::from_secs(3600),
        },
        Duration::from_secs(1),
    )
    .build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    // Before the deadline elapses, the channel must stay PendingToClose.
    assert_channel_never(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        window,
        "channel with future deadline must not be finalized",
        |channel| channel.status == ChannelStatus::Closed,
    )
    .await?;
    assert!(!handle.is_finished(), "closure-finalizer strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}
