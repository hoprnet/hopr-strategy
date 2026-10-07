//! Externally observable [`StrategyState`] of the channel-lifecycle strategy.

use std::sync::Arc;

use anyhow::{Result, ensure};
use hopr_strategy::{
    channel_lifecycle::{ChannelLifecycleConfig, ChannelLifecycleStrategy},
    strategy::StrategyState,
    testing::LifecycleNode,
};
use hopr_strategy_integration_tests::fixtures::{IntegrationFixture, integration_fixture as fixture};
use rstest::rstest;

/// `run` can exit with an error while subscribing to events, before the first
/// tick — the one exit that precedes the pipeline's own state updates. Since
/// `MultiStrategy` logs and swallows that error, the shared state cell is the
/// only failure signal an external observer sees, so it must read `Failed` and
/// not the initial `Running`. Regression guard: before the fix this returned
/// `Err` while leaving the state at `Running`.
#[rstest]
#[test_log::test(tokio::test)]
async fn channel_lifecycle_should_report_failed_when_event_subscription_fails(
    fixture: IntegrationFixture,
) -> Result<()> {
    let [source] = fixture.claim_accounts::<1>();

    // The chain state is irrelevant: `run` fails at subscription, before it reads
    // a single channel. A minimal node with a failing subscription is enough.
    let scenario = fixture.chain_with_channels(&source, &[], &[]).await?;
    let node = Arc::new(
        LifecycleNode::with_views(
            scenario.connector.clone(),
            scenario.graph.clone(),
            scenario.network.clone(),
        )
        .with_failing_subscription(),
    );

    let mut strategy = ChannelLifecycleStrategy::new(ChannelLifecycleConfig::default()).build(node)?;

    let result = strategy.run().await;

    ensure!(result.is_err(), "a failing subscription must surface as a run error");
    ensure!(
        strategy.state() == StrategyState::Failed,
        "a run that dies before its first tick must report Failed, got {:?}",
        strategy.state()
    );
    Ok(())
}
