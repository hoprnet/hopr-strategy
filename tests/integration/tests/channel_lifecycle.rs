use std::{sync::Arc, time::Duration};

use anyhow::Result;
use hopr_api::types::primitive::prelude::HoprBalance;
use hopr_strategy::{
    channel_lifecycle::{ChannelLifecycleConfig, ChannelLifecycleStrategy},
    testing::LifecycleNode,
};
use hopr_strategy_integration_tests::{
    fixtures::{
        IntegrationFixture, ScenarioOpts, assert_channel_never, await_channel_where, integration_fixture as fixture,
    },
    task::StrategyTask,
};
use rstest::rstest;

/// Happy path: the reactive fund pass tops up a channel below
/// `funding.lower_balance_threshold` when the safe is funded (open/close passes
/// neutralised via target == min == 1, proactive + finalizer disabled).
#[rstest]
#[test_log::test(tokio::test)]
async fn tops_up_underfunded_channel(#[future(awt)] fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, destination] = fixture.claim_accounts::<2>();

    let scenario = fixture
        .open_channel_scenario(source, destination, ScenarioOpts::new("1 wxHOPR".parse()?)?)
        .await?;
    let initial_balance = scenario.initial.balance;

    let topup: HoprBalance = "5 wxHOPR".parse()?;
    let mut cfg = ChannelLifecycleConfig {
        tick_interval: Duration::from_secs(3600),
        jitter: Duration::ZERO,
        ..Default::default()
    };
    cfg.population.min_open_channels = 1;
    cfg.population.target_open_channels = 1;
    cfg.funding.lower_balance_threshold = "5 wxHOPR".parse()?;
    cfg.funding.topup_balance = topup;
    cfg.funding.min_safe_balance_required = topup;
    cfg.proactive_funding.enabled = false;
    cfg.finalizer.enabled = false;

    let node = Arc::new(LifecycleNode::new(scenario.connector.clone()));
    let mut strategy = ChannelLifecycleStrategy::new(cfg).build(node);
    let handle = StrategyTask::spawn(async move { strategy.run().await });

    let funded = await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.action,
        "channel funded by lifecycle strategy",
        move |channel| channel.balance > initial_balance,
    )
    .await?;
    assert_eq!(funded.balance, initial_balance + topup);
    assert!(!handle.is_finished(), "channel-lifecycle strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// Affordability gate: with `stop_when_unfunded = true` and a safe balance below
/// `min_safe_balance_required`, the whole fund pass is skipped — an underfunded
/// channel is left untouched.
#[rstest]
#[test_log::test(tokio::test)]
async fn skips_funding_when_safe_below_required(#[future(awt)] fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, destination] = fixture.claim_accounts::<2>();

    // Fund each safe with barely more than the channel stake so the remaining
    // balance sits below `min_safe_balance_required`.
    let scenario = fixture
        .open_channel_scenario(
            source,
            destination,
            ScenarioOpts {
                source_funding: "2 wxHOPR".parse()?,
                destination_funding: "2 wxHOPR".parse()?,
                ..ScenarioOpts::new("1 wxHOPR".parse()?)?
            },
        )
        .await?;
    let initial_balance = scenario.initial.balance;

    let mut cfg = ChannelLifecycleConfig {
        tick_interval: Duration::from_secs(3600),
        jitter: Duration::ZERO,
        ..Default::default()
    };
    // Keep population at the single existing channel so no open/close interferes.
    cfg.population.min_open_channels = 1;
    cfg.population.target_open_channels = 1;
    cfg.funding.lower_balance_threshold = "5 wxHOPR".parse()?;
    cfg.funding.topup_balance = "5 wxHOPR".parse()?;
    // Require far more than the safe can offer, and stop when unfunded.
    cfg.funding.min_safe_balance_required = "50 wxHOPR".parse()?;
    cfg.funding.stop_when_unfunded = true;
    cfg.proactive_funding.enabled = false;
    cfg.finalizer.enabled = false;

    let node = Arc::new(LifecycleNode::new(scenario.connector.clone()));
    let mut strategy = ChannelLifecycleStrategy::new(cfg).build(node);
    let handle = StrategyTask::spawn(async move { strategy.run().await });

    // The underfunded channel must never be topped up while the safe is short.
    assert_channel_never(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.stable,
        "underfunded safe must not fund channel",
        move |channel| channel.balance > initial_balance,
    )
    .await?;
    assert!(!handle.is_finished(), "channel-lifecycle strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}
