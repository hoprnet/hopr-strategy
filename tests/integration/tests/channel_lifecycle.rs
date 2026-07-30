use std::{sync::Arc, time::Duration};

use anyhow::Result;
use bytesize::ByteSize;
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
async fn tops_up_underfunded_channel(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, destination] = fixture.claim_accounts::<2>();

    let scenario = fixture
        .open_channel_scenario(&source, &destination, ScenarioOpts::new("1 wxHOPR".parse()?)?)
        .await?;
    let initial_balance = scenario.initial.balance;

    // Funding is now expressed as data capacity (hoprnet #8243). With the harness's
    // default economics (ticket price 1 wxHOPR, win_prob 1.0, assumed_hops 3),
    // `ByteSize::b(1)` = 1 packet resolves to 3 wxHOPR — see `capacity_to_balance`.
    let topup: HoprBalance = "3 wxHOPR".parse()?; // = resolve(topup_capacity = ByteSize::b(1))
    let mut cfg = ChannelLifecycleConfig {
        tick_interval: Duration::from_secs(3600),
        jitter: Duration::ZERO,
        ..Default::default()
    };
    cfg.population.min_open_channels = 1;
    cfg.population.target_open_channels = 1;
    cfg.funding.lower_capacity_threshold = ByteSize::b(1); // ~3 wxHOPR; channel at 1 wxHOPR is below → tops up
    cfg.funding.topup_capacity = ByteSize::b(1); // adds ~3 wxHOPR
    cfg.funding.min_safe_capacity_required = ByteSize::b(0); // no safe floor
    cfg.proactive_funding.enabled = false;
    cfg.finalizer.enabled = false;

    let node = Arc::new(LifecycleNode::new(scenario.connector.clone()));
    let mut strategy = ChannelLifecycleStrategy::new(cfg).build(node);
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

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
async fn skips_funding_when_safe_below_required(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, destination] = fixture.claim_accounts::<2>();

    // Fund each safe with barely more than the channel stake so the remaining
    // balance sits below `min_safe_balance_required`.
    let scenario = fixture
        .open_channel_scenario(
            &source,
            &destination,
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
    cfg.funding.lower_capacity_threshold = ByteSize::b(1); // ~3 wxHOPR
    cfg.funding.topup_capacity = ByteSize::b(1); // ~3 wxHOPR
    // Require far more capacity than the safe can afford, and stop when unfunded.
    cfg.funding.min_safe_capacity_required = ByteSize::b(u64::MAX);
    cfg.funding.stop_when_unfunded = true;
    cfg.proactive_funding.enabled = false;
    cfg.finalizer.enabled = false;

    let node = Arc::new(LifecycleNode::new(scenario.connector.clone()));
    let mut strategy = ChannelLifecycleStrategy::new(cfg).build(node);
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

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
