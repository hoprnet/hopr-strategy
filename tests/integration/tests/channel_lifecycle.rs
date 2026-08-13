use std::{sync::Arc, time::Duration};

use anyhow::Result;
use bytesize::ByteSize;
use hopr_api::{chain::ChainValues, types::primitive::prelude::HoprBalance};
use hopr_strategy::{
    channel_lifecycle::{CapacitySizingMode, ChannelLifecycleConfig, ChannelLifecycleStrategy},
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

    // Size the capacity from the image's live ticket price. The in-memory
    // connector uses a 1 wxHOPR ticket, while bloklid-anvil may use a smaller
    // network minimum; a fixed one-packet capacity would then sit below the
    // existing 1 wxHOPR channel and never trigger the funding pass.
    let target: HoprBalance = "2 wxHOPR".parse()?;
    let packet_cost = scenario.connector.minimum_ticket_price().await?.amount().low_u128() * 3;
    anyhow::ensure!(packet_cost > 0, "bloklid-anvil returned a zero minimum ticket price");
    let packets = target.amount().low_u128().div_ceil(packet_cost);
    let capacity = ByteSize::b(u64::try_from(packets * 1036)?);
    let mut cfg = ChannelLifecycleConfig {
        tick_interval: Duration::from_secs(3600),
        jitter: Duration::ZERO,
        ..Default::default()
    };
    cfg.population.min_open_channels = 1;
    cfg.population.target_open_channels = 1;
    cfg.funding.sizing_mode = CapacitySizingMode::Deterministic;
    cfg.funding.lower_capacity_threshold = capacity;
    cfg.funding.topup_capacity = capacity;
    cfg.funding.min_safe_capacity_required = ByteSize::b(0); // no safe floor
    cfg.proactive_funding.enabled = false;
    cfg.finalizer.enabled = false;

    let node = Arc::new(LifecycleNode::new(scenario.connector.clone()));
    let mut strategy = ChannelLifecycleStrategy::new(cfg).build(node)?;
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
    // The production conversion intentionally passes through f64, so do not
    // assert the exact last wei derived above; require at least the requested
    // target increase instead.
    assert!(funded.balance >= initial_balance + target);
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
    cfg.funding.lower_capacity_threshold = ByteSize::b(1); // ~3 wxHOPR
    cfg.funding.topup_capacity = ByteSize::b(1); // ~3 wxHOPR
    // Require far more capacity than the safe can afford, and stop when unfunded.
    cfg.funding.min_safe_capacity_required = ByteSize::b(u64::MAX);
    cfg.funding.stop_when_unfunded = true;
    cfg.proactive_funding.enabled = false;
    cfg.finalizer.enabled = false;

    let node = Arc::new(LifecycleNode::new(scenario.connector.clone()));
    let mut strategy = ChannelLifecycleStrategy::new(cfg).build(node)?;
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
