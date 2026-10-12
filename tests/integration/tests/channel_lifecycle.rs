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

    // Funding is expressed as data capacity (hoprnet #8243). With the harness's
    // default economics (ticket price 1 wxHOPR, win_prob 1.0, assumed_hops 3) one
    // face value is 3 wxHOPR, and `ByteSize::b(1)` = 1 packet floors at the path
    // selector's first-edge requirement: `MIN_BALANCE_HEADROOM (2) × face value`
    // = 6 wxHOPR (hopr-strategy#86), not one face value, so a funded channel is
    // actually selectable.
    let topup: HoprBalance = "6 wxHOPR".parse()?; // = resolve(topup_capacity = ByteSize::b(1))
    let mut cfg = ChannelLifecycleConfig {
        tick_interval: Duration::from_secs(3600),
        jitter: Duration::ZERO,
        ..Default::default()
    };
    cfg.population.min_open_channels = 1;
    cfg.population.target_open_channels = 1;
    cfg.funding.lower_capacity_threshold = ByteSize::b(1); // ~6 wxHOPR floor; channel at 1 wxHOPR is below → tops up
    cfg.funding.topup_capacity = ByteSize::b(1); // adds ~6 wxHOPR (2 × face value)
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
    assert_eq!(funded.balance, initial_balance + topup);
    assert!(!handle.is_finished(), "channel-lifecycle strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// Consolidation caps an under-funded channel at exactly one face value: it does
/// not pour the whole affordable safe, or the configured `topup_capacity`, into
/// it, that would strand the other channels a real node is trying to keep usable.
///
/// Economics (ticket price 1 wxHOPR, win_prob 1.0, hops 3): one face value is
/// 3 wxHOPR. `topup_capacity = ByteSize::b(1037)` = 2 packets resolves to 6 wxHOPR,
/// and the safe holds 5 wxHOPR, both well above the 2 wxHOPR gap to face value,
/// yet the channel must gain exactly that 2 wxHOPR gap, reaching 3 wxHOPR and no more.
#[rstest]
#[test_log::test(tokio::test)]
async fn consolidation_caps_an_underfunded_channel_at_one_face_value(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, destination] = fixture.claim_accounts::<2>();

    let scenario = fixture
        .open_channel_scenario(
            &source,
            &destination,
            ScenarioOpts {
                source_funding: "5 wxHOPR".parse()?,
                destination_funding: "5 wxHOPR".parse()?,
                ..ScenarioOpts::new("1 wxHOPR".parse()?)?
            },
        )
        .await?;
    let face_value: HoprBalance = "3 wxHOPR".parse()?;

    let mut cfg = ChannelLifecycleConfig {
        tick_interval: Duration::from_secs(3600),
        jitter: Duration::ZERO,
        ..Default::default()
    };
    cfg.population.min_open_channels = 1;
    cfg.population.target_open_channels = 1;
    cfg.funding.lower_capacity_threshold = ByteSize::b(1); // ~3 wxHOPR
    cfg.funding.topup_capacity = ByteSize::b(1037); // 2 packets → 6 wxHOPR, deliberately above face value
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
        "channel lifted to one face value by consolidation",
        move |channel| channel.balance >= face_value,
    )
    .await?;
    assert_eq!(
        funded.balance, face_value,
        "channel must reach exactly one 3 wxHOPR face value, not the 6 wxHOPR top-up the safe could cover"
    );
    assert!(!handle.is_finished(), "channel-lifecycle strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// Thrash guard: when the safe cannot even close the gap to one face value, the
/// channel is left untouched rather than funded part-way (which would issue no
/// ticket) or closed and reopened in a loop. The channel holds 1 wxHOPR and needs
/// 2 more to reach face value; the safe holds only 1 wxHOPR, so consolidation
/// cannot make it usable and leaves it alone.
#[rstest]
#[test_log::test(tokio::test)]
async fn leaves_channel_untouched_when_the_safe_cannot_reach_face_value(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, destination] = fixture.claim_accounts::<2>();

    // Safe funded with just 1 wxHOPR, short of the 2 wxHOPR gap from the channel's
    // 1 wxHOPR stake up to one face value (3 wxHOPR).
    let scenario = fixture
        .open_channel_scenario(
            &source,
            &destination,
            ScenarioOpts {
                source_funding: "1 wxHOPR".parse()?,
                destination_funding: "1 wxHOPR".parse()?,
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
    cfg.proactive_funding.enabled = false;
    cfg.finalizer.enabled = false;

    let node = Arc::new(LifecycleNode::new(scenario.connector.clone()));
    let mut strategy = ChannelLifecycleStrategy::new(cfg).build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    // The channel must never change: not funded part-way, not closed and reopened.
    assert_channel_never(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.stable,
        "a safe too small to reach face value must leave the channel untouched",
        move |channel| channel.balance != initial_balance,
    )
    .await?;
    assert!(!handle.is_finished(), "channel-lifecycle strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}
