use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use hopr_api::types::primitive::prelude::HoprBalance;
use hopr_strategy::{
    auto_funding::{AutoFundingStrategy, AutoFundingStrategyConfig},
    testing::ChainNode,
};
use hopr_strategy_integration_tests::{
    fixtures::{
        IntegrationFixture, ScenarioOpts, assert_channel_never, await_channel_where, integration_fixture as fixture,
    },
    task::StrategyTask,
};
use rstest::rstest;

/// Happy path: the periodic scan tops up an outgoing channel whose balance is
/// at or below `min_stake_threshold`, when the safe can afford the funding round.
#[rstest]
#[test_log::test(tokio::test)]
async fn tops_up_underfunded_channel(#[future(awt)] fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [src, dst] = fixture.claim_accounts::<2>();

    let scenario = fixture
        .open_channel_scenario(src, dst, ScenarioOpts::new("1 wxHOPR".parse()?)?)
        .await?;
    let initial_balance = scenario.initial.balance;

    let min_stake_threshold = HoprBalance::new_base(5u32);
    let funding_amount = HoprBalance::new_base(5u32);
    assert!(initial_balance < min_stake_threshold);

    let node = Arc::new(ChainNode(scenario.connector.clone()));
    let mut strategy = AutoFundingStrategy::new(
        AutoFundingStrategyConfig {
            min_stake_threshold,
            funding_amount,
        },
        Duration::from_secs(60),
    )
    .build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    let funded = await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.action,
        "channel funded by strategy",
        move |channel| channel.balance > initial_balance,
    )
    .await
    .context("strategy did not fund the channel within the timeout")?;

    assert_eq!(funded.balance, initial_balance + funding_amount);
    assert!(!handle.is_finished(), "auto-funding strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// Affordability gate: when the safe balance is below `funding_amount`, the
/// periodic scan must skip funding even though the channel is under threshold
/// (see [`on_tick`](hopr_strategy::auto_funding) early-return).
#[rstest]
#[test_log::test(tokio::test)]
async fn skips_funding_when_safe_below_funding_amount(#[future(awt)] fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [src, dst] = fixture.claim_accounts::<2>();

    // Fund each safe with barely more than the channel stake so that, once the
    // channel is opened, the safe cannot cover even a single funding round.
    let scenario = fixture
        .open_channel_scenario(
            src,
            dst,
            ScenarioOpts {
                source_funding: "2 wxHOPR".parse()?,
                destination_funding: "2 wxHOPR".parse()?,
                ..ScenarioOpts::new("1 wxHOPR".parse()?)?
            },
        )
        .await?;
    let initial_balance = scenario.initial.balance;

    // Threshold above the channel balance would normally trigger a top-up, but the
    // remaining safe budget (< 2 wxHOPR) cannot cover the 5 wxHOPR funding amount.
    let min_stake_threshold = HoprBalance::new_base(5u32);
    let funding_amount = HoprBalance::new_base(5u32);
    assert!(initial_balance < min_stake_threshold);

    let node = Arc::new(ChainNode(scenario.connector.clone()));
    let mut strategy = AutoFundingStrategy::new(
        AutoFundingStrategyConfig {
            min_stake_threshold,
            funding_amount,
        },
        Duration::from_secs(3600),
    )
    .build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    // The channel balance must never increase within the observation window.
    assert_channel_never(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.stable,
        "underfunded safe must not fund channel",
        move |channel| channel.balance > initial_balance,
    )
    .await?;

    assert!(!handle.is_finished(), "auto-funding strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}
