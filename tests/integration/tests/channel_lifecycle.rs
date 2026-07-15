use std::{str::FromStr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use hopr_api::{
    chain::ChainReadChannelOperations,
    types::{
        crypto::prelude::Keypair,
        primitive::prelude::{Address, HoprBalance},
    },
};
use hopr_strategy::channel_lifecycle::{ChannelLifecycleConfig, ChannelLifecycleStrategy};
use rstest::rstest;

use hopr_strategy_integration_tests::{
    constants::{SAFE_ALLOWANCE, SAFE_FUNDING},
    fixtures::{IntegrationFixture, integration_fixture as fixture, poll_until},
    strategy_node::{LifecycleNode, connect_node, node_chain_keypair},
    task::StrategyTask,
};

#[rstest]
#[test_log::test(tokio::test)]
async fn tops_up_underfunded_channel(#[future(awt)] fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, destination] = fixture.claim_accounts::<2>();
    let source_safe = fixture
        .deploy_safe_and_announce(source, SAFE_FUNDING.parse()?)
        .await
        .context("failed to onboard lifecycle source")?;
    fixture
        .deploy_safe_and_announce(destination, SAFE_FUNDING.parse()?)
        .await
        .context("failed to onboard lifecycle destination")?;
    fixture
        .approve(source, SAFE_ALLOWANCE.parse()?, &source_safe.module_address)
        .await?;
    fixture
        .open_channel(
            source,
            destination,
            "1 wxHOPR".parse()?,
            &source_safe.module_address,
            None,
        )
        .await?;

    let connector = connect_node(
        fixture.client().clone(),
        &source.secret_bytes(),
        Address::from_str(&source_safe.module_address)?,
    )
    .await?;
    let source_addr = node_chain_keypair(&source.secret_bytes())?.public().to_address();
    let destination_addr = node_chain_keypair(&destination.secret_bytes())?.public().to_address();
    let initial = poll_until(
        "lifecycle channel visible",
        timeouts.visibility,
        Duration::from_millis(500),
        || {
            let connector = connector.clone();
            async move { Ok(connector.channel_by_parties(&source_addr, &destination_addr)?) }
        },
    )
    .await?;

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

    let node = Arc::new(LifecycleNode::new(connector.clone()));
    let mut strategy = ChannelLifecycleStrategy::new(cfg).build(node);
    let handle = StrategyTask::spawn(async move { strategy.run().await });
    let funded = poll_until(
        "channel funded by lifecycle strategy",
        timeouts.action,
        Duration::from_secs(1),
        || {
            let connector = connector.clone();
            async move {
                let channel = connector.channel_by_parties(&source_addr, &destination_addr)?;
                Ok(channel.filter(|channel| channel.balance > initial.balance))
            }
        },
    )
    .await?;
    assert_eq!(funded.balance, initial.balance + topup);
    assert!(!handle.is_finished(), "channel-lifecycle strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}
