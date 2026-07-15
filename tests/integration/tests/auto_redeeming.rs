use std::{str::FromStr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use blokli_client::api::BlokliQueryClient;
use hopr_api::{
    chain::ChainReadChannelOperations,
    types::{
        crypto::prelude::{HalfKey, Hash, Keypair, Response},
        internal::prelude::{TicketBuilder, WinningProbability},
        primitive::prelude::{Address, HoprBalance},
    },
};
use hopr_strategy::auto_redeeming::{AutoRedeemingStrategy, AutoRedeemingStrategyConfig};
use rstest::rstest;

use hopr_strategy_integration_tests::{
    constants::{SAFE_ALLOWANCE, SAFE_FUNDING},
    fixtures::{IntegrationFixture, integration_fixture as fixture, poll_until},
    strategy_node::{LiveTicketManager, TicketNode, connect_node, node_chain_keypair},
    task::StrategyTask,
};

#[rstest]
#[test_log::test(tokio::test)]
async fn redeems_queued_ticket(#[future(awt)] fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [issuer, redeemer] = fixture.claim_accounts::<2>();

    let issuer_safe = fixture
        .deploy_safe_and_announce(issuer, SAFE_FUNDING.parse()?)
        .await
        .context("failed to onboard ticket issuer")?;
    let redeemer_safe = fixture
        .deploy_safe_and_announce(redeemer, SAFE_FUNDING.parse()?)
        .await
        .context("failed to onboard ticket redeemer")?;
    fixture
        .approve(issuer, SAFE_ALLOWANCE.parse()?, &issuer_safe.module_address)
        .await
        .context("failed to approve issuer safe module")?;
    fixture
        .open_channel(
            issuer,
            redeemer,
            "10 wxHOPR".parse()?,
            &issuer_safe.module_address,
            None,
        )
        .await
        .context("failed to open ticket channel")?;

    let connector = connect_node(
        fixture.client().clone(),
        &redeemer.secret_bytes(),
        Address::from_str(&redeemer_safe.module_address)?,
    )
    .await?;
    let issuer_key = node_chain_keypair(&issuer.secret_bytes())?;
    let redeemer_key = node_chain_keypair(&redeemer.secret_bytes())?;
    let issuer_addr = issuer_key.public().to_address();
    let redeemer_addr = redeemer_key.public().to_address();
    let initial = poll_until(
        "incoming channel visible to redeemer",
        timeouts.visibility,
        Duration::from_millis(500),
        || {
            let connector = connector.clone();
            async move { Ok(connector.channel_by_parties(&issuer_addr, &redeemer_addr)?) }
        },
    )
    .await?;

    let channel_dst = fixture
        .client()
        .query_chain_info()
        .await?
        .channel_dst
        .context("missing channel domain separator")?;
    let channel_dst = Hash::from_str(&channel_dst)?;
    let issuer_half = HalfKey::try_from(issuer_key.secret().as_ref())?;
    let redeemer_half = HalfKey::try_from(redeemer_key.secret().as_ref())?;
    let response = Response::from_half_keys(&issuer_half, &redeemer_half)?;
    let ticket_amount: HoprBalance = "2 wxHOPR".parse()?;
    let ticket = TicketBuilder::default()
        .counterparty(redeemer_addr)
        .amount(ticket_amount.amount())
        .index(initial.ticket_index)
        .win_prob(WinningProbability::ALWAYS)
        .channel_epoch(initial.channel_epoch)
        .challenge(response.to_challenge()?)
        .build_signed(&issuer_key, &channel_dst)?
        .into_acknowledged(response)
        .into_redeemable(&redeemer_key, &channel_dst)?;

    let node = Arc::new(TicketNode::new(
        connector.clone(),
        LiveTicketManager::with_ticket(ticket),
    ));
    let mut strategy = AutoRedeemingStrategy::new(
        AutoRedeemingStrategyConfig {
            minimum_redeem_ticket_value: HoprBalance::zero(),
            redeem_on_winning: false,
            ..Default::default()
        },
        Duration::from_secs(3600),
    )
    .build(node);
    let handle = StrategyTask::spawn(async move { strategy.run().await });

    let redeemed = poll_until(
        "ticket redeemed by strategy",
        timeouts.action,
        Duration::from_secs(1),
        || {
            let connector = connector.clone();
            async move {
                let channel = connector.channel_by_parties(&issuer_addr, &redeemer_addr)?;
                Ok(channel.filter(|channel| channel.ticket_index > initial.ticket_index))
            }
        },
    )
    .await?;
    assert_eq!(redeemed.balance, initial.balance - ticket_amount);
    assert!(!handle.is_finished(), "auto-redeeming strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}
