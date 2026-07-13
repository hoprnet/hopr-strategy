//! Integration test: the Auto-Funding strategy tops up an under-funded channel
//! against a real Blokli-Anvil stack.
//!
//! Flow (mirrors the issue's proposed approach):
//! 1. Onboard a node on-chain (deploy Safe funded with wxHOPR, announce, approve).
//! 2. Open an outgoing channel whose stake is below the strategy threshold.
//! 3. Build the Auto-Funding strategy over a real connector targeting bloklid.
//! 4. Run the strategy and assert the channel gets funded on-chain.
//!
//! Requires docker + a pullable bloklid image; driven only via
//! `just test-integration` / the `#test-integration` nix app.

#![allow(dead_code)]

mod fixture;

use std::{str::FromStr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use hopr_api::{
    chain::ChainReadChannelOperations,
    types::{
        crypto::prelude::Keypair,
        primitive::prelude::{Address, HoprBalance},
    },
};
use hopr_strategy::auto_funding::{AutoFundingStrategy, AutoFundingStrategyConfig};
use rstest::rstest;
use serial_test::serial;

use crate::fixture::{
    fixtures::{IntegrationFixture, integration_fixture as fixture, poll_until},
    strategy_node::{ChainNode, connect_node, node_chain_keypair},
};

/// wxHOPR the node's Safe is funded with on deployment (ample for onboarding +
/// channel stake + several funding rounds).
const SAFE_FUNDING: &str = "100 wxHOPR";
/// Allowance granted to the Safe module towards the Channels contract.
const SAFE_ALLOWANCE: &str = "100 wxHOPR";

#[rstest]
#[test_log::test(tokio::test)]
#[serial]
async fn auto_funding_tops_up_underfunded_channel(#[future(awt)] fixture: IntegrationFixture) -> Result<()> {
    // `bob` is the strategy's node; `chris` is the channel counterparty.
    let [bob, chris] = fixture.sample_accounts::<2>();

    // ── 1. Onboard the nodes on-chain: deploy + register Safe, announce ──────────
    let safe = fixture
        .deploy_safe_and_announce(bob, SAFE_FUNDING.parse().context("parse SAFE_FUNDING")?)
        .await
        .context("failed to onboard node safe")?;

    fixture
        .deploy_safe_and_announce(chris, SAFE_FUNDING.parse().context("parse SAFE_FUNDING")?)
        .await
        .context("failed to onboard node safe")?;

    fixture
        .approve(
            bob,
            SAFE_ALLOWANCE.parse().context("parse SAFE_ALLOWANCE")?,
            &safe.module_address,
        )
        .await
        .context("failed to approve safe module allowance")?;

    // ── 2. Open an under-funded outgoing channel bob -> chris ───────────────────
    // Strategy threshold is 5 wxHOPR; open the channel at 1 wxHOPR so it is
    // immediately eligible for top-up.
    let channel_stake = "1 wxHOPR".parse().context("parse channel stake")?;
    fixture
        .open_channel(bob, chris, channel_stake, &safe.module_address, None)
        .await
        .context("failed to open channel")?;

    // ── 3. Build the strategy over a real connector for bob ─────────────────────
    let module_address = Address::from_str(&safe.module_address).context("parse module address")?;
    let connector = connect_node(fixture.client().clone(), &bob.secret_bytes(), module_address)
        .await
        .context("failed to connect node connector")?;

    let bob_addr = node_chain_keypair(&bob.secret_bytes())?.public().to_address();
    let chris_addr = node_chain_keypair(&chris.secret_bytes())?.public().to_address();

    // Wait for the connector's channel graph to reflect the freshly-opened channel
    // (bloklid indexing + SSE sync are asynchronous).
    let initial = poll_until(
        "channel visible to connector",
        Duration::from_secs(60),
        Duration::from_millis(500),
        || {
            let connector = connector.clone();
            async move { Ok(connector.channel_by_parties(&bob_addr, &chris_addr)?) }
        },
    )
    .await
    .context("channel never became visible to the connector")?;
    let initial_balance = initial.balance;

    let min_stake_threshold = HoprBalance::new_base(5u32);
    let funding_amount = HoprBalance::new_base(5u32);
    assert!(
        initial_balance < min_stake_threshold,
        "precondition: opened channel ({initial_balance}) must be below threshold ({min_stake_threshold})"
    );

    let cfg = AutoFundingStrategyConfig {
        min_stake_threshold,
        funding_amount,
    };
    let node = Arc::new(ChainNode(connector.clone()));
    let mut strategy = AutoFundingStrategy::new(cfg, Duration::from_secs(60)).build(node);

    // ── 4. Run the strategy; its startup tick scans + funds the channel ─────────
    let handle = tokio::spawn(async move {
        let _ = strategy.run().await;
    });

    // Assert the channel balance increased on-chain (strategy funded it).
    let funded = poll_until(
        "channel funded by strategy",
        Duration::from_secs(90),
        Duration::from_secs(1),
        || {
            let connector = connector.clone();
            async move {
                let ch = connector.channel_by_parties(&bob_addr, &chris_addr)?;
                Ok(ch.filter(|c| c.balance > initial_balance))
            }
        },
    )
    .await
    .context("strategy did not fund the channel within the timeout")?;

    assert!(
        funded.balance >= initial_balance + funding_amount,
        "expected channel balance to grow by at least {funding_amount} (was {initial_balance}, now {})",
        funded.balance
    );

    handle.abort();
    Ok(())
}
