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

use hopr_strategy_integration_tests::{
    constants::{SAFE_ALLOWANCE, SAFE_FUNDING},
    fixtures::{IntegrationFixture, integration_fixture as fixture, poll_until},
    strategy_node::{ChainNode, connect_node, node_chain_keypair},
    task::StrategyTask,
};

#[rstest]
#[test_log::test(tokio::test)]
async fn tops_up_underfunded_channel(#[future(awt)] fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [src, dst] = fixture.claim_accounts::<2>();

    let safe = fixture
        .deploy_safe_and_announce(src, SAFE_FUNDING.parse().context("parse SAFE_FUNDING")?)
        .await
        .context("failed to onboard node safe")?;
    fixture
        .deploy_safe_and_announce(dst, SAFE_FUNDING.parse().context("parse SAFE_FUNDING")?)
        .await
        .context("failed to onboard node safe")?;
    fixture
        .approve(
            src,
            SAFE_ALLOWANCE.parse().context("parse SAFE_ALLOWANCE")?,
            &safe.module_address,
        )
        .await
        .context("failed to approve safe module allowance")?;

    let channel_stake = "1 wxHOPR".parse().context("parse channel stake")?;
    fixture
        .open_channel(src, dst, channel_stake, &safe.module_address, None)
        .await
        .context("failed to open channel")?;

    let module_address = Address::from_str(&safe.module_address).context("parse module address")?;
    let connector = connect_node(fixture.client().clone(), &src.secret_bytes(), module_address)
        .await
        .context("failed to connect node connector")?;
    let src_addr = node_chain_keypair(&src.secret_bytes())?.public().to_address();
    let dst_addr = node_chain_keypair(&dst.secret_bytes())?.public().to_address();

    let initial = poll_until(
        "channel visible to connector",
        timeouts.visibility,
        Duration::from_millis(500),
        || {
            let connector = connector.clone();
            async move { Ok(connector.channel_by_parties(&src_addr, &dst_addr)?) }
        },
    )
    .await
    .context("channel never became visible to the connector")?;
    let initial_balance = initial.balance;

    let min_stake_threshold = HoprBalance::new_base(5u32);
    let funding_amount = HoprBalance::new_base(5u32);
    assert!(initial_balance < min_stake_threshold);

    let node = Arc::new(ChainNode(connector.clone()));
    let mut strategy = AutoFundingStrategy::new(
        AutoFundingStrategyConfig {
            min_stake_threshold,
            funding_amount,
        },
        Duration::from_secs(60),
    )
    .build(node);
    let handle = StrategyTask::spawn(async move { strategy.run().await });

    let funded = poll_until(
        "channel funded by strategy",
        timeouts.action,
        Duration::from_secs(1),
        || {
            let connector = connector.clone();
            async move {
                let channel = connector.channel_by_parties(&src_addr, &dst_addr)?;
                Ok(channel.filter(|channel| channel.balance > initial_balance))
            }
        },
    )
    .await
    .context("strategy did not fund the channel within the timeout")?;

    assert_eq!(funded.balance, initial_balance + funding_amount);
    assert!(!handle.is_finished(), "auto-funding strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}
