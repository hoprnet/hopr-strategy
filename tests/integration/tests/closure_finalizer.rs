use std::{str::FromStr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use hopr_api::{
    chain::ChainReadChannelOperations,
    types::{crypto::prelude::Keypair, internal::prelude::ChannelStatus, primitive::prelude::Address},
};
use hopr_strategy::channel_finalizer::{ClosureFinalizerStrategy, ClosureFinalizerStrategyConfig};
use rstest::rstest;

use hopr_strategy_integration_tests::{
    constants::{SAFE_ALLOWANCE, SAFE_FUNDING},
    fixtures::{IntegrationFixture, integration_fixture as fixture, poll_until},
    strategy_node::{ChainNode, connect_node, node_chain_keypair},
    task::StrategyTask,
};

#[rstest]
#[test_log::test(tokio::test)]
async fn closes_elapsed_channel(#[future(awt)] fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, destination] = fixture.claim_accounts::<2>();
    let source_safe = fixture
        .deploy_safe_and_announce(source, SAFE_FUNDING.parse()?)
        .await
        .context("failed to onboard channel source")?;
    fixture
        .deploy_safe_and_announce(destination, SAFE_FUNDING.parse()?)
        .await
        .context("failed to onboard channel destination")?;
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
    poll_until(
        "channel visible before closure",
        timeouts.visibility,
        Duration::from_millis(500),
        || {
            let connector = connector.clone();
            async move { Ok(connector.channel_by_parties(&source_addr, &destination_addr)?) }
        },
    )
    .await?;

    fixture
        .initiate_outgoing_channel_closure(source, destination, &source_safe.module_address)
        .await?;
    poll_until(
        "channel closure deadline elapsed",
        timeouts.action,
        Duration::from_millis(500),
        || {
            let connector = connector.clone();
            async move {
                Ok(connector
                    .channel_by_parties(&source_addr, &destination_addr)?
                    .filter(|channel| {
                        matches!(channel.status, ChannelStatus::PendingToClose(deadline) if deadline.elapsed().is_ok())
                    }))
            }
        },
    )
    .await?;

    let node = Arc::new(ChainNode(connector.clone()));
    let mut strategy = ClosureFinalizerStrategy::new(
        ClosureFinalizerStrategyConfig {
            max_closure_overdue: Duration::from_secs(3600),
        },
        Duration::from_secs(3600),
    )
    .build(node);
    let handle = StrategyTask::spawn(async move { strategy.run().await });

    poll_until(
        "channel finalized by strategy",
        timeouts.action,
        Duration::from_secs(1),
        || {
            let connector = connector.clone();
            async move {
                Ok(connector
                    .channel_by_parties(&source_addr, &destination_addr)?
                    .filter(|channel| channel.status == ChannelStatus::Closed))
            }
        },
    )
    .await?;
    assert!(!handle.is_finished(), "closure-finalizer strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}
