//! Failed loopbacks starve every relay, so a channel-less node never opens one.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use bytesize::ByteSize;
use hopr_api::{
    chain::ChainReadChannelOperations,
    graph::{
        NetworkGraphWrite,
        traits::{EdgeObservableWrite, EdgeWeightType},
    },
    types::{internal::prelude::ChannelStatus, primitive::prelude::Address},
};
use hopr_network_graph::{ChannelGraph, DEFAULT_MIN_LOOPBACKS_FOR_RATE};
use hopr_strategy::{
    channel_lifecycle::{ChannelLifecycleConfig, ChannelLifecycleStrategy},
    testing::{LifecycleNode, test_offchain_key},
};
use hopr_strategy_integration_tests::{
    fixtures::{IntegrationFixture, RecoveryScenario, integration_fixture as fixture, poll_until},
    task::StrategyTask,
};
use rstest::rstest;

/// As many connected relays as the piz-palu-dev client saw when it stalled.
const RELAYS: usize = 7;

/// Healthy pings on every relay edge, plus a window of failed loopbacks if asked.
fn observe_relays(source: Address, relays: &[Address], loopbacks_failed: bool) -> ChannelGraph {
    let me = test_offchain_key(&source);
    let graph = ChannelGraph::new(me);
    for relay in relays {
        graph.upsert_edge(&me, &test_offchain_key(relay), |obs| {
            obs.record(EdgeWeightType::Connected(true));
            for _ in 0..5 {
                obs.record(EdgeWeightType::Immediate(Ok(Duration::from_millis(30))));
            }
            if loopbacks_failed {
                for _ in 0..DEFAULT_MIN_LOOPBACKS_FOR_RATE {
                    obs.record(EdgeWeightType::Intermediate(Err(())));
                }
            }
        });
    }
    graph
}

fn first_channel_config() -> ChannelLifecycleConfig {
    let mut cfg = ChannelLifecycleConfig {
        tick_interval: Duration::from_millis(50),
        jitter: Duration::ZERO,
        ..Default::default()
    };
    cfg.population.min_open_channels = 1;
    cfg.population.target_open_channels = 5;
    cfg.funding.initial_capacity = ByteSize::b(1); // ~3 wxHOPR
    cfg.proactive_funding.enabled = false;
    cfg.finalizer.enabled = false;
    cfg
}

/// Runs the strategy on a channel-less node and waits for any relay channel to open.
async fn first_channel_opens(fixture: &IntegrationFixture, loopbacks_failed: bool) -> Result<Address> {
    let [source] = fixture.claim_accounts::<1>();
    let relays = fixture.claim_accounts::<RELAYS>();
    let relay_addrs: Vec<Address> = relays.iter().map(|relay| relay.address).collect();

    let scenario: RecoveryScenario = fixture
        .chain_with_channels(&source, &[], &relays.iter().collect::<Vec<_>>())
        .await?;
    for relay in &relay_addrs {
        scenario.network.connect(relay);
    }
    let graph = observe_relays(source.address, &relay_addrs, loopbacks_failed);

    let node = Arc::new(LifecycleNode::with_views(
        scenario.connector.clone(),
        graph,
        scenario.network.clone(),
    ));
    let mut strategy = ChannelLifecycleStrategy::new(first_channel_config()).build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    let opened = poll_until(
        "first channel opened",
        fixture.timeouts().action,
        Duration::from_millis(100),
        || {
            let scenario_connector = scenario.connector.clone();
            let relay_addrs = relay_addrs.clone();
            async move {
                for relay in relay_addrs {
                    let channel = scenario_connector.channel_by_parties(&source.address, &relay)?;
                    if channel.is_some_and(|c| c.status == ChannelStatus::Open) {
                        return Ok(Some(relay));
                    }
                }
                Ok(None)
            }
        },
    )
    .await;

    handle.stop().await;
    opened
}

/// Control: with no loopback evidence the relays score as unmeasured and pass.
#[rstest]
#[test_log::test(tokio::test)]
async fn opens_first_channel_to_unprobed_relays(fixture: IntegrationFixture) -> Result<()> {
    first_channel_opens(&fixture, false).await?;
    Ok(())
}

/// Loopbacks that failed for lack of a channel must not block opening one.
#[rstest]
#[test_log::test(tokio::test)]
async fn opens_first_channel_although_every_loopback_failed(fixture: IntegrationFixture) -> Result<()> {
    first_channel_opens(&fixture, true)
        .await
        .context("failed loopbacks marked every relay starved")?;
    Ok(())
}
