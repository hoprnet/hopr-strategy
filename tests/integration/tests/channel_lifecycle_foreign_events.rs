//! Foreign chain events must not mutate the node's own per-peer state —
//! hoprnet/hopr-strategy#76.
//!
//! The strategy subscribes to every chain event in the network, not only events
//! for its own channels. `on_balance_decreased` filters for own outgoing
//! channels, but `on_channel_closed`, `on_channel_opened` and `on_ticket_redeemed`
//! did not, so another node's channel to a peer `D` could wipe `D`'s ticket
//! score, put `D` on the reopen cooldown, or free the node's pending-open slot
//! for `D`.
//!
//! The snapshot pipeline is already scoped to the node's own channels
//! (`stream_channels(..with_source(me))`), so the defect lives entirely in the
//! event-driven handlers. This reproduces the most damaging case end to end: a
//! foreign close to `D` must not block the node from opening its own channel to
//! `D`.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use bytesize::ByteSize;
use hopr_api::{
    chain::{ChainReadChannelOperations, ChainWriteChannelOperations},
    types::{
        internal::prelude::{ChannelBuilder, ChannelStatus},
        primitive::prelude::{Address, BytesRepresentable, HoprBalance, XDaiBalance},
    },
};
use hopr_strategy::{
    channel_lifecycle::{ChannelLifecycleConfig, ChannelLifecycleStrategy},
    testing::{
        BlokliTestStateBuilder, LifecycleNode, TestGraph, TestNetworkView, create_test_blokli_connector,
        register_test_safe,
    },
};
use hopr_strategy_integration_tests::{
    constants::{SAFE_ALLOWANCE, SAFE_FUNDING},
    fixtures::{IntegrationFixture, await_channel_where, integration_fixture as fixture},
    task::StrategyTask,
};
use rstest::rstest;

/// The Safe module every connector in this scenario is built against — arbitrary,
/// but shared by the client and both connectors so their payloads agree.
fn module_address() -> Address {
    Address::new(&[1u8; Address::SIZE])
}

/// Isolates the open pass: no existing channels to fund or close, the startup
/// guard disabled, and new channels funded with one packet of capacity. The
/// reopen cooldown is the knob under test, so the caller sets it.
fn reopen_config(cooldown: Duration) -> ChannelLifecycleConfig {
    let mut cfg = ChannelLifecycleConfig {
        tick_interval: Duration::from_millis(100),
        jitter: Duration::ZERO,
        ..Default::default()
    };
    cfg.population.min_open_channels = 0;
    // Room for the warmup peer (the synchronization barrier) and dest.
    cfg.population.target_open_channels = 2;
    cfg.population.peer_reopen_cooldown = cooldown;
    cfg.restart.startup_observation_period = Duration::ZERO;
    cfg.restart.startup_close_grace_period = Duration::ZERO;
    // A zero threshold never applies to an existing balance, and new channels are
    // funded through `initial_capacity`, read directly by the open pass.
    cfg.funding.lower_capacity_threshold = ByteSize::b(0);
    cfg.funding.initial_capacity = ByteSize::b(1); // ~3 wxHOPR
    cfg.proactive_funding.enabled = false;
    cfg.finalizer.enabled = false;
    cfg
}

/// A foreign channel's close must not start the reopen cooldown for its
/// destination, because that would block the node from opening its own channel to
/// a perfectly good peer.
#[rstest]
#[test_log::test(tokio::test)]
async fn foreign_channel_close_must_not_block_opening_to_that_peer(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [subject, foreign_src, dest, warmup] = fixture.claim_accounts::<4>();
    let dest_addr = dest.address;
    let warmup_addr = warmup.address;

    // Chain state: one foreign channel foreign_src -> dest, Open. The subject is
    // neither end of it and holds no channel of its own.
    let foreign_channel = ChannelBuilder::default()
        .between(foreign_src.address, dest.address)
        .balance("5 wxHOPR".parse::<HoprBalance>()?)
        .ticket_index(0u64)
        .status(ChannelStatus::Open)
        .epoch(0u32)
        .build()
        .context("failed to build foreign channel")?;

    let addresses = [&subject.address, &foreign_src.address, &dest.address, &warmup.address];
    let allowance: HoprBalance = SAFE_ALLOWANCE.parse()?;
    let client = BlokliTestStateBuilder::default()
        .with_generated_accounts(
            &addresses,
            true,
            XDaiBalance::new_base(1u32),
            SAFE_FUNDING.parse::<HoprBalance>()?,
        )
        .with_safe_allowances(addresses.iter().map(|a| (**a, allowance)))
        .with_channels([foreign_channel])
        .with_closure_grace_period(Duration::ZERO)
        .build_dynamic_client(module_address())
        // Sequential closure txs drive this test; the default simulated delay
        // would dominate it without exercising anything.
        .with_tx_simulation_delay(Duration::ZERO);

    // Two connectors over the same chain state: the subject under test, and the
    // foreign source that will close its channel. The subject's event
    // subscription carries the whole network's events, the foreign close included.
    let subject_connector = Arc::new(
        create_test_blokli_connector(&subject.keypair, client.clone(), module_address())
            .await
            .context("connect subject node")?,
    );
    register_test_safe(&subject_connector, subject.address)
        .await
        .context("register subject safe")?;

    let foreign_connector = create_test_blokli_connector(&foreign_src.keypair, client, module_address())
        .await
        .context("connect foreign source node")?;
    register_test_safe(&foreign_connector, foreign_src.address)
        .await
        .context("register foreign source safe")?;

    // Both candidate peers start ineligible (disconnected, no edge), so the open
    // pass can only pick one once the test makes it so. This decouples the foreign
    // close from the open under test: if it wrongly starts a cooldown, that
    // cooldown is already in place before dest ever becomes a candidate.
    let graph = TestGraph::new(&subject.address);
    let network = TestNetworkView::new();

    let node = Arc::new(LifecycleNode::with_views(
        subject_connector.clone(),
        graph.clone(),
        network.clone(),
    ));
    // Far longer than the action timeout: a wrongly started cooldown keeps the
    // open blocked for the whole test window rather than merely delaying it.
    let mut strategy = ChannelLifecycleStrategy::new(reopen_config(Duration::from_secs(60))).build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    // Let the strategy subscribe before the foreign close fires, so its event
    // stream actually carries the close (the broadcast only reaches live
    // subscribers).
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The foreign source closes foreign_src -> dest end to end: initiate, then
    // finalize.
    let channel_id = *foreign_connector
        .channel_by_parties(&foreign_src.address, &dest_addr)?
        .context("foreign channel not visible to its source")?
        .get_id();
    foreign_connector.close_channel(&channel_id).await?.await?; // Open -> PendingToClose
    foreign_connector.close_channel(&channel_id).await?.await?; // PendingToClose -> Closed

    // Once the subject's own view shows the foreign channel Closed, the same
    // background step has already enqueued ChannelClosed onto the strategy's event
    // stream.
    await_channel_where(
        &subject_connector,
        foreign_src.address,
        dest_addr,
        timeouts.action,
        "subject observed the foreign channel closed",
        |c| c.status == ChannelStatus::Closed,
    )
    .await?;

    // Behavioral barrier instead of a blind sleep: make a *different* peer
    // eligible and wait until the subject opens its own channel to it. The
    // strategy drains its event stream in FIFO order and interleaves it with
    // ticks, so completing a whole open-pass cycle (submit, confirm, observe
    // Open) guarantees the earlier-enqueued ChannelClosed has been dispatched —
    // and, under the old unfiltered code, has already started dest's cooldown.
    graph.set_edge(&warmup_addr, 1.0, Duration::from_secs(1));
    network.connect(&warmup_addr);
    await_channel_where(
        &subject_connector,
        subject.address,
        warmup_addr,
        timeouts.action,
        "subject opened its channel to the warmup peer",
        |c| c.status == ChannelStatus::Open,
    )
    .await?;

    // dest is now a healthy, connected candidate, and the population target still
    // leaves a deficit for it.
    graph.set_edge(&dest_addr, 1.0, Duration::from_secs(1));
    network.connect(&dest_addr);

    // The node must open its own channel to dest. The foreign close concerned a
    // channel the node has no part in, so it must not gate this open.
    await_channel_where(
        &subject_connector,
        subject.address,
        dest_addr,
        timeouts.action,
        "subject opened its own channel to the peer despite the foreign close",
        |c| c.status == ChannelStatus::Open,
    )
    .await?;

    anyhow::ensure!(!handle.is_finished(), "channel-lifecycle strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}
