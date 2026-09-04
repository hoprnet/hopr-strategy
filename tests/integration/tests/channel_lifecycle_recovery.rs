//! Recovery of the channel-lifecycle strategy from deliberately unhealthy or
//! stale channels — hoprnet/hopr-strategy#44.
//!
//! Behaviours exercised:
//!
//! * on startup, closure is staged (see `RestartGuardConfig`): the strategy only observes for a short window, then
//!   retires channels to disconnected peers while still shielding connected ones, and only later applies the usual
//!   closure rules to everyone ([`observes_before_closing_on_startup`]);
//! * past that window, connectivity is itself a close trigger, independent of quality
//!   ([`force_closes_disconnected_channel_regardless_of_quality`]);
//! * a node holding an unusable channel — through poor quality or through being drained — closes it and opens a
//!   replacement to a healthy peer within a bounded time ([`recovers_from_unhealthy_channels`]);
//! * that steady-state recovery cycle fits inside a defaults-derived SLO ([`recovery_budget_on_defaults_meets_slo`]);
//! * a peer whose channel closed becomes reopenable again once healed ([`reopens_to_peer_whose_channel_was_closed`]).
//!
//! Every scenario-setup test follows the same shape: chain state, then quality,
//! then connectivity, each an explicit statement in the test body — see
//! [`hopr_strategy_integration_tests::fixtures::RecoveryScenario`] for why
//! neither is pre-wired by the scenario builder itself.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use bytesize::ByteSize;
use hopr_api::{
    chain::ChainReadChannelOperations,
    types::{internal::prelude::ChannelStatus, primitive::prelude::HoprBalance},
};
use hopr_strategy::{
    channel_lifecycle::{ChannelLifecycleConfig, ChannelLifecycleStrategy},
    testing::LifecycleNode,
};
use hopr_strategy_integration_tests::{
    fixtures::{IntegrationFixture, RecoveryScenario, await_channel_where, integration_fixture as fixture},
    task::StrategyTask,
};
use rstest::rstest;

/// One packet of capacity resolves to 3 wxHOPR under the harness's default
/// economics (ticket price 1 wxHOPR, win_prob 1.0, assumed_hops 3) — see
/// `capacity_to_balance` and the `TOPUP` constant in `channel_lifecycle_resilience.rs`.
const RECOVERED_BALANCE: &str = "3 wxHOPR";

/// True while `source -> peer` is `Open`, per the scenario's connector.
///
/// A single point-in-time read is enough to stand in for "never closed during
/// the window since this check": channel status only ever moves forward
/// (`Open` → `PendingToClose` → `Closed`) within one strategy run, so a peer
/// still `Open` at the end of a window was `Open` throughout it.
fn is_open(scenario: &RecoveryScenario, peer: hopr_api::types::primitive::prelude::Address) -> Result<bool> {
    Ok(matches!(
        scenario.connector.channel_by_parties(&scenario.source_addr, &peer)?,
        Some(c) if c.status == ChannelStatus::Open
    ))
}

/// A `ChannelLifecycleConfig` with funding, proactive funding and finalizer
/// pared down to isolate the close pass and the open pass under test: existing
/// channels are neither topped up nor finalized to `Closed`, and new ones are
/// funded with exactly one packet of capacity.
fn recovery_config(tick_interval: Duration) -> ChannelLifecycleConfig {
    let mut cfg = ChannelLifecycleConfig {
        tick_interval,
        jitter: Duration::ZERO,
        ..Default::default()
    };
    cfg.population.min_open_channels = 0;
    // A resolved threshold of zero never applies to an existing balance ("< 0"
    // is never true), so the fund pass leaves seeded channels alone — including
    // the drained one, which must stay at zero for `close_when_drained_below`
    // to select it. New channels still get funded through `initial_capacity`,
    // a separate knob the open pass reads directly.
    cfg.funding.lower_capacity_threshold = ByteSize::b(0);
    cfg.funding.initial_capacity = ByteSize::b(1); // ~3 wxHOPR
    cfg.funding.min_safe_capacity_required = ByteSize::b(0);
    cfg.proactive_funding.enabled = false;
    cfg
}

/// Startup observes before it retires, and shields connected peers longer than
/// disconnected ones.
///
/// Seeds four already-`Open`, equally poor-quality channels — two to connected
/// peers, two to disconnected ones — plus one connected, high-quality candidate
/// with no channel yet. Three checkpoints:
///
/// 1. within the observation window, nothing closes, and the open pass (which the startup guard never gates) has
///    already picked up the candidate;
/// 2. past observation but still within the grace window, the disconnected peers' channels have left `Open` while the
///    connected peers' have not;
/// 3. past the grace window, the connected peers' channels have left `Open` too.
#[rstest]
#[test_log::test(tokio::test)]
async fn observes_before_closing_on_startup(fixture: IntegrationFixture) -> Result<()> {
    let [
        source,
        connected_a,
        connected_b,
        disconnected_a,
        disconnected_b,
        candidate,
    ] = fixture.claim_accounts::<6>();
    let (connected_a_addr, connected_b_addr, disconnected_a_addr, disconnected_b_addr, candidate_addr) = (
        connected_a.address,
        connected_b.address,
        disconnected_a.address,
        disconnected_b.address,
        candidate.address,
    );
    let stake: HoprBalance = "5 wxHOPR".parse()?;

    // 1. Chain state: four Open channels, one channel-less candidate.
    let scenario = fixture
        .chain_with_channels(
            &source,
            &[
                (&connected_a, stake),
                (&connected_b, stake),
                (&disconnected_a, stake),
                (&disconnected_b, stake),
            ],
            &[&candidate],
        )
        .await?;

    // 2. Quality: all four existing channels are poor; the candidate is healthy.
    for addr in [
        connected_a_addr,
        connected_b_addr,
        disconnected_a_addr,
        disconnected_b_addr,
    ] {
        scenario.graph.set_edge(&addr, 0.0, Duration::from_secs(1));
    }
    scenario.graph.set_edge(&candidate_addr, 1.0, Duration::from_secs(1));

    // 3. Connectivity: connected_a/b and the candidate are live; disconnected_a/b are not.
    for addr in [connected_a_addr, connected_b_addr, candidate_addr] {
        scenario.network.connect(&addr);
    }

    let mut cfg = recovery_config(Duration::from_millis(50));
    cfg.restart.startup_observation_period = Duration::from_millis(400);
    cfg.restart.startup_close_grace_period = Duration::from_millis(1200);
    // 4 seeded channels + 1 candidate: a deficit exists from the first tick, so
    // the open pass has something to do without waiting on any close first.
    cfg.population.target_open_channels = 5;
    // The close pass never runs here — only its `Open`-departure is checked.
    cfg.finalizer.enabled = false;

    let node = Arc::new(LifecycleNode::with_views(
        scenario.connector.clone(),
        scenario.graph.clone(),
        scenario.network.clone(),
    ));
    let mut strategy = ChannelLifecycleStrategy::new(cfg).build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    // Checkpoint 1 (t≈300ms, observation ends at 400ms): nothing has closed,
    // and the candidate — ungated by the startup guard — has already opened.
    tokio::time::sleep(Duration::from_millis(300)).await;
    for peer in [
        connected_a_addr,
        connected_b_addr,
        disconnected_a_addr,
        disconnected_b_addr,
    ] {
        anyhow::ensure!(
            is_open(&scenario, peer)?,
            "channel to {peer} closed during the observation window"
        );
    }
    anyhow::ensure!(
        is_open(&scenario, candidate_addr)?,
        "healthy candidate channel did not open during the observation window"
    );

    // Checkpoint 2 (t≈900ms, grace ends at 1200ms): disconnected peers have
    // been retired; connected peers are still shielded.
    tokio::time::sleep(Duration::from_millis(600)).await;
    for peer in [disconnected_a_addr, disconnected_b_addr] {
        anyhow::ensure!(
            !is_open(&scenario, peer)?,
            "disconnected peer {peer} was not closed during the shielding phase"
        );
    }
    for peer in [connected_a_addr, connected_b_addr] {
        anyhow::ensure!(
            is_open(&scenario, peer)?,
            "connected peer {peer} was closed before its grace period elapsed"
        );
    }

    // Checkpoint 3 (t≈1500ms, past the 1200ms grace window): connected peers
    // are no longer shielded either — this is a window, not a permanent exemption.
    tokio::time::sleep(Duration::from_millis(600)).await;
    for peer in [connected_a_addr, connected_b_addr] {
        anyhow::ensure!(
            !is_open(&scenario, peer)?,
            "connected peer {peer} was not closed once its grace period elapsed"
        );
    }

    assert!(!handle.is_finished(), "channel-lifecycle strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// Connectivity is itself a close trigger, independent of `DefaultSelector`'s
/// quality/staleness rules: a channel to a disconnected peer cannot be used to
/// construct SURBs, so it must not survive purely because its stored quality
/// score still looks fine (or was never measured).
///
/// Seeds one `Open` channel to a peer whose quality score is high enough, and
/// recent enough, that the selector alone would never rank it —
/// `should_close` returns `false` on both the quality and staleness rules. With
/// the startup guard fully disabled (past shielding from the first tick), the
/// only thing that can close this channel is the disconnection itself.
#[rstest]
#[test_log::test(tokio::test)]
async fn force_closes_disconnected_channel_regardless_of_quality(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, peer] = fixture.claim_accounts::<2>();
    let peer_addr = peer.address;

    // 1. Chain state: one Open channel, no candidates.
    let scenario = fixture
        .chain_with_channels(&source, &[(&peer, "5 wxHOPR".parse()?)], &[])
        .await?;

    // 2. Quality: high enough that DefaultSelector would never rank this channel.
    scenario.graph.set_edge(&peer_addr, 1.0, Duration::from_secs(1));

    // 3. Connectivity: peer is not connected — left unset; TestNetworkView starts with nobody connected, and that
    //    absence is the point of this test.

    let mut cfg = recovery_config(Duration::from_millis(100));
    cfg.restart.startup_observation_period = Duration::ZERO;
    cfg.restart.startup_close_grace_period = Duration::ZERO;
    cfg.population.target_open_channels = 0;

    let node = Arc::new(LifecycleNode::with_views(
        scenario.connector.clone(),
        scenario.graph.clone(),
        scenario.network.clone(),
    ));
    let mut strategy = ChannelLifecycleStrategy::new(cfg).build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        peer_addr,
        timeouts.action,
        "disconnected channel force-closed despite fine quality",
        |c| c.status != ChannelStatus::Open,
    )
    .await?;

    assert!(!handle.is_finished(), "channel-lifecycle strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// A node holding one unusable channel recovers to a healthy, funded one within
/// a bounded time, whether the channel is unusable through poor quality or
/// through being drained — the two branches of `DefaultSelector::should_close`
/// a real deployment would hit.
#[rstest]
#[case::poor_quality(0.0, "5 wxHOPR")]
#[case::drained(0.9, "0 wxHOPR")]
#[test_log::test(tokio::test)]
async fn recovers_from_unhealthy_channels(
    fixture: IntegrationFixture,
    #[case] unhealthy_score: f64,
    #[case] unhealthy_balance: &str,
) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, unhealthy_peer, candidate] = fixture.claim_accounts::<3>();
    let (unhealthy_addr, candidate_addr) = (unhealthy_peer.address, candidate.address);

    // 1. Chain state: one Open (unhealthy) channel, one channel-less candidate.
    let scenario = fixture
        .chain_with_channels(&source, &[(&unhealthy_peer, unhealthy_balance.parse()?)], &[&candidate])
        .await?;

    // 2. Quality: the existing channel is unhealthy; the candidate is healthy.
    scenario
        .graph
        .set_edge(&unhealthy_addr, unhealthy_score, Duration::from_secs(1));
    scenario.graph.set_edge(&candidate_addr, 1.0, Duration::from_secs(1));

    // 3. Connectivity: both connected — quality/balance alone must drive recovery, not disconnection (covered
    //    separately by the force-close test above).
    scenario.network.connect(&unhealthy_addr);
    scenario.network.connect(&candidate_addr);

    let mut cfg = recovery_config(Duration::from_millis(100));
    // Isolate the close/open cycle from the startup guard under test elsewhere.
    cfg.restart.startup_observation_period = Duration::ZERO;
    cfg.restart.startup_close_grace_period = Duration::ZERO;
    // Only enough population target for the healthy replacement: a deficit
    // opens up once (and only once) the unhealthy channel is fully retired.
    cfg.population.target_open_channels = 1;
    cfg.finalizer.enabled = true;
    cfg.finalizer.max_closure_overdue = Duration::ZERO;

    let node = Arc::new(LifecycleNode::with_views(
        scenario.connector.clone(),
        scenario.graph.clone(),
        scenario.network.clone(),
    ));
    let mut strategy = ChannelLifecycleStrategy::new(cfg).build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    let recovered_balance: HoprBalance = RECOVERED_BALANCE.parse()?;
    let started = Instant::now();
    let recovered = await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        candidate_addr,
        timeouts.action,
        "recovery: candidate channel opened and funded",
        move |c| c.status == ChannelStatus::Open && c.balance >= recovered_balance,
    )
    .await?;
    tracing::info!(
        elapsed_ms = started.elapsed().as_millis(),
        balance = %recovered.balance,
        "recovered from unhealthy channel"
    );

    anyhow::ensure!(
        !is_open(&scenario, unhealthy_addr)?,
        "unhealthy channel should have left Open by the time recovery completed"
    );

    assert!(!handle.is_finished(), "channel-lifecycle strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// hoprnet/hopr-strategy#44: pure arithmetic over the *steady-state* recovery
/// latency budget — a channel degrading well after any restart, which is most
/// of a node's life. Excludes `restart.startup_close_grace_period`, a one-time
/// cost that only matters in the few minutes right after a restart.
///
/// Sums this crate's own knobs (tick cadence, finalizer overdue buffer, reopen
/// cooldown) plus a realistic on-chain closure latency this crate does not
/// control: ~15 min end-to-end (initiate, notice, finalize, confirmed) under
/// real network conditions — well above the test harness's own idealized ~5
/// min default, which is what the crate's config docs and this constant are
/// calibrated against.
#[test]
fn recovery_budget_on_defaults_meets_slo() {
    /// On-chain closure, initiate-to-confirmed, under realistic network
    /// conditions — not queryable from this crate; a fixed operational
    /// estimate, not the test harness's idealized default.
    const REALISTIC_CLOSURE_LATENCY: Duration = Duration::from_secs(15 * 60);
    const RECOVERY_SLO: Duration = Duration::from_secs(50 * 60);

    let cfg = ChannelLifecycleConfig::default();
    let budget = cfg.tick_interval
        + cfg.jitter
        + REALISTIC_CLOSURE_LATENCY
        + cfg.finalizer.max_closure_overdue
        + cfg.population.peer_reopen_cooldown;

    assert!(
        budget <= RECOVERY_SLO,
        "steady-state recovery budget {budget:?} exceeds the {RECOVERY_SLO:?} SLO"
    );
}

/// A peer whose channel closed becomes reopenable again once healed: quality
/// alone drives the initial closure, and once the peer is confirmed `Closed`
/// and its quality restored, the open pass picks it back up. Pins
/// hoprnet/hopr-strategy#44's `existing_dests` defect, fixed alongside this
/// test — `ChannelSelector::default()`'s empty `allowed_states` previously
/// included `Closed` channels in that set, permanently excluding a healed
/// peer from the open pass.
#[rstest]
#[test_log::test(tokio::test)]
async fn reopens_to_peer_whose_channel_was_closed(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, peer] = fixture.claim_accounts::<2>();
    let peer_addr = peer.address;

    // 1. Chain state: one Open channel, no candidates.
    let scenario = fixture
        .chain_with_channels(&source, &[(&peer, "5 wxHOPR".parse()?)], &[])
        .await?;

    // 2. Quality: poor enough to close.
    scenario.graph.set_edge(&peer_addr, 0.0, Duration::from_secs(1));

    // 3. Connectivity: connected throughout — quality alone drives the close.
    scenario.network.connect(&peer_addr);

    let mut cfg = recovery_config(Duration::from_millis(100));
    cfg.restart.startup_observation_period = Duration::ZERO;
    cfg.restart.startup_close_grace_period = Duration::ZERO;
    cfg.population.target_open_channels = 1;
    cfg.population.peer_reopen_cooldown = Duration::from_millis(200);
    cfg.finalizer.enabled = true;
    cfg.finalizer.max_closure_overdue = Duration::ZERO;

    let node = Arc::new(LifecycleNode::with_views(
        scenario.connector.clone(),
        scenario.graph.clone(),
        scenario.network.clone(),
    ));
    let mut strategy = ChannelLifecycleStrategy::new(cfg).build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        peer_addr,
        timeouts.action,
        "unhealthy channel fully retired",
        |c| c.status == ChannelStatus::Closed,
    )
    .await?;

    // 4. Heal: same call as step 2 — the peer's quality has recovered.
    scenario.graph.set_edge(&peer_addr, 1.0, Duration::from_secs(1));

    // The peer is connected, quality-eligible, and there is a population
    // deficit for it — nothing should stop it from reopening.
    await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        peer_addr,
        timeouts.action,
        "peer reopened after its quality recovered",
        |c| c.status == ChannelStatus::Open,
    )
    .await?;

    assert!(!handle.is_finished(), "channel-lifecycle strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}
