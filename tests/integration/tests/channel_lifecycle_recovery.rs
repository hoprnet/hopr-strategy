//! Recovery of the channel-lifecycle strategy from deliberately unhealthy or
//! stale channels — hoprnet/hopr-strategy#44.
//!
//! Two behaviours are exercised:
//!
//! * on startup, closure is staged (see `RestartGuardConfig`): the strategy only observes for a short window, then
//!   retires channels to disconnected peers while still shielding connected ones, and only later applies the usual
//!   closure rules to everyone;
//! * once past that window, a node holding unusable channels closes them and opens replacements to healthy peers within
//!   a bounded time.
//!
//! The two `#[ignore]`d tests document the issue's own numbers: they fail
//! against `ChannelLifecycleConfig::default()` today, pinning both the ~tens-of-
//! minutes recovery budget and a permanent-reopen defect as regressions a future
//! fix must clear.

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
    fixtures::{
        Candidate, IntegrationFixture, RecoveryScenario, SeededChannel, await_channel_where,
        integration_fixture as fixture,
    },
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

    let channels = vec![
        SeededChannel {
            peer: connected_a,
            connected: true,
            edge_score: 0.0,
            balance: stake,
        },
        SeededChannel {
            peer: connected_b,
            connected: true,
            edge_score: 0.0,
            balance: stake,
        },
        SeededChannel {
            peer: disconnected_a,
            connected: false,
            edge_score: 0.0,
            balance: stake,
        },
        SeededChannel {
            peer: disconnected_b,
            connected: false,
            edge_score: 0.0,
            balance: stake,
        },
    ];
    let candidates = vec![Candidate {
        peer: candidate,
        edge_score: 1.0,
    }];

    let scenario = fixture
        .unhealthy_channels_scenario(&source, &channels, &candidates)
        .await?;

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
/// Seeds one `Open` channel to a disconnected peer whose quality score is high
/// enough, and recent enough, that the selector alone would never rank it —
/// `should_close` returns `false` on both the quality and staleness rules. With
/// the startup guard fully disabled (past shielding from the first tick), the
/// only thing that can close this channel is the disconnection itself.
#[rstest]
#[test_log::test(tokio::test)]
async fn force_closes_disconnected_channel_regardless_of_quality(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, peer] = fixture.claim_accounts::<2>();
    let peer_addr = peer.address;

    let channels = vec![SeededChannel {
        peer,
        connected: false,
        edge_score: 1.0,
        balance: "5 wxHOPR".parse()?,
    }];
    let scenario = fixture.unhealthy_channels_scenario(&source, &channels, &[]).await?;

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

    let channels = vec![SeededChannel {
        peer: unhealthy_peer,
        connected: true,
        edge_score: unhealthy_score,
        balance: unhealthy_balance.parse()?,
    }];
    let candidates = vec![Candidate {
        peer: candidate,
        edge_score: 1.0,
    }];

    let scenario = fixture
        .unhealthy_channels_scenario(&source, &channels, &candidates)
        .await?;

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

/// hoprnet/hopr-strategy#44: pure arithmetic over the serial latency budget a
/// node holding a bad channel must clear before its peer becomes reopenable —
/// the guard window, tick cadence, on-chain closure notice, finalizer overdue
/// buffer, and the reopen cooldown.
///
/// Fails today: even after halving `startup_close_grace_period` (10 min → 5
/// min) for this issue, the sum comfortably exceeds a 5-minute recovery SLO.
#[ignore = "hoprnet/hopr-strategy#44: recovery budget on default config exceeds the 5-minute SLO"]
#[test]
fn recovery_budget_on_defaults_meets_slo() {
    // The closure notice period lives on-chain (`ChainValues::channel_closure_notice_period`),
    // not in this crate's config; 5 minutes is the test harness's own default.
    const NOTICE_PERIOD: Duration = Duration::from_secs(5 * 60);
    const RECOVERY_SLO: Duration = Duration::from_secs(5 * 60);

    let cfg = ChannelLifecycleConfig::default();
    let budget = cfg.restart.startup_close_grace_period
        + cfg.tick_interval
        + cfg.jitter
        + NOTICE_PERIOD
        + cfg.finalizer.max_closure_overdue
        + cfg.population.peer_reopen_cooldown;

    assert!(
        budget <= RECOVERY_SLO,
        "worst-case recovery budget {budget:?} exceeds the {RECOVERY_SLO:?} SLO"
    );
}

/// hoprnet/hopr-strategy#44: pins a likely root cause of the reported failure to
/// recover. The channel snapshot uses `ChannelSelector::default()`, whose empty
/// `allowed_states` `hopr-api` treats as "no state filter" — so `Closed`
/// channels are included in `existing_dests`, which permanently excludes that
/// peer from the open pass even once its quality recovers.
/// `try_open_channel` explicitly handles a `Closed` starting status by opening
/// a fresh channel, so that branch is currently unreachable.
///
/// Fails today: the peer never reopens, though it is connected, quality-
/// eligible, and there is a population deficit for it to fill.
#[ignore = "hoprnet/hopr-strategy#44: a peer whose channel closed can never be reopened to"]
#[rstest]
#[test_log::test(tokio::test)]
async fn reopens_to_peer_whose_channel_was_closed(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [source, peer] = fixture.claim_accounts::<2>();
    let peer_addr = peer.address;

    let channels = vec![SeededChannel {
        peer,
        connected: true,
        edge_score: 0.0,
        balance: "5 wxHOPR".parse()?,
    }];
    let scenario = fixture.unhealthy_channels_scenario(&source, &channels, &[]).await?;

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
    scenario.set_quality(&peer_addr, 1.0);

    // The peer is connected, quality-eligible, and there is a population
    // deficit for it — the only remaining reason it would not reopen is the
    // `existing_dests` defect this test pins.
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
