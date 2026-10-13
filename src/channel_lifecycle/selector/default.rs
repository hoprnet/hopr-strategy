//! Default selector: the original `peer_score_for` / `should_close` scoring,
//! plus the shared ticket-sink demotion (see
//! [`partition_by_forwarding`](super::partition_by_forwarding)).  With
//! `eligibility.demote_non_forwarding_peers` off it is byte-for-byte the
//! pre-refactor pipeline.

use std::time::Duration;

use async_trait::async_trait;
use hopr_api::types::{crypto::prelude::OffchainPublicKey, internal::prelude::ChannelId, primitive::prelude::Address};
use tracing::debug;

use super::{CloseCandidate, OpenCandidate, Selector, SelectorContext};

/// Stateless selector using the original `peer_score_for` + `should_close`
/// scoring, with ticket sinks demoted to a last resort on open (shared with
/// every selector).  This is the default selector; all existing deployments use
/// it unless they opt in to a different profile.
pub struct DefaultSelector;

impl DefaultSelector {
    /// Composite quality score for a candidate peer.
    ///
    /// Mirrors the original `ChannelLifecycleStrategyInner::peer_score_for`.
    fn peer_score(candidate: &OpenCandidate, cfg: &super::super::ChannelLifecycleConfig) -> f64 {
        let edge_score = candidate.edge_info.quality_score();
        cfg.eligibility.peer_quality_weight * edge_score
            + cfg.eligibility.ticket_activity_weight * candidate.ticket_score
    }

    /// Returns `true` when the channel should be closed.
    ///
    /// Mirrors the original `ChannelLifecycleStrategyInner::should_close`.
    /// `quality_threshold` overrides `cfg.closure.close_below_quality_score`; pass
    /// `None` to use the config value.  `MultiObjectiveSelector` passes an adjusted
    /// value to enforce the hysteresis gap.
    pub(super) fn should_close(
        candidate: &CloseCandidate,
        cfg: &super::super::ChannelLifecycleConfig,
        start_epoch_elapsed: Duration,
        quality_threshold: Option<f64>,
    ) -> bool {
        let ch = &candidate.channel;

        if ch.balance <= cfg.closure.close_when_drained_below {
            debug!(
                dest = %ch.destination,
                balance = %ch.balance,
                threshold = %cfg.closure.close_when_drained_below,
                reason = "balance_drained",
                "channel-lifecycle: close candidate"
            );
            return true;
        }

        if candidate.offchain_key.is_none() {
            return false;
        }

        if !candidate.edge_info.has_probing_data() {
            tracing::trace!(
                dest = %ch.destination,
                "channel-lifecycle: skipping close evaluation — no graph observations yet"
            );
            return false;
        }

        let edge_score = candidate.edge_info.quality_score();
        let composite_score = cfg.eligibility.peer_quality_weight * edge_score
            + cfg.eligibility.ticket_activity_weight * candidate.ticket_score;

        let effective_threshold = quality_threshold.unwrap_or(cfg.closure.close_below_quality_score);
        if composite_score < effective_threshold {
            debug!(
                dest = %ch.destination,
                score = composite_score,
                threshold = effective_threshold,
                reason = "low_quality_score",
                "channel-lifecycle: close candidate"
            );
            return true;
        }

        let last_update = candidate.edge_info.last_update;
        let stale = last_update > cfg.closure.close_when_peer_unseen_for;
        // `last_update` is the age of the last observation. If it is smaller
        // than `start_epoch_elapsed`, the observation was recorded after this
        // strategy instance started — the peer has been seen during this run.
        let observed_since_start = last_update < start_epoch_elapsed;
        let guard_passed = !cfg.eligibility.require_observed_since_start || observed_since_start;
        if stale && guard_passed {
            debug!(
                dest = %ch.destination,
                last_update_secs = last_update.as_secs(),
                unseen_threshold_secs = cfg.closure.close_when_peer_unseen_for.as_secs(),
                reason = "peer_stale",
                "channel-lifecycle: close candidate"
            );
            return true;
        }

        false
    }
}

#[async_trait]
impl Selector for DefaultSelector {
    fn required_signals(&self) -> super::SignalSet {
        super::SignalSet::default()
    }

    async fn select_closes(&self, ctx: &SelectorContext<'_>) -> Vec<ChannelId> {
        ctx.close_candidates
            .iter()
            .filter(|c| Self::should_close(c, ctx.cfg, ctx.start_epoch_elapsed, None))
            .map(|c| *c.channel.get_id())
            .collect()
    }

    async fn select_opens(&self, ctx: &SelectorContext<'_>) -> Vec<(Address, OffchainPublicKey)> {
        // Rank forwarding-capable peers ahead of ticket sinks; within each tier
        // preserve the original composite-score ordering.  Sinks are demoted,
        // never dropped — when no capable peer is available they still fill the
        // open slots.  With demotion disabled the sink tier is empty and this
        // reproduces the original single ranked list exactly.
        let (capable, sinks) =
            super::partition_by_forwarding(ctx.open_candidates, &ctx.forwarding_view, &ctx.cfg.eligibility);

        let rank = |tier: Vec<&OpenCandidate>| -> Vec<(Address, OffchainPublicKey)> {
            let mut scored: Vec<(&OpenCandidate, f64)> =
                tier.into_iter().map(|c| (c, Self::peer_score(c, ctx.cfg))).collect();
            scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            scored.into_iter().map(|(c, _)| (c.addr, c.offchain_key)).collect()
        };

        let mut result = rank(capable);
        result.extend(rank(sinks));
        result
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hopr_api::types::{
        crypto::prelude::{Keypair, OffchainKeypair, OffchainPublicKey},
        internal::prelude::{ChannelEntry, ChannelStatus},
        primitive::prelude::{Address, BytesRepresentable, HoprBalance},
    };

    use super::*;
    use crate::channel_lifecycle::{
        ChannelLifecycleConfig,
        selector::{BucketView, CloseCandidate, ForwardingView, PeerEdgeInfo, StakeView, SubnetBucket},
    };

    fn addr(seed: u8) -> Address {
        [seed; Address::SIZE].into()
    }

    fn offchain_key(seed: u8) -> OffchainPublicKey {
        *OffchainKeypair::from_secret(&[seed; 32]).expect("test key").public()
    }

    /// Builds an open-candidate with a given composite-score inputs and outgoing
    /// count; `subnet` is `Unknown` so the (multi-objective-only) anonymity logic
    /// never applies here.
    fn open_candidate(seed: u8, edge_score: f64, ticket_score: f64) -> OpenCandidate {
        OpenCandidate {
            addr: addr(seed),
            offchain_key: offchain_key(seed),
            edge_info: PeerEdgeInfo {
                edge_score: Some(edge_score),
                last_update: Duration::from_secs(1),
                average_latency: Some(Duration::from_millis(50)),
                probe_success_rate: Some(edge_score),
                ack_rate: Some(edge_score),
            },
            ticket_score,
            subnet: SubnetBucket::Unknown,
        }
    }

    fn open_ctx<'a>(
        cfg: &'a ChannelLifecycleConfig,
        candidates: &'a [OpenCandidate],
        forwarding_view: ForwardingView,
    ) -> SelectorContext<'a> {
        SelectorContext {
            cfg,
            deficit: 4,
            open_candidates: candidates,
            close_candidates: &[],
            start_epoch_elapsed: Duration::from_secs(600),
            bucket_view: BucketView::default(),
            stake_view: StakeView::empty(),
            forwarding_view,
        }
    }

    /// The deployed default path also demotes ticket sinks: a forwarding-capable
    /// peer with a *worse* composite score still ranks above a higher-scored sink.
    #[tokio::test]
    async fn default_selector_demotes_sinks_to_last_resort() {
        let capable = open_candidate(1, 0.1, 0.0); // poor score, but forwards
        let sink = open_candidate(2, 1.0, 1.0); // great score, no outgoing channels
        let forwarding_view = ForwardingView::from_counts([(addr(1), 1u32)].into_iter().collect());

        let cfg = ChannelLifecycleConfig::default(); // demotion on by default
        let candidates = [capable.clone(), sink.clone()];
        let ctx = open_ctx(&cfg, &candidates, forwarding_view);

        let opens = DefaultSelector.select_opens(&ctx).await;
        assert_eq!(
            opens.iter().map(|(a, _)| *a).collect::<Vec<_>>(),
            vec![capable.addr, sink.addr],
            "DefaultSelector must rank a forwarding-capable peer above a higher-scored sink"
        );
    }

    /// With demotion disabled the default path is byte-for-byte the original
    /// score-only ranking: the higher-scored sink wins.
    #[tokio::test]
    async fn default_selector_disabled_demotion_is_score_only() {
        let capable = open_candidate(1, 0.1, 0.0);
        let sink = open_candidate(2, 1.0, 1.0);
        let forwarding_view = ForwardingView::from_counts([(addr(1), 1u32)].into_iter().collect());

        let mut cfg = ChannelLifecycleConfig::default();
        cfg.eligibility.demote_non_forwarding_peers = false;
        let candidates = [capable.clone(), sink.clone()];
        let ctx = open_ctx(&cfg, &candidates, forwarding_view);

        let opens = DefaultSelector.select_opens(&ctx).await;
        assert_eq!(
            opens[0].0, sink.addr,
            "with demotion off, the higher-scored peer wins regardless of forwarding"
        );
    }

    /// Demotion never bars: when every candidate is a sink they are still selected.
    #[tokio::test]
    async fn default_selector_all_sinks_still_selected() {
        let cfg = ChannelLifecycleConfig::default();
        let candidates = [open_candidate(1, 0.8, 0.5), open_candidate(2, 0.7, 0.5)];
        let ctx = open_ctx(&cfg, &candidates, ForwardingView::empty());

        let opens = DefaultSelector.select_opens(&ctx).await;
        assert_eq!(
            opens.len(),
            2,
            "sinks must still be opened when they are the only candidates"
        );
    }

    fn open_channel(src: Address, dest: Address) -> ChannelEntry {
        ChannelEntry::builder()
            .between(src, dest)
            .balance(HoprBalance::new_base(10))
            .ticket_index(0)
            .status(ChannelStatus::Open)
            .epoch(1)
            .build()
            .expect("test channel")
    }

    #[test]
    fn default_selector_requires_no_signals() {
        assert_eq!(DefaultSelector.required_signals(), super::super::SignalSet::default());
    }

    /// A close candidate with `offchain_key = None` (key not resolvable from address map)
    /// must never be closed by `should_close`, regardless of other signals.
    #[test]
    fn should_close_returns_false_when_offchain_key_is_none() {
        let ch = open_channel(addr(0), addr(1));
        let candidate = CloseCandidate {
            channel: ch,
            offchain_key: None, // key not resolvable
            edge_info: PeerEdgeInfo {
                edge_score: Some(0.0), // terrible quality — would normally close
                last_update: Duration::from_secs(9999),
                average_latency: Some(Duration::from_millis(300)),
                probe_success_rate: Some(0.0),
                ack_rate: Some(0.0),
            },
            ticket_score: 0.0,
        };
        let cfg = ChannelLifecycleConfig::default();
        assert!(
            !DefaultSelector::should_close(&candidate, &cfg, Duration::from_secs(600), None),
            "channel without a resolvable offchain key must not be closed"
        );
    }

    /// A channel with no graph observations yet (last_update = ZERO) must not be closed.
    #[test]
    fn should_close_returns_false_when_no_probing_data() {
        let ch = open_channel(addr(0), addr(2));
        let candidate = CloseCandidate {
            channel: ch,
            offchain_key: Some(offchain_key(2)),
            edge_info: PeerEdgeInfo {
                edge_score: None,
                last_update: Duration::ZERO, // no observations at all
                average_latency: None,
                probe_success_rate: Some(0.0),
                ack_rate: None,
            },
            ticket_score: 0.0,
        };
        let mut cfg = ChannelLifecycleConfig::default();
        cfg.closure.close_below_quality_score = 1.0; // would close anything with data
        assert!(
            !DefaultSelector::should_close(&candidate, &cfg, Duration::from_secs(600), None),
            "channel with no graph observations must not be closed"
        );
    }

    /// A balance-drained channel must be closed regardless of other signals.
    #[test]
    fn should_close_returns_true_when_balance_drained() {
        let ch = ChannelEntry::builder()
            .between(addr(0), addr(3))
            .balance(HoprBalance::zero()) // fully drained
            .ticket_index(0)
            .status(ChannelStatus::Open)
            .epoch(1)
            .build()
            .expect("test channel");
        let candidate = CloseCandidate {
            channel: ch,
            offchain_key: Some(offchain_key(3)),
            edge_info: PeerEdgeInfo {
                edge_score: Some(1.0), // excellent quality — would normally keep open
                last_update: Duration::from_secs(10),
                average_latency: Some(Duration::from_millis(50)),
                probe_success_rate: Some(1.0),
                ack_rate: Some(1.0),
            },
            ticket_score: 1.0,
        };
        let cfg = ChannelLifecycleConfig::default();
        assert!(
            DefaultSelector::should_close(&candidate, &cfg, Duration::from_secs(600), None),
            "balance-drained channel must always be closed"
        );
    }
}
