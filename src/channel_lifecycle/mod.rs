//! ## Channel Lifecycle Strategy
//!
//! A unified strategy that owns **open / fund / close / finalize** for outgoing
//! payment channels.  It replaces the combination of `AutoFundingStrategy` +
//! `ClosureFinalizerStrategy` with a single component that maintains a target
//! population of funded outgoing channels against online peers and retires
//! channels to peers that have been absent for too long.
//!
//! ### State machine
//!
//! ```text
//!                                   ┌────────────────────────┐
//!                                   │   no on-chain entry    │
//!                                   └───────────┬────────────┘
//!                                               │ open()  (eligibility passed)
//!                                               ▼
//!                                   ┌────────────────────────┐
//!                                   │     OpenInFlight       │
//!                                   └───────────┬────────────┘
//!                                               │ ChannelOpened
//!                                               ▼
//!                                   ┌────────────────────────┐
//!                                   │         Open           │◄──────────────┐
//!                                   └─────┬──────────┬───────┘               │
//!                below_lower_balance      │          │ staleness/quality drop
//!                       fund()            │          │  close()
//!                           ▼             │          ▼
//!                   ┌──────────────┐      │   ┌────────────────────┐
//!                   │ FundInFlight │      │   │   CloseInFlight    │
//!                   └──────┬───────┘      │   └─────────┬──────────┘
//!                          │ Balance↑     │             │ ChannelClosureInitiated
//!                          ▼              │             ▼
//!                         Open ───────────┘   ┌────────────────────┐
//!                                             │  PendingToClose    │
//!                                             └─────────┬──────────┘
//!                                                       │ deadline + max_closure_overdue
//!                                                       │ finalize()
//!                                                       ▼
//!                                             ┌────────────────────┐
//!                                             │ FinalizeInFlight   │
//!                                             └─────────┬──────────┘
//!                                                       │ ChannelClosed
//!                                                       ▼
//!                                             ┌────────────────────┐
//!                                             │  cooldown (peer)   │
//!                                             └────────────────────┘
//!                                                       │ peer_reopen_cooldown
//!                                                       ▼
//!                                                (eligible to reopen)
//! ```
//!
//! In-flight states are tracked off-chain as [`ActionLeases`], keyed by
//! `ChannelId` (fund / close / finalize) or peer `Address` (open).  The on-chain
//! `ChannelStatus` plus those leases together drive transitions.
//!
//! Every in-flight state is left by one of three routes: the operation's
//! confirmation resolving, either way; the chain event named on its edge above;
//! or — because neither is guaranteed to arrive — the expiry of the operation's
//! lease ([`ConcurrencyConfig::action_lease_timeout`]).  The chain, not the
//! strategy's bookkeeping, is the source of truth: after a lease expires the
//! next tick re-reads the channel and only acts if it still needs the
//! operation.
//!
//! The cooldown is keyed by peer `Address` with an `Instant`-stamped map entry.
//!
//! ### Feature flag
//!
//! Enable with `strategy-channel-lifecycle`.

mod config;
pub use config::*;

mod events;
mod pipeline;
pub mod selector;
mod strategy;
use std::{
    collections::HashMap,
    hash::Hash,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;
use hopr_api::{
    PeerId,
    types::{
        crypto::prelude::OffchainPublicKey,
        internal::prelude::ChannelId,
        primitive::prelude::{Address, HoprBalance},
    },
};
use parking_lot::Mutex;
use selector::Selector;
pub use strategy::ChannelLifecycleStrategy;

#[cfg(all(feature = "telemetry", not(test)))]
lazy_static::lazy_static! {
    static ref METRIC_CHANNEL_OPENS: hopr_api::types::telemetry::SimpleCounter =
        hopr_api::types::telemetry::SimpleCounter::new(
            "hopr_strategy_channel_lifecycle_opens",
            "Count of initiated channel opens",
        ).unwrap();
    static ref METRIC_CHANNEL_FUNDS: hopr_api::types::telemetry::SimpleCounter =
        hopr_api::types::telemetry::SimpleCounter::new(
            "hopr_strategy_channel_lifecycle_fundings",
            "Count of initiated channel fundings",
        ).unwrap();
    static ref METRIC_CHANNEL_CLOSES: hopr_api::types::telemetry::SimpleCounter =
        hopr_api::types::telemetry::SimpleCounter::new(
            "hopr_strategy_channel_lifecycle_closes",
            "Count of initiated channel closures",
        ).unwrap();
    static ref METRIC_CHANNEL_FINALIZES: hopr_api::types::telemetry::SimpleCounter =
        hopr_api::types::telemetry::SimpleCounter::new(
            "hopr_strategy_channel_lifecycle_finalizations",
            "Count of initiated channel closure finalizations",
        ).unwrap();

    // ── Diversity / anonymity ─────────────────────────────────────────────────
    /// Shannon-entropy-based effective number of distinct (latency, subnet) cells.
    static ref METRIC_EFFECTIVE_BUCKETS: hopr_api::types::telemetry::SimpleGauge =
        hopr_api::types::telemetry::SimpleGauge::new(
            "hopr_strategy_channel_lifecycle_effective_buckets",
            "Effective number of distinct (latency, subnet) bucket cells among open channels (2^H)",
        ).unwrap();

    /// Per-cell channel count, labelled by the cell description.
    static ref METRIC_BUCKET_COUNT: hopr_api::types::telemetry::MultiGauge =
        hopr_api::types::telemetry::MultiGauge::new(
            "hopr_strategy_channel_lifecycle_bucket_count",
            "Number of open channels in each (latency, subnet) bucket cell",
            &["cell"],
        ).unwrap();

    /// Variance of round-trip times across all open channels, in milliseconds.
    static ref METRIC_LATENCY_VARIANCE_MS: hopr_api::types::telemetry::SimpleGauge =
        hopr_api::types::telemetry::SimpleGauge::new(
            "hopr_strategy_channel_lifecycle_latency_variance_ms",
            "Variance of round-trip times (ms) across all open channels",
        ).unwrap();

    /// Number of distinct /24 or /48 subnet prefixes among open channels.
    static ref METRIC_SUBNET_COUNT: hopr_api::types::telemetry::SimpleGauge =
        hopr_api::types::telemetry::SimpleGauge::new(
            "hopr_strategy_channel_lifecycle_subnet_count",
            "Number of distinct subnet prefixes among open channels",
        ).unwrap();

    /// Average per-axis score across all open-channel candidates for the last tick.
    /// Only non-zero when the multi-objective selector is active.
    static ref METRIC_SCORE_AXIS: hopr_api::types::telemetry::MultiGauge =
        hopr_api::types::telemetry::MultiGauge::new(
            "hopr_strategy_channel_lifecycle_score_axis",
            "Average per-axis score across open candidates in the last strategy tick",
            &["axis"],
        ).unwrap();
}

/// Identifies one holder of a slot, so a release can tell whether the slot it is
/// giving back is still its own.
///
/// Slot ownership turns over when a lease expires and a later attempt takes the
/// key again.  The stale attempt may still report back afterwards — a slow
/// confirmation eventually resolves — and without this it would release the
/// *successor's* live slot, letting a third attempt start while the second is
/// still pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LeaseId(u64);

/// A held slot: who holds it, and until when.
#[derive(Debug, Clone, Copy)]
struct Lease {
    holder: LeaseId,
    until: Instant,
}

/// Time-bounded exclusive slots for in-flight chain-write operations.
///
/// A slot is taken before a transaction is submitted and released when the
/// operation is over: its confirmation resolved, either way, or the
/// corresponding chain event arrived.  Neither signal is guaranteed — the event
/// broadcast drops events under load, and a confirmation may never resolve — so
/// each slot also carries a deadline.  Once that passes the slot is reclaimed
/// and the operation may be attempted again.
///
/// Without the deadline a single lost signal suppresses that channel's
/// operation forever, and — because slots share a global budget
/// ([`ConcurrencyConfig::max_concurrent_actions`]) — enough lost signals
/// suppress every operation on every channel.
struct ActionLeases<K> {
    leases: DashMap<K, Lease>,
    /// Source of [`LeaseId`]s, unique across every key of this set.
    next_holder: AtomicU64,
}

impl<K: Eq + Hash> std::fmt::Debug for ActionLeases<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionLeases")
            .field("slots", &self.leases.len())
            .finish_non_exhaustive()
    }
}

impl<K: Eq + Hash> Default for ActionLeases<K> {
    fn default() -> Self {
        Self {
            leases: DashMap::new(),
            next_holder: AtomicU64::new(0),
        }
    }
}

impl<K: Eq + Hash + Clone> ActionLeases<K> {
    /// Takes the slot for `key` for at most `timeout`, unless it is already
    /// held.  Returns the caller's [`LeaseId`] if it now holds the slot.
    fn acquire(&self, key: K, timeout: Duration) -> Option<LeaseId> {
        use dashmap::mapref::entry::Entry;

        let now = Instant::now();
        let holder = LeaseId(self.next_holder.fetch_add(1, Ordering::Relaxed));
        let lease = Lease {
            holder,
            until: now + timeout,
        };

        match self.leases.entry(key) {
            // Still held by an operation that has not reported back yet.
            Entry::Occupied(held) if held.get().until > now => None,
            Entry::Occupied(mut expired) => {
                expired.insert(lease);
                Some(holder)
            }
            Entry::Vacant(free) => {
                free.insert(lease);
                Some(holder)
            }
        }
    }

    /// Releases the slot for `key` if `holder` still holds it.
    ///
    /// Used by an operation reporting its own outcome: if its lease has since
    /// expired and been taken by a later attempt, this is a no-op and the
    /// successor keeps its slot.
    fn release_owned(&self, key: &K, holder: LeaseId) {
        self.leases.remove_if(key, |_, lease| lease.holder == holder);
    }

    /// Releases the slot for `key` whoever holds it.
    ///
    /// Used by chain events, which report on the channel rather than on a
    /// particular attempt and so carry no [`LeaseId`].  Idempotent: releasing a
    /// slot that is not held is a no-op, which is what an event arriving after a
    /// restart or after the deadline does.
    fn release(&self, key: &K) {
        self.leases.remove(key);
    }

    /// Whether `key`'s slot is currently held.  Expired slots read as free even
    /// before [`ActionLeases::sweep`] removes them.
    fn is_held(&self, key: &K) -> bool {
        self.leases.get(key).is_some_and(|lease| lease.until > Instant::now())
    }

    /// Number of slots currently held, excluding expired ones.
    fn held_count(&self) -> usize {
        let now = Instant::now();
        self.leases.iter().filter(|entry| entry.value().until > now).count()
    }

    /// Drops expired entries.  Only reclaims memory: expired slots already read
    /// as free.
    fn sweep(&self) {
        let now = Instant::now();
        self.leases.retain(|_, lease| lease.until > now);
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }
}

#[cfg(test)]
mod action_leases {
    use super::*;

    const HELD: Duration = Duration::from_secs(3600);
    /// Expires the instant it is taken, standing in for a lease whose operation
    /// overran its deadline.
    const EXPIRED: Duration = Duration::ZERO;

    #[test]
    fn action_leases_should_refuse_a_second_holder_while_the_slot_is_held() {
        let leases = ActionLeases::default();

        assert!(leases.acquire("channel", HELD).is_some(), "a free slot may be taken");
        assert!(
            leases.acquire("channel", HELD).is_none(),
            "a held slot may not be taken again"
        );
        assert_eq!(leases.held_count(), 1);
    }

    #[test]
    fn action_leases_should_hand_the_slot_over_when_the_lease_has_expired() {
        let leases = ActionLeases::default();

        assert!(leases.acquire("channel", EXPIRED).is_some());
        assert!(
            leases.acquire("channel", HELD).is_some(),
            "an expired slot is free to take"
        );
        assert!(leases.is_held(&"channel"));
    }

    /// The operation whose lease expired may still report back afterwards — a
    /// slow confirmation eventually resolves.  Releasing by key alone would then
    /// free the successor's live slot and let a third attempt start while the
    /// second is still in flight.
    #[test]
    fn action_leases_should_keep_the_slot_when_a_stale_holder_releases_it() {
        let leases = ActionLeases::default();

        let overran = leases.acquire("channel", EXPIRED).expect("a free slot");
        let successor = leases.acquire("channel", HELD).expect("an expired slot is free");

        leases.release_owned(&"channel", overran);
        assert!(leases.is_held(&"channel"), "the successor must keep the slot it holds");

        leases.release_owned(&"channel", successor);
        assert!(!leases.is_held(&"channel"), "its own holder may release it");
    }

    /// Chain events report on the channel rather than on one attempt, so they
    /// release whoever holds the slot.
    #[test]
    fn action_leases_should_release_any_holder_when_a_chain_event_reports() {
        let leases = ActionLeases::default();

        leases.acquire("channel", HELD).expect("a free slot");
        leases.release(&"channel");

        assert!(!leases.is_held(&"channel"));
        assert!(leases.is_empty());
    }

    #[test]
    fn action_leases_should_drop_expired_slots_when_swept() {
        let leases = ActionLeases::default();

        leases.acquire("expired", EXPIRED).expect("a free slot");
        leases.acquire("held", HELD).expect("a free slot");
        leases.sweep();

        assert!(!leases.is_empty(), "a held slot survives the sweep");
        assert_eq!(leases.held_count(), 1);
        assert!(leases.is_held(&"held"));
    }
}

/// Per-channel observation snapshot used by the proactive funding estimate.
#[derive(Clone)]
struct ChannelObservation {
    balance: HoprBalance,
    ticket_index: u64,
    at: Instant,
}

/// Cached `peer_id → (offchain key, chain address)` map plus the timestamp at
/// which it was last refreshed.  Lets the snapshot pass skip the full account
/// stream on most ticks.
struct PeerAddrCache {
    refreshed_at: Instant,
    map: HashMap<PeerId, (OffchainPublicKey, Address)>,
}

/// The running strategy instance.  Generic over the node type `N` so that
/// callers can provide any node implementation satisfying the required traits.
///
/// Constructed via [`ChannelLifecycleStrategy::build`]; the builder erases `N`
/// behind `Box<dyn Strategy + Send>`.
struct ChannelLifecycleStrategyInner<N> {
    cfg: ChannelLifecycleConfig,
    node: Arc<N>,
    /// Pluggable selection policy.  Decides which peers to open channels with
    /// and which open channels to retire.  Pipeline invariants (population
    /// floor, concurrent-action caps, safe-balance budget) are enforced by the
    /// pipeline regardless of the selector's choices.
    selector: Arc<dyn Selector>,
    /// Destination addresses for channels currently being opened.
    open_in_flight: Arc<ActionLeases<Address>>,
    /// Channel IDs with an in-flight funding transaction.
    fund_in_flight: Arc<ActionLeases<ChannelId>>,
    /// Channel IDs with an in-flight closure transaction.
    close_in_flight: Arc<ActionLeases<ChannelId>>,
    /// Channel IDs with an in-flight finalization transaction.
    finalize_in_flight: Arc<ActionLeases<ChannelId>>,
    /// Peer addresses mapped to the `Instant` when their cooldown expires.
    cooldown: Arc<DashMap<Address, Instant>>,
    /// When this strategy instance started; used by the restart guard.
    start_epoch: Instant,
    /// Most-recently recorded balance/ticket_index snapshot per channel.
    last_observed: Arc<DashMap<ChannelId, ChannelObservation>>,
    /// Cumulative ticket count increments from `TicketRedeemed` events.
    peer_ticket_activity: Arc<DashMap<Address, u64>>,
    /// TTL-cached peer-id → (offchain key, chain address) map.  Avoids
    /// streaming the full on-chain account list on every tick.
    peer_addr_cache: Arc<Mutex<Option<PeerAddrCache>>>,
    /// Economics resolved by the most-recent pipeline tick, shared with the
    /// event-driven funding handler so it reuses per-tick values instead of
    /// issuing fresh chain RPC calls on every balance-decrease event.
    last_resolved_funding: Arc<Mutex<Option<ResolvedFunding>>>,
}
