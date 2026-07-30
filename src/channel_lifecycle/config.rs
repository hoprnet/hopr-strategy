use std::{collections::HashSet, time::Duration};

use bytesize::ByteSize;
use hopr_api::{
    node::PacketTransport,
    types::primitive::prelude::{Address, HoprBalance, U256},
};
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use validator::Validate;

/// Population thresholds: how many open channels to maintain.
#[serde_as]
#[derive(Debug, Clone, PartialEq, smart_default::SmartDefault, Validate, Serialize, Deserialize)]
pub struct PopulationConfig {
    /// Minimum number of open outgoing channels.  Closures are suppressed
    /// when the open count would drop below this.  Default: 5.
    #[default = 5]
    pub min_open_channels: usize,

    /// Target number of open outgoing channels.  New channels are opened until
    /// this target is reached.  Default: 8.
    #[default = 8]
    pub target_open_channels: usize,

    /// How long a peer is ineligible for a new channel after its previous
    /// channel was closed.  Default: 30 minutes.
    #[serde(default = "default_peer_reopen_cooldown", with = "humantime_serde")]
    #[default(default_peer_reopen_cooldown())]
    pub peer_reopen_cooldown: Duration,
}

#[inline]
fn default_peer_reopen_cooldown() -> Duration {
    Duration::from_secs(30 * 60)
}

/// Peer eligibility filters for channel opening and for determining staleness.
#[serde_as]
#[derive(Debug, Clone, PartialEq, smart_default::SmartDefault, Validate, Serialize, Deserialize)]
pub struct EligibilityConfig {
    /// Only open channels to peers that are currently connected.  Default: true.
    #[default = true]
    pub require_currently_connected: bool,

    /// Peer quality score threshold `[0.0, 1.0]` for opening new channels.
    /// Default: 0.5.
    #[default = 0.5]
    pub min_peer_quality_score: f64,

    /// Weight applied to the graph edge score in the composite peer score.
    /// Default: 0.6.
    #[default = 0.6]
    pub peer_quality_weight: f64,

    /// Weight applied to the normalised ticket-activity signal in the
    /// composite peer score.  Default: 0.4.
    #[default = 0.4]
    pub ticket_activity_weight: f64,

    /// Only close a channel when the peer has been observed since the strategy
    /// started running (i.e. `edge.last_update()` is more recent than
    /// `start_epoch.elapsed()`).  Protects against retiring channels for which
    /// the local view is still warming up after a restart.  Default: true.
    #[default = true]
    pub require_observed_since_start: bool,

    /// If set, only open channels to addresses in this list.  `None` means
    /// all peers are eligible.  Default: None.
    #[default(None)]
    pub allowlist: Option<HashSet<Address>>,

    /// Never open channels to addresses in this list.  Default: empty.
    #[default(HashSet::new())]
    pub blocklist: HashSet<Address>,
}

/// How the strategy converts a data-capacity [`ByteSize`] to a wxHOPR channel
/// stake at runtime.
///
/// Each packet sent through an h-hop path causes one Bernoulli(win_prob) trial
/// per hop: a ticket of face value `ticket_price` is redeemed with probability
/// `win_prob`, draining that amount from the channel balance (§3.2).  The total
/// drain for N packets therefore follows a scaled Binomial distribution:
///
/// ```text
/// D ~ Binomial(N, win_prob) × hops × ticket_price
/// E[D] = N × win_prob × hops × ticket_price
/// σ[D] = hops × ticket_price × √(N × win_prob × (1 − win_prob))
/// ```
///
/// The three modes differ only in how much safety buffer is added above the
/// expected drain.
///
/// # Mode comparison for a typical FundingConfig
///
/// Common parameters: hops = 3, win_prob = 0.001 (ultralow), ticket_price = 0.001 wxHOPR (ultralow)
///
/// ```text
/// Config field            capacity    N (pkts)   Deterministic   Expected   Probabilistic(0.999)
/// ─────────────────────────────────────────────────────────────────────────────────────────────
/// lower_capacity_threshold  250 MB     253 035     759 wxHOPR    0.76 wxHOPR    0.91 wxHOPR
/// initial_capacity            1 GB   1 036 431   3 109 wxHOPR    3.11 wxHOPR    3.41 wxHOPR
/// topup_capacity              5 GB   5 182 152  15 547 wxHOPR   15.55 wxHOPR   16.21 wxHOPR
/// ```
///
/// `Deterministic` over-funds by ~900× relative to `Probabilistic(0.999)` at these ultralow
/// parameters.  The k·σ overhead shrinks as N grows (+19 % at 250 MB, +4 % at 5 GB), making
/// `Probabilistic` indistinguishable from `Expected` at large capacities.
///
/// At `win_prob = 1.0` all three modes are equal: σ = 0 and `E[D] = N × hops × tp`.
///
/// # Choosing a mode
///
/// * **`Deterministic`** — no chain queries for win_prob; always safe but
///   massively over-funds at low win_prob (~900× in the example above).
/// * **`Expected`** — most capital-efficient; ~50 % of cycles see the channel
///   drain slightly faster than planned (triggering a top-up sooner, not loss).
/// * **`Probabilistic`** (**default**) — adds a k·σ buffer; the channel carries
///   its full configured capacity with probability `success_probability`.
///   Overhead over `Expected` is 19 % at 250 MB, 10 % at 1 GB, 4 % at 5 GB.
#[derive(Debug, Clone, PartialEq, smart_default::SmartDefault, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacitySizingMode {
    /// `stake = N × hops × ticket_price`
    ///
    /// Hard worst-case guarantee: the channel never empties prematurely
    /// regardless of win_prob (equivalent to assuming every ticket wins).
    /// Does **not** require the win_prob chain query each tick.
    ///
    /// Over-funds proportionally to `1 / win_prob` relative to the expected
    /// drain.  Use when capital efficiency is not a concern and you want zero
    /// sensitivity to win_prob fluctuations.
    Deterministic,

    /// `stake = N × win_prob × hops × ticket_price`
    ///
    /// Sizes the stake exactly to the expected drain.  Capital-efficient at low
    /// win_prob; approximately half of all fund cycles see the channel drain
    /// slightly faster than planned (triggers a top-up sooner, not message loss).
    /// Requires the win_prob chain query each tick.
    Expected,

    /// `stake = E[D] + k·σ[D]`  where k = Φ⁻¹(success_probability)
    ///
    /// Adds `k` Binomial standard deviations on top of the expected drain,
    /// guaranteeing the channel carries its full configured capacity with
    /// probability `success_probability`.  Requires the win_prob chain query
    /// each tick.
    ///
    /// # Worked example — default settings (k ≈ 3.09)
    ///
    /// Parameters: N = 100 000 packets, win_prob = 0.01, hops = 3,
    /// ticket_price = 0.01 wxHOPR.
    ///
    /// ```text
    /// E[D]  = 30.000 wxHOPR
    /// σ[D]  ≈  0.944 wxHOPR
    /// stake ≈ 30 + 3.09 × 0.944 ≈ 32.9 wxHOPR   (Deterministic would be 3 000)
    /// ```
    ///
    /// At `win_prob = 1.0` the variance term vanishes (σ = 0) and the formula
    /// collapses to `N × hops × ticket_price` — identical to `Deterministic`.
    #[default]
    Probabilistic {
        /// Probability that the channel does **not** drain prematurely in any
        /// given fund cycle.  Must be in the range `(0.5, 1.0)`.
        ///
        /// | value  | k (z-score) | notes |
        /// |--------|-------------|-------|
        /// | 0.841  | 1.0  | one-sigma; adequate for large N |
        /// | 0.977  | 2.0  | two-sigma |
        /// | 0.999  | 3.09 | **default**; recommended for most deployments |
        /// | 0.9999 | 3.72 | four-nines; use for very small N or mission-critical paths |
        #[serde(default = "default_success_probability")]
        #[default = 0.999]
        success_probability: f64,
    },
}

#[inline]
fn default_success_probability() -> f64 {
    0.999
}

impl CapacitySizingMode {
    /// Returns `true` for modes that use the network's winning probability at
    /// runtime.  `Deterministic` returns `false` and skips the win_prob query.
    pub(crate) fn requires_win_prob(&self) -> bool {
        !matches!(self, Self::Deterministic)
    }
}

/// Initial and top-up capacities for channel funding expressed as human-readable
/// data volumes, plus the [`CapacitySizingMode`] that controls how those volumes
/// are converted to wxHOPR stakes at runtime.
///
/// All four capacity fields share the same sizing mode.  [`FundingConfig::resolve`]
/// converts them to [`ResolvedFunding`] balances once per tick using the live
/// ticket price (and, for `Expected`/`Probabilistic` modes, the live winning
/// probability).
///
/// # Quick-start defaults
///
/// ```toml
/// [funding]
/// initial_capacity           = "1 GiB"
/// topup_capacity             = "512 MiB"
/// lower_capacity_threshold   = "512 MiB"
/// min_safe_capacity_required = "512 MiB"
/// assumed_hops               = 3
///
/// [funding.sizing_mode]
/// mode                = "probabilistic"
/// success_probability = 0.999
/// ```
///
/// With `ticket_price = 0.01 wxHOPR` and `win_prob = 0.01` this resolves to:
///
/// ```text
/// N_initial = ceil(1 GiB / 1036 B) = 1 025 165 packets
/// E[D]      = 1 025 165 × 0.01 × 3 × 0.01 ≈ 307.6 wxHOPR
/// σ[D]      = 3 × 0.01 × √(1 025 165 × 0.01 × 0.99) ≈ 0.953 wxHOPR
/// stake     ≈ 307.6 + 3.09 × 0.953 ≈ 310.5 wxHOPR
///
/// (Deterministic would lock 30 760 wxHOPR — 99× more)
/// ```
#[derive(Debug, Clone, PartialEq, smart_default::SmartDefault, Validate, Serialize, Deserialize)]
pub struct FundingConfig {
    /// Data volume a newly opened channel's stake should be able to carry.
    /// Default: 1 GiB.
    #[default(ByteSize::gib(1))]
    pub initial_capacity: ByteSize,

    /// Data volume added to a channel's stake when it is topped up.
    /// Default: 512 MiB.
    #[default(ByteSize::mib(512))]
    pub topup_capacity: ByteSize,

    /// The channel balance (expressed as data capacity) below which a top-up is
    /// triggered.  Default: 512 MiB.
    #[default(ByteSize::mib(512))]
    pub lower_capacity_threshold: ByteSize,

    /// Minimum safe balance (expressed as data capacity) required before the
    /// strategy opens or funds any channel.  Default: 512 MiB.
    #[default(ByteSize::mib(512))]
    pub min_safe_capacity_required: ByteSize,

    /// When `true` the fund and open passes are skipped entirely if the safe
    /// balance is below `min_safe_capacity_required`.  Default: true.
    #[default = true]
    pub stop_when_unfunded: bool,

    /// Number of paid downstream relay hops assumed when sizing the channel
    /// stake.  Must be ≥ 1 and ≤ [`RoutingOptions::MAX_INTERMEDIATE_HOPS`][routing] (3).
    /// Default: 3.
    ///
    /// [routing]: hopr_api::types::internal::routing::RoutingOptions
    #[default = 3]
    #[validate(range(min = 1, max = 3))]
    pub assumed_hops: u32,

    /// How each capacity field is converted to a wxHOPR stake.
    /// Default: `Probabilistic { success_probability: 0.999 }`.
    ///
    /// See [`CapacitySizingMode`] for the full tradeoff analysis.
    #[default(CapacitySizingMode::default())]
    pub sizing_mode: CapacitySizingMode,
}

// ─────────────────────────────────────────────────────────────────────────────
// Capacity → wxHOPR conversion
// ─────────────────────────────────────────────────────────────────────────────

/// wxHOPR amounts resolved from [`FundingConfig`] at the current ticket
/// economics.  Computed once per pipeline tick and threaded through the fund,
/// open, and close-decision paths.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ResolvedFunding {
    /// Initial balance when opening a new channel.
    pub initial_balance: HoprBalance,
    /// Amount added when topping up an underfunded channel.
    pub topup_balance: HoprBalance,
    /// Channel balance below which a top-up is triggered.
    pub lower_balance_threshold: HoprBalance,
    /// Minimum safe balance required before opening or funding any channel.
    pub min_safe_balance_required: HoprBalance,
}

/// Convert a data `capacity` to a wxHOPR channel stake using the live ticket
/// economics and the configured [`CapacitySizingMode`].
///
/// # Formula
///
/// ```text
/// N     = ceil(capacity_bytes / packet_payload_size())
/// p     = win_prob  (clamped to (0, 1])
/// h     = hops
/// tp    = ticket_price
///
/// Deterministic:        stake = N × h × tp
/// Expected:             stake = N × p × h × tp
/// Probabilistic(α):     stake = N × p × h × tp + k × h × tp × √(N × p × (1−p))
///                               where k = Φ⁻¹(α)  (standard-normal quantile)
/// ```
///
/// `win_prob` is ignored for `Deterministic` (pass any value; `1.0` is
/// conventional).  Returns [`HoprBalance::zero`] for zero capacity.
///
/// # Examples
///
/// ```text
/// tp = 0.01 wxHOPR,  h = 3,  N = 10 packets (= 10 × 1036 B capacity)
///
/// p = 1.00 → Deterministic = Expected = Probabilistic = 0.30 wxHOPR
/// p = 0.50 → Expected ≈ 0.150 wxHOPR,  Probabilistic(0.999) ≈ 0.191 wxHOPR
/// p = 0.01 → Expected ≈ 0.003 wxHOPR,  Probabilistic(0.999) ≈ 0.012 wxHOPR
///             Deterministic stays 0.30 wxHOPR (100× expected drain)
/// ```
pub(crate) fn capacity_to_balance<C: PacketTransport>(
    capacity: ByteSize,
    price: HoprBalance,
    win_prob: f64,
    hops: u32,
    mode: &CapacitySizingMode,
) -> HoprBalance {
    let bytes = capacity.as_u64();
    if bytes == 0 {
        return HoprBalance::zero();
    }

    let payload = C::packet_payload_size() as u64;
    let n = bytes.div_ceil(payload) as f64;
    let p = win_prob.clamp(f64::MIN_POSITIVE, 1.0_f64);
    let h = hops as f64;

    // Effective number of winning tickets the stake must cover.
    let effective_wins: f64 = match mode {
        CapacitySizingMode::Deterministic => n,
        CapacitySizingMode::Expected => n * p,
        CapacitySizingMode::Probabilistic { success_probability } => {
            use statrs::distribution::{ContinuousCDF, Normal};
            let alpha = success_probability.clamp(0.5001, 0.99999);
            let k = Normal::new(0.0, 1.0)
                .expect("standard normal parameters are valid")
                .inverse_cdf(alpha);
            // mean + k · std-dev  (Binomial approximated by Normal via CLT)
            n * p + k * (n * p * (1.0 - p)).sqrt()
        }
    };

    // stake = effective_wins × hops × ticket_price  (saturating; overflow → U256::MAX)
    let price_f64 = price.amount().low_u128() as f64;
    let stake_f64 = (effective_wins * h * price_f64).max(0.0);
    HoprBalance::from(U256::from(stake_f64 as u128))
}

impl FundingConfig {
    /// Resolve all data-capacity fields to wxHOPR amounts at the given ticket
    /// economics.  Called once per pipeline tick.
    ///
    /// `win_prob` must be in `(0, 1]`; it is ignored for
    /// [`CapacitySizingMode::Deterministic`] (pass `1.0` as the conventional
    /// placeholder).
    pub(crate) fn resolve<C: PacketTransport>(&self, price: HoprBalance, win_prob: f64) -> ResolvedFunding {
        let hops = self.assumed_hops;
        let mode = &self.sizing_mode;
        ResolvedFunding {
            initial_balance: capacity_to_balance::<C>(self.initial_capacity, price, win_prob, hops, mode),
            topup_balance: capacity_to_balance::<C>(self.topup_capacity, price, win_prob, hops, mode),
            lower_balance_threshold: capacity_to_balance::<C>(
                self.lower_capacity_threshold,
                price,
                win_prob,
                hops,
                mode,
            ),
            min_safe_balance_required: capacity_to_balance::<C>(
                self.min_safe_capacity_required,
                price,
                win_prob,
                hops,
                mode,
            ),
        }
    }
}

/// Configuration for proactive (predictive) channel funding.
///
/// When enabled the strategy estimates how much the channel balance will drain
/// during the time a funding transaction takes to confirm, and pre-funds if
/// the projected balance after confirmation would fall below the threshold.
#[serde_as]
#[derive(Debug, Clone, PartialEq, smart_default::SmartDefault, Validate, Serialize, Deserialize)]
pub struct ProactiveFundingConfig {
    /// Enable proactive funding.  Default: true.
    #[default = true]
    pub enabled: bool,

    /// Fallback tx-confirmation duration used when
    /// `ChainValues::typical_resolution_time()` fails.  Default: 60 s.
    #[serde(default = "default_fallback_chain_op_duration", with = "humantime_serde")]
    #[default(default_fallback_chain_op_duration())]
    pub fallback_chain_op_duration: Duration,

    /// How far back to look when computing the drain rate.  Default: 10 min.
    #[serde(default = "default_depletion_lookback", with = "humantime_serde")]
    #[default(default_depletion_lookback())]
    pub depletion_lookback: Duration,

    /// Multiplicative safety margin applied to the projected drain.
    /// `1.5` means fund if projected drain is 1.5× the threshold.  Default: 1.5.
    #[default = 1.5]
    pub safety_margin: f64,

    /// Weight of the balance-decrease signal in the drain rate estimate.
    /// Default: 1.0.
    #[default = 1.0]
    pub balance_drain_weight: f64,

    /// Weight of the ticket-index-increase signal (scaled by min ticket price)
    /// in the drain rate estimate.  Default: 1.0.
    #[default = 1.0]
    pub ticket_index_drain_weight: f64,
}

#[inline]
fn default_fallback_chain_op_duration() -> Duration {
    Duration::from_secs(60)
}
#[inline]
fn default_depletion_lookback() -> Duration {
    Duration::from_secs(10 * 60)
}

/// Thresholds that trigger channel closure.
#[serde_as]
#[derive(Debug, Clone, PartialEq, smart_default::SmartDefault, Validate, Serialize, Deserialize)]
pub struct ClosureConfig {
    /// Close a channel after the peer has been absent for this long.  Default: 24 h.
    #[serde(default = "default_close_when_peer_unseen_for", with = "humantime_serde")]
    #[default(default_close_when_peer_unseen_for())]
    pub close_when_peer_unseen_for: Duration,

    /// Close channels to peers whose quality score has dropped below this.
    /// Default: 0.3.
    #[default = 0.3]
    pub close_below_quality_score: f64,

    /// Close channels whose balance has dropped below this amount.  Default: 0.
    #[serde_as(as = "DisplayFromStr")]
    #[default(HoprBalance::zero())]
    pub close_when_drained_below: HoprBalance,

    /// Maximum simultaneous closure transactions initiated per pass.
    /// Default: 2.
    #[default = 2]
    pub close_max_concurrent: usize,
}

#[inline]
fn default_close_when_peer_unseen_for() -> Duration {
    Duration::from_secs(24 * 60 * 60)
}

/// Controls the finalizer phase (second `close_channel` call for `PendingToClose`
/// channels once the notice period has elapsed).
#[serde_as]
#[derive(Debug, Clone, PartialEq, smart_default::SmartDefault, Validate, Serialize, Deserialize)]
pub struct FinalizerConfig {
    /// Enable the finalizer phase.  When `false`, `PendingToClose` channels
    /// are left to be finalized externally.  Default: true.
    #[default = true]
    pub enabled: bool,

    /// Extra time to wait beyond the on-chain notice period before finalizing.
    /// Provides a buffer for slow-block periods.  Default: 30 min.
    #[serde(default = "default_max_closure_overdue", with = "humantime_serde")]
    #[default(default_max_closure_overdue())]
    pub max_closure_overdue: Duration,

    /// Maximum simultaneous finalization transactions initiated per pass.
    /// Default: 4.
    #[default = 4]
    pub finalize_max_concurrent: usize,
}

#[inline]
fn default_max_closure_overdue() -> Duration {
    Duration::from_secs(30 * 60)
}

/// Guards against mass-closing channels on restart (the graph is rebuilt from
/// scratch and peers appear unseen until heartbeats arrive).
#[serde_as]
#[derive(Debug, Clone, PartialEq, smart_default::SmartDefault, Validate, Serialize, Deserialize)]
pub struct RestartGuardConfig {
    /// The close pass is suppressed entirely for this long after startup.
    /// Should exceed network bootstrap time + first heartbeat round.
    /// Default: 10 min.
    #[serde(default = "default_startup_close_grace_period", with = "humantime_serde")]
    #[default(default_startup_close_grace_period())]
    pub startup_close_grace_period: Duration,
}

#[inline]
fn default_startup_close_grace_period() -> Duration {
    Duration::from_secs(10 * 60)
}

/// Concurrency knobs for the per-channel evaluation loops.
#[serde_as]
#[derive(Debug, Clone, PartialEq, smart_default::SmartDefault, Validate, Serialize, Deserialize)]
pub struct ConcurrencyConfig {
    /// Maximum simultaneous in-flight chain-write operations (open + fund +
    /// close + finalize combined).  Additional operations are deferred to the
    /// next tick.  Default: 4.
    #[default = 4]
    pub max_concurrent_actions: usize,
}

/// Per-axis weights for the multi-objective channel selector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SelectorWeights {
    /// Weight of the latency axis.
    pub latency: f64,
    /// Weight of the combined trust axis (probe success + ACK rate + ticket activity).
    pub trust: f64,
    /// Weight of the on-chain stake axis.
    pub stake: f64,
    /// Weight of the anonymity (bucket diversity) axis.
    pub anonymity: f64,
    /// Inner weight for probe success rate within the trust axis.  Default: 0.50.
    pub trust_probe: f64,
    /// Inner weight for ACK rate within the trust axis.  Default: 0.35.
    pub trust_ack: f64,
    /// Inner weight for ticket activity within the trust axis.  Default: 0.15.
    pub trust_ticket: f64,
}

impl SelectorWeights {
    pub const fn new(latency: f64, trust: f64, stake: f64, anonymity: f64) -> Self {
        Self {
            latency,
            trust,
            stake,
            anonymity,
            trust_probe: 0.50,
            trust_ack: 0.35,
            trust_ticket: 0.15,
        }
    }
}

/// Configuration for the multi-objective channel selector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MultiObjectiveSelectorConfig {
    pub weights: SelectorWeights,
    /// Maximum number of opens initiated per strategy tick.  Selector returns at most this many
    /// candidates; the pipeline may dispatch fewer due to safe-balance or concurrency limits.
    pub open_per_tick: usize,
    /// Maximum number of closes initiated per strategy tick.
    pub close_per_tick: usize,
    /// Minimum number of distinct `(latency, subnet)` cells that must be populated among open
    /// channels.  The open pass fills underrepresented cells first; the close pass vetoes closing
    /// the sole occupant of any cell.  `Unknown` subnet peers are excluded from the floor.
    pub k_floor: usize,
    /// Hysteresis gap between the open quality threshold
    /// (`eligibility.min_peer_quality_score`) and the effective close quality
    /// threshold.  The close threshold used by this selector is
    /// `max(0, min_peer_quality_score − hysteresis_gap)`, which is
    /// typically lower than `closure.close_below_quality_score`.  A wider gap
    /// suppresses churn — once open, a channel stays open until quality is
    /// substantially worse than the open bar.
    pub hysteresis_gap: f64,
}

impl MultiObjectiveSelectorConfig {
    pub fn low_latency() -> Self {
        Self {
            weights: SelectorWeights::new(0.70, 0.20, 0.05, 0.05),
            open_per_tick: 4,
            close_per_tick: 4,
            k_floor: 2,
            hysteresis_gap: 0.10,
        }
    }

    pub fn balanced() -> Self {
        Self {
            weights: SelectorWeights::new(0.35, 0.30, 0.15, 0.20),
            open_per_tick: 2,
            close_per_tick: 2,
            k_floor: 3,
            hysteresis_gap: 0.20,
        }
    }

    pub fn dispersed() -> Self {
        Self {
            weights: SelectorWeights::new(0.20, 0.20, 0.10, 0.50),
            open_per_tick: 2,
            close_per_tick: 2,
            k_floor: 4,
            hysteresis_gap: 0.20,
        }
    }

    pub fn economical() -> Self {
        Self {
            weights: SelectorWeights::new(0.30, 0.30, 0.30, 0.10),
            open_per_tick: 1,
            close_per_tick: 1,
            k_floor: 2,
            hysteresis_gap: 0.40,
        }
    }

    /// Returns an error message if the inner trust weights do not approximately sum to 1.0.
    /// Intended for use by `Custom` profile validation.
    pub fn validate_trust_weights(&self) -> Result<(), String> {
        let sum = self.weights.trust_probe + self.weights.trust_ack + self.weights.trust_ticket;
        if (sum - 1.0).abs() > 0.01 {
            Err(format!(
                "trust inner weights must sum to ~1.0 (got {:.4}): probe={}, ack={}, ticket={}",
                sum, self.weights.trust_probe, self.weights.trust_ack, self.weights.trust_ticket
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod config_tests {
    use anyhow::Context as _;
    use rstest::rstest;

    use super::*;

    struct TestTransport;
    impl PacketTransport for TestTransport {
        fn packet_payload_size() -> usize {
            1036
        }
    }

    // ── capacity_to_balance: parameterised unit tests ────────────────────────

    fn balance_from_wei(wei: u128) -> HoprBalance {
        HoprBalance::from(U256::from(wei))
    }

    /// 0.01 wxHOPR in wei  (10^16)
    const PRICE_WEI: u128 = 10_000_000_000_000_000;

    /// Expected stake in wei for `Deterministic` mode: N × hops × price_wei.
    fn det_stake(n_packets: u128, hops: u128) -> u128 {
        n_packets * hops * PRICE_WEI
    }

    /// Expected stake in wei for `Expected` mode: N × p × hops × price_wei.
    fn exp_stake(n_packets: u128, win_prob: f64, hops: u128) -> u128 {
        (n_packets as f64 * win_prob * hops as f64 * PRICE_WEI as f64) as u128
    }

    // ── Deterministic: stake = N × hops × price, win_prob irrelevant ─────────

    /// Vary packet count — Deterministic stake grows linearly with N.
    #[rstest]
    #[case(1,  1, 1 * 1 * PRICE_WEI)]
    #[case(10, 1, 10 * 1 * PRICE_WEI)]
    #[case(100, 1, 100 * 1 * PRICE_WEI)]
    #[case(1000, 1, 1000 * 1 * PRICE_WEI)]
    fn deterministic_scales_with_packet_count(#[case] n_pkts: u64, #[case] hops: u32, #[case] expected_wei: u128) {
        let price = balance_from_wei(PRICE_WEI);
        let cap = ByteSize::b(1036 * n_pkts);
        let result = capacity_to_balance::<TestTransport>(cap, price, 0.5, hops, &CapacitySizingMode::Deterministic);
        assert_eq!(result.amount().low_u128(), expected_wei, "n={n_pkts}");
    }

    /// Vary hop count — Deterministic stake grows linearly with hops.
    #[rstest]
    #[case(1, 10 * 1 * PRICE_WEI)]
    #[case(2, 10 * 2 * PRICE_WEI)]
    #[case(3, 10 * 3 * PRICE_WEI)]
    fn deterministic_scales_with_hops(#[case] hops: u32, #[case] expected_wei: u128) {
        let price = balance_from_wei(PRICE_WEI);
        let cap = ByteSize::b(1036 * 10); // 10 packets
        let result = capacity_to_balance::<TestTransport>(cap, price, 0.01, hops, &CapacitySizingMode::Deterministic);
        assert_eq!(result.amount().low_u128(), expected_wei, "hops={hops}");
    }

    /// Vary win_prob — Deterministic must be invariant.
    #[rstest]
    #[case(0.001)]
    #[case(0.01)]
    #[case(0.1)]
    #[case(0.5)]
    #[case(1.0)]
    fn deterministic_invariant_to_win_prob(#[case] win_prob: f64) {
        let price = balance_from_wei(PRICE_WEI);
        let cap = ByteSize::b(1036 * 10);
        let result = capacity_to_balance::<TestTransport>(cap, price, win_prob, 3, &CapacitySizingMode::Deterministic);
        assert_eq!(result.amount().low_u128(), det_stake(10, 3), "win_prob={win_prob}");
    }

    /// Sub-packet capacity is always rounded up to 1 packet.
    #[rstest]
    #[case(1)]
    #[case(500)]
    #[case(1035)]
    fn deterministic_sub_packet_rounds_up(#[case] bytes: u64) {
        let price = balance_from_wei(PRICE_WEI);
        let result =
            capacity_to_balance::<TestTransport>(ByteSize::b(bytes), price, 1.0, 1, &CapacitySizingMode::Deterministic);
        assert_eq!(result.amount().low_u128(), PRICE_WEI, "bytes={bytes}");
    }

    // ── Expected: stake = N × p × hops × price ───────────────────────────────

    /// Vary win_prob — Expected stake scales linearly with p.
    #[rstest]
    // (win_prob, n_packets, hops) → expected wei (integer truncation)
    #[case(1.0,  10, 3, (10.0 * 1.0 * 3.0 * PRICE_WEI as f64) as u128)]
    #[case(0.5,  10, 3, (10.0 * 0.5 * 3.0 * PRICE_WEI as f64) as u128)]
    #[case(0.1,  10, 3, (10.0 * 0.1 * 3.0 * PRICE_WEI as f64) as u128)]
    #[case(0.01, 10, 3, (10.0 * 0.01 * 3.0 * PRICE_WEI as f64) as u128)]
    fn expected_scales_with_win_prob(
        #[case] win_prob: f64,
        #[case] n: u64,
        #[case] hops: u32,
        #[case] expected_wei: u128,
    ) {
        let price = balance_from_wei(PRICE_WEI);
        let cap = ByteSize::b(1036 * n);
        let result = capacity_to_balance::<TestTransport>(cap, price, win_prob, hops, &CapacitySizingMode::Expected);
        // Allow 1 wei truncation error from f64 arithmetic
        let diff = result.amount().low_u128().abs_diff(expected_wei);
        assert!(
            diff <= 1,
            "win_prob={win_prob}: got {} expected {} (diff={diff})",
            result.amount().low_u128(),
            expected_wei
        );
    }

    /// Expected at win_prob=1.0 must equal Deterministic.
    #[rstest]
    #[case(1, 1)]
    #[case(10, 1)]
    #[case(100, 3)]
    #[case(1000, 2)]
    fn expected_at_full_prob_equals_deterministic(#[case] n_pkts: u64, #[case] hops: u32) {
        let price = balance_from_wei(PRICE_WEI);
        let cap = ByteSize::b(1036 * n_pkts);
        let det = capacity_to_balance::<TestTransport>(cap, price, 1.0, hops, &CapacitySizingMode::Deterministic);
        let exp = capacity_to_balance::<TestTransport>(cap, price, 1.0, hops, &CapacitySizingMode::Expected);
        // 1 wei tolerance for f64 rounding at large N
        let diff = det.amount().low_u128().abs_diff(exp.amount().low_u128());
        assert!(
            diff <= 1,
            "n={n_pkts} hops={hops}: Deterministic={det} Expected={exp} diff={diff}"
        );
    }

    // ── Probabilistic: stake = μ + k·σ ───────────────────────────────────────

    /// At win_prob=1.0 variance is 0 → Probabilistic == Deterministic (±1 wei).
    #[rstest]
    #[case(0.841)]
    #[case(0.977)]
    #[case(0.999)]
    #[case(0.9999)]
    fn probabilistic_at_full_prob_equals_deterministic(#[case] alpha: f64) {
        let price = balance_from_wei(PRICE_WEI);
        let cap = ByteSize::b(1036 * 100);
        let mode = CapacitySizingMode::Probabilistic {
            success_probability: alpha,
        };
        let prob = capacity_to_balance::<TestTransport>(cap, price, 1.0, 3, &mode);
        let det = capacity_to_balance::<TestTransport>(cap, price, 1.0, 3, &CapacitySizingMode::Deterministic);
        let diff = prob.amount().low_u128().abs_diff(det.amount().low_u128());
        assert!(
            diff <= 1,
            "alpha={alpha}: Probabilistic={prob} Deterministic={det} diff={diff}"
        );
    }

    /// Probabilistic > Expected for any win_prob < 1 (k > 0 adds a buffer).
    #[rstest]
    #[case(0.001)]
    #[case(0.01)]
    #[case(0.1)]
    #[case(0.5)]
    fn probabilistic_exceeds_expected(#[case] win_prob: f64) {
        let price = balance_from_wei(PRICE_WEI);
        let cap = ByteSize::b(1036 * 10_000); // large N so σ is significant
        let mode = CapacitySizingMode::Probabilistic {
            success_probability: 0.999,
        };
        let prob = capacity_to_balance::<TestTransport>(cap, price, win_prob, 3, &mode);
        let exp = capacity_to_balance::<TestTransport>(cap, price, win_prob, 3, &CapacitySizingMode::Expected);
        assert!(
            prob > exp,
            "win_prob={win_prob}: Probabilistic={prob} must exceed Expected={exp}"
        );
    }

    /// Probabilistic < Deterministic at low win_prob (the key property).
    #[rstest]
    #[case(0.001)]
    #[case(0.01)]
    #[case(0.05)]
    #[case(0.1)]
    fn probabilistic_below_deterministic_at_low_prob(#[case] win_prob: f64) {
        let price = balance_from_wei(PRICE_WEI);
        let cap = ByteSize::b(1036 * 10_000);
        let mode = CapacitySizingMode::Probabilistic {
            success_probability: 0.999,
        };
        let prob = capacity_to_balance::<TestTransport>(cap, price, win_prob, 3, &mode);
        let det = capacity_to_balance::<TestTransport>(cap, price, win_prob, 3, &CapacitySizingMode::Deterministic);
        assert!(
            prob < det,
            "win_prob={win_prob}: Probabilistic={prob} must be < Deterministic={det}"
        );
    }

    /// Higher confidence → larger stake (monotone in alpha).
    #[rstest]
    #[case(0.5, 0.9)]
    #[case(0.9, 0.99)]
    #[case(0.99, 0.999)]
    #[case(0.999, 0.9999)]
    fn probabilistic_monotone_in_confidence(#[case] alpha_lo: f64, #[case] alpha_hi: f64) {
        let price = balance_from_wei(PRICE_WEI);
        let cap = ByteSize::b(1036 * 10_000);
        let lo = capacity_to_balance::<TestTransport>(
            cap,
            price,
            0.1,
            3,
            &CapacitySizingMode::Probabilistic {
                success_probability: alpha_lo,
            },
        );
        let hi = capacity_to_balance::<TestTransport>(
            cap,
            price,
            0.1,
            3,
            &CapacitySizingMode::Probabilistic {
                success_probability: alpha_hi,
            },
        );
        assert!(
            hi > lo,
            "alpha_hi={alpha_hi} must give larger stake than alpha_lo={alpha_lo}"
        );
    }

    /// Vary hops — all three modes scale linearly with hops.
    #[rstest]
    #[case(CapacitySizingMode::Deterministic, 0.5)]
    #[case(CapacitySizingMode::Expected, 0.5)]
    #[case(CapacitySizingMode::Probabilistic { success_probability: 0.999 }, 0.5)]
    fn all_modes_scale_linearly_with_hops(#[case] mode: CapacitySizingMode, #[case] win_prob: f64) {
        let price = balance_from_wei(PRICE_WEI);
        let cap = ByteSize::b(1036 * 1000);
        let h1 = capacity_to_balance::<TestTransport>(cap, price, win_prob, 1, &mode);
        let h2 = capacity_to_balance::<TestTransport>(cap, price, win_prob, 2, &mode);
        let h3 = capacity_to_balance::<TestTransport>(cap, price, win_prob, 3, &mode);
        // Linear: h2 ≈ 2×h1, h3 ≈ 3×h1 (within 2 wei for f64 rounding in prob mode)
        let diff2 = h2.amount().low_u128().abs_diff(h1.amount().low_u128() * 2);
        let diff3 = h3.amount().low_u128().abs_diff(h1.amount().low_u128() * 3);
        assert!(diff2 <= 2, "{mode:?}: 2-hop={h2} should be 2×1-hop={h1} (diff={diff2})");
        assert!(diff3 <= 2, "{mode:?}: 3-hop={h3} should be 3×1-hop={h1} (diff={diff3})");
    }

    // ── Ordering invariant: Expected ≤ Probabilistic ≤ Deterministic ─────────

    /// For all win_prob ∈ (0,1): Expected ≤ Probabilistic(0.999) ≤ Deterministic.
    #[rstest]
    #[case(0.001, 1_000)]
    #[case(0.01, 10_000)]
    #[case(0.1, 100_000)]
    #[case(0.5, 1_000_000)]
    fn ordering_expected_le_probabilistic_le_deterministic(#[case] win_prob: f64, #[case] n_pkts: u64) {
        let price = balance_from_wei(PRICE_WEI);
        let cap = ByteSize::b(1036 * n_pkts);
        let exp = capacity_to_balance::<TestTransport>(cap, price, win_prob, 3, &CapacitySizingMode::Expected);
        let prob = capacity_to_balance::<TestTransport>(
            cap,
            price,
            win_prob,
            3,
            &CapacitySizingMode::Probabilistic {
                success_probability: 0.999,
            },
        );
        let det = capacity_to_balance::<TestTransport>(cap, price, win_prob, 3, &CapacitySizingMode::Deterministic);
        assert!(
            exp <= prob,
            "win_prob={win_prob}: Expected={exp} must be ≤ Probabilistic={prob}"
        );
        assert!(
            prob <= det,
            "win_prob={win_prob}: Probabilistic={prob} must be ≤ Deterministic={det}"
        );
    }

    // ── FundingConfig::resolve ───────────────────────────────────────────────

    #[test]
    fn resolve_maps_all_four_fields() {
        let cfg = FundingConfig::default();
        let price = balance_from_wei(PRICE_WEI);
        let win_prob = 0.5_f64;
        let resolved = cfg.resolve::<TestTransport>(price, win_prob);

        assert_eq!(
            resolved.initial_balance,
            capacity_to_balance::<TestTransport>(
                cfg.initial_capacity,
                price,
                win_prob,
                cfg.assumed_hops,
                &cfg.sizing_mode
            )
        );
        assert_eq!(
            resolved.topup_balance,
            capacity_to_balance::<TestTransport>(
                cfg.topup_capacity,
                price,
                win_prob,
                cfg.assumed_hops,
                &cfg.sizing_mode
            )
        );
        assert_eq!(
            resolved.lower_balance_threshold,
            capacity_to_balance::<TestTransport>(
                cfg.lower_capacity_threshold,
                price,
                win_prob,
                cfg.assumed_hops,
                &cfg.sizing_mode
            )
        );
        assert_eq!(
            resolved.min_safe_balance_required,
            capacity_to_balance::<TestTransport>(
                cfg.min_safe_capacity_required,
                price,
                win_prob,
                cfg.assumed_hops,
                &cfg.sizing_mode
            )
        );
    }

    // ── defaults & validation ────────────────────────────────────────────────

    #[test]
    fn default_sizing_mode_is_probabilistic_999() {
        match FundingConfig::default().sizing_mode {
            CapacitySizingMode::Probabilistic { success_probability } => {
                assert!((success_probability - 0.999).abs() < 1e-9);
            }
            other => panic!("expected Probabilistic, got {other:?}"),
        }
    }

    #[test]
    fn requires_win_prob_returns_false_only_for_deterministic() {
        assert!(!CapacitySizingMode::Deterministic.requires_win_prob());
        assert!(CapacitySizingMode::Expected.requires_win_prob());
        assert!(
            CapacitySizingMode::Probabilistic {
                success_probability: 0.999
            }
            .requires_win_prob()
        );
    }

    #[test]
    fn default_config_passes_validation() {
        use validator::Validate as _;
        assert!(FundingConfig::default().validate().is_ok());
    }

    #[test]
    fn assumed_hops_zero_is_rejected() {
        use validator::Validate as _;
        let mut cfg = FundingConfig::default();
        cfg.assumed_hops = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn default_assumed_hops_is_three() {
        assert_eq!(FundingConfig::default().assumed_hops, 3);
    }

    // ── Serde round-trips ─────────────────────────────────────────────────────

    #[test]
    fn funding_config_serde_roundtrip_probabilistic() -> anyhow::Result<()> {
        let cfg = FundingConfig {
            initial_capacity: ByteSize::gib(5),
            topup_capacity: ByteSize::mib(512),
            lower_capacity_threshold: ByteSize::mib(128),
            min_safe_capacity_required: ByteSize::gib(2),
            stop_when_unfunded: false,
            assumed_hops: 2,
            sizing_mode: CapacitySizingMode::Probabilistic {
                success_probability: 0.9999,
            },
        };
        let json = serde_json::to_string(&cfg).context("serialize")?;
        let back: FundingConfig = serde_json::from_str(&json).context("deserialize")?;
        assert_eq!(cfg, back);
        Ok(())
    }

    #[test]
    fn funding_config_serde_roundtrip_deterministic() -> anyhow::Result<()> {
        let cfg = FundingConfig {
            sizing_mode: CapacitySizingMode::Deterministic,
            ..FundingConfig::default()
        };
        let json = serde_json::to_string(&cfg).context("serialize")?;
        let back: FundingConfig = serde_json::from_str(&json).context("deserialize")?;
        assert_eq!(cfg, back);
        Ok(())
    }

    #[test]
    fn sizing_mode_serde_external_tag() -> anyhow::Result<()> {
        // Unit variants round-trip as plain strings.
        let det: CapacitySizingMode = serde_json::from_str(r#""deterministic""#)?;
        assert_eq!(det, CapacitySizingMode::Deterministic);
        let exp: CapacitySizingMode = serde_json::from_str(r#""expected""#)?;
        assert_eq!(exp, CapacitySizingMode::Expected);
        // Struct variant uses {"probabilistic": {fields}} in JSON /
        // `probabilistic:\n  success_probability: 0.999` in YAML.
        let prob: CapacitySizingMode = serde_json::from_str(r#"{"probabilistic":{"success_probability":0.99}}"#)?;
        assert_eq!(
            prob,
            CapacitySizingMode::Probabilistic {
                success_probability: 0.99
            }
        );
        Ok(())
    }

    // ── MultiObjectiveSelectorConfig tests ───────────────────────────────────

    #[test]
    fn all_named_profiles_have_valid_trust_weights() {
        for cfg in [
            MultiObjectiveSelectorConfig::low_latency(),
            MultiObjectiveSelectorConfig::balanced(),
            MultiObjectiveSelectorConfig::dispersed(),
            MultiObjectiveSelectorConfig::economical(),
        ] {
            assert!(
                cfg.validate_trust_weights().is_ok(),
                "profile has invalid trust weights: {:?}",
                cfg.validate_trust_weights()
            );
        }
    }

    #[test]
    fn invalid_trust_weights_are_caught() {
        let mut cfg = MultiObjectiveSelectorConfig::low_latency();
        cfg.weights.trust_probe = 0.9;
        cfg.weights.trust_ack = 0.9;
        cfg.weights.trust_ticket = 0.9; // sum = 2.7
        assert!(cfg.validate_trust_weights().is_err());
    }
}

/// Selector profile selection for [`ChannelLifecycleConfig`].
///
/// Defaults to `Default` (existing `DefaultSelector` behavior, zero behavior change).
/// Operators opt in to multi-objective selection by choosing a named profile or `Custom`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectorProfile {
    /// Original weighted-sum selector.  Zero behavior change from pre-redesign deployments.
    #[default]
    Default,
    LowLatency,
    Balanced,
    Dispersed,
    Economical,
    Custom(MultiObjectiveSelectorConfig),
}

impl SelectorProfile {
    /// Returns the `MultiObjectiveSelectorConfig` for this profile, or `None` for `Default`.
    pub fn multi_objective_config(&self) -> Option<MultiObjectiveSelectorConfig> {
        match self {
            Self::Default => None,
            Self::LowLatency => Some(MultiObjectiveSelectorConfig::low_latency()),
            Self::Balanced => Some(MultiObjectiveSelectorConfig::balanced()),
            Self::Dispersed => Some(MultiObjectiveSelectorConfig::dispersed()),
            Self::Economical => Some(MultiObjectiveSelectorConfig::economical()),
            Self::Custom(cfg) => Some(cfg.clone()),
        }
    }
}

/// Top-level configuration for [`ChannelLifecycleStrategy`].
///
/// All fields have sensible defaults; consumers only need to set the fields
/// they want to override.
#[serde_as]
#[derive(Debug, Clone, PartialEq, smart_default::SmartDefault, Validate, Serialize, Deserialize)]
pub struct ChannelLifecycleConfig {
    /// Base period between full evaluation passes.  Default: 60 s.
    #[serde(default = "default_tick_interval", with = "humantime_serde")]
    #[default(default_tick_interval())]
    pub tick_interval: Duration,

    /// Maximum random offset added to the tick interval to spread out
    /// concurrent node restarts.  Implemented as a deterministic offset based
    /// on the current system time nanoseconds.  Default: 5 s.
    #[serde(default = "default_jitter", with = "humantime_serde")]
    #[default(default_jitter())]
    pub jitter: Duration,

    pub population: PopulationConfig,
    pub eligibility: EligibilityConfig,
    pub funding: FundingConfig,
    pub proactive_funding: ProactiveFundingConfig,
    pub closure: ClosureConfig,
    pub finalizer: FinalizerConfig,
    pub restart: RestartGuardConfig,
    pub concurrency: ConcurrencyConfig,
    /// Open/close selection policy.  Defaults to the original weighted-sum selector.
    #[default(SelectorProfile::Default)]
    pub selector: SelectorProfile,
}

#[inline]
fn default_tick_interval() -> Duration {
    Duration::from_secs(60)
}
#[inline]
fn default_jitter() -> Duration {
    Duration::from_secs(5)
}
