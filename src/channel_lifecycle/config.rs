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
#[serde(default, deny_unknown_fields)]
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
    #[serde(with = "humantime_serde")]
    #[default(Duration::from_secs(30 * 60))]
    pub peer_reopen_cooldown: Duration,
}

/// Peer eligibility filters for channel opening and for determining staleness.
#[serde_as]
#[derive(Debug, Clone, PartialEq, smart_default::SmartDefault, Validate, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
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
/// # Ticket economics
///
/// A packet relayed over an `h`-hop path is paid for with probabilistic
/// tickets.  On-chain (`HoprTicketFactory`), a single winning ticket's face
/// value is
///
/// ```text
/// face_value = ticket_price × hops / win_prob
/// ```
///
/// i.e. per packet the sender issues **one** aggregated multi-hop ticket of face
/// value `ticket_price × hops / win_prob` against this channel (not `h`
/// independent tickets) — a large, indivisible amount redeemed with probability
/// `win_prob`.  The winning tickets over `N` packets are therefore a single
/// `Binomial(N, win_prob)`, and the total channel drain `D` is that count scaled
/// by one face value:
///
/// ```text
/// D    = (ticket_price × hops / win_prob) × Binomial(N, win_prob)
/// E[D] = N × hops × ticket_price                              (win-prob independent)
/// σ[D] = hops × ticket_price × √(N × (1 − win_prob) / win_prob)
/// ```
///
/// Note `E[D]` does **not** depend on `win_prob`: lower win-prob means rarer but
/// proportionally larger payouts, so the mean drain is unchanged while the
/// variance grows as `1 / win_prob`.
///
/// # The one-winning-ticket floor (applies to every mode)
///
/// A channel cannot even *issue* a ticket whose face value exceeds its balance
/// — the factory returns `OutOfFunds`.  Every resolved stake is therefore
/// floored at a single full-path winning ticket:
///
/// ```text
/// stake = max( ticket_price × hops / win_prob ,  <mode term> )
/// ```
///
/// Without this floor, at HOPR's production win-probs (1e-4 … 1e-6) a stake
/// sized to the *mean* drain can be smaller than one ticket, leaving the
/// channel unable to relay a single packet.  The floor guarantees every field —
/// initial, top-up, and lower threshold — always covers ≥ 1 winning ticket.
///
/// # Modes
///
/// Both modes are floored as above; they differ only in the buffer added above
/// the mean drain.  At `win_prob = 1.0` the variance vanishes (`σ = 0`) and both
/// collapse to `N × hops × ticket_price`.
///
/// # Configuration (YAML)
///
/// ```yaml
/// # Mean-drain stake (default); floored at one winning ticket.
/// sizing_mode: deterministic
///
/// # Statistical guarantee; adds k·σ above the mean drain.
/// sizing_mode:
///   probabilistic:
///     success_probability: 0.999
///
/// # `success_probability` is optional (defaults to 0.999), but the empty map is
/// # required — a struct variant cannot be named on its own.
/// sizing_mode:
///   probabilistic: {}
/// ```
#[derive(Debug, Clone, PartialEq, smart_default::SmartDefault, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CapacitySizingMode {
    /// `stake = max( ticket_price × hops / win_prob ,  N × hops × ticket_price )`
    ///
    /// Sizes the stake to the **expected** drain `N × hops × ticket_price`,
    /// floored at one winning ticket.  The main term is independent of
    /// `win_prob`, so the stake is insensitive to win-prob fluctuations; the
    /// floor is the only win-prob-dependent part.
    ///
    /// This is the **default**.  Because payouts are lumpy, roughly half of all
    /// fund cycles see the channel drain slightly faster than the mean — this
    /// triggers a top-up sooner (handled by proactive funding), never message
    /// loss, as long as the balance stays above the one-ticket floor.
    ///
    /// ```yaml
    /// sizing_mode: deterministic
    /// ```
    #[default]
    Deterministic,

    /// `stake = max( ticket_price × hops / win_prob ,  E[D] + k·σ[D] )`
    /// where `k = Φ⁻¹(success_probability)`,
    /// `E[D] = N × hops × ticket_price` and
    /// `σ[D] = hops × ticket_price × √(N × (1 − win_prob) / win_prob)`.
    ///
    /// Adds `k` standard deviations on top of the mean drain so the channel
    /// carries its full configured capacity between top-ups with probability
    /// `success_probability`.  Costs more capital than `Deterministic` and, at
    /// low win-prob, the `1 / win_prob` variance makes the buffer large — use
    /// when premature top-ups must be minimised on high-value paths.
    ///
    /// # Worked example — default confidence (k ≈ 3.09)
    ///
    /// Parameters: N = 100 000 packets, win_prob = 0.01, hops = 3,
    /// ticket_price = 0.01 wxHOPR.
    ///
    /// ```text
    /// E[D]  = N × h × tp                       = 3,000 wxHOPR
    /// σ[D]  = h × tp × √(N × (1−p)/p)           ≈ 94.39 wxHOPR
    /// stake ≈ 3,000 + 3.09 × 94.39             ≈ 3,292 wxHOPR
    /// ```
    ///
    /// At `win_prob = 1.0` the variance term vanishes and the formula collapses
    /// to `N × hops × ticket_price` — identical to `Deterministic`.
    ///
    /// ```yaml
    /// sizing_mode:
    ///   probabilistic:
    ///     success_probability: 0.999
    /// ```
    Probabilistic {
        /// Probability that the channel does **not** drain prematurely in any
        /// given fund cycle.  Must be in the range `(0.5, 1.0)`.
        ///
        /// | value  | k (z-score) | notes |
        /// |--------|-------------|-------|
        /// | 0.841  | 1.0  | one-sigma; adequate for large N |
        /// | 0.977  | 2.0  | two-sigma |
        /// | 0.999  | 3.09 | recommended for most deployments |
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

fn validate_sizing_mode(mode: &CapacitySizingMode) -> Result<(), validator::ValidationError> {
    if let CapacitySizingMode::Probabilistic { success_probability } = mode
        && !(*success_probability >= 0.5001 && *success_probability <= 0.99999)
    {
        return Err(validator::ValidationError::new(
            "success_probability must be in (0.5001, 0.99999)",
        ));
    }
    Ok(())
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
/// ```yaml
/// initial_capacity: 1 GiB
/// topup_capacity: 1 GiB
/// lower_capacity_threshold: 256 MiB
/// min_safe_capacity_required: 1 GiB
/// assumed_hops: 3
/// sizing_mode: deterministic
/// ```
///
/// With `ticket_price = 0.001 wxHOPR` and `win_prob = 0.001` the default
/// `Deterministic` mode resolves `initial_capacity` to:
///
/// ```text
/// N_initial = ceil(1 GiB / 1036 B)          = 1 036 431 packets
/// E[D]      = N × hops × tp = 1 036 431 × 3 × 0.001 ≈ 3 109 wxHOPR
/// floor     = tp × hops / p = 0.001 × 3 / 0.001     = 3 wxHOPR
/// stake     = max(floor, E[D])              ≈ 3 109 wxHOPR   (mean drain; floor inert)
/// ```
///
/// The floor only binds for tiny capacities (`N < 1 / win_prob`), where it lifts
/// the stake up to one winning ticket so the channel can still relay.
#[derive(Debug, Clone, PartialEq, smart_default::SmartDefault, Validate, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FundingConfig {
    /// Data volume a newly opened channel's stake should be able to carry.
    /// Default: 1 GiB.
    #[default(ByteSize::gib(1))]
    pub initial_capacity: ByteSize,

    /// Data volume added to a channel's stake when it is topped up.
    /// Default: 1 GiB.
    #[default(ByteSize::gib(1))]
    pub topup_capacity: ByteSize,

    /// The channel balance (expressed as data capacity) below which a top-up is
    /// triggered.  Default: 256 MiB.
    #[default(ByteSize::mib(256))]
    pub lower_capacity_threshold: ByteSize,

    /// Minimum safe balance (expressed as data capacity) required before the
    /// strategy opens or funds any channel.  Default: 1 GiB.
    #[default(ByteSize::gib(1))]
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
    /// Default: `Deterministic` (mean drain, floored at one winning ticket).
    ///
    /// See [`CapacitySizingMode`] for the full tradeoff analysis.
    #[default(CapacitySizingMode::default())]
    #[validate(custom(function = "validate_sizing_mode"))]
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
/// p     = win_prob  (clamped to [ε, 1])
/// h     = hops
/// tp    = ticket_price
///
/// floor = tp × h / p                         one full-path winning ticket
/// E[D]  = N × h × tp                          mean drain (win-prob independent)
/// σ[D]  = tp × h × √(N × (1 − p) / p)         (tp·h/p) × Binomial(N, p) std-dev
///
/// Deterministic:    stake = max(floor, E[D])
/// Probabilistic(α): stake = max(floor, E[D] + k·σ[D])   k = Φ⁻¹(α)
/// ```
///
/// The `max(floor, …)` guarantees the stake always covers at least one winning
/// ticket, so the channel can always issue the next ticket regardless of how
/// small the capacity is or how low `win_prob` is.  Returns
/// [`HoprBalance::zero`] only for zero capacity.
///
/// # Examples
///
/// ```text
/// tp = 0.01 wxHOPR,  h = 3
///
/// N = 100 000, p = 0.01:  floor = 3 wxHOPR
///     Deterministic  = max(3, 3,000)                 = 3,000 wxHOPR
///     Probabilistic  = max(3, 3,000 + 3.09 × 94.39)  ≈ 3,292 wxHOPR
///
/// N = 10, p = 1e-4:  floor = tp·h/p = 300 wxHOPR  (dominates)
///     Deterministic  = max(300, 0.3)                 = 300 wxHOPR   (floor binds)
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
    // Clamp win_prob into [f64::EPSILON, 1.0].  Zero, negative, or NaN inputs
    // would otherwise make the one-ticket floor `tp × h / p` diverge to
    // `f64::INFINITY` and saturate the stake to `u128::MAX`.  `f64::MIN_POSITIVE`
    // is too small a lower bound — `tp × h / p` overflows f64 — so `f64::EPSILON`
    // is used as the effective floor on the win probability.
    let p = if win_prob.is_nan() {
        f64::EPSILON
    } else {
        win_prob.clamp(f64::EPSILON, 1.0_f64)
    };
    let h = hops as f64;
    let price_f64 = price.amount().low_u128() as f64;

    // Mean drain E[D] = N × h × tp — the same for every mode, independent of p.
    let mean_drain = n * h * price_f64;

    // Mode-specific term above the mean.
    let target: f64 = match mode {
        CapacitySizingMode::Deterministic => mean_drain,
        CapacitySizingMode::Probabilistic { success_probability } => {
            use statrs::distribution::{ContinuousCDF, Normal};
            let alpha = success_probability.clamp(0.5001, 0.99999);
            let k = Normal::standard().inverse_cdf(alpha);
            // σ[D] = tp·h × √(N·(1−p)/p).  Each packet issues ONE aggregated
            // multi-hop ticket of face value tp·h/p (not h independent tickets),
            // so the number of winning tickets is Binomial(N, p) and the drain is
            // (tp·h/p)·Binomial(N, p).  Var = (tp·h/p)²·N·p(1−p) ⇒ σ = tp·h·√(N(1−p)/p).
            let sigma = price_f64 * h * (n * (1.0 - p) / p).sqrt();
            mean_drain + k * sigma
        }
    };

    // One-winning-ticket floor: the channel must always be able to issue a
    // full-path ticket of face value tp × h / p, or it cannot relay at all.
    let floor = price_f64 * h / p;

    // Round up: the one-ticket floor is a strict safety guarantee (the on-chain
    // face value is integer wei), so a downward-truncating cast could yield a
    // stake one wei below face value and still trip `OutOfFunds`.
    let stake_f64 = target.max(floor).max(0.0);
    HoprBalance::from(U256::from(stake_f64.ceil() as u128))
}

impl FundingConfig {
    /// Resolve all data-capacity fields to wxHOPR amounts at the given ticket
    /// economics.  Called once per pipeline tick.
    ///
    /// `win_prob` must be in `(0, 1]`.  Every mode uses it to compute the
    /// one-winning-ticket floor, so it is always required.
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
#[serde(default, deny_unknown_fields)]
pub struct ProactiveFundingConfig {
    /// Enable proactive funding.  Default: true.
    #[default = true]
    pub enabled: bool,

    /// Fallback tx-confirmation duration used when
    /// `ChainValues::typical_resolution_time()` fails.  Default: 60 s.
    #[serde(with = "humantime_serde")]
    #[default(Duration::from_secs(60))]
    pub fallback_chain_op_duration: Duration,

    /// How far back to look when computing the drain rate.  Default: 10 min.
    #[serde(with = "humantime_serde")]
    #[default(Duration::from_secs(10 * 60))]
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

/// Thresholds that trigger channel closure.
#[serde_as]
#[derive(Debug, Clone, PartialEq, smart_default::SmartDefault, Validate, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClosureConfig {
    /// Close a channel after the peer has been absent for this long.  Default: 24 h.
    #[serde(with = "humantime_serde")]
    #[default(Duration::from_secs(24 * 60 * 60))]
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

/// Controls the finalizer phase (second `close_channel` call for `PendingToClose`
/// channels once the notice period has elapsed).
#[serde_as]
#[derive(Debug, Clone, PartialEq, smart_default::SmartDefault, Validate, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FinalizerConfig {
    /// Enable the finalizer phase.  When `false`, `PendingToClose` channels
    /// are left to be finalized externally.  Default: true.
    #[default = true]
    pub enabled: bool,

    /// Extra time to wait beyond the on-chain notice period before finalizing.
    /// Provides a buffer for slow-block periods.  Default: 30 min.
    #[serde(with = "humantime_serde")]
    #[default(Duration::from_secs(30 * 60))]
    pub max_closure_overdue: Duration,

    /// Maximum simultaneous finalization transactions initiated per pass.
    /// Default: 4.
    #[default = 4]
    pub finalize_max_concurrent: usize,
}

/// Guards against mass-closing channels on restart (the graph is rebuilt from
/// scratch and peers appear unseen until heartbeats arrive).
#[serde_as]
#[derive(Debug, Clone, PartialEq, smart_default::SmartDefault, Validate, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RestartGuardConfig {
    /// The close pass is suppressed entirely for this long after startup.
    /// Should exceed network bootstrap time + first heartbeat round.
    /// Default: 10 min.
    #[serde(with = "humantime_serde")]
    #[default(Duration::from_secs(10 * 60))]
    pub startup_close_grace_period: Duration,
}

/// Concurrency knobs for the per-channel evaluation loops.
#[serde_as]
#[derive(Debug, Clone, PartialEq, smart_default::SmartDefault, Validate, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConcurrencyConfig {
    /// Maximum simultaneous in-flight chain-write operations (open + fund +
    /// close + finalize combined).  Additional operations are deferred to the
    /// next tick.  Default: 4.
    #[default = 4]
    pub max_concurrent_actions: usize,
}

/// Per-axis weights for the multi-objective channel selector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
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

impl Default for SelectorWeights {
    fn default() -> Self {
        Self::BALANCED
    }
}

impl SelectorWeights {
    /// Axis weights of the [`balanced`](MultiObjectiveSelectorConfig::balanced)
    /// profile, and the [`Default`] for this type.
    ///
    /// ```
    /// # use hopr_strategy::channel_lifecycle::{MultiObjectiveSelectorConfig, SelectorWeights};
    /// // The default weights are the balanced profile's weights.
    /// assert_eq!(SelectorWeights::BALANCED, SelectorWeights::default());
    /// assert_eq!(
    ///     SelectorWeights::BALANCED,
    ///     MultiObjectiveSelectorConfig::balanced().weights
    /// );
    ///
    /// // Start from them and tune a single axis.
    /// let mut weights = SelectorWeights::BALANCED;
    /// weights.latency = 0.50;
    /// assert_eq!(weights.anonymity, SelectorWeights::BALANCED.anonymity);
    /// ```
    pub const BALANCED: Self = Self::new(0.35, 0.30, 0.15, 0.20);

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
#[serde(default, deny_unknown_fields)]
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

impl Default for MultiObjectiveSelectorConfig {
    /// The [`balanced`](MultiObjectiveSelectorConfig::balanced) profile.
    fn default() -> Self {
        Self::balanced()
    }
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
            weights: SelectorWeights::BALANCED,
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

    // ── capacity_to_balance: helpers ─────────────────────────────────────────

    const PAYLOAD: u64 = 1036;
    /// 0.01 wxHOPR in wei (10^16).
    const PRICE_WEI: u128 = 10_000_000_000_000_000;

    fn balance_from_wei(wei: u128) -> HoprBalance {
        HoprBalance::from(U256::from(wei))
    }

    fn packets(bytes: u64) -> u128 {
        bytes.div_ceil(PAYLOAD) as u128
    }

    /// One full-path winning ticket face value in wei: `tp × hops / p`.
    fn floor_wei(tp_wei: u128, hops: u32, p: f64) -> u128 {
        (tp_wei as f64 * hops as f64 / p) as u128
    }

    /// Mean drain in wei: `N × hops × tp`.
    fn mean_wei(n: u128, hops: u32, tp_wei: u128) -> u128 {
        n * hops as u128 * tp_wei
    }

    /// Φ⁻¹(alpha) — the z-score used by `Probabilistic`.
    fn z_score(alpha: f64) -> f64 {
        use statrs::distribution::{ContinuousCDF, Normal};
        Normal::standard().inverse_cdf(alpha)
    }

    fn stake_wei(cap: ByteSize, tp_wei: u128, p: f64, hops: u32, mode: &CapacitySizingMode) -> u128 {
        capacity_to_balance::<TestTransport>(cap, balance_from_wei(tp_wei), p, hops, mode)
            .amount()
            .low_u128()
    }

    /// Assert `got ≈ want` with a 1e-9 relative + 4 wei absolute tolerance
    /// (accounts for the f64 round-trip inside `capacity_to_balance`).
    fn assert_close(got: u128, want: u128, ctx: &str) {
        let hi = got.max(want);
        let lo = got.min(want);
        let tol = (hi / 1_000_000_000).max(4);
        assert!(
            hi - lo <= tol,
            "{ctx}: got {got} want {want} (diff {}, tol {tol})",
            hi - lo
        );
    }

    const DET: CapacitySizingMode = CapacitySizingMode::Deterministic;
    fn prob(alpha: f64) -> CapacitySizingMode {
        CapacitySizingMode::Probabilistic {
            success_probability: alpha,
        }
    }

    // Live-network parameters used across regression tests.
    const JURA_TP: u128 = 10_000_000_000_000; // 1e13 wei = 1e-5 wxHOPR
    const JURA_P: f64 = 4.0e-6; // 288230376143 / (2^56 - 1)
    const ROTSEE_TP: u128 = 100; // 1e-16 wxHOPR
    const ROTSEE_P: f64 = 1.25e-4; // 9007199254735 / (2^56 - 1)

    // ── Deterministic: stake = max(floor, N × hops × tp) ─────────────────────

    /// Above the floor, Deterministic equals the mean drain and grows linearly
    /// with packet count.  (p = 0.5 keeps the floor small.)
    #[rstest]
    #[case(10)]
    #[case(100)]
    #[case(1_000)]
    #[case(100_000)]
    fn deterministic_equals_mean_drain_above_floor(#[case] n_pkts: u64) {
        let cap = ByteSize::b(PAYLOAD * n_pkts);
        let got = stake_wei(cap, PRICE_WEI, 0.5, 3, &DET);
        assert_close(got, mean_wei(n_pkts as u128, 3, PRICE_WEI), &format!("n={n_pkts}"));
    }

    /// Above the floor, Deterministic scales linearly with hops.
    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn deterministic_scales_with_hops(#[case] hops: u32) {
        let cap = ByteSize::b(PAYLOAD * 100_000);
        let got = stake_wei(cap, PRICE_WEI, 0.5, hops, &DET);
        assert_close(got, mean_wei(100_000, hops, PRICE_WEI), &format!("hops={hops}"));
    }

    /// The mean-drain term is win-prob independent: as long as it stays above the
    /// floor (N > 1/p), varying win_prob leaves the stake unchanged.
    #[rstest]
    #[case(0.01)]
    #[case(0.1)]
    #[case(0.5)]
    #[case(1.0)]
    fn deterministic_mean_invariant_to_win_prob_above_floor(#[case] p: f64) {
        // N = 1e6 ≫ 1/p for every p above, so the floor never binds.
        let cap = ByteSize::b(PAYLOAD * 1_000_000);
        let got = stake_wei(cap, PRICE_WEI, p, 3, &DET);
        assert_close(got, mean_wei(1_000_000, 3, PRICE_WEI), &format!("p={p}"));
    }

    /// Sub-packet capacity rounds up to exactly one packet.
    #[rstest]
    #[case(1)]
    #[case(500)]
    #[case(1035)]
    fn sub_packet_rounds_up_to_one_packet(#[case] bytes: u64) {
        // p = 1.0 → floor = tp·h = mean for N=1, so stake = tp·h.
        let got = stake_wei(ByteSize::b(bytes), PRICE_WEI, 1.0, 1, &DET);
        assert_eq!(got, PRICE_WEI, "bytes={bytes}");
    }

    // ── The one-winning-ticket floor (the core fix) ──────────────────────────

    /// When the capacity is worth less than one winning ticket (`N < 1/p`), the
    /// floor binds and the stake equals exactly one full-path ticket face value.
    #[rstest]
    // (n_pkts, p) chosen so N·h·tp < tp·h/p  ⟺  N < 1/p
    #[case(1, 1.0e-4)]
    #[case(10, 1.0e-4)]
    #[case(1_000, 4.0e-6)] // jura-like: 1/p = 250 000 ≫ 1 000
    #[case(1, 1.0e-9)]
    fn floor_binds_below_one_ticket(#[case] n_pkts: u64, #[case] p: f64) {
        let cap = ByteSize::b(PAYLOAD * n_pkts);
        let want_floor = floor_wei(PRICE_WEI, 3, p);
        let got = stake_wei(cap, PRICE_WEI, p, 3, &DET);
        assert_close(got, want_floor, &format!("n={n_pkts} p={p}"));
        // And it must be ≥ one ticket by construction.
        assert!(
            got >= want_floor - 4,
            "n={n_pkts} p={p}: {got} below one ticket {want_floor}"
        );
    }

    /// Both modes always fund at least one winning ticket, for any capacity,
    /// win_prob and ticket price — the invariant the floor guarantees.
    #[test]
    fn never_below_one_winning_ticket() {
        let ps = [1.0, 0.5, 0.1, 1e-2, 1e-3, ROTSEE_P, JURA_P, 1e-8];
        let tps = [1u128, 100, PRICE_WEI, JURA_TP, 1_000_000_000_000_000_000];
        let caps = [
            ByteSize::b(1),
            ByteSize::b(PAYLOAD),
            ByteSize::mib(256),
            ByteSize::gib(1),
        ];
        for &p in &ps {
            for &tp in &tps {
                for &cap in &caps {
                    let floor = floor_wei(tp, 3, p);
                    for mode in [DET, prob(0.999)] {
                        let got = stake_wei(cap, tp, p, 3, &mode);
                        assert!(
                            got + 4 >= floor,
                            "{mode:?} p={p} tp={tp} cap={cap:?}: stake {got} < one ticket {floor}"
                        );
                    }
                }
            }
        }
    }

    /// The floor is applied independently to every FundingConfig field, so even
    /// with 1-byte capacities every resolved balance covers one winning ticket.
    #[test]
    fn floor_applies_to_all_four_fields() {
        let cfg = FundingConfig {
            initial_capacity: ByteSize::b(1),
            topup_capacity: ByteSize::b(1),
            lower_capacity_threshold: ByteSize::b(1),
            min_safe_capacity_required: ByteSize::b(1),
            ..FundingConfig::default()
        };
        let floor = floor_wei(JURA_TP, 3, JURA_P);
        let r = cfg.resolve::<TestTransport>(balance_from_wei(JURA_TP), JURA_P);
        for (name, bal) in [
            ("initial", r.initial_balance),
            ("topup", r.topup_balance),
            ("lower_threshold", r.lower_balance_threshold),
            ("min_safe", r.min_safe_balance_required),
        ] {
            assert_close(bal.amount().low_u128(), floor, name);
        }
    }

    // ── Probabilistic: stake = max(floor, mean + k·σ) ────────────────────────

    /// At win_prob = 1.0 the variance vanishes → Probabilistic == Deterministic.
    #[rstest]
    #[case(0.841)]
    #[case(0.977)]
    #[case(0.999)]
    #[case(0.9999)]
    fn probabilistic_equals_deterministic_at_full_prob(#[case] alpha: f64) {
        let cap = ByteSize::b(PAYLOAD * 100_000);
        let p = stake_wei(cap, PRICE_WEI, 1.0, 3, &prob(alpha));
        let d = stake_wei(cap, PRICE_WEI, 1.0, 3, &DET);
        assert_close(p, d, &format!("alpha={alpha}"));
    }

    /// Probabilistic ≥ Deterministic for every win_prob (same floor, non-negative
    /// buffer).  This is the corrected ordering: the buffer sits *above* the mean.
    #[rstest]
    #[case(1e-3)]
    #[case(1e-2)]
    #[case(0.1)]
    #[case(0.5)]
    #[case(1.0)]
    fn probabilistic_at_least_deterministic(#[case] p: f64) {
        let cap = ByteSize::b(PAYLOAD * 1_000_000);
        let pr = stake_wei(cap, PRICE_WEI, p, 3, &prob(0.999));
        let d = stake_wei(cap, PRICE_WEI, p, 3, &DET);
        assert!(pr + 4 >= d, "p={p}: Probabilistic {pr} must be ≥ Deterministic {d}");
    }

    /// Above the floor, Probabilistic matches mean + k·σ with the corrected σ
    /// (`σ = tp·h·√(N·(1−p)/p)`), verified against an independent computation.
    #[rstest]
    #[case(0.5, 0.999)]
    #[case(0.1, 0.999)]
    #[case(0.01, 0.999)]
    #[case(0.01, 0.9999)]
    fn probabilistic_matches_mean_plus_k_sigma(#[case] p: f64, #[case] alpha: f64) {
        let n = 10_000_000u128; // large N so the buffer keeps us above the floor
        let cap = ByteSize::b(PAYLOAD * n as u64);
        let mean = mean_wei(n, 3, PRICE_WEI) as f64;
        let sigma = PRICE_WEI as f64 * 3.0 * (n as f64 * (1.0 - p) / p).sqrt();
        let want = (mean + z_score(alpha) * sigma) as u128;
        let got = stake_wei(cap, PRICE_WEI, p, 3, &prob(alpha));
        assert_close(got, want, &format!("p={p} alpha={alpha}"));
    }

    /// Higher confidence → larger stake (monotone in alpha), above the floor.
    #[rstest]
    #[case(0.6, 0.9)]
    #[case(0.9, 0.99)]
    #[case(0.99, 0.999)]
    #[case(0.999, 0.9999)]
    fn probabilistic_monotone_in_confidence(#[case] lo: f64, #[case] hi: f64) {
        let cap = ByteSize::b(PAYLOAD * 10_000_000);
        let s_lo = stake_wei(cap, PRICE_WEI, 0.1, 3, &prob(lo));
        let s_hi = stake_wei(cap, PRICE_WEI, 0.1, 3, &prob(hi));
        assert!(s_hi > s_lo, "alpha {hi} must exceed {lo}: {s_hi} vs {s_lo}");
    }

    /// Regression: the variance buffer scales **linearly** with hops.  Each
    /// packet issues one aggregated ticket of face value `tp·h/p`, so both the
    /// mean drain and `σ = tp·h·√(N·(1−p)/p)` scale with `h` — the buffer at
    /// `h = 3` must be ≈ 3× the buffer at `h = 1`.  The prior `σ = tp·√(N·h·…)`
    /// scaled the buffer by only `√3 ≈ 1.73` and would fail this assertion.
    #[test]
    fn probabilistic_buffer_scales_linearly_with_hops() {
        let n = 10_000_000u128;
        let cap = ByteSize::b(PAYLOAD * n as u64);
        let p = 0.01;
        let buffer = |h: u32| {
            let mean = mean_wei(n, h, PRICE_WEI);
            stake_wei(cap, PRICE_WEI, p, h, &prob(0.999)).saturating_sub(mean) as f64
        };
        let ratio = buffer(3) / buffer(1);
        assert!(
            (ratio - 3.0).abs() < 0.02,
            "buffer(3)/buffer(1) = {ratio:.4}, expected ≈ 3.0 (√h would give ≈ 1.73)"
        );
    }

    /// The variance buffer grows as win_prob falls (rarer, larger payouts).
    #[test]
    fn probabilistic_buffer_grows_as_win_prob_falls() {
        let cap = ByteSize::b(PAYLOAD * 10_000_000);
        let mean = mean_wei(10_000_000, 3, PRICE_WEI);
        let buffer = |p: f64| stake_wei(cap, PRICE_WEI, p, 3, &prob(0.999)).saturating_sub(mean);
        assert!(buffer(0.001) > buffer(0.01), "buffer must grow as p falls");
        assert!(buffer(0.01) > buffer(0.1));
    }

    // ── Sanity sweep across all probabilities and ticket prices ──────────────

    /// Cross-product sanity check: for every (win_prob, ticket_price, mode) the
    /// resolved default config is well-formed — finite, ≥ one winning ticket on
    /// every field, initial ≥ lower threshold, and Probabilistic ≥ Deterministic.
    #[test]
    fn sanity_grid_all_probs_and_prices() {
        let ps = [1.0, 0.5, 0.1, 1e-2, 1e-3, ROTSEE_P, JURA_P, 1e-7];
        let tps = [1u128, 100, PRICE_WEI, JURA_TP, 1_000_000_000_000_000_000];
        for &p in &ps {
            for &tp in &tps {
                let floor = floor_wei(tp, 3, p);
                let cfg = FundingConfig::default();
                let det = cfg.resolve::<TestTransport>(balance_from_wei(tp), p);
                let pr_cfg = FundingConfig {
                    sizing_mode: prob(0.999),
                    ..FundingConfig::default()
                };
                let pr = pr_cfg.resolve::<TestTransport>(balance_from_wei(tp), p);

                for (name, d, q) in [
                    ("initial", det.initial_balance, pr.initial_balance),
                    ("topup", det.topup_balance, pr.topup_balance),
                    ("lower", det.lower_balance_threshold, pr.lower_balance_threshold),
                    ("min_safe", det.min_safe_balance_required, pr.min_safe_balance_required),
                ] {
                    let dw = d.amount().low_u128();
                    let qw = q.amount().low_u128();
                    assert!(dw + 4 >= floor, "det {name} p={p} tp={tp}: {dw} < ticket {floor}");
                    assert!(qw + 4 >= floor, "prob {name} p={p} tp={tp}: {qw} < ticket {floor}");
                    assert!(qw + 4 >= dw, "prob<det {name} p={p} tp={tp}: {qw} < {dw}");
                }
                // initial (1 GiB) must dominate the lower threshold (256 MiB).
                assert!(
                    det.initial_balance >= det.lower_balance_threshold,
                    "initial < lower p={p} tp={tp}"
                );
            }
        }
    }

    /// Win_prob = 1.0 edge: floor = tp·hops, mean = N·hops·tp, and for N ≥ 1 the
    /// mean dominates, so every field equals its mean drain.
    #[test]
    fn edge_win_prob_one() {
        let n = packets(ByteSize::gib(1).as_u64());
        let got = stake_wei(ByteSize::gib(1), PRICE_WEI, 1.0, 3, &DET);
        assert_close(got, mean_wei(n, 3, PRICE_WEI), "p=1.0");
    }

    /// Extreme-low win_prob edge: floor = tp·hops/p is enormous but computed
    /// without overflowing to zero, and the stake equals it.
    #[test]
    fn edge_extreme_low_win_prob_uses_floor() {
        let p = 1e-9;
        let got = stake_wei(ByteSize::gib(1), PRICE_WEI, p, 3, &DET);
        let floor = floor_wei(PRICE_WEI, 3, p);
        assert!(got > 0, "must not underflow to zero");
        assert_close(got, floor, "p=1e-9");
    }

    /// Regression: a degenerate win_prob (zero, negative, NaN, -∞) must not blow
    /// the one-ticket floor `tp·hops/p` up to `f64::INFINITY` and saturate the
    /// stake to `u128::MAX`.  win_prob is clamped into `[f64::EPSILON, 1.0]`, so
    /// such inputs resolve to the large-but-finite floor at `p = f64::EPSILON`.
    #[test]
    fn degenerate_win_prob_is_clamped_not_saturated() {
        let floor_at_eps = floor_wei(PRICE_WEI, 3, f64::EPSILON);
        for p in [0.0_f64, -1.0, f64::NAN, f64::NEG_INFINITY] {
            let got = stake_wei(ByteSize::gib(1), PRICE_WEI, p, 3, &DET);
            assert!(got < u128::MAX, "p={p}: must not saturate to u128::MAX");
            assert_close(got, floor_at_eps, &format!("p={p} clamped to ε"));
        }
    }

    // ── Live-network regression: jura & rotsee (default Deterministic) ───────

    /// jura (staging): tp = 1e13 wei, win_prob = 4e-6.  Documents the exact
    /// default-Deterministic stakes and confirms each covers ≥ 1 winning ticket
    /// (face value = 7.5 wxHOPR = 7.5e18 wei).
    #[test]
    fn jura_default_deterministic_stakes() {
        let cfg = FundingConfig::default();
        let r = cfg.resolve::<TestTransport>(balance_from_wei(JURA_TP), JURA_P);
        let floor = floor_wei(JURA_TP, 3, JURA_P); // 7.5e18
        assert_close(floor, 7_500_000_000_000_000_000, "jura 1-ticket floor");

        // initial / topup / min_safe = 1 GiB → mean drain ≈ 31.09 wxHOPR.
        let n_gib = packets(ByteSize::gib(1).as_u64()); // 1_036_431
        assert_close(
            r.initial_balance.amount().low_u128(),
            mean_wei(n_gib, 3, JURA_TP),
            "jura initial",
        );
        assert_close(
            r.initial_balance.amount().low_u128(),
            31_092_930_000_000_000_000,
            "jura initial ≈ 31.09 wxHOPR",
        );
        // lower threshold = 256 MiB → ≈ 7.77 wxHOPR, still ≥ one ticket (7.5).
        let n_256 = packets(ByteSize::mib(256).as_u64()); // 259_108
        assert_close(
            r.lower_balance_threshold.amount().low_u128(),
            mean_wei(n_256, 3, JURA_TP),
            "jura lower",
        );
        assert!(
            r.lower_balance_threshold.amount().low_u128() >= floor,
            "jura lower must cover ≥ 1 winning ticket"
        );
    }

    /// rotsee (development): tp = 100 wei, win_prob = 1.25e-4.  Face value =
    /// 2.4e6 wei; every default field sits far above it.
    #[test]
    fn rotsee_default_deterministic_stakes() {
        let cfg = FundingConfig::default();
        let r = cfg.resolve::<TestTransport>(balance_from_wei(ROTSEE_TP), ROTSEE_P);
        let floor = floor_wei(ROTSEE_TP, 3, ROTSEE_P); // 2_400_000 wei
        assert_close(floor, 2_400_000, "rotsee 1-ticket floor");

        let n_gib = packets(ByteSize::gib(1).as_u64());
        assert_close(
            r.initial_balance.amount().low_u128(),
            mean_wei(n_gib, 3, ROTSEE_TP),
            "rotsee initial",
        );
        assert_close(
            r.initial_balance.amount().low_u128(),
            310_929_300,
            "rotsee initial (wei)",
        );
        let n_256 = packets(ByteSize::mib(256).as_u64());
        assert_close(
            r.lower_balance_threshold.amount().low_u128(),
            mean_wei(n_256, 3, ROTSEE_TP),
            "rotsee lower",
        );
        assert!(r.lower_balance_threshold.amount().low_u128() >= floor);
    }

    // ── FundingConfig::resolve, defaults, validation, serde ──────────────────

    #[test]
    fn resolve_maps_all_four_fields() {
        let cfg = FundingConfig::default();
        let price = balance_from_wei(PRICE_WEI);
        let p = 0.5_f64;
        let r = cfg.resolve::<TestTransport>(price, p);
        let cap = |c| capacity_to_balance::<TestTransport>(c, price, p, cfg.assumed_hops, &cfg.sizing_mode);
        assert_eq!(r.initial_balance, cap(cfg.initial_capacity));
        assert_eq!(r.topup_balance, cap(cfg.topup_capacity));
        assert_eq!(r.lower_balance_threshold, cap(cfg.lower_capacity_threshold));
        assert_eq!(r.min_safe_balance_required, cap(cfg.min_safe_capacity_required));
    }

    #[test]
    fn default_sizing_mode_is_deterministic() {
        assert_eq!(FundingConfig::default().sizing_mode, CapacitySizingMode::Deterministic);
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

    #[test]
    fn funding_config_serde_roundtrip_probabilistic() -> anyhow::Result<()> {
        let cfg = FundingConfig {
            initial_capacity: ByteSize::gib(5),
            topup_capacity: ByteSize::mib(512),
            lower_capacity_threshold: ByteSize::mib(128),
            min_safe_capacity_required: ByteSize::gib(2),
            stop_when_unfunded: false,
            assumed_hops: 2,
            sizing_mode: prob(0.9999),
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
        let det: CapacitySizingMode = serde_json::from_str(r#""deterministic""#)?;
        assert_eq!(det, CapacitySizingMode::Deterministic);
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

    #[test]
    fn selector_weights_default_matches_balanced() {
        assert_eq!(
            SelectorWeights::default(),
            MultiObjectiveSelectorConfig::balanced().weights
        );
        assert_eq!(
            MultiObjectiveSelectorConfig::default(),
            MultiObjectiveSelectorConfig::balanced()
        );
        // The inner trust weights documented on the fields.
        let w = SelectorWeights::default();
        assert_eq!((w.trust_probe, w.trust_ack, w.trust_ticket), (0.50, 0.35, 0.15));
    }

    // ── Partial configuration: every field is optional ───────────────────────

    #[test]
    fn empty_config_deserializes_to_default() -> anyhow::Result<()> {
        let cfg: ChannelLifecycleConfig = serde_json::from_str("{}").context("empty object")?;
        assert_eq!(cfg, ChannelLifecycleConfig::default());
        Ok(())
    }

    #[test]
    fn partial_config_defaults_the_rest() -> anyhow::Result<()> {
        // A single leaf field inside a single section — everything else must default.
        let cfg: ChannelLifecycleConfig =
            serde_json::from_str(r#"{"population":{"min_open_channels":3}}"#).context("partial")?;

        assert_eq!(cfg.population.min_open_channels, 3, "the overridden field");
        assert_eq!(cfg.population.target_open_channels, 8, "sibling in the same section");
        assert_eq!(
            cfg.population.peer_reopen_cooldown,
            Duration::from_secs(30 * 60),
            "sibling of a different type"
        );
        assert_eq!(cfg.funding, FundingConfig::default(), "untouched section");
        assert_eq!(cfg.tick_interval, Duration::from_secs(60), "untouched top-level field");
        Ok(())
    }

    /// Walk every object node reachable from a serialized default config and, at
    /// each one, assert the two properties the container-level
    /// `#[serde(default, deny_unknown_fields)]` is there to provide: the node may
    /// be reduced to `{}` and still yield the default, and an unknown key inside
    /// it is an error.
    ///
    /// Deliberately data-driven rather than a hand-written case list: a section
    /// added to [`ChannelLifecycleConfig`] later is covered automatically, which
    /// is exactly the recurrence this test exists to prevent. Non-object nodes
    /// (`sizing_mode: "deterministic"`, durations, byte sizes) are skipped —
    /// container-level `default` does not apply to them.
    #[test]
    fn every_nested_object_is_partial_and_rejects_unknown_keys() -> anyhow::Result<()> {
        use serde_json::{Map, Value};

        /// Rebuilds `root` with the object at `path` replaced by `replacement`.
        fn substitute(root: &Value, path: &[String], replacement: Value) -> Value {
            match path.split_first() {
                None => replacement,
                Some((key, rest)) => {
                    let mut obj = root.as_object().cloned().unwrap_or_default();
                    let child = obj.get(key).cloned().unwrap_or(Value::Null);
                    obj.insert(key.clone(), substitute(&child, rest, replacement));
                    Value::Object(obj)
                }
            }
        }

        fn object_paths(node: &Value, path: Vec<String>, out: &mut Vec<Vec<String>>) {
            if let Value::Object(map) = node {
                out.push(path.clone());
                for (key, child) in map {
                    let mut child_path = path.clone();
                    child_path.push(key.clone());
                    object_paths(child, child_path, out);
                }
            }
        }

        let default = ChannelLifecycleConfig::default();
        let root = serde_json::to_value(&default).context("serialize default")?;
        let mut paths = Vec::new();
        object_paths(&root, Vec::new(), &mut paths);
        assert!(
            paths.len() > 8,
            "expected the root plus every nested section, found {} object nodes",
            paths.len()
        );

        for path in paths {
            let at = if path.is_empty() {
                "<root>".into()
            } else {
                path.join(".")
            };

            let emptied = substitute(&root, &path, Value::Object(Map::new()));
            let parsed: ChannelLifecycleConfig =
                serde_json::from_value(emptied).with_context(|| format!("`{at}` reduced to {{}}"))?;
            assert_eq!(parsed, default, "`{at}` reduced to {{}} must yield the default");

            let mut with_unknown = Map::new();
            with_unknown.insert("__unknown__".into(), Value::Bool(true));
            let polluted = substitute(&root, &path, Value::Object(with_unknown));
            assert!(
                serde_json::from_value::<ChannelLifecycleConfig>(polluted).is_err(),
                "unknown key in `{at}` must be an error, not a silent default"
            );
        }
        Ok(())
    }

    #[test]
    fn partial_nested_selector_custom_defaults_inner_weights() -> anyhow::Result<()> {
        let cfg: ChannelLifecycleConfig =
            serde_json::from_str(r#"{"selector":{"custom":{"open_per_tick":5}}}"#).context("custom selector")?;
        let mo = cfg
            .selector
            .multi_objective_config()
            .expect("custom profile must yield a config");
        assert_eq!(mo.open_per_tick, 5, "the overridden field");
        assert_eq!(mo.weights, SelectorWeights::default(), "weights default wholesale");
        // `selector` is outside the `Validate` tree, so `build()` checks this separately.
        mo.validate_trust_weights().map_err(anyhow::Error::msg)?;
        Ok(())
    }

    #[test]
    fn probabilistic_sizing_mode_defaults_success_probability() -> anyhow::Result<()> {
        let cfg: ChannelLifecycleConfig =
            serde_json::from_str(r#"{"funding":{"sizing_mode":{"probabilistic":{}}}}"#).context("probabilistic")?;
        assert_eq!(
            cfg.funding.sizing_mode,
            CapacitySizingMode::Probabilistic {
                success_probability: 0.999
            }
        );
        Ok(())
    }

    // ── Unknown keys are rejected, not silently defaulted ────────────────────

    /// The generic walk above covers unknown keys in every *struct* node; these
    /// are the cases it cannot reach — a misspelling of the section key itself,
    /// and a key inside an enum struct variant.
    #[rstest]
    #[case(r#"{"populatio":{}}"#)] // misspelled section
    #[case(r#"{"funding":{"sizing_mode":{"probabilistic":{"sucess_probability":0.9}}}}"#)] // in a variant
    fn unknown_field_is_rejected(#[case] json: &str) {
        assert!(
            serde_json::from_str::<ChannelLifecycleConfig>(json).is_err(),
            "unknown key must be an error, not a silent default: {json}"
        );
    }

    // ── Nested validation actually runs ──────────────────────────────────────

    #[test]
    fn default_lifecycle_config_passes_validation() -> anyhow::Result<()> {
        // A caller that validates a defaulted config must never see an error.
        ChannelLifecycleConfig::default().validate().context("default config")?;
        Ok(())
    }

    /// Constraints declared on a nested section must surface from a single
    /// `validate()` on the top-level config — this is what `#[validate(nested)]`
    /// buys, and without it these validators are dead code.
    #[rstest]
    #[case(r#"{"funding":{"assumed_hops":0}}"#)]
    #[case(r#"{"funding":{"sizing_mode":{"probabilistic":{"success_probability":0.2}}}}"#)]
    fn nested_validation_rejects_out_of_range_values(#[case] json: &str) -> anyhow::Result<()> {
        let cfg: ChannelLifecycleConfig = serde_json::from_str(json).with_context(|| json.to_string())?;
        assert!(cfg.validate().is_err(), "must fail top-level validation: {json}");
        Ok(())
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
/// Every field — including every field of every nested section — has a sensible
/// default, so any subset of the fields deserializes: consumers only need to set
/// the fields they want to override, and an empty configuration is equivalent to
/// [`ChannelLifecycleConfig::default`]. Omitted fields are defaulted; values that
/// *are* supplied must still pass validation (see below).
///
/// ```yaml
/// # Everything not mentioned keeps its default.
/// population:
///   target_open_channels: 12      # min_open_channels stays 5
/// funding:
///   initial_capacity: 2 GiB       # topup_capacity stays 1 GiB
/// ```
///
/// Unknown keys are rejected rather than ignored, so a misspelled field is a
/// load-time error instead of a silent fallback to the default.
///
/// # Defaulting is not validation
///
/// Deserialization fills in every unspecified field but does **not** check the
/// constraints declared on this type and its nested sections
/// (`funding.assumed_hops` ∈ `[1, 3]`, `funding.sizing_mode`'s
/// `success_probability` bounds). Those are enforced when the strategy is built:
/// [`ChannelLifecycleStrategy::build`] returns
/// [`StrategyError::InvalidConfiguration`](crate::errors::StrategyError::InvalidConfiguration)
/// rather than panicking.
///
/// A config loader that wants to reject a bad file before constructing anything
/// can validate up front instead. The nested sections are marked
/// `#[validate(nested)]`, so one
/// [`Validate::validate`](validator::Validate::validate) call covers all of
/// them:
///
/// ```
/// # use hopr_strategy::channel_lifecycle::ChannelLifecycleConfig;
/// use validator::Validate as _;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let cfg: ChannelLifecycleConfig = serde_json::from_str(r#"{"population":{"min_open_channels":3}}"#)?;
/// cfg.validate()?;
/// # Ok(())
/// # }
/// ```
///
/// The one exception is [`selector`](Self::selector): [`SelectorProfile`] does not
/// derive [`Validate`], so a `Custom` profile's trust weights are checked only by
/// [`MultiObjectiveSelectorConfig::validate_trust_weights`], which
/// [`ChannelLifecycleStrategy::build`] calls separately. A loader that validates
/// up front should call it too, or leave that check to `build`.
///
/// [`ChannelLifecycleStrategy::build`]: crate::channel_lifecycle::ChannelLifecycleStrategy::build
#[serde_as]
#[derive(Debug, Clone, PartialEq, smart_default::SmartDefault, Validate, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ChannelLifecycleConfig {
    /// Base period between full evaluation passes.  Default: 60 s.
    #[serde(with = "humantime_serde")]
    #[default(Duration::from_secs(60))]
    pub tick_interval: Duration,

    /// Maximum random offset added to the tick interval to spread out
    /// concurrent node restarts.  Implemented as a deterministic offset based
    /// on the current system time nanoseconds.  Default: 5 s.
    #[serde(with = "humantime_serde")]
    #[default(Duration::from_secs(5))]
    pub jitter: Duration,

    #[validate(nested)]
    pub population: PopulationConfig,
    #[validate(nested)]
    pub eligibility: EligibilityConfig,
    #[validate(nested)]
    pub funding: FundingConfig,
    #[validate(nested)]
    pub proactive_funding: ProactiveFundingConfig,
    #[validate(nested)]
    pub closure: ClosureConfig,
    #[validate(nested)]
    pub finalizer: FinalizerConfig,
    #[validate(nested)]
    pub restart: RestartGuardConfig,
    #[validate(nested)]
    pub concurrency: ConcurrencyConfig,
    /// Open/close selection policy.  Defaults to the original weighted-sum selector.
    #[default(SelectorProfile::Default)]
    pub selector: SelectorProfile,
}
