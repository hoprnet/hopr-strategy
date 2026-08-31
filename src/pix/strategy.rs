//! ## PIX Strategy
//!
//! Generic over [`DepositPool`] implementations.  Manages the PIX lifecycle:
//! Entry-side deposits, Exit-side tracking and recovery, and crash recovery
//! via the [`PixRecoveryStore`].
//!
//! # Type parameters
//!
//! * `D` — The deposit pool implementation.
//! * `N` — The node type that emits PIX events via [`ActionableEventSource`].
//!
//! One builder per bundled pool, each taking that pool's own config: `build_non_anonymous` for
//! `plain::NonAnonymousDepositPool` and `build_curvy` for `curvy::CurvyDepositPool`. Each
//! exists whenever its own `strategy-pix-*` feature does, and both may exist at once, so the pool
//! is named at the call site rather than inferred from the feature graph. For a custom pool,
//! construct it first and pass it to [`PixStrategy::build_with_pool`].
// The two builders above are code spans, not intra-doc links: each exists only when its own
// `strategy-pix-*` feature is on, so linking them warns on every single-pool build.

use std::{
    fmt::{Debug, Display, Formatter},
    sync::Arc,
    time::Duration,
};

use futures::{SinkExt, StreamExt};
use hopr_api::{
    chain::{DepositPool, PixDepositAddress, PixDepositSecret},
    node::{
        ActionableEventDiscriminant, ActionableEventSource, HasChainApi, PixAddressId, PixDepositDataRequest, PixEvent,
    },
    types::{
        crypto::prelude::Keypair,
        primitive::prelude::{Address, GeneralError, HoprBalance},
    },
};
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use validator::Validate;

use crate::{
    errors::{Result, StrategyError},
    pix::recovery_store::PixRecoveryStore,
    strategy::Strategy as StrategyTrait,
};

// ---------------------------------------------------------------------------
// Telemetry
// ---------------------------------------------------------------------------

#[cfg(all(feature = "telemetry", not(test)))]
lazy_static::lazy_static! {
    static ref METRIC_PIX_DEPOSITS: hopr_api::types::telemetry::SimpleCounter =
        hopr_api::types::telemetry::SimpleCounter::new(
            "hopr_strategy_pix_deposits_total",
            "Count of SSA deposits successfully sent by the Entry",
        ).unwrap();
    static ref METRIC_PIX_DEPOSITS_REJECTED: hopr_api::types::telemetry::SimpleCounter =
        hopr_api::types::telemetry::SimpleCounter::new(
            "hopr_strategy_pix_deposits_rejected_total",
            "Count of SSA deposits refused because they exceed max_ssa_allocation",
        ).unwrap();
    static ref METRIC_PIX_DEPOSITS_OVER_BUDGET: hopr_api::types::telemetry::SimpleCounter =
        hopr_api::types::telemetry::SimpleCounter::new(
            "hopr_strategy_pix_deposits_over_budget_total",
            "Count of SSA deposits refused because they would cross max_spend_per_window",
        ).unwrap();
    static ref METRIC_PIX_DEPOSITS_FAILED: hopr_api::types::telemetry::SimpleCounter =
        hopr_api::types::telemetry::SimpleCounter::new(
            "hopr_strategy_pix_deposits_failed_total",
            "Count of SSA deposits that failed after exhausting retries",
        ).unwrap();
    static ref METRIC_PIX_DEPOSIT_DATA: hopr_api::types::telemetry::MultiCounter =
        hopr_api::types::telemetry::MultiCounter::new(
            "hopr_strategy_pix_deposit_data_total",
            "Outcomes of the Exit asking its pool to generate PIX deposit data, per allocation",
            &["outcome"],
        ).unwrap();
    static ref METRIC_PIX_DEPOSIT_TRACKING: hopr_api::types::telemetry::MultiCounter =
        hopr_api::types::telemetry::MultiCounter::new(
            "hopr_strategy_pix_deposit_tracking_total",
            "Outcomes of the Exit waiting for an SSA deposit to land",
            &["outcome"],
        ).unwrap();
    static ref METRIC_PIX_KEYS_RECOVERED: hopr_api::types::telemetry::SimpleCounter =
        hopr_api::types::telemetry::SimpleCounter::new(
            "hopr_strategy_pix_keys_recovered_total",
            "Count of SSA stealth address private keys reconstructed by the Exit",
        ).unwrap();
    static ref METRIC_PIX_SWEEPS: hopr_api::types::telemetry::SimpleCounter =
        hopr_api::types::telemetry::SimpleCounter::new(
            "hopr_strategy_pix_sweeps_total",
            "Count of recovered SSA deposits swept into the Exit's Safe",
        ).unwrap();
    static ref METRIC_PIX_LAST_SWEEP: hopr_api::types::telemetry::SimpleGauge =
        hopr_api::types::telemetry::SimpleGauge::new(
            "hopr_strategy_pix_last_sweep_hopr",
            "wxHOPR moved by the most recent SSA sweep, in base units",
        ).unwrap();
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

fn default_price_per_byte() -> HoprBalance {
    HoprBalance::new_base(1)
}

fn default_max_ssa_allocation() -> HoprBalance {
    HoprBalance::new_base(100)
}

fn default_max_spend_per_window() -> HoprBalance {
    HoprBalance::new_base(10_000)
}

fn default_spend_window() -> Duration {
    Duration::from_secs(3600)
}

// `Result` in this module is the crate alias, which fixes the error type.
fn validate_min_1sec(duration: &Duration) -> std::result::Result<(), validator::ValidationError> {
    if duration.as_secs() < 1 {
        return Err(validator::ValidationError::new("must be at least 1 second"));
    }
    Ok(())
}

fn default_deposit_buffer_period() -> Duration {
    Duration::from_millis(500)
}

fn default_withdrawal_buffer_period() -> Duration {
    Duration::from_millis(500)
}

/// Configuration for [`PixStrategy`].
///
/// Deliberately pool-agnostic: a pool's own configuration is passed to the builder that names it
/// (`build_non_anonymous`, `build_curvy`) rather than nested here. The two pool configs share
/// **no** fields by contract, so a single `pool` field would have to be typed by whichever
/// `strategy-pix-*` feature was on — which is exactly what made the two features mutually
/// exclusive. Keeping settlement config out of strategy config is what lets both pools be
/// compiled together.
///
/// # Examples
///
/// The two spend controls are independent: [`Self::max_ssa_allocation`] caps a single deposit,
/// while [`Self::max_spend_per_window`] caps the total committed across a rolling
/// [`Self::spend_window`] — so a stream of individually-acceptable deposits is bounded too.
///
/// ```
/// use std::time::Duration;
///
/// use hopr_api::types::primitive::prelude::HoprBalance;
/// use hopr_strategy::pix::strategy::PixStrategyConfig;
///
/// // At most 100 wxHOPR to any one deposit address, and at most 1 000 wxHOPR in total
/// // over any 10-minute stretch.
/// let cfg = PixStrategyConfig {
///     max_ssa_allocation: HoprBalance::new_base(100),
///     max_spend_per_window: HoprBalance::new_base(1_000),
///     spend_window: Duration::from_secs(600),
///     ..Default::default()
/// };
///
/// assert_eq!(cfg.max_spend_per_window, HoprBalance::new_base(1_000));
/// assert_eq!(cfg.spend_window, Duration::from_secs(600));
/// ```
///
/// The window limit is opt-out rather than opt-in: it is armed by default, and only a zero
/// budget disables it. The defaults are 10 000 wxHOPR per hour.
///
/// ```
/// use std::time::Duration;
///
/// use hopr_api::types::primitive::prelude::HoprBalance;
/// use hopr_strategy::pix::strategy::PixStrategyConfig;
///
/// let armed = PixStrategyConfig::default();
/// assert_eq!(armed.max_spend_per_window, HoprBalance::new_base(10_000));
/// assert_eq!(armed.spend_window, Duration::from_secs(3600));
///
/// let unlimited = PixStrategyConfig {
///     max_spend_per_window: HoprBalance::zero(),
///     ..Default::default()
/// };
/// assert!(unlimited.max_spend_per_window.is_zero());
/// ```
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate, smart_default::SmartDefault)]
#[serde(deny_unknown_fields)]
pub struct PixStrategyConfig {
    /// wxHOPR paid per byte of SSA quota.
    #[default(default_price_per_byte())]
    #[serde_as(as = "DisplayFromStr")]
    #[serde(default = "default_price_per_byte")]
    pub price_per_byte: HoprBalance,
    /// Maximum wxHOPR the strategy will send to a single deposit address.
    ///
    /// A per-address ceiling only. It says nothing about how *many* addresses get funded — that
    /// is [`Self::max_spend_per_window`]'s job.
    #[default(default_max_ssa_allocation())]
    #[serde_as(as = "DisplayFromStr")]
    #[serde(default = "default_max_ssa_allocation")]
    pub max_ssa_allocation: HoprBalance,

    /// Maximum wxHOPR the strategy will commit to deposits within any [`Self::spend_window`].
    /// Default: 10 000 wxHOPR.  Zero disables the limit.
    ///
    /// The circuit breaker for a runaway or hostile event stream: distinct PIX ids to distinct
    /// addresses each pass the dedupe, the in-flight guard and [`Self::max_ssa_allocation`], so
    /// without an aggregate ceiling they are all funded until the node's wxHOPR is gone.
    ///
    /// Sized as a runaway detector rather than a throttle — the default is 100 deposits at the
    /// default `max_ssa_allocation` — so reaching it means something is wrong, not that the node
    /// is busy. A deposit that would cross it is refused with
    /// [`StrategyError::CriteriaNotSatisfied`] and the event is dropped; it is not re-tried when
    /// the window rolls forward.
    ///
    /// The ledger behind it is in memory, so a restart forgives the window. It bounds a burst,
    /// not lifetime spend; `plain::NonAnonymousDepositPoolConfig::min_safe_hopr_reserve`
    /// is the balance floor that survives restarts.
    #[default(default_max_spend_per_window())]
    #[serde_as(as = "DisplayFromStr")]
    #[serde(default = "default_max_spend_per_window")]
    pub max_spend_per_window: HoprBalance,

    /// Length of the rolling window for [`Self::max_spend_per_window`].  Default: 1 hour.
    ///
    /// Rolling rather than fixed: there is no reset instant for a burst to line up with.
    #[default(default_spend_window())]
    #[serde(with = "humantime_serde", default = "default_spend_window")]
    #[validate(custom(function = "validate_min_1sec"))]
    pub spend_window: Duration,
    /// If set, recovered private keys are persisted to redb at this path.
    ///
    /// Strongly recommended in production. A `PrivateKeyRecovered` event can arrive before
    /// its deposit has been confirmed on-chain, in which case the sweep is retried and then
    /// abandoned. Without a recovery store there is nothing to replay on the next start, and
    /// the recovered key — the only means of moving those funds — is lost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pix_recovery_db_path: Option<std::path::PathBuf>,
    /// Environment variable for the recovery store encryption password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pix_recovery_password_env: Option<String>,
    /// How long to wait for additional deposit events before flushing the batch.
    /// Default: 500ms (debounced — resets on each new event).
    #[default(default_deposit_buffer_period())]
    #[serde(with = "humantime_serde", default = "default_deposit_buffer_period")]
    pub deposit_buffer_period: Duration,
    /// How long to wait for additional withdrawal events before flushing the batch.
    /// Default: 500ms (debounced — resets on each new event).
    #[default(default_withdrawal_buffer_period())]
    #[serde(with = "humantime_serde", default = "default_withdrawal_buffer_period")]
    pub withdrawal_buffer_period: Duration,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PROCESSED_DEPOSITS_CAPACITY: u64 = 8192;
const PROCESSED_DEPOSITS_TTL: Duration = Duration::from_secs(24 * 3600);
const IN_FLIGHT_GUARD_CAPACITY: u64 = 1024;
const IN_FLIGHT_GUARD_TTL: Duration = Duration::from_secs(600);

/// Entries the spend ledger keeps before coalescing the oldest two.
///
/// The window cap already bounds the ledger for any sane configuration — entries stop being
/// added once it trips — but `price_per_byte` is free to be tiny, which would let a large cap
/// admit an unbounded number of minute deposits. Coalescing keeps that bounded without ever
/// under-counting.
const SPEND_LEDGER_CAPACITY: usize = 4096;

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for a generic PIX strategy.
pub struct PixStrategy {
    cfg: PixStrategyConfig,
}

impl PixStrategy {
    pub fn new(cfg: PixStrategyConfig) -> Self {
        Self { cfg }
    }

    /// Build with the
    /// [`NonAnonymousDepositPool`](crate::pix::pools::plain::NonAnonymousDepositPool), settling
    /// to secp256k1 (`Address`) deposit addresses.
    ///
    /// `A` is the deposit-address type the node's PIX spec produces, and the `PoolKeypair:
    /// Keypair<Public = A>` bound makes naming it the whole compatibility check. Pass
    /// `<HoprPixSpec as PixSpec>::DepositAddress` and a build that paired this pool with the wrong
    /// `hopr-lib/pix-*` feature stops here, at the call site:
    ///
    /// ```text
    /// error[E0271]: type mismatch resolving `<EthDepositKey as Keypair>::Public == BjjPublicKey`
    /// ```
    ///
    /// The check has to live in the caller because it cannot live here: `PixDepositAddress` is a
    /// runtime enum over *every* scheme, so the strategy's narrowing to `K::Public` is a
    /// `TryFrom` that this crate can only fail at runtime — once per event, having deposited
    /// nothing. `A` is what converts that into a compile error. It appears only in the bound, so
    /// it must be named explicitly; that is deliberate, not an oversight.
    ///
    /// The sweep destination is `node.identity().safe_address`. All operations are fully visible
    /// on-chain — **not for production use.**
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::sync::Arc;
    ///
    /// use hopr_api::{
    ///     ChainKeypair,
    ///     node::{ActionableEventSource, HasChainApi},
    ///     types::primitive::prelude::Address,
    /// };
    /// use hopr_strategy::pix::strategy::{PixStrategy, PixStrategyConfig};
    ///
    /// # fn main() -> anyhow::Result<()> {
    /// # fn build<N: HasChainApi + ActionableEventSource + Send + Sync + 'static>(node: Arc<N>, node_key: ChainKeypair)
    /// #     -> hopr_strategy::errors::Result<()> {
    /// // In `hoprd` this is `<HoprPixSpec as PixSpec>::DepositAddress`, not a literal `Address`.
    /// // `node_key` signs the sweep-gas top-ups, which cannot go through the node's Safe.
    /// let _strategy = PixStrategy::new(PixStrategyConfig::default())
    ///     .build_non_anonymous::<_, Address>(node, node_key, Default::default())?;
    /// # Ok(()) }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Pairing this pool with Baby JubJub deposit addresses does not compile:
    ///
    /// ```compile_fail
    /// use std::sync::Arc;
    ///
    /// use hopr_api::{
    ///     ChainKeypair,
    ///     node::{ActionableEventSource, HasChainApi},
    ///     types::crypto::prelude::BjjPublicKey,
    /// };
    /// use hopr_strategy::pix::strategy::{PixStrategy, PixStrategyConfig};
    ///
    /// fn build<N: HasChainApi + ActionableEventSource + Send + Sync + 'static>(node: Arc<N>, node_key: ChainKeypair) {
    ///     // `NonAnonymousDepositPool` settles to `Address`, so this pairing is rejected here
    ///     // rather than failing on every event at runtime.
    ///     let _ = PixStrategy::new(PixStrategyConfig::default())
    ///         .build_non_anonymous::<_, BjjPublicKey>(node, node_key, Default::default());
    /// }
    /// ```
    #[cfg(feature = "strategy-pix-test")]
    pub fn build_non_anonymous<N, A>(
        self,
        node: Arc<N>,
        node_key: hopr_api::ChainKeypair,
        pool_cfg: crate::pix::pools::plain::PoolConfig,
    ) -> Result<Box<dyn StrategyTrait + Send>>
    where
        N: HasChainApi + ActionableEventSource + Send + Sync + 'static,
        A: crate::pix::DepositAddressOf<crate::pix::pools::plain::PoolKeypair>,
    {
        // Each builder validates the config it owns: the pool's here, the strategy's inside
        // `build_with_pool`. Checked before anything is constructed, so a build that is going to
        // fail does not first open a recovery store on disk.
        StrategyError::validate_config(&pool_cfg)?;

        let client = hopr_chain_connector::create_blokli_client(hopr_chain_connector::HoprBlokliClientConfig::new(
            pool_cfg.blokli_url.clone(),
        ));
        self.build_non_anonymous_with_client::<N, A, _>(node, node_key, pool_cfg, client)
    }

    /// [`build_non_anonymous`](Self::build_non_anonymous) against an already-built blokli client.
    ///
    /// The pool builds EOA-signing connectors of its own for the gas top-up and the sweep, and
    /// those connect to [`PoolConfig::blokli_url`](crate::pix::pools::plain::PoolConfig). An
    /// in-process test chain has no URL, so this hands the client over directly. Everything after
    /// that point is the code the real builder runs, which is why
    /// [`build_non_anonymous`](Self::build_non_anonymous) delegates here rather than duplicating
    /// it. Also useful to a consumer that already holds a client and would rather not have a
    /// second one opened on its behalf.
    ///
    /// `node_key` must be the node's own chain key — the same requirement as
    /// [`build_non_anonymous`](Self::build_non_anonymous), and rejected here rather than at the
    /// first sweep.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::sync::Arc;
    ///
    /// use hopr_api::{
    ///     ChainKeypair,
    ///     node::{ActionableEventSource, HasChainApi},
    ///     types::primitive::prelude::Address,
    /// };
    /// use hopr_chain_connector::blokli_client::{BlokliQueryClient, BlokliSubscriptionClient, BlokliTransactionClient};
    /// use hopr_strategy::pix::strategy::{PixStrategy, PixStrategyConfig};
    ///
    /// fn build<N, C>(node: Arc<N>, node_key: ChainKeypair, client: C) -> anyhow::Result<()>
    /// where
    ///     N: HasChainApi + ActionableEventSource + Send + Sync + 'static,
    ///     C: BlokliSubscriptionClient + BlokliQueryClient + BlokliTransactionClient + Clone + Send + Sync + 'static,
    /// {
    ///     // The client stands in for the one `build_non_anonymous` would open from
    ///     // `PoolConfig::blokli_url`; everything after this point is identical.
    ///     let _strategy = PixStrategy::new(PixStrategyConfig::default())
    ///         .build_non_anonymous_with_client::<_, Address, _>(node, node_key, Default::default(), client)?;
    ///     Ok(())
    /// }
    /// ```
    #[cfg(feature = "strategy-pix-test")]
    pub fn build_non_anonymous_with_client<N, A, C>(
        self,
        node: Arc<N>,
        node_key: hopr_api::ChainKeypair,
        pool_cfg: crate::pix::pools::plain::PoolConfig,
        client: C,
    ) -> Result<Box<dyn StrategyTrait + Send>>
    where
        N: HasChainApi + ActionableEventSource + Send + Sync + 'static,
        A: crate::pix::DepositAddressOf<crate::pix::pools::plain::PoolKeypair>,
        C: hopr_chain_connector::blokli_client::BlokliSubscriptionClient
            + hopr_chain_connector::blokli_client::BlokliQueryClient
            + hopr_chain_connector::blokli_client::BlokliTransactionClient
            + Clone
            + Send
            + Sync
            + 'static,
    {
        StrategyError::validate_config(&pool_cfg)?;

        // The pool signs sweep-gas top-ups with `node_key` directly, and its reserve gate reads
        // that key's own balance. A key that is not the node's would therefore spend and gate an
        // account unrelated to the one `node.chain_api()` settles deposits from — a wiring mistake
        // worth catching at build time rather than at the first recovered deposit.
        let key_address = node_key.public().to_address();
        let node_address = node.identity().node_address;
        if key_address != node_address {
            return Err(StrategyError::InvalidConfiguration(format!(
                "the given node key belongs to {key_address}, but the node's on-chain identity is {node_address}"
            )));
        }

        // `Arc` rather than the bare pool: `build_with_pool` needs a cloneable `D`, and
        // `DepositPool` is auto-implemented for `Arc<D>`.
        let pool = Arc::new(crate::pix::pools::plain::NonAnonymousDepositPool::with_client(
            Arc::clone(&node),
            node_key,
            pool_cfg,
            client,
        ));
        let safe_address = node.identity().safe_address;

        // The key is named rather than inferred: it is the choice this builder exists to make.
        self.build_with_pool::<_, _, crate::pix::pools::plain::PoolKeypair>(pool, node, safe_address)
    }

    /// Build with the [`CurvyDepositPool`](crate::pix::pools::curvy::CurvyDepositPool), settling to
    /// Baby JubJub (`BjjPublicKey`) deposit addresses.
    ///
    /// `A` is the deposit-address type the node's PIX spec produces; see
    /// `build_non_anonymous` for why naming it is the compatibility
    /// check and why it cannot be checked inside this crate. Pass
    /// `<HoprPixSpec as PixSpec>::DepositAddress`; `hopr-lib/pix-bjj` is the default, so a consumer
    /// enabling only this feature already agrees.
    ///
    /// Note that this pool is a **stub**: building succeeds and the first deposit panics. See
    /// [`crate::pix::pools::curvy`].
    ///
    /// # Examples
    ///
    /// Pairing this pool with secp256k1 deposit addresses does not compile:
    ///
    /// ```compile_fail
    /// use std::sync::Arc;
    ///
    /// use hopr_api::{
    ///     node::{ActionableEventSource, HasChainApi},
    ///     types::primitive::prelude::Address,
    /// };
    /// use hopr_strategy::pix::strategy::{PixStrategy, PixStrategyConfig};
    ///
    /// fn build<N: HasChainApi + ActionableEventSource + Send + Sync + 'static>(node: Arc<N>) {
    ///     // `CurvyDepositPool` settles to `BjjPublicKey`, so this pairing is rejected here
    ///     // rather than failing on every event at runtime.
    ///     let _ = PixStrategy::new(PixStrategyConfig::default())
    ///         .build_curvy::<_, Address>(node, Default::default());
    /// }
    /// ```
    #[cfg(feature = "strategy-pix-curvy")]
    pub fn build_curvy<N, A>(
        self,
        node: Arc<N>,
        pool_cfg: crate::pix::pools::curvy::PoolConfig,
    ) -> Result<Box<dyn StrategyTrait + Send>>
    where
        N: HasChainApi + ActionableEventSource + Send + Sync + 'static,
        A: crate::pix::DepositAddressOf<crate::pix::pools::curvy::PoolKeypair>,
    {
        // See `build_non_anonymous`: the pool config is this builder's to validate.
        StrategyError::validate_config(&pool_cfg)?;

        let pool = Arc::new(crate::pix::pools::curvy::CurvyDepositPool::new(
            Arc::clone(&node),
            pool_cfg,
        ));
        let safe_address = node.identity().safe_address;

        self.build_with_pool::<_, _, crate::pix::pools::curvy::PoolKeypair>(pool, node, safe_address)
    }

    /// Build with an arbitrary [`DepositPool`] implementation.
    ///
    /// `D` must be [`Clone`] so the startup recovery replay can run in its own task. A pool
    /// that is not cloneable is used by wrapping it in an [`Arc`], which [`DepositPool`]
    /// implements for.
    pub fn build_with_pool<D, N, K>(
        self,
        pool: D,
        node: Arc<N>,
        safe_address: Address,
    ) -> Result<Box<dyn StrategyTrait + Send>>
    where
        D: DepositPool<K> + Clone + Send + Sync + 'static,
        K: Keypair<SecretLen = hopr_api::types::primitive::typenum::U32> + Send + Sync + 'static,
        K::Public: Into<PixDepositAddress>
            + TryFrom<PixDepositAddress>
            + Eq
            + std::hash::Hash
            + Clone
            + std::fmt::Debug
            + Send
            + Sync
            + 'static,
        D::Error: Into<StrategyError>,
        N: ActionableEventSource + Send + Sync + 'static,
    {
        // Every other strategy validates in its builder; this one derived `Validate` without ever
        // calling it, so `spend_window`'s constraint would have been decorative.
        StrategyError::validate_config(&self.cfg)?;

        let recovery_store = open_recovery_store(
            self.cfg.pix_recovery_db_path.as_ref(),
            self.cfg.pix_recovery_password_env.as_ref(),
        )?;

        Ok(Box::new(PixStrategyInner {
            pool,
            node,
            cfg: self.cfg,
            safe_address,
            recovery_store,
            processed_deposits: Cache::builder()
                .max_capacity(PROCESSED_DEPOSITS_CAPACITY)
                .time_to_live(PROCESSED_DEPOSITS_TTL)
                .build(),
            in_flight_sweeps: Cache::builder()
                .max_capacity(IN_FLIGHT_GUARD_CAPACITY)
                .time_to_live(IN_FLIGHT_GUARD_TTL)
                .build(),
            in_flight_destinations: Cache::builder()
                .max_capacity(IN_FLIGHT_GUARD_CAPACITY)
                .time_to_live(IN_FLIGHT_GUARD_TTL)
                .build(),
            deposit_buffer: Vec::new(),
            withdrawal_buffer: Vec::new(),
            spend_ledger: std::collections::VecDeque::new(),
            detach_flushes: false,
        }))
    }
}

fn open_recovery_store(
    db_path: Option<&std::path::PathBuf>,
    password_env: Option<&String>,
) -> Result<Option<PixRecoveryStore>> {
    match (db_path, password_env) {
        (Some(path), Some(env)) => {
            let password = std::env::var(env).map_err(|_| {
                StrategyError::Other(anyhow::anyhow!(
                    "environment variable {env} must be set when PIX recovery persistence is enabled"
                ))
            })?;
            PixRecoveryStore::open(path, &password)
                .map(Some)
                .map_err(StrategyError::other)
        }
        (None, None) => Ok(None),
        (Some(_), None) => Err(StrategyError::Other(anyhow::anyhow!(
            "pix_recovery_password_env must be set when pix_recovery_db_path is set"
        ))),
        (None, Some(_)) => Err(StrategyError::Other(anyhow::anyhow!(
            "pix_recovery_db_path must be set when pix_recovery_password_env is set"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Inner strategy
// ---------------------------------------------------------------------------

/// One buffered deposit, which is exactly
/// [`DepositPool::deposit_funds_to_multiple`]'s slice element.
///
/// Named so that the buffer and the batch argument cannot drift apart: a flush passes the buffer
/// to the pool directly, with no projection in between for a field to go missing from.
type BufferedDeposit<D, K> = (
    PixAddressId,
    <K as Keypair>::Public,
    HoprBalance,
    <D as DepositPool<K>>::PoolDepositData,
);

/// The generic PIX strategy runner.
struct PixStrategyInner<D, N, K>
where
    D: DepositPool<K>,
    K: Keypair<SecretLen = hopr_api::types::primitive::typenum::U32> + Send + Sync + 'static,
    K::Public: Into<PixDepositAddress>
        + TryFrom<PixDepositAddress>
        + Eq
        + std::hash::Hash
        + Clone
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
{
    pool: D,
    node: Arc<N>,
    cfg: PixStrategyConfig,
    safe_address: Address,
    recovery_store: Option<PixRecoveryStore>,
    processed_deposits: Cache<PixAddressId, ()>,
    in_flight_sweeps: Cache<PixAddressId, ()>,
    in_flight_destinations: Cache<K::Public, ()>,
    /// Debounced deposit buffer. See [`BufferedDeposit`].
    deposit_buffer: Vec<BufferedDeposit<D, K>>,
    /// Debounced withdrawal buffer.
    withdrawal_buffer: Vec<(PixAddressId, PixDepositSecret)>,
    /// Rolling record of deposits committed within [`PixStrategyConfig::spend_window`], oldest
    /// first. Entries are appended when a deposit is accepted into the buffer and expire by age.
    spend_ledger: std::collections::VecDeque<(std::time::Instant, HoprBalance)>,
    /// Whether a zero buffer period flushes on a task instead of awaiting inline.
    ///
    /// Set by [`StrategyTrait::run`] and false otherwise, because it is a statement about who is
    /// driving this instance rather than about how it is configured. Under `run` there is an event
    /// loop to keep responsive and awaiting a flush inside a handler stalls it exactly as awaiting
    /// one in the loop does — a zero period must not be a way back into the bug
    /// [`Self::detach_flush_withdrawals`] exists to fix. Driven directly, as the tests do, there is
    /// no loop to protect and "no debounce" is most useful meaning the work is done when
    /// [`Self::on_pix_event`] returns.
    detach_flushes: bool,
}

#[cfg(test)]
impl<D, N, K> PixStrategyInner<D, N, K>
where
    D: DepositPool<K>,
    K: Keypair<SecretLen = hopr_api::types::primitive::typenum::U32> + Send + Sync + 'static,
    K::Public: Into<PixDepositAddress>
        + TryFrom<PixDepositAddress>
        + Eq
        + std::hash::Hash
        + Clone
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
{
    fn new(
        pool: D,
        node: Arc<N>,
        cfg: PixStrategyConfig,
        safe_address: Address,
        recovery_store: Option<PixRecoveryStore>,
    ) -> Self {
        Self {
            pool,
            node,
            cfg,
            safe_address,
            recovery_store,
            processed_deposits: Cache::builder()
                .max_capacity(PROCESSED_DEPOSITS_CAPACITY)
                .time_to_live(PROCESSED_DEPOSITS_TTL)
                .build(),
            in_flight_sweeps: Cache::builder()
                .max_capacity(IN_FLIGHT_GUARD_CAPACITY)
                .time_to_live(IN_FLIGHT_GUARD_TTL)
                .build(),
            in_flight_destinations: Cache::builder()
                .max_capacity(IN_FLIGHT_GUARD_CAPACITY)
                .time_to_live(IN_FLIGHT_GUARD_TTL)
                .build(),
            deposit_buffer: Vec::new(),
            withdrawal_buffer: Vec::new(),
            spend_ledger: std::collections::VecDeque::new(),
            detach_flushes: false,
        }
    }
}

impl<D, N, K> PixStrategyInner<D, N, K>
where
    // `Clone + Send + 'static` on top of what the rest of this block needs, because
    // the `DepositDataRequest` arm hands the pool to a spawned task. The
    // `StrategyTrait` impl below already required exactly this, so no caller
    // gains a bound.
    D: DepositPool<K> + Clone + Send + Sync + 'static,
    N: ActionableEventSource + Send + Sync + 'static,
    K: Keypair<SecretLen = hopr_api::types::primitive::typenum::U32> + Send + Sync + 'static,
    K::Public: Into<PixDepositAddress>
        + TryFrom<PixDepositAddress>
        + Eq
        + std::hash::Hash
        + Clone
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
    D::Error: Into<StrategyError>,
{
    /// Drops ledger entries that have aged out of the window and returns what is still committed.
    ///
    /// Called on every deposit event, so eviction keeps pace with arrivals without a timer.
    fn spent_in_window(&mut self) -> HoprBalance {
        let (window, now) = (self.cfg.spend_window, std::time::Instant::now());

        while let Some((at, _)) = self.spend_ledger.front() {
            if now.duration_since(*at) < window {
                break;
            }
            self.spend_ledger.pop_front();
        }

        self.spend_ledger
            .iter()
            .fold(HoprBalance::zero(), |total, (_, amount)| total + *amount)
    }

    /// Records `amount` against the window.
    ///
    /// Committed at the moment a deposit is accepted into the buffer rather than after it
    /// settles, and never refunded on failure: `deposit_funds_to` retries internally and
    /// re-reads the destination balance precisely because a transfer reported as failed may
    /// still have landed. A ledger that only counted confirmed spend could therefore under-count
    /// real ones, which is the wrong direction for a safety limit to err in.
    fn commit_spend(&mut self, amount: HoprBalance) {
        self.spend_ledger.push_back((std::time::Instant::now(), amount));

        // Fold the oldest entry into its successor. The merged amount then expires with the
        // *newer* timestamp, so it is counted for longer than it strictly should be — the
        // conservative direction for a cap.
        if self.spend_ledger.len() > SPEND_LEDGER_CAPACITY
            && let Some((_, oldest)) = self.spend_ledger.pop_front()
            && let Some((_, next)) = self.spend_ledger.front_mut()
        {
            *next += oldest;
        }
    }

    /// Validate and buffer a PIX event for batched execution.
    ///
    /// [`NewDepositAddress`] and [`PrivateKeyRecovered`] events are pushed into
    /// debounced buffers and flushed later by [`flush_deposits`] / [`flush_withdrawals`].
    /// [`DepositAddressReceived`] and [`DepositDataRequest`] are handled immediately, each in a
    /// task of its own.
    async fn on_pix_event(&mut self, event: PixEvent) -> Result<()> {
        match event {
            PixEvent::NewDepositAddress(new_deposit_address) => {
                tracing::info!(?new_deposit_address, "new deposit address");

                if self.processed_deposits.contains_key(&new_deposit_address.id) {
                    tracing::warn!(id = ?new_deposit_address.id, "duplicate NewDepositAddress event, skipping");
                    return Ok(());
                }

                let target_deposit = self.cfg.price_per_byte * new_deposit_address.quota;
                if target_deposit > self.cfg.max_ssa_allocation {
                    tracing::warn!(
                        %target_deposit,
                        max_deposit = %self.cfg.max_ssa_allocation,
                        "target deposit too high"
                    );
                    #[cfg(all(feature = "telemetry", not(test)))]
                    METRIC_PIX_DEPOSITS_REJECTED.increment();
                    return Err(StrategyError::CriteriaNotSatisfied);
                }

                // Checked here, next to the per-address ceiling, but committed only once the
                // event has cleared every other gate below — a deposit rejected for some other
                // reason spends nothing and must not consume the window.
                if !self.cfg.max_spend_per_window.is_zero() {
                    let spent = self.spent_in_window();
                    if spent + target_deposit > self.cfg.max_spend_per_window {
                        tracing::warn!(
                            %target_deposit,
                            %spent,
                            budget = %self.cfg.max_spend_per_window,
                            window = ?self.cfg.spend_window,
                            "deposit refused: it would cross the rolling spend limit"
                        );
                        #[cfg(all(feature = "telemetry", not(test)))]
                        METRIC_PIX_DEPOSITS_OVER_BUDGET.increment();
                        return Err(StrategyError::CriteriaNotSatisfied);
                    }
                }

                // The single narrowing from the wire form to the one this pool settles. It cannot
                // fail once the node's PIX spec and the pool agree on a scheme, which is what the
                // `A` witness on the builder makes a compile error — but the event type is a sum
                // over every scheme, so the conversion still has to be written.
                //
                // Logged with the same detail as the Exit-side narrowing below: a mismatch here
                // fires on every event and deposits nothing, and `run` only reports the returned
                // error, so a bare `InvalidInput` would leave an operator with no way to tell a
                // curve mismatch from any other rejected event.
                let address_type = new_deposit_address.address.address_type();
                let dest_addr: K::Public = new_deposit_address.address.try_into().map_err(|_| {
                    tracing::error!(
                        pix_id = ?new_deposit_address.id,
                        ?address_type,
                        "deposit address is not the form this pool settles - the node's PIX spec and the selected \
                         deposit pool disagree on the address scheme; pair `strategy-pix-*` with the matching \
                         `hopr-lib/pix-*` feature"
                    );
                    StrategyError::GeneralError(GeneralError::InvalidInput)
                })?;
                if self.in_flight_destinations.contains_key(&dest_addr) {
                    tracing::warn!(?dest_addr, "withdrawal already in flight to this destination, skipping");
                    return Ok(());
                }

                // The payload now carries its own allocation id, so there are two in this event and
                // they have to agree. A disagreement means the Entry was handed deposit data filed
                // under a different allocation than the one it is being asked to fund — the pool
                // would settle against `id` while the payload described another SSA — so it is
                // refused before any funds move, rather than passed on for the pool to reconcile.
                if new_deposit_address.deposit_data.id != new_deposit_address.id {
                    tracing::error!(
                        pix_id = ?new_deposit_address.id,
                        deposit_data_id = ?new_deposit_address.deposit_data.id,
                        "deposit data belongs to a different allocation than the deposit address it arrived with"
                    );
                    return Err(StrategyError::GeneralError(GeneralError::InvalidInput));
                }

                // Converted before the in-flight guard is claimed: a payload this pool cannot read
                // means the two ends disagree about which pool is running, and marking the
                // destination in flight for a deposit that is about to be rejected would block
                // the retry that a corrected peer would send.
                let deposit_data = D::PoolDepositData::try_from(new_deposit_address.deposit_data).map_err(|error| {
                    let error: StrategyError = error.into();
                    tracing::error!(
                        %error,
                        pix_id = ?new_deposit_address.id,
                        "additional deposit data is not the form this pool reads - the Entry and this node's \
                         deposit pool disagree on the payload format"
                    );
                    error
                })?;

                self.in_flight_destinations.insert(dest_addr.clone(), ());

                self.commit_spend(target_deposit);
                self.deposit_buffer
                    .push((new_deposit_address.id, dest_addr, target_deposit, deposit_data));

                tracing::info!(%target_deposit, "deposit buffered, pending flush");

                if self.cfg.deposit_buffer_period.is_zero() {
                    if self.detach_flushes {
                        self.detach_flush_deposits();
                    } else {
                        self.flush_deposits().await;
                    }
                }
            }
            PixEvent::DepositDataRequest(request) => {
                tracing::info!(count = request.deposit_ids.len(), "deposit data requested");

                // Not debounced, unlike the deposit and withdrawal arms: the Exit is blocked on
                // this channel before it can send its PIX request at all, so delaying the answer
                // delays the deposit that the answer is a precondition for.
                //
                // Spawned rather than awaited inline for the same reason `DepositAddressReceived`
                // is: what generation costs is the pool's business and is not bounded by anything
                // this strategy knows, and the event loop it would otherwise block is what feeds
                // every other event — including the flush deadlines.
                let pool = self.pool.clone();
                hopr_utils::runtime::prelude::spawn(async move {
                    let PixDepositDataRequest {
                        deposit_ids,
                        mut deposit_data_created,
                    } = request;

                    // Sequentially, in the order asked. The Exit matches payloads by their own
                    // `id`, so nothing depends on the order — but a batch is unbounded and
                    // fanning it all at the pool at once is not obviously kinder than pacing it.
                    //
                    // Unbounded is not the same as unpaced, which is why there is no cap on
                    // `deposit_ids` here. `DepositDataCreated` is a *bounded* sender, and the loop
                    // strictly alternates generate-then-send, so it advances only as fast as the
                    // Exit consumes and parks on backpressure otherwise. A cap would also have to
                    // drop ids to be worth anything, and the Exit rejects the Session when a
                    // payload is missing — so capping trades work the Exit asked for against
                    // sessions that cannot start. The request comes from this node's own PIX layer
                    // for one Session's SSAs, not from a peer, so its size is upstream's to bound.
                    for id in deposit_ids {
                        let generated = pool
                            .generate_deposit_data(&id)
                            .await
                            .map_err(Into::<StrategyError>::into)
                            .and_then(|data| data.try_into().map_err(Into::<StrategyError>::into));

                        match generated {
                            Ok(deposit_data) => {
                                if deposit_data_created.send(deposit_data).await.is_err() {
                                    // The Exit dropped the receiver: it is no longer waiting, so
                                    // the rest of the batch has nowhere to go.
                                    tracing::warn!(?id, "deposit data receiver is gone, abandoning the rest");
                                    break;
                                }
                                #[cfg(all(feature = "telemetry", not(test)))]
                                METRIC_PIX_DEPOSIT_DATA.increment_by(&["generated"], 1);
                            }
                            // Skipped rather than fatal to the batch: every other id in the
                            // request can still be answered. The Exit sees a payload missing when
                            // the channel closes below and rejects the Session, which is where
                            // that decision belongs.
                            Err(error) => {
                                tracing::error!(%error, ?id, "failed to generate deposit data");
                                #[cfg(all(feature = "telemetry", not(test)))]
                                METRIC_PIX_DEPOSIT_DATA.increment_by(&["failed"], 1);
                            }
                        }
                    }

                    // `deposit_data_created` drops here, closing the channel. That is the only
                    // signal the Exit gets that the set is complete — or, after an error above,
                    // that it never will be.
                });
            }
            PixEvent::DepositAddressReceived(deposit_address_recv) => {
                tracing::info!(?deposit_address_recv, "deposit address received");

                let pix_id = deposit_address_recv.id;
                let deposit_updated = deposit_address_recv.deposit_updated;
                let target_deposit = self.cfg.price_per_byte * deposit_address_recv.quota;

                let address_type = deposit_address_recv.address.address_type();
                let track_addr: K::Public = match deposit_address_recv.address.try_into() {
                    Ok(a) => a,
                    Err(_) => {
                        tracing::error!(
                            ?pix_id,
                            ?address_type,
                            "deposit address is not the form this pool settles - the node's PIX spec and the selected \
                             deposit pool disagree on the address scheme; pair `strategy-pix-*` with the matching \
                             `hopr-lib/pix-*` feature"
                        );
                        return Err(StrategyError::GeneralError(GeneralError::InvalidInput));
                    }
                };

                let notify_fut = match self.pool.notify_deposit(pix_id, track_addr, target_deposit) {
                    Ok(fut) => fut,
                    Err(error) => {
                        tracing::error!(%error, ?pix_id, "cannot track this deposit");
                        return Err(StrategyError::CriteriaNotSatisfied);
                    }
                };

                // The tracking deadline now lives in the pool, which is what the failure channel
                // on `notify_deposit`'s future bought: this used to reach into `cfg.pool` for a
                // bound the implementation already knew.
                hopr_utils::runtime::prelude::spawn(async move {
                    let result = notify_fut.await;

                    match result {
                        // The allocation id comes back from the pool rather than being captured
                        // from the event, so what is reported cannot drift from what was tracked.
                        Ok((id, _addr, balance)) => {
                            // The notifier is not optional: the Exit always wants to hear that the
                            // deposit landed. A send failure only means it stopped listening, which
                            // is its business, so it is dropped rather than reported.
                            let mut notifier = deposit_updated;
                            let _ = notifier.send((id, balance)).await;
                            #[cfg(all(feature = "telemetry", not(test)))]
                            METRIC_PIX_DEPOSIT_TRACKING.increment_by(&["confirmed"], 1);
                            tracing::info!("deposit tracking completed");
                        }
                        Err(ref _elapsed) => {
                            #[cfg(all(feature = "telemetry", not(test)))]
                            METRIC_PIX_DEPOSIT_TRACKING.increment_by(&["timeout"], 1);
                            tracing::error!("deposit tracking timed out");
                        }
                    }
                });
            }
            PixEvent::PrivateKeyRecovered(private_key_recovered) => {
                tracing::info!(?private_key_recovered, "private key recovered");

                if let Some(ref store) = self.recovery_store
                    && let Err(error) = store.insert(&private_key_recovered.id, &private_key_recovered.secret)
                {
                    tracing::error!(%error, ?private_key_recovered.id, "failed to persist recovered key");
                    return Err(StrategyError::other(error));
                }

                if self.in_flight_sweeps.contains_key(&private_key_recovered.id) {
                    tracing::warn!(?private_key_recovered.id, "sweep already in flight, skipping");
                    return Ok(());
                }
                self.in_flight_sweeps.insert(private_key_recovered.id, ());

                // Counted past the duplicate guard so a repeated event for the same SSA does
                // not inflate the total.
                #[cfg(all(feature = "telemetry", not(test)))]
                METRIC_PIX_KEYS_RECOVERED.increment();

                self.withdrawal_buffer
                    .push((private_key_recovered.id, private_key_recovered.secret));

                tracing::info!("withdrawal buffered, pending flush");

                if self.cfg.withdrawal_buffer_period.is_zero() {
                    if self.detach_flushes {
                        self.detach_flush_withdrawals();
                    } else {
                        self.flush_withdrawals().await;
                    }
                }
            }
        }

        Ok(())
    }

    /// Flush the buffered deposits, waiting for the pool to finish.
    ///
    /// Retries are the pool's responsibility, so an error here means the pool already
    /// exhausted its own budget and the deposit is abandoned for this flush.
    ///
    /// Used on the shutdown path, where there is no loop left to keep responsive and the work
    /// must complete before `run` returns. Everywhere else the loop uses
    /// [`Self::detach_flush_deposits`] — see there for why.
    async fn flush_deposits(&mut self) {
        let batch = std::mem::take(&mut self.deposit_buffer);
        flush_deposit_batch::<D, K>(
            self.pool.clone(),
            self.processed_deposits.clone(),
            self.in_flight_destinations.clone(),
            batch,
        )
        .await;
    }

    /// Hand the buffered deposits to a task and return immediately.
    ///
    /// The buffer is drained *here*, on the event loop, so a flush and the events that arrive
    /// during it cannot see the same entry twice. What is spawned is only the pool call.
    ///
    /// Concurrent flushes are safe because the guards outlive them: `in_flight_destinations` is
    /// populated in [`Self::on_pix_event`] before an entry is ever buffered and released by the
    /// flush that owns it, and its [`Cache`] clones share state — so a second event for the same
    /// destination is still refused while the first is in flight.
    fn detach_flush_deposits(&mut self) {
        if self.deposit_buffer.is_empty() {
            return;
        }

        let batch = std::mem::take(&mut self.deposit_buffer);
        let pool = self.pool.clone();
        let processed_deposits = self.processed_deposits.clone();
        let in_flight_destinations = self.in_flight_destinations.clone();

        hopr_utils::runtime::prelude::spawn(async move {
            flush_deposit_batch::<D, K>(pool, processed_deposits, in_flight_destinations, batch).await;
        });
    }

    /// Flush the buffered withdrawals, waiting for the pool to finish.
    ///
    /// Retries are the pool's responsibility. An entry that still fails keeps its persisted
    /// key so a later start can try again — see [`replay_pending_recoveries`].
    ///
    /// Used on the shutdown path; the loop uses [`Self::detach_flush_withdrawals`].
    async fn flush_withdrawals(&mut self) {
        let batch = std::mem::take(&mut self.withdrawal_buffer);
        flush_withdrawal_batch::<D, K>(
            self.pool.clone(),
            self.safe_address,
            self.in_flight_sweeps.clone(),
            self.recovery_store.clone(),
            batch,
        )
        .await;
    }

    /// Hand the buffered withdrawals to a task and return immediately.
    ///
    /// This is the one that matters. A sweep carries the pool's whole retry budget — five
    /// attempts with exponential backoff, on the order of a minute — and awaiting it here stops
    /// the loop dispatching *any* PIX event for that long. `DepositDataRequest` is the event that
    /// cannot survive it: the Exit blocks on the answer and gives up after three seconds, closing
    /// the Session with `MissingDepositData`. That arm is already spawned for exactly this
    /// reason, which is worth nothing while the arm before it holds the loop.
    ///
    /// Safe for the same reason [`Self::detach_flush_deposits`] is: `in_flight_sweeps` is claimed
    /// on the loop before the entry is buffered and released by the flush that owns it, and
    /// [`Cache`] clones share state.
    fn detach_flush_withdrawals(&mut self) {
        if self.withdrawal_buffer.is_empty() {
            return;
        }

        let batch = std::mem::take(&mut self.withdrawal_buffer);
        let pool = self.pool.clone();
        let safe_address = self.safe_address;
        let in_flight_sweeps = self.in_flight_sweeps.clone();
        let recovery_store = self.recovery_store.clone();

        hopr_utils::runtime::prelude::spawn(async move {
            flush_withdrawal_batch::<D, K>(pool, safe_address, in_flight_sweeps, recovery_store, batch).await;
        });
    }
}

/// Deposit one drained buffer through the pool.
///
/// A free function so that both the awaiting and the detached caller share one body: the loop
/// must not block on the pool (see [`PixStrategyInner::detach_flush_deposits`]), while shutdown
/// and the tests must. Splitting the drain from the work is what makes the same code serve both —
/// the buffer is emptied by the caller, on the event loop, and only this is spawned.
async fn flush_deposit_batch<D, K>(
    pool: D,
    processed_deposits: Cache<PixAddressId, ()>,
    in_flight_destinations: Cache<K::Public, ()>,
    batch: Vec<BufferedDeposit<D, K>>,
) where
    // `Send + Sync + 'static` beyond what the work itself needs, so the future is spawnable. The
    // `StrategyTrait` impl already requires exactly this of `D`, so no caller gains a bound.
    D: DepositPool<K> + Send + Sync + 'static,
    K: Keypair<SecretLen = hopr_api::types::primitive::typenum::U32> + Send + Sync + 'static,
    K::Public: Into<PixDepositAddress>
        + TryFrom<PixDepositAddress>
        + Eq
        + std::hash::Hash
        + Clone
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
    D::Error: Into<StrategyError>,
{
    let count = batch.len();
    if count == 0 {
        return;
    }

    if count == 1 {
        let (id, dest_addr, amount, deposit_data) = batch.into_iter().next().unwrap();
        let result = pool
            .deposit_funds_to(&id, &dest_addr, amount, deposit_data)
            .await
            .map_err(Into::<StrategyError>::into);

        match result {
            Ok(_) => {
                processed_deposits.insert(id, ());
                in_flight_destinations.invalidate(&dest_addr);
                tracing::info!(?id, %amount, "single deposit flushed successfully");
                #[cfg(all(feature = "telemetry", not(test)))]
                METRIC_PIX_DEPOSITS.increment();
            }
            Err(error) => {
                in_flight_destinations.invalidate(&dest_addr);
                tracing::error!(%error, ?id, "single deposit flush failed");
                #[cfg(all(feature = "telemetry", not(test)))]
                METRIC_PIX_DEPOSITS_FAILED.increment();
            }
        }
    } else {
        // The buffer is already the argument: see `deposit_buffer`.
        let result = pool
            .deposit_funds_to_multiple(&batch)
            .await
            .map_err(Into::<StrategyError>::into);

        match result {
            Ok(outcomes) => {
                // Every destination is released whatever happened, and only the allocations
                // that actually settled are recorded as processed. `BatchOutcomes` carries the
                // id in each outcome, so a partially failed batch no longer marks its failures
                // done — the duplicate guard would otherwise drop the retry a peer resends.
                for (_, dest_addr, ..) in &batch {
                    in_flight_destinations.invalidate(dest_addr);
                }

                let mut deposited = 0u64;
                for outcome in outcomes {
                    match outcome {
                        Ok((id, _receipt)) => {
                            processed_deposits.insert(id, ());
                            deposited += 1;
                        }
                        Err(error) => {
                            let error: StrategyError = error.into();
                            tracing::error!(%error, "deposit within the batch failed");
                        }
                    }
                }

                tracing::info!(count, deposited, "batch deposit flushed");
                #[cfg(all(feature = "telemetry", not(test)))]
                {
                    METRIC_PIX_DEPOSITS.increment_by(deposited);
                    METRIC_PIX_DEPOSITS_FAILED.increment_by(count as u64 - deposited);
                }
            }
            // The batch itself could not be attempted, as distinct from its items failing
            // individually above.
            Err(error) => {
                for (_, dest_addr, ..) in &batch {
                    in_flight_destinations.invalidate(dest_addr);
                }
                tracing::error!(%error, count, "batch deposit flush failed");
                #[cfg(all(feature = "telemetry", not(test)))]
                METRIC_PIX_DEPOSITS_FAILED.increment_by(count as u64);
            }
        }
    }
}

/// Sweep one drained buffer through the pool. The withdrawal counterpart of
/// [`flush_deposit_batch`]; see [`PixStrategyInner::detach_flush_withdrawals`] for why the loop
/// must not await it.
async fn flush_withdrawal_batch<D, K>(
    pool: D,
    safe_address: Address,
    in_flight_sweeps: Cache<PixAddressId, ()>,
    recovery_store: Option<PixRecoveryStore>,
    batch: Vec<(PixAddressId, PixDepositSecret)>,
) where
    // See [`flush_deposit_batch`].
    D: DepositPool<K> + Send + Sync + 'static,
    K: Keypair<SecretLen = hopr_api::types::primitive::typenum::U32> + Send + Sync + 'static,
    K::Public: Into<PixDepositAddress>
        + TryFrom<PixDepositAddress>
        + Eq
        + std::hash::Hash
        + Clone
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
    D::Error: Into<StrategyError>,
{
    let count = batch.len();
    if count == 0 {
        return;
    }

    if count == 1 {
        let (id, secret) = batch.into_iter().next().unwrap();
        let Ok(key) = key_from_secret::<K>(&secret) else {
            in_flight_sweeps.invalidate(&id);
            tracing::error!(?id, "stored recovery secret is not valid for this pool's scheme");
            return;
        };
        let result = pool
            .withdraw_deposit(&id, &key, safe_address, None)
            .await
            .map_err(Into::<StrategyError>::into);

        match result {
            Ok(_) => {
                in_flight_sweeps.invalidate(&id);
                if let Some(ref store) = recovery_store
                    && let Err(error) = store.remove(&id)
                {
                    tracing::error!(%error, ?id, "failed to remove the swept entry from the recovery store");
                }
                tracing::info!(?id, "single withdrawal flushed successfully");
                #[cfg(all(feature = "telemetry", not(test)))]
                METRIC_PIX_SWEEPS.increment();
            }
            Err(error) => {
                in_flight_sweeps.invalidate(&id);
                tracing::error!(%error, ?id, "single withdrawal flush failed");
            }
        }
    } else {
        // Each key travels with the id it belongs to, which is what `withdraw_multiple_deposits`
        // now takes. It used to take a bare `&[K]` alongside a separately built `Vec` of ids,
        // and results were matched back to ids by position — so a single unparseable secret
        // shortened the key list, shifted every later result, and attributed sweep outcomes to
        // the wrong allocations. That correlation is no longer expressible.
        let keys: Vec<(PixAddressId, K)> = batch
            .iter()
            .filter_map(|(id, secret)| match key_from_secret::<K>(secret) {
                Ok(key) => Some((*id, key)),
                Err(_) => {
                    tracing::error!(?id, "stored recovery secret is not valid for this pool's scheme");
                    in_flight_sweeps.invalidate(id);
                    None
                }
            })
            .collect();

        let attempted = keys.len();
        if attempted == 0 {
            tracing::error!(count, "no buffered withdrawal had a usable key, nothing to flush");
            return;
        }

        let result = pool
            .withdraw_multiple_deposits(&keys, safe_address)
            .await
            .map_err(Into::<StrategyError>::into);

        match result {
            Ok(outcomes) => {
                // Every attempted id is released whatever happened, so a later start can retry
                // one that did not move.
                for (id, _) in &keys {
                    in_flight_sweeps.invalidate(id);
                }

                // Keyed by the id in each outcome, not by position. `BatchOutcomes` carries the
                // allocation it belongs to, so nothing here has to assume the pool returned one
                // result per key in the order given — an assumption that, when this took a bare
                // `&[K]`, silently attributed sweep outcomes to the wrong allocations.
                let mut swept = 0u64;
                for outcome in outcomes {
                    match outcome {
                        Ok((id, _receipt)) => {
                            swept += 1;
                            if let Some(ref store) = recovery_store
                                && let Err(error) = store.remove(&id)
                            {
                                tracing::error!(%error, ?id, "failed to remove the swept entry from the recovery store");
                            }
                        }
                        // Keeps its persisted key, so the next start replays it.
                        Err(error) => {
                            let error: StrategyError = error.into();
                            tracing::error!(%error, "withdrawal within the batch failed");
                        }
                    }
                }
                // Only the items that actually moved funds are counted; the rest keep their
                // persisted key for a later retry. `attempted` is reported separately from
                // `count` so keys dropped above are visible rather than looking like failures.
                tracing::info!(count, attempted, swept, "batch withdrawal flushed");
                #[cfg(all(feature = "telemetry", not(test)))]
                METRIC_PIX_SWEEPS.increment_by(swept);
            }
            Err(error) => {
                for (id, _) in &keys {
                    in_flight_sweeps.invalidate(id);
                }
                tracing::error!(%error, count, attempted, "batch withdrawal flush failed");
            }
        }
    }
}

/// Rebuild the pool's keypair from the 32 bytes the recovery store persists.
///
/// The store predates the typed pool and holds a bare [`PixDepositSecret`], which is the same
/// representation for every scheme — so this is where a secret belonging to a different curve
/// would surface, as a scalar that does not parse. Keeping the store untyped is deliberate: it
/// is a durable on-disk format, and 32 bytes is what it has always held.
fn key_from_secret<K>(secret: &PixDepositSecret) -> Result<K>
where
    K: Keypair<SecretLen = hopr_api::types::primitive::typenum::U32>,
{
    K::from_secret(secret.0.as_ref()).map_err(StrategyError::other)
}

/// Re-attempt the sweep for every persisted recovery entry.
///
/// Entries are swept sequentially. An entry whose deposit address is still empty fails
/// with [`StrategyError::CriteriaNotSatisfied`] and is deliberately left in the store, so
/// a deposit that lands later is picked up by a subsequent start rather than lost.
///
/// This is a free function rather than a method so that [`StrategyTrait::run`] can spawn it:
/// each sweep carries the pool's own retry budget, and running the whole store inline would
/// stop the strategy consuming PIX events for as long as that takes. `in_flight_sweeps` is a
/// [`Cache`], whose clones share state, so the guard still excludes a concurrent sweep of the
/// same id from the event loop.
async fn replay_pending_recoveries<D, K>(
    pool: D,
    store: PixRecoveryStore,
    in_flight_sweeps: Cache<PixAddressId, ()>,
    safe_address: Address,
) where
    D: DepositPool<K>,
    K: Keypair<SecretLen = hopr_api::types::primitive::typenum::U32> + Send + Sync + 'static,
    K::Public: Into<PixDepositAddress>
        + TryFrom<PixDepositAddress>
        + Eq
        + std::hash::Hash
        + Clone
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
    D::Error: Into<StrategyError>,
{
    let entries = match store.iter() {
        Ok(entries) => entries,
        Err(error) => {
            tracing::error!(%error, "failed to iterate recovery store on startup");
            return;
        }
    };

    if entries.is_empty() {
        return;
    }

    tracing::info!(count = entries.len(), "replaying pending private key recoveries");

    for (id, secret) in entries {
        if in_flight_sweeps.contains_key(&id) {
            tracing::warn!(?id, "sweep already in flight for recovery replay entry, skipping");
            continue;
        }
        in_flight_sweeps.insert(id, ());

        let Ok(key) = key_from_secret::<K>(&secret) else {
            tracing::error!(?id, "stored recovery secret is not valid for this pool's scheme");
            continue;
        };
        let sweep_result = pool
            .withdraw_deposit(&id, &key, safe_address, None)
            .await
            .map_err(Into::<StrategyError>::into);

        match sweep_result {
            Ok(_) => {
                in_flight_sweeps.invalidate(&id);
                if let Err(error) = store.remove(&id) {
                    tracing::warn!(%error, ?id, "failed to remove swept entry from store");
                }
                tracing::info!(?id, "recovery replay completed");
            }
            Err(error) => {
                tracing::error!(%error, ?id, "recovery replay failed after max retries, giving up");
                in_flight_sweeps.invalidate(&id);
                // Leave the entry in the store for manual recovery.
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Display / Debug
// ---------------------------------------------------------------------------

impl<D, N, K> Display for PixStrategyInner<D, N, K>
where
    D: DepositPool<K>,
    K: Keypair<SecretLen = hopr_api::types::primitive::typenum::U32> + Send + Sync + 'static,
    K::Public: Into<PixDepositAddress>
        + TryFrom<PixDepositAddress>
        + Eq
        + std::hash::Hash
        + Clone
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "pix")
    }
}

impl<D, N, K> Debug for PixStrategyInner<D, N, K>
where
    D: DepositPool<K>,
    K: Keypair<SecretLen = hopr_api::types::primitive::typenum::U32> + Send + Sync + 'static,
    K::Public: Into<PixDepositAddress>
        + TryFrom<PixDepositAddress>
        + Eq
        + std::hash::Hash
        + Clone
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "PixStrategy({:?})", self.cfg)
    }
}

// ---------------------------------------------------------------------------
// Strategy trait impl
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl<D, N, K> StrategyTrait for PixStrategyInner<D, N, K>
where
    D: DepositPool<K> + Clone + Send + Sync + 'static,
    K: Keypair<SecretLen = hopr_api::types::primitive::typenum::U32> + Send + Sync + 'static,
    K::Public: Into<PixDepositAddress>
        + TryFrom<PixDepositAddress>
        + Eq
        + std::hash::Hash
        + Clone
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
    D::Error: Into<StrategyError>,
    N: ActionableEventSource + Send + Sync + 'static,
{
    /// Consume PIX events until the stream ends.
    ///
    /// Any persisted recovery entries are replayed in a task of their own rather than before
    /// the loop: a store holding many stranded entries would otherwise take the pool's full
    /// retry budget per entry with no PIX events consumed. The task is aborted once the loop
    /// exits — an interrupted replay loses nothing, because an entry is removed from the store
    /// only after its funds have moved.
    async fn run(&mut self) -> Result<()> {
        // From here on there is an event loop to keep responsive, so no flush may be awaited on
        // it — including the one a zero buffer period triggers from inside a handler. See
        // `detach_flushes`.
        self.detach_flushes = true;

        let mut event_stream = self
            .node
            .subscribe_to_actionable_events(Some(&[ActionableEventDiscriminant::Pix]))
            .map_err(|e| StrategyError::Other(anyhow::anyhow!(e)))?
            .filter_map(|event| futures::future::ready(event.try_as_pix()));

        let replay = self.recovery_store.clone().map(|store| {
            hopr_utils::runtime::prelude::spawn(replay_pending_recoveries(
                self.pool.clone(),
                store,
                self.in_flight_sweeps.clone(),
                self.safe_address,
            ))
        });

        // Debounce deadlines. `None` = not armed (no items buffered).
        let mut deposit_flush_at: Option<tokio::time::Instant> = None;
        let mut withdrawal_flush_at: Option<tokio::time::Instant> = None;

        loop {
            // Compute sleep deadline from active deposit/withdrawal timers.
            let sleep_deadline = [deposit_flush_at, withdrawal_flush_at]
                .iter()
                .filter_map(|&d| d)
                .min()
                .map(|d| d.max(tokio::time::Instant::now()));

            if let Some(deadline) = sleep_deadline {
                let sleep = tokio::time::sleep_until(deadline);
                tokio::pin!(let sleep = sleep;);

                tokio::select! {
                    biased;
                    maybe = event_stream.next() => {
                        if let Some(event) = maybe {
                            if let Err(error) = self.on_pix_event(event).await {
                                tracing::error!(%error, "pix event failed");
                            }
                            // Debounce: reset deadline when a new event arrives.
                            if !self.deposit_buffer.is_empty() {
                                deposit_flush_at = Some(tokio::time::Instant::now() + self.cfg.deposit_buffer_period);
                            }
                            if !self.withdrawal_buffer.is_empty() {
                                withdrawal_flush_at = Some(tokio::time::Instant::now() + self.cfg.withdrawal_buffer_period);
                            }
                        } else {
                            break;
                        }
                    }
                    _ = &mut sleep => {
                        // At least one deadline elapsed — hand off the ready buffers. Detached
                        // rather than awaited: the pool call carries its own retry budget, and
                        // waiting for it here is waiting with the event stream unread. The
                        // buffers are still drained synchronously, so the next iteration sees
                        // them empty and nothing is flushed twice.
                        let now = tokio::time::Instant::now();
                        if deposit_flush_at.is_some_and(|d| d <= now) {
                            self.detach_flush_deposits();
                            deposit_flush_at = None;
                        }
                        if withdrawal_flush_at.is_some_and(|d| d <= now) {
                            self.detach_flush_withdrawals();
                            withdrawal_flush_at = None;
                        }
                    }
                }
            } else {
                match event_stream.next().await {
                    Some(event) => {
                        if let Err(error) = self.on_pix_event(event).await {
                            tracing::error!(%error, "pix event failed");
                        }
                        if !self.deposit_buffer.is_empty() {
                            deposit_flush_at = Some(tokio::time::Instant::now() + self.cfg.deposit_buffer_period);
                        }
                        if !self.withdrawal_buffer.is_empty() {
                            withdrawal_flush_at = Some(tokio::time::Instant::now() + self.cfg.withdrawal_buffer_period);
                        }
                    }
                    None => break,
                }
            }
        }

        // Flush any remaining buffered items. Awaited, not detached: the loop is over, so there is
        // nothing left to keep responsive, and a task spawned here would race `run` returning.
        self.flush_deposits().await;
        self.flush_withdrawals().await;

        if let Some(replay) = replay {
            replay.abort();
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Gated on the secp pairing rather than plain `test`: every case here drives a real
// `NonAnonymousDepositPool` against a stub chain, so they exercise the pool as much as the
// strategy. The bjj pairing has no equivalent yet because its pool is a stub — when
// `CurvyDepositPool` is implemented, the engine-level cases here are the ones worth
// generalising over `PoolKeypair` rather than duplicating.
#[cfg(all(test, feature = "strategy-pix-test"))]
mod tests {
    use std::{num::NonZeroU32, sync::Arc, time::Duration as StdDuration};

    use anyhow::Context;
    use futures::{StreamExt, channel::mpsc};
    use hex_literal::hex;
    use hopr_api::{
        chain::{
            AccountSelector, ChainEvents, ChainReadAccountOperations, ChainReadChannelOperations, ChainValues,
            ChainWriteAccountOperations, HoprChainApi,
        },
        node::{
            ActionableEvent, ActionableEventDiscriminant, ActionableEventSource, ComponentStatus,
            ComponentStatusReporter, EventWaitResult, HasChainApi, NodeOnchainIdentity, PixAddressId,
            PixDepositAddressReceived, PixDepositData, PixDepositDataRequest, PixEvent,
        },
        types::{
            crypto::{
                keypairs::Keypair,
                prelude::{ChainKeypair, OffchainKeypair},
            },
            crypto_random::Randomizable,
            internal::prelude::{AccountEntry, AccountType, HoprPseudonym},
            primitive::prelude::{Address, HoprBalance, XDaiBalance},
        },
    };
    use tokio::time::timeout;

    use super::{PixStrategy, PixStrategyConfig, PixStrategyInner};
    use crate::{
        errors::StrategyError,
        pix::{
            ByteDepositData,
            pools::plain::{DEPOSIT_MARKER_PAYLOAD, NonAnonymousDepositPool},
            recovery_store::PixRecoveryStore,
        },
        testing::{BlokliTestClient, BlokliTestStateBuilder, FullStateEmulator, TestChainConnector},
    };

    /// Owned exclusively by `test_build_with_recovery_path_opens_store`. Tests share one
    /// process environment and run on several threads, so a name used by two tests can be
    /// unset by one while the other still needs it.
    const BUILD_PASSWORD_ENV: &str = "HOPRD_TEST_PIX_RECOVERY_PASSWORD_BUILD";

    lazy_static::lazy_static! {
        static ref BOB_KP: ChainKeypair = ChainKeypair::from_secret(&hex!(
            "492057cf93e99b31d2a85bc5e98a9c3aa0021feec52c227cc8170e8f7d047775"
        )).expect("lazy static keypair");

        static ref ALICE: Address = hex!("18f8ae833c85c51fbeba29cef9fbfb53b3bad950").into();
        static ref BOB: Address = BOB_KP.public().to_address();
        static ref CHRIS: Address = hex!("b6021e0860dd9d96c9ff0a73e2e5ba3a466ba234").into();
    }

    const MODULE_ADDRESS: [u8; 20] = [1u8; 20];

    /// A fresh allocation id at `ssa_index`, with a random session behind it.
    ///
    /// Random per call, so two ids only collide if they are meant to: tests that need the same
    /// allocation twice reuse one value rather than rebuilding it.
    fn pix_id(ssa_index: u32) -> PixAddressId {
        PixAddressId::new(
            &HoprPseudonym::random(),
            NonZeroU32::new(ssa_index).expect("ssa index must be non-zero"),
        )
    }

    /// The wire payload `NonAnonymousDepositPool` generates and accepts, filed under `id`.
    ///
    /// Every test here drives that pool, so this is what an event has to carry for the deposit to
    /// be settled rather than refused — see `plain::DEPOSIT_MARKER_PAYLOAD`.
    ///
    /// `id` has to be the same value the event carries, so callers bind it to a local first rather
    /// than calling `pix_id` twice — [`pix_id`] is random per call.
    fn pool_deposit_data(id: PixAddressId) -> PixDepositData {
        PixDepositData {
            id,
            data: DEPOSIT_MARKER_PAYLOAD.into(),
        }
    }

    /// Registers the node account with **itself** as its Safe, and credits that account.
    ///
    /// [`ChainNode::identity`] reports `safe_address == node_address`, while
    /// `with_generated_accounts` derives a *distinct* Safe per account. Left to disagree, a deposit
    /// would be gated on one account's balance and settled out of another's — which is exactly the
    /// class of defect this module's payer handling exists to prevent, so the two are made to
    /// agree rather than papered over in the assertions.
    ///
    /// Tests that genuinely need the node and its Safe to be different accounts live in
    /// `pix::pools::plain`, whose fixture keeps them apart on purpose.
    fn with_self_safed_node(
        builder: BlokliTestStateBuilder,
        node: Address,
        key_id: u32,
        balance: HoprBalance,
    ) -> BlokliTestStateBuilder {
        // Derived from the address rather than random: these fixtures feed snapshot assertions,
        // and a fresh packet key each run would never match twice.
        let packet_key =
            OffchainKeypair::from_secret(hopr_api::types::crypto::types::Hash::create(&[node.as_ref()]).as_ref())
                .expect("offchain keypair creation cannot fail");

        builder
            .with_accounts([(
                AccountEntry {
                    public_key: *packet_key.public(),
                    chain_addr: node,
                    entry_type: AccountType::NotAnnounced,
                    safe_address: Some(node),
                    key_id: key_id.into(),
                },
                balance,
                XDaiBalance::new_base(1),
            )])
            // `with_accounts` credits the Safe and zeroes the node's own token balance, then
            // zeroes the Safe's xDai. Both writes land on this one account, so the float and the
            // gas have to be put back afterwards.
            .with_balances([(node, balance)])
            .with_balances([(node, XDaiBalance::new_base(1))])
    }

    struct ChainNode<C>(C);

    impl<C> HasChainApi for ChainNode<C>
    where
        C: HoprChainApi + ChainReadChannelOperations + ComponentStatusReporter + Clone + Send + Sync + 'static,
    {
        type ChainApi = C;
        type ChainError = <C as HoprChainApi>::ChainError;

        fn identity(&self) -> &NodeOnchainIdentity {
            static IDENTITY: std::sync::OnceLock<NodeOnchainIdentity> = std::sync::OnceLock::new();
            IDENTITY.get_or_init(|| {
                let me = *self.0.me();
                NodeOnchainIdentity {
                    node_address: me,
                    safe_address: me,
                    module_address: MODULE_ADDRESS.into(),
                }
            })
        }

        fn chain_api(&self) -> &C {
            &self.0
        }

        fn status(&self) -> ComponentStatus {
            self.0.component_status()
        }

        fn wait_for_on_chain_event<F>(
            &self,
            _: F,
            _: String,
            _: std::time::Duration,
        ) -> EventWaitResult<<C as HoprChainApi>::ChainError, <C as HoprChainApi>::ChainError>
        where
            F: Fn(&hopr_api::chain::ChainEvent) -> bool + Send + Sync + 'static,
        {
            unimplemented!()
        }
    }

    impl<C> ActionableEventSource for ChainNode<C>
    where
        C: ChainEvents + Send + Sync + 'static,
    {
        fn subscribe_to_actionable_events(
            &self,
            _: Option<&[ActionableEventDiscriminant]>,
        ) -> std::result::Result<futures::stream::BoxStream<'static, ActionableEvent>, String> {
            Ok(self
                .0
                .subscribe()
                .map_err(|e| e.to_string())?
                .map(ActionableEvent::Chain)
                .boxed())
        }
    }

    async fn register_test_safe<C>(cc: &C, addr: Address) -> anyhow::Result<()>
    where
        C: HoprChainApi + ChainReadAccountOperations + ChainWriteAccountOperations,
    {
        let account = cc
            .stream_accounts(AccountSelector::default().with_chain_key(addr))?
            .next()
            .await
            .context("no account")?;
        let safe = account.safe_address.context("no safe")?;
        cc.register_safe(&safe).await?.await?;
        Ok(())
    }

    /// Pool config with the retry budgets zeroed.
    ///
    /// Every test using this helper asserts on the outcome of a single attempt, so retrying
    /// would only add real backoff sleeps to the suite. Tests that are *about* retrying use
    /// [`pool_cfg_with_retries`].
    fn pool_cfg(t: StdDuration, g: XDaiBalance) -> crate::pix::pools::plain::NonAnonymousDepositPoolConfig {
        pool_cfg_with_retries(t, g, 0, 0)
    }

    fn pool_cfg_with_retries(
        t: StdDuration,
        g: XDaiBalance,
        max_deposit_retries: usize,
        max_sweep_retries: usize,
    ) -> crate::pix::pools::plain::NonAnonymousDepositPoolConfig {
        crate::pix::pools::plain::NonAnonymousDepositPoolConfig {
            max_deposit_tracking_time: t,
            gas_xdai_per_sweep: g,
            max_deposit_retries,
            max_sweep_retries,
            ..Default::default()
        }
    }

    /// Helper to query a HOPR balance from the chain connector through ChainValues.
    async fn hopr_balance(cc: &impl ChainValues, addr: Address) -> anyhow::Result<HoprBalance> {
        ChainValues::balance(cc, addr).await.map_err(Into::into)
    }

    // ── Tests ──────────────────────────────────────────────────────

    #[test_log::test(tokio::test)]
    async fn test_deposit_address_received_notifies_on_balance_arrival() -> anyhow::Result<()> {
        let target = HoprBalance::new_base(100);
        let addr: Address = [0x99u8; 20].into();
        let (tx, mut rx) = mpsc::channel::<(hopr_api::node::PixAddressId, HoprBalance)>(1);

        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .with_balances([(addr, target)])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut cc = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        cc.connect().await?;
        let client = cc.client();
        let cc = Arc::new(cc);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::with_client(
            Arc::clone(&node),
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
            client,
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
            ..Default::default()
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        let id = pix_id(1);
        s.on_pix_event(PixEvent::DepositAddressReceived(PixDepositAddressReceived {
            id,
            address: addr.into(),
            quota: 100,
            deposit_updated: tx,
            deposit_data: pool_deposit_data(id),
        }))
        .await?;
        let n = timeout(StdDuration::from_secs(10), rx.next())
            .await?
            .context("no notification")?;
        assert_eq!(n.1, target);
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_new_deposit_address_withdraws_to_deposit_address() -> anyhow::Result<()> {
        let da: Address = [0x42u8; 20].into();
        let sim = BlokliTestStateBuilder::default().with_generated_accounts(
            &[&*ALICE, &*CHRIS],
            false,
            XDaiBalance::new_base(1),
            HoprBalance::new_base(1000),
        );
        let sim = with_self_safed_node(sim, *BOB, 9, HoprBalance::new_base(1000))
            // `deposit_funds_to` reads the destination balance before transferring, and the
            // stub chain has no entry for an address that was never funded.
            .with_balances([(da, HoprBalance::zero())])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let snap = sim.snapshot();
        let mut cc = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        cc.connect().await?;
        let client = cc.client();
        let cc = Arc::new(cc);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::with_client(
            Arc::clone(&node),
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
            client,
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
            ..Default::default()
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        let bb: HoprBalance = hopr_balance(&*cc, *BOB).await?;
        let id = pix_id(1);
        s.on_pix_event(PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
            id,
            address: da.into(),
            quota: 20,
            deposit_data: pool_deposit_data(id),
        }))
        .await?;
        s.flush_deposits().await;
        assert_eq!(hopr_balance(&*cc, *BOB).await?, bb - HoprBalance::new_base(20));
        assert_eq!(hopr_balance(&*cc, da).await?, HoprBalance::new_base(20));
        insta::assert_yaml_snapshot!(*snap.refresh(), { ".chain_info.contract_addresses" => "[contract_addresses]" });
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_new_deposit_address_rejects_when_exceeds_max_ssa_allocation() -> anyhow::Result<()> {
        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut cc = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        cc.connect().await?;
        let client = cc.client();
        let cc = Arc::new(cc);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::with_client(
            Arc::clone(&node),
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
            client,
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(10),
            max_ssa_allocation: HoprBalance::new_base(50),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
            ..Default::default()
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        let id = pix_id(1);
        let r = s
            .on_pix_event(PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
                id,
                address: Address::from([0x42u8; 20]).into(),
                quota: 10,
                deposit_data: pool_deposit_data(id),
            }))
            .await;
        assert!(matches!(r, Err(StrategyError::CriteriaNotSatisfied)));
        Ok(())
    }

    /// Deposit data this pool cannot read must stop the deposit, not be dropped on the way past.
    ///
    /// `NonAnonymousDepositPool` accepts exactly `DEPOSIT_MARKER_PAYLOAD`; anything else means the
    /// Entry and this node's pool disagree on the payload format — the same class of mismatch as a
    /// wrong curve. Settling anyway would be the silent failure the check exists to prevent, so the
    /// assertion that matters is that the destination is *not* funded.
    ///
    /// The rejection happens inside the pool rather than at the `PixDepositData` conversion, which
    /// is shared by every pool and so cannot know what any one of them reads. That puts it after
    /// the event is buffered, which is why `on_pix_event` itself returns `Ok`: `flush_deposits`
    /// reports the pool's error through the log and the failure metric rather than through its
    /// return value.
    ///
    /// The in-flight destination guard must not survive the rejection: a corrected peer retrying
    /// the same address has to get through, which the second half of the test exercises directly.
    #[test_log::test(tokio::test)]
    async fn test_new_deposit_address_does_not_settle_unreadable_deposit_data() -> anyhow::Result<()> {
        let dest_addr = Address::from([0x42u8; 20]);
        let sim = BlokliTestStateBuilder::default().with_generated_accounts(
            &[&*ALICE, &*CHRIS],
            false,
            XDaiBalance::new_base(1),
            HoprBalance::new_base(1000),
        );
        let sim = with_self_safed_node(sim, *BOB, 9, HoprBalance::new_base(1000))
            // `deposit_funds_to` reads the destination balance before transferring, and the
            // stub chain has no entry for an address that was never funded.
            .with_balances([(dest_addr, HoprBalance::zero())])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut cc = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        cc.connect().await?;
        let client = cc.client();
        let cc = Arc::new(cc);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::with_client(
            Arc::clone(&node),
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
            client,
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(1000),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
            ..Default::default()
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);

        let id = pix_id(1);
        s.on_pix_event(PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
            id,
            address: dest_addr.into(),
            quota: 10,
            deposit_data: PixDepositData {
                id,
                data: vec![0xde, 0xad, 0xbe, 0xef].into(),
            },
        }))
        .await?;

        assert_eq!(
            hopr_balance(&*cc, dest_addr).await?,
            HoprBalance::zero(),
            "a payload this pool cannot read must not be settled"
        );
        assert!(
            !s.processed_deposits.contains_key(&id),
            "a refused deposit must not be recorded as processed"
        );
        assert!(s.deposit_buffer.is_empty(), "a refused deposit must not stay buffered");
        assert!(
            !s.in_flight_destinations.contains_key(&dest_addr),
            "the destination must be freed so a corrected retry can get through"
        );

        // The payload is the only thing that differed, so the same allocation and the same
        // destination now settle — which is what makes the assertions above about the payload
        // rather than about the deposit path being broken in some unrelated way.
        s.on_pix_event(PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
            id,
            address: dest_addr.into(),
            quota: 10,
            deposit_data: pool_deposit_data(id),
        }))
        .await?;

        assert_eq!(
            hopr_balance(&*cc, dest_addr).await?,
            HoprBalance::new_base(10),
            "the corrected retry must settle"
        );
        Ok(())
    }

    /// Deposit data filed under a different allocation than the address it arrived with is refused.
    ///
    /// `PixDepositData` carries its own id, so this event has two — and if they disagree, the pool
    /// would be told to settle against one allocation using a payload describing another. Refused
    /// before any funds move, and, as with an unreadable payload, without leaving the destination
    /// marked in flight.
    #[test_log::test(tokio::test)]
    async fn test_new_deposit_address_rejects_deposit_data_for_another_allocation() -> anyhow::Result<()> {
        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut cc = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        cc.connect().await?;
        let client = cc.client();
        let node = Arc::new(ChainNode(Arc::new(cc)));
        let pool = Arc::new(NonAnonymousDepositPool::with_client(
            Arc::clone(&node),
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
            client,
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(1000),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
            ..Default::default()
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);

        let dest_addr = Address::from([0x43u8; 20]);
        let r = s
            .on_pix_event(PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
                id: pix_id(1),
                address: dest_addr.into(),
                quota: 10,
                // A well-formed, readable, *empty* payload — it is only the id that is wrong, so
                // this cannot be mistaken for the payload-format rejection above.
                deposit_data: pool_deposit_data(pix_id(2)),
            }))
            .await;

        assert!(
            matches!(r, Err(StrategyError::GeneralError(_))),
            "deposit data for another allocation must be rejected, got {r:?}"
        );
        assert!(
            s.deposit_buffer.is_empty(),
            "a rejected event must not leave a deposit buffered"
        );
        assert!(
            !s.in_flight_destinations.contains_key(&dest_addr),
            "the destination must stay free so a corrected retry can get through"
        );
        Ok(())
    }

    /// The Exit asks for deposit data and gets exactly one payload per requested allocation.
    ///
    /// Both bundled pools carry nothing, so every payload is empty but for its id — what is under
    /// test is the routing: one payload per id, each filed under the id that was asked for, and the
    /// channel closed afterwards so the Exit can tell the set is complete. The handler is spawned,
    /// hence the timeout on the read rather than a bare `next()`.
    #[test_log::test(tokio::test)]
    async fn test_deposit_data_request_answers_every_requested_allocation() -> anyhow::Result<()> {
        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut cc = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        cc.connect().await?;
        let client = cc.client();
        let node = Arc::new(ChainNode(Arc::new(cc)));
        let pool = Arc::new(NonAnonymousDepositPool::with_client(
            Arc::clone(&node),
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
            client,
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(1000),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
            ..Default::default()
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);

        let requested = vec![pix_id(1), pix_id(2), pix_id(3)];
        // Unbuffered, so a handler that sent everything before yielding would deadlock against a
        // receiver that is only read after `on_pix_event` returns — which is exactly the shape a
        // spawned handler must survive.
        let (tx, rx) = mpsc::channel(0);

        s.on_pix_event(PixEvent::DepositDataRequest(PixDepositDataRequest {
            deposit_ids: requested.clone(),
            deposit_data_created: tx,
        }))
        .await?;

        let delivered: Vec<_> = timeout(StdDuration::from_secs(10), rx.collect()).await?;

        assert_eq!(
            delivered.iter().map(|d| d.id).collect::<Vec<_>>(),
            requested,
            "one payload per requested allocation, in the order asked"
        );
        assert!(
            delivered.iter().all(|d| *d.data == DEPOSIT_MARKER_PAYLOAD),
            "every payload must be the marker the receiving pool checks for"
        );
        Ok(())
    }

    /// A request the Exit has abandoned does not keep the strategy generating.
    ///
    /// Dropping the receiver is the only signal that the Exit gave up, and the send failure it
    /// causes has to end the batch rather than be logged once per remaining id.
    #[test_log::test(tokio::test)]
    async fn test_deposit_data_request_stops_when_the_receiver_is_gone() -> anyhow::Result<()> {
        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut cc = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        cc.connect().await?;
        let client = cc.client();
        let node = Arc::new(ChainNode(Arc::new(cc)));
        let pool = Arc::new(NonAnonymousDepositPool::with_client(
            Arc::clone(&node),
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
            client,
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(1000),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
            ..Default::default()
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);

        let (tx, rx) = mpsc::channel(0);
        drop(rx);

        // The event itself still succeeds: the handler is spawned, so the failure is the task's and
        // is reported through the log. What must not happen is a hang or a panic.
        s.on_pix_event(PixEvent::DepositDataRequest(PixDepositDataRequest {
            deposit_ids: vec![pix_id(1), pix_id(2)],
            deposit_data_created: tx,
        }))
        .await?;

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_unusable_secret_releases_the_in_flight_sweep_guard() -> anyhow::Result<()> {
        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(2),
                HoprBalance::new_base(1000),
            )
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut cc = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        cc.connect().await?;
        let client = cc.client();
        let cc = Arc::new(cc);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::with_client(
            Arc::clone(&node),
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
            client,
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
            ..Default::default()
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        let id = pix_id(1);
        // Buffer a sweep with an invalid secret — on_pix_event succeeds.
        s.on_pix_event(PixEvent::PrivateKeyRecovered(hopr_api::node::PixPrivateKeyRecovered {
            id,
            secret: hopr_api::chain::PixDepositSecret(
                hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").into(),
            ),
        }))
        .await?;
        // Flush should fail with the invalid secret and release the guard.
        s.flush_withdrawals().await;
        assert!(!s.in_flight_sweeps.contains_key(&id));
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_private_key_recovered_withdraws_to_safe() -> anyhow::Result<()> {
        let rk = hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let rkp = ChainKeypair::from_secret(&rk)?;
        let ra = rkp.public().to_address();
        let rib = HoprBalance::new_base(50);

        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .with_balances([(ra, rib)])
            .with_balances([(ra, XDaiBalance::new_base(1))])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let snap = sim.snapshot();
        let mut connector = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        connector.connect().await?;
        let client = connector.client();
        register_test_safe(&connector, *BOB).await?;
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::with_client(
            Arc::clone(&node),
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
            client,
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
            ..Default::default()
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        s.on_pix_event(PixEvent::PrivateKeyRecovered(hopr_api::node::PixPrivateKeyRecovered {
            id: pix_id(1),
            secret: hopr_api::chain::PixDepositSecret(rk.into()),
        }))
        .await?;
        s.flush_withdrawals().await;
        assert!(hopr_balance(&*cc, ra).await?.is_zero());
        assert!(hopr_balance(&*cc, *BOB).await? >= rib);
        insta::assert_yaml_snapshot!(*snap.refresh(), { ".chain_info.contract_addresses" => "[contract_addresses]" });
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_config_default_passes_validation() -> anyhow::Result<()> {
        validator::Validate::validate(&PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
            ..Default::default()
        })?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_build_returns_strategy_trait_object() -> anyhow::Result<()> {
        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut cc = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        cc.connect().await?;
        let s = PixStrategy::new(PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
            ..Default::default()
        })
        .build_non_anonymous::<_, Address>(
            Arc::new(ChainNode(Arc::new(cc))),
            BOB_KP.clone(),
            Default::default(),
        )?;
        assert_eq!(s.to_string(), "pix");
        fn assert_send<T: Send>(_: &T) {}
        assert_send(&s);
        Ok(())
    }

    // ── Rolling spend limit ────────────────────────────────────────

    type SpendTestConnector = Arc<TestChainConnector<crate::testing::FullStateEmulator>>;
    type SpendTestNode = ChainNode<SpendTestConnector>;

    /// A connected Entry-side node with each of `destinations` pre-created empty.
    ///
    /// `deposit_funds_to` reads the destination balance before transferring, and the stub chain
    /// has no entry for an address that was never funded.
    async fn entry_side(
        destinations: &[Address],
    ) -> anyhow::Result<(
        SpendTestConnector,
        Arc<SpendTestNode>,
        Arc<NonAnonymousDepositPool<SpendTestNode, BlokliTestClient<FullStateEmulator>>>,
    )> {
        let mut builder = with_self_safed_node(
            BlokliTestStateBuilder::default().with_generated_accounts(
                &[&*ALICE, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            ),
            *BOB,
            9,
            HoprBalance::new_base(1000),
        );
        for destination in destinations {
            builder = builder.with_balances([(*destination, HoprBalance::zero())]);
        }

        let mut cc = TestChainConnector::new(
            builder.build_dynamic_client(MODULE_ADDRESS.into()),
            *BOB,
            BOB_KP.clone(),
            MODULE_ADDRESS.into(),
        );
        cc.connect().await?;
        let client = cc.client();
        let cc = Arc::new(cc);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::with_client(
            Arc::clone(&node),
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
            client,
        ));
        Ok((cc, node, pool))
    }

    /// A `PixStrategyConfig` that flushes immediately, so a deposit's effect is observable as
    /// soon as the event has been handled.
    fn spend_cfg(max_spend_per_window: HoprBalance, spend_window: StdDuration) -> PixStrategyConfig {
        PixStrategyConfig {
            max_spend_per_window,
            spend_window,
            // Stated rather than inherited: these tests price a quota and then assert on the
            // resulting deposit, so the arithmetic depends on both.
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
            ..Default::default()
        }
    }

    fn new_deposit(address: Address, quota: u64) -> PixEvent {
        // `pix_id` is random per call, so every event carries a distinct allocation — which is
        // what these tests need: distinct ids to distinct addresses clear the dedupe cache and the
        // in-flight guard, leaving the spend limit as the only thing that can refuse them.
        let id = pix_id(1);
        PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
            id,
            address: address.into(),
            quota,
            deposit_data: pool_deposit_data(id),
        })
    }

    /// The aggregate ceiling the per-address one never provided.
    ///
    /// Distinct ids to distinct addresses clear the dedupe, the in-flight guard and
    /// `max_ssa_allocation` alike, so before this limit existed a stream of them drained the
    /// node's whole float one legitimate-looking deposit at a time.
    #[test_log::test(tokio::test)]
    async fn test_deposits_are_refused_once_the_rolling_spend_limit_is_crossed() -> anyhow::Result<()> {
        let (first, second): (Address, Address) = ([0x42u8; 20].into(), [0x43u8; 20].into());
        let (cc, node, pool) = entry_side(&[first, second]).await?;

        let mut s = PixStrategyInner::new(
            pool,
            node,
            spend_cfg(HoprBalance::new_base(50), StdDuration::from_secs(3600)),
            *BOB,
            None,
        );

        s.on_pix_event(new_deposit(first, 30)).await?;
        assert_eq!(hopr_balance(&*cc, first).await?, HoprBalance::new_base(30));

        // 30 already committed + 30 more would be 60, past the 50 ceiling.
        let result = s.on_pix_event(new_deposit(second, 30)).await;

        assert!(matches!(result, Err(StrategyError::CriteriaNotSatisfied)));
        assert!(
            hopr_balance(&*cc, second).await?.is_zero(),
            "the refused deposit must not be funded"
        );
        Ok(())
    }

    /// The window rolls rather than resetting on a fixed boundary, so the budget frees up as the
    /// oldest deposits age out and a node that tripped the limit recovers by itself.
    #[test_log::test(tokio::test)]
    async fn test_rolling_spend_limit_frees_up_as_the_window_advances() -> anyhow::Result<()> {
        let (first, second): (Address, Address) = ([0x42u8; 20].into(), [0x43u8; 20].into());
        let (cc, node, pool) = entry_side(&[first, second]).await?;

        // Buffered rather than flushed per event: a confirmation takes about a second on the stub
        // chain, which would age the first deposit out of a window this short before the second
        // one is even offered.
        let mut cfg = spend_cfg(HoprBalance::new_base(30), StdDuration::from_secs(1));
        cfg.deposit_buffer_period = StdDuration::from_secs(60);
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);

        s.on_pix_event(new_deposit(first, 30)).await?;
        assert!(
            matches!(
                s.on_pix_event(new_deposit(second, 30)).await,
                Err(StrategyError::CriteriaNotSatisfied)
            ),
            "the budget must be exhausted immediately after the first deposit"
        );

        tokio::time::sleep(StdDuration::from_millis(1300)).await;

        s.on_pix_event(new_deposit(second, 30)).await?;
        s.flush_deposits().await;
        assert_eq!(
            hopr_balance(&*cc, second).await?,
            HoprBalance::new_base(30),
            "the same deposit must succeed once the first has aged out of the window"
        );
        Ok(())
    }

    /// Zero opts out, matching how a zero `gas_xdai_per_sweep` disables the gas top-up.
    #[test_log::test(tokio::test)]
    async fn test_zero_spend_limit_disables_the_check() -> anyhow::Result<()> {
        let addresses: [Address; 3] = [[0x42u8; 20].into(), [0x43u8; 20].into(), [0x44u8; 20].into()];
        let (cc, node, pool) = entry_side(&addresses).await?;

        let mut s = PixStrategyInner::new(
            pool,
            node,
            spend_cfg(HoprBalance::zero(), StdDuration::from_secs(3600)),
            *BOB,
            None,
        );

        // Well past any of the defaults, and past the node's own float were it not for the pool's
        // own affordability check.
        for address in addresses {
            s.on_pix_event(new_deposit(address, 100)).await?;
            assert_eq!(hopr_balance(&*cc, address).await?, HoprBalance::new_base(100));
        }
        Ok(())
    }

    /// The window counts committed deposits, not attempted ones.
    ///
    /// The limit is checked alongside `max_ssa_allocation` but committed only after every other
    /// gate has passed, so an event refused for an unrelated reason — which spends nothing — must
    /// leave the budget where it was.
    #[test_log::test(tokio::test)]
    async fn test_deposit_rejected_for_another_reason_does_not_consume_the_window() -> anyhow::Result<()> {
        let (oversized, ordinary): (Address, Address) = ([0x42u8; 20].into(), [0x43u8; 20].into());
        let (cc, node, pool) = entry_side(&[oversized, ordinary]).await?;

        let mut cfg = spend_cfg(HoprBalance::new_base(50), StdDuration::from_secs(3600));
        cfg.max_ssa_allocation = HoprBalance::new_base(50);
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);

        // Refused by the per-address ceiling, which is checked first.
        assert!(matches!(
            s.on_pix_event(new_deposit(oversized, 100)).await,
            Err(StrategyError::CriteriaNotSatisfied)
        ));

        // Would fail if the rejected event above had eaten the window's whole budget.
        s.on_pix_event(new_deposit(ordinary, 50)).await?;
        assert_eq!(hopr_balance(&*cc, ordinary).await?, HoprBalance::new_base(50));
        Ok(())
    }

    /// The same invariant, for a gate that runs *after* the spend check rather than before it.
    ///
    /// `max_ssa_allocation` above is checked first, so that case never reaches the spend limit at
    /// all. The deposit-data gates are the harder half: the limit has already been consulted and
    /// passed by the time the payload is rejected, so only the fact that `commit_spend` runs last
    /// keeps the budget intact. Moving the commit up beside its check would leave the test above
    /// green and silently start charging the window for events that deposit nothing.
    #[test_log::test(tokio::test)]
    async fn test_deposit_rejected_after_the_spend_check_does_not_consume_the_window() -> anyhow::Result<()> {
        let (mismatched, ordinary): (Address, Address) = ([0x44u8; 20].into(), [0x45u8; 20].into());
        let (cc, node, pool) = entry_side(&[mismatched, ordinary]).await?;

        // Budget is exactly one 50 wxHOPR deposit, and the per-address ceiling is high enough that
        // it cannot be what refuses either event.
        let mut cfg = spend_cfg(HoprBalance::new_base(50), StdDuration::from_secs(3600));
        cfg.max_ssa_allocation = HoprBalance::new_base(100);
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);

        // Clears dedupe, the per-address ceiling and the spend limit; refused only because the
        // payload names a different allocation than the address it arrived with.
        let id = pix_id(1);
        let refused = s
            .on_pix_event(PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
                id,
                address: mismatched.into(),
                quota: 50,
                deposit_data: pool_deposit_data(pix_id(2)),
            }))
            .await;
        assert!(
            matches!(refused, Err(StrategyError::GeneralError(_))),
            "expected the id-mismatch rejection, got {refused:?}"
        );
        assert!(
            hopr_balance(&*cc, mismatched).await?.is_zero(),
            "a refused event must not deposit"
        );

        // Would fail if the refusal above had charged the window.
        s.on_pix_event(new_deposit(ordinary, 50)).await?;
        assert_eq!(hopr_balance(&*cc, ordinary).await?, HoprBalance::new_base(50));
        Ok(())
    }

    /// A zero window would evict every entry the instant it was written, silently disabling a
    /// limit the operator believes is armed. The builder is where that is caught — and it did not
    /// validate its config at all before this.
    #[test_log::test(tokio::test)]
    async fn test_build_rejects_a_zero_spend_window() -> anyhow::Result<()> {
        let (_cc, node, _pool) = entry_side(&[]).await?;

        let result = PixStrategy::new(spend_cfg(HoprBalance::new_base(50), StdDuration::ZERO))
            .build_non_anonymous::<_, Address>(node, BOB_KP.clone(), Default::default());

        assert!(matches!(result, Err(StrategyError::InvalidConfiguration(_))));
        Ok(())
    }

    // ── Builder config validation ──────────────────────────────────

    /// The *pool* config is validated too, not just the strategy's.
    ///
    /// `NonAnonymousDepositPoolConfig` has carried validators since it was written and derived
    /// `Validate` for them, but no builder ever ran them — a tracking time the pool's own
    /// constraint forbids was accepted and turned into a polling interval of zero.
    #[test_log::test(tokio::test)]
    async fn test_build_non_anonymous_rejects_an_invalid_pool_config() -> anyhow::Result<()> {
        let (_cc, node, _pool) = entry_side(&[]).await?;

        let result = PixStrategy::new(PixStrategyConfig::default()).build_non_anonymous::<_, Address>(
            node,
            BOB_KP.clone(),
            crate::pix::pools::plain::PoolConfig {
                max_deposit_tracking_time: StdDuration::ZERO,
                ..Default::default()
            },
        );

        assert!(matches!(result, Err(StrategyError::InvalidConfiguration(_))));
        Ok(())
    }

    /// The pool signs sweep-gas top-ups with the key it is handed, and gates them on that same
    /// key's balance. A key that is not the node's would therefore top up gas out of an account
    /// unrelated to the one deposits settle from — silently, and only on the sweep path, which is
    /// the hardest place to notice it. The builder is the one place that can see both.
    #[test_log::test(tokio::test)]
    async fn test_build_non_anonymous_rejects_a_key_that_is_not_the_nodes() -> anyhow::Result<()> {
        let (cc, node, _pool) = entry_side(&[]).await?;

        let stranger = ChainKeypair::from_secret(&[7u8; 32])?;
        assert_ne!(stranger.public().to_address(), node.identity().node_address);

        // Discarded rather than inspected: `Strategy` is `Display + Send`, not `Debug`.
        let result = PixStrategy::new(PixStrategyConfig::default())
            .build_non_anonymous_with_client::<_, Address, _>(node, stranger, Default::default(), cc.client())
            .map(|_| ());

        assert!(
            matches!(result, Err(StrategyError::InvalidConfiguration(_))),
            "a foreign node key must be refused, got {result:?}"
        );
        Ok(())
    }

    /// Zero retries means "one attempt, no backoff" — the documented meaning of a budget counted
    /// *in addition to* the first attempt, and what most of the tests in this file rely on.
    ///
    /// It was declared `range(min = 1)`, contradicting that. Harmless while nothing validated;
    /// turning validation on would have made a legitimate config unbuildable.
    #[test_log::test(tokio::test)]
    async fn test_build_non_anonymous_accepts_zero_retry_budgets() -> anyhow::Result<()> {
        let (_cc, node, _pool) = entry_side(&[]).await?;

        PixStrategy::new(PixStrategyConfig::default()).build_non_anonymous::<_, Address>(
            node,
            BOB_KP.clone(),
            crate::pix::pools::plain::PoolConfig {
                max_deposit_retries: 0,
                max_sweep_retries: 0,
                ..Default::default()
            },
        )?;

        Ok(())
    }

    /// The curvy builder validates its own pool config on the same footing, even though the pool
    /// behind it is still a stub.
    #[cfg(feature = "strategy-pix-curvy")]
    #[test_log::test(tokio::test)]
    async fn test_build_curvy_rejects_an_invalid_pool_config() -> anyhow::Result<()> {
        use hopr_api::types::crypto::prelude::BjjPublicKey;

        let (_cc, node, _pool) = entry_side(&[]).await?;

        let result = PixStrategy::new(PixStrategyConfig::default()).build_curvy::<_, BjjPublicKey>(
            node,
            crate::pix::pools::curvy::PoolConfig {
                max_deposit_tracking_time: StdDuration::ZERO,
            },
        );

        assert!(matches!(result, Err(StrategyError::InvalidConfiguration(_))));
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_new_deposit_address_dedup_skips_duplicate() -> anyhow::Result<()> {
        let da: Address = [0x42u8; 20].into();
        let sim = BlokliTestStateBuilder::default().with_generated_accounts(
            &[&*ALICE, &*CHRIS],
            false,
            XDaiBalance::new_base(1),
            HoprBalance::new_base(1000),
        );
        let sim = with_self_safed_node(sim, *BOB, 9, HoprBalance::new_base(1000))
            // `deposit_funds_to` reads the destination balance before transferring, and the
            // stub chain has no entry for an address that was never funded.
            .with_balances([(da, HoprBalance::zero())])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut cc = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        cc.connect().await?;
        let client = cc.client();
        let cc = Arc::new(cc);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::with_client(
            Arc::clone(&node),
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
            client,
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
            ..Default::default()
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        let id = pix_id(1);
        let mk = |id| {
            PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
                id,
                address: da.into(),
                quota: 20,
                deposit_data: pool_deposit_data(id),
            })
        };
        let bb: HoprBalance = hopr_balance(&*cc, *BOB).await?;
        s.on_pix_event(mk(id)).await?;
        s.flush_deposits().await;
        assert_eq!(hopr_balance(&*cc, *BOB).await?, bb - HoprBalance::new_base(20));
        s.on_pix_event(mk(id)).await?;
        s.flush_deposits().await;
        assert_eq!(hopr_balance(&*cc, *BOB).await?, bb - HoprBalance::new_base(20));
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_build_with_recovery_path_opens_store() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let db = dir.path().join("pix.redb");
        // SAFETY: `BUILD_PASSWORD_ENV` is touched by this test alone, so no other test
        // thread can observe or clobber it.
        unsafe { std::env::set_var(BUILD_PASSWORD_ENV, "test_password") };
        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut cc = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        cc.connect().await?;
        PixStrategy::new(PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: Some(db.clone()),
            pix_recovery_password_env: Some(BUILD_PASSWORD_ENV.to_string()),
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
            ..Default::default()
        })
        .build_non_anonymous::<_, Address>(
            Arc::new(ChainNode(Arc::new(cc))),
            BOB_KP.clone(),
            Default::default(),
        )?;
        assert!(db.exists());
        // SAFETY: as above.
        unsafe { std::env::remove_var(BUILD_PASSWORD_ENV) };
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_private_key_recovered_with_recovery_store() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        // No environment variable here: the store is opened directly and the config leaves
        // `pix_recovery_password_env` unset.
        let store = PixRecoveryStore::open(dir.path().join("pix.redb"), "test_password")?;
        let rk = hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let rkp = ChainKeypair::from_secret(&rk)?;
        let ra = rkp.public().to_address();

        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(2),
                HoprBalance::new_base(1000),
            )
            .with_balances([(ra, HoprBalance::new_base(50))])
            .with_balances([(ra, XDaiBalance::new_base(1))])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut connector = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        connector.connect().await?;
        let client = connector.client();
        register_test_safe(&connector, *BOB).await?;
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::with_client(
            Arc::clone(&node),
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
            client,
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
            ..Default::default()
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, Some(store));
        let id = pix_id(1);
        s.recovery_store
            .as_ref()
            .unwrap()
            .insert(&id, &hopr_api::chain::PixDepositSecret(rk.into()))?;
        s.on_pix_event(PixEvent::PrivateKeyRecovered(hopr_api::node::PixPrivateKeyRecovered {
            id,
            secret: hopr_api::chain::PixDepositSecret(rk.into()),
        }))
        .await?;
        s.flush_withdrawals().await;
        assert!(!s.recovery_store.as_ref().unwrap().contains(&id)?);
        assert!(hopr_balance(&*cc, ra).await?.is_zero());
        Ok(())
    }

    /// The pool must refuse to sweep an address that holds nothing instead of reporting a
    /// zero-value success, so the caller cannot mistake "the deposit has not landed" for
    /// "the deposit has been withdrawn".
    #[test_log::test(tokio::test)]
    async fn test_sweep_of_empty_deposit_address_is_rejected() -> anyhow::Result<()> {
        use hopr_api::chain::DepositPool;

        let rk = hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let ra = ChainKeypair::from_secret(&rk)?.public().to_address();

        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            // The deposit address exists on-chain but is still empty.
            .with_balances([(ra, HoprBalance::zero())])
            .with_balances([(ra, XDaiBalance::new_base(1))])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut cc = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        cc.connect().await?;
        let client = cc.client();
        let node = Arc::new(ChainNode(Arc::new(cc)));
        let pool = NonAnonymousDepositPool::with_client(
            node,
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
            client,
        );

        let started = std::time::Instant::now();
        let result = pool
            .withdraw_deposit(
                &pix_id(1),
                &crate::pix::pools::plain::EthDepositKey::from_secret(&rk)?,
                *BOB,
                None,
            )
            .await;

        assert!(matches!(result, Err(StrategyError::CriteriaNotSatisfied)));
        assert!(
            started.elapsed() < StdDuration::from_secs(1),
            "a zero retry budget must fail on the first attempt, without any backoff"
        );
        Ok(())
    }

    /// A sweep whose deposit has not landed yet must keep trying: the pool owns the retry, so
    /// a deposit that arrives during the backoff is swept without the caller doing anything.
    #[test_log::test(tokio::test)]
    async fn test_sweep_retries_until_the_deposit_lands() -> anyhow::Result<()> {
        use hopr_api::chain::DepositPool;

        let deposit = HoprBalance::new_base(5);
        let rk = hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let ra = ChainKeypair::from_secret(&rk)?.public().to_address();

        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(2),
                HoprBalance::new_base(1000),
            )
            // Funds the transfer that makes the deposit land mid-retry.
            .with_balances([(*BOB, HoprBalance::new_base(1000))])
            // The deposit address has gas but no wxHOPR yet.
            .with_balances([(ra, HoprBalance::zero())])
            .with_balances([(ra, XDaiBalance::new_base(1))])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut connector = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        connector.connect().await?;
        let client = connector.client();
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = NonAnonymousDepositPool::with_client(
            node,
            BOB_KP.clone(),
            pool_cfg_with_retries(StdDuration::from_secs(60), XDaiBalance::zero(), 0, 3),
            client,
        );

        // The deposit lands after the first attempt has already failed.
        let funder = Arc::clone(&cc);
        let landing = tokio::spawn(async move {
            tokio::time::sleep(StdDuration::from_millis(300)).await;
            funder.withdraw(deposit, &ra).await?.await?;
            Ok::<_, anyhow::Error>(())
        });

        let result = pool
            .withdraw_deposit(
                &pix_id(1),
                &crate::pix::pools::plain::EthDepositKey::from_secret(&rk)?,
                *CHRIS,
                None,
            )
            .await;
        landing.await??;

        assert!(
            result.is_ok(),
            "the sweep must succeed once the deposit lands: {result:?}"
        );
        assert_eq!(
            hopr_balance(&*cc, ra).await?,
            HoprBalance::zero(),
            "the deposit address must be emptied by the sweep"
        );
        Ok(())
    }

    /// `pool_transfer` must move the deposit to the destination it is *given*.
    ///
    /// It delegates to `withdraw_deposit`, whose every other caller passes the Safe — so the
    /// one thing that can go wrong in the delegation is the destination being dropped and the
    /// funds landing in the Safe anyway. That would look like success from the return value.
    /// `CHRIS` is deliberately neither the Safe (`BOB`) nor the deposit address.
    #[test_log::test(tokio::test)]
    async fn test_pool_transfer_moves_the_deposit_to_the_given_destination() -> anyhow::Result<()> {
        use hopr_api::chain::DepositPool;

        let deposit = HoprBalance::new_base(7);
        let rk = hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let ra = ChainKeypair::from_secret(&rk)?.public().to_address();

        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            // A funded deposit address with gas of its own to pay for the transfer.
            .with_balances([(ra, deposit)])
            .with_balances([(ra, XDaiBalance::new_base(1))])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut connector = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        connector.connect().await?;
        let client = connector.client();
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = NonAnonymousDepositPool::with_client(
            node,
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
            client,
        );

        let safe_before = hopr_balance(&*cc, *BOB).await?;
        let dst_before = hopr_balance(&*cc, *CHRIS).await?;

        let dst_id = pix_id(2);
        pool.pool_transfer(
            &pix_id(1),
            &crate::pix::pools::plain::EthDepositKey::from_secret(&rk)?,
            &dst_id,
            *CHRIS,
            ByteDepositData::new(dst_id, DEPOSIT_MARKER_PAYLOAD),
            None,
        )
        .await?;

        assert_eq!(
            hopr_balance(&*cc, ra).await?,
            HoprBalance::zero(),
            "the deposit address must be emptied by the transfer"
        );
        assert_eq!(
            hopr_balance(&*cc, *CHRIS).await?,
            dst_before + deposit,
            "the destination passed to pool_transfer must receive the deposit"
        );
        assert_eq!(
            hopr_balance(&*cc, *BOB).await?,
            safe_before,
            "the Safe must not receive anything: this is a transfer, not a withdrawal"
        );
        Ok(())
    }

    /// An empty address is refused rather than reported as a no-op transfer.
    ///
    /// Same contract as the sweep, and for the same reason: a `pool_transfer` that "succeeded"
    /// while moving nothing is indistinguishable from one that moved the funds, so a caller
    /// tracking the deposit would drop it.
    #[test_log::test(tokio::test)]
    async fn test_pool_transfer_of_empty_address_is_rejected() -> anyhow::Result<()> {
        use hopr_api::chain::DepositPool;

        let rk = hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let ra = ChainKeypair::from_secret(&rk)?.public().to_address();

        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .with_balances([(ra, HoprBalance::zero())])
            .with_balances([(ra, XDaiBalance::new_base(1))])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut cc = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        cc.connect().await?;
        let client = cc.client();
        let node = Arc::new(ChainNode(Arc::new(cc)));
        let pool = NonAnonymousDepositPool::with_client(
            node,
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
            client,
        );

        let dst_id = pix_id(2);
        let result = pool
            .pool_transfer(
                &pix_id(1),
                &crate::pix::pools::plain::EthDepositKey::from_secret(&rk)?,
                &dst_id,
                *CHRIS,
                ByteDepositData::new(dst_id, DEPOSIT_MARKER_PAYLOAD),
                None,
            )
            .await;

        assert!(
            matches!(result, Err(StrategyError::CriteriaNotSatisfied)),
            "an empty address must be refused, got {result:?}"
        );
        Ok(())
    }

    /// Both entry points that are handed a payload refuse one this pool cannot read.
    ///
    /// Asserted at the pool rather than through the strategy because that is where the check lives:
    /// the `PixDepositData` conversion is shared by every pool and cannot know what any one of them
    /// reads, so `DEPOSIT_MARKER_PAYLOAD` is enforced here.
    ///
    /// Everything else is set up to succeed — the Safe is funded, the deposit address holds a
    /// balance and its own gas — so the payload is the only thing that can be refusing these calls.
    /// The balance assertions are the substance: a rejection that still moved the funds would be
    /// the failure the check exists to prevent, and the error alone would not catch it.
    #[test_log::test(tokio::test)]
    async fn test_pool_refuses_a_payload_it_cannot_read() -> anyhow::Result<()> {
        use hopr_api::chain::DepositPool;

        let dest_addr = Address::from([0x42u8; 20]);
        let deposit = HoprBalance::new_base(7);
        let rk = hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let ra = ChainKeypair::from_secret(&rk)?.public().to_address();

        let sim = BlokliTestStateBuilder::default().with_generated_accounts(
            &[&*ALICE, &*CHRIS],
            false,
            XDaiBalance::new_base(1),
            HoprBalance::new_base(1000),
        );
        let sim = with_self_safed_node(sim, *BOB, 9, HoprBalance::new_base(1000))
            // `deposit_funds_to` reads the destination balance before transferring, and the
            // stub chain has no entry for an address that was never funded.
            .with_balances([(dest_addr, HoprBalance::zero())])
            // A funded deposit address with gas of its own to pay for the transfer.
            .with_balances([(ra, deposit)])
            .with_balances([(ra, XDaiBalance::new_base(1))])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut connector = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        connector.connect().await?;
        let client = connector.client();
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = NonAnonymousDepositPool::with_client(
            node,
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
            client,
        );

        let dst_before = hopr_balance(&*cc, *CHRIS).await?;

        let id = pix_id(1);
        let unreadable = ByteDepositData::new(id, [0xde, 0xad, 0xbe, 0xef]);

        let deposited = pool
            .deposit_funds_to(&id, &dest_addr, HoprBalance::new_base(10), unreadable.clone())
            .await;
        assert!(
            matches!(deposited, Err(StrategyError::GeneralError(_))),
            "deposit_funds_to must refuse an unreadable payload, got {deposited:?}"
        );
        assert_eq!(
            hopr_balance(&*cc, dest_addr).await?,
            HoprBalance::zero(),
            "a refused deposit must move nothing"
        );

        let dst_id = pix_id(2);
        let transferred = pool
            .pool_transfer(
                &id,
                &crate::pix::pools::plain::EthDepositKey::from_secret(&rk)?,
                &dst_id,
                *CHRIS,
                ByteDepositData::new(dst_id, [0xde, 0xad, 0xbe, 0xef]),
                None,
            )
            .await;
        assert!(
            matches!(transferred, Err(StrategyError::GeneralError(_))),
            "pool_transfer must refuse an unreadable payload, got {transferred:?}"
        );
        assert_eq!(
            hopr_balance(&*cc, ra).await?,
            deposit,
            "a refused transfer must leave the deposit where it was"
        );
        assert_eq!(
            hopr_balance(&*cc, *CHRIS).await?,
            dst_before,
            "a refused transfer must move nothing"
        );

        // An empty payload is refused for the same reason a wrong one is: this pool reads exactly
        // one shape, and "nothing" is not it. Pinned separately because empty bytes are what the
        // type's own `for_id` produces, so this is the mistake most easily made.
        let empty = pool
            .deposit_funds_to(&id, &dest_addr, HoprBalance::new_base(10), ByteDepositData::for_id(id))
            .await;
        assert!(
            matches!(empty, Err(StrategyError::GeneralError(_))),
            "an empty payload must be refused too, got {empty:?}"
        );
        Ok(())
    }

    /// Deposit data filed under a different allocation than the deposit it arrived with is refused
    /// by the pool, even when the payload itself is the marker.
    ///
    /// The pool-level sibling of
    /// [`test_new_deposit_address_rejects_deposit_data_for_another_allocation`], and not redundant
    /// with it: that one covers the strategy's `NewDepositAddress` arm, which compares the ids on
    /// the wire form. `pool_transfer` has no such arm — the strategy never calls it — so a
    /// misfiled `dst_id` reaches the pool unchecked by anything else, and a caller that does not go
    /// through the strategy at all bypasses that comparison for deposits too.
    ///
    /// Nothing in this pool is filed per allocation, so a mismatch corrupts no state of its own.
    /// What it means is that the two ends disagree, and the id travels inside the payload precisely
    /// so that can be noticed rather than assumed. Settling regardless would make carrying it
    /// pointless.
    #[test_log::test(tokio::test)]
    async fn test_pool_refuses_deposit_data_for_another_allocation() -> anyhow::Result<()> {
        use hopr_api::chain::DepositPool;

        let dest_addr = Address::from([0x42u8; 20]);
        let deposit = HoprBalance::new_base(7);
        let rk = hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let ra = ChainKeypair::from_secret(&rk)?.public().to_address();

        let sim = BlokliTestStateBuilder::default().with_generated_accounts(
            &[&*ALICE, &*CHRIS],
            false,
            XDaiBalance::new_base(1),
            HoprBalance::new_base(1000),
        );
        let sim = with_self_safed_node(sim, *BOB, 9, HoprBalance::new_base(1000))
            .with_balances([(dest_addr, HoprBalance::zero())])
            // A funded deposit address with gas of its own to pay for the transfer.
            .with_balances([(ra, deposit)])
            .with_balances([(ra, XDaiBalance::new_base(1))])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut connector = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        connector.connect().await?;
        let client = connector.client();
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = NonAnonymousDepositPool::with_client(
            node,
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
            client,
        );

        let dst_before = hopr_balance(&*cc, *CHRIS).await?;

        // The payload is exactly what the pool generates — only the allocation it is filed under
        // differs, so the id comparison is the only thing that can refuse these calls.
        let id = pix_id(1);
        let other_id = pix_id(2);
        let misfiled = ByteDepositData::new(other_id, DEPOSIT_MARKER_PAYLOAD);

        let deposited = pool
            .deposit_funds_to(&id, &dest_addr, HoprBalance::new_base(10), misfiled.clone())
            .await;
        assert!(
            matches!(deposited, Err(StrategyError::GeneralError(_))),
            "deposit_funds_to must refuse deposit data filed under another allocation, got {deposited:?}"
        );
        assert_eq!(
            hopr_balance(&*cc, dest_addr).await?,
            HoprBalance::zero(),
            "a refused deposit must move nothing"
        );

        let dst_id = pix_id(3);
        let transferred = pool
            .pool_transfer(
                &id,
                &crate::pix::pools::plain::EthDepositKey::from_secret(&rk)?,
                &dst_id,
                *CHRIS,
                misfiled,
                None,
            )
            .await;
        assert!(
            matches!(transferred, Err(StrategyError::GeneralError(_))),
            "pool_transfer must refuse deposit data filed under another allocation, got {transferred:?}"
        );
        assert_eq!(
            hopr_balance(&*cc, ra).await?,
            deposit,
            "a refused transfer must leave the deposit where it was"
        );
        assert_eq!(
            hopr_balance(&*cc, *CHRIS).await?,
            dst_before,
            "a refused transfer must move nothing"
        );
        Ok(())
    }

    /// `pool_transfer` inherits the sweep's retry budget, because it is the same operation.
    ///
    /// Worth pinning: the delegation is what makes this true, and someone giving
    /// `pool_transfer` its own body later would silently lose it — leaving a transfer that
    /// gives up on the first attempt while the identical withdrawal keeps trying.
    #[test_log::test(tokio::test)]
    async fn test_pool_transfer_retries_until_the_deposit_lands() -> anyhow::Result<()> {
        use hopr_api::chain::DepositPool;

        let deposit = HoprBalance::new_base(5);
        let rk = hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let ra = ChainKeypair::from_secret(&rk)?.public().to_address();

        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(2),
                HoprBalance::new_base(1000),
            )
            .with_balances([(*BOB, HoprBalance::new_base(1000))])
            .with_balances([(ra, HoprBalance::zero())])
            .with_balances([(ra, XDaiBalance::new_base(1))])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut connector = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        connector.connect().await?;
        let client = connector.client();
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = NonAnonymousDepositPool::with_client(
            node,
            BOB_KP.clone(),
            pool_cfg_with_retries(StdDuration::from_secs(60), XDaiBalance::zero(), 0, 3),
            client,
        );

        let funder = Arc::clone(&cc);
        let landing = tokio::spawn(async move {
            tokio::time::sleep(StdDuration::from_millis(300)).await;
            funder.withdraw(deposit, &ra).await?.await?;
            Ok::<_, anyhow::Error>(())
        });

        let dst_id = pix_id(2);
        let result = pool
            .pool_transfer(
                &pix_id(1),
                &crate::pix::pools::plain::EthDepositKey::from_secret(&rk)?,
                &dst_id,
                *CHRIS,
                ByteDepositData::new(dst_id, DEPOSIT_MARKER_PAYLOAD),
                None,
            )
            .await;
        landing.await??;

        assert!(
            result.is_ok(),
            "the transfer must succeed once the deposit lands: {result:?}"
        );
        assert_eq!(
            hopr_balance(&*cc, ra).await?,
            HoprBalance::zero(),
            "the deposit address must be emptied by the transfer"
        );
        Ok(())
    }

    /// Regression: the batch sweep must retry each item.
    ///
    /// `withdraw_multiple_deposits` defaults to a `join_all` over `withdraw_deposit` and returns
    /// `Ok(Vec<Result<..>>)` — it never reports an outer error, so a retry wrapped around the
    /// *batch* can never fire. Only a retry inside `withdraw_deposit` covers these.
    #[test_log::test(tokio::test)]
    async fn test_batch_sweep_retries_each_item_independently() -> anyhow::Result<()> {
        use hopr_api::chain::DepositPool;

        let deposit = HoprBalance::new_base(5);
        let rks = [
            hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"),
            hex!("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"),
        ];
        let ras = rks
            .iter()
            .map(|rk| Ok(ChainKeypair::from_secret(rk)?.public().to_address()))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(2),
                HoprBalance::new_base(1000),
            )
            // Funds the transfers that make the deposits land mid-retry.
            .with_balances([(*BOB, HoprBalance::new_base(1000))])
            // Both deposit addresses have gas but no wxHOPR yet.
            .with_balances(ras.iter().map(|ra| (*ra, HoprBalance::zero())))
            .with_balances(ras.iter().map(|ra| (*ra, XDaiBalance::new_base(1))))
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut connector = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        connector.connect().await?;
        let client = connector.client();
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = NonAnonymousDepositPool::with_client(
            node,
            BOB_KP.clone(),
            pool_cfg_with_retries(StdDuration::from_secs(60), XDaiBalance::zero(), 0, 3),
            client,
        );

        let funder = Arc::clone(&cc);
        let funded = ras.clone();
        let landing = tokio::spawn(async move {
            tokio::time::sleep(StdDuration::from_millis(300)).await;
            for ra in funded {
                funder.withdraw(deposit, &ra).await?.await?;
            }
            Ok::<_, anyhow::Error>(())
        });

        // Each key carries the allocation it belongs to, so a result can be attributed back to
        // the right id by position without a second, separately built list to keep in step.
        let keys: Vec<_> = rks
            .iter()
            .enumerate()
            .map(|(i, rk)| {
                (
                    pix_id(i as u32 + 1),
                    crate::pix::pools::plain::EthDepositKey::from_secret(rk).expect("valid test secret"),
                )
            })
            .collect();
        let results = pool.withdraw_multiple_deposits(&keys, *CHRIS).await?;
        landing.await??;

        assert_eq!(results.len(), 2);
        for (i, result) in results.iter().enumerate() {
            assert!(
                result.is_ok(),
                "batch item {i} must be retried until it succeeds: {result:?}"
            );
            assert_eq!(
                hopr_balance(&*cc, ras[i]).await?,
                HoprBalance::zero(),
                "batch item {i} must have been swept"
            );
        }
        Ok(())
    }

    /// Regression: the startup replay must not stall event consumption.
    ///
    /// The store holds one entry whose deposit address is empty, so its sweep burns the pool's
    /// whole retry budget — tens of seconds. A `NewDepositAddress` injected while that is in
    /// flight must still be served promptly. Replaying inline, as `run` used to, would make
    /// this deposit wait for the replay to give up first.
    #[test_log::test(tokio::test)]
    async fn test_startup_replay_does_not_block_event_consumption() -> anyhow::Result<()> {
        use crate::{strategy::Strategy as _, testing::PixNode};

        let da: Address = [0x43u8; 20].into();
        let quota = 20u64;
        let expected = HoprBalance::new_base(quota);

        let rk = hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let ra = ChainKeypair::from_secret(&rk)?.public().to_address();

        let dir = tempfile::tempdir()?;
        let store = PixRecoveryStore::open(dir.path().join("pix.redb"), "test_password")?;
        let stranded = pix_id(1);
        store.insert(&stranded, &hopr_api::chain::PixDepositSecret(rk.into()))?;

        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(2),
                HoprBalance::new_base(1000),
            )
            .with_balances([(*BOB, HoprBalance::new_base(1000))])
            .with_balances([(da, HoprBalance::zero())])
            // The stranded entry's address stays empty for the whole test.
            .with_balances([(ra, HoprBalance::zero())])
            .with_balances([(ra, XDaiBalance::new_base(1))])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut cc = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        cc.connect().await?;
        let client = cc.client();
        let cc = Arc::new(cc);
        let node = Arc::new(PixNode::new(
            Arc::clone(&cc),
            NodeOnchainIdentity {
                node_address: *BOB,
                safe_address: *BOB,
                module_address: MODULE_ADDRESS.into(),
            },
        ));
        // The default sweep budget, so the replay stays busy far longer than the assertion
        // below is willing to wait.
        let pool = Arc::new(NonAnonymousDepositPool::with_client(
            Arc::clone(&node),
            BOB_KP.clone(),
            pool_cfg_with_retries(StdDuration::from_secs(60), XDaiBalance::zero(), 0, 5),
            client,
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
            ..Default::default()
        };
        let mut s = PixStrategyInner::new(pool, Arc::clone(&node), cfg, *BOB, Some(store));

        let running = tokio::spawn(async move { s.run().await });
        let id = pix_id(1);
        node.inject_pix(PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
            id,
            address: da.into(),
            quota,
            deposit_data: pool_deposit_data(id),
        }));

        let landed = timeout(StdDuration::from_secs(10), async {
            loop {
                if hopr_balance(&*cc, da).await.is_ok_and(|b| b == expected) {
                    return;
                }
                tokio::time::sleep(StdDuration::from_millis(50)).await;
            }
        })
        .await;

        running.abort();
        landed.context("the deposit was not served while the recovery replay was still running")?;
        Ok(())
    }

    /// Regression: a sweep in progress must not stall event consumption.
    ///
    /// The sibling of `test_startup_replay_does_not_block_event_consumption`, for the flush path
    /// rather than the replay one. `run` used to await `flush_withdrawals` directly on its
    /// `select!`, so a sweep held the loop for its whole retry budget and no PIX event was
    /// dispatched meanwhile. Downstream that is fatal rather than slow: hoprnet's Exit gives a
    /// deposit pool three seconds to answer `DepositDataRequest` and closes the Session with
    /// `MissingDepositData` when it does not. Spawning the `DepositDataRequest` arm — which this
    /// module already does — buys nothing if the loop never reaches it.
    ///
    /// The recovered key's address stays empty, so its sweep burns the full five-attempt budget:
    /// tens of seconds, against the ten this is willing to wait.
    #[test_log::test(tokio::test)]
    async fn test_sweep_does_not_block_event_consumption() -> anyhow::Result<()> {
        use crate::{strategy::Strategy as _, testing::PixNode};

        let da: Address = [0x44u8; 20].into();
        let quota = 20u64;
        let expected = HoprBalance::new_base(quota);

        let rk = hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let ra = ChainKeypair::from_secret(&rk)?.public().to_address();

        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(2),
                HoprBalance::new_base(1000),
            )
            .with_balances([(*BOB, HoprBalance::new_base(1000))])
            .with_balances([(da, HoprBalance::zero())])
            // Never funded, so every sweep attempt fails and the budget is spent in full.
            .with_balances([(ra, HoprBalance::zero())])
            .with_balances([(ra, XDaiBalance::new_base(1))])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut cc = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        cc.connect().await?;
        let client = cc.client();
        let cc = Arc::new(cc);
        let node = Arc::new(PixNode::new(
            Arc::clone(&cc),
            NodeOnchainIdentity {
                node_address: *BOB,
                safe_address: *BOB,
                module_address: MODULE_ADDRESS.into(),
            },
        ));
        let pool = Arc::new(NonAnonymousDepositPool::with_client(
            Arc::clone(&node),
            BOB_KP.clone(),
            pool_cfg_with_retries(StdDuration::from_secs(60), XDaiBalance::zero(), 0, 5),
            client,
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
            ..Default::default()
        };
        let mut s = PixStrategyInner::new(pool, Arc::clone(&node), cfg, *BOB, None);

        let running = tokio::spawn(async move { s.run().await });

        // Start the doomed sweep first, then ask for a deposit while it is still retrying.
        node.inject_pix(PixEvent::PrivateKeyRecovered(hopr_api::node::PixPrivateKeyRecovered {
            id: pix_id(1),
            secret: hopr_api::chain::PixDepositSecret(rk.into()),
        }));
        tokio::time::sleep(StdDuration::from_millis(200)).await;

        let id = pix_id(2);
        node.inject_pix(PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
            id,
            address: da.into(),
            quota,
            deposit_data: pool_deposit_data(id),
        }));

        let landed = timeout(StdDuration::from_secs(10), async {
            loop {
                if hopr_balance(&*cc, da).await.is_ok_and(|b| b == expected) {
                    return;
                }
                tokio::time::sleep(StdDuration::from_millis(50)).await;
            }
        })
        .await;

        running.abort();
        landed.context("the deposit was not served while a sweep was still retrying")?;
        Ok(())
    }

    /// Regression: a `PrivateKeyRecovered` that arrives before its deposit has landed must
    /// leave the persisted key in place. Dropping it would strand the deposit permanently —
    /// the recovered key is the only means of ever moving those funds.
    ///
    /// The pool's sweep budget is zeroed so the abandonment happens on the first attempt;
    /// what the budget is set to does not change the outcome being asserted here.
    #[test_log::test(tokio::test)]
    async fn test_recovery_entry_survives_sweep_of_empty_deposit_address() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = PixRecoveryStore::open(dir.path().join("pix.redb"), "test_password")?;
        let rk = hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let ra = ChainKeypair::from_secret(&rk)?.public().to_address();

        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(2),
                HoprBalance::new_base(1000),
            )
            // The deposit address exists on-chain but is still empty.
            .with_balances([(ra, HoprBalance::zero())])
            .with_balances([(ra, XDaiBalance::new_base(1))])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut connector = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        connector.connect().await?;
        let client = connector.client();
        register_test_safe(&connector, *BOB).await?;
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::with_client(
            Arc::clone(&node),
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
            client,
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            // Flush immediately: this test asserts on the outcome of the sweep itself.
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
            ..Default::default()
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, Some(store));
        let id = pix_id(1);

        // `flush_withdrawals` logs the failure rather than propagating it, so the event
        // itself reports success — what matters is that the key was not discarded.
        s.on_pix_event(PixEvent::PrivateKeyRecovered(hopr_api::node::PixPrivateKeyRecovered {
            id,
            secret: hopr_api::chain::PixDepositSecret(rk.into()),
        }))
        .await?;

        assert!(
            s.recovery_store.as_ref().unwrap().contains(&id)?,
            "the recovered key must stay persisted so a later start can retry the sweep"
        );
        assert!(
            !s.in_flight_sweeps.contains_key(&id),
            "the in-flight guard must be released after the sweep is abandoned"
        );
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_build_fails_when_only_one_recovery_config_set() -> anyhow::Result<()> {
        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut cc = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        cc.connect().await?;
        let r = PixStrategy::new(PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: Some("/tmp/nonexistent/pix.redb".into()),
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
            ..Default::default()
        })
        .build_non_anonymous::<_, Address>(
            Arc::new(ChainNode(Arc::new(cc))),
            BOB_KP.clone(),
            Default::default(),
        );
        // The message must name the field that is missing, not just report a failed criterion.
        let error = r
            .err()
            .context("build should reject a half-configured recovery store")?;
        assert!(
            error.to_string().contains("pix_recovery_password_env"),
            "unhelpful error: {error}"
        );
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_build_fails_when_password_env_var_missing() -> anyhow::Result<()> {
        let ev = "HOPRD_TEST_ENV_THAT_DOES_NOT_EXIST_HOPEFULLY";
        // SAFETY: single-threaded test, no concurrent access to this variable.
        unsafe { std::env::remove_var(ev) };
        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut cc = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        cc.connect().await?;
        let r = PixStrategy::new(PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: Some("/tmp/nonexistent/pix.redb".into()),
            pix_recovery_password_env: Some(ev.to_string()),
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
            ..Default::default()
        })
        .build_non_anonymous::<_, Address>(
            Arc::new(ChainNode(Arc::new(cc))),
            BOB_KP.clone(),
            Default::default(),
        );
        assert!(r.is_err());
        Ok(())
    }

    /// Two events inside one buffer window must reach the pool as a *batch*.
    ///
    /// The buffer period is non-zero on purpose. With a zero period `on_pix_event` flushes each
    /// event as it arrives, so the explicit `flush_deposits` below finds an empty buffer and the
    /// batch branch never runs — the assertions still pass, because two single deposits move the
    /// same funds, which is exactly why this went unnoticed.
    #[test_log::test(tokio::test)]
    async fn test_multiple_deposits_batched_within_buffer_period() -> anyhow::Result<()> {
        let da1: Address = [0x42u8; 20].into();
        let da2: Address = [0x43u8; 20].into();
        let start_balance = HoprBalance::new_base(1000);
        let sim = BlokliTestStateBuilder::default().with_generated_accounts(
            &[&*ALICE, &*CHRIS],
            false,
            XDaiBalance::new_base(1),
            start_balance,
        );
        let sim = with_self_safed_node(sim, *BOB, 9, start_balance)
            // `deposit_funds_to` reads the destination balance before transferring, and the
            // stub chain has no entry for an address that was never funded.
            .with_balances([(da1, HoprBalance::zero()), (da2, HoprBalance::zero())])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut cc = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        cc.connect().await?;
        let client = cc.client();
        let cc = Arc::new(cc);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::with_client(
            Arc::clone(&node),
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
            client,
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::from_secs(60),
            withdrawal_buffer_period: StdDuration::ZERO,
            ..Default::default()
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        let bb = hopr_balance(&*cc, *BOB).await?;
        let amount1 = HoprBalance::new_base(20);
        let amount2 = HoprBalance::new_base(30);
        let id1 = pix_id(1);
        let id2 = pix_id(2);
        s.on_pix_event(PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
            id: id1,
            address: da1.into(),
            quota: 20,
            deposit_data: pool_deposit_data(id1),
        }))
        .await?;
        s.on_pix_event(PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
            id: id2,
            address: da2.into(),
            quota: 30,
            deposit_data: pool_deposit_data(id2),
        }))
        .await?;
        // Nothing has moved yet: the window is still open.
        assert_eq!(s.deposit_buffer.len(), 2, "both events must still be buffered");
        assert_eq!(hopr_balance(&*cc, da1).await?, HoprBalance::zero());

        s.flush_deposits().await;
        assert_eq!(hopr_balance(&*cc, *BOB).await?, bb - amount1 - amount2);
        assert_eq!(hopr_balance(&*cc, da1).await?, amount1);
        assert_eq!(hopr_balance(&*cc, da2).await?, amount2);
        Ok(())
    }

    /// Same reasoning as the deposit batch test: the window has to stay open for the batch branch
    /// to be the one under test.
    #[test_log::test(tokio::test)]
    async fn test_multiple_withdrawals_batched_within_buffer_period() -> anyhow::Result<()> {
        let rk1 = hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let rk2 = hex!("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
        let kp1 = ChainKeypair::from_secret(&rk1)?;
        let kp2 = ChainKeypair::from_secret(&rk2)?;
        let ra1 = kp1.public().to_address();
        let ra2 = kp2.public().to_address();
        let b1 = HoprBalance::new_base(50);
        let b2 = HoprBalance::new_base(70);

        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .with_balances([(ra1, b1), (ra2, b2)])
            .with_balances([(ra1, XDaiBalance::new_base(1)), (ra2, XDaiBalance::new_base(1))])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut connector = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        connector.connect().await?;
        let client = connector.client();
        register_test_safe(&connector, *BOB).await?;
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::with_client(
            Arc::clone(&node),
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
            client,
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::from_secs(60),
            ..Default::default()
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        s.on_pix_event(PixEvent::PrivateKeyRecovered(hopr_api::node::PixPrivateKeyRecovered {
            id: pix_id(1),
            secret: hopr_api::chain::PixDepositSecret(rk1.into()),
        }))
        .await?;
        s.on_pix_event(PixEvent::PrivateKeyRecovered(hopr_api::node::PixPrivateKeyRecovered {
            id: pix_id(2),
            secret: hopr_api::chain::PixDepositSecret(rk2.into()),
        }))
        .await?;
        assert_eq!(s.withdrawal_buffer.len(), 2, "both events must still be buffered");

        s.flush_withdrawals().await;
        assert!(hopr_balance(&*cc, ra1).await?.is_zero());
        assert!(hopr_balance(&*cc, ra2).await?.is_zero());
        assert!(hopr_balance(&*cc, *BOB).await? >= b1 + b2);
        Ok(())
    }

    /// Regression test for the batch sweep's result-to-id correlation.
    ///
    /// The middle entry of a three-item batch carries a secret this pool's scheme cannot parse.
    /// The two usable entries must still be swept *and* have their recovery-store rows removed;
    /// the unusable one must be released from the in-flight guard and keep its row for a later
    /// attempt.
    ///
    /// The old code built the key list with `filter_map` next to an id list built with `map`, then
    /// matched sweep results back to ids by index. The dropped middle key shortened the key list,
    /// so result 1 — the second *surviving* key's outcome — was credited to id 2, the entry that
    /// was never attempted. That removed a live recovery row while leaving a swept one behind.
    #[test_log::test(tokio::test)]
    async fn test_batch_sweep_attributes_results_past_an_unusable_secret() -> anyhow::Result<()> {
        let rk1 = hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let rk3 = hex!("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
        let ra1 = ChainKeypair::from_secret(&rk1)?.public().to_address();
        let ra3 = ChainKeypair::from_secret(&rk3)?.public().to_address();
        let (b1, b3) = (HoprBalance::new_base(50), HoprBalance::new_base(70));

        // All-zero is not a valid secp256k1 scalar, so `key_from_secret` rejects it.
        let bad_secret = hopr_api::chain::PixDepositSecret([0u8; 32].into());

        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .with_balances([(ra1, b1), (ra3, b3)])
            .with_balances([(ra1, XDaiBalance::new_base(1)), (ra3, XDaiBalance::new_base(1))])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut connector = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        connector.connect().await?;
        let client = connector.client();
        register_test_safe(&connector, *BOB).await?;
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::with_client(
            Arc::clone(&node),
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
            client,
        ));

        let dir = tempfile::tempdir()?;
        let store = PixRecoveryStore::open(dir.path().join("pix.db"), "batch-attribution-test")?;
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::from_secs(60),
            ..Default::default()
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, Some(store.clone()));

        let (id1, id2, id3) = (pix_id(1), pix_id(2), pix_id(3));
        for (id, secret) in [
            (id1, hopr_api::chain::PixDepositSecret(rk1.into())),
            (id2, bad_secret),
            (id3, hopr_api::chain::PixDepositSecret(rk3.into())),
        ] {
            s.on_pix_event(PixEvent::PrivateKeyRecovered(hopr_api::node::PixPrivateKeyRecovered {
                id,
                secret,
            }))
            .await?;
        }
        assert_eq!(s.withdrawal_buffer.len(), 3, "all three must be buffered");

        s.flush_withdrawals().await;

        assert!(hopr_balance(&*cc, ra1).await?.is_zero(), "the first key must be swept");
        assert!(hopr_balance(&*cc, ra3).await?.is_zero(), "the third key must be swept");
        assert!(hopr_balance(&*cc, *BOB).await? >= b1 + b3);

        assert!(!store.contains(&id1)?, "a swept entry must be removed from the store");
        assert!(!store.contains(&id3)?, "a swept entry must be removed from the store");
        assert!(
            store.contains(&id2)?,
            "the unusable entry was never attempted, so it must keep its row for manual recovery"
        );
        Ok(())
    }

    /// The deposit retry has to be visible, and it has to actually retry.
    ///
    /// `deposit_funds_to` reads the destination balance before transferring, and the stub chain
    /// has no entry for an address that was never funded — so a destination that does not exist
    /// yet fails the first attempt. A tiny transfer during the backoff brings it into existence
    /// and a later attempt succeeds.
    ///
    /// This is the deposit-side counterpart of `test_sweep_retries_until_the_deposit_lands`, and
    /// the only thing that exercises `deposit_funds_to`'s retry-notification path.
    #[test_log::test(tokio::test)]
    async fn test_deposit_retries_until_the_destination_is_reachable() -> anyhow::Result<()> {
        use hopr_api::chain::DepositPool;

        let dst: Address = [0x42u8; 20].into();
        let amount = HoprBalance::new_base(40);
        let seed = HoprBalance::new_base(1);

        let sim = BlokliTestStateBuilder::default().with_generated_accounts(
            &[&*ALICE, &*CHRIS],
            false,
            XDaiBalance::new_base(1),
            HoprBalance::new_base(1000),
        );
        let sim = with_self_safed_node(sim, *BOB, 9, HoprBalance::new_base(1000))
            // Deliberately no entry for `dst`: the first read fails.
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut connector = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        connector.connect().await?;
        let client = connector.client();
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = NonAnonymousDepositPool::with_client(
            node,
            BOB_KP.clone(),
            pool_cfg_with_retries(StdDuration::from_secs(60), XDaiBalance::zero(), 5, 0),
            client,
        );

        let funder = Arc::clone(&cc);
        let appearing = tokio::spawn(async move {
            tokio::time::sleep(StdDuration::from_millis(300)).await;
            funder.withdraw(seed, &dst).await?.await?;
            Ok::<_, anyhow::Error>(())
        });

        let id = pix_id(1);
        let result = pool
            .deposit_funds_to(&id, &dst, amount, ByteDepositData::new(id, DEPOSIT_MARKER_PAYLOAD))
            .await;
        appearing.await??;

        assert!(
            result.is_ok(),
            "the deposit must succeed once the destination exists: {result:?}"
        );
        assert_eq!(hopr_balance(&*cc, dst).await?, seed + amount);
        Ok(())
    }

    /// A deposit that never lands must fail the tracking future rather than hang.
    ///
    /// The deadline belongs to the pool, so this is the only place it is observable: the future
    /// resolves to an error of its own accord once `max_deposit_tracking_time` elapses.
    #[test_log::test(tokio::test)]
    async fn test_notify_deposit_times_out_when_nothing_arrives() -> anyhow::Result<()> {
        use hopr_api::chain::DepositPool;

        let dst: Address = [0x44u8; 20].into();
        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .with_balances([(dst, HoprBalance::zero())])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut connector = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        connector.connect().await?;
        let client = connector.client();
        let node = Arc::new(ChainNode(Arc::new(connector)));
        let pool = NonAnonymousDepositPool::with_client(
            Arc::new(node),
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(1), XDaiBalance::zero()),
            client,
        );

        let fut = pool.notify_deposit(pix_id(1), dst, HoprBalance::new_base(10))?;
        let result = fut.await;

        assert!(
            result.is_err(),
            "tracking must give up on its own deadline, got {:?}",
            result.map(|(_, a, b)| (a, b))
        );
        Ok(())
    }

    /// The non-anonymous pool generates its marker payload, filed under the allocation asked about.
    ///
    /// Asserted through the round trip to `PixDepositData` rather than on `ByteDepositData`
    /// directly, because the wire form is what the Exit actually puts on the request — and the
    /// conversion is the pool's own, so it is part of what is under test. What comes out has to be
    /// byte-for-byte what the peer's copy of this pool will accept; the payload check on the
    /// receiving side is what makes that a contract rather than a detail.
    #[test_log::test(tokio::test)]
    async fn test_generate_deposit_data_carries_the_marker_and_the_id() -> anyhow::Result<()> {
        use hopr_api::chain::DepositPool;

        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut connector = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        connector.connect().await?;
        let client = connector.client();
        let node = Arc::new(ChainNode(Arc::new(connector)));
        let pool = NonAnonymousDepositPool::with_client(
            Arc::new(node),
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
            client,
        );

        let id = pix_id(1);
        let wire: PixDepositData = pool.generate_deposit_data(&id).await?.try_into()?;

        assert_eq!(wire.id, id, "the payload must be filed under the requested allocation");
        assert_eq!(
            &*wire.data, &DEPOSIT_MARKER_PAYLOAD,
            "the payload must be the marker the receiving side checks for"
        );
        Ok(())
    }

    /// A batch in which nothing is usable must not reach the pool at all.
    ///
    /// Handing an empty slice to `withdraw_multiple_deposits` would be a pointless round trip, and
    /// the guards still have to be released so a later start can retry.
    #[test_log::test(tokio::test)]
    async fn test_batch_sweep_with_no_usable_keys_skips_the_pool() -> anyhow::Result<()> {
        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut connector = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        connector.connect().await?;
        let client = connector.client();
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::with_client(
            Arc::clone(&node),
            BOB_KP.clone(),
            pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
            client,
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::from_secs(60),
            ..Default::default()
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);

        let (id1, id2) = (pix_id(1), pix_id(2));
        for id in [id1, id2] {
            s.on_pix_event(PixEvent::PrivateKeyRecovered(hopr_api::node::PixPrivateKeyRecovered {
                id,
                secret: hopr_api::chain::PixDepositSecret([0u8; 32].into()),
            }))
            .await?;
        }

        s.flush_withdrawals().await;

        assert!(s.withdrawal_buffer.is_empty(), "the buffer must be drained either way");
        for id in [id1, id2] {
            assert!(
                !s.in_flight_sweeps.contains_key(&id),
                "every id must be released from the in-flight guard"
            );
        }
        Ok(())
    }
}
