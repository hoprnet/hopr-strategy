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
//! `secp256k1::NonAnonymousDepositPool` and `build_curvy` for `curvy::CurvyDepositPool`. Each
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
    #[default(default_max_ssa_allocation())]
    #[serde_as(as = "DisplayFromStr")]
    #[serde(default = "default_max_ssa_allocation")]
    pub max_ssa_allocation: HoprBalance,
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

    /// Build with the [`NonAnonymousDepositPool`](crate::pix::secp256k1::NonAnonymousDepositPool),
    /// settling to secp256k1 (`Address`) deposit addresses.
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
    ///     node::{ActionableEventSource, HasChainApi},
    ///     types::primitive::prelude::Address,
    /// };
    /// use hopr_strategy::pix::strategy::{PixStrategy, PixStrategyConfig};
    ///
    /// # fn main() -> anyhow::Result<()> {
    /// # fn build<N: HasChainApi + ActionableEventSource + Send + Sync + 'static>(node: Arc<N>)
    /// #     -> hopr_strategy::errors::Result<()> {
    /// // In `hoprd` this is `<HoprPixSpec as PixSpec>::DepositAddress`, not a literal `Address`.
    /// let _strategy =
    ///     PixStrategy::new(PixStrategyConfig::default()).build_non_anonymous::<_, Address>(node, Default::default())?;
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
    ///     node::{ActionableEventSource, HasChainApi},
    ///     types::crypto::prelude::BjjPublicKey,
    /// };
    /// use hopr_strategy::pix::strategy::{PixStrategy, PixStrategyConfig};
    ///
    /// fn build<N: HasChainApi + ActionableEventSource + Send + Sync + 'static>(node: Arc<N>) {
    ///     // `NonAnonymousDepositPool` settles to `Address`, so this pairing is rejected here
    ///     // rather than failing on every event at runtime.
    ///     let _ = PixStrategy::new(PixStrategyConfig::default())
    ///         .build_non_anonymous::<_, BjjPublicKey>(node, Default::default());
    /// }
    /// ```
    #[cfg(feature = "strategy-pix-test")]
    pub fn build_non_anonymous<N, A>(
        self,
        node: Arc<N>,
        pool_cfg: crate::pix::secp256k1::PoolConfig,
    ) -> Result<Box<dyn StrategyTrait + Send>>
    where
        N: HasChainApi + ActionableEventSource + Send + Sync + 'static,
        A: crate::pix::DepositAddressOf<crate::pix::secp256k1::PoolKeypair>,
    {
        // `Arc` rather than the bare pool: `build_with_pool` needs a cloneable `D`, and
        // `DepositPool` is auto-implemented for `Arc<D>`.
        let pool = Arc::new(crate::pix::secp256k1::NonAnonymousDepositPool::new(
            Arc::clone(&node),
            pool_cfg,
        ));
        let safe_address = node.identity().safe_address;

        // The key is named rather than inferred: it is the choice this builder exists to make.
        self.build_with_pool::<_, _, crate::pix::secp256k1::PoolKeypair>(pool, node, safe_address)
    }

    /// Build with the [`CurvyDepositPool`](crate::pix::curvy::CurvyDepositPool), settling to Baby
    /// JubJub (`BjjPublicKey`) deposit addresses.
    ///
    /// `A` is the deposit-address type the node's PIX spec produces; see
    /// `build_non_anonymous` for why naming it is the compatibility
    /// check and why it cannot be checked inside this crate. Pass
    /// `<HoprPixSpec as PixSpec>::DepositAddress`; `hopr-lib/pix-bjj` is the default, so a consumer
    /// enabling only this feature already agrees.
    ///
    /// Note that this pool is a **stub**: building succeeds and the first deposit panics. See
    /// [`crate::pix::curvy`].
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
        pool_cfg: crate::pix::curvy::PoolConfig,
    ) -> Result<Box<dyn StrategyTrait + Send>>
    where
        N: HasChainApi + ActionableEventSource + Send + Sync + 'static,
        A: crate::pix::DepositAddressOf<crate::pix::curvy::PoolKeypair>,
    {
        let pool = Arc::new(crate::pix::curvy::CurvyDepositPool::new(Arc::clone(&node), pool_cfg));
        let safe_address = node.identity().safe_address;

        self.build_with_pool::<_, _, crate::pix::curvy::PoolKeypair>(pool, node, safe_address)
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

                self.deposit_buffer
                    .push((new_deposit_address.id, dest_addr, target_deposit, deposit_data));

                tracing::info!(%target_deposit, "deposit buffered, pending flush");

                if self.cfg.deposit_buffer_period.is_zero() {
                    self.flush_deposits().await;
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
                    self.flush_withdrawals().await;
                }
            }
        }

        Ok(())
    }

    /// Flush the buffered deposits using single or batch [`DepositPool`] methods.
    ///
    /// Retries are the pool's responsibility, so an error here means the pool already
    /// exhausted its own budget and the deposit is abandoned for this flush.
    async fn flush_deposits(&mut self) {
        if self.deposit_buffer.is_empty() {
            return;
        }

        let batch = std::mem::take(&mut self.deposit_buffer);
        let count = batch.len();
        let pool = &self.pool;

        if count == 1 {
            let (id, dest_addr, amount, deposit_data) = batch.into_iter().next().unwrap();
            let result = pool
                .deposit_funds_to(&id, &dest_addr, amount, deposit_data)
                .await
                .map_err(Into::<StrategyError>::into);

            match result {
                Ok(_) => {
                    self.processed_deposits.insert(id, ());
                    self.in_flight_destinations.invalidate(&dest_addr);
                    tracing::info!(?id, %amount, "single deposit flushed successfully");
                    #[cfg(all(feature = "telemetry", not(test)))]
                    METRIC_PIX_DEPOSITS.increment();
                }
                Err(error) => {
                    self.in_flight_destinations.invalidate(&dest_addr);
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
                        self.in_flight_destinations.invalidate(dest_addr);
                    }

                    let mut deposited = 0u64;
                    for outcome in outcomes {
                        match outcome {
                            Ok((id, _receipt)) => {
                                self.processed_deposits.insert(id, ());
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
                        self.in_flight_destinations.invalidate(dest_addr);
                    }
                    tracing::error!(%error, count, "batch deposit flush failed");
                    #[cfg(all(feature = "telemetry", not(test)))]
                    METRIC_PIX_DEPOSITS_FAILED.increment_by(count as u64);
                }
            }
        }
    }

    /// Flush the buffered withdrawals using single or batch [`DepositPool`] methods.
    ///
    /// Retries are the pool's responsibility. An entry that still fails keeps its persisted
    /// key so a later start can try again — see [`Self::replay_pending_recoveries`].
    async fn flush_withdrawals(&mut self) {
        if self.withdrawal_buffer.is_empty() {
            return;
        }

        let batch = std::mem::take(&mut self.withdrawal_buffer);
        let count = batch.len();
        let pool = &self.pool;
        let safe_address = self.safe_address;

        if count == 1 {
            let (id, secret) = batch.into_iter().next().unwrap();
            let Ok(key) = key_from_secret::<K>(&secret) else {
                self.in_flight_sweeps.invalidate(&id);
                tracing::error!(?id, "stored recovery secret is not valid for this pool's scheme");
                return;
            };
            let result = pool
                .withdraw_deposit(&id, &key, safe_address, None)
                .await
                .map_err(Into::<StrategyError>::into);

            match result {
                Ok(_) => {
                    self.in_flight_sweeps.invalidate(&id);
                    if let Some(ref store) = self.recovery_store
                        && let Err(error) = store.remove(&id)
                    {
                        tracing::error!(%error, ?id, "failed to remove the swept entry from the recovery store");
                    }
                    tracing::info!(?id, "single withdrawal flushed successfully");
                    #[cfg(all(feature = "telemetry", not(test)))]
                    METRIC_PIX_SWEEPS.increment();
                }
                Err(error) => {
                    self.in_flight_sweeps.invalidate(&id);
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
                        self.in_flight_sweeps.invalidate(id);
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
                        self.in_flight_sweeps.invalidate(id);
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
                                if let Some(ref store) = self.recovery_store
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
                        self.in_flight_sweeps.invalidate(id);
                    }
                    tracing::error!(%error, count, attempted, "batch withdrawal flush failed");
                }
            }
        }
    }
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
                        // At least one deadline elapsed — flush ready buffers.
                        let now = tokio::time::Instant::now();
                        if deposit_flush_at.is_some_and(|d| d <= now) {
                            self.flush_deposits().await;
                            deposit_flush_at = None;
                        }
                        if withdrawal_flush_at.is_some_and(|d| d <= now) {
                            self.flush_withdrawals().await;
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

        // Flush any remaining buffered items.
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
            crypto::{keypairs::Keypair, prelude::ChainKeypair},
            crypto_random::Randomizable,
            internal::prelude::HoprPseudonym,
            primitive::prelude::{Address, HoprBalance, XDaiBalance},
        },
    };
    use tokio::time::timeout;

    use super::{PixStrategy, PixStrategyConfig, PixStrategyInner};
    use crate::{
        errors::StrategyError,
        pix::{EmptyDepositData, recovery_store::PixRecoveryStore, secp256k1::NonAnonymousDepositPool},
        testing::{BlokliTestStateBuilder, TestChainConnector},
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

    /// The payload both bundled pools generate: no bytes, filed under `id`.
    ///
    /// `id` has to be the same value the event carries, so callers bind it to a local first rather
    /// than calling `pix_id` twice — [`pix_id`] is random per call.
    fn empty_deposit_data(id: PixAddressId) -> PixDepositData {
        PixDepositData {
            id,
            data: Box::default(),
        }
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
    fn pool_cfg(t: StdDuration, g: XDaiBalance) -> crate::pix::secp256k1::NonAnonymousDepositPoolConfig {
        pool_cfg_with_retries(t, g, 0, 0)
    }

    fn pool_cfg_with_retries(
        t: StdDuration,
        g: XDaiBalance,
        max_deposit_retries: usize,
        max_sweep_retries: usize,
    ) -> crate::pix::secp256k1::NonAnonymousDepositPoolConfig {
        crate::pix::secp256k1::NonAnonymousDepositPoolConfig {
            max_deposit_tracking_time: t,
            gas_xdai_per_sweep: g,
            max_deposit_retries,
            max_sweep_retries,
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
        let cc = Arc::new(cc);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::new(
            Arc::clone(&node),
            pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        let id = pix_id(1);
        s.on_pix_event(PixEvent::DepositAddressReceived(PixDepositAddressReceived {
            id,
            address: addr.into(),
            quota: 100,
            deposit_updated: tx,
            deposit_data: empty_deposit_data(id),
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
        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .with_balances([(*BOB, HoprBalance::new_base(1000))])
            // `deposit_funds_to` reads the destination balance before transferring, and the
            // stub chain has no entry for an address that was never funded.
            .with_balances([(da, HoprBalance::zero())])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let snap = sim.snapshot();
        let mut cc = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        cc.connect().await?;
        let cc = Arc::new(cc);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::new(
            Arc::clone(&node),
            pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        let bb: HoprBalance = hopr_balance(&*cc, *BOB).await?;
        let id = pix_id(1);
        s.on_pix_event(PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
            id,
            address: da.into(),
            quota: 20,
            deposit_data: empty_deposit_data(id),
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
        let cc = Arc::new(cc);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::new(
            Arc::clone(&node),
            pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(10),
            max_ssa_allocation: HoprBalance::new_base(50),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        let id = pix_id(1);
        let r = s
            .on_pix_event(PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
                id,
                address: Address::from([0x42u8; 20]).into(),
                quota: 10,
                deposit_data: empty_deposit_data(id),
            }))
            .await;
        assert!(matches!(r, Err(StrategyError::CriteriaNotSatisfied)));
        Ok(())
    }

    /// Deposit data this pool cannot read must be reported, not ignored.
    ///
    /// `NonAnonymousDepositPool` carries no side-channel payload, so `EmptyDepositData` rejects
    /// any non-empty bytes. Bytes arriving here mean the Entry and this node's pool disagree on
    /// the payload format — the same class of mismatch as a wrong curve, and it deserves the same
    /// loud failure rather than a deposit that silently drops what the peer sent.
    ///
    /// The in-flight destination guard must survive the rejection: a corrected peer retrying the
    /// same address has to get through, which it cannot if the failed attempt left the address
    /// marked as busy.
    #[test_log::test(tokio::test)]
    async fn test_new_deposit_address_rejects_unreadable_deposit_data() -> anyhow::Result<()> {
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
        let cc = Arc::new(cc);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::new(
            Arc::clone(&node),
            pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(1000),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);

        let dest_addr = Address::from([0x42u8; 20]);
        let id = pix_id(1);
        let r = s
            .on_pix_event(PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
                id,
                address: dest_addr.into(),
                quota: 10,
                deposit_data: PixDepositData {
                    id,
                    data: vec![0xde, 0xad, 0xbe, 0xef].into(),
                },
            }))
            .await;

        assert!(
            matches!(r, Err(StrategyError::GeneralError(_))),
            "unreadable deposit data must be rejected, got {r:?}"
        );
        assert!(
            s.deposit_buffer.is_empty(),
            "a rejected event must not leave a deposit buffered"
        );
        assert!(
            !s.in_flight_destinations.contains_key(&dest_addr),
            "the destination must stay free so a corrected retry can get through"
        );

        // An empty payload is not the same thing as an unreadable one. `PixDepositData` is no
        // longer optional, so "nothing to carry" is now expressed as empty bytes — and that has to
        // be accepted, because it is what both bundled pools generate.
        let accepted = s
            .on_pix_event(PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
                id,
                address: dest_addr.into(),
                quota: 10,
                deposit_data: empty_deposit_data(id),
            }))
            .await;
        assert!(accepted.is_ok(), "an empty payload must be accepted, got {accepted:?}");
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
        let node = Arc::new(ChainNode(Arc::new(cc)));
        let pool = Arc::new(NonAnonymousDepositPool::new(
            Arc::clone(&node),
            pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(1000),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
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
                deposit_data: empty_deposit_data(pix_id(2)),
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
        let node = Arc::new(ChainNode(Arc::new(cc)));
        let pool = Arc::new(NonAnonymousDepositPool::new(
            Arc::clone(&node),
            pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(1000),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
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
            delivered.iter().all(|d| d.is_empty()),
            "the non-anonymous pool carries no side-channel bytes"
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
        let node = Arc::new(ChainNode(Arc::new(cc)));
        let pool = Arc::new(NonAnonymousDepositPool::new(
            Arc::clone(&node),
            pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(1000),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
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
        let cc = Arc::new(cc);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::new(
            Arc::clone(&node),
            pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
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
        register_test_safe(&connector, *BOB).await?;
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::new(
            Arc::clone(&node),
            pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
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
        })
        .build_non_anonymous::<_, Address>(Arc::new(ChainNode(Arc::new(cc))), Default::default())?;
        assert_eq!(s.to_string(), "pix");
        fn assert_send<T: Send>(_: &T) {}
        assert_send(&s);
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_new_deposit_address_dedup_skips_duplicate() -> anyhow::Result<()> {
        let da: Address = [0x42u8; 20].into();
        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .with_balances([(*BOB, HoprBalance::new_base(1000))])
            // `deposit_funds_to` reads the destination balance before transferring, and the
            // stub chain has no entry for an address that was never funded.
            .with_balances([(da, HoprBalance::zero())])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut cc = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        cc.connect().await?;
        let cc = Arc::new(cc);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::new(
            Arc::clone(&node),
            pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        let id = pix_id(1);
        let mk = |id| {
            PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
                id,
                address: da.into(),
                quota: 20,
                deposit_data: empty_deposit_data(id),
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
        })
        .build_non_anonymous::<_, Address>(Arc::new(ChainNode(Arc::new(cc))), Default::default())?;
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
        register_test_safe(&connector, *BOB).await?;
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::new(
            Arc::clone(&node),
            pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
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
        let node = Arc::new(ChainNode(Arc::new(cc)));
        let pool = NonAnonymousDepositPool::new(node, pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()));

        let started = std::time::Instant::now();
        let result = pool
            .withdraw_deposit(
                &pix_id(1),
                &crate::pix::secp256k1::EthDepositKey::from_secret(&rk)?,
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
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = NonAnonymousDepositPool::new(
            node,
            pool_cfg_with_retries(StdDuration::from_secs(60), XDaiBalance::zero(), 0, 3),
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
                &crate::pix::secp256k1::EthDepositKey::from_secret(&rk)?,
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
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = NonAnonymousDepositPool::new(node, pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()));

        let safe_before = hopr_balance(&*cc, *BOB).await?;
        let dst_before = hopr_balance(&*cc, *CHRIS).await?;

        let dst_id = pix_id(2);
        pool.pool_transfer(
            &pix_id(1),
            &crate::pix::secp256k1::EthDepositKey::from_secret(&rk)?,
            &dst_id,
            *CHRIS,
            EmptyDepositData::for_id(dst_id),
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
        let node = Arc::new(ChainNode(Arc::new(cc)));
        let pool = NonAnonymousDepositPool::new(node, pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()));

        let dst_id = pix_id(2);
        let result = pool
            .pool_transfer(
                &pix_id(1),
                &crate::pix::secp256k1::EthDepositKey::from_secret(&rk)?,
                &dst_id,
                *CHRIS,
                EmptyDepositData::for_id(dst_id),
                None,
            )
            .await;

        assert!(
            matches!(result, Err(StrategyError::CriteriaNotSatisfied)),
            "an empty address must be refused, got {result:?}"
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
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = NonAnonymousDepositPool::new(
            node,
            pool_cfg_with_retries(StdDuration::from_secs(60), XDaiBalance::zero(), 0, 3),
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
                &crate::pix::secp256k1::EthDepositKey::from_secret(&rk)?,
                &dst_id,
                *CHRIS,
                EmptyDepositData::for_id(dst_id),
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
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = NonAnonymousDepositPool::new(
            node,
            pool_cfg_with_retries(StdDuration::from_secs(60), XDaiBalance::zero(), 0, 3),
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
                    crate::pix::secp256k1::EthDepositKey::from_secret(rk).expect("valid test secret"),
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
        let pool = Arc::new(NonAnonymousDepositPool::new(
            Arc::clone(&node),
            pool_cfg_with_retries(StdDuration::from_secs(60), XDaiBalance::zero(), 0, 5),
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
        };
        let mut s = PixStrategyInner::new(pool, Arc::clone(&node), cfg, *BOB, Some(store));

        let running = tokio::spawn(async move { s.run().await });
        let id = pix_id(1);
        node.inject_pix(PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
            id,
            address: da.into(),
            quota,
            deposit_data: empty_deposit_data(id),
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
        register_test_safe(&connector, *BOB).await?;
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::new(
            Arc::clone(&node),
            pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            // Flush immediately: this test asserts on the outcome of the sweep itself.
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
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
        })
        .build_non_anonymous::<_, Address>(Arc::new(ChainNode(Arc::new(cc))), Default::default());
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
        })
        .build_non_anonymous::<_, Address>(Arc::new(ChainNode(Arc::new(cc))), Default::default());
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
        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                start_balance,
            )
            .with_balances([(*BOB, start_balance)])
            // `deposit_funds_to` reads the destination balance before transferring, and the
            // stub chain has no entry for an address that was never funded.
            .with_balances([(da1, HoprBalance::zero()), (da2, HoprBalance::zero())])
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut cc = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        cc.connect().await?;
        let cc = Arc::new(cc);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::new(
            Arc::clone(&node),
            pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::from_secs(60),
            withdrawal_buffer_period: StdDuration::ZERO,
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
            deposit_data: empty_deposit_data(id1),
        }))
        .await?;
        s.on_pix_event(PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
            id: id2,
            address: da2.into(),
            quota: 30,
            deposit_data: empty_deposit_data(id2),
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
        register_test_safe(&connector, *BOB).await?;
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::new(
            Arc::clone(&node),
            pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::from_secs(60),
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
        register_test_safe(&connector, *BOB).await?;
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::new(
            Arc::clone(&node),
            pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
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

        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .with_balances([(*BOB, HoprBalance::new_base(1000))])
            // Deliberately no entry for `dst`: the first read fails.
            .build_dynamic_client(MODULE_ADDRESS.into());
        let mut connector = TestChainConnector::new(sim, *BOB, BOB_KP.clone(), MODULE_ADDRESS.into());
        connector.connect().await?;
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = NonAnonymousDepositPool::new(
            node,
            pool_cfg_with_retries(StdDuration::from_secs(60), XDaiBalance::zero(), 5, 0),
        );

        let funder = Arc::clone(&cc);
        let appearing = tokio::spawn(async move {
            tokio::time::sleep(StdDuration::from_millis(300)).await;
            funder.withdraw(seed, &dst).await?.await?;
            Ok::<_, anyhow::Error>(())
        });

        let id = pix_id(1);
        let result = pool
            .deposit_funds_to(&id, &dst, amount, EmptyDepositData::for_id(id))
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
        let node = Arc::new(ChainNode(Arc::new(connector)));
        let pool =
            NonAnonymousDepositPool::new(Arc::new(node), pool_cfg(StdDuration::from_secs(1), XDaiBalance::zero()));

        let fut = pool.notify_deposit(pix_id(1), dst, HoprBalance::new_base(10))?;
        let result = fut.await;

        assert!(
            result.is_err(),
            "tracking must give up on its own deadline, got {:?}",
            result.map(|(_, a, b)| (a, b))
        );
        Ok(())
    }

    /// The non-anonymous pool generates an empty payload, filed under the allocation asked about.
    ///
    /// Asserted through the round trip to `PixDepositData` rather than on `EmptyDepositData`
    /// directly, because the wire form is what the Exit actually puts on the request — and the
    /// conversion is the pool's own, so it is part of what is under test.
    #[test_log::test(tokio::test)]
    async fn test_generate_deposit_data_is_empty_and_carries_the_id() -> anyhow::Result<()> {
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
        let node = Arc::new(ChainNode(Arc::new(connector)));
        let pool =
            NonAnonymousDepositPool::new(Arc::new(node), pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()));

        let id = pix_id(1);
        let wire: PixDepositData = pool.generate_deposit_data(&id).await?.try_into()?;

        assert_eq!(wire.id, id, "the payload must be filed under the requested allocation");
        assert!(wire.is_empty(), "a plain transfer has no side-channel payload");
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
        let cc = Arc::new(connector);
        let node = Arc::new(ChainNode(Arc::clone(&cc)));
        let pool = Arc::new(NonAnonymousDepositPool::new(
            Arc::clone(&node),
            pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
        ));
        let cfg = PixStrategyConfig {
            price_per_byte: HoprBalance::new_base(1),
            max_ssa_allocation: HoprBalance::new_base(100),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::from_secs(60),
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
