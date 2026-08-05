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
//! When the default [`NonAnonymousDepositPool`] is sufficient, use
//! [`PixStrategy::build`] directly.  For a custom pool, construct it first and
//! pass it to [`PixStrategy::build_with_pool`].

use std::{
    fmt::{Debug, Display, Formatter},
    sync::Arc,
    time::Duration,
};

use backon::Retryable;
use futures::{SinkExt, StreamExt};
use hopr_api::{
    chain::{DepositPool, PixDepositAddress, PixDepositSecret},
    node::{ActionableEventDiscriminant, ActionableEventSource, HasChainApi, PixAddressId, PixEvent},
    types::primitive::prelude::*,
};
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::{
    errors::{Result, StrategyError},
    pix::{
        non_anonymous_pool::{NonAnonymousDepositPool, NonAnonymousDepositPoolConfig},
        recovery_store::PixRecoveryStore,
    },
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

/// Configuration for [`PixStrategy`].
#[derive(Clone, Debug, Serialize, Deserialize, Validate, smart_default::SmartDefault)]
pub struct PixStrategyConfig {
    /// wxHOPR paid per byte of SSA quota.
    #[default(HoprBalance::new_base(1))]
    #[serde(default)]
    pub price_per_byte: HoprBalance,
    /// Maximum wxHOPR the strategy will send to a single deposit address.
    #[default(HoprBalance::new_base(100))]
    #[serde(default)]
    pub max_ssa_allocation: HoprBalance,
    /// Configuration for the default non-anonymous deposit pool.
    #[serde(default)]
    pub pool: NonAnonymousDepositPoolConfig,
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
    #[default(Duration::from_millis(500))]
    #[serde(with = "humantime_serde", default)]
    pub deposit_buffer_period: Duration,
    /// How long to wait for additional withdrawal events before flushing the batch.
    /// Default: 500ms (debounced — resets on each new event).
    #[default(Duration::from_millis(500))]
    #[serde(with = "humantime_serde", default)]
    pub withdrawal_buffer_period: Duration,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PROCESSED_DEPOSITS_CAPACITY: u64 = 8192;
const PROCESSED_DEPOSITS_TTL: Duration = Duration::from_secs(24 * 3600);
const IN_FLIGHT_GUARD_CAPACITY: u64 = 1024;
const IN_FLIGHT_GUARD_TTL: Duration = Duration::from_secs(600);

/// Retry budget for the Entry-side deposit withdrawal.
const MAX_DEPOSIT_WITHDRAW_RETRIES: usize = 3;

/// Retry budget for the Exit-side sweep of a deposit address.
const MAX_SWEEP_RETRIES: usize = 5;

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

    /// Build with the default [`NonAnonymousDepositPool`].
    pub fn build_non_anonymous<N>(self, node: Arc<N>) -> Result<Box<dyn StrategyTrait + Send>>
    where
        N: HasChainApi + ActionableEventSource + Send + Sync + 'static,
    {
        let pool = NonAnonymousDepositPool::new(Arc::clone(&node), self.cfg.pool.clone());
        let safe_address = node.identity().safe_address;

        self.build_with_pool(pool, node, safe_address)
    }

    /// Build with an arbitrary [`DepositPool`] implementation.
    pub fn build_with_pool<D, N>(
        self,
        pool: D,
        node: Arc<N>,
        safe_address: Address,
    ) -> Result<Box<dyn StrategyTrait + Send>>
    where
        D: DepositPool + Send + Sync + 'static,
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
        _ => Err(StrategyError::CriteriaNotSatisfied),
    }
}

// ---------------------------------------------------------------------------
// Inner strategy
// ---------------------------------------------------------------------------

/// The generic PIX strategy runner.
struct PixStrategyInner<D: DepositPool, N> {
    pool: D,
    node: Arc<N>,
    cfg: PixStrategyConfig,
    safe_address: Address,
    recovery_store: Option<PixRecoveryStore>,
    processed_deposits: Cache<PixAddressId, ()>,
    in_flight_sweeps: Cache<PixAddressId, ()>,
    in_flight_destinations: Cache<Address, ()>,
    /// Debounced deposit buffer.
    deposit_buffer: Vec<(PixAddressId, PixDepositAddress, Address, HoprBalance)>,
    /// Debounced withdrawal buffer.
    withdrawal_buffer: Vec<(PixAddressId, PixDepositSecret)>,
}

#[cfg(test)]
impl<D: DepositPool, N> PixStrategyInner<D, N> {
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

impl<D: DepositPool + Sync, N: ActionableEventSource + Send + Sync + 'static> PixStrategyInner<D, N>
where
    D::Error: Into<StrategyError>,
{
    /// Validate and buffer a PIX event for batched execution.
    ///
    /// [`NewDepositAddress`] and [`PrivateKeyRecovered`] events are pushed into
    /// debounced buffers and flushed later by [`flush_deposits`] / [`flush_withdrawals`].
    /// [`DepositAddressReceived`] is handled immediately (spawns a polling task).
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

                let dest_addr: Address = new_deposit_address.address.try_into()?;
                if self.in_flight_destinations.contains_key(&dest_addr) {
                    tracing::warn!(?dest_addr, "withdrawal already in flight to this destination, skipping");
                    return Ok(());
                }
                self.in_flight_destinations.insert(dest_addr, ());

                self.deposit_buffer.push((
                    new_deposit_address.id,
                    new_deposit_address.address,
                    dest_addr,
                    target_deposit,
                ));

                tracing::info!(%target_deposit, "deposit buffered, pending flush");

                if self.cfg.deposit_buffer_period.is_zero() {
                    self.flush_deposits().await;
                }
            }
            PixEvent::DepositAddressReceived(deposit_address_recv) => {
                tracing::info!(?deposit_address_recv, "deposit address received");

                let pix_id = deposit_address_recv.id;
                let deposit_updated = deposit_address_recv.deposit_updated;
                let target_deposit = self.cfg.price_per_byte * deposit_address_recv.quota;

                let notify_fut = match self.pool.notify_deposit(deposit_address_recv.address, target_deposit) {
                    Ok(fut) => fut,
                    Err(_) => {
                        tracing::error!(
                            ?pix_id,
                            "too many concurrent deposit trackers, not tracking this deposit"
                        );
                        return Err(StrategyError::CriteriaNotSatisfied);
                    }
                };

                let max_tracking_time = self.cfg.pool.max_deposit_tracking_time;

                hopr_utils::runtime::prelude::spawn(async move {
                    let result = futures_time::future::FutureExt::timeout(
                        notify_fut,
                        futures_time::time::Duration::from(max_tracking_time),
                    )
                    .await;

                    match result {
                        Ok((_addr, balance)) => {
                            if let Some(mut notifier) = deposit_updated {
                                let _ = notifier.send((pix_id, balance)).await;
                            }
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
                #[cfg(all(feature = "telemetry", not(test)))]
                METRIC_PIX_KEYS_RECOVERED.increment();

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
    async fn flush_deposits(&mut self) {
        if self.deposit_buffer.is_empty() {
            return;
        }

        let batch = std::mem::take(&mut self.deposit_buffer);
        let count = batch.len();
        let pool = &self.pool;

        if count == 1 {
            let (id, pix_addr, dest_addr, amount) = batch.into_iter().next().unwrap();
            let result = (move || {
                let addr = pix_addr;
                async move { pool.deposit_funds_to(addr, amount).await.map_err(Into::into) }
            })
            .retry(backon::ExponentialBuilder::default().with_max_times(MAX_DEPOSIT_WITHDRAW_RETRIES))
            .sleep(backon::FuturesTimerSleeper)
            .notify(|error, dur| {
                tracing::warn!(%error, ?dur, "deposit withdrawal failed, retrying in");
            })
            .await;

            match result {
                Ok(_) => {
                    self.processed_deposits.insert(id, ());
                    self.in_flight_destinations.invalidate(&dest_addr);
                    tracing::info!(%amount, "single deposit flushed successfully");
                    #[cfg(all(feature = "telemetry", not(test)))]
                    METRIC_PIX_DEPOSITS.increment();
                }
                Err(error) => {
                    self.in_flight_destinations.invalidate(&dest_addr);
                    tracing::error!(%error, "single deposit flush failed");
                    #[cfg(all(feature = "telemetry", not(test)))]
                    METRIC_PIX_DEPOSITS_FAILED.increment();
                }
            }
        } else {
            let deposits: Vec<(PixDepositAddress, HoprBalance)> =
                batch.iter().map(|(_, addr, _, amount)| (*addr, *amount)).collect();

            let result = (move || {
                let deps = deposits.clone();
                async move { pool.deposit_funds_to_multiple(deps).await.map_err(Into::into) }
            })
            .retry(backon::ExponentialBuilder::default().with_max_times(MAX_DEPOSIT_WITHDRAW_RETRIES))
            .sleep(backon::FuturesTimerSleeper)
            .notify(|error, dur| {
                tracing::warn!(%error, ?dur, "batch deposit failed, retrying in");
            })
            .await;

            match result {
                Ok(_receipts) => {
                    for (id, _, dest_addr, _) in &batch {
                        self.processed_deposits.insert(*id, ());
                        self.in_flight_destinations.invalidate(dest_addr);
                    }
                    tracing::info!(count, "batch deposit flushed successfully");
                    #[cfg(all(feature = "telemetry", not(test)))]
                    METRIC_PIX_DEPOSITS.increment_by(count as u64);
                }
                Err(error) => {
                    for (_, _, dest_addr, _) in &batch {
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
            let result = (move || {
                let sec = secret.clone();
                async move {
                    pool.withdraw_deposit(&sec, safe_address, None)
                        .await
                        .map_err(Into::into)
                }
            })
            .retry(backon::ExponentialBuilder::default().with_max_times(MAX_SWEEP_RETRIES))
            .sleep(backon::FuturesTimerSleeper)
            .notify(|error, dur| {
                tracing::warn!(%error, ?dur, "sweep failed, retrying in");
            })
            .await;

            match result {
                Ok(_) => {
                    self.in_flight_sweeps.invalidate(&id);
                    if let Some(ref store) = self.recovery_store {
                        let _ = store.remove(&id);
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
            let keys: Vec<PixDepositSecret> = batch.iter().map(|(_, secret)| secret.clone()).collect();
            let ids: Vec<PixAddressId> = batch.iter().map(|(id, _)| *id).collect();

            let result = (move || {
                let k = keys.clone();
                async move {
                    pool.withdraw_multiple_deposits(&k, safe_address)
                        .await
                        .map_err(Into::into)
                }
            })
            .retry(backon::ExponentialBuilder::default().with_max_times(MAX_SWEEP_RETRIES))
            .sleep(backon::FuturesTimerSleeper)
            .notify(|error, dur| {
                tracing::warn!(%error, ?dur, "batch sweep failed, retrying in");
            })
            .await;

            match result {
                Ok(results) => {
                    for (i, id) in ids.iter().enumerate() {
                        if results.get(i).map_or(false, |r| r.is_ok()) {
                            self.in_flight_sweeps.invalidate(id);
                            if let Some(ref store) = self.recovery_store {
                                let _ = store.remove(id);
                            }
                        } else {
                            self.in_flight_sweeps.invalidate(id);
                        }
                    }
                    tracing::info!(count, "batch withdrawal flushed");
                    #[cfg(all(feature = "telemetry", not(test)))]
                    METRIC_PIX_SWEEPS.increment_by(count as u64);
                }
                Err(error) => {
                    for id in &ids {
                        self.in_flight_sweeps.invalidate(id);
                    }
                    tracing::error!(%error, count, "batch withdrawal flush failed");
                }
            }
        }
    }

    /// Re-attempt the sweep for every persisted recovery entry.
    ///
    /// Entries are swept sequentially. An entry whose deposit address is still empty fails
    /// with [`StrategyError::CriteriaNotSatisfied`] and is deliberately left in the store, so
    /// a deposit that lands later is picked up by a subsequent start rather than lost.
    async fn replay_pending_recoveries(&self, store: &PixRecoveryStore) {
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
            if self.in_flight_sweeps.contains_key(&id) {
                tracing::warn!(?id, "sweep already in flight for recovery replay entry, skipping");
                continue;
            }
            self.in_flight_sweeps.insert(id, ());

            let pool = &self.pool;
            let safe_address = self.safe_address;
            let local_secret = secret;
            let sweep_result = (move || {
                let secret = local_secret.clone();
                async move {
                    pool.withdraw_deposit(&secret, safe_address, None)
                        .await
                        .map_err(Into::into)
                }
            })
            .retry(backon::ExponentialBuilder::default().with_max_times(MAX_SWEEP_RETRIES))
            .sleep(backon::FuturesTimerSleeper)
            .notify(|error, dur| {
                tracing::warn!(%error, ?dur, "recovery replay sweep failed, retrying in");
            })
            .await;

            match sweep_result {
                Ok(_) => {
                    self.in_flight_sweeps.invalidate(&id);
                    if let Err(error) = store.remove(&id) {
                        tracing::warn!(%error, ?id, "failed to remove swept entry from store");
                    }
                    tracing::info!(?id, "recovery replay completed");
                }
                Err(error) => {
                    tracing::error!(%error, ?id, "recovery replay failed after max retries, giving up");
                    self.in_flight_sweeps.invalidate(&id);
                    // Leave the entry in the store for manual recovery.
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Display / Debug
// ---------------------------------------------------------------------------

impl<D: DepositPool, N> Display for PixStrategyInner<D, N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "pix")
    }
}

impl<D: DepositPool, N> Debug for PixStrategyInner<D, N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "PixStrategy({:?})", self.cfg)
    }
}

// ---------------------------------------------------------------------------
// Strategy trait impl
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl<D, N> StrategyTrait for PixStrategyInner<D, N>
where
    D: DepositPool + Send + Sync + 'static,
    D::Error: Into<StrategyError>,
    N: ActionableEventSource + Send + Sync + 'static,
{
    async fn run(&mut self) -> Result<()> {
        let mut event_stream = self
            .node
            .subscribe_to_actionable_events(Some(&[ActionableEventDiscriminant::Pix]))
            .map_err(|e| StrategyError::Other(anyhow::anyhow!(e)))?
            .filter_map(|event| futures::future::ready(event.try_as_pix()));

        if let Some(ref store) = self.recovery_store {
            self.replay_pending_recoveries(store).await;
        }

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
                        if deposit_flush_at.map_or(false, |d| d <= now) {
                            self.flush_deposits().await;
                            deposit_flush_at = None;
                        }
                        if withdrawal_flush_at.map_or(false, |d| d <= now) {
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

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
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
            ComponentStatusReporter, EventWaitResult, HasChainApi, NodeOnchainIdentity, PixDepositAddressReceived,
            PixEvent,
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
        pix::{non_anonymous_pool::NonAnonymousDepositPool, recovery_store::PixRecoveryStore},
        testing::{BlokliTestStateBuilder, TestChainConnector},
    };

    const TEST_PASSWORD_ENV: &str = "HOPRD_TEST_PIX_RECOVERY_PASSWORD";

    lazy_static::lazy_static! {
        static ref BOB_KP: ChainKeypair = ChainKeypair::from_secret(&hex!(
            "492057cf93e99b31d2a85bc5e98a9c3aa0021feec52c227cc8170e8f7d047775"
        )).expect("lazy static keypair");

        static ref ALICE: Address = hex!("18f8ae833c85c51fbeba29cef9fbfb53b3bad950").into();
        static ref BOB: Address = BOB_KP.public().to_address();
        static ref CHRIS: Address = hex!("b6021e0860dd9d96c9ff0a73e2e5ba3a466ba234").into();
    }

    const MODULE_ADDRESS: [u8; 20] = [1u8; 20];

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

    fn pool_cfg(t: StdDuration, g: XDaiBalance) -> crate::pix::non_anonymous_pool::NonAnonymousDepositPoolConfig {
        crate::pix::non_anonymous_pool::NonAnonymousDepositPoolConfig {
            max_deposit_tracking_time: t,
            gas_xdai_per_sweep: g,
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
            pool: pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        s.on_pix_event(PixEvent::DepositAddressReceived(PixDepositAddressReceived {
            id: (HoprPseudonym::random(), NonZeroU32::new(1).unwrap()),
            address: addr.into(),
            quota: 100,
            deposit_updated: Some(tx),
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
            pool: pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        let bb: HoprBalance = hopr_balance(&*cc, *BOB).await?;
        s.on_pix_event(PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
            id: (HoprPseudonym::random(), NonZeroU32::new(1).unwrap()),
            address: da.into(),
            quota: 20,
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
            pool: pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        let r = s
            .on_pix_event(PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
                id: (HoprPseudonym::random(), NonZeroU32::new(1).unwrap()),
                address: Address::from([0x42u8; 20]).into(),
                quota: 10,
            }))
            .await;
        assert!(matches!(r, Err(StrategyError::CriteriaNotSatisfied)));
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
            pool: pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        let id = (HoprPseudonym::random(), NonZeroU32::new(1).unwrap());
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
            pool: pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        s.on_pix_event(PixEvent::PrivateKeyRecovered(hopr_api::node::PixPrivateKeyRecovered {
            id: (HoprPseudonym::random(), NonZeroU32::new(1).unwrap()),
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
            pool: Default::default(),
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
            pool: Default::default(),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
        })
        .build_non_anonymous(Arc::new(ChainNode(Arc::new(cc))))?;
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
            pool: pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        let id = (HoprPseudonym::random(), NonZeroU32::new(1).unwrap());
        let mk = |id| {
            PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
                id,
                address: da.into(),
                quota: 20,
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
        // SAFETY: single-threaded test, no concurrent access to the environment
        // for this variable.
        unsafe { std::env::set_var(TEST_PASSWORD_ENV, "test_password") };
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
            pool: Default::default(),
            pix_recovery_db_path: Some(db.clone()),
            pix_recovery_password_env: Some(TEST_PASSWORD_ENV.to_string()),
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
        })
        .build_non_anonymous(Arc::new(ChainNode(Arc::new(cc))))?;
        assert!(db.exists());
        // SAFETY: single-threaded test, cleanup.
        unsafe { std::env::remove_var(TEST_PASSWORD_ENV) };
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_private_key_recovered_with_recovery_store() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        // SAFETY: single-threaded test, no concurrent access to this variable.
        unsafe { std::env::set_var(TEST_PASSWORD_ENV, "test_password") };
        let store = PixRecoveryStore::open(&dir.path().join("pix.redb"), "test_password")?;
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
            pool: pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, Some(store));
        let id = (HoprPseudonym::random(), NonZeroU32::new(1).unwrap());
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
        // SAFETY: single-threaded test, cleanup.
        unsafe { std::env::remove_var(TEST_PASSWORD_ENV) };
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

        let result = pool
            .withdraw_deposit(&hopr_api::chain::PixDepositSecret(rk.into()), *BOB, None)
            .await;

        assert!(matches!(result, Err(StrategyError::CriteriaNotSatisfied)));
        Ok(())
    }

    /// Regression: a `PrivateKeyRecovered` that arrives before its deposit has landed must
    /// leave the persisted key in place. Dropping it would strand the deposit permanently —
    /// the recovered key is the only means of ever moving those funds.
    ///
    /// Exhausts the sweep retry budget, so this test spends ~31s in backoff.
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
            pool: pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            // Flush immediately: this test asserts on the outcome of the sweep itself.
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, Some(store));
        let id = (HoprPseudonym::random(), NonZeroU32::new(1).unwrap());

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
            pool: Default::default(),
            pix_recovery_db_path: Some("/tmp/nonexistent/pix.redb".into()),
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
        })
        .build_non_anonymous(Arc::new(ChainNode(Arc::new(cc))));
        assert!(matches!(r, Err(StrategyError::CriteriaNotSatisfied)));
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
            pool: Default::default(),
            pix_recovery_db_path: Some("/tmp/nonexistent/pix.redb".into()),
            pix_recovery_password_env: Some(ev.to_string()),
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
        })
        .build_non_anonymous(Arc::new(ChainNode(Arc::new(cc))));
        assert!(r.is_err());
        Ok(())
    }

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
            pool: pool_cfg(StdDuration::from_secs(5), XDaiBalance::zero()),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        let bb = hopr_balance(&*cc, *BOB).await?;
        let amount1 = HoprBalance::new_base(20);
        let amount2 = HoprBalance::new_base(30);
        s.on_pix_event(PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
            id: (HoprPseudonym::random(), NonZeroU32::new(1).unwrap()),
            address: da1.into(),
            quota: 20,
        }))
        .await?;
        s.on_pix_event(PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
            id: (HoprPseudonym::random(), NonZeroU32::new(2).unwrap()),
            address: da2.into(),
            quota: 30,
        }))
        .await?;
        // Both events buffered — flush deposits.
        s.flush_deposits().await;
        assert_eq!(hopr_balance(&*cc, *BOB).await?, bb - amount1 - amount2);
        assert_eq!(hopr_balance(&*cc, da1).await?, amount1);
        assert_eq!(hopr_balance(&*cc, da2).await?, amount2);
        Ok(())
    }

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
            pool: pool_cfg(StdDuration::from_secs(60), XDaiBalance::zero()),
            pix_recovery_db_path: None,
            pix_recovery_password_env: None,
            deposit_buffer_period: StdDuration::ZERO,
            withdrawal_buffer_period: StdDuration::ZERO,
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        s.on_pix_event(PixEvent::PrivateKeyRecovered(hopr_api::node::PixPrivateKeyRecovered {
            id: (HoprPseudonym::random(), NonZeroU32::new(1).unwrap()),
            secret: hopr_api::chain::PixDepositSecret(rk1.into()),
        }))
        .await?;
        s.on_pix_event(PixEvent::PrivateKeyRecovered(hopr_api::node::PixPrivateKeyRecovered {
            id: (HoprPseudonym::random(), NonZeroU32::new(2).unwrap()),
            secret: hopr_api::chain::PixDepositSecret(rk2.into()),
        }))
        .await?;
        // Both withdrawals buffered — flush withdrawals.
        s.flush_withdrawals().await;
        assert!(hopr_balance(&*cc, ra1).await?.is_zero());
        assert!(hopr_balance(&*cc, ra2).await?.is_zero());
        assert!(hopr_balance(&*cc, *BOB).await? >= b1 + b2);
        Ok(())
    }
}
