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

use futures::{SinkExt, StreamExt};
use hopr_api::{
    chain::DepositPool,
    node::{ActionableEventDiscriminant, ActionableEventSource, HasChainApi, PixEvent},
    types::primitive::prelude::*,
};
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::{
    errors::{Result, StrategyError},
    pix::{non_anonymous_pool::NonAnonymousDepositPool, recovery_store::PixRecoveryStore},
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

fn default_price_per_byte() -> HoprBalance {
    HoprBalance::new_base(1)
}

fn default_max_ssa_allocation() -> HoprBalance {
    HoprBalance::new_base(100)
}

/// Configuration for [`PixStrategy`].
#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
pub struct PixStrategyConfig {
    /// wxHOPR paid per byte of SSA quota.
    #[serde(default = "default_price_per_byte")]
    pub price_per_byte: HoprBalance,
    /// Maximum wxHOPR the strategy will send to a single deposit address.
    #[serde(default = "default_max_ssa_allocation")]
    pub max_ssa_allocation: HoprBalance,
    /// Configuration for the default non-anonymous deposit pool.
    #[serde(default)]
    pub pool: crate::pix::non_anonymous_pool::NonAnonymousDepositPoolConfig,
    /// If set, recovered private keys are persisted to redb at this path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pix_recovery_db_path: Option<std::path::PathBuf>,
    /// Environment variable for the recovery store encryption password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pix_recovery_password_env: Option<String>,
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
    processed_deposits: Cache<hopr_api::node::PixAddressId, ()>,
    in_flight_sweeps: Cache<hopr_api::node::PixAddressId, ()>,
    in_flight_destinations: Cache<Address, ()>,
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
        }
    }
}

impl<D: DepositPool, N: ActionableEventSource + Send + Sync + 'static> PixStrategyInner<D, N>
where
    D::Error: Into<StrategyError>,
{
    /// Handle a single PIX event.
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

                let result = self
                    .pool
                    .deposit_funds_to(new_deposit_address.address, target_deposit)
                    .await
                    .map_err(Into::into);

                if let Err(error) = result {
                    self.in_flight_destinations.invalidate(&dest_addr);
                    #[cfg(all(feature = "telemetry", not(test)))]
                    METRIC_PIX_DEPOSITS_FAILED.increment();
                    return Err(error);
                }

                self.processed_deposits.insert(new_deposit_address.id, ());
                self.in_flight_destinations.invalidate(&dest_addr);
                tracing::info!(%target_deposit, ?new_deposit_address, "deposit successful");
                #[cfg(all(feature = "telemetry", not(test)))]
                METRIC_PIX_DEPOSITS.increment();
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
                        Ok((_, balance)) => {
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

                match self
                    .pool
                    .withdraw_deposit(&private_key_recovered.secret, self.safe_address, None)
                    .await
                    .map_err(Into::into)
                {
                    Ok(_) => {
                        self.in_flight_sweeps.invalidate(&private_key_recovered.id);
                        if let Some(ref store) = self.recovery_store {
                            let _ = store.remove(&private_key_recovered.id);
                        }
                        tracing::info!(?private_key_recovered.id, "deposit withdrawn");
                        #[cfg(all(feature = "telemetry", not(test)))]
                        METRIC_PIX_SWEEPS.increment();
                    }
                    Err(error) => {
                        tracing::error!(%error, ?private_key_recovered.id, "sweep failed after max retries");
                        self.in_flight_sweeps.invalidate(&private_key_recovered.id);
                        return Err(error);
                    }
                }
            }
        }

        Ok(())
    }

    /// Replay recovery entries whose on-chain balance is still non-zero.
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

            match self
                .pool
                .withdraw_deposit(&secret, self.safe_address, None)
                .await
                .map_err(Into::into)
            {
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

        while let Some(event) = event_stream.next().await {
            if let Err(error) = self.on_pix_event(event).await {
                tracing::error!(%error, "pix event failed");
            }
        }

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
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        let bb: HoprBalance = hopr_balance(&*cc, *BOB).await?;
        s.on_pix_event(PixEvent::NewDepositAddress(hopr_api::node::PixNewDepositAddress {
            id: (HoprPseudonym::random(), NonZeroU32::new(1).unwrap()),
            address: da.into(),
            quota: 20,
        }))
        .await?;
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
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        let id = (HoprPseudonym::random(), NonZeroU32::new(1).unwrap());
        // Attempt sweep with an invalid secret — should fail and release the guard.
        assert!(
            s.on_pix_event(PixEvent::PrivateKeyRecovered(hopr_api::node::PixPrivateKeyRecovered {
                id,
                secret: hopr_api::node::PixDepositSecret(
                    hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").into()
                ),
            }))
            .await
            .is_err()
        );
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
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, None);
        s.on_pix_event(PixEvent::PrivateKeyRecovered(hopr_api::node::PixPrivateKeyRecovered {
            id: (HoprPseudonym::random(), NonZeroU32::new(1).unwrap()),
            secret: hopr_api::node::PixDepositSecret(rk.into()),
        }))
        .await?;
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
        assert_eq!(hopr_balance(&*cc, *BOB).await?, bb - HoprBalance::new_base(20));
        s.on_pix_event(mk(id)).await?;
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
        };
        let mut s = PixStrategyInner::new(pool, node, cfg, *BOB, Some(store));
        let id = (HoprPseudonym::random(), NonZeroU32::new(1).unwrap());
        s.recovery_store
            .as_ref()
            .unwrap()
            .insert(&id, &hopr_api::node::PixDepositSecret(rk.into()))?;
        s.on_pix_event(PixEvent::PrivateKeyRecovered(hopr_api::node::PixPrivateKeyRecovered {
            id,
            secret: hopr_api::node::PixDepositSecret(rk.into()),
        }))
        .await?;
        assert!(!s.recovery_store.as_ref().unwrap().contains(&id)?);
        assert!(hopr_balance(&*cc, ra).await?.is_zero());
        // SAFETY: single-threaded test, cleanup.
        unsafe { std::env::remove_var(TEST_PASSWORD_ENV) };
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
        })
        .build_non_anonymous(Arc::new(ChainNode(Arc::new(cc))));
        assert!(r.is_err());
        Ok(())
    }
}
