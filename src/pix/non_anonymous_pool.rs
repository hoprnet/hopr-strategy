//! ## Non-anonymous [`DepositPool`] implementation
//!
//! A [`DepositPool`] that uses plain Ethereum transactions from the node's Safe
//! to fund deposit addresses.  All operations are fully visible on-chain.
//!
//! **DO NOT USE IN PRODUCTION.**

use std::{
    convert::identity,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use backon::Retryable;
use futures::{StreamExt, TryFutureExt, future::BoxFuture};
use hopr_api::{
    ChainKeypair,
    chain::{ChainValues, ChainWriteAccountOperations, DepositPool},
    node::{HasChainApi, PixDepositAddress, PixDepositSecret},
    types::{crypto::prelude::Keypair, primitive::prelude::*},
};

use crate::errors::StrategyError;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

fn default_gas_xdai() -> XDaiBalance {
    "0.01 xdai".parse().expect("valid static xDai amount")
}

fn default_max_deposit_tracking_time() -> Duration {
    Duration::from_secs(60)
}

/// Configuration for [`NonAnonymousDepositPool`].
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NonAnonymousDepositPoolConfig {
    /// How long to keep polling a stealth address for the expected deposit before
    /// giving up.  Default: 60 seconds.
    #[serde(with = "humantime_serde", default = "default_max_deposit_tracking_time")]
    pub max_deposit_tracking_time: Duration,

    /// Amount of xDai to send from the Safe to a recovered stealth address that
    /// has run out of gas for the withdrawal sweep.  Default: 0.01 xDai.
    #[serde(default = "default_gas_xdai")]
    pub gas_xdai_per_sweep: XDaiBalance,
}

impl Default for NonAnonymousDepositPoolConfig {
    fn default() -> Self {
        Self {
            max_deposit_tracking_time: default_max_deposit_tracking_time(),
            gas_xdai_per_sweep: default_gas_xdai(),
        }
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Retry budget for the Entry-side deposit withdrawal.  Deliberately small: the
/// Exit gives up on the deposit after `max_deposit_wait` (60 s by default), so
/// a long backoff would outlive the session it is trying to save.
const MAX_DEPOSIT_WITHDRAW_RETRIES: usize = 3;

/// Retry budget for the Exit-side sweep of a deposit address.
const MAX_SWEEP_RETRIES: usize = 5;

/// Upper bound on concurrent deposit-tracking polling tasks, and hence on the
/// RPC polling rate this pool generates.
const MAX_CONCURRENT_DEPOSIT_TRACKERS: usize = 256;

// ---------------------------------------------------------------------------
// Deposit tracker slot — RAII rate limiter
// ---------------------------------------------------------------------------

/// RAII guard that holds one of [`MAX_CONCURRENT_DEPOSIT_TRACKERS`] slots.
/// Dropped when the tracking future completes or is cancelled.
struct DepositTrackerSlot(Arc<AtomicUsize>);

impl DepositTrackerSlot {
    fn try_acquire(counter: &Arc<AtomicUsize>) -> Option<Self> {
        counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < MAX_CONCURRENT_DEPOSIT_TRACKERS).then_some(n + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(counter)))
    }
}

impl Drop for DepositTrackerSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Pool
// ---------------------------------------------------------------------------

/// Non-anonymous deposit pool that uses plain on-chain transactions.
///
/// Every deposit and withdrawal is performed via the chain API — fully
/// transparent and visible to all.
pub struct NonAnonymousDepositPool<N: HasChainApi> {
    node: Arc<N>,
    cfg: NonAnonymousDepositPoolConfig,
    active_deposit_trackers: Arc<AtomicUsize>,
}

impl<N: HasChainApi> NonAnonymousDepositPool<N> {
    pub fn new(node: Arc<N>, cfg: NonAnonymousDepositPoolConfig) -> Self {
        Self {
            node,
            cfg,
            active_deposit_trackers: Arc::new(AtomicUsize::new(0)),
        }
    }
}

// ---------------------------------------------------------------------------
// Private helpers (free functions to avoid borrowing self across retry)
// ---------------------------------------------------------------------------

/// Ensure the recovered stealth address has enough xDai for gas.
async fn fund_sweep_gas(
    node: &impl HasChainApi,
    gas_xdai_per_sweep: XDaiBalance,
    recovered_address: Address,
) -> Result<(), StrategyError> {
    if gas_xdai_per_sweep.is_zero() {
        return Ok(());
    }

    let recovered_xdai: XDaiBalance = node
        .chain_api()
        .balance(recovered_address)
        .await
        .map_err(StrategyError::other)?;

    if recovered_xdai >= gas_xdai_per_sweep {
        return Ok(());
    }

    let deficit = gas_xdai_per_sweep - recovered_xdai;

    let safe_address = node.identity().safe_address;
    let safe_xdai: XDaiBalance = node
        .chain_api()
        .balance(safe_address)
        .await
        .map_err(StrategyError::other)?;

    if safe_xdai < deficit {
        tracing::warn!(
            safe = %safe_address,
            deficit = %deficit,
            available = %safe_xdai,
            "insufficient xDai in safe to fund sweep gas"
        );
        return Err(StrategyError::CriteriaNotSatisfied);
    }

    node.chain_api()
        .withdraw(deficit, &recovered_address)
        .and_then(identity)
        .await
        .map_err(StrategyError::other)?;

    tracing::info!(amount = %deficit, %recovered_address, "funded sweep gas from safe");

    Ok(())
}

/// Sweep the full balance from a recovered stealth address into the destination.
/// Called inside a retry closure (takes `Arc` to avoid borrow issues).
async fn sweep_single(
    node: Arc<impl HasChainApi>,
    cfg: &NonAnonymousDepositPoolConfig,
    chain_key: &ChainKeypair,
    dst: Address,
) -> Result<HoprBalance, StrategyError> {
    let recovered_address = chain_key.public().to_address();

    let balance: HoprBalance = node
        .chain_api()
        .balance(recovered_address)
        .await
        .map_err(StrategyError::other)?;

    if balance.is_zero() {
        return Ok(HoprBalance::zero());
    }

    fund_sweep_gas(&*node, cfg.gas_xdai_per_sweep, recovered_address).await?;

    node.chain_api()
        .withdraw_from_signer(chain_key, balance, &dst)
        .await
        .map_err(StrategyError::other)?
        .await
        .map_err(StrategyError::other)?;

    Ok(balance)
}

// ---------------------------------------------------------------------------
// DepositPool trait implementation
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl<N> DepositPool for NonAnonymousDepositPool<N>
where
    N: HasChainApi + Send + Sync + 'static,
{
    type Error = StrategyError;
    type Receipt = ();

    /// Deposit funds from the node's Safe to a deposit address.
    async fn deposit_funds_to(
        &self,
        dst: PixDepositAddress,
        amount: HoprBalance,
    ) -> Result<Self::Receipt, Self::Error> {
        let dest_addr: Address = dst.try_into()?;

        (|| {
            let node = Arc::clone(&self.node);
            async move {
                node.chain_api()
                    .withdraw(amount, &dest_addr)
                    .and_then(identity)
                    .await
                    .map_err(StrategyError::other)?;
                Ok(())
            }
        })
        .retry(backon::ExponentialBuilder::default().with_max_times(MAX_DEPOSIT_WITHDRAW_RETRIES))
        .sleep(backon::FuturesTimerSleeper)
        .notify(|error, dur| {
            tracing::warn!(%error, ?dur, ?dest_addr, "deposit withdrawal failed, retrying in");
        })
        .await
    }

    /// Returns a future that resolves once `min_amount` has been deposited to `dst`.
    fn notify_deposit(
        &self,
        dst: PixDepositAddress,
        min_amount: HoprBalance,
    ) -> Result<BoxFuture<'static, (PixDepositAddress, HoprBalance)>, Self::Error> {
        let deposit_addr: Address = dst.try_into()?;

        let Some(tracker_slot) = DepositTrackerSlot::try_acquire(&self.active_deposit_trackers) else {
            return Err(StrategyError::CriteriaNotSatisfied);
        };

        let node = Arc::clone(&self.node);
        let target = min_amount;
        let max_tracking = self.cfg.max_deposit_tracking_time;
        let address = deposit_addr;

        Ok(Box::pin(async move {
            let _tracker_slot = tracker_slot;

            let poll_interval = (max_tracking / 10).max(Duration::from_secs(1));

            let phase_jitter = Duration::from_millis(hopr_api::types::crypto_random::random_integer(
                0,
                Some(poll_interval.as_millis() as u64),
            ));

            let immediate = node.chain_api().balance(address).await.ok().filter(|b| *b >= target);

            if let Some(balance) = immediate {
                return (dst, balance);
            }

            futures_time::task::sleep(phase_jitter.into()).await;

            let mut stream = futures_time::stream::interval(poll_interval.into())
                .then(move |_| {
                    let node = Arc::clone(&node);
                    async move { node.chain_api().balance(address).await }
                })
                .filter_map(move |result| async move {
                    match result {
                        Ok(balance) if balance >= target => Some(balance),
                        Ok(_) => None,
                        Err(error) => {
                            tracing::error!(%error, %target, "deposit balance poll failed");
                            None
                        }
                    }
                })
                .boxed();

            let balance = stream.next().await.expect("interval stream never terminates");

            (dst, balance)
        }))
    }

    /// Withdraw a deposit (or sweep the recovered address).
    ///
    /// Retries the full sweep (balance check, gas funding, transfer) with
    /// exponential backoff, up to [`MAX_SWEEP_RETRIES`] attempts.
    async fn withdraw_deposit(
        &self,
        key: &PixDepositSecret,
        dst: Address,
        _amount: Option<HoprBalance>,
    ) -> Result<Self::Receipt, Self::Error> {
        let chain_key = ChainKeypair::from_secret(key.0.as_ref()).map_err(StrategyError::other)?;
        let node = Arc::clone(&self.node);
        let cfg = self.cfg.clone();

        (|| {
            let node = Arc::clone(&node);
            let chain_key = chain_key.clone();
            let cfg = cfg.clone();
            async move {
                sweep_single(node, &cfg, &chain_key, dst).await?;
                Ok(())
            }
        })
        .retry(backon::ExponentialBuilder::default().with_max_times(MAX_SWEEP_RETRIES))
        .sleep(backon::FuturesTimerSleeper)
        .notify(|error, dur| {
            tracing::warn!(%error, ?dur, "sweep failed, retrying in");
        })
        .await
    }
}
