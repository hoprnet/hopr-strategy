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
    chain::{ChainValues, ChainWriteAccountOperations, DepositPool, PixDepositAddress, PixDepositSecret},
    node::HasChainApi,
    types::{
        crypto::prelude::Keypair,
        primitive::prelude::{Address, HoprBalance, XDaiBalance},
    },
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

fn default_max_deposit_retries() -> usize {
    3
}

fn default_max_sweep_retries() -> usize {
    5
}

/// Configuration for [`NonAnonymousDepositPool`].
///
/// Every field names its own default through a function, so that
/// [`Default`] and a config file that omits the field agree. A bare
/// `#[serde(default)]` would fall back to the *field type's* `Default`
/// (zero) rather than to the documented value.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
///
/// use hopr_strategy::pix::non_anonymous_pool::NonAnonymousDepositPoolConfig;
///
/// // Override one budget and inherit the documented defaults for the rest.
/// let cfg = NonAnonymousDepositPoolConfig {
///     max_sweep_retries: 8,
///     ..Default::default()
/// };
///
/// assert_eq!(cfg.max_sweep_retries, 8);
/// assert_eq!(cfg.max_deposit_retries, 3);
/// assert_eq!(cfg.max_deposit_tracking_time, Duration::from_secs(60));
/// assert_eq!(cfg.gas_xdai_per_sweep, "0.01 xdai".parse().unwrap());
/// ```
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, smart_default::SmartDefault)]
pub struct NonAnonymousDepositPoolConfig {
    /// How long to keep polling a stealth address for the expected deposit before
    /// giving up.  Default: 60 seconds.
    #[default(default_max_deposit_tracking_time())]
    #[serde(with = "humantime_serde", default = "default_max_deposit_tracking_time")]
    pub max_deposit_tracking_time: Duration,

    /// Amount of xDai to send from the Safe to a recovered stealth address that
    /// has run out of gas for the withdrawal sweep.  Default: 0.01 xDai.
    #[default(default_gas_xdai())]
    #[serde(default = "default_gas_xdai")]
    pub gas_xdai_per_sweep: XDaiBalance,

    /// Attempts *in addition to* the first for a deposit transfer.  Default: 3.
    ///
    /// Retrying is safe because [`DepositPool::deposit_funds_to`] re-reads the
    /// destination balance before each transfer.
    #[default(default_max_deposit_retries())]
    #[serde(default = "default_max_deposit_retries")]
    pub max_deposit_retries: usize,

    /// Attempts *in addition to* the first for a withdrawal sweep.  Default: 5.
    ///
    /// The budget is deliberately larger than [`Self::max_deposit_retries`]: a sweep
    /// of an address whose deposit has not landed yet fails, and each retry is another
    /// chance for the deposit to arrive.
    #[default(default_max_sweep_retries())]
    #[serde(default = "default_max_sweep_retries")]
    pub max_sweep_retries: usize,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

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
///
/// # Examples
///
/// ```no_run
/// use std::sync::Arc;
///
/// use hopr_api::{chain::DepositPool, node::HasChainApi, types::primitive::prelude::HoprBalance};
/// use hopr_strategy::pix::non_anonymous_pool::{NonAnonymousDepositPool, NonAnonymousDepositPoolConfig};
///
/// async fn deposit<N>(node: Arc<N>, dst: hopr_api::chain::PixDepositAddress) -> anyhow::Result<()>
/// where
///     N: HasChainApi + Send + Sync + 'static,
/// {
///     let pool = NonAnonymousDepositPool::new(node, NonAnonymousDepositPoolConfig::default());
///
///     // The pool owns the retries; a single call is best effort by itself.
///     pool.deposit_funds_to(dst, HoprBalance::new_base(20)).await?;
///     Ok(())
/// }
/// ```
pub struct NonAnonymousDepositPool<N: HasChainApi> {
    node: Arc<N>,
    cfg: NonAnonymousDepositPoolConfig,
    active_deposit_trackers: Arc<AtomicUsize>,
}

impl<N: HasChainApi> NonAnonymousDepositPool<N> {
    /// Creates a pool that funds deposit addresses from `node`'s Safe.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::sync::Arc;
    ///
    /// use hopr_api::node::HasChainApi;
    /// use hopr_strategy::pix::non_anonymous_pool::{NonAnonymousDepositPool, NonAnonymousDepositPoolConfig};
    ///
    /// fn build<N: HasChainApi>(node: Arc<N>) -> NonAnonymousDepositPool<N> {
    ///     NonAnonymousDepositPool::new(node, NonAnonymousDepositPoolConfig::default())
    /// }
    /// ```
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

/// Backoff shared by every retried pool operation.
///
/// Jitter matters here: without it, a batch whose items all fail against the same
/// unhealthy RPC endpoint re-fires in lockstep on every attempt.
fn retry_policy(max_times: usize) -> backon::ExponentialBuilder {
    backon::ExponentialBuilder::default()
        .with_max_times(max_times)
        .with_jitter()
}

/// A single deposit attempt.  Called inside a retry loop (takes `Arc` to avoid borrow issues).
///
/// The transfer is not idempotent, so the destination balance is re-read before every
/// attempt: if a previous attempt was submitted but its confirmation was lost, re-sending
/// would deposit `amount` a second time and the Safe would lose the surplus.
///
/// A failed balance read is propagated instead of being ignored — a retry after an
/// unreadable balance is exactly the case this guard exists for.
async fn deposit_once(
    node: Arc<impl HasChainApi>,
    dest_addr: Address,
    amount: HoprBalance,
) -> Result<(), StrategyError> {
    let current: HoprBalance = node
        .chain_api()
        .balance(dest_addr)
        .await
        .map_err(StrategyError::other)?;
    if current >= amount {
        tracing::debug!(
            %dest_addr, %current, %amount,
            "deposit address is already funded, not sending another transfer"
        );
        return Ok(());
    }

    node.chain_api()
        .withdraw(amount, &dest_addr)
        .and_then(identity)
        .await
        .map_err(StrategyError::other)?;

    Ok(())
}

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
///
/// An empty address is reported as [`StrategyError::CriteriaNotSatisfied`], **not** as a
/// zero-value success. A recovered key whose deposit has not landed yet must stay
/// pending: reporting success would let the caller drop the key (and with it the only
/// means of ever moving those funds) while the deposit is still in flight.
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
        tracing::warn!(
            %recovered_address,
            "nothing to sweep: deposit address is empty, the deposit may not have landed yet"
        );
        return Err(StrategyError::CriteriaNotSatisfied);
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

    /// Deposit funds from the node's Safe to a deposit address, retrying up to
    /// [`NonAnonymousDepositPoolConfig::max_deposit_retries`] times.
    ///
    /// What makes the retry safe is that every attempt re-reads the destination balance and
    /// reports success without sending anything if it already holds `amount`; a submitted
    /// transfer whose confirmation was lost is therefore not sent twice. The guarantee is
    /// balance-based rather than transaction-based, so a third party funding the same
    /// address also satisfies the check.
    ///
    /// Converting `dst` is deterministic, so it happens once, outside the retry loop:
    /// an address that cannot be parsed will not parse on the next attempt either.
    async fn deposit_funds_to(
        &self,
        dst: PixDepositAddress,
        amount: HoprBalance,
    ) -> Result<Self::Receipt, Self::Error> {
        let dest_addr: Address = dst.try_into()?;
        let node = &self.node;

        (move || deposit_once(Arc::clone(node), dest_addr, amount))
            .retry(retry_policy(self.cfg.max_deposit_retries))
            .sleep(backon::FuturesTimerSleeper)
            .notify(|error, dur| {
                tracing::warn!(%error, %dest_addr, ?dur, "deposit failed, retrying in");
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

    /// Withdraw a deposit (or sweep the recovered address), retrying up to
    /// [`NonAnonymousDepositPoolConfig::max_sweep_retries`] times.
    ///
    /// An address that holds nothing fails with [`StrategyError::CriteriaNotSatisfied`], so a
    /// key recovered before its deposit landed is retried rather than discarded — and each
    /// retry is another chance for the deposit to arrive. Once the budget is exhausted the
    /// error is returned so the caller can keep the key for a later attempt.
    ///
    /// Reconstructing the keypair is deterministic, so it happens once, outside the retry
    /// loop: a secret that is not a valid scalar will never become one.
    async fn withdraw_deposit(
        &self,
        key: &PixDepositSecret,
        dst: Address,
        _amount: Option<HoprBalance>,
    ) -> Result<Self::Receipt, Self::Error> {
        let chain_key = ChainKeypair::from_secret(key.0.as_ref()).map_err(StrategyError::other)?;
        let (node, cfg, chain_key) = (&self.node, &self.cfg, &chain_key);

        (move || sweep_single(Arc::clone(node), cfg, chain_key, dst))
            .retry(retry_policy(cfg.max_sweep_retries))
            .sleep(backon::FuturesTimerSleeper)
            .notify(|error, dur| {
                tracing::warn!(%error, %dst, ?dur, "sweep failed, retrying in");
            })
            .await
            .map(|_| ())
    }
}
