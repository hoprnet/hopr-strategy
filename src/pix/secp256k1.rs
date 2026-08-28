//! ## Non-anonymous [`DepositPool`] implementation — secp256k1 deposit addresses
//!
//! A [`DepositPool`] that uses plain Ethereum transactions from the node's Safe
//! to fund deposit addresses.  All operations are fully visible on-chain.
//!
//! **DO NOT USE IN PRODUCTION.**
//!
//! Enabled by `strategy-pix-test`, and to be paired with `hopr-lib/pix-secp256k1` so that
//! `HoprPixSpec` produces the `Address` deposit addresses this pool can settle to. Built through
//! [`PixStrategy::build_non_anonymous`](crate::pix::strategy::PixStrategy::build_non_anonymous).

use std::{
    convert::identity,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use backon::Retryable;
use futures::{StreamExt, TryFutureExt};
use hopr_api::{
    ChainKeypair,
    chain::{ChainValues, ChainWriteAccountOperations, DepositNotification, DepositPool},
    node::{HasChainApi, PixAddressId},
    types::{
        crypto::prelude::Keypair,
        primitive::prelude::{Address, GeneralError, HoprBalance, XDaiBalance},
    },
};
use serde_with::{DisplayFromStr, serde_as};
use subtle::{Choice, ConstantTimeEq};
use validator::Validate;

use crate::{errors::StrategyError, pix::ByteDepositData};

// ---------------------------------------------------------------------------
// Module-level aliases
// ---------------------------------------------------------------------------

/// This pool's keypair — the `K` in [`DepositPool`], whose `K::Public` is the deposit address it
/// settles to.
///
/// Named separately from [`EthDepositKey`] so a consumer can assert the pool/curve invariant
/// `<HoprPixSpec as PixSpec>::DepositAddress == PoolKeypair::Public` against a stable path. The
/// `pix::curvy` module exports the same two names for its own pool, so the two
/// coexist and the choice is made by which one is imported.
pub type PoolKeypair = EthDepositKey;

/// This pool's configuration type.
///
/// Passed to
/// [`PixStrategy::build_non_anonymous`](crate::pix::strategy::PixStrategy::build_non_anonymous)
/// rather than carried in `PixStrategyConfig`: the two pools settle by different means and share
/// **no** fields by contract, so neither one's knobs are evidence that the other needs them.
/// Keeping it out of the strategy config is what stops a value meant for one pool from silently
/// reaching the other.
pub type PoolConfig = NonAnonymousDepositPoolConfig;

/// The deposit address this pool settles to — [`Address`], via [`PoolKeypair`].
///
/// Spelled as a projection rather than as `Address` directly so that the
/// [`DepositAddressOf`](crate::pix::DepositAddressOf) impl below is *derived* from the keypair
/// instead of restating it. A hand-written impl could name an address type this pool does not
/// actually settle to, which would leave the caller's witness asserting nothing; this cannot.
pub type DepositAddress = <PoolKeypair as Keypair>::Public;

/// Naming [`DepositAddress`] (i.e. `Address`) in
/// [`PixStrategy::build_non_anonymous`](crate::pix::strategy::PixStrategy::build_non_anonymous) is
/// therefore accepted, and naming any other address type is a compile error at that call site.
impl crate::pix::DepositAddressOf<PoolKeypair> for DepositAddress {}

// ---------------------------------------------------------------------------
// Deposit payload
// ---------------------------------------------------------------------------

/// Length of [`DEPOSIT_MARKER_PAYLOAD`], in bytes.
pub const DEPOSIT_MARKER_PAYLOAD_LEN: usize = 64;

/// The payload every deposit in this pool carries: `b"test"` followed by 60 zero bytes.
///
/// A deposit here is a plain Ethereum transfer, so there is no note, commitment or blinding factor
/// for the Exit to hand the Entry — nothing this pool needs to send. The payload is therefore a
/// fixed marker rather than derived data, and it exists for one reason: this is the only
/// implemented pool, so without it the PIX side-channel path (generated on the Exit, carried over
/// the wire, checked on the Entry) is code that nothing can run until an anonymous pool lands. A
/// marker that is generated, transported and verified on every deposit keeps that path exercised.
///
/// Both the marker and the padding are part of the contract: this pool accepts this exact byte
/// string and nothing else, so a peer running a different pool — or a different version of this one
/// — is caught rather than silently tolerated.
///
/// `pub` because the integration test crate builds wire-form events against it.
pub const DEPOSIT_MARKER_PAYLOAD: [u8; DEPOSIT_MARKER_PAYLOAD_LEN] = {
    let mut payload = [0u8; DEPOSIT_MARKER_PAYLOAD_LEN];
    let marker = *b"test";

    // Written a byte at a time because `copy_from_slice` is not `const`.
    let mut i = 0;
    while i < marker.len() {
        payload[i] = marker[i];
        i += 1;
    }

    payload
};

/// Rejects deposit data that is not [`DEPOSIT_MARKER_PAYLOAD`] filed under `id`.
///
/// Both halves are checked, because [`ByteDepositData`] is a pair and either half can disagree:
///
/// - A payload that is not the marker means the Entry sent deposit data this pool cannot read — the two ends disagree
///   about which pool is running, the same class of failure as a wrong curve.
/// - A payload filed under another allocation means the pool is being asked to settle against `id` using data that
///   describes a different SSA. This pool keeps no allocation-indexed state, so nothing here would actually be
///   corrupted by it — but the disagreement is real, and the id is carried in the payload precisely so that it can be
///   checked rather than assumed.
///
/// Both are reported rather than ignored, and before any funds move: swallowing either would
/// reproduce exactly the failure the `pix::curvy` docs describe, a deposit that quietly drops what
/// the peer sent. The strategy makes the same id comparison on the wire form in its
/// `NewDepositAddress` arm; this one covers every other way into the pool, including callers that
/// do not go through the strategy at all.
///
/// Compared with `==` rather than [`ConstantTimeEq`]: the expected value is a public constant, so
/// there is no secret for a timing side channel to leak, and a constant-time comparison here would
/// only suggest to a reader that there is one.
fn check_deposit_payload(id: &PixAddressId, data: &ByteDepositData) -> Result<(), StrategyError> {
    if data.id() != id {
        tracing::error!(
            pix_id = ?id,
            deposit_data_id = ?data.id(),
            "deposit data belongs to a different allocation than the deposit it was handed for"
        );

        return Err(StrategyError::GeneralError(GeneralError::InvalidInput));
    }

    if data.payload() != DEPOSIT_MARKER_PAYLOAD {
        tracing::error!(
            pix_id = ?id,
            expected_len = DEPOSIT_MARKER_PAYLOAD_LEN,
            actual_len = data.payload().len(),
            "additional deposit data is not the form this pool reads - the Entry and this node's deposit pool \
             disagree on the payload format"
        );

        return Err(StrategyError::GeneralError(GeneralError::InvalidInput));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Pool key
// ---------------------------------------------------------------------------

/// A [`ChainKeypair`] presented with its Ethereum address as the public part.
///
/// [`DepositPool`] is generic over the keypair and takes `K::Public` as the deposit address, while
/// the PIX event delivers a `PixDepositAddress` whose `Eth` variant holds an [`Address`].
/// `ChainKeypair::Public` is a `PublicKey`, and an `Address` is a *hash* of one — there is no way
/// back. A pool parameterised on `ChainKeypair` directly could therefore never be handed a
/// destination derived from an event, which is the only place destinations come from.
///
/// An address is also exactly what a plain `HoprToken.transfer` needs, so it is the honest public
/// part for a non-anonymous deposit key rather than a workaround. Implementing the foreign
/// [`Keypair`] trait is allowed because the newtype is local.
///
/// The address is stored rather than derived on demand because [`Keypair::public`] returns a
/// reference.
#[derive(Clone)]
pub struct EthDepositKey(ChainKeypair, Address);

impl EthDepositKey {
    /// The underlying chain keypair, which is what actually signs a transfer.
    pub fn chain_key(&self) -> &ChainKeypair {
        &self.0
    }
}

impl From<ChainKeypair> for EthDepositKey {
    fn from(value: ChainKeypair) -> Self {
        let address = value.public().to_address();
        Self(value, address)
    }
}

impl ConstantTimeEq for EthDepositKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl Keypair for EthDepositKey {
    type Public = Address;
    type SecretLen = hopr_api::types::primitive::typenum::U32;

    fn random() -> Self {
        ChainKeypair::random().into()
    }

    fn from_secret(bytes: &[u8]) -> hopr_api::types::crypto::errors::Result<Self> {
        Ok(ChainKeypair::from_secret(bytes)?.into())
    }

    fn secret(&self) -> &hopr_api::types::crypto::utils::SecretValue<Self::SecretLen> {
        self.0.secret()
    }

    fn public(&self) -> &Self::Public {
        &self.1
    }
}

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

fn validate_min_1sec(duration: &Duration) -> Result<(), validator::ValidationError> {
    if duration.as_secs() < 1 {
        return Err(validator::ValidationError::new("must be at least 1 second"));
    }
    Ok(())
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
/// use hopr_strategy::pix::secp256k1::NonAnonymousDepositPoolConfig;
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
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, smart_default::SmartDefault, Validate)]
#[serde(deny_unknown_fields)]
pub struct NonAnonymousDepositPoolConfig {
    /// How long to keep polling a stealth address for the expected deposit before
    /// giving up.  Default: 60 seconds.
    #[default(default_max_deposit_tracking_time())]
    #[serde(with = "humantime_serde", default = "default_max_deposit_tracking_time")]
    #[validate(custom(function = "validate_min_1sec"))]
    pub max_deposit_tracking_time: Duration,

    /// Amount of xDai to send from the Safe to a recovered stealth address that
    /// has run out of gas for the withdrawal sweep.  Default: 0.01 xDai.
    #[default(default_gas_xdai())]
    #[serde_as(as = "DisplayFromStr")]
    #[serde(default = "default_gas_xdai")]
    pub gas_xdai_per_sweep: XDaiBalance,

    /// Attempts *in addition to* the first for a deposit transfer.  Default: 3.
    ///
    /// Retrying is safe because [`DepositPool::deposit_funds_to`] re-reads the
    /// destination balance before each transfer.
    #[default(default_max_deposit_retries())]
    #[serde(default = "default_max_deposit_retries")]
    #[validate(range(min = 1))]
    pub max_deposit_retries: usize,

    /// Attempts *in addition to* the first for a withdrawal sweep.  Default: 5.
    ///
    /// The budget is deliberately larger than [`Self::max_deposit_retries`]: a sweep
    /// of an address whose deposit has not landed yet fails, and each retry is another
    /// chance for the deposit to arrive.
    #[default(default_max_sweep_retries())]
    #[serde(default = "default_max_sweep_retries")]
    #[validate(range(min = 1))]
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
/// use hopr_api::{
///     chain::DepositPool,
///     node::{HasChainApi, PixAddressId},
///     types::primitive::prelude::{Address, HoprBalance},
/// };
/// use hopr_strategy::pix::secp256k1::{NonAnonymousDepositPool, NonAnonymousDepositPoolConfig};
///
/// // `dst` is an `Address` — the pool settles to `EthDepositKey::Public`, not to the
/// // curve-agnostic `PixDepositAddress` the events carry. `id` names the allocation the
/// // deposit belongs to; it comes from the `PixEvent` that asked for the deposit.
/// async fn deposit<N>(node: Arc<N>, id: PixAddressId, dst: Address) -> anyhow::Result<()>
/// where
///     N: HasChainApi + Send + Sync + 'static,
/// {
///     let pool = NonAnonymousDepositPool::new(node, NonAnonymousDepositPoolConfig::default());
///
///     // The payload is the pool's own to make, so it is asked for rather than assembled here.
///     // This pool carries no side-channel data, so what comes back is empty but for `id`.
///     let deposit_data = pool.generate_deposit_data(&id).await?;
///
///     // The pool owns the retries; a single call is best effort by itself.
///     pool.deposit_funds_to(&id, &dst, HoprBalance::new_base(20), deposit_data)
///         .await?;
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
    /// use hopr_strategy::pix::secp256k1::{NonAnonymousDepositPool, NonAnonymousDepositPoolConfig};
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
impl<N> DepositPool<EthDepositKey> for NonAnonymousDepositPool<N>
where
    N: HasChainApi + Send + Sync + 'static,
{
    type Error = StrategyError;
    /// [`ByteDepositData`] carrying [`DEPOSIT_MARKER_PAYLOAD`], filed under the allocation id.
    ///
    /// A deposit address in this pool is an ordinary Ethereum account and a deposit is a plain
    /// transfer, so there is nothing this pool genuinely needs to send alongside one. What it sends
    /// instead is a fixed marker, so that the side-channel path is exercised rather than dormant —
    /// see [`DEPOSIT_MARKER_PAYLOAD`]. See [`ByteDepositData`] for why this is not `()`, and why it
    /// carries the allocation id as well as the bytes.
    ///
    /// This is the pool `ByteDepositData` is written for, and between them they are the worked
    /// example of what a `PoolDepositData` has to do — not a pattern to copy into a production
    /// pool. A pool that carries something real should define a type of its own that names it; one
    /// that carries nothing at all can use an empty `ByteDepositData` and stop there.
    type PoolDepositData = ByteDepositData;
    type Receipt = ();

    /// Always [`DEPOSIT_MARKER_PAYLOAD`], filed under `id`.
    ///
    /// Infallible in practice: there is nothing to derive, commit to or prove, so the payload is
    /// the same constant for every allocation and only the id it is filed under differs.
    async fn generate_deposit_data(&self, id: &PixAddressId) -> Result<Self::PoolDepositData, Self::Error> {
        Ok(ByteDepositData::new(*id, DEPOSIT_MARKER_PAYLOAD))
    }

    /// Deposit funds from the node's Safe to a deposit address, retrying up to
    /// [`NonAnonymousDepositPoolConfig::max_deposit_retries`] times.
    ///
    /// What makes the retry safe is that every attempt re-reads the destination balance and
    /// reports success without sending anything if it already holds `amount`; a submitted
    /// transfer whose confirmation was lost is therefore not sent twice. The guarantee is
    /// balance-based rather than transaction-based, so a third party funding the same
    /// address also satisfies the check.
    ///
    /// `id` does not select anything to settle against — the destination address is what identifies
    /// the deposit on-chain, and this pool keeps no allocation-indexed state of its own. Beyond
    /// logging it is used only to check `additional_data` against.
    ///
    /// `additional_data` must carry [`DEPOSIT_MARKER_PAYLOAD`] and be filed under `id`. It is
    /// checked *before* the first attempt rather than inside the retry closure: deposit data the
    /// pool cannot accept is not a transient failure, and spending the retry budget on it would
    /// only delay the diagnostic.
    async fn deposit_funds_to(
        &self,
        id: &PixAddressId,
        dst: &Address,
        amount: HoprBalance,
        additional_data: Self::PoolDepositData,
    ) -> Result<Self::Receipt, Self::Error> {
        check_deposit_payload(id, &additional_data)?;

        let dest_addr = *dst;
        let node = &self.node;
        let id = *id;

        (move || deposit_once(Arc::clone(node), dest_addr, amount))
            .retry(retry_policy(self.cfg.max_deposit_retries))
            .sleep(backon::FuturesTimerSleeper)
            .notify(move |error, dur| {
                tracing::warn!(%error, ?id, %dest_addr, ?dur, "deposit failed, retrying in");
            })
            .await
    }

    /// Returns a future that resolves once `min_amount` has been deposited to `dst`, or with an
    /// error once [`NonAnonymousDepositPoolConfig::max_deposit_tracking_time`] elapses.
    ///
    /// The deadline lives here rather than with the caller because the returned future now has a
    /// failure channel to report it through. It previously did not, so the bound had to be
    /// imposed from outside — which meant the caller reached into this pool's own config to find
    /// out what the bound should be.
    fn notify_deposit(
        &self,
        id: PixAddressId,
        dst: Address,
        min_amount: HoprBalance,
    ) -> Result<DepositNotification<'static, Address, Self::Error>, Self::Error> {
        let deposit_addr = dst;

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
                return Ok((id, dst, balance));
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

            // The stream itself never terminates, so this is the only thing that ends the wait
            // other than the deposit landing.
            match futures_time::future::FutureExt::timeout(
                stream.next(),
                futures_time::time::Duration::from(max_tracking),
            )
            .await
            {
                Ok(Some(balance)) => Ok((id, dst, balance)),
                Ok(None) => Err(StrategyError::other(anyhow::anyhow!(
                    "deposit balance stream ended unexpectedly"
                ))),
                Err(_) => {
                    tracing::warn!(?id, %address, %target, ?max_tracking, "gave up waiting for the deposit");
                    Err(StrategyError::other(anyhow::anyhow!(
                        "deposit to {address} did not reach {target} within {max_tracking:?}"
                    )))
                }
            }
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
    /// The keypair arrives typed, so there is no secret to reconstruct and no way to be handed
    /// one belonging to a different scheme.
    async fn withdraw_deposit(
        &self,
        id: &PixAddressId,
        key: &EthDepositKey,
        dst: Address,
        _amount: Option<HoprBalance>,
    ) -> Result<Self::Receipt, Self::Error> {
        let (node, cfg, chain_key) = (&self.node, &self.cfg, key.chain_key());
        let id = *id;

        (move || sweep_single(Arc::clone(node), cfg, chain_key, dst))
            .retry(retry_policy(cfg.max_sweep_retries))
            .sleep(backon::FuturesTimerSleeper)
            .notify(move |error, dur| {
                tracing::warn!(%error, ?id, %dst, ?dur, "sweep failed, retrying in");
            })
            .await
            .map(|_| ())
    }

    /// Move a deposit to another address inside the pool.
    ///
    /// For a non-anonymous pool "inside the pool" is not a meaningful distinction — every address
    /// is an ordinary Ethereum account and every movement is a plain transfer — so this is the
    /// same operation as [`withdraw_deposit`](Self::withdraw_deposit) with a different
    /// destination, and it shares the sweep's retry budget and gas top-up for that reason.
    ///
    /// An anonymous pool is where the two diverge: there a transfer can stay within the pool's
    /// anonymity set while a withdrawal leaves it.
    ///
    /// `src_id` identifies the allocation whose key is being spent, which is what the underlying
    /// sweep acts on. `dst_id` names an allocation on the receiving side, a notion this pool does
    /// not have — the destination is just another Ethereum account, and nothing here is filed per
    /// allocation — so it is used only to check `additional_dst_data` against, and to attribute it
    /// when that check fails.
    ///
    /// `additional_dst_data` is checked exactly as in
    /// [`deposit_funds_to`](Self::deposit_funds_to), and for the same reason: every payload this
    /// pool is handed is one it has to be able to accept, and a transfer that moves funds while
    /// dropping deposit data it disagreed with is the silent failure the check exists to prevent.
    /// This is the only guard on `dst_id`: unlike a deposit, a transfer has no arm in the strategy
    /// that compares the ids on the wire form first.
    async fn pool_transfer(
        &self,
        src_id: &PixAddressId,
        key: &EthDepositKey,
        dst_id: &PixAddressId,
        dst: Address,
        additional_dst_data: Self::PoolDepositData,
        amount: Option<HoprBalance>,
    ) -> Result<Self::Receipt, Self::Error> {
        check_deposit_payload(dst_id, &additional_dst_data)?;

        self.withdraw_deposit(src_id, key, dst, amount).await
    }
}
