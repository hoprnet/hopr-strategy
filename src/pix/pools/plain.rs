//! ## Non-anonymous [`DepositPool`] implementation — plain on-chain settlement
//!
//! A [`DepositPool`] that funds deposit addresses with plain Ethereum transactions: the node's Safe
//! supplies the wxHOPR, the node key signs and pays the gas. All operations are fully visible
//! on-chain.
//!
//! The module is named for *how* it settles rather than for the curve it settles on, matching its
//! sibling [`curvy`](super::curvy): the deposit addresses happen to be secp256k1 `Address`es, but
//! what distinguishes this pool is that every movement is an ordinary, linkable transfer.
//!
//! Three movements, three payers — which is the thing to keep straight when reading this module:
//!
//! | movement | signed by | paid by |
//! |---|---|---|
//! | wxHOPR deposit to a stealth address | node key | the **Safe** |
//! | xDai gas top-up of a stealth address | node key | the **node account** |
//! | sweep of a recovered stealth address | that address's key | the **stealth address** |
//!
//! The split follows from `SafePayloadGenerator::transfer`, which since hopr-types 4.0.1 wraps
//! every transfer in the Safe module's `execTransactionFromModule`. A deposit goes through
//! [`ChainWriteAccountOperations::withdraw`] and so spends the Safe, which is where the float
//! lives. The other two cannot use that path — a Safe holds no xDai to top up gas with, and a
//! stealth address is not a party to the node's Safe at all — so both sign directly with the key
//! that owns the funds.
//!
//! Recovered deposits are nevertheless swept *to* the Safe; see [`crate::pix::strategy`].
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
use hopr_chain_connector::{
    BlockchainConnectorConfig, HoprBlockchainBasicConnector,
    blokli_client::{BlokliClient, Url},
    create_trustful_safeless_hopr_blokli_connector,
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
/// `pix::pools::curvy` module exports the same two names for its own pool, so the two
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
/// reproduce exactly the failure the `pix::pools::curvy` docs describe, a deposit that quietly drops what
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

/// A placeholder an operator is expected to replace; nothing useful is reachable there.
///
/// It exists because [`Default`] has to produce *something*, and every other field in this config
/// names its default through a function.
fn default_blokli_url() -> Url {
    "http://localhost:8080/".parse().expect("valid static URL")
}

/// Mirrors `BlockchainConnectorConfig`'s own default rather than guessing a chain.
///
/// The pool has no idea what it is settling on, and a value chosen here would be wrong for
/// somebody. Matching the library keeps this field purely additive: a consumer that never sets it
/// gets exactly the behaviour it had before the field existed.
fn default_tx_timeout_multiplier() -> u32 {
    BlockchainConnectorConfig::default().tx_timeout_multiplier
}

fn default_gas_xdai() -> XDaiBalance {
    "0.01 xdai".parse().expect("valid static xDai amount")
}

fn default_node_xdai_reserve() -> XDaiBalance {
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
/// use hopr_strategy::pix::pools::plain::NonAnonymousDepositPoolConfig;
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
/// assert_eq!(cfg.min_node_xdai_reserve, "0.01 xdai".parse().unwrap());
/// assert!(cfg.min_safe_hopr_reserve.is_zero());
/// ```
///
/// The two floors guard **different accounts**, because a deposit and a sweep's gas are paid by
/// different ones. A deposit goes out through [`ChainWriteAccountOperations::withdraw`], which the
/// node's `SafePayloadGenerator` wraps in the Safe module, so the *Safe* pays — hence
/// [`Self::min_safe_hopr_reserve`]. A sweep's gas top-up is signed by the node's own key, so the
/// *node account* pays — hence [`Self::min_node_xdai_reserve`]. Raise either where that account is
/// funded for something other than PIX; the wxHOPR floor defaults to zero precisely because the
/// Safe's balance usually *is* the deposit float:
///
/// ```
/// use hopr_api::types::primitive::prelude::HoprBalance;
/// use hopr_strategy::pix::pools::plain::NonAnonymousDepositPoolConfig;
///
/// let cfg = NonAnonymousDepositPoolConfig {
///     // Keep enough xDai back for the node's own transactions...
///     min_node_xdai_reserve: "0.5 xdai".parse()?,
///     // ...and leave 200 wxHOPR in the Safe that PIX deposits will not draw on.
///     min_safe_hopr_reserve: HoprBalance::new_base(200),
///     ..Default::default()
/// };
///
/// assert_eq!(cfg.min_node_xdai_reserve, "0.5 xdai".parse()?);
/// assert_eq!(cfg.min_safe_hopr_reserve, HoprBalance::new_base(200));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, smart_default::SmartDefault, Validate)]
#[serde(deny_unknown_fields)]
pub struct NonAnonymousDepositPoolConfig {
    /// Blokli endpoint the pool builds its own EOA-signing connectors against.
    /// Default: `http://localhost:8080/`, a placeholder an operator must replace.
    ///
    /// Two of this pool's three movements cannot go through the node's connector, because that one
    /// signs through the Safe module — see the module docs. The pool therefore builds short-lived
    /// [`BasicPayloadGenerator`](hopr_chain_connector::BasicPayloadGenerator) connectors of its
    /// own, and this is where they connect. Contract addresses are read from the endpoint rather
    /// than configured, so nothing else is needed here.
    #[serde_as(as = "DisplayFromStr")]
    #[serde(default = "default_blokli_url")]
    #[default(default_blokli_url())]
    pub blokli_url: Url,

    /// How long the pool's own connectors wait for one of their transactions to confirm, as a
    /// multiple of the chain's block time and finality.  Default: 2, minimum 1.
    ///
    /// This is [`BlockchainConnectorConfig::tx_timeout_multiplier`] for the connectors reached
    /// through [`Self::blokli_url`], and it is here for the same reason that field is: those
    /// connectors belong to the pool, so nothing an operator sets on the *node's* connector
    /// reaches them. Without it they ran at the library default while the rest of the deployment
    /// ran at whatever its chain actually needed.
    ///
    /// Raising it is how a sweep on a slow chain is waited out rather than abandoned. Too low is
    /// the expensive direction to be wrong in: the transfer lands, the wait times out, the pool
    /// records a failure, and every retry after it finds the address already emptied and reports
    /// [`StrategyError::CriteriaNotSatisfied`]. The funds are safe; the accounting is not, and the
    /// retry budget is spent on work that already succeeded.
    #[default(default_tx_timeout_multiplier())]
    #[serde(default = "default_tx_timeout_multiplier")]
    #[validate(range(min = 1))]
    pub tx_timeout_multiplier: u32,

    /// How long to keep polling a stealth address for the expected deposit before
    /// giving up.  Default: 60 seconds.
    #[default(default_max_deposit_tracking_time())]
    #[serde(with = "humantime_serde", default = "default_max_deposit_tracking_time")]
    #[validate(custom(function = "validate_min_1sec"))]
    pub max_deposit_tracking_time: Duration,

    /// Amount of xDai to send from the node's account to a recovered stealth address
    /// that has run out of gas for the withdrawal sweep.  Default: 0.01 xDai.
    ///
    /// Zero disables the top-up entirely, which is only viable where something else
    /// keeps deposit addresses in gas.
    #[default(default_gas_xdai())]
    #[serde_as(as = "DisplayFromStr")]
    #[serde(default = "default_gas_xdai")]
    pub gas_xdai_per_sweep: XDaiBalance,

    /// xDai the node's account must still hold after paying for a sweep's gas.
    /// Default: 0.01 xDai.
    ///
    /// The top-up in [`Self::gas_xdai_per_sweep`] is paid by the node's own account —
    /// the same account that pays gas for announcements, ticket redemptions and every
    /// channel operation. Without a floor, a run of recovered addresses can spend the
    /// node down to nothing and leave it unable to transact at all; the deposits are
    /// then no more recoverable than they were before, and the rest of the node is
    /// stuck too.
    ///
    /// The node rather than the Safe, and deliberately so: a Safe holds wxHOPR and no xDai on a
    /// normal deployment, so a top-up drawn from it would be refused every time and recovered
    /// deposits would stay stranded. `fund_sweep_gas` therefore signs with the node key directly
    /// rather than going through [`ChainWriteAccountOperations::withdraw`], which would route
    /// through the Safe module.
    ///
    /// The default matches one sweep's gas budget, so the node always keeps back at
    /// least what it just handed out. Zero opts out, leaving only the plain
    /// affordability check.
    ///
    /// **Approximate, in two known ways.** It is a pre-flight check on a balance that is not
    /// held, rather than a reservation, so it can be undershot rather than strictly enforced:
    ///
    /// * Concurrent sweeps race it. `withdraw_multiple_deposits` funds gas for each key concurrently, and a recovery
    ///   replay runs alongside the event loop, so several top-ups can each observe the same pre-transfer balance and
    ///   all proceed — overshooting the floor by up to one deficit per concurrent sweep.
    /// * The native transaction fee is not counted. `required` covers the transferred deficit and this floor, but the
    ///   transfer's own gas is paid from the same account, so a balance of exactly `required` ends just below the
    ///   floor.
    ///
    /// Size it as a soft cushion rather than a hard minimum: set it comfortably above the smallest
    /// balance the node can still function at, not exactly at it.
    #[default(default_node_xdai_reserve())]
    #[serde_as(as = "DisplayFromStr")]
    #[serde(default = "default_node_xdai_reserve")]
    pub min_node_xdai_reserve: XDaiBalance,

    /// wxHOPR the **Safe** must still hold after funding a deposit.  Default: 0.
    ///
    /// The Safe rather than the node account, because that is what a deposit actually spends:
    /// `withdraw` settles through the Safe module. See `deposit_once`.
    ///
    /// Unlike [`Self::min_node_xdai_reserve`] this defaults to zero, because the Safe's wxHOPR
    /// *is* the deposit float — nothing else in this strategy spends it, so drawing it down is
    /// the intended behaviour rather than a hazard. Set it where the Safe is funded for
    /// something else too, such as channel stakes.
    ///
    /// The affordability check it participates in runs either way: a deposit the Safe cannot
    /// cover is refused with [`StrategyError::CriteriaNotSatisfied`] instead of being submitted
    /// and reverted.
    #[default(HoprBalance::zero())]
    #[serde_as(as = "DisplayFromStr")]
    #[serde(default = "HoprBalance::zero")]
    pub min_safe_hopr_reserve: HoprBalance,

    /// Attempts *in addition to* the first for a deposit transfer.  Default: 3.
    /// Zero means a single attempt with no backoff.
    ///
    /// Retrying is safe because [`DepositPool::deposit_funds_to`] re-reads the
    /// destination balance before each transfer.
    #[default(default_max_deposit_retries())]
    #[serde(default = "default_max_deposit_retries")]
    pub max_deposit_retries: usize,

    /// Attempts *in addition to* the first for a withdrawal sweep.  Default: 5.
    /// Zero means a single attempt with no backoff.
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
/// use hopr_api::{
///     ChainKeypair,
///     chain::DepositPool,
///     node::{HasChainApi, PixAddressId},
///     types::primitive::prelude::{Address, HoprBalance},
/// };
/// use hopr_strategy::pix::pools::plain::{NonAnonymousDepositPool, NonAnonymousDepositPoolConfig};
///
/// // `dst` is an `Address` — the pool settles to `EthDepositKey::Public`, not to the
/// // curve-agnostic `PixDepositAddress` the events carry. `id` names the allocation the
/// // deposit belongs to; it comes from the `PixEvent` that asked for the deposit.
/// async fn deposit<N>(node: Arc<N>, node_key: ChainKeypair, id: PixAddressId, dst: Address) -> anyhow::Result<()>
/// where
///     N: HasChainApi + Send + Sync + 'static,
/// {
///     let pool = NonAnonymousDepositPool::new(node, node_key, NonAnonymousDepositPoolConfig::default());
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
pub struct NonAnonymousDepositPool<N: HasChainApi, C = BlokliClient> {
    node: Arc<N>,
    /// The node's own key, used to sign gas top-ups directly rather than through the Safe module.
    /// See [`fund_sweep_gas`].
    node_key: ChainKeypair,
    /// Blokli client the pool's own EOA-signing connectors are built on. Defaults to one created
    /// from [`NonAnonymousDepositPoolConfig::blokli_url`]; tests substitute an in-process one.
    client: C,
    cfg: NonAnonymousDepositPoolConfig,
    active_deposit_trackers: Arc<AtomicUsize>,
}

impl<N: HasChainApi> NonAnonymousDepositPool<N> {
    /// Creates a pool that deposits from the node's Safe and signs gas top-ups with `node_key`.
    ///
    /// `node_key` must be the node's own chain key: it signs the gas top-ups, which cannot go
    /// through [`ChainWriteAccountOperations::withdraw`] because that spends the Safe. See the
    /// module docs for the three payers.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::sync::Arc;
    ///
    /// use hopr_api::{ChainKeypair, node::HasChainApi};
    /// use hopr_strategy::pix::pools::plain::{NonAnonymousDepositPool, NonAnonymousDepositPoolConfig};
    ///
    /// fn build<N: HasChainApi>(node: Arc<N>, node_key: ChainKeypair) -> NonAnonymousDepositPool<N> {
    ///     NonAnonymousDepositPool::new(node, node_key, NonAnonymousDepositPoolConfig::default())
    /// }
    /// ```
    pub fn new(node: Arc<N>, node_key: ChainKeypair, cfg: NonAnonymousDepositPoolConfig) -> Self {
        let client = hopr_chain_connector::create_blokli_client(hopr_chain_connector::HoprBlokliClientConfig::new(
            cfg.blokli_url.clone(),
        ));
        Self::with_client(node, node_key, cfg, client)
    }
}

impl<N: HasChainApi, C> NonAnonymousDepositPool<N, C> {
    /// Creates a pool against an already-built blokli client, bypassing
    /// [`NonAnonymousDepositPoolConfig::blokli_url`].
    ///
    /// The pool's own connectors are what make the gas top-up and the sweep work, so they have to
    /// be on the tested path rather than stubbed. Tests hand in the in-process
    /// `BlokliTestClient` here; production goes through [`Self::new`], and the two then run
    /// exactly the same code.
    ///
    /// `node_key` carries the same requirement as in [`Self::new`] — it must be the node's own
    /// chain key, since it is what signs the gas top-ups.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::sync::Arc;
    ///
    /// use hopr_api::{ChainKeypair, node::HasChainApi};
    /// use hopr_chain_connector::blokli_client::{BlokliQueryClient, BlokliSubscriptionClient, BlokliTransactionClient};
    /// use hopr_strategy::pix::pools::plain::{NonAnonymousDepositPool, NonAnonymousDepositPoolConfig};
    ///
    /// // `C` is the client the pool's EOA-signing connectors are built on; passing it here
    /// // bypasses `NonAnonymousDepositPoolConfig::blokli_url` entirely.
    /// fn build<N, C>(node: Arc<N>, node_key: ChainKeypair, client: C) -> NonAnonymousDepositPool<N, C>
    /// where
    ///     N: HasChainApi,
    ///     C: BlokliSubscriptionClient + BlokliQueryClient + BlokliTransactionClient + Clone + Send + Sync + 'static,
    /// {
    ///     NonAnonymousDepositPool::with_client(node, node_key, NonAnonymousDepositPoolConfig::default(), client)
    /// }
    /// ```
    pub fn with_client(node: Arc<N>, node_key: ChainKeypair, cfg: NonAnonymousDepositPoolConfig, client: C) -> Self {
        Self {
            node,
            node_key,
            client,
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

/// A connector that spends `key`'s own balance, built for one transfer and dropped after it.
///
/// The node's connector cannot do this. It carries a `SafePayloadGenerator`, whose `transfer`
/// wraps the call in the Safe module's `execTransactionFromModule` — so it always spends the Safe,
/// whoever signs. `withdraw_from_signer` does not help either: it swaps the *signature* but keeps
/// that payload, producing a module call the signer has no authority over. A
/// `BasicPayloadGenerator` emits the plain transfer this needs.
///
/// Built per call rather than cached. These are rare operations — a gas top-up and a sweep, both
/// only for recovered addresses — and a cache would have to hold a live subscription per key and
/// decide when to evict it. `withdraw` no longer requires the connector to be connected (since
/// hopr-chain-connector 0.26.0), so construction here is cheap: it is one `query_chain_info` call
/// to learn the contract addresses.
///
/// *Trustful*: the contract addresses come from the endpoint rather than from configuration, which
/// is what lets this work against a test emulator unchanged.
/// `tx_timeout_multiplier` comes from the pool's config rather than the library default: these
/// connectors are the pool's own, so the one an operator tuned for the node never reaches them,
/// and the confirmation wait has to be the chain's, not a constant. See
/// [`NonAnonymousDepositPoolConfig::tx_timeout_multiplier`].
///
/// The rest of [`BlockchainConnectorConfig`] is left at its default deliberately:
/// `connection_sync_timeout` and `sync_tolerance` both govern
/// [`connect`](hopr_chain_connector::api::HoprChainConnector::connect), which these connectors
/// never call.
async fn eoa_connector<C>(
    client: C,
    key: &ChainKeypair,
    tx_timeout_multiplier: u32,
) -> Result<HoprBlockchainBasicConnector<C>, StrategyError>
where
    C: hopr_chain_connector::blokli_client::BlokliSubscriptionClient
        + hopr_chain_connector::blokli_client::BlokliQueryClient
        + hopr_chain_connector::blokli_client::BlokliTransactionClient
        + Send
        + Sync
        + 'static,
{
    create_trustful_safeless_hopr_blokli_connector(
        key,
        BlockchainConnectorConfig {
            tx_timeout_multiplier,
            ..Default::default()
        },
        client,
    )
    .await
    .map_err(StrategyError::other)
}

/// A single deposit attempt.  Called inside a retry loop (takes `Arc` to avoid borrow issues).
///
/// The transfer is not idempotent, so the destination balance is re-read before every
/// attempt: if a previous attempt was submitted but its confirmation was lost, re-sending
/// would deposit `amount` a second time and the node would lose the surplus.
///
/// A failed balance read is propagated instead of being ignored — a retry after an
/// unreadable balance is exactly the case this guard exists for.
///
/// The payer here is the **Safe**, not the node's own account.
/// [`ChainWriteAccountOperations::withdraw`] builds its transaction with the node's payload
/// generator, and `SafePayloadGenerator::transfer` wraps every transfer — wxHOPR and xDai alike —
/// in the Safe module's `execTransactionFromModule`. The node key signs and pays the gas; the
/// tokens come out of the Safe. That is also where the wxHOPR float lives on a normal deployment,
/// so it is the right account to spend, and [`Self::min_safe_hopr_reserve`] is what guards it.
///
/// It has not always been so: in hopr-types 3.x `SafePayloadGenerator::transfer` emitted a plain,
/// node-signed transfer, and this gate correctly read the node's account. hopr-types 4.0.1 routed
/// it through the module, which moved the payer without moving the check.
///
/// The payer's balance is checked before transferring, so a deposit the Safe cannot cover is
/// refused rather than submitted and reverted — an operator then sees the reason instead of an
/// opaque transaction failure. The check is per-deposit and the balance read is not atomic with
/// the transfer, so a *batch* fanned out through
/// [`DepositPool::deposit_funds_to_multiple`] can still collectively overshoot; bounding the
/// aggregate is `PixStrategyConfig::max_spend_per_window`'s job, not this one's.
async fn deposit_once(
    node: Arc<impl HasChainApi>,
    cfg: &NonAnonymousDepositPoolConfig,
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

    // The Safe, because `withdraw` settles through the Safe module — see this function's docs.
    let payer = node.identity().safe_address;
    let payer_hopr: HoprBalance = node.chain_api().balance(payer).await.map_err(StrategyError::other)?;

    // Saturating addition, so an absurd reserve refuses the deposit rather than wrapping.
    let required = amount + cfg.min_safe_hopr_reserve;

    if payer_hopr < required {
        tracing::warn!(
            safe = %payer,
            %amount,
            reserve = %cfg.min_safe_hopr_reserve,
            available = %payer_hopr,
            "insufficient wxHOPR in the Safe to fund the deposit"
        );
        return Err(StrategyError::CriteriaNotSatisfied);
    }

    node.chain_api()
        .withdraw(amount, &dest_addr)
        .and_then(identity)
        .await
        .map_err(StrategyError::other)?;

    Ok(())
}

/// Ensure the recovered stealth address has enough xDai for gas.
///
/// The top-up is paid by the **node's own account**, not by the Safe. The pre-flight check reads
/// the balance of `node_key`'s own address rather than of `identity().node_address`, so the account
/// gated is always the account debited. `build_non_anonymous_with_client` rejects a `node_key` that
/// is not the node's, so on a correctly built pool the two are the same address anyway.
///
/// That is a constraint rather than a preference. A Safe holds wxHOPR and no xDai on a normal
/// deployment, so a top-up drawn from it would be refused every time and every recovered deposit
/// that could not already pay its own way would stay stranded. The node account is the one that
/// actually holds gas.
///
/// [`ChainWriteAccountOperations::withdraw`] cannot deliver that: since hopr-types 4.0.1,
/// `SafePayloadGenerator::transfer` wraps *both* currencies in the Safe module's
/// `execTransactionFromModule`, so it always spends the Safe. (In 3.x it emitted a plain
/// node-signed transfer, which is why this function used to be able to use it.) The transfer is
/// therefore signed by the node key directly.
///
/// [`NonAnonymousDepositPoolConfig::min_node_xdai_reserve`] is what the node keeps back, so
/// funding a sweep cannot leave it without gas for its own transactions.
async fn fund_sweep_gas<C>(
    node: &impl HasChainApi,
    client: C,
    node_key: &ChainKeypair,
    cfg: &NonAnonymousDepositPoolConfig,
    recovered_address: Address,
) -> Result<(), StrategyError>
where
    C: hopr_chain_connector::blokli_client::BlokliSubscriptionClient
        + hopr_chain_connector::blokli_client::BlokliQueryClient
        + hopr_chain_connector::blokli_client::BlokliTransactionClient
        + Send
        + Sync
        + 'static,
{
    if cfg.gas_xdai_per_sweep.is_zero() {
        return Ok(());
    }

    let recovered_xdai: XDaiBalance = node
        .chain_api()
        .balance(recovered_address)
        .await
        .map_err(StrategyError::other)?;

    if recovered_xdai >= cfg.gas_xdai_per_sweep {
        return Ok(());
    }

    let deficit = cfg.gas_xdai_per_sweep - recovered_xdai;

    // Derived from `node_key` rather than read from `identity()`. The transfer below is signed by
    // that key, so this is the account that pays *by construction* — the gate cannot end up
    // guarding one account while the spend debits another.
    let payer = node_key.public().to_address();
    let payer_xdai: XDaiBalance = node.chain_api().balance(payer).await.map_err(StrategyError::other)?;

    // `Balance` addition saturates rather than wrapping, so an absurd reserve refuses the top-up
    // instead of silently permitting it.
    //
    // A pre-flight check, not a reservation: nothing holds `payer_xdai` between the read above and
    // the transfer below, and `required` excludes the transfer's own gas. Concurrent sweeps can
    // therefore each pass this and collectively undershoot the floor. See
    // `NonAnonymousDepositPoolConfig::min_node_xdai_reserve`, which documents the floor as a soft
    // cushion for exactly these two reasons.
    let required = deficit + cfg.min_node_xdai_reserve;

    if payer_xdai < required {
        tracing::warn!(
            node = %payer,
            deficit = %deficit,
            reserve = %cfg.min_node_xdai_reserve,
            available = %payer_xdai,
            "insufficient xDai in the node account to fund sweep gas"
        );
        return Err(StrategyError::CriteriaNotSatisfied);
    }

    // Signed by the node key on its own behalf, so the xDai leaves the account the gate just
    // checked. Going through `node.chain_api().withdraw` here would spend the Safe instead.
    eoa_connector(client, node_key, cfg.tx_timeout_multiplier)
        .await?
        .withdraw(deficit, &recovered_address)
        .and_then(identity)
        .await
        .map_err(StrategyError::other)?;

    tracing::info!(amount = %deficit, %recovered_address, "funded sweep gas from the node account");

    Ok(())
}

/// Sweep the full balance from a recovered stealth address into the destination.
/// Called inside a retry closure (takes `Arc` to avoid borrow issues).
///
/// The transfer is signed by `chain_key` — the recovered address's own key — through a connector
/// built for it, so the funds move out of that address directly.
///
/// It cannot go through [`ChainWriteAccountOperations::withdraw_from_signer`], which is what this
/// used to do. That method swaps the signature but keeps the node's `SafePayloadGenerator` payload,
/// so it produces an `execTransactionFromModule` call on the node's Safe signed by a stealth EOA:
/// an address that is not a party to that Safe and cannot drive its module. On-chain it reverts,
/// and had it not, it would have moved the Safe's funds rather than the deposit. See
/// [`eoa_connector`].
///
/// An empty address is reported as [`StrategyError::CriteriaNotSatisfied`], **not** as a
/// zero-value success. A recovered key whose deposit has not landed yet must stay
/// pending: reporting success would let the caller drop the key (and with it the only
/// means of ever moving those funds) while the deposit is still in flight.
async fn sweep_single<C>(
    node: Arc<impl HasChainApi>,
    client: C,
    node_key: &ChainKeypair,
    cfg: &NonAnonymousDepositPoolConfig,
    chain_key: &ChainKeypair,
    dst: Address,
) -> Result<HoprBalance, StrategyError>
where
    C: hopr_chain_connector::blokli_client::BlokliSubscriptionClient
        + hopr_chain_connector::blokli_client::BlokliQueryClient
        + hopr_chain_connector::blokli_client::BlokliTransactionClient
        + Clone
        + Send
        + Sync
        + 'static,
{
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

    fund_sweep_gas(&*node, client.clone(), node_key, cfg, recovered_address).await?;

    eoa_connector(client, chain_key, cfg.tx_timeout_multiplier)
        .await?
        .withdraw(balance, &dst)
        .and_then(identity)
        .await
        .map_err(StrategyError::other)?;

    Ok(balance)
}

// ---------------------------------------------------------------------------
// DepositPool trait implementation
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl<N, C> DepositPool<EthDepositKey> for NonAnonymousDepositPool<N, C>
where
    N: HasChainApi + Send + Sync + 'static,
    C: hopr_chain_connector::blokli_client::BlokliSubscriptionClient
        + hopr_chain_connector::blokli_client::BlokliQueryClient
        + hopr_chain_connector::blokli_client::BlokliTransactionClient
        + Clone
        + Send
        + Sync
        + 'static,
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

    /// Deposit funds from the node's own account to a deposit address, retrying up to
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
        // `cfg` as well as `node`: `deposit_once` reads `min_safe_hopr_reserve` from it.
        let (node, cfg) = (&self.node, &self.cfg);
        let id = *id;

        (move || deposit_once(Arc::clone(node), cfg, dest_addr, amount))
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
        let (client, node_key) = (&self.client, &self.node_key);
        let id = *id;

        (move || sweep_single(Arc::clone(node), client.clone(), node_key, cfg, chain_key, dst))
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Tests for the sweep gas top-up.
///
/// The node and the Safe are given **different** addresses here, which the strategy's own tests
/// do not do — their node adapter reports `safe_address == node_address`, and that collapse is
/// what let the top-up gate read the wrong account unnoticed.
#[cfg(test)]
mod tests {
    use std::{num::NonZeroU32, sync::Arc};

    use hex_literal::hex;
    use hopr_api::{
        chain::{ChainValues, DepositPool},
        node::{NodeOnchainIdentity, PixAddressId},
        types::{
            crypto::{
                keypairs::Keypair,
                prelude::{ChainKeypair, OffchainKeypair},
            },
            internal::prelude::{AccountEntry, AccountType, HoprPseudonym},
            primitive::prelude::{Address, BytesRepresentable, HoprBalance, XDaiBalance},
        },
    };

    use super::{DEPOSIT_MARKER_PAYLOAD, EthDepositKey, NonAnonymousDepositPool, NonAnonymousDepositPoolConfig};
    use crate::{
        errors::StrategyError,
        pix::ByteDepositData,
        testing::{
            BlokliTestClient, BlokliTestStateBuilder, FullStateEmulator, PixNode, TestChainConnector,
            create_test_blokli_connector,
        },
    };

    const MODULE_ADDRESS: [u8; 20] = [1u8; 20];

    /// Named explicitly instead of letting `with_generated_accounts` derive one, so a test can
    /// stock the Safe with xDai at build time and show that the top-up ignores it.
    const SAFE_ADDRESS: [u8; 20] = [0x5au8; 20];

    /// A fresh deposit *destination* — distinct from the stealth address the sweep tests spend
    /// from, and created empty so `deposit_once` does not short-circuit on it.
    const DEST_ADDRESS: [u8; 20] = [0xdeu8; 20];

    const NODE_SECRET: [u8; 32] = hex!("492057cf93e99b31d2a85bc5e98a9c3aa0021feec52c227cc8170e8f7d047775");
    const DEPOSIT_SECRET: [u8; 32] = hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    /// An allocation id for the pool calls below.
    ///
    /// Fixed rather than random, and shared by every call: this pool keeps no allocation-indexed
    /// state and carries the id for logging only, so nothing in these tests depends on two calls
    /// having different ones.
    fn an_id() -> PixAddressId {
        PixAddressId::new(
            &HoprPseudonym::from([0x7au8; HoprPseudonym::SIZE]),
            NonZeroU32::new(1).expect("non-zero"),
        )
    }

    /// wxHOPR the Safe starts with, so a sweep's arrival is visible as a delta.
    fn safe_hopr() -> HoprBalance {
        HoprBalance::new_base(1000)
    }

    /// The deposit waiting on the stealth address in the sweep tests.
    fn deposited() -> HoprBalance {
        HoprBalance::new_base(40)
    }

    /// Retry budgets zeroed: every test asserts on a single attempt, so retrying would only add
    /// real backoff sleeps. The gas knobs keep their shipped defaults unless a test names them.
    fn cfg() -> NonAnonymousDepositPoolConfig {
        NonAnonymousDepositPoolConfig {
            max_deposit_retries: 0,
            max_sweep_retries: 0,
            ..Default::default()
        }
    }

    /// The starting balances a test cares about, named rather than positional — most tests vary
    /// one of them and inherit the rest.
    struct Balances {
        node_xdai: XDaiBalance,
        node_hopr: HoprBalance,
        safe_hopr: HoprBalance,
        safe_xdai: XDaiBalance,
        deposit_hopr: HoprBalance,
        deposit_xdai: XDaiBalance,
    }

    impl Default for Balances {
        /// The shape a real deployment has: the Safe holds the wxHOPR float and no xDai, the node
        /// holds the gas, and a stealth address holding a deposit cannot pay to move it.
        ///
        /// `node_hopr` is non-zero only so that a test drawing on the Safe can assert the node was
        /// *not* drawn on instead; nothing in the pool spends it.
        fn default() -> Self {
            Self {
                node_xdai: XDaiBalance::new_base(1),
                node_hopr: HoprBalance::new_base(1000),
                safe_hopr: safe_hopr(),
                safe_xdai: XDaiBalance::zero(),
                deposit_hopr: deposited(),
                deposit_xdai: XDaiBalance::zero(),
            }
        }
    }

    type Connector = Arc<TestChainConnector<FullStateEmulator>>;

    struct Fixture {
        cc: Connector,
        pool: NonAnonymousDepositPool<PixNode<Connector>, BlokliTestClient<FullStateEmulator>>,
        node_addr: Address,
        safe_addr: Address,
        deposit_addr: Address,
        dest_addr: Address,
    }

    impl Fixture {
        async fn hopr(&self, address: Address) -> anyhow::Result<HoprBalance> {
            ChainValues::balance(&*self.cc, address).await.map_err(Into::into)
        }

        async fn xdai(&self, address: Address) -> anyhow::Result<XDaiBalance> {
            ChainValues::balance(&*self.cc, address).await.map_err(Into::into)
        }

        /// Sweeps the deposit address into the Safe, which is what the strategy always does.
        async fn sweep(&self) -> Result<(), StrategyError> {
            let key = EthDepositKey::from_secret(&DEPOSIT_SECRET).expect("valid test secret");
            self.pool.withdraw_deposit(&an_id(), &key, self.safe_addr, None).await
        }

        /// Deposits into the fresh destination, which is what the Entry side does.
        ///
        /// The payload is the marker rather than an empty one: these tests are about the balance
        /// gates, so the deposit data has to be what the pool accepts or `check_deposit_payload`
        /// refuses first and the gate under test never runs.
        async fn deposit(&self, amount: HoprBalance) -> Result<(), StrategyError> {
            let id = an_id();
            self.pool
                .deposit_funds_to(
                    &id,
                    &self.dest_addr,
                    amount,
                    ByteDepositData::new(id, DEPOSIT_MARKER_PAYLOAD),
                )
                .await
        }
    }

    /// Builds a node whose Safe is a *different* account, with each balance that matters set
    /// independently.
    async fn fixture(balances: Balances, cfg: NonAnonymousDepositPoolConfig) -> anyhow::Result<Fixture> {
        let node_kp = ChainKeypair::from_secret(&NODE_SECRET)?;
        let node_addr = node_kp.public().to_address();
        let safe_addr: Address = SAFE_ADDRESS.into();
        let dest_addr: Address = DEST_ADDRESS.into();
        let deposit_addr = ChainKeypair::from_secret(&DEPOSIT_SECRET)?.public().to_address();

        let sim = BlokliTestStateBuilder::default()
            .with_accounts([(
                AccountEntry {
                    public_key: *OffchainKeypair::from_secret(&NODE_SECRET)?.public(),
                    chain_addr: node_addr,
                    entry_type: AccountType::NotAnnounced,
                    safe_address: Some(safe_addr),
                    key_id: 0u32.into(),
                },
                balances.safe_hopr,
                balances.node_xdai,
            )])
            // `with_accounts` puts the wxHOPR on the Safe and zeroes both of the node's balances,
            // so the node's own wxHOPR has to be credited after the fact. It also zeroes the
            // Safe's xDai, which mirrors a real deployment; a test overrides it to prove the gas
            // top-up ignores it.
            .with_balances([(node_addr, balances.node_hopr)])
            .with_balances([(safe_addr, balances.safe_xdai)])
            .with_balances([(deposit_addr, balances.deposit_hopr)])
            .with_balances([(deposit_addr, balances.deposit_xdai)])
            // Both entries must exist or the balance query fails outright, which would look like
            // a refusal rather than the absence of one.
            .with_balances([(dest_addr, HoprBalance::zero())])
            .with_balances([(dest_addr, XDaiBalance::zero())])
            .build_dynamic_client(MODULE_ADDRESS.into());

        // The same in-process chain, reached two ways: `cc` is the node's Safe-signing connector,
        // and the clone goes to the pool so its own EOA-signing connectors settle against exactly
        // the same state. Cloning shares the state rather than copying it.
        let sim_for_pool = sim.clone();
        let cc = Arc::new(create_test_blokli_connector(&node_kp, sim, MODULE_ADDRESS.into()).await?);
        let node = Arc::new(PixNode::new(
            Arc::clone(&cc),
            NodeOnchainIdentity {
                node_address: node_addr,
                safe_address: safe_addr,
                module_address: MODULE_ADDRESS.into(),
            },
        ));

        Ok(Fixture {
            pool: NonAnonymousDepositPool::with_client(node, node_kp.clone(), cfg, sim_for_pool),
            cc,
            node_addr,
            safe_addr,
            deposit_addr,
            dest_addr,
        })
    }

    /// The regression test for the defect this pool was rewritten to fix.
    ///
    /// The sweep used to go through `withdraw_from_signer`, which keeps the node's
    /// `SafePayloadGenerator` payload and only swaps the signature — producing an
    /// `execTransactionFromModule` call on the node's Safe signed by a stealth EOA that has no
    /// authority over it. On-chain that reverts; had it not, it would have moved the Safe's funds
    /// instead of the deposit.
    ///
    /// Three things pinned together, because the wrong one passing is how this hid before:
    /// the deposit address is emptied, the Safe receives exactly that amount, and the Safe is not
    /// *also* debited along the way. The last is what a module-routed sweep would violate.
    ///
    /// The gas top-up is disabled so the only movement asserted here is the sweep itself.
    #[test_log::test(tokio::test)]
    async fn sweep_debits_the_deposit_address_and_credits_the_safe() -> anyhow::Result<()> {
        let f = fixture(
            Balances {
                // The top-up is off, so the address has to be able to sign for itself.
                deposit_xdai: XDaiBalance::new_base(1),
                ..Default::default()
            },
            NonAnonymousDepositPoolConfig {
                gas_xdai_per_sweep: XDaiBalance::zero(),
                ..cfg()
            },
        )
        .await?;

        let safe_before = f.hopr(f.safe_addr).await?;

        f.sweep().await?;

        assert!(
            f.hopr(f.deposit_addr).await?.is_zero(),
            "the deposit address must be swept dry"
        );
        assert_eq!(
            f.hopr(f.safe_addr).await?,
            safe_before + deposited(),
            "the Safe must receive exactly the deposit, having funded none of it"
        );
        Ok(())
    }

    /// The regression test for the gate/payer mismatch.
    ///
    /// A Safe with no xDai is the normal case, not a corner one — it holds wxHOPR and the node
    /// holds the gas. Gating the top-up on the Safe therefore refused *every* sweep of an
    /// address that could not already pay its own way.
    #[test_log::test(tokio::test)]
    async fn sweep_tops_up_gas_from_the_node_when_the_safe_holds_no_xdai() -> anyhow::Result<()> {
        let f = fixture(Balances::default(), cfg()).await?;

        f.sweep().await?;

        assert!(
            f.hopr(f.deposit_addr).await?.is_zero(),
            "the deposit address must be swept dry"
        );
        assert_eq!(
            f.hopr(f.safe_addr).await?,
            safe_hopr() + deposited(),
            "the deposit must land in the Safe"
        );
        assert!(
            !f.xdai(f.deposit_addr).await?.is_zero(),
            "the deposit address must have been topped up with gas to sign the sweep"
        );
        Ok(())
    }

    /// The Safe's xDai is not the pool's to spend, so having plenty of it must not let a top-up
    /// through. Without this the fix could be reverted by symmetry and still pass the test above.
    #[test_log::test(tokio::test)]
    async fn sweep_gas_gate_ignores_a_flush_safe_when_the_node_is_empty() -> anyhow::Result<()> {
        let f = fixture(
            Balances {
                node_xdai: XDaiBalance::zero(),
                safe_xdai: XDaiBalance::new_base(100),
                ..Default::default()
            },
            NonAnonymousDepositPoolConfig {
                // Isolates the affordability check from the reserve floor below.
                min_node_xdai_reserve: XDaiBalance::zero(),
                ..cfg()
            },
        )
        .await?;

        assert!(matches!(f.sweep().await, Err(StrategyError::CriteriaNotSatisfied)));
        assert_eq!(
            f.hopr(f.deposit_addr).await?,
            deposited(),
            "a refused top-up must leave the deposit untouched"
        );
        Ok(())
    }

    /// The node pays gas for its own announcements, redemptions and channel operations out of the
    /// same account, so a top-up it can technically afford must still be refused when it would
    /// breach the reserve.
    #[test_log::test(tokio::test)]
    async fn sweep_gas_top_up_stops_at_the_node_reserve() -> anyhow::Result<()> {
        let reserve: XDaiBalance = "0.01 xdai".parse()?;
        // More than one top-up's worth, so the shortfall is the reserve rather than the transfer:
        // the default 0.01 xDai top-up is affordable here, `0.01 + reserve` is not.
        let node_xdai: XDaiBalance = "0.015 xdai".parse()?;

        let refused = fixture(
            Balances {
                node_xdai,
                ..Default::default()
            },
            NonAnonymousDepositPoolConfig {
                min_node_xdai_reserve: reserve,
                ..cfg()
            },
        )
        .await?;

        assert!(matches!(
            refused.sweep().await,
            Err(StrategyError::CriteriaNotSatisfied)
        ));
        assert_eq!(
            refused.xdai(refused.node_addr).await?,
            node_xdai,
            "a refused top-up must not spend anything"
        );

        // Same balances, reserve opted out — proving the refusal above is the reserve talking and
        // not a plain shortfall. The leftover also has to cover the top-up transaction's own gas,
        // which is the concrete thing the reserve protects: a node drained to exactly zero cannot
        // even send the transfer that drained it.
        let allowed = fixture(
            Balances {
                node_xdai,
                ..Default::default()
            },
            NonAnonymousDepositPoolConfig {
                min_node_xdai_reserve: XDaiBalance::zero(),
                ..cfg()
            },
        )
        .await?;

        allowed.sweep().await?;
        assert!(
            allowed.hopr(allowed.deposit_addr).await?.is_zero(),
            "with the reserve opted out the same node can fund the sweep"
        );
        Ok(())
    }

    /// A deposit the node cannot cover is refused up front rather than submitted and reverted.
    ///
    /// The pool used to transfer blind: nothing read the payer's balance, so running the float
    /// dry surfaced as an opaque transaction failure with no indication of the cause.
    #[test_log::test(tokio::test)]
    async fn deposit_is_refused_when_the_safe_cannot_cover_it() -> anyhow::Result<()> {
        let f = fixture(
            Balances {
                safe_hopr: HoprBalance::new_base(10),
                ..Default::default()
            },
            cfg(),
        )
        .await?;

        let result = f.deposit(HoprBalance::new_base(25)).await;

        assert!(matches!(result, Err(StrategyError::CriteriaNotSatisfied)));
        assert!(
            f.hopr(f.dest_addr).await?.is_zero(),
            "a refused deposit must not move anything"
        );
        assert_eq!(
            f.hopr(f.safe_addr).await?,
            HoprBalance::new_base(10),
            "and must not spend anything either"
        );
        Ok(())
    }

    /// `min_safe_hopr_reserve` holds back a floor the deposits may not eat into, for an operator
    /// whose Safe is funded for something beyond the PIX float — channel stakes, say.
    #[test_log::test(tokio::test)]
    async fn deposit_stops_at_the_safe_hopr_reserve() -> anyhow::Result<()> {
        let balances = || Balances {
            safe_hopr: HoprBalance::new_base(30),
            ..Default::default()
        };
        let amount = HoprBalance::new_base(25);

        let refused = fixture(
            balances(),
            NonAnonymousDepositPoolConfig {
                min_safe_hopr_reserve: HoprBalance::new_base(10),
                ..cfg()
            },
        )
        .await?;

        assert!(matches!(
            refused.deposit(amount).await,
            Err(StrategyError::CriteriaNotSatisfied)
        ));
        assert!(refused.hopr(refused.dest_addr).await?.is_zero());

        // Same balances, default (zero) reserve — so the refusal above is the floor talking and
        // not a shortfall.
        let allowed = fixture(balances(), cfg()).await?;

        allowed.deposit(amount).await?;
        assert_eq!(
            allowed.hopr(allowed.dest_addr).await?,
            amount,
            "with no reserve configured the same Safe funds the deposit"
        );
        assert_eq!(
            allowed.hopr(allowed.node_addr).await?,
            HoprBalance::new_base(1000),
            "the node's own wxHOPR is never what a deposit spends"
        );
        Ok(())
    }

    /// The struct's docs promise that omitting a field in a config document and taking
    /// [`Default`] agree. Nothing tested that for any field; the new one is the occasion to.
    #[test]
    fn config_omitting_the_reserve_falls_back_to_the_documented_default() -> anyhow::Result<()> {
        let parsed: NonAnonymousDepositPoolConfig = serde_json::from_str(r#"{"max_sweep_retries": 8}"#)?;

        assert_eq!(parsed.max_sweep_retries, 8);
        assert_eq!(
            parsed.min_node_xdai_reserve,
            NonAnonymousDepositPoolConfig::default().min_node_xdai_reserve
        );
        assert_eq!(parsed.min_node_xdai_reserve, "0.01 xdai".parse()?);
        assert!(parsed.min_safe_hopr_reserve.is_zero());
        Ok(())
    }
}
