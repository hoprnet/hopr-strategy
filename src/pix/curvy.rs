//! ## Baby JubJub [`DepositPool`] implementation — **stub**
//!
//! [`CurvyDepositPool`] is the counterpart to
//! `secp256k1::NonAnonymousDepositPool` for the
//! Baby JubJub instantiation of `HoprPixSpec`, where a deposit address is a curve point rather
//! than an Ethereum account.
//!
//! # Status
//!
//! **Every trait method panics.** This module exists so that the feature wiring, the key type
//! and the compile-time invariant that binds them are all in place and exercised by the build
//! *before* the settlement logic lands. What is final here is the shape; what is missing is the
//! implementation.
//!
//! The panic is deliberate rather than a silent no-op or an error return. A pool that quietly
//! did nothing is precisely the failure this whole arrangement exists to prevent — hoprnet
//! `27b4b255f9` cost a day because a mis-selected curve produced no deposits and no diagnostic.
//!
//! # Why no newtype
//!
//! The secp arm needs
//! `secp256k1::EthDepositKey` because
//! `ChainKeypair::Public` is a `PublicKey` while a deposit address is an `Address` — a *hash* of
//! it, with no way back. Baby JubJub has no such gap: `BjjKeypair::Public` **is** `BjjPublicKey`,
//! which is exactly what `PixDepositAddress::Bjj` carries, and hopr-types supplies the
//! conversion both ways. So this pool is parameterised on the upstream keypair directly.

use std::{sync::Arc, time::Duration};

use hopr_api::{
    chain::{DepositNotification, DepositPool},
    node::HasChainApi,
    types::{
        crypto::prelude::{BjjKeypair, BjjPublicKey},
        primitive::prelude::{Address, HoprBalance},
    },
};

use crate::errors::StrategyError;

// ---------------------------------------------------------------------------
// Module-level aliases
// ---------------------------------------------------------------------------

/// This pool's keypair — the `K` in [`DepositPool`], whose `K::Public` is the deposit address it
/// settles to.
///
/// The upstream [`BjjKeypair`] directly, for the reason given under *Why no newtype* above. The
/// `pix::secp256k1` module exports the same two names for its own pool, so the
/// two coexist and the choice is made by which one is imported.
pub type PoolKeypair = BjjKeypair;

/// This pool's configuration type.
///
/// Passed to [`PixStrategy::build_curvy`](crate::pix::strategy::PixStrategy::build_curvy) rather
/// than carried in `PixStrategyConfig`, so that a value meant for one pool cannot silently reach
/// the other.
pub type PoolConfig = CurvyDepositPoolConfig;

/// The deposit address this pool settles to — [`BjjPublicKey`], via [`PoolKeypair`].
///
/// A projection rather than `BjjPublicKey` directly, for the reason given on
/// `secp256k1::DepositAddress`: it derives the
/// [`DepositAddressOf`](crate::pix::DepositAddressOf) impl below from the keypair instead of
/// restating it, so the impl cannot claim an address type this pool does not settle to.
pub type DepositAddress = <PoolKeypair as hopr_api::types::crypto::prelude::Keypair>::Public;

/// Naming [`DepositAddress`] (i.e. `BjjPublicKey`) in
/// [`PixStrategy::build_curvy`](crate::pix::strategy::PixStrategy::build_curvy) is therefore
/// accepted, and naming any other address type is a compile error at that call site.
impl crate::pix::DepositAddressOf<PoolKeypair> for DepositAddress {}

fn default_max_deposit_tracking_time() -> Duration {
    Duration::from_secs(60)
}

/// Configuration for [`CurvyDepositPool`].
///
/// **Shares nothing with `secp256k1::NonAnonymousDepositPoolConfig` by design.** The two pools
/// settle by different means, so neither one's knobs are evidence
/// that the other needs them, in either direction:
///
/// * The non-anonymous pool's `gas_xdai_per_sweep` funds a recovered stealth address so it can pay for its own
///   `withdraw_from_signer` transaction. That is a fact about settling on-chain from an EOA, not about deposit pools.
///   This pool has no such field and should not acquire one by analogy.
/// * Its `max_deposit_retries` / `max_sweep_retries` budget retries of a *transaction* against a chain that may drop
///   it. What this pool retries, and whether retrying is even meaningful, is not yet decided.
///
/// So this carries only what the [`DepositPool`] contract itself forces — a pool owns the
/// deadline on the future it returns from [`DepositPool::notify_deposit`], so it needs somewhere
/// to keep it — and stays otherwise empty until the settlement design says what belongs here.
/// A consumer that wants both pools configured writes the two separately; nothing lets a value
/// intended for one silently reach the other.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, smart_default::SmartDefault)]
pub struct CurvyDepositPoolConfig {
    /// How long [`DepositPool::notify_deposit`]'s future waits before resolving to an error.
    /// Default: 60 seconds.
    ///
    /// Present because the trait requires the pool to own this deadline, not because the
    /// non-anonymous pool has a field of the same name.
    #[default(default_max_deposit_tracking_time())]
    #[serde(with = "humantime_serde", default = "default_max_deposit_tracking_time")]
    pub max_deposit_tracking_time: Duration,
}

/// A [`DepositPool`] for Baby JubJub deposit addresses.
///
/// See the module documentation: **every method panics**. The type, its key and its config are
/// final; the settlement logic is not written.
pub struct CurvyDepositPool<N> {
    #[allow(dead_code)]
    node: Arc<N>,
    #[allow(dead_code)]
    cfg: CurvyDepositPoolConfig,
}

impl<N> CurvyDepositPool<N> {
    pub fn new(node: Arc<N>, cfg: CurvyDepositPoolConfig) -> Self {
        Self { node, cfg }
    }
}

/// Panics with a message naming the missing implementation and the working alternative.
///
/// A bare `unimplemented!()` would surface as a line number in a stack trace; an operator who
/// hits this needs to know that the *build* chose this pool and which feature chooses the other.
macro_rules! not_implemented {
    ($what:literal) => {
        unimplemented!(
            "CurvyDepositPool::{} is not implemented — this build selected the Baby JubJub deposit pool via \
             `strategy-pix-curvy`, which is currently a stub. For a working pool build with `strategy-pix-secp256k1` \
             instead (and `hopr-lib/pix-secp256k1` with it).",
            $what
        )
    };
}

#[async_trait::async_trait]
impl<N> DepositPool<BjjKeypair> for CurvyDepositPool<N>
where
    N: HasChainApi + Send + Sync + 'static,
{
    type Error = StrategyError;
    type Receipt = ();

    async fn deposit_funds_to(&self, _dst: BjjPublicKey, _amount: HoprBalance) -> Result<Self::Receipt, Self::Error> {
        not_implemented!("deposit_funds_to")
    }

    fn notify_deposit(
        &self,
        _dst: BjjPublicKey,
        _min_amount: HoprBalance,
    ) -> Result<DepositNotification<'static, BjjPublicKey, Self::Error>, Self::Error> {
        not_implemented!("notify_deposit")
    }

    async fn withdraw_deposit(
        &self,
        _key: &BjjKeypair,
        _dst: Address,
        _amount: Option<HoprBalance>,
    ) -> Result<Self::Receipt, Self::Error> {
        not_implemented!("withdraw_deposit")
    }

    async fn pool_transfer(
        &self,
        _key: &BjjKeypair,
        _dst: BjjPublicKey,
        _amount: Option<HoprBalance>,
    ) -> Result<Self::Receipt, Self::Error> {
        not_implemented!("pool_transfer")
    }
}
