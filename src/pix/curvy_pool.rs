//! ## Baby JubJub [`DepositPool`] implementation — **stub**
//!
//! [`CurvyDepositPool`] is the counterpart to
//! [`NonAnonymousDepositPool`](crate::pix::non_anonymous_pool::NonAnonymousDepositPool) for the
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
//! [`EthDepositKey`](crate::pix::non_anonymous_pool::EthDepositKey) because
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

fn default_max_deposit_tracking_time() -> Duration {
    Duration::from_secs(60)
}

/// Configuration for [`CurvyDepositPool`].
///
/// Deliberately field-compatible with
/// [`NonAnonymousDepositPoolConfig`](crate::pix::non_anonymous_pool::NonAnonymousDepositPoolConfig)
/// on the values a consumer actually sets, so that `PixStrategyConfig` and any YAML that feeds it
/// do not have to change shape when the pool does. Fields specific to on-chain settlement, such
/// as the sweep gas top-up, are absent — an anonymous pool does not send a transaction the
/// depositor pays for.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, smart_default::SmartDefault)]
pub struct CurvyDepositPoolConfig {
    /// How long to keep waiting for the expected deposit before giving up. Default: 60 seconds.
    #[default(default_max_deposit_tracking_time())]
    #[serde(with = "humantime_serde", default = "default_max_deposit_tracking_time")]
    pub max_deposit_tracking_time: Duration,

    /// Attempts *in addition to* the first for a deposit.  Default: 3.
    #[default(3)]
    #[serde(default)]
    pub max_deposit_retries: usize,

    /// Attempts *in addition to* the first for a withdrawal.  Default: 5.
    #[default(5)]
    #[serde(default)]
    pub max_sweep_retries: usize,
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
            "CurvyDepositPool::{} is not implemented — this build selected the Baby JubJub \
             deposit pool via `strategy-pix-bjj`, which is currently a stub. For a working pool \
             build with `strategy-pix-secp256k1` instead (and `hopr-lib/pix-secp256k1` with it).",
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
