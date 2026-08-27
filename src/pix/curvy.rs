//! ## Baby JubJub [`DepositPool`] implementation — **stub**
//!
//! [`CurvyDepositPool`] is the counterpart to
//! `secp256k1::NonAnonymousDepositPool` for the
//! Baby JubJub instantiation of `HoprPixSpec`, where a deposit address is a curve point rather
//! than an Ethereum account.
use std::{sync::Arc, time::Duration};

use hopr_api::{
    chain::{DepositNotification, DepositPool},
    node::{HasChainApi, PixAddressId},
    types::{
        crypto::prelude::{BjjKeypair, BjjPublicKey},
        primitive::prelude::{Address, HoprBalance},
    },
};
use validator::Validate;

use crate::{errors::StrategyError, pix::ByteDepositData};

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

fn validate_min_1sec(duration: &Duration) -> Result<(), validator::ValidationError> {
    if duration.as_secs() < 1 {
        return Err(validator::ValidationError::new("must be at least 1 second"));
    }
    Ok(())
}

/// Configuration for [`CurvyDepositPool`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, smart_default::SmartDefault, Validate)]
pub struct CurvyDepositPoolConfig {
    /// How long [`DepositPool::notify_deposit`]'s future waits before resolving to an error.
    /// Default: 60 seconds.
    ///
    /// Present because the trait requires the pool to own this deadline, not because the
    /// non-anonymous pool has a field of the same name.
    #[default(default_max_deposit_tracking_time())]
    #[serde(with = "humantime_serde", default = "default_max_deposit_tracking_time")]
    #[validate(custom(function = "validate_min_1sec"))]
    pub max_deposit_tracking_time: Duration,
}

/// A [`DepositPool`] for Baby JubJub deposit addresses.
///
/// See the module documentation: **every method that moves or tracks funds panics**, and
/// [`generate_deposit_data`](DepositPool::generate_deposit_data) answers with an empty payload. The
/// type, its key and its config are final; the settlement logic is not written.
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
             `strategy-pix-curvy`, which is currently a stub. For a working pool build with `strategy-pix-test` \
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
    /// [`ByteDepositData`], empty — a placeholder until the settlement logic lands.
    ///
    /// Curvy pool should replace it with its custom deposit data, which is convertible to/from
    /// [`PixDepositData`](hopr_api::chain::PixDepositData).
    type PoolDepositData = ByteDepositData;
    type Receipt = ();

    /// The empty payload for `id` — the one method here that does not panic.
    ///
    /// See the module docs: this runs on the Exit before any deposit exists, so panicking would
    /// break the request path rather than the settlement path, and the settlement path is where a
    /// stub should be discovered. A Curvy build therefore gets this far and then fails at
    /// [`deposit_funds_to`](Self::deposit_funds_to).
    async fn generate_deposit_data(&self, id: &PixAddressId) -> Result<Self::PoolDepositData, Self::Error> {
        Ok(ByteDepositData::for_id(*id))
    }

    async fn deposit_funds_to(
        &self,
        _id: &PixAddressId,
        _dst: &BjjPublicKey,
        _amount: HoprBalance,
        _additional_data: Self::PoolDepositData,
    ) -> Result<Self::Receipt, Self::Error> {
        not_implemented!("deposit_funds_to")
    }

    fn notify_deposit(
        &self,
        _id: PixAddressId,
        _dst: BjjPublicKey,
        _min_amount: HoprBalance,
    ) -> Result<DepositNotification<'static, BjjPublicKey, Self::Error>, Self::Error> {
        not_implemented!("notify_deposit")
    }

    async fn withdraw_deposit(
        &self,
        _id: &PixAddressId,
        _key: &BjjKeypair,
        _dst: Address,
        _amount: Option<HoprBalance>,
    ) -> Result<Self::Receipt, Self::Error> {
        not_implemented!("withdraw_deposit")
    }

    async fn pool_transfer(
        &self,
        _src_id: &PixAddressId,
        _key: &BjjKeypair,
        _dst_id: &PixAddressId,
        _dst: BjjPublicKey,
        _additional_dst_data: Self::PoolDepositData,
        _amount: Option<HoprBalance>,
    ) -> Result<Self::Receipt, Self::Error> {
        not_implemented!("pool_transfer")
    }
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroU32, sync::Arc};

    use hopr_api::{
        ChainKeypair,
        chain::DepositPool,
        node::PixAddressId,
        types::{
            crypto::prelude::{BjjKeypair, Keypair},
            crypto_random::Randomizable,
            internal::prelude::HoprPseudonym,
            primitive::prelude::{Address, HoprBalance, XDaiBalance},
        },
    };

    use super::{CurvyDepositPool, CurvyDepositPoolConfig};
    use crate::{
        pix::ByteDepositData,
        testing::{BlokliTestStateBuilder, ChainNode, create_test_blokli_connector},
    };

    /// Builds a pool over a real chain connector, so that a panic observed below is the stub's own
    /// and not an unrelated failure while standing the pool up.
    async fn stub_pool() -> anyhow::Result<CurvyDepositPool<impl hopr_api::node::HasChainApi>> {
        let me = ChainKeypair::from_secret(&hex_literal::hex!(
            "492057cf93e99b31d2a85bc5e98a9c3aa0021feec52c227cc8170e8f7d047775"
        ))?;
        let sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&me.public().to_address()],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .build_dynamic_client(Address::from([1u8; 20]));
        let connector = create_test_blokli_connector(&me, sim, Address::from([1u8; 20])).await?;
        Ok(CurvyDepositPool::new(
            Arc::new(ChainNode(Arc::new(connector))),
            CurvyDepositPoolConfig::default(),
        ))
    }

    fn an_id() -> PixAddressId {
        PixAddressId::new(&HoprPseudonym::random(), NonZeroU32::new(1).unwrap())
    }

    // Each settlement method must panic, and the panic must name the feature that selected this
    // pool. The assertion is on the *message*, not merely on the unwind: a stub returning `Ok(())`
    // or a plain error would look like a working pool that simply never deposits, which is the
    // failure this module's docs describe as having cost a day to diagnose. The message is the part
    // that does the work, so the message is what is pinned.
    //
    // `generate_deposit_data` is the exception, and has its own test below.

    #[tokio::test]
    #[should_panic(expected = "strategy-pix-curvy")]
    async fn test_deposit_funds_to_panics_naming_the_feature() {
        let pool = stub_pool().await.expect("pool must stand up");
        let id = an_id();
        let _ = pool
            .deposit_funds_to(
                &id,
                BjjKeypair::random().public(),
                HoprBalance::new_base(1),
                ByteDepositData::for_id(id),
            )
            .await;
    }

    /// The one method that must *not* panic.
    ///
    /// Deposit data is generated on the Exit before any deposit exists, so a panic here would break
    /// the `DepositDataRequest` path rather than the settlement path — and the settlement path is
    /// where this pool being a stub should be discovered. See the module docs.
    #[tokio::test]
    async fn test_generate_deposit_data_returns_an_empty_payload() -> anyhow::Result<()> {
        let pool = stub_pool().await?;
        let id = an_id();

        let generated = pool.generate_deposit_data(&id).await?;
        let wire: hopr_api::node::PixDepositData = generated.try_into()?;

        assert_eq!(wire.id, id, "the payload must be filed under the requested allocation");
        assert!(wire.is_empty(), "the curvy stub carries no bytes yet");
        Ok(())
    }

    #[tokio::test]
    #[should_panic(expected = "strategy-pix-curvy")]
    async fn test_notify_deposit_panics_naming_the_feature() {
        let pool = stub_pool().await.expect("pool must stand up");
        let _ = pool.notify_deposit(an_id(), *BjjKeypair::random().public(), HoprBalance::new_base(1));
    }

    #[tokio::test]
    #[should_panic(expected = "strategy-pix-curvy")]
    async fn test_withdraw_deposit_panics_naming_the_feature() {
        let pool = stub_pool().await.expect("pool must stand up");
        let _ = pool
            .withdraw_deposit(&an_id(), &BjjKeypair::random(), Address::from([1u8; 20]), None)
            .await;
    }

    #[tokio::test]
    #[should_panic(expected = "strategy-pix-curvy")]
    async fn test_pool_transfer_panics_naming_the_feature() {
        let pool = stub_pool().await.expect("pool must stand up");
        let dst_id = an_id();
        let _ = pool
            .pool_transfer(
                &an_id(),
                &BjjKeypair::random(),
                &dst_id,
                *BjjKeypair::random().public(),
                ByteDepositData::for_id(dst_id),
                None,
            )
            .await;
    }
}
