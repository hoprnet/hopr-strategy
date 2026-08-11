//! # PIX strategy
//!
//! ## Choosing a deposit pool
//!
//! [`DepositPool`](hopr_api::chain::DepositPool) is generic over its keypair, and `K::Public` is
//! the deposit address the pool can settle to. That address type has to match the one
//! `HoprPixSpec` produces — which is chosen by a feature on `hopr-crypto-packet`, in a different
//! crate. Two independent axes that must agree, and Cargo cannot express agreement across
//! crates.
//!
//! What it *can* express is a bundle, so each pool is offered as one feature that a consumer
//! pairs with the matching spec feature:
//!
//! | feature | pool | `K::Public` | pair with |
//! |---|---|---|---|
//! | `strategy-pix-secp256k1` | [`non_anonymous_pool::NonAnonymousDepositPool`] | `Address` | `hopr-lib/pix-secp256k1` |
//! | `strategy-pix-curvy` | [`curvy_pool::CurvyDepositPool`] (**stub**) | `BjjPublicKey` | `hopr-lib/pix-bjj` (default) |
//!
//! [`PoolKeypair`] and [`PoolConfig`] name the selected pool's types in one place, so a consumer
//! can state the invariant `<HoprPixSpec as PixSpec>::DepositAddress == PoolKeypair::Public`
//! without naming a concrete pool. `hoprd::strategy` asserts exactly that at compile time, and
//! it keeps holding unedited across a switch — what it rejects is the two axes moving apart.
//!
//! Enabling `strategy-pix` alone is supported and gives the engine without a pool, for a
//! consumer supplying its own via
//! [`PixStrategy::build_with_pool`](strategy::PixStrategy::build_with_pool).

#[cfg(feature = "strategy-pix-curvy")]
pub mod curvy_pool;
#[cfg(feature = "strategy-pix-secp256k1")]
pub mod non_anonymous_pool;
pub mod recovery_store;
pub mod strategy;

// The two pairings select different types for the same aliases, so enabling both is not a
// merge — it is a contradiction. Cargo features are additive and this crate is a library, so
// this fires when two consumers in one graph each pick a different pool; that is a real
// configuration error and the error message is the only place it can be explained.
#[cfg(all(feature = "strategy-pix-secp256k1", feature = "strategy-pix-curvy"))]
compile_error!(
    "features `strategy-pix-secp256k1` and `strategy-pix-curvy` are mutually exclusive: they \
     select deposit pools with incompatible address types. Exactly one crate in the dependency \
     graph may choose, and every consumer of `hopr-strategy` must agree on the same one."
);

/// The keypair of the deposit pool selected by the enabled `strategy-pix-*` feature.
///
/// `K::Public` is the deposit address that pool can settle to; asserting it against
/// `<HoprPixSpec as PixSpec>::DepositAddress` is what makes a pool/curve mismatch a compile
/// error rather than a silent runtime failure.
#[cfg(feature = "strategy-pix-secp256k1")]
pub type PoolKeypair = non_anonymous_pool::EthDepositKey;
// `not(secp)` so that enabling both yields only the `compile_error!` above, rather than burying
// it under a pile of duplicate-definition errors.
#[cfg(all(feature = "strategy-pix-curvy", not(feature = "strategy-pix-secp256k1")))]
pub type PoolKeypair = hopr_api::types::crypto::prelude::BjjKeypair;

/// The configuration type of the deposit pool selected by the enabled `strategy-pix-*` feature.
///
/// Carried by [`strategy::PixStrategyConfig::pool`]. The two configs deliberately share **no**
/// fields by contract: the pools settle by different means, so neither one's knobs are evidence
/// that the other needs them. A caller that sets pool-specific values therefore writes them
/// under the same `cfg` that selects the pool, which is what stops a value meant for one from
/// silently reaching the other.
#[cfg(feature = "strategy-pix-secp256k1")]
pub type PoolConfig = non_anonymous_pool::NonAnonymousDepositPoolConfig;
#[cfg(all(feature = "strategy-pix-curvy", not(feature = "strategy-pix-secp256k1")))]
pub type PoolConfig = curvy_pool::CurvyDepositPoolConfig;
