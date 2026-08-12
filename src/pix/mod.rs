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
//! | `strategy-pix-curvy` | connector-owned, injected with `build_with_pool` | `BjjPublicKey` | `hopr-lib/pix-bjj` (default) |
//!
//! Each typed builder fixes its keypair explicitly, so selecting both features remains valid
//! under Cargo's additive feature model. The node composition layer still has to pair the
//! chosen builder with the matching `HoprPixSpec` deposit-address type.
//!
//! Enabling `strategy-pix` alone is supported and gives the engine without a pool, for a
//! consumer supplying its own via
//! [`PixStrategy::build_with_pool`](strategy::PixStrategy::build_with_pool).

#[cfg(feature = "strategy-pix-secp256k1")]
pub mod non_anonymous_pool;
pub mod recovery_store;
pub mod strategy;

/// Configuration for the bundled non-anonymous pool.
#[cfg(feature = "strategy-pix-secp256k1")]
pub type PoolConfig = non_anonymous_pool::NonAnonymousDepositPoolConfig;
