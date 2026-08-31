//! The [`DepositPool`](hopr_api::chain::DepositPool) implementations bundled with this crate.
//!
//! One module per pool, each behind its own feature, each exporting its own `PoolKeypair`,
//! `PoolConfig` and `DepositAddress` under the same names. The features are additive rather than
//! exclusive, so a build may carry both; which pool actually runs is decided at the call site by
//! which builder on [`PixStrategy`](crate::pix::strategy::PixStrategy) is invoked. See
//! [`crate::pix`] for why the choice cannot be made by the feature graph, and for the pairing each
//! pool needs on the `hopr-crypto-packet` side.

#[cfg(feature = "strategy-pix-curvy")]
pub mod curvy;
#[cfg(feature = "strategy-pix-test")]
pub mod plain;
