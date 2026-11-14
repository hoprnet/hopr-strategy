//! The [`DepositPool`](hopr_api::chain::DepositPool) implementations bundled with this crate.
//!
//! One module per pool, each behind its own feature, each exporting its own `PoolKeypair`,
//! `PoolConfig` and `DepositAddress` under the same names. The features are additive rather than
//! exclusive, so a build may carry both; which pool actually runs is decided at the call site by
//! which builder on [`PixStrategy`](crate::pix::strategy::PixStrategy) is invoked. See
//! [`crate::pix`] for why the choice cannot be made by the feature graph, and for the pairing each
//! pool needs on the `hopr-crypto-packet` side.
//!
//! ## Failed deposits and the spend limit
//!
//! A deposit is reserved against
//! [`max_spend_per_window`](crate::pix::strategy::PixStrategyConfig::max_spend_per_window) when it
//! is accepted, and the reservation is handed back only when a failure *provably* moved no funds.
//! Refunding on any error would be unsound: a transfer reported as failed may still have landed.
//!
//! The pool states that proof through
//! [`StrategyError::moved_no_funds`](crate::errors::StrategyError::moved_no_funds). A wrong `true`
//! lets a burst of failures outspend the window, so the default answers `false`.

#[cfg(feature = "strategy-pix-curvy")]
pub mod curvy;
#[cfg(feature = "strategy-pix-test")]
pub mod plain;

/// Asks a bundled pool whether a wrapped error proves the failed deposit moved no funds.
///
/// Called from [`StrategyError::moved_no_funds`](crate::errors::StrategyError::moved_no_funds)
/// for an [`Other`](crate::errors::StrategyError::Other) carrying one of this module's error
/// types. Kept here rather than on `StrategyError` itself so the error enum stays pool-agnostic
/// and the two pools' classifications live next to the pools.
///
/// The downcasts are tried in turn: neither bundled error is ever produced above the other, so at
/// most one matches.
pub(crate) fn error_moved_no_funds(error: &anyhow::Error) -> bool {
    #[cfg(feature = "strategy-pix-curvy")]
    if let Some(curvy) = error.downcast_ref::<curvy::CurvyDepositPoolError>() {
        return curvy.moved_no_funds();
    }
    #[cfg(feature = "strategy-pix-test")]
    if let Some(plain) = error.downcast_ref::<plain::PlainDepositError>() {
        return matches!(plain, plain::PlainDepositError::Unaffordable { after_attempt: false });
    }
    let _ = error;
    false
}

/// Asks a bundled pool whether a wrapped error only waits for an earlier Curvy operation to be
/// reconciled, rather than saying this deposit failed.
///
/// Called from
/// [`StrategyError::is_reconciliation_pending`](crate::errors::StrategyError::is_reconciliation_pending).
/// The plain pool has no reconciliation step, so it never answers `true`.
pub(crate) fn error_is_reconciliation_pending(error: &anyhow::Error) -> bool {
    #[cfg(feature = "strategy-pix-curvy")]
    if let Some(curvy) = error.downcast_ref::<curvy::CurvyDepositPoolError>() {
        return curvy.is_reconciliation_pending();
    }
    let _ = error;
    false
}
