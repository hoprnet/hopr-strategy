pub mod non_anonymous_pool;
pub mod recovery_store;
pub mod strategy;

/// The keypair consumed by the [`DepositPool`](hopr_api::chain::DepositPool) that
/// [`PixStrategy::build_non_anonymous`](strategy::PixStrategy::build_non_anonymous) selects.
///
/// [`DepositPool`](hopr_api::chain::DepositPool) is generic over its keypair, and `K::Public` is
/// the deposit address the pool can settle to. That address type has to match the one
/// `HoprPixSpec` produces, or the strategy narrows an event to a type its pool cannot spend —
/// a mismatch that used to be a silent runtime failure (see the compile-time assertion in
/// `hoprd::strategy`).
///
/// This alias is the single place that binding is stated. A consumer asserts against it rather
/// than against a concrete key type, so the assertion stays correct when a Baby JubJub pool
/// arrives and this line is repointed at its keypair.
pub type PoolKeypair = non_anonymous_pool::EthDepositKey;
