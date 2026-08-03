pub mod non_anonymous;
pub mod strategy;

use futures::{StreamExt, stream::FuturesUnordered, future::BoxFuture};
use hopr_api::{Address, HoprBalance, node::{PixDepositAddress, PixDepositSecret}};

/// Contains abstraction over the deposit pool from PIX.
///
/// The implementations can be completely non-anonymous (e.g. plain Ethereum transactions from
/// node's Safe to the [`PixDepositAddress`], if the `PixDepositAddress` and [`PixDepositSecret`] represents
/// standard Ethereum keypair), or anonymous using a privacy pool in the background.
///
/// In general, any anonymous privacy pool must be able to implement this trait in order
/// to be used with PIX.
///
/// The operations MUST fail if used with `PixDepositAddress`/`PixDepositSecret` which are internally
/// not compatible with the underlying pool's deposit address representation.
// TODO: this going to be moved to hopr-api eventually
#[async_trait::async_trait]
#[auto_impl::auto_impl(&, Box, Arc)]
pub trait DepositPool {
    /// Errors on failures.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Some receipt returned on successful deposits and withdrawals.
    type Receipt: Send + Sync + 'static;

    /// Deposits `amount` of funds from node's Safe to the given `dst` deposit address.
    async fn deposit_funds_to(&self, dst: PixDepositAddress, amount: HoprBalance) -> Result<Self::Receipt, Self::Error>;

    /// Returns a future that resolves once `min_amount` has been deposited to the `dst` [`PixDepositAddress`].
    ///
    /// The returned future is `'static` so it can be spawned independently of the borrow on `&self`.
    fn notify_deposit(&self, dst: PixDepositAddress, min_amount: HoprBalance) -> Result<BoxFuture<'static, (PixDepositAddress, HoprBalance)>, Self::Error>;

    /// Performs withdrawal of a previously made deposit using its [`PixDepositSecret`] to the
    /// `dst` Ethereum address.
    ///
    /// Should allow for partial withdrawals if `amount` is specified,
    /// otherwise withdraws the entire deposit.
    async fn withdraw_deposit(&self, key: &PixDepositSecret, dst: Address, amount: Option<HoprBalance>) -> Result<Self::Receipt, Self::Error>;

    /// Performs batch [full withdrawal](Self::withdraw_deposit) of multiple deposits into a single Ethereum address.
    ///
    /// This default implementation simply concurrently calls [`self.withdraw_deposit`].
    /// Implementors may choose a more efficient pool-native batching.
    async fn withdraw_multiple_deposits(&self, keys: &[PixDepositSecret], dst: Address) -> Result<Vec<Result<Self::Receipt, Self::Error>>, Self::Error>
    where Self: Clone + Send + Sync
    {
        let futures = keys.iter()
            .cloned()
            .map(|key| {
                let this = self.clone();
                async move {
                    this.withdraw_deposit(&key, dst, None).await
                }
            })
            .collect::<FuturesUnordered<_>>();

        Ok(futures.collect().await)
    }
}