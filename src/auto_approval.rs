//! ## Auto Approval Strategy
//! Keeps the wxHOPR allowance that the node's Safe grants to the `HoprChannels` contract
//! from running out.
//!
//! Every channel opening or funding from the Safe spends this allowance. Once it is lower than
//! the amount being moved, the transaction reverts (`ERC777: transfer amount exceeds allowance`)
//! even when the Safe holds enough tokens, so channels can no longer be opened or topped up.
//!
//! The strategy watches the allowance and, when it falls strictly below
//! `min_allowance_threshold`, calls `approve(HoprChannels, allowance_amount)` on the wxHOPR token
//! through the Safe module. This **sets** the allowance to `allowance_amount`, it does not add to it.
//!
//! ### Triggers
//! - every [`ChainEvent::SafeAllowanceChanged`] of the node's Safe that is below the threshold (the allowance also goes
//!   down when channel funding spends it),
//! - at startup,
//! - periodically, to recover from missed events and failed transactions.
//!
//! Before every approval the current allowance is read again, so stale or repeated updates do not
//! cause extra transactions. At most one approval is in flight at any time.
//!
//! ### Metrics
//! - `hopr_strategy_auto_approval_approval_count` — incremented on successful enqueue
//! - `hopr_strategy_auto_approval_failure_count` — incremented on enqueue/confirm failure
use std::{
    fmt::{Debug, Display, Formatter},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use async_trait::async_trait;
use futures::{
    FutureExt, StreamExt,
    future::{BoxFuture, Fuse, FusedFuture},
};
use hopr_api::{
    chain::{ChainEvent, ChainReadChannelOperations, ChainReadSafeOperations, ChainWriteSafeOperations, SafeSelector},
    node::{ActionableEvent, ActionableEventDiscriminant, ActionableEventSource, HasChainApi},
    types::primitive::prelude::{Address, HoprBalance},
};
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use tracing::{debug, info, trace, warn};
use validator::{Validate, ValidationError};

use crate::{
    errors::StrategyError,
    strategy::{AtomicStrategyState, Strategy as StrategyTrait, StrategyState},
};

#[cfg(all(feature = "telemetry", not(test)))]
lazy_static::lazy_static! {
    static ref METRIC_COUNT_AUTO_APPROVALS: hopr_api::types::telemetry::SimpleCounter =
        hopr_api::types::telemetry::SimpleCounter::new("hopr_strategy_auto_approval_approval_count", "Count of initiated automatic Safe approvals").unwrap();
    static ref METRIC_COUNT_AUTO_APPROVAL_FAILURES: hopr_api::types::telemetry::SimpleCounter =
        hopr_api::types::telemetry::SimpleCounter::new("hopr_strategy_auto_approval_failure_count", "Count of failed automatic Safe approval attempts").unwrap();
}

fn validate_allowances(cfg: &AutoApprovalStrategyConfig) -> Result<(), ValidationError> {
    if cfg.min_allowance_threshold.is_zero() {
        return Err(ValidationError::new(
            "min_allowance_threshold must be greater than zero",
        ));
    }
    if cfg.allowance_amount <= cfg.min_allowance_threshold {
        return Err(ValidationError::new(
            "allowance_amount must be greater than min_allowance_threshold",
        ));
    }
    Ok(())
}

/// Configuration for `AutoApprovalStrategy`.
///
/// Every field is optional; unknown keys are rejected.
///
/// The threshold should be at least as large as the biggest amount moved into a channel at once
/// (for example the `funding_amount` of the auto funding strategy), so that the allowance is
/// restored before a funding transaction can revert.
///
/// ```
/// # use hopr_strategy::auto_approval::AutoApprovalStrategyConfig as C;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// assert_eq!(serde_json::from_str::<C>("{}")?, C::default());
/// let cfg: C = serde_json::from_str(r#"{"allowance_amount":"5000 wxHOPR"}"#)?;
/// assert_eq!(cfg.min_allowance_threshold, C::default().min_allowance_threshold);
/// assert!(serde_json::from_str::<C>(r#"{"allowance_amout":"5000 wxHOPR"}"#).is_err());
/// # Ok(())
/// # }
/// ```
#[serde_as]
#[derive(Debug, Clone, Copy, PartialEq, Eq, smart_default::SmartDefault, Validate, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[validate(schema(function = "validate_allowances"))]
pub struct AutoApprovalStrategyConfig {
    /// The allowance is restored when it is strictly below this value. Must be greater than zero.
    ///
    /// Default is 100 wxHOPR.
    #[serde_as(as = "DisplayFromStr")]
    #[default(HoprBalance::new_base(100))]
    pub min_allowance_threshold: HoprBalance,

    /// The allowance is set to this value (not increased by it).
    /// Must be greater than `min_allowance_threshold`.
    ///
    /// Default is 1000 wxHOPR.
    #[serde_as(as = "DisplayFromStr")]
    #[default(HoprBalance::new_base(1000))]
    pub allowance_amount: HoprBalance,
}

/// Builder for [`AutoApprovalStrategy`].
///
/// Call [`new`](AutoApprovalStrategy::new) with the strategy configuration,
/// then [`build`](AutoApprovalStrategy::build) to wire in a node and obtain a
/// runnable `Box<dyn Strategy + Send>`.
pub struct AutoApprovalStrategy {
    cfg: AutoApprovalStrategyConfig,
    interval: Duration,
}

impl AutoApprovalStrategy {
    /// Create a new builder with the given configuration.
    ///
    /// `interval` is the period of the allowance check that runs in addition to the allowance updates.
    pub fn new(cfg: AutoApprovalStrategyConfig, interval: Duration) -> Self {
        Self { cfg, interval }
    }

    /// Wire in a node and return a running-ready strategy.
    ///
    /// # Errors
    ///
    /// [`StrategyError::InvalidConfiguration`] if `min_allowance_threshold` is zero,
    /// `allowance_amount` is not greater than `min_allowance_threshold`, or `interval` is zero.
    /// Never panics.
    ///
    /// ```text
    /// let strategy = AutoApprovalStrategy::new(cfg, interval).build(node)?;
    /// ```
    ///
    /// `text` because `N`'s bounds need a live node, constructible only under the
    /// `testing` feature; see `tests::build_should_reject_invalid_configuration`.
    pub fn build<N>(self, node: Arc<N>) -> crate::errors::Result<Box<dyn StrategyTrait + Send>>
    where
        N: HasChainApi + ActionableEventSource + Send + Sync + 'static,
    {
        StrategyError::validate_config(&self.cfg)?;
        if self.interval.is_zero() {
            return Err(StrategyError::InvalidConfiguration(
                "interval must be greater than zero".into(),
            ));
        }

        Ok(Box::new(AutoApprovalStrategyInner::new(self.cfg, self.interval, node)))
    }
}

type PendingApproval = Fuse<BoxFuture<'static, ()>>;

/// Private generic runner — constructed by [`AutoApprovalStrategy::build`].
struct AutoApprovalStrategyInner<N> {
    node: Arc<N>,
    cfg: AutoApprovalStrategyConfig,
    interval: Duration,
    /// `Degraded` while the node has no Safe or the last approval failed.
    state: Arc<AtomicStrategyState>,
}

impl<N> AutoApprovalStrategyInner<N>
where
    N: HasChainApi + ActionableEventSource + Send + Sync + 'static,
{
    fn new(cfg: AutoApprovalStrategyConfig, interval: Duration, node: Arc<N>) -> Self {
        Self {
            node,
            cfg,
            interval,
            state: Arc::new(AtomicStrategyState::new(StrategyState::Running)),
        }
    }

    /// Returns the address of the Safe the node is registered with, which funds its channels.
    async fn resolve_safe(&self) -> crate::errors::Result<Option<Address>> {
        let me = *self.node.chain_api().me();
        Ok(self
            .node
            .chain_api()
            .safe_info(SafeSelector::NodeAddress(me))
            .await
            .map_err(StrategyError::other)?
            .map(|safe| safe.address))
    }

    /// Reads the current allowance and starts an approval if it is below the threshold.
    ///
    /// Returns `Ok(true)` if an approval was started. The run loop owns and polls the approval
    /// alongside incoming events, so cancelling the loop also drops any pending approval.
    async fn check_allowance(&self, safe: Address, pending: &mut PendingApproval) -> crate::errors::Result<bool> {
        if !pending.is_terminated() {
            debug!(%safe, "skipping allowance check while an approval is in flight");
            return Ok(false);
        }

        // Always read the current allowance: a streamed update may already be outdated.
        let allowance: HoprBalance = self
            .node
            .chain_api()
            .safe_allowance(safe)
            .await
            .map_err(StrategyError::other)?;

        if allowance >= self.cfg.min_allowance_threshold {
            trace!(%safe, %allowance, threshold = %self.cfg.min_allowance_threshold, "safe allowance is sufficient");
            return Ok(false);
        }

        *pending = self.approve(safe, allowance).fuse();
        Ok(true)
    }

    /// Creates the one approval future owned by the run loop.
    fn approve(&self, safe: Address, current: HoprBalance) -> BoxFuture<'static, ()> {
        info!(
            %safe,
            allowance = %current,
            threshold = %self.cfg.min_allowance_threshold,
            new_allowance = %self.cfg.allowance_amount,
            "safe allowance for channels is below threshold"
        );

        let chain = self.node.chain_api().clone();
        let amount = self.cfg.allowance_amount;
        let state = Arc::clone(&self.state);

        async move {
            let result = match chain.set_safe_allowance(amount).await {
                Ok(confirmation) => {
                    #[cfg(all(feature = "telemetry", not(test)))]
                    METRIC_COUNT_AUTO_APPROVALS.increment();

                    info!(%safe, %amount, "issued safe approval for channels");
                    confirmation.await.map(|receipt| {
                        info!(%safe, %amount, %receipt, "safe approval for channels confirmed");
                    })
                }
                Err(error) => Err(error),
            };

            if let Err(error) = &result {
                // The transaction may still land after a confirmation timeout. A repeated approval is
                // harmless: it sets the same absolute allowance again.
                warn!(%safe, %amount, %error, "safe approval failed, will retry on the next check");

                #[cfg(all(feature = "telemetry", not(test)))]
                METRIC_COUNT_AUTO_APPROVAL_FAILURES.increment();
            }

            state.store(
                if result.is_ok() {
                    StrategyState::Running
                } else {
                    StrategyState::Degraded
                },
                Ordering::Relaxed,
            );
        }
        .boxed()
    }

    /// Resolves the node's Safe, then checks its allowance. Does nothing while the node has no Safe.
    async fn on_trigger(&self, safe: &mut Option<Address>, pending: &mut PendingApproval, trigger: &str) {
        if safe.is_none() {
            match self.resolve_safe().await {
                Ok(Some(resolved)) => {
                    *safe = Some(resolved);
                    self.state.store(StrategyState::Running, Ordering::Relaxed);
                }
                Ok(None) => {
                    warn!(trigger, "auto-approval skipped: the node is not registered with a safe");
                    self.state.store(StrategyState::Degraded, Ordering::Relaxed);
                    return;
                }
                Err(error) => {
                    warn!(%error, trigger, "auto-approval skipped: cannot look up the node's safe");
                    return;
                }
            }
        }

        if let Some(safe) = *safe
            && let Err(error) = self.check_allowance(safe, pending).await
        {
            warn!(%safe, %error, trigger, "auto-approval allowance check failed");
        }
    }
}

impl<N> Debug for AutoApprovalStrategyInner<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "AutoApprovalStrategy({:?})", self.cfg)
    }
}

impl<N> Display for AutoApprovalStrategyInner<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "auto_approval")
    }
}

#[async_trait]
impl<N> StrategyTrait for AutoApprovalStrategyInner<N>
where
    N: HasChainApi + ActionableEventSource + Send + Sync + 'static,
{
    async fn run(&mut self) -> crate::errors::Result<()> {
        enum Event {
            Tick,
            Actionable(Box<ActionableEvent>),
        }

        // Subscribe before the first check, so no change in between is missed.
        let event_stream = self
            .node
            .subscribe_to_actionable_events(Some(&[ActionableEventDiscriminant::Chain]))
            .map_err(|e| StrategyError::Other(anyhow::anyhow!(e)))?
            .map(|e| Event::Actionable(Box::new(e)));

        let mut safe = None;
        let mut pending = PendingApproval::terminated();
        self.on_trigger(&mut safe, &mut pending, "startup").await;

        let tick_stream = futures_time::stream::interval(self.interval.into()).map(|_| Event::Tick);
        let mut combined = futures_concurrency::stream::Merge::merge((tick_stream, event_stream));

        loop {
            let event = futures::select_biased! {
                () = pending => continue,
                event = combined.next().fuse() => event,
            };
            let Some(event) = event else {
                break;
            };
            match event {
                Event::Tick => self.on_trigger(&mut safe, &mut pending, "tick").await,
                Event::Actionable(event) => {
                    if let ActionableEvent::Chain(ChainEvent::SafeAllowanceChanged(owner, allowance)) = *event
                        && safe.is_none_or(|safe| safe == owner)
                        && allowance < self.cfg.min_allowance_threshold
                    {
                        debug!(%owner, %allowance, "safe allowance changed below threshold");
                        self.on_trigger(&mut safe, &mut pending, "allowance changed").await;
                    }
                }
            }
        }

        Ok(())
    }

    fn state(&self) -> StrategyState {
        self.state.load(Ordering::Relaxed)
    }

    fn state_handle(&self) -> Arc<AtomicStrategyState> {
        self.state.clone()
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use hex_literal::hex;
    use hopr_api::{
        chain::ChainWriteChannelOperations,
        types::{
            crypto::{keypairs::Keypair, prelude::ChainKeypair},
            internal::prelude::{ChannelEntry, ChannelStatus},
            primitive::prelude::{BytesRepresentable, XDaiBalance},
        },
    };

    use super::*;
    use crate::testing::{
        BlokliTestClient, BlokliTestStateBuilder, ChainNode, ChainOp, EventKind, Fault, FullStateEmulator,
        TestChainConnector, create_test_blokli_connector, register_test_safe,
    };

    lazy_static::lazy_static! {
        static ref BOB_KP: ChainKeypair = ChainKeypair::from_secret(&hex!(
            "492057cf93e99b31d2a85bc5e98a9c3aa0021feec52c227cc8170e8f7d047775"
        ))
        .expect("lazy static keypair should be valid");

        static ref BOB: Address = BOB_KP.public().to_address();
        static ref CHRIS: Address = hex!("b6021e0860dd9d96c9ff0a73e2e5ba3a466ba234").into();
    }

    const MODULE: [u8; Address::SIZE] = [1; Address::SIZE];
    const INTERVAL: Duration = Duration::from_millis(100);
    const TIMEOUT: Duration = Duration::from_secs(5);

    type Connector = Arc<TestChainConnector<BlokliTestClient<FullStateEmulator>>>;

    fn config() -> AutoApprovalStrategyConfig {
        AutoApprovalStrategyConfig {
            min_allowance_threshold: HoprBalance::new_base(10),
            allowance_amount: HoprBalance::new_base(100),
        }
    }

    /// A connected node BOB, registered with its Safe, holding an open channel to CHRIS.
    async fn setup(allowance: HoprBalance) -> anyhow::Result<(Connector, Address, ChannelEntry)> {
        let channel = ChannelEntry::builder()
            .between(*BOB, *CHRIS)
            .amount(1)
            .ticket_index(0)
            .status(ChannelStatus::Open)
            .epoch(0)
            .build()?;

        let client = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*BOB, &*CHRIS],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .with_channels([channel])
            .build_dynamic_client(MODULE.into())
            .with_tx_simulation_delay(Duration::ZERO);

        let connector = Arc::new(create_test_blokli_connector(&BOB_KP, client, MODULE.into()).await?);
        register_test_safe(&connector, *BOB).await?;
        let safe = connector
            .safe_info(SafeSelector::NodeAddress(*BOB))
            .await?
            .context("missing safe of the test node")?
            .address;
        connector.client().update_safe_allowance(
            &safe.into(),
            blokli_client::api::types::TokenValueString(allowance.to_string()),
        );

        Ok((connector, safe, channel))
    }

    fn start(connector: &Connector) -> anyhow::Result<(tokio::task::JoinHandle<()>, Arc<AtomicStrategyState>)> {
        let mut strategy =
            AutoApprovalStrategy::new(config(), INTERVAL).build(Arc::new(ChainNode(connector.clone())))?;
        let state = strategy.state_handle();
        let handle = tokio::spawn(async move {
            let _ = strategy.run().await;
        });
        Ok((handle, state))
    }

    async fn allowance(connector: &Connector, safe: Address) -> anyhow::Result<HoprBalance> {
        Ok(connector.safe_allowance(safe).await?)
    }

    /// Polls `condition` until it holds, failing after [`TIMEOUT`].
    async fn eventually<F, Fut>(mut condition: F) -> anyhow::Result<()>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = bool>,
    {
        tokio::time::timeout(TIMEOUT, async {
            while !condition().await {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("condition not met in time")
    }

    #[test_log::test(tokio::test)]
    async fn should_set_allowance_at_startup_when_below_threshold() -> anyhow::Result<()> {
        let (connector, safe, _) = setup(HoprBalance::new_base(5)).await?;
        let (handle, state) = start(&connector)?;

        eventually(|| async { allowance(&connector, safe).await.ok() == Some(HoprBalance::new_base(100)) }).await?;
        // Let a few more ticks pass: nothing else must be sent.
        tokio::time::sleep(INTERVAL * 3).await;
        handle.abort();

        assert_eq!(
            allowance(&connector, safe).await?,
            HoprBalance::new_base(100),
            "the allowance must be set to the amount, not increased by it"
        );
        assert_eq!(connector.faults().calls(ChainOp::SetSafeAllowance), 1);
        assert_eq!(state.load(Ordering::Relaxed), StrategyState::Running);
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn should_not_set_allowance_at_or_above_threshold() -> anyhow::Result<()> {
        for initial in [10, 11, 5000] {
            let (connector, safe, _) = setup(HoprBalance::new_base(initial)).await?;
            let (handle, _) = start(&connector)?;

            tokio::time::sleep(INTERVAL * 3).await;
            handle.abort();

            assert_eq!(
                connector.faults().calls(ChainOp::SetSafeAllowance),
                0,
                "allowance {initial} must not be approved"
            );
            assert_eq!(allowance(&connector, safe).await?, HoprBalance::new_base(initial));
        }
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn should_restore_allowance_spent_by_channel_funding() -> anyhow::Result<()> {
        let (connector, safe, channel) = setup(HoprBalance::new_base(50)).await?;
        // A long interval, so only the allowance update can trigger the approval in time.
        let mut strategy = AutoApprovalStrategy::new(config(), Duration::from_secs(3600))
            .build(Arc::new(ChainNode(connector.clone())))?;
        let handle = tokio::spawn(async move {
            let _ = strategy.run().await;
        });
        tokio::time::sleep(INTERVAL).await;
        assert_eq!(connector.faults().calls(ChainOp::SetSafeAllowance), 0);

        // Funding spends 45 of the allowance, leaving 5, which is below the threshold.
        connector
            .fund_channel(channel.get_id(), HoprBalance::new_base(45))
            .await?
            .await?;

        eventually(|| async { allowance(&connector, safe).await.ok() == Some(HoprBalance::new_base(100)) }).await?;
        handle.abort();

        assert_eq!(connector.faults().calls(ChainOp::SetSafeAllowance), 1);
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn should_not_send_another_approval_while_one_is_pending() -> anyhow::Result<()> {
        let (connector, safe, _) = setup(HoprBalance::new_base(5)).await?;
        // The approval is submitted, but its confirmation never arrives.
        connector
            .faults()
            .set_confirmation(ChainOp::SetSafeAllowance, Fault::Hang);
        let (handle, _) = start(&connector)?;

        eventually(|| async { connector.faults().calls(ChainOp::SetSafeAllowance) == 1 }).await?;

        // More low-allowance updates and ticks arrive while the approval is pending.
        for _ in 0..3 {
            connector.client().update_safe_allowance(
                &safe.into(),
                blokli_client::api::types::TokenValueString(HoprBalance::new_base(1).to_string()),
            );
            tokio::time::sleep(INTERVAL).await;
        }
        handle.abort();

        assert_eq!(connector.faults().calls(ChainOp::SetSafeAllowance), 1);
        assert_eq!(connector.faults().peak_in_flight(ChainOp::SetSafeAllowance), 1);
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn cancellation_releases_a_pending_submission() -> anyhow::Result<()> {
        let (connector, safe, _) = setup(HoprBalance::new_base(5)).await?;
        connector.faults().set(ChainOp::SetSafeAllowance, Fault::Hang);
        let (handle, state) = start(&connector)?;
        let state_lifetime = Arc::downgrade(&state);
        drop(state);
        eventually(|| async { connector.faults().calls(ChainOp::SetSafeAllowance) == 1 }).await?;
        handle.abort();
        assert!(handle.await.unwrap_err().is_cancelled());

        // A detached submission would still own the strategy's state after cancellation.
        assert!(state_lifetime.upgrade().is_none());
        assert_eq!(allowance(&connector, safe).await?, HoprBalance::new_base(5));
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn cancellation_releases_confirmation_before_restart() -> anyhow::Result<()> {
        let (connector, safe, _) = setup(HoprBalance::new_base(5)).await?;
        connector
            .faults()
            .set_confirmation(ChainOp::SetSafeAllowance, Fault::Hang);
        let (handle, _) = start(&connector)?;
        eventually(|| async { connector.faults().peak_in_flight(ChainOp::SetSafeAllowance) == 1 }).await?;
        handle.abort();
        assert!(handle.await.unwrap_err().is_cancelled());

        connector.client().update_safe_allowance(
            &safe.into(),
            blokli_client::api::types::TokenValueString(HoprBalance::new_base(5).to_string()),
        );
        let (restarted, _) = start(&connector)?;
        eventually(|| async { connector.faults().calls(ChainOp::SetSafeAllowance) == 2 }).await?;
        eventually(|| async { allowance(&connector, safe).await.ok() == Some(HoprBalance::new_base(100)) }).await?;
        restarted.abort();
        assert!(restarted.await.unwrap_err().is_cancelled());
        assert_eq!(
            connector.faults().peak_in_flight(ChainOp::SetSafeAllowance),
            1,
            "the cancelled confirmation must release its local in-flight guard",
        );
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn should_retry_failed_approval_on_next_tick() -> anyhow::Result<()> {
        let (connector, safe, _) = setup(HoprBalance::new_base(5)).await?;
        connector.faults().set(ChainOp::SetSafeAllowance, Fault::Fail);
        let (handle, state) = start(&connector)?;

        eventually(|| async { connector.faults().calls(ChainOp::SetSafeAllowance) >= 1 }).await?;
        eventually(|| async { state.load(Ordering::Relaxed) == StrategyState::Degraded }).await?;
        assert_eq!(allowance(&connector, safe).await?, HoprBalance::new_base(5));

        connector.faults().clear(ChainOp::SetSafeAllowance);
        eventually(|| async { allowance(&connector, safe).await.ok() == Some(HoprBalance::new_base(100)) }).await?;
        eventually(|| async { state.load(Ordering::Relaxed) == StrategyState::Running }).await?;
        handle.abort();

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn should_retry_failed_confirmation_on_next_tick() -> anyhow::Result<()> {
        let (connector, safe, _) = setup(HoprBalance::new_base(5)).await?;
        connector
            .faults()
            .set_confirmation(ChainOp::SetSafeAllowance, Fault::Fail);
        // The simulated transaction lands on submission; undo it to model a reverted transaction.
        let (handle, _) = start(&connector)?;
        eventually(|| async { connector.faults().calls(ChainOp::SetSafeAllowance) == 1 }).await?;
        connector.client().update_safe_allowance(
            &safe.into(),
            blokli_client::api::types::TokenValueString(HoprBalance::new_base(5).to_string()),
        );

        connector.faults().clear(ChainOp::SetSafeAllowance);
        eventually(|| async { connector.faults().calls(ChainOp::SetSafeAllowance) == 2 }).await?;
        eventually(|| async { allowance(&connector, safe).await.ok() == Some(HoprBalance::new_base(100)) }).await?;
        handle.abort();

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn should_keep_checking_periodically_without_allowance_events() -> anyhow::Result<()> {
        let (connector, safe, _) = setup(HoprBalance::new_base(50)).await?;
        connector.faults().withhold_event(EventKind::SafeAllowanceChanged);
        let (handle, _) = start(&connector)?;
        tokio::time::sleep(INTERVAL).await;

        // Without events, the drop below the threshold is found by the periodic check.
        connector.client().update_safe_allowance(
            &safe.into(),
            blokli_client::api::types::TokenValueString(HoprBalance::new_base(3).to_string()),
        );
        eventually(|| async { allowance(&connector, safe).await.ok() == Some(HoprBalance::new_base(100)) }).await?;
        handle.abort();

        assert_eq!(connector.faults().calls(ChainOp::SetSafeAllowance), 1);
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn should_ignore_allowance_updates_above_threshold_and_of_other_safes() -> anyhow::Result<()> {
        let (connector, safe, _) = setup(HoprBalance::new_base(50)).await?;
        let mut strategy = AutoApprovalStrategy::new(config(), Duration::from_secs(3600))
            .build(Arc::new(ChainNode(connector.clone())))?;
        let handle = tokio::spawn(async move {
            let _ = strategy.run().await;
        });
        tokio::time::sleep(INTERVAL).await;

        connector.client().update_safe_allowance(
            &[9u8; Address::SIZE],
            blokli_client::api::types::TokenValueString(HoprBalance::zero().to_string()),
        );
        connector.client().update_safe_allowance(
            &safe.into(),
            blokli_client::api::types::TokenValueString(HoprBalance::new_base(20).to_string()),
        );
        tokio::time::sleep(INTERVAL * 2).await;
        handle.abort();

        assert_eq!(connector.faults().calls(ChainOp::SetSafeAllowance), 0);
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn build_should_reject_invalid_configuration() -> anyhow::Result<()> {
        let (connector, ..) = setup(HoprBalance::new_base(50)).await?;
        let node = Arc::new(ChainNode(connector));

        for (threshold, amount) in [(0, 100), (10, 0), (10, 9), (10, 10)] {
            let cfg = AutoApprovalStrategyConfig {
                min_allowance_threshold: HoprBalance::new_base(threshold),
                allowance_amount: HoprBalance::new_base(amount),
            };
            assert!(
                matches!(
                    AutoApprovalStrategy::new(cfg, INTERVAL).build(node.clone()),
                    Err(StrategyError::InvalidConfiguration(_))
                ),
                "threshold {threshold} and amount {amount} must be rejected"
            );
        }

        assert!(matches!(
            AutoApprovalStrategy::new(config(), Duration::ZERO).build(node.clone()),
            Err(StrategyError::InvalidConfiguration(_))
        ));

        let strategy = AutoApprovalStrategy::new(AutoApprovalStrategyConfig::default(), INTERVAL).build(node)?;
        assert_eq!(strategy.to_string(), "auto_approval");
        Ok(())
    }

    #[test]
    fn config_should_round_trip_and_use_defaults() -> anyhow::Result<()> {
        let default = AutoApprovalStrategyConfig::default();
        assert_eq!(default.min_allowance_threshold, HoprBalance::new_base(100));
        assert_eq!(default.allowance_amount, HoprBalance::new_base(1000));
        assert!(default.validate().is_ok());
        assert_eq!(
            serde_json::from_str::<AutoApprovalStrategyConfig>(&serde_json::to_string(&default)?)?,
            default
        );

        let cfg: AutoApprovalStrategyConfig =
            serde_json::from_str(r#"{"min_allowance_threshold":"37.5 wxHOPR","allowance_amount":"1000000 wxHOPR"}"#)?;
        assert_eq!(cfg.min_allowance_threshold.to_string(), "37.5 wxHOPR");
        assert!(cfg.validate().is_ok());
        Ok(())
    }
}
