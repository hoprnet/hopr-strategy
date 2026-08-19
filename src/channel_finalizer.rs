use std::{
    fmt::{Debug, Display, Formatter},
    ops::Sub,
    sync::Arc,
    time::Duration,
};

use futures::StreamExt;
use hopr_api::{
    chain::{ChainReadChannelOperations, ChainWriteChannelOperations, ChannelSelector},
    node::HasChainApi,
    types::{internal::prelude::ChannelStatusDiscriminants, primitive::prelude::Utc},
};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};
use validator::Validate;

use crate::{errors, errors::StrategyError, strategy::Strategy as StrategyTrait};

#[cfg(all(feature = "telemetry", not(test)))]
lazy_static::lazy_static! {
    static ref METRIC_COUNT_CLOSURE_FINALIZATIONS: hopr_api::types::telemetry::SimpleCounter = hopr_api::types::telemetry::SimpleCounter::new(
        "hopr_strategy_closure_auto_finalization_count",
        "Count of channels where closure finalizing was initiated automatically"
    )
    .unwrap();
}

/// Contains configuration of the [`ClosureFinalizerStrategy`].
///
/// The field is optional and humantime-encoded; unknown keys are rejected.
///
/// ```
/// # use std::time::Duration;
/// # use hopr_strategy::channel_finalizer::ClosureFinalizerStrategyConfig as C;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// assert_eq!(
///     serde_json::from_str::<C>("{}")?.max_closure_overdue,
///     Duration::from_secs(300)
/// );
/// let cfg: C = serde_json::from_str(r#"{"max_closure_overdue":"10m"}"#)?;
/// assert_eq!(cfg.max_closure_overdue, Duration::from_secs(600));
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, smart_default::SmartDefault, Validate, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClosureFinalizerStrategyConfig {
    /// Do not attempt to finalize closure of channels that have
    /// been overdue for closure for more than this period.
    ///
    /// Default is 300 seconds.
    #[serde(with = "humantime_serde")]
    #[default(Duration::from_secs(300))]
    pub max_closure_overdue: Duration,
}

/// Builder for [`ClosureFinalizerStrategy`].
///
/// Call [`new`](ClosureFinalizerStrategy::new) with the strategy configuration,
/// then [`build`](ClosureFinalizerStrategy::build) to wire in a node and obtain a
/// runnable `Box<dyn Strategy + Send>`.
pub struct ClosureFinalizerStrategy {
    cfg: ClosureFinalizerStrategyConfig,
    interval: Duration,
}

impl ClosureFinalizerStrategy {
    /// Create a new builder with the given configuration.
    pub fn new(cfg: ClosureFinalizerStrategyConfig, interval: Duration) -> Self {
        Self { cfg, interval }
    }

    /// Wire in a node and return a running-ready strategy.
    ///
    /// The generic `N` is erased at construction time; the returned
    /// `Box<dyn Strategy + Send>` can be held and spawned without knowledge
    /// of the concrete node type.
    ///
    /// # Errors
    ///
    /// [`StrategyError::InvalidConfiguration`] if the configuration violates any
    /// of its declared constraints. Never panics.
    ///
    /// ```text
    /// let strategy = ClosureFinalizerStrategy::new(cfg, interval).build(node)?;
    /// ```
    ///
    /// `text` because `N`'s bounds need a live node, constructible only under the
    /// `testing` feature.
    pub fn build<N>(self, node: Arc<N>) -> crate::errors::Result<Box<dyn StrategyTrait + Send>>
    where
        N: HasChainApi + Send + Sync + 'static,
        N::ChainApi: ChainReadChannelOperations + ChainWriteChannelOperations + Clone + Send + Sync + 'static,
    {
        StrategyError::validate_config(&self.cfg)?;

        Ok(Box::new(ClosureFinalizerStrategyInner {
            node,
            cfg: self.cfg,
            interval: self.interval,
        }))
    }
}

/// Private generic runner — constructed by [`ClosureFinalizerStrategy::build`].
struct ClosureFinalizerStrategyInner<N: HasChainApi> {
    node: Arc<N>,
    cfg: ClosureFinalizerStrategyConfig,
    interval: Duration,
}

impl<N> ClosureFinalizerStrategyInner<N>
where
    N: HasChainApi + Send + Sync + 'static,
    <N as HasChainApi>::ChainApi:
        ChainReadChannelOperations + ChainWriteChannelOperations + Clone + Send + Sync + 'static,
{
    async fn on_tick(&self) -> errors::Result<()> {
        let now = Utc::now();
        let chain = self.node.chain_api();
        let mut outgoing_channels = chain
            .stream_channels(
                ChannelSelector::default()
                    .with_source(*chain.me())
                    .with_allowed_states(&[ChannelStatusDiscriminants::PendingToClose])
                    .with_closure_time_range(now.sub(self.cfg.max_closure_overdue)..=now),
            )
            .map_err(|e| errors::StrategyError::Other(e.into()))?;

        while let Some(channel) = outgoing_channels.next().await {
            info!(%channel, "channel closure finalizer: finalizing closure");
            match self.node.chain_api().close_channel(channel.get_id()).await {
                Ok(_) => {
                    debug!(%channel, "channel closure finalizer: submitted close transaction");
                    #[cfg(all(feature = "telemetry", not(test)))]
                    METRIC_COUNT_CLOSURE_FINALIZATIONS.increment();
                }
                Err(e) => error!(%channel, error = %e, "channel closure finalizer: failed to finalize closure"),
            }
        }

        debug!("channel closure finalizer: initiated closure finalization done");
        Ok(())
    }
}

impl<N: HasChainApi> Debug for ClosureFinalizerStrategyInner<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClosureFinalizerStrategy({:?})", self.cfg)
    }
}

impl<N: HasChainApi> Display for ClosureFinalizerStrategyInner<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "closure_finalizer")
    }
}

#[async_trait::async_trait]
impl<N> StrategyTrait for ClosureFinalizerStrategyInner<N>
where
    N: HasChainApi + Send + Sync + 'static,
    <N as HasChainApi>::ChainApi:
        ChainReadChannelOperations + ChainWriteChannelOperations + Clone + Send + Sync + 'static,
{
    async fn run(&mut self) -> errors::Result<()> {
        // Run the first scan immediately at startup without waiting for the initial interval.
        if let Err(e) = self.on_tick().await {
            tracing::error!(%e, "closure finalizer tick failed");
        }

        let tick_stream = futures_time::stream::interval(self.interval.into()).map(|_| ());

        futures::pin_mut!(tick_stream);
        while tick_stream.next().await.is_some() {
            if let Err(e) = self.on_tick().await {
                tracing::error!(%e, "closure finalizer tick failed");
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{ops::Add, sync::Arc, time::SystemTime};

    use futures::StreamExt;
    use futures_time::future::FutureExt;
    use hex_literal::hex;
    use hopr_api::{
        chain::{ChainEvent, ChainEvents},
        types::{
            crypto::{keypairs::Keypair, prelude::ChainKeypair},
            internal::prelude::{ChannelEntry, ChannelStatus},
            primitive::prelude::{Address, BytesRepresentable, HoprBalance, XDaiBalance},
        },
    };
    use lazy_static::lazy_static;

    use super::*;
    use crate::testing::{BlokliTestStateBuilder, ChainNode, create_test_blokli_connector};

    lazy_static! {
        static ref ALICE_KP: ChainKeypair = ChainKeypair::from_secret(&hex!(
            "492057cf93e99b31d2a85bc5e98a9c3aa0021feec52c227cc8170e8f7d047775"
        ))
        .expect("lazy static keypair should be valid");
        static ref ALICE: Address = ALICE_KP.public().to_address();
        static ref BOB: Address = hex!("3798fa65d6326d3813a0d33489ac35377f4496ef").into();
        static ref CHARLIE: Address = hex!("250eefb2586ab0873befe90b905126810960ee7c").into();
        static ref DAVE: Address = hex!("68499f50ff68d523385dc60686069935d17d762a").into();
        static ref EUGENE: Address = hex!("0c1da65d269f89b05e3775bf8fcd21a138e8cbeb").into();
    }

    #[tokio::test]
    async fn test_should_close_only_non_overdue_pending_to_close_channels_with_elapsed_closure() -> anyhow::Result<()> {
        let max_closure_overdue = Duration::from_secs(600);

        let channel_to_be_closed = ChannelEntry::builder()
            .between(*ALICE, *DAVE)
            .amount(10)
            .ticket_index(0)
            .status(ChannelStatus::PendingToClose(
                SystemTime::now().sub(Duration::from_secs(60)),
            ))
            .epoch(1)
            .build()?;

        let blokli_sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB, &*CHARLIE, &*DAVE, &*EUGENE],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .with_channels([
                ChannelEntry::builder()
                    .between(*ALICE, *BOB)
                    .amount(10)
                    .ticket_index(0)
                    .status(ChannelStatus::Open)
                    .epoch(0)
                    .build()?,
                ChannelEntry::builder()
                    .between(*ALICE, *CHARLIE)
                    .amount(10)
                    .ticket_index(0)
                    .status(ChannelStatus::PendingToClose(
                        SystemTime::now().add(Duration::from_secs(60)),
                    ))
                    .epoch(1)
                    .build()?,
                channel_to_be_closed,
                ChannelEntry::builder()
                    .between(*ALICE, *EUGENE)
                    .amount(10)
                    .ticket_index(0)
                    .status(ChannelStatus::PendingToClose(
                        SystemTime::now().sub(max_closure_overdue * 2),
                    ))
                    .epoch(1)
                    .build()?,
            ])
            .build_dynamic_client([1; Address::SIZE].into())
            .with_tx_simulation_delay(std::time::Duration::ZERO);

        let chain_connector =
            Arc::new(create_test_blokli_connector(&ALICE_KP, blokli_sim, [1; Address::SIZE].into()).await?);
        let events = chain_connector.subscribe()?;

        let cfg = ClosureFinalizerStrategyConfig { max_closure_overdue };

        let strat = ClosureFinalizerStrategyInner {
            node: Arc::new(ChainNode(Arc::clone(&chain_connector))),
            cfg,
            interval: Duration::from_secs(60),
        };
        strat.on_tick().await?;

        events
            .filter(|event| {
                futures::future::ready(
                    matches!(event, ChainEvent::ChannelClosed(c) if channel_to_be_closed.get_id() == c.get_id()),
                )
            })
            .next()
            .timeout(futures_time::time::Duration::from_secs(2))
            .await?;

        Ok(())
    }

    /// Tests the public builder API: `ClosureFinalizerStrategy::new(...).build(node)` must
    /// return a `Box<dyn Strategy + Send>` with the expected Display string.
    #[tokio::test]
    async fn test_build_returns_strategy_trait_object() -> anyhow::Result<()> {
        let blokli_sim = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&*ALICE, &*BOB],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(1000),
            )
            .with_channels([])
            .build_dynamic_client([1; Address::SIZE].into())
            .with_tx_simulation_delay(std::time::Duration::ZERO);

        let chain_connector = create_test_blokli_connector(&ALICE_KP, blokli_sim, [1; Address::SIZE].into()).await?;
        let node = Arc::new(ChainNode(Arc::new(chain_connector)));

        let strategy: Box<dyn crate::strategy::Strategy + Send> = super::ClosureFinalizerStrategy::new(
            ClosureFinalizerStrategyConfig::default(),
            std::time::Duration::from_secs(60),
        )
        .build(node)?;

        assert_eq!(strategy.to_string(), "closure_finalizer");
        // Verify the box is Send (compile-time check via trait object)
        fn assert_send<T: Send>(_: T) {}
        assert_send(strategy);

        Ok(())
    }
}
