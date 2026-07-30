//! Higher-level scenario setup shared by the strategy integration tests: build a
//! stub state with two accounts and an open channel between them, connect a node,
//! and the polling helpers used to observe channel state transitions.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use hopr_api::{
    chain::{ChainReadChannelOperations, ChainWriteChannelOperations},
    types::{
        crypto::prelude::Keypair,
        internal::prelude::ChannelEntry,
        primitive::prelude::{Address, BytesRepresentable, HoprBalance, XDaiBalance},
    },
};
use hopr_strategy::testing::{BlokliTestStateBuilder, create_test_blokli_connector, register_test_safe};

use super::{IntegrationFixture, TestAccount, poll_stable, poll_until};
use crate::{
    constants::{SAFE_ALLOWANCE, SAFE_FUNDING},
    strategy_node::NodeConnector,
};

/// Which end of the channel the scenario attaches its node connector to.
#[derive(Clone, Copy)]
pub enum ChannelParty {
    Source,
    Destination,
}

/// Parameters for [`IntegrationFixture::open_channel_scenario`].
pub struct ScenarioOpts {
    pub source_funding: HoprBalance,
    pub destination_funding: HoprBalance,
    pub allowance: HoprBalance,
    pub stake: HoprBalance,
    pub connect_as: ChannelParty,
}

impl ScenarioOpts {
    /// Defaults: both safes funded with `SAFE_FUNDING`, `SAFE_ALLOWANCE` approved
    /// on the source safe, connector attached to the source.
    pub fn new(stake: HoprBalance) -> Result<Self> {
        Ok(Self {
            source_funding: SAFE_FUNDING.parse()?,
            destination_funding: SAFE_FUNDING.parse()?,
            allowance: SAFE_ALLOWANCE.parse()?,
            stake,
            connect_as: ChannelParty::Source,
        })
    }
}

/// A fully set up scenario with an open source→destination channel.
/// Both source and destination connectors share the same `BlokliTestClient` state.
pub struct ChannelScenario {
    /// Node connector for the "connect_as" party (main test subject).
    pub connector: Arc<NodeConnector>,
    /// Node connector for the source (used to initiate closure from source side).
    source_connector: Arc<NodeConnector>,
    pub source_addr: Address,
    pub destination_addr: Address,
    pub initial: ChannelEntry,
}

impl ChannelScenario {
    /// Initiates outgoing channel closure from the source side.
    /// The source_connector submits `initiate_outgoing_channel_closure`; the main
    /// connector's background task receives `ChannelClosureInitiated` automatically.
    pub async fn initiate_closure(&self) -> Result<()> {
        let channel = self
            .source_connector
            .channel_by_parties(&self.source_addr, &self.destination_addr)?
            .context("channel not found for closure initiation")?;
        let confirmation = self.source_connector.close_channel(channel.get_id()).await?;
        confirmation.await?;
        Ok(())
    }
}

fn module_address() -> Address {
    Address::new(&[1u8; Address::SIZE])
}

impl IntegrationFixture {
    /// Builds initial stub state with both accounts and an open channel, connects a
    /// node to the requested party, and waits until the channel is visible to it.
    pub async fn open_channel_scenario(
        &self,
        source: &TestAccount,
        destination: &TestAccount,
        opts: ScenarioOpts,
    ) -> Result<ChannelScenario> {
        use hopr_api::types::internal::prelude::{ChannelBuilder, ChannelStatus};

        let channel = ChannelBuilder::default()
            .between(source.address, destination.address)
            .balance(opts.stake)
            .ticket_index(0u64)
            .status(ChannelStatus::Open)
            .epoch(0u32)
            .build()
            .context("failed to build initial channel")?;

        let client = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&source.address],
                true,
                XDaiBalance::new_base(1u32),
                opts.source_funding,
            )
            .with_generated_accounts(
                &[&destination.address],
                true,
                XDaiBalance::new_base(1u32),
                opts.destination_funding,
            )
            .with_safe_allowances([(source.address, opts.allowance), (destination.address, opts.allowance)])
            .with_channels([channel])
            // Use a short grace period so closure deadline elapses within the test action timeout.
            .with_closure_grace_period(Duration::from_secs(2))
            .build_dynamic_client(module_address());

        // Source and destination share the same state — clone the client.
        let source_client = client.clone();
        let dest_client = client;

        let (main_client, main_kp) = match opts.connect_as {
            ChannelParty::Source => (source_client.clone(), &source.keypair),
            ChannelParty::Destination => (dest_client.clone(), &destination.keypair),
        };

        let connector = create_test_blokli_connector(main_kp, main_client, module_address())
            .await
            .context("failed to connect main node")?;
        register_test_safe(&connector, main_kp.public().to_address())
            .await
            .context("failed to register main node safe")?;
        let connector = Arc::new(connector);

        let source_connector = create_test_blokli_connector(&source.keypair, source_client, module_address())
            .await
            .context("failed to connect source node")?;
        // Only register source safe if main connector is not already the source node.
        if main_kp.public().to_address() != source.address {
            register_test_safe(&source_connector, source.address)
                .await
                .context("failed to register source node safe")?;
        }
        let source_connector = Arc::new(source_connector);

        // Wait for the channel to be visible in the main connector's cache.
        let initial = await_channel(
            &connector,
            source.address,
            destination.address,
            self.timeouts().visibility,
            "scenario channel visible",
        )
        .await
        .context("scenario channel never became visible")?;

        Ok(ChannelScenario {
            connector,
            source_connector,
            source_addr: source.address,
            destination_addr: destination.address,
            initial,
        })
    }
}

/// Polls until `connector` reports a `from -> to` channel satisfying `predicate`.
pub async fn await_channel_where<P>(
    connector: &Arc<NodeConnector>,
    from: Address,
    to: Address,
    timeout: Duration,
    description: &str,
    predicate: P,
) -> Result<ChannelEntry>
where
    P: Fn(&ChannelEntry) -> bool + Clone + Send + 'static,
{
    poll_until(description, timeout, Duration::from_millis(100), || {
        let connector = connector.clone();
        let predicate = predicate.clone();
        async move { Ok(connector.channel_by_parties(&from, &to)?.filter(|c| predicate(c))) }
    })
    .await
}

/// Polls until a `from -> to` channel is visible, regardless of its contents.
pub async fn await_channel(
    connector: &Arc<NodeConnector>,
    from: Address,
    to: Address,
    timeout: Duration,
    description: &str,
) -> Result<ChannelEntry> {
    await_channel_where(connector, from, to, timeout, description, |_| true).await
}

/// Asserts no `from -> to` channel satisfies `predicate` for the whole `window`.
pub async fn assert_channel_never<P>(
    connector: &Arc<NodeConnector>,
    from: Address,
    to: Address,
    window: Duration,
    description: &str,
    predicate: P,
) -> Result<()>
where
    P: Fn(&ChannelEntry) -> bool + Clone + Send + 'static,
{
    poll_stable(description, window, Duration::from_millis(100), || {
        let connector = connector.clone();
        let predicate = predicate.clone();
        async move { Ok(connector.channel_by_parties(&from, &to)?.filter(|c| predicate(c))) }
    })
    .await
}
