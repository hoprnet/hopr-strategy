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
        primitive::prelude::{Address, HoprBalance, XDaiBalance},
    },
};
use hopr_strategy::testing::{
    BlokliTestStateBuilder, TestGraph, TestNetworkView, create_test_blokli_connector, register_test_safe,
};

use super::{IntegrationFixture, TestAccount, module_address, poll_stable, poll_until};
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

/// A scenario with several open channels from one source to distinct
/// destinations, all visible to a single connector attached to the source.
///
/// Used by tests that need more concurrent channels than the strategy's
/// `concurrency.max_concurrent_actions` budget allows.
pub struct MultiChannelScenario {
    pub connector: Arc<NodeConnector>,
    pub source_addr: Address,
    pub destination_addrs: Vec<Address>,
    /// Channels as first seen by the connector, in `destination_addrs` order.
    pub initial: Vec<ChannelEntry>,
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

        // Pass both addresses in a single call since `with_generated_accounts`
        // assigns key IDs sequentially starting from 0 and cannot be called twice
        // (the second call would reuse key ID 0 and panic).
        let client = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&source.address, &destination.address],
                true,
                XDaiBalance::new_base(1u32),
                opts.source_funding,
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

impl IntegrationFixture {
    /// Builds initial stub state with one source, `destinations.len()` peers, and
    /// an open channel from the source to each of them.  The returned connector is
    /// attached to the source and has seen every channel.
    pub async fn open_channels_scenario(
        &self,
        source: &TestAccount,
        destinations: &[TestAccount],
        stake: HoprBalance,
    ) -> Result<MultiChannelScenario> {
        use hopr_api::types::internal::prelude::{ChannelBuilder, ChannelStatus};

        let channels = destinations
            .iter()
            .map(|destination| {
                ChannelBuilder::default()
                    .between(source.address, destination.address)
                    .balance(stake)
                    .ticket_index(0u64)
                    .status(ChannelStatus::Open)
                    .epoch(0u32)
                    .build()
                    .context("failed to build initial channel")
            })
            .collect::<Result<Vec<_>>>()?;

        // `with_generated_accounts` assigns key IDs sequentially from 0 and must
        // therefore see every account in one call.
        let addresses: Vec<Address> = std::iter::once(source.address)
            .chain(destinations.iter().map(|d| d.address))
            .collect();
        let address_refs: Vec<&Address> = addresses.iter().collect();
        let allowance: HoprBalance = SAFE_ALLOWANCE.parse()?;

        let client = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &address_refs,
                true,
                XDaiBalance::new_base(1u32),
                SAFE_FUNDING.parse::<HoprBalance>()?,
            )
            .with_safe_allowances(addresses.iter().map(|address| (*address, allowance)))
            .with_channels(channels)
            .with_closure_grace_period(Duration::from_secs(2))
            .build_dynamic_client(module_address());

        let connector = create_test_blokli_connector(&source.keypair, client, module_address())
            .await
            .context("failed to connect source node")?;
        register_test_safe(&connector, source.address)
            .await
            .context("failed to register source node safe")?;
        let connector = Arc::new(connector);

        let mut initial = Vec::with_capacity(destinations.len());
        for destination in destinations {
            initial.push(
                await_channel(
                    &connector,
                    source.address,
                    destination.address,
                    self.timeouts().visibility,
                    "scenario channel visible",
                )
                .await
                .context("scenario channel never became visible")?,
            );
        }

        Ok(MultiChannelScenario {
            connector,
            source_addr: source.address,
            destination_addrs: destinations.iter().map(|d| d.address).collect(),
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

/// Polls until at least `min_count` of `source -> dest` channels over
/// `destinations` satisfy `predicate`, returning the matching channels.
///
/// The population-recovery assertion needs a *count*, not a single pair —
/// [`await_channel_where`] only ever watches one destination.
pub async fn await_channel_count_where<P>(
    connector: &Arc<NodeConnector>,
    source: Address,
    destinations: &[Address],
    min_count: usize,
    timeout: Duration,
    description: &str,
    predicate: P,
) -> Result<Vec<ChannelEntry>>
where
    P: Fn(&ChannelEntry) -> bool + Clone + Send + 'static,
{
    poll_until(description, timeout, Duration::from_millis(100), || {
        let connector = connector.clone();
        let predicate = predicate.clone();
        let destinations = destinations.to_vec();
        async move {
            let matched: Vec<ChannelEntry> = destinations
                .iter()
                .filter_map(|dest| connector.channel_by_parties(&source, dest).ok().flatten())
                .filter(|c| predicate(c))
                .collect();
            Ok((matched.len() >= min_count).then_some(matched))
        }
    })
    .await
}

// ─── Unhealthy-channel recovery scenario ─────────────────────────────────────

/// A channel the recovery scenario seeds as already `Open`, together with the
/// peer's connectivity and quality signal.
pub struct SeededChannel {
    pub peer: TestAccount,
    pub connected: bool,
    pub edge_score: f64,
    pub balance: HoprBalance,
}

/// A connected peer with no channel — an open-pass candidate the strategy may
/// pick up during recovery.
pub struct Candidate {
    pub peer: TestAccount,
    pub edge_score: f64,
}

/// A scenario with a source node holding `channels` and able to see
/// `candidates` as connected, quality-scored peers with no channel yet.
///
/// [`Self::graph`] and [`Self::network`] are live handles: mutating them
/// through [`Self::degrade`], [`Self::disconnect`] or [`Self::connect`] is
/// visible to the strategy on its very next tick, the same way
/// `graph.insert_edge` degrades a channel mid-run in the crate's own unit
/// tests.
pub struct RecoveryScenario {
    pub connector: Arc<NodeConnector>,
    pub source_addr: Address,
    pub graph: TestGraph,
    pub network: TestNetworkView,
    /// Seeded channels, in `channels` input order.
    pub initial: Vec<ChannelEntry>,
}

impl RecoveryScenario {
    /// Records a new edge-quality observation for `addr`, one second old — old
    /// enough to count as `has_probing_data()` without tripping
    /// `close_when_peer_unseen_for`. Used both to degrade a peer and, later in
    /// the same run, to heal it.
    pub fn set_quality(&self, addr: &Address, score: f64) {
        self.graph.set_edge(addr, score, Duration::from_secs(1));
    }

    pub fn disconnect(&self, addr: &Address) {
        self.network.disconnect(addr);
    }

    pub fn connect(&self, addr: &Address) {
        self.network.connect(addr);
    }
}

impl IntegrationFixture {
    /// Builds a source node with one `Open` channel per entry in `channels`
    /// and `candidates.len()` further connected, channel-less peers.
    ///
    /// Every account is created in a single `with_generated_accounts` call —
    /// required because key-id assignment is sequential from 0 and the call
    /// cannot be repeated.
    pub async fn unhealthy_channels_scenario(
        &self,
        source: &TestAccount,
        channels: &[SeededChannel],
        candidates: &[Candidate],
    ) -> Result<RecoveryScenario> {
        use hopr_api::types::internal::prelude::{ChannelBuilder, ChannelStatus};

        let channel_entries = channels
            .iter()
            .map(|seed| {
                ChannelBuilder::default()
                    .between(source.address, seed.peer.address)
                    .balance(seed.balance)
                    .ticket_index(0u64)
                    .status(ChannelStatus::Open)
                    .epoch(0u32)
                    .build()
                    .context("failed to build seeded channel")
            })
            .collect::<Result<Vec<_>>>()?;

        let addresses: Vec<Address> = std::iter::once(source.address)
            .chain(channels.iter().map(|seed| seed.peer.address))
            .chain(candidates.iter().map(|candidate| candidate.peer.address))
            .collect();
        let address_refs: Vec<&Address> = addresses.iter().collect();
        let allowance: HoprBalance = SAFE_ALLOWANCE.parse()?;

        let client = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &address_refs,
                true,
                XDaiBalance::new_base(1u32),
                SAFE_FUNDING.parse::<HoprBalance>()?,
            )
            .with_safe_allowances(addresses.iter().map(|address| (*address, allowance)))
            .with_channels(channel_entries)
            // The emulator floors this at 100 ms regardless; ZERO gets there fastest.
            .with_closure_grace_period(Duration::ZERO)
            .build_dynamic_client(module_address())
            // Recovery is measured in wall-clock time across several sequential
            // transactions (close, finalize, open); the harness's default 1 s
            // simulated confirmation delay would dominate that measurement
            // rather than the strategy's own timing logic.
            .with_tx_simulation_delay(Duration::ZERO);

        let connector = create_test_blokli_connector(&source.keypair, client, module_address())
            .await
            .context("failed to connect source node")?;
        register_test_safe(&connector, source.address)
            .await
            .context("failed to register source node safe")?;
        let connector = Arc::new(connector);

        let graph = TestGraph::new(&source.address);
        let network = TestNetworkView::new();
        for seed in channels {
            graph.set_edge(&seed.peer.address, seed.edge_score, Duration::from_secs(1));
            if seed.connected {
                network.connect(&seed.peer.address);
            }
        }
        for candidate in candidates {
            graph.set_edge(&candidate.peer.address, candidate.edge_score, Duration::from_secs(1));
            network.connect(&candidate.peer.address);
        }

        let mut initial = Vec::with_capacity(channels.len());
        for seed in channels {
            initial.push(
                await_channel(
                    &connector,
                    source.address,
                    seed.peer.address,
                    self.timeouts().visibility,
                    "scenario channel visible",
                )
                .await
                .context("scenario channel never became visible")?,
            );
        }

        Ok(RecoveryScenario {
            connector,
            source_addr: source.address,
            graph,
            network,
            initial,
        })
    }
}
