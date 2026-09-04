//! Test-support node adapters shared by the crate's own unit tests and the
//! `hopr-strategy-integration-tests` crate.
//!
//! A chain connector is a *chain API*, not a *node*: strategies are generic over
//! the [`hopr_api::node`] traits (`HasChainApi`, `ActionableEventSource`, and for
//! the lifecycle strategy `HasNetworkView` / `HasGraphView`). These newtypes adapt
//! a bare chain connector into the minimal node surface a strategy needs, so tests
//! can drive a strategy without standing up a full `Hopr` node.
//!
//! Available to internal unit tests (`cfg(test)`) and to downstream crates that
//! enable the `testing` feature.

use std::{
    collections::HashSet,
    io,
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use blokli_client::api::{
    AccountSelector as BlokliAccountSelector, BlokliQueryClient, BlokliSubscriptionClient, BlokliTransactionClient,
    ChannelSelector, RedeemedStatsSelector, SafeSelector as BlokliSafeSelector,
};
use futures::{StreamExt, stream::BoxStream};
use hopr_api::{
    PeerId,
    chain::{
        AccountSelector, ChainEvent, ChainEvents, ChainReadAccountOperations, ChainWriteAccountOperations,
        ChainWriteTicketOperations, HoprChainApi, TicketRedeemError,
    },
    node::{
        ActionableEvent, ActionableEventDiscriminant, ActionableEventSource, ComponentStatus, ComponentStatusReporter,
        EventWaitResult, HasChainApi, HasGraphView, HasNetworkView, HasTicketManagement, NodeOnchainIdentity,
        PacketTransport, PixEvent, TicketEvent,
    },
    tickets::{ChannelStats, RedemptionResult, TicketManagement},
    types::{
        chain::prelude::{PayloadGenerator, SignableTransaction},
        crypto::{
            prelude::{Keypair, OffchainKeypair, OffchainPublicKey},
            types::Hash,
        },
        internal::prelude::{
            AccountEntry, AccountType, ChannelBuilder, ChannelId, ChannelStatus, RedeemableTicket, VerifiedTicket,
            WinningProbability, generate_channel_id,
        },
        primitive::prelude::{Address, HoprBalance, WxHOPR, XDai},
    },
};

/// Implements the (identical across adapters) `HasChainApi` surface for a node
/// newtype, given an expression yielding a `&C` reference to its chain field.
///
/// The second form takes the adapter's extra type parameters (beyond the chain
/// `C`), so an adapter carrying injectable views is covered for every choice of
/// them rather than only for their defaults.
macro_rules! impl_has_chain_api {
    ($ty:ident, |$node:ident| $chain:expr) => {
        impl_has_chain_api!($ty, <>, |$node| $chain);
    };
    ($ty:ident, <$($extra:ident),*>, |$node:ident| $chain:expr) => {
        impl<C, $($extra),*> HasChainApi for $ty<C, $($extra),*>
        where
            C: HoprChainApi + ComponentStatusReporter + Clone + Send + Sync + 'static,
        {
            type ChainApi = C;
            type ChainError = <C as HoprChainApi>::ChainError;

            fn identity(&self) -> &NodeOnchainIdentity {
                static IDENTITY: std::sync::OnceLock<NodeOnchainIdentity> = std::sync::OnceLock::new();
                IDENTITY.get_or_init(NodeOnchainIdentity::default)
            }

            fn chain_api(&self) -> &C {
                let $node = self;
                $chain
            }

            fn status(&self) -> ComponentStatus {
                let $node = self;
                $chain.component_status()
            }

            fn wait_for_on_chain_event<F>(
                &self,
                _predicate: F,
                _context: String,
                _timeout: Duration,
            ) -> EventWaitResult<Self::ChainError, Self::ChainError>
            where
                F: Fn(&ChainEvent) -> bool + Send + Sync + 'static,
            {
                unimplemented!("tests do not call wait_for_on_chain_event")
            }
        }
    };
}

/// Wraps a chain API implementor as a minimal, chain-only node.
///
/// Implements `HasChainApi` and `ActionableEventSource` — the surface required by
/// the auto-funding, auto-redeeming and closure-finalizer strategies.
pub struct ChainNode<C>(pub C);

impl_has_chain_api!(ChainNode, |node| &node.0);

impl<C> ActionableEventSource for ChainNode<C>
where
    C: ChainEvents + Send + Sync + 'static,
{
    fn subscribe_to_actionable_events(
        &self,
        _filter: Option<&[ActionableEventDiscriminant]>,
    ) -> Result<BoxStream<'static, ActionableEvent>, String> {
        Ok(self
            .0
            .subscribe()
            .map_err(|error| error.to_string())?
            .map(ActionableEvent::Chain)
            .boxed())
    }
}

/// Chain-only node augmented with the network and graph views the
/// channel-lifecycle strategy requires.
///
/// Defaults to inert views, in which case population/proactive passes that
/// consult them are expected to be neutralised in the test config. Use
/// [`LifecycleNode::with_views`] to drive those passes instead, supplying
/// [`TestGraph`] and [`TestNetworkView`].
pub struct LifecycleNode<C, G = EmptyGraph, V = EmptyNetworkView> {
    chain: C,
    graph: G,
    network: V,
}

impl<C> LifecycleNode<C> {
    /// Wraps `chain` with inert views that report no peers and no edges.
    pub fn new(chain: C) -> Self {
        Self {
            chain,
            graph: EmptyGraph,
            network: EmptyNetworkView,
        }
    }
}

impl<C, G, V> LifecycleNode<C, G, V> {
    /// Wraps `chain` with programmable `graph` and `network` views.
    ///
    /// Required by any test exercising the open pass or a quality-driven close:
    /// both read peer state exclusively through these two views.
    pub fn with_views(chain: C, graph: G, network: V) -> Self {
        Self { chain, graph, network }
    }
}

impl_has_chain_api!(LifecycleNode, <G, V>, |node| &node.chain);

impl<C, G, V> ActionableEventSource for LifecycleNode<C, G, V>
where
    C: ChainEvents + Send + Sync + 'static,
{
    fn subscribe_to_actionable_events(
        &self,
        _filter: Option<&[ActionableEventDiscriminant]>,
    ) -> Result<BoxStream<'static, ActionableEvent>, String> {
        Ok(self
            .chain
            .subscribe()
            .map_err(|error| error.to_string())?
            .map(ActionableEvent::Chain)
            .boxed())
    }
}

impl<C, G, V> HasNetworkView for LifecycleNode<C, G, V>
where
    C: HoprChainApi + ComponentStatusReporter + Clone + Send + Sync + 'static,
    V: hopr_api::network::NetworkView + Send + Sync + 'static,
{
    type NetworkView = V;

    fn network_view(&self) -> &Self::NetworkView {
        &self.network
    }

    fn status(&self) -> ComponentStatus {
        ComponentStatus::Ready
    }
}

impl<C, G, V> HasGraphView for LifecycleNode<C, G, V>
where
    C: HoprChainApi + ComponentStatusReporter + Clone + Send + Sync + 'static,
    G: hopr_api::graph::NetworkGraphView<NodeId = OffchainPublicKey>
        + hopr_api::graph::NetworkGraphConnectivity<NodeId = OffchainPublicKey>
        + hopr_api::graph::NetworkGraphTraverse<NodeId = OffchainPublicKey>
        + Send
        + Sync
        + 'static,
{
    type Graph = G;

    fn graph(&self) -> &Self::Graph {
        &self.graph
    }

    fn status(&self) -> ComponentStatus {
        ComponentStatus::Ready
    }
}

impl<C: PacketTransport> PacketTransport for ChainNode<C> {
    fn packet_payload_size() -> usize {
        C::packet_payload_size()
    }
}

impl<C: PacketTransport, G, V> PacketTransport for LifecycleNode<C, G, V> {
    fn packet_payload_size() -> usize {
        C::packet_payload_size()
    }
}

/// A network view that reports no peers and `Red` health.
pub struct EmptyNetworkView;

impl hopr_api::network::NetworkView for EmptyNetworkView {
    fn listening_as(&self) -> HashSet<hopr_api::Multiaddr> {
        HashSet::new()
    }

    fn multiaddress_of(&self, _peer: &PeerId) -> Option<HashSet<hopr_api::Multiaddr>> {
        None
    }

    fn discovered_peers(&self) -> HashSet<PeerId> {
        HashSet::new()
    }

    fn connected_peers(&self) -> HashSet<PeerId> {
        HashSet::new()
    }

    fn is_connected(&self, _peer: &PeerId) -> bool {
        false
    }

    fn health(&self) -> hopr_api::network::Health {
        hopr_api::network::Health::Red
    }

    fn subscribe_network_events(
        &self,
    ) -> impl futures::Stream<Item = hopr_api::network::NetworkEvent> + Send + 'static {
        futures::stream::pending()
    }
}

/// A network graph with no nodes and no edges.
#[derive(Clone)]
pub struct EmptyGraph;

#[derive(Clone)]
pub struct EmptyEdge;

pub struct EmptyMeasurement;

impl hopr_api::graph::NetworkGraphView for EmptyGraph {
    type NodeId = OffchainPublicKey;
    type Observed = EmptyEdge;

    fn ticket_face_value(&self) -> Option<hopr_api::graph::traits::Balance> {
        None
    }

    fn path_slot(&self, _key: &Self::NodeId) -> Option<u64> {
        None
    }

    fn node_count(&self) -> usize {
        0
    }

    fn contains_node(&self, _key: &Self::NodeId) -> bool {
        false
    }

    fn nodes(&self) -> BoxStream<'static, Self::NodeId> {
        futures::stream::empty().boxed()
    }

    fn edge(&self, _src: &Self::NodeId, _dest: &Self::NodeId) -> Option<Self::Observed> {
        None
    }

    fn identity(&self) -> &Self::NodeId {
        static KEY: std::sync::OnceLock<OffchainPublicKey> = std::sync::OnceLock::new();
        KEY.get_or_init(|| *OffchainKeypair::from_secret(&[1; 32]).expect("valid test key").public())
    }
}

impl hopr_api::graph::NetworkGraphConnectivity for EmptyGraph {
    type NodeId = OffchainPublicKey;
    type Observed = EmptyEdge;

    fn connected_edges(&self) -> Vec<(Self::NodeId, Self::NodeId, Self::Observed)> {
        Vec::new()
    }

    fn reachable_edges(&self) -> Vec<(Self::NodeId, Self::NodeId, Self::Observed)> {
        Vec::new()
    }
}

impl hopr_api::graph::NetworkGraphTraverse for EmptyGraph {
    type NodeId = OffchainPublicKey;
    type Observed = EmptyEdge;

    fn simple_paths<V: hopr_api::graph::ValueFn<Weight = Self::Observed>>(
        &self,
        _source: &Self::NodeId,
        _destination: &Self::NodeId,
        _length: usize,
        _take_count: Option<usize>,
        _value_fn: V,
    ) -> Vec<(Vec<Self::NodeId>, [u64; 5], V::Value)> {
        Vec::new()
    }

    fn simple_paths_from<V: hopr_api::graph::ValueFn<Weight = Self::Observed>>(
        &self,
        _source: &Self::NodeId,
        _length: usize,
        _take_count: Option<usize>,
        _value_fn: V,
    ) -> Vec<(Vec<Self::NodeId>, [u64; 5], V::Value)> {
        Vec::new()
    }

    fn simple_loopback_to_self(
        &self,
        _length: usize,
        _take_count: Option<usize>,
    ) -> Vec<(Vec<Self::NodeId>, [u64; 5])> {
        Vec::new()
    }
}

impl hopr_api::graph::EdgeObservableRead for EmptyEdge {
    type ImmediateMeasurement = EmptyMeasurement;
    type IntermediateMeasurement = EmptyMeasurement;

    fn last_update(&self) -> Duration {
        Duration::ZERO
    }

    fn immediate_qos(&self) -> Option<&Self::ImmediateMeasurement> {
        None
    }

    fn intermediate_qos(&self) -> Option<&Self::IntermediateMeasurement> {
        None
    }

    fn score(&self) -> Option<f64> {
        None
    }
}

impl hopr_api::graph::traits::EdgeObservableWrite for EmptyEdge {
    fn record(&mut self, _measurement: hopr_api::graph::traits::EdgeWeightType) {}
}

impl hopr_api::graph::EdgeLinkObservable for EmptyMeasurement {
    fn record(&mut self, _measurement: hopr_api::graph::traits::EdgeTransportMeasurement) {}

    fn average_latency(&self) -> Option<Duration> {
        None
    }

    fn average_probe_rate(&self) -> Option<f64> {
        None
    }

    fn score(&self) -> Option<f64> {
        None
    }
}

impl hopr_api::graph::traits::EdgeNetworkObservableRead for EmptyMeasurement {
    fn is_connected(&self) -> Option<bool> {
        None
    }
}

impl hopr_api::graph::EdgeImmediateProtocolObservable for EmptyMeasurement {
    fn ack_rate(&self) -> Option<f64> {
        None
    }
}

impl hopr_api::graph::traits::EdgeProtocolObservable for EmptyMeasurement {
    fn balance(&self) -> Option<hopr_api::graph::traits::Balance> {
        None
    }
}

// ─── Programmable network and graph views ────────────────────────────────────

/// Off-chain key `BlokliTestStateBuilder::with_generated_accounts` derives for `addr`.
///
/// Peer state reaches a strategy keyed by off-chain key or `PeerId`, while tests
/// address peers by chain address; this is the bridge between the two.
pub fn test_offchain_key(addr: &Address) -> OffchainPublicKey {
    let pseudo_secret = Hash::create(&[addr.as_ref()]);
    *OffchainKeypair::from_secret(pseudo_secret.as_ref())
        .expect("hash output is a valid off-chain secret")
        .public()
}

/// `PeerId` of the account `addr`, matching [`test_offchain_key`].
pub fn test_peer_id(addr: &Address) -> PeerId {
    PeerId::from(&test_offchain_key(addr))
}

/// A network view whose connected peer set is settable while a strategy runs.
///
/// The open pass draws its candidates from `connected_peers`, and connectivity
/// also decides whether a channel is shielded during the startup observation
/// window — neither is expressible with [`EmptyNetworkView`], which reports no
/// peers at all.
#[derive(Clone, Default)]
pub struct TestNetworkView {
    connected: Arc<dashmap::DashSet<PeerId>>,
}

impl TestNetworkView {
    /// An empty view: every peer counts as disconnected.
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks `addr` as currently connected.
    pub fn connect(&self, addr: &Address) {
        self.connected.insert(test_peer_id(addr));
    }

    /// Marks `addr` as no longer connected.
    pub fn disconnect(&self, addr: &Address) {
        self.connected.remove(&test_peer_id(addr));
    }
}

impl hopr_api::network::NetworkView for TestNetworkView {
    fn listening_as(&self) -> HashSet<hopr_api::Multiaddr> {
        HashSet::new()
    }

    /// Always `None`, so every peer lands in `SubnetBucket::Unknown`.
    ///
    /// Only the multi-objective selector buckets by subnet; tests needing that
    /// diversity axis have to extend this view.
    fn multiaddress_of(&self, _peer: &PeerId) -> Option<HashSet<hopr_api::Multiaddr>> {
        None
    }

    fn discovered_peers(&self) -> HashSet<PeerId> {
        self.connected_peers()
    }

    fn connected_peers(&self) -> HashSet<PeerId> {
        self.connected.iter().map(|peer| *peer).collect()
    }

    fn is_connected(&self, peer: &PeerId) -> bool {
        self.connected.contains(peer)
    }

    /// Reports `Green`: a view with a settable peer set models a network that
    /// has finished bootstrapping.
    fn health(&self) -> hopr_api::network::Health {
        hopr_api::network::Health::Green
    }

    fn subscribe_network_events(
        &self,
    ) -> impl futures::Stream<Item = hopr_api::network::NetworkEvent> + Send + 'static {
        futures::stream::pending()
    }
}

/// A network graph whose per-peer edge observations are settable while a
/// strategy runs.
///
/// Quality-driven closes and the open pass's eligibility gate both read
/// `edge(identity, peer).score()`, which [`EmptyGraph`] leaves unset.
#[derive(Clone)]
pub struct TestGraph {
    identity: OffchainPublicKey,
    edges: Arc<dashmap::DashMap<(OffchainPublicKey, OffchainPublicKey), TestEdge>>,
}

impl TestGraph {
    /// A graph rooted at `node_addr`, the address of the node under test.
    ///
    /// The root must match, or edges recorded here are invisible to the
    /// strategy: it only ever queries edges outgoing from its own identity.
    pub fn new(node_addr: &Address) -> Self {
        Self {
            identity: test_offchain_key(node_addr),
            edges: Arc::new(dashmap::DashMap::new()),
        }
    }

    /// Records an observation of the edge to `addr`, replacing any previous one.
    ///
    /// `last_update` is the *age* of the observation and must be non-zero for a
    /// quality-driven close: `Duration::ZERO` reads as "never probed", which
    /// suppresses closure entirely.
    pub fn set_edge(&self, addr: &Address, score: f64, last_update: Duration) {
        self.edges.insert(
            (self.identity, test_offchain_key(addr)),
            TestEdge { score, last_update },
        );
    }
}

/// A single programmable edge observation of [`TestGraph`].
#[derive(Clone)]
pub struct TestEdge {
    score: f64,
    last_update: Duration,
}

impl hopr_api::graph::NetworkGraphView for TestGraph {
    type NodeId = OffchainPublicKey;
    type Observed = TestEdge;

    fn ticket_face_value(&self) -> Option<hopr_api::graph::traits::Balance> {
        None
    }

    fn path_slot(&self, _key: &Self::NodeId) -> Option<u64> {
        None
    }

    fn node_count(&self) -> usize {
        self.edges.len()
    }

    fn contains_node(&self, key: &Self::NodeId) -> bool {
        self.edges.iter().any(|entry| entry.key().1 == *key)
    }

    fn nodes(&self) -> BoxStream<'static, Self::NodeId> {
        let nodes: Vec<_> = self.edges.iter().map(|entry| entry.key().1).collect();
        futures::stream::iter(nodes).boxed()
    }

    fn edge(&self, src: &Self::NodeId, dest: &Self::NodeId) -> Option<Self::Observed> {
        self.edges.get(&(*src, *dest)).map(|entry| entry.clone())
    }

    fn identity(&self) -> &Self::NodeId {
        &self.identity
    }
}

impl hopr_api::graph::NetworkGraphConnectivity for TestGraph {
    type NodeId = OffchainPublicKey;
    type Observed = TestEdge;

    fn connected_edges(&self) -> Vec<(Self::NodeId, Self::NodeId, Self::Observed)> {
        Vec::new()
    }

    fn reachable_edges(&self) -> Vec<(Self::NodeId, Self::NodeId, Self::Observed)> {
        Vec::new()
    }
}

/// Traversal is unimplemented: the channel-lifecycle strategy reads individual
/// edges and never plans paths, so every method yields nothing.
impl hopr_api::graph::NetworkGraphTraverse for TestGraph {
    type NodeId = OffchainPublicKey;
    type Observed = TestEdge;

    fn simple_paths<V: hopr_api::graph::ValueFn<Weight = Self::Observed>>(
        &self,
        _source: &Self::NodeId,
        _destination: &Self::NodeId,
        _length: usize,
        _take_count: Option<usize>,
        _value_fn: V,
    ) -> Vec<(Vec<Self::NodeId>, [u64; 5], V::Value)> {
        Vec::new()
    }

    fn simple_paths_from<V: hopr_api::graph::ValueFn<Weight = Self::Observed>>(
        &self,
        _source: &Self::NodeId,
        _length: usize,
        _take_count: Option<usize>,
        _value_fn: V,
    ) -> Vec<(Vec<Self::NodeId>, [u64; 5], V::Value)> {
        Vec::new()
    }

    fn simple_loopback_to_self(
        &self,
        _length: usize,
        _take_count: Option<usize>,
    ) -> Vec<(Vec<Self::NodeId>, [u64; 5])> {
        Vec::new()
    }
}

impl hopr_api::graph::EdgeObservableRead for TestEdge {
    type ImmediateMeasurement = EmptyMeasurement;
    type IntermediateMeasurement = EmptyMeasurement;

    fn last_update(&self) -> Duration {
        self.last_update
    }

    fn immediate_qos(&self) -> Option<&Self::ImmediateMeasurement> {
        None
    }

    fn intermediate_qos(&self) -> Option<&Self::IntermediateMeasurement> {
        None
    }

    fn score(&self) -> Option<f64> {
        Some(self.score)
    }
}

impl hopr_api::graph::traits::EdgeObservableWrite for TestEdge {
    fn record(&mut self, _measurement: hopr_api::graph::traits::EdgeWeightType) {}
}

// ─── Test chain connector ────────────────────────────────────────────────────

pub use blokli_client::exports::Entry;
/// Re-exports of blokli testing types.
pub use blokli_client::{BlokliTestClient, BlokliTestState, BlokliTestStateMutator, BlokliTestStateSnapshot};
/// Re-exports of Blokli testing types now provided by `hopr-utilities`.
pub use hopr_utils::testing::blokli::{
    BlokliTestStateBuilder, ChainInfo, ChainMutator, FullStateEmulator, StaticState,
};

/// Concrete error type used by [`TestChainConnector`] trait implementations.
///
/// The chain API traits require `Error: std::error::Error + Send + Sync + 'static`.
/// `anyhow::Error` does not implement `std::error::Error` directly, so this
/// transparent newtype bridges the gap.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct TestConnectorError(#[from] anyhow::Error);

impl From<blokli_client::errors::BlokliClientError> for TestConnectorError {
    fn from(e: blokli_client::errors::BlokliClientError) -> Self {
        Self(anyhow::anyhow!("{e}"))
    }
}

impl From<hopr_api::types::primitive::prelude::GeneralError> for TestConnectorError {
    fn from(e: hopr_api::types::primitive::prelude::GeneralError) -> Self {
        Self(anyhow::anyhow!("{e}"))
    }
}

impl From<hopr_api::types::chain::errors::ChainTypesError> for TestConnectorError {
    fn from(e: hopr_api::types::chain::errors::ChainTypesError) -> Self {
        Self(anyhow::anyhow!("{e}"))
    }
}

impl From<hopr_api::types::internal::prelude::CoreTypesError> for TestConnectorError {
    fn from(e: hopr_api::types::internal::prelude::CoreTypesError) -> Self {
        Self(anyhow::anyhow!("{e}"))
    }
}

/// In-memory ticket store backed by live on-chain redemption, for driving the
/// auto-redeeming strategy. Tickets are queued in memory; redemption itself goes
/// through the real chain connector supplied to [`TicketManagement::redeem_stream`].
#[derive(Clone, Default)]
pub struct LiveTicketManager {
    tickets: Arc<Mutex<Vec<RedeemableTicket>>>,
}

impl LiveTicketManager {
    pub fn with_ticket(ticket: RedeemableTicket) -> Self {
        Self {
            tickets: Arc::new(Mutex::new(vec![ticket])),
        }
    }

    /// Returns a clone of the first queued ticket, if any. Used to synthesize a
    /// winning-ticket event for a ticket that is already queued for redemption.
    pub fn first_ticket(&self) -> Option<RedeemableTicket> {
        self.tickets.lock().ok()?.first().cloned()
    }
}

fn ticket_error<E: std::fmt::Display>(error: E) -> io::Error {
    io::Error::other(error.to_string())
}

impl TicketManagement for LiveTicketManager {
    type Error = io::Error;

    #[allow(refining_impl_trait)]
    fn redeem_stream<C: ChainWriteTicketOperations + Send + Sync + 'static>(
        &self,
        client: C,
        channel_id: ChannelId,
        min_amount: Option<HoprBalance>,
    ) -> Result<BoxStream<'static, Result<RedemptionResult, Self::Error>>, Self::Error> {
        let selected = {
            let mut tickets = self
                .tickets
                .lock()
                .map_err(|_| io::Error::other("ticket queue poisoned"))?;
            let (selected, retained) = tickets
                .drain(..)
                .partition(|ticket| ticket.ticket.channel_id() == &channel_id);
            *tickets = retained;
            selected
        };

        Ok(futures::stream::unfold(
            (client, selected.into_iter()),
            move |(client, mut tickets)| async move {
                let ticket = tickets.next()?;
                let result = if min_amount.is_some_and(|minimum| ticket.verified_ticket().amount < minimum) {
                    Ok(RedemptionResult::ValueTooLow(ticket.ticket))
                } else {
                    match client.redeem_ticket(ticket).await {
                        Ok(confirmation) => match confirmation.await {
                            Ok((ticket, _receipt)) => Ok(RedemptionResult::Redeemed(ticket)),
                            Err(TicketRedeemError::Rejected(ticket, reason)) => {
                                Ok(RedemptionResult::RejectedOnChain(ticket, reason))
                            }
                            Err(TicketRedeemError::ProcessingError(_ticket, error)) => Err(ticket_error(error)),
                        },
                        Err(TicketRedeemError::Rejected(ticket, reason)) => {
                            Ok(RedemptionResult::RejectedOnChain(ticket, reason))
                        }
                        Err(TicketRedeemError::ProcessingError(_ticket, error)) => Err(ticket_error(error)),
                    }
                };
                Some((result, (client, tickets)))
            },
        )
        .boxed())
    }

    fn neglect_tickets(
        &self,
        channel_id: &ChannelId,
        max_ticket_index: Option<u64>,
    ) -> Result<Vec<VerifiedTicket>, Self::Error> {
        let mut tickets = self
            .tickets
            .lock()
            .map_err(|_| io::Error::other("ticket queue poisoned"))?;
        let (neglected, retained): (Vec<_>, Vec<_>) = tickets.drain(..).partition(|ticket| {
            ticket.ticket.channel_id() == channel_id
                && max_ticket_index.is_none_or(|max| ticket.verified_ticket().index <= max)
        });
        *tickets = retained;
        Ok(neglected.into_iter().map(|ticket| ticket.ticket).collect())
    }

    fn ticket_stats(&self, channel_id: Option<&ChannelId>) -> Result<ChannelStats, Self::Error> {
        let tickets = self
            .tickets
            .lock()
            .map_err(|_| io::Error::other("ticket queue poisoned"))?;
        let mut stats = ChannelStats::default();
        for ticket in tickets
            .iter()
            .filter(|ticket| channel_id.is_none_or(|id| ticket.ticket.channel_id() == id))
        {
            stats.winning_tickets += 1;
            stats.unredeemed_value += ticket.verified_ticket().amount;
        }
        Ok(stats)
    }

    fn insert_incoming_ticket(&self, ticket: RedeemableTicket) -> Result<Vec<VerifiedTicket>, Self::Error> {
        self.tickets
            .lock()
            .map_err(|_| io::Error::other("ticket queue poisoned"))?
            .push(ticket);
        Ok(Vec::new())
    }
}

/// Chain-only node augmented with ticket management, as required by the
/// auto-redeeming strategy.
pub struct TicketNode<C> {
    chain: C,
    tickets: LiveTicketManager,
    /// Sender for events injected via [`TicketNode::inject_winning_ticket`].
    injected_tx: futures::channel::mpsc::UnboundedSender<ActionableEvent>,
    /// Receiver, taken on the first `subscribe_to_actionable_events` call and
    /// merged into the actionable-event stream.
    injected_rx: Mutex<Option<futures::channel::mpsc::UnboundedReceiver<ActionableEvent>>>,
}

impl<C> TicketNode<C> {
    pub fn new(chain: C, tickets: LiveTicketManager) -> Self {
        let (injected_tx, injected_rx) = futures::channel::mpsc::unbounded();
        Self {
            chain,
            tickets,
            injected_tx,
            injected_rx: Mutex::new(Some(injected_rx)),
        }
    }

    /// Emits a `WinningTicket` actionable event for the first queued ticket,
    /// mirroring what the real node's event source produces when an acknowledged
    /// winning ticket arrives. Drives the strategy's `redeem_on_winning` path.
    /// No-op if the ticket queue is empty.
    pub fn inject_winning_ticket(&self) {
        if let Some(ticket) = self.tickets.first_ticket() {
            let _ = self
                .injected_tx
                .unbounded_send(ActionableEvent::Ticket(TicketEvent::WinningTicket(Box::new(ticket))));
        }
    }
}

impl_has_chain_api!(TicketNode, |node| &node.chain);

impl<C> HasTicketManagement for TicketNode<C>
where
    C: Send + Sync + 'static,
{
    type TicketManager = LiveTicketManager;

    fn ticket_management(&self) -> &Self::TicketManager {
        &self.tickets
    }

    fn subscribe_ticket_events(&self) -> impl futures::Stream<Item = TicketEvent> + Send + 'static {
        futures::stream::empty()
    }

    fn status(&self) -> ComponentStatus {
        ComponentStatus::Ready
    }
}

impl<C> ActionableEventSource for TicketNode<C>
where
    C: ChainEvents + Send + Sync + 'static,
{
    fn subscribe_to_actionable_events(
        &self,
        _filter: Option<&[ActionableEventDiscriminant]>,
    ) -> Result<BoxStream<'static, ActionableEvent>, String> {
        let chain = self
            .chain
            .subscribe()
            .map_err(|error| error.to_string())?
            .map(ActionableEvent::Chain);
        // Merge in injected ticket events on the first subscription so the
        // `redeem_on_winning` path can be driven from tests.
        match self.injected_rx.lock().expect("injected event lock poisoned").take() {
            Some(injected) => Ok(futures::stream::select(chain, injected).boxed()),
            None => Ok(chain.boxed()),
        }
    }
}

/// Chain-only node with a caller-supplied on-chain identity and an injectable
/// PIX event stream, as required by the PIX strategy.
///
/// Unlike the other adapters, the [`NodeOnchainIdentity`] is held per instance
/// rather than served from a `static` cell. The PIX strategy captures
/// `identity().safe_address` at build time as the sweep destination, so a shared
/// identity would make every test in a binary sweep into the first test's safe.
pub struct PixNode<C> {
    chain: C,
    identity: NodeOnchainIdentity,
    /// Sender for events injected via [`PixNode::inject_pix`].
    injected_tx: futures::channel::mpsc::UnboundedSender<ActionableEvent>,
    /// Receiver, taken on the first `subscribe_to_actionable_events` call and
    /// merged into the actionable-event stream.
    injected_rx: Mutex<Option<futures::channel::mpsc::UnboundedReceiver<ActionableEvent>>>,
}

impl<C> PixNode<C> {
    pub fn new(chain: C, identity: NodeOnchainIdentity) -> Self {
        let (injected_tx, injected_rx) = futures::channel::mpsc::unbounded();
        Self {
            chain,
            identity,
            injected_tx,
            injected_rx: Mutex::new(Some(injected_rx)),
        }
    }

    /// Emits a PIX actionable event, mirroring what the real node's event source
    /// produces. The unbounded channel buffers it, so injecting before the
    /// strategy has subscribed is safe.
    pub fn inject_pix(&self, event: PixEvent) {
        let _ = self.injected_tx.unbounded_send(ActionableEvent::Pix(event));
    }
}

impl<C> HasChainApi for PixNode<C>
where
    C: HoprChainApi + ComponentStatusReporter + Clone + Send + Sync + 'static,
{
    type ChainApi = C;
    type ChainError = <C as HoprChainApi>::ChainError;

    fn identity(&self) -> &NodeOnchainIdentity {
        &self.identity
    }

    fn chain_api(&self) -> &C {
        &self.chain
    }

    fn status(&self) -> ComponentStatus {
        self.chain.component_status()
    }

    fn wait_for_on_chain_event<F>(
        &self,
        _predicate: F,
        _context: String,
        _timeout: Duration,
    ) -> EventWaitResult<Self::ChainError, Self::ChainError>
    where
        F: Fn(&ChainEvent) -> bool + Send + Sync + 'static,
    {
        unimplemented!("tests do not call wait_for_on_chain_event")
    }
}

impl<C> ActionableEventSource for PixNode<C>
where
    C: ChainEvents + Send + Sync + 'static,
{
    fn subscribe_to_actionable_events(
        &self,
        _filter: Option<&[ActionableEventDiscriminant]>,
    ) -> Result<BoxStream<'static, ActionableEvent>, String> {
        let chain = self
            .chain
            .subscribe()
            .map_err(|error| error.to_string())?
            .map(ActionableEvent::Chain);
        // Merge in injected PIX events on the first subscription. Chain events stay
        // in the stream deliberately: the real event source is unfiltered too, and
        // the strategy discards non-PIX variants itself.
        match self.injected_rx.lock().expect("injected event lock poisoned").take() {
            Some(injected) => Ok(futures::stream::select(chain, injected).boxed()),
            None => Ok(chain.boxed()),
        }
    }
}

impl<C: PacketTransport> PacketTransport for PixNode<C> {
    fn packet_payload_size() -> usize {
        C::packet_payload_size()
    }
}

// ─── TestChainConnector ──────────────────────────────────────────────────────

/// A noop key mapper that always returns `None` for all key lookups.
///
/// This is sufficient for unit tests that do not exercise the
/// packet-key/chain-key mapping code path.
#[derive(Clone, Debug, Default)]
pub struct NoopKeyMapper;

impl hopr_api::chain::KeyIdMapping<hopr_api::chain::HoprKeyIdent, hopr_api::types::crypto::prelude::OffchainPublicKey>
    for NoopKeyMapper
{
    fn map_key_to_id(
        &self,
        _key: &hopr_api::types::crypto::prelude::OffchainPublicKey,
    ) -> Option<hopr_api::chain::HoprKeyIdent> {
        None
    }

    fn map_id_to_public(
        &self,
        _id: &hopr_api::chain::HoprKeyIdent,
    ) -> Option<hopr_api::types::crypto::prelude::OffchainPublicKey> {
        None
    }
}

type TestEventsChannel = (
    async_broadcast::Sender<hopr_api::chain::ChainEvent>,
    async_broadcast::InactiveReceiver<hopr_api::chain::ChainEvent>,
);

struct ParsedChainInfo {
    chain_info: hopr_api::chain::ChainInfo,
    domain_separators: hopr_api::chain::DomainSeparators,
    ticket_win_prob: hopr_api::types::internal::prelude::WinningProbability,
    ticket_price: hopr_api::types::primitive::prelude::HoprBalance,
    closure_grace_period: std::time::Duration,
}

// ─── Fault injection ─────────────────────────────────────────────────────────

/// How a chain operation should misbehave.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Fault {
    /// Operate normally.
    #[default]
    None,
    /// Return an error.
    Fail,
    /// Never resolve.  Models an RPC that neither answers nor times out.
    Hang,
}

/// Chain operations that [`ChainFaults`] can perturb, each naming the call it
/// stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainOp {
    /// `ChainReadSafeOperations::safe_info`.
    SafeInfo,
    /// `ChainValues::balance`, for the safe and for per-peer stake.
    Balance,
    /// `ChainValues::minimum_ticket_price`.
    TicketPrice,
    /// `ChainValues::minimum_incoming_ticket_win_prob`.
    WinProb,
    /// `ChainValues::typical_resolution_time`.
    ResolutionTime,
    /// `ChainReadChannelOperations::stream_channels`.
    StreamChannels,
    /// `ChainReadAccountOperations::stream_accounts`.
    StreamAccounts,
    /// `ChainWriteChannelOperations::open_channel`.
    OpenChannel,
    /// `ChainWriteChannelOperations::fund_channel`.
    FundChannel,
    /// `ChainWriteChannelOperations::close_channel`, which both initiates and
    /// finalizes a closure depending on the channel's status.
    CloseChannel,
}

/// Chain event kinds that [`ChainFaults`] can withhold from subscribers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    /// `ChainEvent::ChannelBalanceIncreased`, reporting a funded channel.
    BalanceIncreased,
    /// `ChainEvent::ChannelBalanceDecreased`, reporting a drained channel.
    BalanceDecreased,
    /// `ChainEvent::ChannelOpened`.
    ChannelOpened,
    /// `ChainEvent::ChannelClosureInitiated`, the first of the two closure
    /// steps: the channel has entered its notice period.
    ClosureInitiated,
    /// `ChainEvent::ChannelClosed`, the second closure step.
    Closed,
    /// `ChainEvent::TicketRedeemed`.
    TicketRedeemed,
}

impl EventKind {
    fn of(event: &ChainEvent) -> Option<Self> {
        match event {
            ChainEvent::ChannelBalanceIncreased(..) => Some(Self::BalanceIncreased),
            ChainEvent::ChannelBalanceDecreased(..) => Some(Self::BalanceDecreased),
            ChainEvent::ChannelOpened(_) => Some(Self::ChannelOpened),
            ChainEvent::ChannelClosureInitiated(_) => Some(Self::ClosureInitiated),
            ChainEvent::ChannelClosed(_) => Some(Self::Closed),
            ChainEvent::TicketRedeemed(..) => Some(Self::TicketRedeemed),
            _ => None,
        }
    }
}

/// Shared, live-mutable fault configuration for a [`TestChainConnector`].
///
/// Handed out by [`TestChainConnector::faults`] so a test can perturb the chain
/// while the strategy is running — which is how these failures actually occur.
/// Empty by default.
///
/// ```text
/// let faults = connector.faults();
///
/// // The funding tx lands, but its outcome never comes back and the event that
/// // would report it is lost — the strategy learns nothing either way.
/// faults.set_confirmation(ChainOp::FundChannel, Fault::Hang);
/// faults.withhold_event(EventKind::BalanceIncreased);
///
/// // ... drive the strategy, then let the chain recover:
/// faults.clear(ChainOp::FundChannel);
/// faults.deliver_event(EventKind::BalanceIncreased);
///
/// // What the strategy did meanwhile:
/// assert_eq!(faults.calls(ChainOp::FundChannel), 1);
/// assert_eq!(faults.peak_in_flight(ChainOp::FundChannel), 1);
/// ```
///
/// `text` because the example needs a connected [`TestChainConnector`], which
/// exists only under the `testing` feature.
#[derive(Debug, Default)]
pub struct ChainFaults {
    ops: dashmap::DashMap<ChainOp, Fault>,
    /// Faults applied to the confirmation future of a write op, rather than to
    /// its submission.
    confirmations: dashmap::DashMap<ChainOp, Fault>,
    withheld_events: dashmap::DashSet<EventKind>,
    calls: dashmap::DashMap<ChainOp, usize>,
    /// Writes between submission and confirmation, and the most ever outstanding
    /// at once, per kind and in total.  Lets a test observe what the strategy
    /// does in parallel, not just what it eventually achieves.
    in_flight: dashmap::DashMap<ChainOp, usize>,
    peak_in_flight: dashmap::DashMap<ChainOp, usize>,
    peak_in_flight_total: std::sync::atomic::AtomicUsize,
}

impl ChainFaults {
    /// Makes `op` misbehave from now on.  For writes this is *submission*; see
    /// [`ChainFaults::set_confirmation`].
    pub fn set(&self, op: ChainOp, fault: Fault) {
        self.ops.insert(op, fault);
    }

    /// Makes `op`'s confirmation misbehave while submission still succeeds: a tx
    /// accepted but whose outcome never arrives (`Hang`) or fails (`Fail`).
    pub fn set_confirmation(&self, op: ChainOp, fault: Fault) {
        self.confirmations.insert(op, fault);
    }

    /// Restores normal behaviour of `op`, both submission and confirmation.
    pub fn clear(&self, op: ChainOp) {
        self.ops.remove(&op);
        self.confirmations.remove(&op);
    }

    /// Stops delivering `kind` to subscribers, as the lossy broadcast does: the
    /// on-chain effect still happens, the notification does not.
    pub fn withhold_event(&self, kind: EventKind) {
        self.withheld_events.insert(kind);
    }

    /// Resumes delivery of `kind`.
    pub fn deliver_event(&self, kind: EventKind) {
        self.withheld_events.remove(&kind);
    }

    /// Times `op` was invoked, counted on entry, before any injected fault.
    pub fn calls(&self, op: ChainOp) -> usize {
        self.calls.get(&op).map(|c| *c).unwrap_or(0)
    }

    /// Most `op` transactions that were ever in flight at the same time.
    pub fn peak_in_flight(&self, op: ChainOp) -> usize {
        self.peak_in_flight.get(&op).map(|c| *c).unwrap_or(0)
    }

    /// Most writes of any kind ever in flight at once — what
    /// `concurrency.max_concurrent_actions` bounds.
    pub fn peak_in_flight_total(&self) -> usize {
        self.peak_in_flight_total.load(Ordering::Relaxed)
    }

    /// Marks a submitted write as outstanding and updates the watermarks.  The
    /// returned guard releases it when dropped.
    #[must_use]
    fn enter_in_flight(self: &std::sync::Arc<Self>, op: ChainOp) -> InFlightGuard {
        // Scoped so the entry guard is released before the map is iterated below.
        let outstanding = {
            let mut entry = self.in_flight.entry(op).or_insert(0);
            *entry += 1;
            *entry
        };

        self.peak_in_flight
            .entry(op)
            .and_modify(|peak| *peak = (*peak).max(outstanding))
            .or_insert(outstanding);

        let total: usize = self.in_flight.iter().map(|entry| *entry.value()).sum();
        self.peak_in_flight_total.fetch_max(total, Ordering::Relaxed);

        InFlightGuard {
            faults: std::sync::Arc::clone(self),
            op,
        }
    }

    /// Marks an outstanding write as finished.
    fn leave_in_flight(&self, op: ChainOp) {
        if let Some(mut outstanding) = self.in_flight.get_mut(&op) {
            *outstanding = outstanding.saturating_sub(1);
        }
    }

    fn fault(&self, op: ChainOp) -> Fault {
        self.ops.get(&op).map(|f| *f).unwrap_or_default()
    }

    fn confirmation_fault(&self, op: ChainOp) -> Fault {
        self.confirmations.get(&op).map(|f| *f).unwrap_or_default()
    }

    fn record(&self, op: ChainOp) {
        *self.calls.entry(op).or_insert(0) += 1;
    }

    fn is_withheld(&self, event: &ChainEvent) -> bool {
        EventKind::of(event).is_some_and(|kind| self.withheld_events.contains(&kind))
    }

    /// Applies a `Fail`/`Hang` fault to an async operation, if one is set.
    async fn gate(&self, op: ChainOp) -> Result<(), TestConnectorError> {
        self.record(op);
        match self.fault(op) {
            Fault::None => Ok(()),
            Fault::Fail => Err(injected_fault(op)),
            Fault::Hang => futures::future::pending().await,
        }
    }

    /// Applies a fault to a stream-returning operation: `Fail` errors from the
    /// call, `Hang` is returned so the caller can yield a pending stream.
    fn gate_stream(&self, op: ChainOp) -> Result<Fault, TestConnectorError> {
        self.record(op);
        match self.fault(op) {
            Fault::Fail => Err(injected_fault(op)),
            other => Ok(other),
        }
    }

    /// Resolves the confirmation future of write op `op`.
    async fn confirm(&self, op: ChainOp) -> Result<(), TestConnectorError> {
        match self.confirmation_fault(op) {
            Fault::None => Ok(()),
            Fault::Fail => Err(injected_fault(op)),
            Fault::Hang => futures::future::pending().await,
        }
    }
}

/// Holds an operation's in-flight count up for as long as it lives.
///
/// Tied to the confirmation future's lifetime rather than to a call at its end,
/// so a caller that drops the future without polling it to completion — an
/// aborted task, say — cannot leave the count raised and every later watermark
/// reading too high.
pub struct InFlightGuard {
    faults: std::sync::Arc<ChainFaults>,
    op: ChainOp,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.faults.leave_in_flight(self.op);
    }
}

fn injected_fault(op: ChainOp) -> TestConnectorError {
    TestConnectorError::from(anyhow::anyhow!("injected fault on {op:?}"))
}

/// A minimal chain connector backed by a [`BlokliTestClient`] for use in unit tests.
///
/// Wraps the test blokli client and implements all [`HoprChainApi`](hopr_api::chain::HoprChainApi)
/// sub-traits with `Error = anyhow::Error`. Write operations that unit tests
/// do not exercise return an error instead of panicking.
pub struct TestChainConnector<M: BlokliTestStateMutator> {
    client: std::sync::Arc<BlokliTestClient<M>>,
    my_addr: hopr_api::types::primitive::prelude::Address,
    chain_key: hopr_api::types::crypto::prelude::ChainKeypair,
    module_address: hopr_api::types::primitive::prelude::Address,
    events: TestEventsChannel,
    /// Payload generator, initialized on `connect()` after fetching chain info.
    payload_gen: std::sync::Arc<std::sync::OnceLock<hopr_api::types::chain::payload::SafePayloadGenerator>>,
    /// chain_id, initialized on `connect()`.
    chain_id: std::sync::Arc<std::sync::OnceLock<u64>>,
    /// Ticket price from chain info, populated on `connect()` for synchronous access.
    ticket_price: std::sync::Arc<std::sync::OnceLock<hopr_api::types::primitive::prelude::HoprBalance>>,
    /// Minimum winning probability from chain info, populated on `connect()` for synchronous access.
    ticket_win_prob: std::sync::Arc<std::sync::OnceLock<hopr_api::types::internal::prelude::WinningProbability>>,
    /// Nonce counters for transaction sequencing, one per signing address.
    ///
    /// Keyed by signer because `withdraw_from_signer` signs with a caller-supplied key: a
    /// single shared counter would hand that key a nonce advanced by the connector's own
    /// transactions, and then reuse a nonce for the connector.
    nonces: std::sync::Arc<dashmap::DashMap<hopr_api::types::primitive::prelude::Address, Arc<AtomicU64>>>,
    /// Accounts cache: chain address → AccountEntry, populated on `connect()`.
    accounts: std::sync::Arc<
        dashmap::DashMap<
            hopr_api::types::primitive::prelude::Address,
            hopr_api::types::internal::prelude::AccountEntry,
        >,
    >,
    /// Channel cache: channel id → ChannelEntry, populated on `connect()`.
    channels: std::sync::Arc<
        dashmap::DashMap<
            hopr_api::types::internal::prelude::ChannelId,
            hopr_api::types::internal::prelude::ChannelEntry,
        >,
    >,
    /// Injected chain-operation faults; empty unless a test configures them.
    faults: std::sync::Arc<ChainFaults>,
}

impl<M: BlokliTestStateMutator + Clone + Send + Sync + 'static> TestChainConnector<M> {
    pub fn new(
        client: BlokliTestClient<M>,
        my_addr: hopr_api::types::primitive::prelude::Address,
        chain_key: hopr_api::types::crypto::prelude::ChainKeypair,
        module_address: hopr_api::types::primitive::prelude::Address,
    ) -> Self {
        let (mut tx, rx) = async_broadcast::broadcast(256);
        tx.set_overflow(true);
        Self {
            client: std::sync::Arc::new(client),
            my_addr,
            chain_key,
            module_address,
            events: (tx, rx.deactivate()),
            payload_gen: Default::default(),
            chain_id: Default::default(),
            ticket_price: Default::default(),
            ticket_win_prob: Default::default(),
            nonces: Default::default(),
            accounts: Default::default(),
            channels: Default::default(),
            faults: Default::default(),
        }
    }

    /// Handle to this connector's fault configuration.  Faults can be set and
    /// cleared at any time, including while a strategy is running against it.
    pub fn faults(&self) -> std::sync::Arc<ChainFaults> {
        self.faults.clone()
    }

    /// A handle to the same in-process chain this connector talks to.
    ///
    /// `BlokliTestClient` shares its state when cloned, so the returned handle sees and mutates
    /// exactly the state this connector does. Needed by anything that builds a *second* connector
    /// over the same chain — a component signing as an EOA rather than through the node's Safe,
    /// say — which otherwise has no way to reach it.
    pub fn client(&self) -> BlokliTestClient<M> {
        (*self.client).clone()
    }

    /// Loads initial state via finite queries and spawns a background task for live event forwarding.
    pub async fn connect(&mut self) -> anyhow::Result<()> {
        // Fetch chain info to initialize the payload generator and cache ticket values.
        let chain_info_raw = self.client.query_chain_info().await?;
        let chain_id = chain_info_raw.chain_id as u64;
        let contract_addresses: hopr_api::types::chain::ContractAddresses =
            serde_json::from_str(&chain_info_raw.contract_addresses.0)
                .map_err(|e| anyhow::anyhow!("invalid contract addresses: {e}"))?;
        let _ = self.chain_id.set(chain_id);
        let _ = self
            .payload_gen
            .set(hopr_api::types::chain::payload::SafePayloadGenerator::new(
                &self.chain_key,
                contract_addresses,
                self.module_address,
            ));
        let parsed = Self::parse_chain_info_model(chain_info_raw)?;
        let _ = self.ticket_price.set(parsed.ticket_price);
        let _ = self.ticket_win_prob.set(parsed.ticket_win_prob);

        // Load all accounts via a finite snapshot query and build a keyid→address map.
        let mut keyid_to_addr = std::collections::HashMap::<u32, hopr_api::types::primitive::prelude::Address>::new();
        for account_model in self.client.query_accounts(BlokliAccountSelector::Any).await? {
            let entry = Self::convert_account_model(account_model)?;
            keyid_to_addr.insert(u32::from(entry.key_id), entry.chain_addr);
            self.accounts.insert(entry.chain_addr, entry);
        }

        // Load all channels via a finite snapshot query and fire ChannelOpened for Open channels.
        for channel_model in self.client.query_channels(ChannelSelector::default()).await?.channels {
            let src_addr = keyid_to_addr
                .get(&(channel_model.source as u32))
                .copied()
                .ok_or_else(|| anyhow::anyhow!("source key_id {} not found in accounts", channel_model.source))?;
            let dst_addr = keyid_to_addr
                .get(&(channel_model.destination as u32))
                .copied()
                .ok_or_else(|| {
                    anyhow::anyhow!("destination key_id {} not found in accounts", channel_model.destination)
                })?;
            let channel = Self::convert_channel_model(&channel_model, src_addr, dst_addr)?;
            let channel_id = *channel.get_id();
            self.channels.insert(channel_id, channel);
        }

        // Spawn a background task that forwards live graph updates as ChainEvents.
        // subscribe_graph() emits an initial snapshot (already loaded above) then live updates.
        // The initial snapshot items produce no-op comparisons against the cache; only real
        // state changes trigger new events.
        let client = self.client.clone();
        let events_tx = self.events.0.clone();
        let accounts_cache = self.accounts.clone();
        let channels_cache = self.channels.clone();
        tokio::spawn(async move {
            use futures::TryStreamExt;

            let graph_stream = match client.subscribe_graph() {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("subscribe_graph() failed in background event loop: {e}");
                    return;
                }
            };
            futures::pin_mut!(graph_stream);

            loop {
                let entry = match graph_stream.try_next().await {
                    Ok(Some(e)) => e,
                    Ok(None) => break,
                    Err(e) => {
                        tracing::error!("graph stream error in background event loop: {e}");
                        break;
                    }
                };
                let src = match Self::convert_account_model(entry.source) {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::warn!("failed to convert account in graph event: {e}");
                        continue;
                    }
                };
                let dst = match Self::convert_account_model(entry.destination) {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::warn!("failed to convert account in graph event: {e}");
                        continue;
                    }
                };
                let new_channel = match Self::convert_channel_model(&entry.channel, src.chain_addr, dst.chain_addr) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!("failed to convert channel in graph event: {e}");
                        continue;
                    }
                };

                accounts_cache.insert(src.chain_addr, src);
                accounts_cache.insert(dst.chain_addr, dst);

                let channel_id = *new_channel.get_id();
                let old_channel = channels_cache.get(&channel_id).map(|r| *r);
                channels_cache.insert(channel_id, new_channel);

                let event = match old_channel {
                    None => {
                        if new_channel.status == ChannelStatus::Open {
                            Some(hopr_api::chain::ChainEvent::ChannelOpened(new_channel))
                        } else {
                            None
                        }
                    }
                    Some(ref old) if old.status == new_channel.status && old.balance == new_channel.balance => None,
                    Some(ref old) if old.status != new_channel.status => match new_channel.status {
                        ChannelStatus::Open => Some(hopr_api::chain::ChainEvent::ChannelOpened(new_channel)),
                        ChannelStatus::PendingToClose(_) => {
                            Some(hopr_api::chain::ChainEvent::ChannelClosureInitiated(new_channel))
                        }
                        ChannelStatus::Closed => Some(hopr_api::chain::ChainEvent::ChannelClosed(new_channel)),
                    },
                    Some(ref old) => {
                        if new_channel.balance > old.balance {
                            let diff = new_channel.balance - old.balance;
                            Some(hopr_api::chain::ChainEvent::ChannelBalanceIncreased(new_channel, diff))
                        } else if new_channel.ticket_index > old.ticket_index {
                            Some(hopr_api::chain::ChainEvent::TicketRedeemed(new_channel, None))
                        } else {
                            let diff = old.balance - new_channel.balance;
                            Some(hopr_api::chain::ChainEvent::ChannelBalanceDecreased(new_channel, diff))
                        }
                    }
                };

                if let Some(evt) = event {
                    let _ = events_tx.try_broadcast(evt);
                }
            }
        });

        Ok(())
    }

    fn convert_account_model(
        model: blokli_client::api::types::Account,
    ) -> anyhow::Result<hopr_api::types::internal::prelude::AccountEntry> {
        let entry_type = if !model.multi_addresses.is_empty() {
            AccountType::Announced(
                model
                    .multi_addresses
                    .into_iter()
                    .filter_map(|a| hopr_api::chain::Multiaddr::from_str(&a).ok())
                    .collect(),
            )
        } else {
            AccountType::NotAnnounced
        };

        Ok(AccountEntry {
            public_key: model.packet_key.parse()?,
            chain_addr: model.chain_key.parse()?,
            key_id: (model.keyid as u32).into(),
            entry_type,
            safe_address: model.safe_address.map(|a| a.parse::<Address>()).transpose()?,
        })
    }

    fn convert_channel_model(
        model: &blokli_client::api::types::Channel,
        src_addr: hopr_api::types::primitive::prelude::Address,
        dst_addr: hopr_api::types::primitive::prelude::Address,
    ) -> anyhow::Result<hopr_api::types::internal::prelude::ChannelEntry> {
        let status = match model.status {
            blokli_client::api::types::ChannelStatus::Open => ChannelStatus::Open,
            blokli_client::api::types::ChannelStatus::PendingToClose => {
                let closure_time = model
                    .closure_time
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("missing closure time on PendingToClose channel"))?;
                ChannelStatus::PendingToClose(hopr_api::chain::DateTime::from_str(&closure_time.0)?.into())
            }
            blokli_client::api::types::ChannelStatus::Closed => ChannelStatus::Closed,
        };

        Ok(ChannelBuilder::default()
            .between(src_addr, dst_addr)
            .balance(model.balance.0.parse()?)
            .ticket_index(
                model
                    .ticket_index
                    .0
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid ticket index: {e}"))?,
            )
            .status(status)
            .epoch(model.epoch as u32)
            .build()?)
    }

    /// Nonce counter for `signer`, created on first use.
    ///
    /// Always pair this with the key that actually signs the transaction — see the note on
    /// [`TestChainConnector::nonces`].
    fn nonce_for(&self, signer: &hopr_api::types::primitive::prelude::Address) -> Arc<AtomicU64> {
        self.nonces.entry(*signer).or_default().clone()
    }

    /// Waits until this connector's own channel view satisfies `predicate`.
    ///
    /// The emulated RPC wraps the chain, not the other way round: the tx has
    /// already executed and broadcast by the time submission returns, so a
    /// confirmation must not resolve before the caller can read the result.
    /// This connector ingests that broadcast on a background task, so without
    /// the wait it would report success against a view it has not caught up
    /// with — which no real chain RPC does.
    async fn await_own_view(
        channels: std::sync::Arc<
            dashmap::DashMap<
                hopr_api::types::internal::prelude::ChannelId,
                hopr_api::types::internal::prelude::ChannelEntry,
            >,
        >,
        channel_id: hopr_api::types::internal::prelude::ChannelId,
        predicate: impl Fn(&hopr_api::types::internal::prelude::ChannelEntry) -> bool,
    ) {
        // Generous for an in-process broadcast: only a stuck background task
        // reaches it, and the caller's own timeout covers that.
        const LIMIT: std::time::Duration = std::time::Duration::from_secs(5);
        const POLL: std::time::Duration = std::time::Duration::from_millis(2);

        let deadline = std::time::Instant::now() + LIMIT;
        loop {
            if channels.get(&channel_id).is_some_and(|entry| predicate(&entry)) {
                return;
            }
            if std::time::Instant::now() >= deadline {
                tracing::warn!(%channel_id, "test connector: own view never caught up with the confirmed tx");
                return;
            }
            futures_time::task::sleep(POLL.into()).await;
        }
    }

    async fn send_tx(
        client: &BlokliTestClient<M>,
        tx_req: hopr_api::types::chain::payload::TransactionRequest,
        chain_id: u64,
        chain_key: &hopr_api::types::crypto::prelude::ChainKeypair,
        nonce: &AtomicU64,
    ) -> anyhow::Result<hopr_api::chain::ChainReceipt> {
        let n = nonce.fetch_add(1, Ordering::Relaxed);
        let signed = tx_req.sign_and_encode_to_eip2718(n, chain_id, None, chain_key).await?;
        let receipt = client.submit_and_confirm_transaction(&signed, 1).await?;
        Ok(hopr_api::chain::ChainReceipt::from(receipt))
    }

    fn parse_chain_info_model(model: blokli_client::api::types::ChainInfo) -> anyhow::Result<ParsedChainInfo> {
        let channel_closure_grace_period = std::time::Duration::from_secs(
            model
                .channel_closure_grace_period
                .0
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid closure grace period: {e}"))?,
        );

        let domain_separators = hopr_api::chain::DomainSeparators {
            ledger: model
                .ledger_dst
                .as_deref()
                .map(Hash::from_str)
                .transpose()?
                .unwrap_or_default(),
            safe_registry: model
                .safe_registry_dst
                .as_deref()
                .map(Hash::from_str)
                .transpose()?
                .unwrap_or_default(),
            channel: model
                .channel_dst
                .as_deref()
                .map(Hash::from_str)
                .transpose()?
                .unwrap_or_default(),
        };

        let ticket_win_prob = WinningProbability::try_from_f64(model.min_ticket_winning_probability)?;
        let ticket_price: HoprBalance = model.ticket_price.0.parse()?;
        let chain_info = hopr_api::chain::ChainInfo {
            chain_id: model.chain_id as u64,
            hopr_network_name: model.network,
            contract_addresses: serde_json::from_str(&model.contract_addresses.0)
                .map_err(|e| anyhow::anyhow!("invalid contract addresses: {e}"))?,
        };

        Ok(ParsedChainInfo {
            chain_info,
            domain_separators,
            ticket_win_prob,
            ticket_price,
            closure_grace_period: channel_closure_grace_period,
        })
    }

    fn payload_gen(&self) -> anyhow::Result<&hopr_api::types::chain::payload::SafePayloadGenerator> {
        self.payload_gen
            .get()
            .ok_or_else(|| anyhow::anyhow!("connector not connected"))
    }

    fn chain_id(&self) -> anyhow::Result<u64> {
        self.chain_id
            .get()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("connector not connected"))
    }
}

// ── ChainReadAccountOperations ────────────────────────────────────────────────

#[async_trait::async_trait]
impl<M: BlokliTestStateMutator + Clone + Send + Sync + 'static> hopr_api::chain::ChainReadAccountOperations
    for TestChainConnector<M>
{
    type Error = TestConnectorError;

    fn stream_accounts<'a>(
        &'a self,
        selector: hopr_api::chain::AccountSelector,
    ) -> Result<futures::stream::BoxStream<'a, hopr_api::types::internal::prelude::AccountEntry>, Self::Error> {
        if self.faults.gate_stream(ChainOp::StreamAccounts)? == Fault::Hang {
            return Ok(futures::stream::pending().boxed());
        }

        let entries: Vec<_> = self
            .accounts
            .iter()
            .filter(|e| selector.satisfies(e.value()))
            .map(|e| e.value().clone())
            .collect();
        Ok(futures::stream::iter(entries).boxed())
    }

    async fn count_accounts(&self, selector: hopr_api::chain::AccountSelector) -> Result<usize, Self::Error> {
        Ok(self.accounts.iter().filter(|e| selector.satisfies(e.value())).count())
    }

    async fn await_key_binding(
        &self,
        offchain_key: &hopr_api::types::crypto::prelude::OffchainPublicKey,
        _timeout: std::time::Duration,
    ) -> Result<hopr_api::types::internal::prelude::AccountEntry, Self::Error> {
        self.accounts
            .iter()
            .find(|e| &e.value().public_key == offchain_key)
            .map(|e| e.value().clone())
            .ok_or_else(|| TestConnectorError::from(anyhow::anyhow!("account with key {offchain_key} not found")))
    }
}

// ── ChainWriteAccountOperations ───────────────────────────────────────────────

#[async_trait::async_trait]
impl<M: BlokliTestStateMutator + Clone + Send + Sync + 'static> hopr_api::chain::ChainWriteAccountOperations
    for TestChainConnector<M>
{
    type Error = TestConnectorError;

    async fn announce(
        &self,
        _multiaddrs: &[hopr_api::chain::Multiaddr],
        _key: &hopr_api::types::crypto::prelude::OffchainKeypair,
    ) -> Result<
        futures::future::BoxFuture<'_, Result<hopr_api::chain::ChainReceipt, Self::Error>>,
        hopr_api::chain::AnnouncementError<Self::Error>,
    > {
        Err(hopr_api::chain::AnnouncementError::processing(anyhow::anyhow!(
            "not supported by TestChainConnector"
        )))
    }

    async fn withdraw<C: hopr_api::types::primitive::prelude::Currency + Send>(
        &self,
        balance: hopr_api::types::primitive::prelude::Balance<C>,
        recipient: &hopr_api::types::primitive::prelude::Address,
    ) -> Result<futures::future::BoxFuture<'_, Result<hopr_api::chain::ChainReceipt, Self::Error>>, Self::Error> {
        let tx_req = self
            .payload_gen()
            .map_err(TestConnectorError::from)?
            .transfer(*recipient, balance)
            .map_err(|e| TestConnectorError::from(anyhow::anyhow!("{e}")))?;

        let client = self.client.clone();
        let chain_id = self.chain_id().map_err(TestConnectorError::from)?;
        let chain_key = self.chain_key.clone();
        let nonce = self.nonce_for(&self.my_addr);

        Ok(Box::pin(async move {
            Self::send_tx(&client, tx_req, chain_id, &chain_key, &nonce)
                .await
                .map_err(TestConnectorError::from)
        }))
    }

    async fn withdraw_from_signer<C: hopr_api::types::primitive::prelude::Currency + Send>(
        &self,
        signer: &hopr_api::types::crypto::prelude::ChainKeypair,
        balance: hopr_api::types::primitive::prelude::Balance<C>,
        recipient: &hopr_api::types::primitive::prelude::Address,
    ) -> Result<futures::future::BoxFuture<'_, Result<hopr_api::chain::ChainReceipt, Self::Error>>, Self::Error> {
        let tx_req = self
            .payload_gen()
            .map_err(TestConnectorError::from)?
            .transfer(*recipient, balance)
            .map_err(|e| TestConnectorError::from(anyhow::anyhow!("{e}")))?;

        let client = self.client.clone();
        let chain_id = self.chain_id().map_err(TestConnectorError::from)?;
        // The caller's key signs this one, so it needs that key's own nonce sequence.
        let nonce = self.nonce_for(&signer.public().to_address());
        let signer = signer.clone();

        Ok(Box::pin(async move {
            let n = nonce.fetch_add(1, Ordering::Relaxed);
            let signed = tx_req
                .sign_and_encode_to_eip2718(n, chain_id, None, &signer)
                .await
                .map_err(|e| TestConnectorError::from(anyhow::anyhow!("{e}")))?;
            let receipt = client
                .submit_and_confirm_transaction(&signed, 1)
                .await
                .map_err(TestConnectorError::from)?;
            Ok(hopr_api::chain::ChainReceipt::from(receipt))
        }))
    }

    async fn register_safe(
        &self,
        safe_address: &hopr_api::types::primitive::prelude::Address,
    ) -> Result<
        futures::future::BoxFuture<'_, Result<hopr_api::chain::ChainReceipt, Self::Error>>,
        hopr_api::chain::SafeRegistrationError<Self::Error>,
    > {
        let my_addr = self.my_addr;

        // Check if already registered
        if let Some(existing) = self
            .client
            .query_safe(BlokliSafeSelector::RegisteredNode(my_addr.into()))
            .await
            .map_err(hopr_api::chain::SafeRegistrationError::processing)?
            .first()
        {
            let registered = existing
                .address
                .parse::<hopr_api::types::primitive::prelude::Address>()
                .map_err(hopr_api::chain::SafeRegistrationError::processing)?;
            return Err(hopr_api::chain::SafeRegistrationError::AlreadyRegistered(registered));
        }

        // Check the safe exists
        if self
            .client
            .query_safe(BlokliSafeSelector::SafeAddress((*safe_address).into()))
            .await
            .map_err(hopr_api::chain::SafeRegistrationError::processing)?
            .is_empty()
        {
            return Err(hopr_api::chain::SafeRegistrationError::processing(anyhow::anyhow!(
                "safe {safe_address} does not exist"
            )));
        }

        let tx_req = self
            .payload_gen()
            .map_err(hopr_api::chain::SafeRegistrationError::processing)?
            .register_safe_by_node(*safe_address)
            .map_err(hopr_api::chain::SafeRegistrationError::processing)?;

        let client = self.client.clone();
        let chain_id = self
            .chain_id()
            .map_err(hopr_api::chain::SafeRegistrationError::processing)?;
        let chain_key = self.chain_key.clone();
        let nonce = self.nonce_for(&self.my_addr);
        Ok(Box::pin(async move {
            Self::send_tx(&client, tx_req, chain_id, &chain_key, &nonce)
                .await
                .map_err(TestConnectorError::from)
        }))
    }
}

// ── Service registry ─────────────────────────────────────────────────────────
//
// `HoprChainApi` gained the two service-registry traits, so a chain API has to answer for them
// even though no strategy in this crate reads or writes the registry — none is about services.
// The Blokli emulator behind this connector does not model the registry at all, so these are
// stubs rather than a thin layer over it.
//
// Reads answer as an *empty* registry: that is a truthful answer for a chain where nothing was
// ever registered, and it keeps a caller that merely surveys the registry working. Writes report
// "not supported", matching `announce` above — silently accepting a registration the emulator
// cannot store would make a later read look like a lost write.

#[async_trait::async_trait]
impl<M: BlokliTestStateMutator + Clone + Send + Sync + 'static> hopr_api::chain::ChainReadServiceOperations
    for TestChainConnector<M>
{
    type Error = TestConnectorError;

    fn stream_services(
        &self,
        _selector: hopr_api::chain::ServiceSelector,
    ) -> Result<futures::stream::BoxStream<'_, hopr_api::chain::ServiceEntry>, Self::Error> {
        Ok(futures::stream::empty().boxed())
    }

    async fn count_services(&self, _selector: hopr_api::chain::ServiceSelector) -> Result<usize, Self::Error> {
        Ok(0)
    }

    async fn get_service_type_config(
        &self,
        _service_type: hopr_api::chain::ServiceType,
    ) -> Result<Option<hopr_api::chain::ServiceTypeConfig>, Self::Error> {
        Ok(None)
    }

    async fn get_service_registry_config(&self) -> Result<hopr_api::chain::ServiceRegistryConfig, Self::Error> {
        Ok(hopr_api::chain::ServiceRegistryConfig {
            type_registration_fee: HoprBalance::zero(),
            node_safe_registry: Address::default(),
        })
    }
}

#[async_trait::async_trait]
impl<M: BlokliTestStateMutator + Clone + Send + Sync + 'static> hopr_api::chain::ChainWriteServiceOperations
    for TestChainConnector<M>
{
    type Error = TestConnectorError;

    async fn register_service(
        &self,
        _service_type: hopr_api::chain::ServiceType,
        _metadata: hopr_api::chain::ServiceMetadata,
    ) -> Result<futures::future::BoxFuture<'_, Result<hopr_api::chain::ChainReceipt, Self::Error>>, Self::Error> {
        Err(unsupported_by_test_connector("register_service"))
    }

    async fn update_service(
        &self,
        _service_type: hopr_api::chain::ServiceType,
        _metadata: hopr_api::chain::ServiceMetadata,
    ) -> Result<futures::future::BoxFuture<'_, Result<hopr_api::chain::ChainReceipt, Self::Error>>, Self::Error> {
        Err(unsupported_by_test_connector("update_service"))
    }

    async fn deregister_service(
        &self,
        _service_type: hopr_api::chain::ServiceType,
    ) -> Result<futures::future::BoxFuture<'_, Result<hopr_api::chain::ChainReceipt, Self::Error>>, Self::Error> {
        Err(unsupported_by_test_connector("deregister_service"))
    }
}

fn unsupported_by_test_connector(what: &str) -> TestConnectorError {
    TestConnectorError::from(anyhow::anyhow!("{what} is not supported by TestChainConnector"))
}

// ── ChainReadChannelOperations ────────────────────────────────────────────────

impl<M: BlokliTestStateMutator + Clone + Send + Sync + 'static> hopr_api::chain::ChainReadChannelOperations
    for TestChainConnector<M>
{
    type Error = TestConnectorError;

    fn me(&self) -> &hopr_api::types::primitive::prelude::Address {
        &self.my_addr
    }

    fn channel_by_id(
        &self,
        channel_id: &hopr_api::types::internal::prelude::ChannelId,
    ) -> Result<Option<hopr_api::types::internal::prelude::ChannelEntry>, Self::Error> {
        Ok(self.channels.get(channel_id).map(|e| *e))
    }

    fn stream_channels<'a>(
        &'a self,
        selector: hopr_api::chain::ChannelSelector,
    ) -> Result<futures::stream::BoxStream<'a, hopr_api::types::internal::prelude::ChannelEntry>, Self::Error> {
        if self.faults.gate_stream(ChainOp::StreamChannels)? == Fault::Hang {
            return Ok(futures::stream::pending().boxed());
        }

        let entries: Vec<_> = self
            .channels
            .iter()
            .filter(|e| selector.satisfies(e.value()))
            .map(|e| *e.value())
            .collect();
        Ok(futures::stream::iter(entries).boxed())
    }
}

// ── ChainWriteChannelOperations ───────────────────────────────────────────────

#[async_trait::async_trait]
impl<M: BlokliTestStateMutator + Clone + Send + Sync + 'static> hopr_api::chain::ChainWriteChannelOperations
    for TestChainConnector<M>
{
    type Error = TestConnectorError;

    async fn open_channel<'a>(
        &'a self,
        dst: &'a hopr_api::types::primitive::prelude::Address,
        amount: hopr_api::types::primitive::prelude::HoprBalance,
    ) -> Result<futures::future::BoxFuture<'a, Result<hopr_api::chain::ChainReceipt, Self::Error>>, Self::Error> {
        self.faults.gate(ChainOp::OpenChannel).await?;

        let channel_id = generate_channel_id(&self.my_addr, dst);
        let tx_req = self.payload_gen()?.fund_channel(*dst, amount)?;
        let receipt = Self::send_tx(
            &self.client,
            tx_req,
            self.chain_id()?,
            &self.chain_key,
            &self.nonce_for(&self.my_addr),
        )
        .await
        .map_err(TestConnectorError::from)?;
        let faults = self.faults.clone();
        let channels = self.channels.clone();
        let in_flight = faults.enter_in_flight(ChainOp::OpenChannel);
        Ok(Box::pin(async move {
            let _in_flight = in_flight;
            Self::await_own_view(channels, channel_id, |channel| channel.status == ChannelStatus::Open).await;
            faults.confirm(ChainOp::OpenChannel).await?;
            Ok(receipt)
        }))
    }

    async fn fund_channel<'a>(
        &'a self,
        channel_id: &'a hopr_api::types::internal::prelude::ChannelId,
        amount: hopr_api::types::primitive::prelude::HoprBalance,
    ) -> Result<futures::future::BoxFuture<'a, Result<hopr_api::chain::ChainReceipt, Self::Error>>, Self::Error> {
        self.faults.gate(ChainOp::FundChannel).await?;

        let channel = self
            .channels
            .get(channel_id)
            .map(|e| *e)
            .ok_or_else(|| anyhow::anyhow!("channel {channel_id} not found"))?;

        let tx_req = self.payload_gen()?.fund_channel(channel.destination, amount)?;
        let funded_to = channel.balance + amount;
        let receipt = Self::send_tx(
            &self.client,
            tx_req,
            self.chain_id()?,
            &self.chain_key,
            &self.nonce_for(&self.my_addr),
        )
        .await
        .map_err(TestConnectorError::from)?;
        let faults = self.faults.clone();
        let channels = self.channels.clone();
        let channel_id = *channel_id;
        let in_flight = faults.enter_in_flight(ChainOp::FundChannel);
        Ok(Box::pin(async move {
            let _in_flight = in_flight;
            Self::await_own_view(channels, channel_id, |channel| channel.balance >= funded_to).await;
            faults.confirm(ChainOp::FundChannel).await?;
            Ok(receipt)
        }))
    }

    async fn close_channel<'a>(
        &'a self,
        channel_id: &'a hopr_api::types::internal::prelude::ChannelId,
    ) -> Result<futures::future::BoxFuture<'a, Result<hopr_api::chain::ChainReceipt, Self::Error>>, Self::Error> {
        self.faults.gate(ChainOp::CloseChannel).await?;

        let channel = self
            .channels
            .get(channel_id)
            .map(|e| *e)
            .ok_or_else(|| anyhow::anyhow!("channel {channel_id} not found"))?;

        let tx_req = match channel.status {
            ChannelStatus::Open => self
                .payload_gen()?
                .initiate_outgoing_channel_closure(channel.destination)?,
            ChannelStatus::PendingToClose(_) => self
                .payload_gen()?
                .finalize_outgoing_channel_closure(channel.destination)?,
            ChannelStatus::Closed => return Err(anyhow::anyhow!("channel {channel_id} is already closed").into()),
        };

        let previous_status = channel.status;
        let receipt = Self::send_tx(
            &self.client,
            tx_req,
            self.chain_id()?,
            &self.chain_key,
            &self.nonce_for(&self.my_addr),
        )
        .await
        .map_err(TestConnectorError::from)?;
        let faults = self.faults.clone();
        let channels = self.channels.clone();
        let channel_id = *channel_id;
        let in_flight = faults.enter_in_flight(ChainOp::CloseChannel);
        Ok(Box::pin(async move {
            let _in_flight = in_flight;
            // Closure is two steps (Open → PendingToClose → Closed); either way
            // the status this call moved the channel out of must be gone from
            // our own view before we report success.
            Self::await_own_view(channels, channel_id, |channel| channel.status != previous_status).await;
            faults.confirm(ChainOp::CloseChannel).await?;
            Ok(receipt)
        }))
    }
}

// ── ChainReadSafeOperations ───────────────────────────────────────────────────

#[async_trait::async_trait]
impl<M: BlokliTestStateMutator + Clone + Send + Sync + 'static> hopr_api::chain::ChainReadSafeOperations
    for TestChainConnector<M>
{
    type Error = TestConnectorError;

    async fn safe_allowance<
        C: hopr_api::types::primitive::prelude::Currency,
        A: Into<hopr_api::types::primitive::prelude::Address> + Send,
    >(
        &self,
        safe_address: A,
    ) -> Result<hopr_api::types::primitive::prelude::Balance<C>, Self::Error> {
        let address = safe_address.into();
        if C::is::<WxHOPR>() {
            Ok(self
                .client
                .query_safe_allowance(&address.into())
                .await?
                .allowance
                .0
                .parse()?)
        } else if C::is::<XDai>() {
            Err(anyhow::anyhow!("cannot query allowance on xDai").into())
        } else {
            Err(anyhow::anyhow!("unsupported currency").into())
        }
    }

    async fn safe_info(
        &self,
        selector: hopr_api::chain::SafeSelector,
    ) -> Result<Option<hopr_api::chain::DeployedSafe>, Self::Error> {
        self.faults.gate(ChainOp::SafeInfo).await?;

        let blokli_selector = match selector {
            hopr_api::chain::SafeSelector::Address(a) => BlokliSafeSelector::SafeAddress(a.into()),
            hopr_api::chain::SafeSelector::Deployer(a) => BlokliSafeSelector::ChainKey(a.into()),
            hopr_api::chain::SafeSelector::NodeAddress(a) => BlokliSafeSelector::RegisteredNode(a.into()),
            hopr_api::chain::SafeSelector::Owner(a) => BlokliSafeSelector::Owner(a.into()),
        };

        if let Some(safe) = self.client.query_safe(blokli_selector).await?.first().cloned() {
            Ok(Some(hopr_api::chain::DeployedSafe {
                address: safe.address.parse::<Address>()?,
                owners: safe
                    .owners
                    .into_iter()
                    .map(|a| a.parse::<Address>())
                    .collect::<Result<Vec<_>, _>>()?,
                module: safe.module_address.parse::<Address>()?,
                registered_nodes: safe
                    .registered_nodes
                    .into_iter()
                    .map(|a| a.parse::<Address>())
                    .collect::<Result<Vec<_>, _>>()?,
                deployer: safe.chain_key.parse::<Address>()?,
            }))
        } else {
            Ok(None)
        }
    }

    async fn await_safe_deployment(
        &self,
        selector: hopr_api::chain::SafeSelector,
        _timeout: std::time::Duration,
    ) -> Result<hopr_api::chain::DeployedSafe, Self::Error> {
        self.safe_info(selector)
            .await?
            .ok_or_else(|| TestConnectorError::from(anyhow::anyhow!("safe not found")))
    }

    async fn predict_module_address(
        &self,
        _nonce: u64,
        _owner: &hopr_api::types::primitive::prelude::Address,
        _safe_address: &hopr_api::types::primitive::prelude::Address,
    ) -> Result<hopr_api::types::primitive::prelude::Address, Self::Error> {
        Err(TestConnectorError::from(anyhow::anyhow!(
            "not supported by TestChainConnector"
        )))
    }
}

// ── ChainWriteSafeOperations ──────────────────────────────────────────────────

#[async_trait::async_trait]
impl<M: BlokliTestStateMutator + Clone + Send + Sync + 'static> hopr_api::chain::ChainWriteSafeOperations
    for TestChainConnector<M>
{
    type Error = TestConnectorError;

    async fn deploy_safe<'a>(
        &'a self,
        _balance: hopr_api::types::primitive::prelude::HoprBalance,
    ) -> Result<futures::future::BoxFuture<'a, Result<hopr_api::chain::ChainReceipt, Self::Error>>, Self::Error> {
        Err(TestConnectorError::from(anyhow::anyhow!(
            "not supported by TestChainConnector"
        )))
    }
}

// ── ChainEvents ───────────────────────────────────────────────────────────────

impl<M: BlokliTestStateMutator + Clone + Send + Sync + 'static> hopr_api::chain::ChainEvents for TestChainConnector<M> {
    type Error = TestConnectorError;

    fn subscribe_with_state_sync<I: IntoIterator<Item = hopr_api::chain::StateSyncOptions>>(
        &self,
        _options: I,
    ) -> Result<impl futures::Stream<Item = hopr_api::chain::ChainEvent> + Send + 'static, Self::Error> {
        // async_broadcast::try_broadcast returns TrySendError::Inactive when receiver_count == 0
        // (only InactiveReceiver present), so events fired before the first subscribe() call are
        // silently dropped. Prepend a current-state snapshot to cover any missed transitions.
        let snapshot: Vec<ChainEvent> = self
            .channels
            .iter()
            .filter_map(|e| {
                let ch = *e.value();
                match ch.status {
                    ChannelStatus::Open => Some(ChainEvent::ChannelOpened(ch)),
                    ChannelStatus::PendingToClose(_) => Some(ChainEvent::ChannelClosureInitiated(ch)),
                    ChannelStatus::Closed => None,
                }
            })
            .collect();
        // Withheld kinds are filtered per subscriber: the chain state still
        // changes, only the notification is lost — exactly what an overflowing
        // event broadcast does to a slow consumer.
        // Boxed so the returned stream stays `Unpin` for callers that poll it
        // directly (`next().timeout(..)`), which `Filter` is not.
        let faults = self.faults.clone();
        Ok(futures::stream::iter(snapshot)
            .chain(self.events.1.activate_cloned())
            .filter(move |event| futures::future::ready(!faults.is_withheld(event)))
            .boxed())
    }
}

// ── ChainKeyOperations ────────────────────────────────────────────────────────

impl<M: BlokliTestStateMutator + Clone + Send + Sync + 'static> hopr_api::chain::ChainKeyOperations
    for TestChainConnector<M>
{
    type Error = TestConnectorError;
    type Mapper = NoopKeyMapper;

    fn chain_key_to_packet_key(
        &self,
        chain: &hopr_api::types::primitive::prelude::Address,
    ) -> Result<Option<hopr_api::types::crypto::prelude::OffchainPublicKey>, Self::Error> {
        Ok(self.accounts.get(chain).map(|e| e.public_key))
    }

    fn packet_key_to_chain_key(
        &self,
        packet: &hopr_api::types::crypto::prelude::OffchainPublicKey,
    ) -> Result<Option<hopr_api::types::primitive::prelude::Address>, Self::Error> {
        Ok(self
            .accounts
            .iter()
            .find(|e| &e.value().public_key == packet)
            .map(|e| e.value().chain_addr))
    }

    fn key_id_mapper_ref(&self) -> &Self::Mapper {
        static NOOP: NoopKeyMapper = NoopKeyMapper;
        &NOOP
    }
}

// ── ChainValues ───────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl<M: BlokliTestStateMutator + Clone + Send + Sync + 'static> hopr_api::chain::ChainValues for TestChainConnector<M> {
    type Error = TestConnectorError;

    async fn balance<
        C: hopr_api::types::primitive::prelude::Currency,
        A: Into<hopr_api::types::primitive::prelude::Address> + Send,
    >(
        &self,
        address: A,
    ) -> Result<hopr_api::types::primitive::prelude::Balance<C>, Self::Error> {
        self.faults.gate(ChainOp::Balance).await?;

        let address = address.into();
        if C::is::<WxHOPR>() {
            Ok(self
                .client
                .query_token_balance(&address.into(), blokli_client::types::Token::WxHOPR)
                .await?
                .balance
                .0
                .parse()?)
        } else if C::is::<XDai>() {
            Ok(self
                .client
                .query_native_balance(&address.into())
                .await?
                .balance
                .0
                .parse()?)
        } else {
            Err(anyhow::anyhow!("unsupported currency").into())
        }
    }

    async fn domain_separators(&self) -> Result<hopr_api::chain::DomainSeparators, Self::Error> {
        let info = self.client.query_chain_info().await?;
        Ok(Self::parse_chain_info_model(info)?.domain_separators)
    }

    async fn minimum_incoming_ticket_win_prob(
        &self,
    ) -> Result<hopr_api::types::internal::prelude::WinningProbability, Self::Error> {
        self.faults.gate(ChainOp::WinProb).await?;

        let info = self.client.query_chain_info().await?;
        Ok(Self::parse_chain_info_model(info)?.ticket_win_prob)
    }

    async fn minimum_ticket_price(&self) -> Result<hopr_api::types::primitive::prelude::HoprBalance, Self::Error> {
        self.faults.gate(ChainOp::TicketPrice).await?;

        let info = self.client.query_chain_info().await?;
        Ok(Self::parse_chain_info_model(info)?.ticket_price)
    }

    async fn key_binding_fee(&self) -> Result<hopr_api::types::primitive::prelude::HoprBalance, Self::Error> {
        let info = self.client.query_chain_info().await?;
        info.key_binding_fee
            .0
            .parse()
            .map_err(|e| TestConnectorError::from(anyhow::anyhow!("invalid key binding fee: {e}")))
    }

    async fn channel_closure_notice_period(&self) -> Result<std::time::Duration, Self::Error> {
        let info = self.client.query_chain_info().await?;
        Ok(Self::parse_chain_info_model(info)?.closure_grace_period)
    }

    async fn chain_info(&self) -> Result<hopr_api::chain::ChainInfo, Self::Error> {
        let info = self.client.query_chain_info().await?;
        Ok(Self::parse_chain_info_model(info)?.chain_info)
    }

    async fn redemption_stats<A: Into<hopr_api::types::primitive::prelude::Address> + Send>(
        &self,
        safe_addr: A,
    ) -> Result<hopr_api::chain::RedemptionStats, Self::Error> {
        let safe_addr = safe_addr.into();
        let stats = self
            .client
            .query_redeemed_stats(RedeemedStatsSelector::SafeAddress(safe_addr.into()))
            .await?;
        Ok(hopr_api::chain::RedemptionStats {
            redeemed_count: stats
                .redemption_count
                .0
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid redemption count"))?,
            redeemed_value: stats
                .redeemed_amount
                .0
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid redeemed amount"))?,
        })
    }

    async fn typical_resolution_time(&self) -> Result<std::time::Duration, Self::Error> {
        self.faults.gate(ChainOp::ResolutionTime).await?;

        Ok(std::time::Duration::from_secs(5))
    }
}

// ── ChainReadTicketOperations ─────────────────────────────────────────────────

impl<M: BlokliTestStateMutator + Clone + Send + Sync + 'static> hopr_api::chain::ChainReadTicketOperations
    for TestChainConnector<M>
{
    type Error = TestConnectorError;

    fn incoming_ticket_values(
        &self,
    ) -> Result<
        (
            hopr_api::types::internal::prelude::WinningProbability,
            hopr_api::types::primitive::prelude::HoprBalance,
        ),
        Self::Error,
    > {
        let win_prob = self
            .ticket_win_prob
            .get()
            .copied()
            .ok_or_else(|| TestConnectorError::from(anyhow::anyhow!("connector not connected")))?;
        let price = self
            .ticket_price
            .get()
            .cloned()
            .ok_or_else(|| TestConnectorError::from(anyhow::anyhow!("connector not connected")))?;
        Ok((win_prob, price))
    }
}

// ── ChainWriteTicketOperations ────────────────────────────────────────────────

#[async_trait::async_trait]
impl<M: BlokliTestStateMutator + Clone + Send + Sync + 'static> hopr_api::chain::ChainWriteTicketOperations
    for TestChainConnector<M>
{
    type Error = TestConnectorError;

    async fn redeem_ticket<'a>(
        &'a self,
        ticket: hopr_api::types::internal::prelude::RedeemableTicket,
    ) -> Result<
        futures::future::BoxFuture<
            'a,
            Result<
                (
                    hopr_api::types::internal::prelude::VerifiedTicket,
                    hopr_api::chain::ChainReceipt,
                ),
                hopr_api::chain::TicketRedeemError<Self::Error>,
            >,
        >,
        hopr_api::chain::TicketRedeemError<Self::Error>,
    > {
        let verified_ticket = ticket.ticket;
        let tx_req = self
            .payload_gen()
            .map_err(|e| {
                hopr_api::chain::TicketRedeemError::ProcessingError(verified_ticket, TestConnectorError::from(e))
            })?
            .redeem_ticket(ticket)
            .map_err(|e| {
                hopr_api::chain::TicketRedeemError::ProcessingError(
                    verified_ticket,
                    TestConnectorError::from(anyhow::anyhow!("{e}")),
                )
            })?;

        let chain_id = self.chain_id().map_err(|e| {
            hopr_api::chain::TicketRedeemError::ProcessingError(verified_ticket, TestConnectorError::from(e))
        })?;
        let chain_key = self.chain_key.clone();
        let nonce = self.nonce_for(&self.my_addr);
        let client = self.client.clone();

        Ok(Box::pin(async move {
            let receipt = Self::send_tx(&client, tx_req, chain_id, &chain_key, &nonce)
                .await
                .map_err(|e| {
                    hopr_api::chain::TicketRedeemError::ProcessingError(verified_ticket, TestConnectorError::from(e))
                })?;
            Ok((verified_ticket, receipt))
        }))
    }
}

// ── ComponentStatusReporter ───────────────────────────────────────────────────

impl<M: BlokliTestStateMutator + Clone + Send + Sync + 'static> hopr_api::node::ComponentStatusReporter
    for TestChainConnector<M>
{
    fn component_status(&self) -> hopr_api::node::ComponentStatus {
        hopr_api::node::ComponentStatus::Ready
    }
}

// ── PacketTransport ───────────────────────────────────────────────────────────

impl<M: BlokliTestStateMutator + Clone + Send + Sync + 'static> hopr_api::node::PacketTransport
    for TestChainConnector<M>
{
    fn packet_payload_size() -> usize {
        1036
    }
}

// ── Factory function ──────────────────────────────────────────────────────────

/// Creates and connects a [`TestChainConnector`] backed by the given blokli test client.
///
/// Equivalent to `create_trustful_hopr_blokli_connector` but without the
/// `hopr-chain-connector` git dependency.
pub async fn create_test_blokli_connector<M>(
    chain_key: &hopr_api::types::crypto::prelude::ChainKeypair,
    client: BlokliTestClient<M>,
    module_address: hopr_api::types::primitive::prelude::Address,
) -> anyhow::Result<TestChainConnector<M>>
where
    M: BlokliTestStateMutator + Clone + Send + Sync + 'static,
{
    let my_addr = chain_key.public().to_address();
    let mut connector = TestChainConnector::new(client, my_addr, chain_key.clone(), module_address);
    connector.connect().await?;
    Ok(connector)
}

/// Registers `node_address` in its pre-created safe.
///
/// After [`create_test_blokli_connector`] connects a node, call this so that
/// `safe_info(NodeAddress(me))` returns the safe — a prerequisite for strategies
/// that read the safe balance (e.g. `auto_funding`).
pub async fn register_test_safe<M>(
    connector: &TestChainConnector<M>,
    node_address: hopr_api::types::primitive::prelude::Address,
) -> anyhow::Result<()>
where
    M: BlokliTestStateMutator + Clone + Send + Sync + 'static,
{
    let account = connector
        .stream_accounts(AccountSelector::default().with_chain_key(node_address))
        .map_err(anyhow::Error::from)?
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("account not found for {node_address}"))?;

    let safe_address = account
        .safe_address
        .ok_or_else(|| anyhow::anyhow!("no safe address for node {node_address}"))?;

    connector
        .register_safe(&safe_address)
        .await
        .map_err(|e| anyhow::anyhow!("register_safe submission failed: {e}"))?
        .await
        .map_err(|e| anyhow::anyhow!("register_safe confirmation failed: {e}"))?;

    Ok(())
}
