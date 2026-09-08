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
    sync::{Arc, Mutex},
    time::Duration,
};

use futures::{StreamExt, stream::BoxStream};
use hopr_api::{
    PeerId,
    chain::{ChainEvent, ChainEvents, ChainWriteTicketOperations, HoprChainApi, TicketRedeemError},
    node::{
        ActionableEvent, ActionableEventDiscriminant, ActionableEventSource, ComponentStatus, ComponentStatusReporter,
        EventWaitResult, HasChainApi, HasGraphView, HasNetworkView, HasTicketManagement, NodeOnchainIdentity,
        PacketTransport, PixEvent, TicketEvent,
    },
    tickets::{ChannelStats, RedemptionResult, TicketManagement},
    types::{
        crypto::prelude::{Keypair, OffchainKeypair, OffchainPublicKey},
        internal::prelude::{ChannelId, RedeemableTicket, VerifiedTicket},
        primitive::prelude::HoprBalance,
    },
};

/// Implements the (identical across adapters) `HasChainApi` surface for a node
/// newtype, given an expression yielding a `&C` reference to its chain field.
macro_rules! impl_has_chain_api {
    ($ty:ident, |$node:ident| $chain:expr) => {
        impl<C> HasChainApi for $ty<C>
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

/// Chain-only node augmented with inert network and graph views, as required by
/// the channel-lifecycle strategy. The views are empty: population/proactive
/// passes that consult them are expected to be neutralised in the test config.
pub struct LifecycleNode<C> {
    chain: C,
    graph: EmptyGraph,
}

impl<C> LifecycleNode<C> {
    pub fn new(chain: C) -> Self {
        Self {
            chain,
            graph: EmptyGraph,
        }
    }
}

impl_has_chain_api!(LifecycleNode, |node| &node.chain);

impl<C> ActionableEventSource for LifecycleNode<C>
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

impl<C> HasNetworkView for LifecycleNode<C>
where
    C: HoprChainApi + ComponentStatusReporter + Clone + Send + Sync + 'static,
{
    type NetworkView = EmptyNetworkView;

    fn network_view(&self) -> &Self::NetworkView {
        static VIEW: EmptyNetworkView = EmptyNetworkView;
        &VIEW
    }

    fn status(&self) -> ComponentStatus {
        ComponentStatus::Ready
    }
}

impl<C> HasGraphView for LifecycleNode<C>
where
    C: HoprChainApi + ComponentStatusReporter + Clone + Send + Sync + 'static,
{
    type Graph = EmptyGraph;

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

impl<C: PacketTransport> PacketTransport for LifecycleNode<C> {
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

// ─── Test chain connector ────────────────────────────────────────────────────
//
// The Blokli state emulator (state, builder, mutator trait, test client) and the
// `TestChainConnector` that adapts it to `hopr_api::chain::HoprChainApi` both live
// upstream in `hopr-utilities` — see `hopr_utils::testing::blokli`. Only the
// strategy-specific node adapters above are local to this crate.
pub use hopr_utils::testing::blokli::{
    BlokliTestClient, BlokliTestState, BlokliTestStateBuilder, BlokliTestStateMutator, BlokliTestStateSnapshot,
    ChainFaults, ChainInfo, ChainMutator, ChainOp, Entry, EventKind, Fault, FullStateEmulator, NoopKeyMapper,
    StaticState, TestChainConnector, TestConnectorError, create_test_blokli_connector, register_test_safe,
};

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
