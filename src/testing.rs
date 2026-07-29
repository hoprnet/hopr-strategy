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
    ops::Add,
    str::FromStr,
    sync::{Arc, Mutex, atomic::Ordering},
    time::Duration,
};

use blokli_client::api::types::RedeemedStats;
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
        PacketTransport,
        EventWaitResult, HasChainApi, HasGraphView, HasNetworkView, HasTicketManagement, NodeOnchainIdentity,
        TicketEvent,
    },
    tickets::{ChannelStats, RedemptionResult, TicketManagement},
    types::{
        chain::{
            ParsedHoprChainAction, contract_addresses_for_network,
            prelude::{ContractAddresses, PayloadGenerator, SignableTransaction},
        },
        crypto::{
            prelude::{Keypair, OffchainKeypair, OffchainPublicKey},
            types::Hash,
        },
        internal::prelude::{
            AccountEntry, AccountType, ChannelBuilder, ChannelId, ChannelStatus, RedeemableTicket, VerifiedTicket,
            WinningProbability, generate_channel_id,
        },
        primitive::prelude::{Address, BytesRepresentable, HoprBalance, KeyIdent, WxHOPR, XDai, XDaiBalance},
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

    fn score(&self) -> f64 {
        0.0
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

    fn average_probe_rate(&self) -> f64 {
        0.0
    }

    fn score(&self) -> f64 {
        0.0
    }
}

impl hopr_api::graph::traits::EdgeNetworkObservableRead for EmptyMeasurement {
    fn is_connected(&self) -> bool {
        false
    }
}

impl hopr_api::graph::EdgeImmediateProtocolObservable for EmptyMeasurement {
    fn ack_rate(&self) -> Option<f64> {
        None
    }
}

impl hopr_api::graph::traits::EdgeProtocolObservable for EmptyMeasurement {
    fn capacity(&self) -> Option<u128> {
        None
    }
}

// ─── Test chain connector ────────────────────────────────────────────────────

pub use blokli_client::exports::Entry;
/// Re-exports of blokli testing types.
pub use blokli_client::{BlokliTestClient, BlokliTestState, BlokliTestStateMutator, BlokliTestStateSnapshot};

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

/// A [`BlokliTestStateMutator`] that does not update the state.
/// Any attempt for a state change will raise an error.
#[derive(Clone, Debug)]
pub struct StaticState;

impl BlokliTestStateMutator for StaticState {
    fn update_state(&self, _: &[u8], _: &mut BlokliTestState) -> Result<(), blokli_client::errors::BlokliClientError> {
        Err(
            blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!("static client must not update state"))
                .into(),
        )
    }
}

/// A [`BlokliTestStateMutator`] that updates the state based on the actions parsed from the signed transaction.
/// This tries to emulate the behavior of the HOPR smart contracts on-chain.
#[derive(Clone, Debug)]
pub struct FullStateEmulator(
    pub hopr_api::types::primitive::prelude::Address,
    pub Option<futures::channel::mpsc::UnboundedSender<hopr_api::types::chain::ParsedHoprChainAction>>,
);

const EMULATED_TX_PRICE: u128 = 1_u128;

impl FullStateEmulator {
    pub fn new(module: hopr_api::types::primitive::prelude::Address) -> Self {
        Self(module, None)
    }

    pub fn new_with_chain_events_interceptor(
        module: hopr_api::types::primitive::prelude::Address,
    ) -> (
        Self,
        impl futures::Stream<Item = hopr_api::types::chain::ParsedHoprChainAction>,
    ) {
        let (sender, receiver) = futures::channel::mpsc::unbounded();
        (Self(module, Some(sender)), receiver)
    }
}

impl BlokliTestStateMutator for FullStateEmulator {
    fn update_state(
        &self,
        signed_tx: &[u8],
        state: &mut BlokliTestState,
    ) -> Result<(), blokli_client::errors::BlokliClientError> {
        let addresses: ContractAddresses =
            serde_json::from_str(&state.chain_info.contract_addresses.0).map_err(|_| {
                blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!("failed to parse contract addresses"))
            })?;

        let (action, sender) = ParsedHoprChainAction::parse_from_eip2718(signed_tx, &self.0, &addresses)
            .map_err(|e| blokli_client::errors::ErrorKind::MockClientError(e.into()))?;
        tracing::debug!(%sender, ?action, "parsed action from signed transaction");

        match &action {
            ParsedHoprChainAction::RegisterSafeAddress(safe_address) => {
                if let Some(safe) = state.deployed_safes.get_mut(&const_hex::encode(safe_address)) {
                    if safe.registered_nodes.contains(&const_hex::encode(sender)) {
                        return Err(blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                            "node {sender} already registered at safe address {safe_address}"
                        ))
                        .into());
                    }
                    safe.registered_nodes.push(const_hex::encode(sender));

                    if let Some(account) = state.get_account_mut(&sender.into()) {
                        account.safe_address = Some(const_hex::encode(safe_address));
                        tracing::debug!(%sender, %safe_address, "registered safe address to account");
                    }
                } else {
                    return Err(blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                        "safe address {safe_address} is not a deployed safe"
                    ))
                    .into());
                }
            }
            ParsedHoprChainAction::Announce {
                packet_key,
                multiaddress,
            } => {
                if let Some(account) = state.get_account_mut(&sender.into()) {
                    account.packet_key = const_hex::encode(packet_key);
                    if let Some(multiaddress) = multiaddress.clone() {
                        if !multiaddress.is_empty() {
                            account.multi_addresses.push(multiaddress.to_string());
                        } else {
                            return Err(blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                                "multiaddress must not be empty"
                            ))
                            .into());
                        }
                    }
                    tracing::debug!(%sender, %packet_key, ?multiaddress, "node re-announced");
                } else {
                    let next_key_id = state.accounts.keys().max().map(|k| k + 1).unwrap_or(1);
                    state.accounts.insert(
                        next_key_id,
                        blokli_client::api::types::Account {
                            chain_key: const_hex::encode(sender),
                            keyid: next_key_id as i32,
                            multi_addresses: multiaddress.iter().map(|a| a.to_string()).collect(),
                            packet_key: const_hex::encode(packet_key),
                            safe_address: state
                                .get_safe_by_owner(&sender.into())
                                .first()
                                .map(|s| s.address.clone()),
                        },
                    );
                    tracing::debug!(%sender, %packet_key, ?multiaddress, "node announced");
                }
            }
            ParsedHoprChainAction::WithdrawNative(destination, amount) => {
                let balance = state.native_balances.get_mut(&const_hex::encode(sender)).ok_or(
                    blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                        "missing native balance for {sender}"
                    )),
                )?;

                let balance_num = balance.balance.0.parse::<XDaiBalance>().map_err(|_| {
                    blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                        "failed to parse token balance for {sender}"
                    ))
                })?;

                if &balance_num < amount {
                    return Err(blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                        "balance {balance_num} for {sender} is lower than amount {amount}"
                    ))
                    .into());
                }

                balance.balance = blokli_client::api::types::TokenValueString((balance_num - *amount).to_string());

                match state.native_balances.entry(const_hex::encode(destination)) {
                    Entry::Occupied(mut dst_balance) => {
                        let new_balance = dst_balance.get().balance.0.parse::<XDaiBalance>().map_err(|_| {
                            blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                                "failed to parse native balance for {destination}"
                            ))
                        })? + *amount;
                        dst_balance.get_mut().balance =
                            blokli_client::api::types::TokenValueString(new_balance.to_string());
                        tracing::debug!(%sender, %amount, %destination, "xdai withdrawn to an existing account");
                    }
                    Entry::Vacant(new_balance) => {
                        new_balance.insert(blokli_client::api::types::NativeBalance {
                            __typename: "NativeBalance".into(),
                            balance: blokli_client::api::types::TokenValueString(amount.to_string()),
                        });
                        tracing::debug!(%sender, %amount, %destination, "xdai withdrawn to a new account");
                    }
                }
            }
            ParsedHoprChainAction::WithdrawToken(destination, amount) => {
                let balance = state.token_balances.get_mut(&const_hex::encode(sender)).ok_or(
                    blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                        "missing token balance for {sender}"
                    )),
                )?;

                let balance_num = balance.balance.0.parse::<HoprBalance>().map_err(|_| {
                    blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                        "failed to parse token balance for {sender}"
                    ))
                })?;

                if &balance_num < amount {
                    return Err(blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                        "balance {balance_num} for {sender} is lower than amount {amount}"
                    ))
                    .into());
                }

                balance.balance = blokli_client::api::types::TokenValueString((balance_num - *amount).to_string());

                match state.token_balances.entry(const_hex::encode(destination)) {
                    Entry::Occupied(mut dst_balance) => {
                        let new_balance = dst_balance.get().balance.0.parse::<HoprBalance>().map_err(|_| {
                            blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                                "failed to parse token balance for {destination}"
                            ))
                        })? + *amount;
                        dst_balance.get_mut().balance =
                            blokli_client::api::types::TokenValueString(new_balance.to_string());
                        tracing::debug!(%sender, %amount, %destination, "wxhopr withdrawn to an existing account");
                    }
                    Entry::Vacant(new_balance) => {
                        new_balance.insert(blokli_client::api::types::HoprBalance {
                            __typename: "HoprBalance".into(),
                            balance: blokli_client::api::types::TokenValueString(amount.to_string()),
                        });
                        tracing::debug!(%sender, %amount, %destination, "wxhopr withdrawn to a new account");
                    }
                }
            }
            ParsedHoprChainAction::FundChannel(dst_addr, stake) => {
                let source = state.get_account(&sender.into()).cloned().ok_or(
                    blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!("missing account for {sender}")),
                )?;
                let destination = state.get_account(&(*dst_addr).into()).cloned().ok_or(
                    blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                        "missing account for {dst_addr}"
                    )),
                )?;

                if stake.is_zero() {
                    return Err(blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                        "stake must be greater than zero"
                    ))
                    .into());
                }

                {
                    let safe_balance = state.get_account_safe_token_balance_mut(&sender.into()).ok_or(
                        blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                            "missing safe balance for {sender}"
                        )),
                    )?;

                    let safe_balance_num = safe_balance.balance.0.parse::<HoprBalance>().map_err(|_| {
                        blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                            "failed to parse safe balance for safe of {sender}"
                        ))
                    })?;

                    if &safe_balance_num < stake {
                        return Err(blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                            "safe balance of {sender} for {sender} is lower than stake {stake}"
                        ))
                        .into());
                    }

                    safe_balance.balance =
                        blokli_client::api::types::TokenValueString((safe_balance_num - *stake).to_string());
                }

                {
                    let safe_allowance = state.get_account_safe_allowance_mut(&sender.into()).ok_or(
                        blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                            "missing safe allowance for {sender}"
                        )),
                    )?;

                    let safe_allowance_num = safe_allowance.allowance.0.parse::<HoprBalance>().map_err(|_| {
                        blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                            "failed to parse safe allowance for {sender}"
                        ))
                    })?;

                    if &safe_allowance_num < stake {
                        return Err(blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                            "safe allowance for {sender} is lower than stake {stake}"
                        ))
                        .into());
                    }

                    safe_allowance.allowance =
                        blokli_client::api::types::TokenValueString((safe_allowance_num - *stake).to_string());
                }

                if let Some(existing_channel) = state
                    .channels
                    .values_mut()
                    .find(|c| c.source == source.keyid && c.destination == destination.keyid)
                {
                    if existing_channel.status == blokli_client::api::types::ChannelStatus::Closed {
                        existing_channel.status = blokli_client::api::types::ChannelStatus::Open;
                        existing_channel.ticket_index = blokli_client::api::types::Uint64("0".into());
                        existing_channel.closure_time = None;
                        existing_channel.epoch += 1;
                        tracing::debug!(%sender, %dst_addr, %stake, "channel re-opened");
                    }

                    let balance = existing_channel.balance.0.parse::<HoprBalance>().map_err(|_| {
                        blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                            "failed to parse balance on channel {sender} -> {dst_addr}"
                        ))
                    })?;

                    existing_channel.balance =
                        blokli_client::api::types::TokenValueString((balance + *stake).to_string());
                    tracing::debug!(%sender, %dst_addr, %stake, "channel funded");
                } else {
                    let new_id = generate_channel_id(&sender, dst_addr);
                    state.channels.insert(
                        const_hex::encode(new_id),
                        blokli_client::api::types::Channel {
                            balance: blokli_client::api::types::TokenValueString(stake.to_string()),
                            closure_time: None,
                            concrete_channel_id: const_hex::encode(new_id),
                            destination: destination.keyid,
                            epoch: 1,
                            source: source.keyid,
                            status: blokli_client::api::types::ChannelStatus::Open,
                            ticket_index: blokli_client::api::types::Uint64("0".into()),
                        },
                    );
                    tracing::debug!(%sender, %dst_addr, %stake, "channel opened");
                }
            }
            ParsedHoprChainAction::InitializeChannelClosure(channel_id) => {
                let grace_period = &state.chain_info.channel_closure_grace_period.0;
                let grace_period = u64::from_str(grace_period)
                    .map(|p| std::time::Duration::from_secs(p).max(std::time::Duration::from_secs(2)))
                    .map_err(|_| {
                        blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                            "failed to parse channel closure grace period"
                        ))
                    })?;

                let channel = state.get_channel_by_id_mut(&channel_id.into()).ok_or(
                    blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!("missing channel {channel_id}")),
                )?;

                channel.status = blokli_client::api::types::ChannelStatus::PendingToClose;
                channel.closure_time = Some(blokli_client::api::types::DateTime(
                    hopr_api::chain::DateTime::from(std::time::SystemTime::now().add(grace_period)).to_rfc3339(),
                ));
                tracing::debug!(%channel_id, "channel closure initialized");
            }
            ParsedHoprChainAction::FinalizeChannelClosure(channel_id) => {
                let channel = state.get_channel_by_id_mut(&channel_id.into()).ok_or(
                    blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!("missing channel {channel_id}")),
                )?;

                if channel.status != blokli_client::api::types::ChannelStatus::PendingToClose {
                    return Err(blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                        "channel {channel_id} is not pending to close"
                    ))
                    .into());
                }

                channel.status = blokli_client::api::types::ChannelStatus::Closed;
                tracing::debug!(%channel_id, "channel closure finalized");
            }
            ParsedHoprChainAction::IncomingChannelClosure(channel_id) => {
                let channel = state.get_channel_by_id_mut(&channel_id.into()).ok_or(
                    blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!("missing channel {channel_id}")),
                )?;

                channel.status = blokli_client::api::types::ChannelStatus::Closed;
                tracing::debug!(%channel_id, "incoming channel closed");
            }
            ParsedHoprChainAction::RedeemTicket {
                channel_id,
                ticket_index,
                ticket_amount,
            } => {
                let channel = state.get_channel_by_id_mut(&channel_id.into()).ok_or(
                    blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!("missing channel {channel_id}")),
                )?;

                if channel.status == blokli_client::api::types::ChannelStatus::Closed {
                    return Err(blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                        "channel {channel_id} is closed"
                    ))
                    .into());
                }

                let channel_ticket_index = u64::from_str(&channel.ticket_index.0).map_err(|_| {
                    blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                        "failed to parse ticket index of {channel_id}"
                    ))
                })?;

                if &channel_ticket_index > ticket_index {
                    return Err(blokli_client::errors::ErrorKind::MockClientError(
                        blokli_client::errors::InternalTxError(anyhow::anyhow!(
                            "ticket index of {channel_id} ({channel_ticket_index}) is greater than redeemed ticket \
                             index {ticket_index}"
                        ))
                        .into(),
                    )
                    .into());
                }

                let balance = channel.balance.0.parse::<HoprBalance>().map_err(|_| {
                    blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                        "failed to parse balance on channel {channel_id}"
                    ))
                })?;

                if &balance < ticket_amount {
                    return Err(blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                        "balance of channel {channel_id} ({balance}) is lower than ticket amount {ticket_amount}"
                    ))
                    .into());
                }

                channel.ticket_index = blokli_client::api::types::Uint64((*ticket_index + 1).to_string());
                channel.balance = blokli_client::api::types::TokenValueString((balance - *ticket_amount).to_string());

                let channel = channel.clone();
                if let Some(opposite_channel) = state
                    .channels
                    .values_mut()
                    .find(|c| c.source == channel.destination && c.destination == channel.source)
                {
                    let balance = opposite_channel.balance.0.parse::<HoprBalance>().map_err(|_| {
                        blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                            "failed to parse balance on opposite channel {channel_id}"
                        ))
                    })?;
                    opposite_channel.balance =
                        blokli_client::api::types::TokenValueString((balance + *ticket_amount).to_string());
                    tracing::debug!(%channel_id, %ticket_index, other_id = channel.concrete_channel_id, "ticket redeemed with channel rebalance");
                } else if let Some((safe_addr, safe_balance)) = state
                    .accounts
                    .get_mut(&(channel.destination as u32))
                    .and_then(|a| a.safe_address.clone())
                    .and_then(|safe_addr| state.token_balances.get_mut(&safe_addr).map(|b| (safe_addr, b)))
                {
                    let balance = safe_balance.balance.0.parse::<HoprBalance>().map_err(|_| {
                        blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                            "failed to parse balance on safe {safe_addr}"
                        ))
                    })?;
                    safe_balance.balance =
                        blokli_client::api::types::TokenValueString((balance + *ticket_amount).to_string());

                    match state.safe_redeem_stats.entry(safe_addr.clone()) {
                        Entry::Occupied(mut e) => {
                            let stats = e.get_mut();
                            let current_redeemed_amount: HoprBalance =
                                stats.redeemed_amount.0.parse().map_err(|_| {
                                    blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                                        "failed to parse redeemed value on {safe_addr}"
                                    ))
                                })?;
                            let current_redeemed_count: u64 = stats.redemption_count.0.parse().map_err(|_| {
                                blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                                    "failed to parse redeemed count on {safe_addr}"
                                ))
                            })?;

                            stats.redeemed_amount = blokli_client::api::types::TokenValueString(
                                (current_redeemed_amount + *ticket_amount).to_string(),
                            );
                            stats.redemption_count =
                                blokli_client::api::types::Uint64((current_redeemed_count + 1).to_string());
                        }
                        Entry::Vacant(v) => {
                            v.insert(RedeemedStats {
                                __typename: "RedeemedStats".to_string(),
                                redeemed_amount: blokli_client::api::types::TokenValueString(ticket_amount.to_string()),
                                redemption_count: blokli_client::api::types::Uint64("1".into()),
                                rejected_amount: blokli_client::api::types::TokenValueString("0".into()),
                                rejection_count: blokli_client::api::types::Uint64("0".into()),
                            });
                        }
                    }

                    tracing::debug!(%channel_id, %ticket_index, %safe_addr, "ticket redeemed into safe");
                } else {
                    tracing::debug!(%channel_id, %ticket_index, "ticket redeemed");
                }
            }
        }

        *state.tx_counts.entry(const_hex::encode(sender)).or_default() += 1;

        let balance = state.native_balances.get_mut(&const_hex::encode(sender)).ok_or(
            blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!("missing native balance for {sender}")),
        )?;

        let balance_num = balance
            .balance
            .0
            .parse::<hopr_api::types::primitive::prelude::XDaiBalance>()
            .map_err(|_| {
                blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                    "failed to parse native balance for {sender}"
                ))
            })?;

        if balance_num.amount() < EMULATED_TX_PRICE.into() {
            return Err(blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                "insufficient native funds for tx"
            ))
            .into());
        }

        balance.balance = blokli_client::api::types::TokenValueString((balance_num - EMULATED_TX_PRICE).to_string());

        if let Some(sender_tx) = &self.1 {
            sender_tx.unbounded_send(action).map_err(|_| {
                blokli_client::errors::ErrorKind::MockClientError(anyhow::anyhow!(
                    "failed to send tx to tx interceptor"
                ))
            })?;
        }

        Ok(())
    }
}

/// Allows chaining of two [mutators](BlokliTestStateMutator) into a single one (in order).
#[derive(Debug, Clone)]
pub struct ChainMutator<M1, M2> {
    mutator_1: M1,
    mutator_2: M2,
}

impl<M1, M2> ChainMutator<M1, M2> {
    /// Creates new chained mutator.
    ///
    /// The `mutator_1` is applied first, then `mutator_2`.
    pub fn new(mutator_1: M1, mutator_2: M2) -> Self {
        Self { mutator_1, mutator_2 }
    }
}

impl<M1: BlokliTestStateMutator, M2: BlokliTestStateMutator> BlokliTestStateMutator for ChainMutator<M1, M2> {
    fn update_state(
        &self,
        signed_tx: &[u8],
        state: &mut BlokliTestState,
    ) -> Result<(), blokli_client::errors::BlokliClientError> {
        self.mutator_1.update_state(signed_tx, state)?;
        self.mutator_2.update_state(signed_tx, state)?;
        Ok(())
    }
}

/// Builder for [`BlokliTestState`] using HOPR-native types.
#[derive(Clone)]
pub struct BlokliTestStateBuilder(BlokliTestState);

impl Default for BlokliTestStateBuilder {
    fn default() -> Self {
        Self(BlokliTestState::default()).with_hopr_network_chain_info("anvil-localhost")
    }
}

const DEFAULT_ALLOWANCE: u128 = 10_000_000_000_000_u128;

impl From<BlokliTestState> for BlokliTestStateBuilder {
    fn from(state: BlokliTestState) -> Self {
        Self(state)
    }
}

impl BlokliTestStateBuilder {
    /// Appends the initial [`ChannelEntries`](ChannelEntry) in the state.
    #[must_use]
    pub fn with_channels<I: IntoIterator<Item = hopr_api::types::internal::prelude::ChannelEntry>>(
        mut self,
        channels: I,
    ) -> Self {
        self.0.channels.extend(channels.into_iter().map(|channel| {
            (
                const_hex::encode(channel.get_id()),
                blokli_client::api::types::Channel {
                    balance: blokli_client::api::types::TokenValueString(channel.balance.to_string()),
                    closure_time: if let ChannelStatus::PendingToClose(time) = channel.status {
                        Some(blokli_client::api::types::DateTime(
                            hopr_api::chain::DateTime::from(time).to_rfc3339(),
                        ))
                    } else {
                        None
                    },
                    concrete_channel_id: const_hex::encode(channel.get_id()),
                    source: self
                        .0
                        .accounts
                        .values()
                        .find(|a| a.chain_key == const_hex::encode(channel.source))
                        .map(|a| a.keyid)
                        .unwrap_or_else(|| panic!("missing src account {}", channel.source)),
                    epoch: channel.channel_epoch as i32,
                    destination: self
                        .0
                        .accounts
                        .values()
                        .find(|a| a.chain_key == const_hex::encode(channel.destination))
                        .map(|a| a.keyid)
                        .unwrap_or_else(|| panic!("missing dst account {}", channel.destination)),
                    status: match channel.status {
                        ChannelStatus::Closed => blokli_client::api::types::ChannelStatus::Closed,
                        ChannelStatus::Open => blokli_client::api::types::ChannelStatus::Open,
                        ChannelStatus::PendingToClose(_) => blokli_client::api::types::ChannelStatus::PendingToClose,
                    },
                    ticket_index: blokli_client::api::types::Uint64(channel.ticket_index.to_string()),
                },
            )
        }));
        self
    }

    /// Appends the initial [`AccountEntries`](AccountEntry) in the state.
    #[must_use]
    pub fn with_accounts<
        I: IntoIterator<
            Item = (
                hopr_api::types::internal::prelude::AccountEntry,
                hopr_api::types::primitive::prelude::HoprBalance,
                hopr_api::types::primitive::prelude::XDaiBalance,
            ),
        >,
    >(
        mut self,
        accounts: I,
    ) -> Self {
        for (account, hopr_balance, native_balance) in accounts {
            match self.0.accounts.entry(account.key_id.into()) {
                Entry::Occupied(_) => panic!("duplicate key id for account {}", account.chain_addr),
                Entry::Vacant(v) => {
                    v.insert(blokli_client::api::types::Account {
                        chain_key: const_hex::encode(account.chain_addr),
                        keyid: u32::from(account.key_id) as i32,
                        multi_addresses: account.get_multiaddrs().iter().map(|a| a.to_string()).collect(),
                        packet_key: const_hex::encode(account.public_key),
                        safe_address: account.safe_address.map(const_hex::encode),
                    });
                    if let Some(safe_addr) = account.safe_address.as_ref().map(const_hex::encode) {
                        self.0.deployed_safes.insert(
                            safe_addr.clone(),
                            blokli_client::api::types::Safe {
                                address: safe_addr.clone(),
                                chain_key: const_hex::encode(account.chain_addr),
                                owners: [const_hex::encode(account.chain_addr)].to_vec(),
                                module_address: const_hex::encode(
                                    &Hash::create(&[account.chain_addr.as_ref()]).as_ref()[0..Address::SIZE],
                                ),
                                registered_nodes: vec![],
                                threshold: Some("1".to_string()),
                            },
                        );
                    }
                    self.0.token_balances.insert(
                        const_hex::encode(account.chain_addr),
                        blokli_client::api::types::HoprBalance {
                            __typename: "HoprBalance".to_string(),
                            balance: blokli_client::api::types::TokenValueString(HoprBalance::zero().to_string()),
                        },
                    );
                    self.0.native_balances.insert(
                        const_hex::encode(account.chain_addr),
                        blokli_client::api::types::NativeBalance {
                            __typename: "NativeBalance".to_string(),
                            balance: blokli_client::api::types::TokenValueString(native_balance.to_string()),
                        },
                    );
                    if let Some(addr) = account.safe_address.as_ref().map(const_hex::encode) {
                        self.0.token_balances.insert(
                            addr.clone(),
                            blokli_client::api::types::HoprBalance {
                                __typename: "HoprBalance".to_string(),
                                balance: blokli_client::api::types::TokenValueString(hopr_balance.to_string()),
                            },
                        );
                        self.0.native_balances.insert(
                            addr.clone(),
                            blokli_client::api::types::NativeBalance {
                                __typename: "NativeBalance".to_string(),
                                balance: blokli_client::api::types::TokenValueString(XDaiBalance::zero().to_string()),
                            },
                        );
                        self.0.safe_allowances.insert(
                            addr.clone(),
                            blokli_client::api::types::SafeHoprAllowance {
                                __typename: "SafeHoprAllowance".to_string(),
                                allowance: blokli_client::api::types::TokenValueString(
                                    HoprBalance::new_base(DEFAULT_ALLOWANCE).to_string(),
                                ),
                            },
                        );
                    }
                }
            }
        }
        self
    }

    /// Generates [`AccountEntries`](AccountEntry) for the given addresses.
    #[must_use]
    pub fn with_generated_accounts(
        self,
        addresses: &[&hopr_api::types::primitive::prelude::Address],
        public: bool,
        native: hopr_api::types::primitive::prelude::XDaiBalance,
        token: hopr_api::types::primitive::prelude::HoprBalance,
    ) -> Self {
        let next_id = self.0.accounts.keys().max().copied().map_or(0, |m| m + 1);
        self.with_accounts(addresses.iter().enumerate().map(|(index, &chain_addr)| {
            let pseudorandom_data = Hash::create(&[chain_addr.as_ref()]);
            let ok = OffchainKeypair::from_secret(pseudorandom_data.as_ref())
                .expect("offchain keypair creation cannot fail");
            let safe_addr = pseudorandom_data.hash();
            (
                AccountEntry {
                    public_key: *ok.public(),
                    chain_addr: *chain_addr,
                    entry_type: if public {
                        AccountType::Announced(vec![
                            format!("/ip4/1.2.3.4/udp/{}/p2p/{}", 10000 + index, ok.public().to_peerid_str())
                                .parse()
                                .unwrap(),
                        ])
                    } else {
                        AccountType::NotAnnounced
                    },
                    safe_address: Some(Address::new(&safe_addr.as_ref()[0..Address::SIZE])),
                    key_id: KeyIdent::from(next_id + index as u32),
                },
                token,
                native,
            )
        }))
    }

    /// Sets the initial Safe allowances.
    #[must_use]
    pub fn with_safe_allowances<
        I: IntoIterator<
            Item = (
                hopr_api::types::primitive::prelude::Address,
                hopr_api::types::primitive::prelude::HoprBalance,
            ),
        >,
    >(
        mut self,
        balances: I,
    ) -> Self {
        self.0
            .safe_allowances
            .extend(balances.into_iter().map(|(addr, allowance)| {
                (
                    const_hex::encode(addr),
                    blokli_client::api::types::SafeHoprAllowance {
                        __typename: "SafeAllowance".into(),
                        allowance: blokli_client::api::types::TokenValueString(allowance.to_string()),
                    },
                )
            }));
        self
    }

    /// Appends the initial [`DeployedSafes`](hopr_api::chain::DeployedSafe) to the state.
    #[must_use]
    pub fn with_deployed_safes<I: IntoIterator<Item = hopr_api::chain::DeployedSafe>>(mut self, safes: I) -> Self {
        self.0.deployed_safes.extend(safes.into_iter().map(|safe| {
            (
                const_hex::encode(safe.address),
                blokli_client::api::types::Safe {
                    address: const_hex::encode(safe.address),
                    chain_key: const_hex::encode(safe.deployer),
                    owners: safe.owners.into_iter().map(const_hex::encode).collect(),
                    module_address: const_hex::encode(safe.module),
                    registered_nodes: safe.registered_nodes.into_iter().map(const_hex::encode).collect(),
                    threshold: Some("1".to_string()),
                },
            )
        }));
        self
    }

    /// Sets [`ChainInfo`] to the state.
    #[must_use]
    pub fn with_chain_info(mut self, info: hopr_api::chain::ChainInfo) -> Self {
        self.0.chain_info.chain_id = info.chain_id as i32;
        self.0.chain_info.network = info.hopr_network_name;
        self.0.chain_info.contract_addresses = blokli_client::api::types::ContractAddressMap(
            serde_json::to_string(&info.contract_addresses).expect("failed to serialize contract addresses"),
        );
        self
    }

    /// Sets chain info based on the known HOPR network name.
    #[must_use]
    pub fn with_hopr_network_chain_info(mut self, name: &str) -> Self {
        let (chain_id, addrs) = contract_addresses_for_network(name).expect("network name not found");
        self.0.chain_info.network = name.to_string();
        self.0.chain_info.contract_addresses = blokli_client::api::types::ContractAddressMap(
            serde_json::to_string(&addrs).expect("failed to serialize contract addresses"),
        );
        self.0.chain_info.chain_id = chain_id as i32;
        self
    }

    /// Sets the ticket price.
    #[must_use]
    pub fn with_ticket_price(mut self, price: hopr_api::types::primitive::prelude::HoprBalance) -> Self {
        self.0.chain_info.ticket_price = blokli_client::api::types::TokenValueString(price.to_string());
        self
    }

    /// Sets the minimum winning probability.
    #[must_use]
    pub fn with_minimum_win_prob(mut self, prob: hopr_api::types::internal::prelude::WinningProbability) -> Self {
        self.0.chain_info.min_ticket_winning_probability = prob.as_f64();
        self
    }

    /// Sets the channel closure grace period.
    #[must_use]
    pub fn with_closure_grace_period(mut self, grace_period: std::time::Duration) -> Self {
        self.0.chain_info.channel_closure_grace_period =
            blokli_client::api::types::Uint64(grace_period.as_secs().to_string());
        self
    }

    /// Builds the state.
    #[must_use]
    pub fn build(self) -> BlokliTestState {
        self.0
    }

    /// Builds a static client (cannot mutate state).
    #[must_use]
    pub fn build_static_client(self) -> BlokliTestClient<StaticState> {
        BlokliTestClient::new(self.0, StaticState)
    }

    /// Builds a dynamic client (can mutate state via [`FullStateEmulator`]).
    #[must_use]
    pub fn build_dynamic_client(
        self,
        module_address: hopr_api::types::primitive::prelude::Address,
    ) -> BlokliTestClient<FullStateEmulator> {
        BlokliTestClient::new(self.0, FullStateEmulator(module_address, None))
            .with_tx_simulation_delay(std::time::Duration::ZERO)
    }

    /// Builds a dynamic client with a custom mutator.
    #[must_use]
    pub fn build_dynamic_client_with_mutator<M: BlokliTestStateMutator>(self, mutator: M) -> BlokliTestClient<M> {
        BlokliTestClient::new(self.0, mutator).with_tx_simulation_delay(std::time::Duration::ZERO)
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

/// A minimal chain connector backed by a [`BlokliTestClient`] for use in unit tests.
///
/// Wraps the test blokli client and implements all [`HoprChainApi`](hopr_api::chain::HoprChainApi)
/// sub-traits with `Error = anyhow::Error`. Write operations that unit tests
/// do not exercise return `unimplemented!()`.
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
    /// Nonce counter for transaction sequencing.
    nonce: std::sync::Arc<std::sync::atomic::AtomicU64>,
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
}

impl<M: BlokliTestStateMutator + Clone + Send + Sync + 'static> TestChainConnector<M> {
    fn new(
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
            nonce: Default::default(),
            accounts: Default::default(),
            channels: Default::default(),
        }
    }

    /// Loads initial state via finite queries and spawns a background task for live event forwarding.
    pub async fn connect(&mut self) -> anyhow::Result<()> {
        // Fetch chain info to initialize the payload generator.
        let chain_info = self.client.query_chain_info().await?;
        let chain_id = chain_info.chain_id as u64;
        let contract_addresses: hopr_api::types::chain::ContractAddresses =
            serde_json::from_str(&chain_info.contract_addresses.0)
                .map_err(|e| anyhow::anyhow!("invalid contract addresses: {e}"))?;
        let _ = self.chain_id.set(chain_id);
        let _ = self
            .payload_gen
            .set(hopr_api::types::chain::payload::SafePayloadGenerator::new(
                &self.chain_key,
                contract_addresses,
                self.module_address,
            ));

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
            self.channels.insert(channel_id, channel.clone());
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

            while let Ok(Some(entry)) = graph_stream.try_next().await {
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
                let old_channel = channels_cache.get(&channel_id).map(|r| r.clone());
                channels_cache.insert(channel_id, new_channel.clone());

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

    async fn send_tx(
        client: &BlokliTestClient<M>,
        tx_req: hopr_api::types::chain::payload::TransactionRequest,
        chain_id: u64,
        chain_key: &hopr_api::types::crypto::prelude::ChainKeypair,
        nonce: &std::sync::atomic::AtomicU64,
    ) -> anyhow::Result<hopr_api::chain::ChainReceipt> {
        let n = nonce.fetch_add(1, Ordering::Relaxed);
        let signed = tx_req.sign_and_encode_to_eip2718(n, chain_id, None, chain_key).await?;
        let receipt = client.submit_and_confirm_transaction(&signed, 1).await?;
        Ok(hopr_api::chain::ChainReceipt::from(receipt))
    }

    fn parse_chain_info_model(
        model: blokli_client::api::types::ChainInfo,
    ) -> anyhow::Result<(
        hopr_api::chain::ChainInfo,
        hopr_api::chain::DomainSeparators,
        hopr_api::types::internal::prelude::WinningProbability,
        hopr_api::types::primitive::prelude::HoprBalance,
        std::time::Duration,
    )> {
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

        Ok((
            chain_info,
            domain_separators,
            ticket_win_prob,
            ticket_price,
            channel_closure_grace_period,
        ))
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
        unimplemented!("TestChainConnector::announce")
    }

    async fn withdraw<C: hopr_api::types::primitive::prelude::Currency + Send>(
        &self,
        _balance: hopr_api::types::primitive::prelude::Balance<C>,
        _recipient: &hopr_api::types::primitive::prelude::Address,
    ) -> Result<futures::future::BoxFuture<'_, Result<hopr_api::chain::ChainReceipt, Self::Error>>, Self::Error> {
        unimplemented!("TestChainConnector::withdraw")
    }

    async fn withdraw_from_signer<C: hopr_api::types::primitive::prelude::Currency + Send>(
        &self,
        _signer: &hopr_api::types::crypto::prelude::ChainKeypair,
        _balance: hopr_api::types::primitive::prelude::Balance<C>,
        _recipient: &hopr_api::types::primitive::prelude::Address,
    ) -> Result<futures::future::BoxFuture<'_, Result<hopr_api::chain::ChainReceipt, Self::Error>>, Self::Error> {
        unimplemented!("TestChainConnector::withdraw_from_signer")
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
        let nonce = self.nonce.clone();
        Ok(Box::pin(async move {
            Self::send_tx(&client, tx_req, chain_id, &chain_key, &nonce)
                .await
                .map_err(TestConnectorError::from)
        }))
    }
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
        Ok(self.channels.get(channel_id).map(|e| e.clone()))
    }

    fn stream_channels<'a>(
        &'a self,
        selector: hopr_api::chain::ChannelSelector,
    ) -> Result<futures::stream::BoxStream<'a, hopr_api::types::internal::prelude::ChannelEntry>, Self::Error> {
        let entries: Vec<_> = self
            .channels
            .iter()
            .filter(|e| selector.satisfies(e.value()))
            .map(|e| e.value().clone())
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
        let tx_req = self.payload_gen()?.fund_channel(*dst, amount)?;
        let receipt = Self::send_tx(&self.client, tx_req, self.chain_id()?, &self.chain_key, &self.nonce)
            .await
            .map_err(TestConnectorError::from)?;
        Ok(Box::pin(async move { Ok(receipt) }))
    }

    async fn fund_channel<'a>(
        &'a self,
        channel_id: &'a hopr_api::types::internal::prelude::ChannelId,
        amount: hopr_api::types::primitive::prelude::HoprBalance,
    ) -> Result<futures::future::BoxFuture<'a, Result<hopr_api::chain::ChainReceipt, Self::Error>>, Self::Error> {
        let channel = self
            .channels
            .get(channel_id)
            .map(|e| e.clone())
            .ok_or_else(|| anyhow::anyhow!("channel {channel_id} not found"))?;

        let tx_req = self.payload_gen()?.fund_channel(channel.destination, amount)?;
        let receipt = Self::send_tx(&self.client, tx_req, self.chain_id()?, &self.chain_key, &self.nonce)
            .await
            .map_err(TestConnectorError::from)?;
        Ok(Box::pin(async move { Ok(receipt) }))
    }

    async fn close_channel<'a>(
        &'a self,
        channel_id: &'a hopr_api::types::internal::prelude::ChannelId,
    ) -> Result<futures::future::BoxFuture<'a, Result<hopr_api::chain::ChainReceipt, Self::Error>>, Self::Error> {
        let channel = self
            .channels
            .get(channel_id)
            .map(|e| e.clone())
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

        let receipt = Self::send_tx(&self.client, tx_req, self.chain_id()?, &self.chain_key, &self.nonce)
            .await
            .map_err(TestConnectorError::from)?;
        Ok(Box::pin(async move { Ok(receipt) }))
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
        unimplemented!("TestChainConnector::predict_module_address")
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
        unimplemented!("TestChainConnector::deploy_safe")
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
                let ch = e.value().clone();
                match ch.status {
                    ChannelStatus::Open => Some(ChainEvent::ChannelOpened(ch)),
                    ChannelStatus::PendingToClose(_) => Some(ChainEvent::ChannelClosureInitiated(ch)),
                    ChannelStatus::Closed => None,
                }
            })
            .collect();
        Ok(futures::stream::iter(snapshot).chain(self.events.1.activate_cloned()))
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
        Ok(Self::parse_chain_info_model(info)?.1)
    }

    async fn minimum_incoming_ticket_win_prob(
        &self,
    ) -> Result<hopr_api::types::internal::prelude::WinningProbability, Self::Error> {
        let info = self.client.query_chain_info().await?;
        Ok(Self::parse_chain_info_model(info)?.2)
    }

    async fn minimum_ticket_price(&self) -> Result<hopr_api::types::primitive::prelude::HoprBalance, Self::Error> {
        let info = self.client.query_chain_info().await?;
        Ok(Self::parse_chain_info_model(info)?.3)
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
        Ok(Self::parse_chain_info_model(info)?.4)
    }

    async fn chain_info(&self) -> Result<hopr_api::chain::ChainInfo, Self::Error> {
        let info = self.client.query_chain_info().await?;
        Ok(Self::parse_chain_info_model(info)?.0)
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
        // Return sensible defaults for tests
        let win_prob = hopr_api::types::internal::prelude::WinningProbability::try_from_f64(1.0)?;
        let price = hopr_api::types::primitive::prelude::HoprBalance::zero();
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
        let verified_ticket = ticket.ticket.clone();
        let tx_req = self
            .payload_gen()
            .map_err(|e| {
                hopr_api::chain::TicketRedeemError::ProcessingError(
                    verified_ticket.clone(),
                    TestConnectorError::from(e),
                )
            })?
            .redeem_ticket(ticket)
            .map_err(|e| {
                hopr_api::chain::TicketRedeemError::ProcessingError(
                    verified_ticket.clone(),
                    TestConnectorError::from(anyhow::anyhow!("{e}")),
                )
            })?;

        let chain_id = self.chain_id().map_err(|e| {
            hopr_api::chain::TicketRedeemError::ProcessingError(verified_ticket.clone(), TestConnectorError::from(e))
        })?;
        let chain_key = self.chain_key.clone();
        let nonce = self.nonce.clone();
        let client = self.client.clone();

        Ok(Box::pin(async move {
            let receipt = Self::send_tx(&client, tx_req, chain_id, &chain_key, &nonce)
                .await
                .map_err(|e| {
                    hopr_api::chain::TicketRedeemError::ProcessingError(
                        verified_ticket.clone(),
                        TestConnectorError::from(e),
                    )
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
