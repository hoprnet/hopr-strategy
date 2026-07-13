//! Bridge from the live Blokli connector to the node interface strategies expect.
//!
//! This is the `hopr-api` 1.15 side of the harness. A [`ChainNode`] newtype wraps
//! a real `HoprBlockchainSafeConnector` (talking to the anvil-backed bloklid) and
//! implements the minimal node traits (`HasChainApi`, `ActionableEventSource`) so a
//! strategy can be built and run against it — exactly as the in-crate unit tests do,
//! but pointed at a real chain instead of the in-memory simulator.

use std::sync::Arc;

use futures::StreamExt;
use hopr_api::{
    chain::{ChainEvent, ChainEvents, HoprChainApi},
    node::{
        ActionableEvent, ActionableEventDiscriminant, ActionableEventSource, ComponentStatus, ComponentStatusReporter,
        EventWaitResult, HasChainApi, NodeOnchainIdentity,
    },
    types::crypto::prelude::{ChainKeypair, Keypair},
};
use hopr_chain_connector::{HoprBlockchainSafeConnector, create_trustful_hopr_blokli_connector};

/// The concrete connector type used by the integration tests: a Safe-based
/// connector over the real blokli client.
pub type NodeConnector = HoprBlockchainSafeConnector<blokli_client::BlokliClient>;

/// Reconstructs the strategy-side (`hopr-api` 1.15) chain keypair from raw secret
/// bytes obtained from an [`crate::support::anvil::AnvilAccount`] (whose key lives in the
/// `hopr-types` 1.11 world).
pub fn node_chain_keypair(secret: &[u8]) -> anyhow::Result<ChainKeypair> {
    ChainKeypair::from_secret(secret).map_err(|e| anyhow::anyhow!("invalid node secret: {e}"))
}

/// Builds and connects a trustful Safe connector for the node identified by
/// `secret`, routing writes through the node's Safe `module_address`.
///
/// `client` should be a clone of the fixture's blokli client so the connector
/// shares the same anvil-backed bloklid endpoint. Contract addresses are read
/// from bloklid (trustful).
pub async fn connect_node(
    client: blokli_client::BlokliClient,
    secret: &[u8],
    module_address: hopr_api::types::primitive::prelude::Address,
) -> anyhow::Result<Arc<NodeConnector>> {
    let chain_key = node_chain_keypair(secret)?;
    let mut connector =
        create_trustful_hopr_blokli_connector(&chain_key, Default::default(), client, module_address).await?;
    connector.connect().await?;
    Ok(Arc::new(connector))
}

/// Wraps a chain API implementor as a minimal node for strategy tests.
///
/// The connector itself is a chain API, not a node. This newtype implements the
/// `HasChainApi` and `ActionableEventSource` node traits so integration tests can
/// drive strategies without a full `Hopr` node. Mirrors the wrapper used by the
/// in-crate unit tests.
pub struct ChainNode<C>(pub C);

impl<C> HasChainApi for ChainNode<C>
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
        &self.0
    }

    fn status(&self) -> ComponentStatus {
        self.0.component_status()
    }

    fn wait_for_on_chain_event<F>(
        &self,
        _predicate: F,
        _context: String,
        _timeout: std::time::Duration,
    ) -> EventWaitResult<<C as HoprChainApi>::ChainError, <C as HoprChainApi>::ChainError>
    where
        F: Fn(&ChainEvent) -> bool + Send + Sync + 'static,
    {
        unimplemented!("integration tests do not call wait_for_on_chain_event")
    }
}

impl<C> ActionableEventSource for ChainNode<C>
where
    C: ChainEvents + Send + Sync + 'static,
{
    fn subscribe_to_actionable_events(
        &self,
        _filter: Option<&[ActionableEventDiscriminant]>,
    ) -> Result<futures::stream::BoxStream<'static, ActionableEvent>, String> {
        Ok(self
            .0
            .subscribe()
            .map_err(|e| e.to_string())?
            .map(ActionableEvent::Chain)
            .boxed())
    }
}
