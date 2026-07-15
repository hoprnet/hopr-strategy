//! Connector construction and the common chain-only node adapter.

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

pub type NodeConnector = HoprBlockchainSafeConnector<blokli_client::BlokliClient>;

pub fn node_chain_keypair(secret: &[u8]) -> anyhow::Result<ChainKeypair> {
    ChainKeypair::from_secret(secret).map_err(|error| anyhow::anyhow!("invalid node secret: {error}"))
}

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

/// Adapts a chain connector to the minimal node interface used by strategies.
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
    ) -> EventWaitResult<Self::ChainError, Self::ChainError>
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
            .map_err(|error| error.to_string())?
            .map(ActionableEvent::Chain)
            .boxed())
    }
}
