//! Construction of the live chain connector the strategies run against.
//!
//! The node adapters that wrap this connector into the `hopr_api` node traits
//! (`ChainNode`, `LifecycleNode`, `TicketNode`, ...) live in
//! [`hopr_strategy::testing`] and are shared with the strategy crate's own unit
//! tests.

use std::sync::Arc;

use hopr_api::types::{
    crypto::prelude::{ChainKeypair, Keypair},
    primitive::prelude::Address,
};
use hopr_chain_connector::{HoprBlockchainSafeConnector, create_trustful_hopr_blokli_connector};

pub type NodeConnector = HoprBlockchainSafeConnector<blokli_client::BlokliClient>;

pub fn node_chain_keypair(secret: &[u8]) -> anyhow::Result<ChainKeypair> {
    ChainKeypair::from_secret(secret).map_err(|error| anyhow::anyhow!("invalid node secret: {error}"))
}

pub async fn connect_node(
    client: blokli_client::BlokliClient,
    secret: &[u8],
    module_address: Address,
) -> anyhow::Result<Arc<NodeConnector>> {
    let chain_key = node_chain_keypair(secret)?;
    let mut connector =
        create_trustful_hopr_blokli_connector(&chain_key, Default::default(), client, module_address).await?;
    connector.connect().await?;
    Ok(Arc::new(connector))
}
