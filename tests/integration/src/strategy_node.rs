//! Construction of the stub chain connector the strategies run against.
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
use hopr_strategy::testing::{BlokliTestClient, FullStateEmulator, TestChainConnector, create_test_blokli_connector};

pub type NodeConnector = TestChainConnector<BlokliTestClient<FullStateEmulator>>;

pub fn node_chain_keypair(secret: &[u8]) -> anyhow::Result<ChainKeypair> {
    ChainKeypair::from_secret(secret).map_err(|e| anyhow::anyhow!("invalid node secret: {e}"))
}

pub async fn connect_node(
    client: BlokliTestClient<FullStateEmulator>,
    secret: &[u8],
    module_address: Address,
) -> anyhow::Result<Arc<NodeConnector>> {
    let chain_key = node_chain_keypair(secret)?;
    let connector = create_test_blokli_connector(&chain_key, client, module_address).await?;
    Ok(Arc::new(connector))
}
