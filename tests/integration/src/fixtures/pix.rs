//! Scenario setup for the PIX strategy: a single connected node whose address and
//! Safe are funded, deposit addresses pre-created on the stub chain, and a
//! [`PixNode`] whose injectable event stream stands in for the PIX protocol.
//!
//! PIX involves no channels, so this is a sibling of the channel scenario rather
//! than a layer on top of it, but it reuses the same building blocks.

use std::{num::NonZeroU32, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use futures::StreamExt;
use hopr_api::{
    chain::{AccountSelector, ChainReadAccountOperations, ChainValues},
    node::{NodeOnchainIdentity, PixAddressId, PixDepositSecret, PixEvent},
    types::{
        internal::prelude::HoprPseudonym,
        primitive::prelude::{Address, BytesRepresentable, HoprBalance, XDaiBalance},
    },
};
use hopr_strategy::testing::{BlokliTestStateBuilder, PixNode, create_test_blokli_connector, register_test_safe};

use super::{IntegrationFixture, TestAccount, module_address, poll_stable, poll_until};
use crate::{
    constants::{NODE_FUNDING, SAFE_FUNDING},
    strategy_node::NodeConnector,
};

/// Poll interval for the balance helpers, matching `await_channel_where`.
const BALANCE_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Parameters for [`IntegrationFixture::open_pix_scenario`].
pub struct PixScenarioOpts {
    /// wxHOPR credited to the node address — the source a PIX deposit draws on.
    pub node_funding: HoprBalance,
    /// Deposit addresses to pre-create, with their initial wxHOPR and xDai.
    ///
    /// Both entries have to exist up front: balance queries against the stub chain
    /// fail for an address with no entry at all, and every emulated transaction
    /// charges its signer a native fee — so an address the strategy will later
    /// sweep needs non-zero xDai even when its token balance starts at zero.
    pub deposit_addresses: Vec<(Address, HoprBalance, XDaiBalance)>,
}

impl PixScenarioOpts {
    /// Defaults: node funded with `NODE_FUNDING`, each deposit address created
    /// empty but with enough xDai to sign its own sweep.
    pub fn new(deposit_addresses: &[Address]) -> Result<Self> {
        Ok(Self {
            node_funding: NODE_FUNDING.parse()?,
            deposit_addresses: deposit_addresses
                .iter()
                .map(|address| (*address, HoprBalance::zero(), XDaiBalance::new_base(1u32)))
                .collect(),
        })
    }

    /// Pre-credits `address` with `balance` wxHOPR, as if a deposit had already landed.
    pub fn with_deposited(mut self, address: Address, balance: HoprBalance) -> Self {
        match self.deposit_addresses.iter_mut().find(|(addr, ..)| *addr == address) {
            Some(entry) => entry.1 = balance,
            None => self
                .deposit_addresses
                .push((address, balance, XDaiBalance::new_base(1u32))),
        }
        self
    }
}

/// A connected node with an injectable PIX event stream.
pub struct PixScenario {
    pub connector: Arc<NodeConnector>,
    /// Node adapter to hand to `PixStrategy::build_non_anonymous`.
    pub node: Arc<PixNode<Arc<NodeConnector>>>,
    pub node_addr: Address,
    /// The node's generated Safe — the destination `build_non_anonymous` picks up
    /// from `identity()` and sweeps recovered deposits into.
    pub safe_addr: Address,
}

impl PixScenario {
    /// Emits a PIX event into the node's actionable-event stream.
    pub fn inject(&self, event: PixEvent) {
        self.node.inject_pix(event);
    }

    /// Reads the current wxHOPR balance of `address`.
    pub async fn hopr_balance(&self, address: Address) -> Result<HoprBalance> {
        ChainValues::balance(&*self.connector, address)
            .await
            .with_context(|| format!("failed to read wxHOPR balance of {address}"))
    }

    /// Polls until `address` holds a wxHOPR balance satisfying `predicate`.
    pub async fn await_hopr_balance<P>(
        &self,
        address: Address,
        timeout: Duration,
        description: &str,
        predicate: P,
    ) -> Result<HoprBalance>
    where
        P: Fn(&HoprBalance) -> bool + Clone + Send + 'static,
    {
        let connector = self.connector.clone();
        poll_until(description, timeout, BALANCE_POLL_INTERVAL, || {
            let connector = connector.clone();
            let predicate = predicate.clone();
            async move {
                let balance: HoprBalance = ChainValues::balance(&*connector, address).await?;
                Ok(Some(balance).filter(|balance| predicate(balance)))
            }
        })
        .await
    }

    /// Asserts `address` never holds a wxHOPR balance satisfying `predicate` for
    /// the whole `window`.
    pub async fn assert_hopr_balance_never<P>(
        &self,
        address: Address,
        window: Duration,
        description: &str,
        predicate: P,
    ) -> Result<()>
    where
        P: Fn(&HoprBalance) -> bool + Clone + Send + 'static,
    {
        let connector = self.connector.clone();
        poll_stable(description, window, BALANCE_POLL_INTERVAL, || {
            let connector = connector.clone();
            let predicate = predicate.clone();
            async move {
                let balance: HoprBalance = ChainValues::balance(&*connector, address).await?;
                Ok(Some(balance).filter(|balance| predicate(balance)))
            }
        })
        .await
    }
}

impl IntegrationFixture {
    /// Builds stub state with one funded node account plus the given deposit
    /// addresses, connects the node, registers its Safe, and wraps it in a
    /// [`PixNode`] carrying that node's real on-chain identity.
    pub async fn open_pix_scenario(&self, node: &TestAccount, opts: PixScenarioOpts) -> Result<PixScenario> {
        let client = BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&node.address],
                false,
                XDaiBalance::new_base(1u32),
                SAFE_FUNDING.parse()?,
            )
            // `with_generated_accounts` puts the token funding on the Safe and leaves
            // the node address at zero. A PIX deposit is a transfer signed by the node
            // key, and the emulator debits the signer, so credit the node directly.
            // Unlike `with_generated_accounts`, `with_balances` may be called repeatedly.
            .with_balances([(node.address, opts.node_funding)])
            .with_balances(opts.deposit_addresses.iter().map(|(addr, hopr, _)| (*addr, *hopr)))
            .with_balances(opts.deposit_addresses.iter().map(|(addr, _, native)| (*addr, *native)))
            .build_dynamic_client(module_address());

        let connector = create_test_blokli_connector(&node.keypair, client, module_address())
            .await
            .context("failed to connect pix node")?;
        register_test_safe(&connector, node.address)
            .await
            .context("failed to register pix node safe")?;
        let connector = Arc::new(connector);

        // Read the generated Safe back off the chain rather than re-deriving it.
        let safe_addr = connector
            .stream_accounts(AccountSelector::default().with_chain_key(node.address))?
            .next()
            .await
            .with_context(|| format!("no account for pix node {}", node.address))?
            .safe_address
            .with_context(|| format!("no safe address for pix node {}", node.address))?;

        let pix_node = Arc::new(PixNode::new(
            Arc::clone(&connector),
            NodeOnchainIdentity {
                node_address: node.address,
                safe_address: safe_addr,
                module_address: module_address(),
            },
        ));

        Ok(PixScenario {
            connector,
            node: pix_node,
            node_addr: node.address,
            safe_addr,
        })
    }
}

/// Builds a deterministic [`PixAddressId`] from a seed byte and an SSA index.
pub fn pix_address_id(seed: u8, ssa_index: u32) -> PixAddressId {
    (
        HoprPseudonym::from([seed; HoprPseudonym::SIZE]),
        NonZeroU32::new(ssa_index).expect("ssa index must be non-zero"),
    )
}

/// The PIX deposit secret of a deposit address claimed as a [`TestAccount`], so a
/// test can hand the strategy the very key that owns the address it funded.
pub fn deposit_secret(account: &TestAccount) -> Result<PixDepositSecret> {
    let secret: [u8; 32] = account
        .secret_bytes()
        .try_into()
        .context("chain keypair secret is not 32 bytes")?;
    Ok(PixDepositSecret(secret.into()))
}
