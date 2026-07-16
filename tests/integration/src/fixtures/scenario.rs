//! Higher-level scenario setup shared by the strategy integration tests: onboard
//! two accounts, open a channel between them, connect a node, and the polling
//! helpers used to observe channel state transitions.

use std::{str::FromStr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use blokli_client::api::types::Safe;
use hopr_api::{
    chain::ChainReadChannelOperations,
    types::{crypto::prelude::Keypair, internal::prelude::ChannelEntry, primitive::prelude::Address},
};
// Onboarding/channel fixture methods live in the `hopr-types` (1.x) type-world,
// which is distinct from `hopr-api`'s bundled `hopr-types`; funding amounts must
// use this one to match those signatures.
use hopr_types::primitive::prelude::HoprBalance;

use super::{IntegrationFixture, poll_stable, poll_until};
use crate::{
    anvil::AnvilAccount,
    constants::{SAFE_ALLOWANCE, SAFE_FUNDING},
    strategy_node::{NodeConnector, connect_node, node_chain_keypair},
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

/// A fully onboarded, open `source -> destination` channel that is already
/// visible to the connected node.
pub struct ChannelScenario {
    pub connector: Arc<NodeConnector>,
    pub source_safe: Safe,
    pub destination_safe: Safe,
    pub source_addr: Address,
    pub destination_addr: Address,
    pub initial: ChannelEntry,
}

impl IntegrationFixture {
    /// Onboards both accounts (safe deploy + announce), approves the source safe
    /// module, opens a `source -> destination` channel, connects a node to the
    /// requested party, and waits until the channel is visible to it.
    pub async fn open_channel_scenario(
        &self,
        source: &AnvilAccount,
        destination: &AnvilAccount,
        opts: ScenarioOpts,
    ) -> Result<ChannelScenario> {
        let source_safe = self
            .deploy_safe_and_announce(source, opts.source_funding)
            .await
            .context("failed to onboard scenario source")?;
        let destination_safe = self
            .deploy_safe_and_announce(destination, opts.destination_funding)
            .await
            .context("failed to onboard scenario destination")?;
        self.approve(source, opts.allowance, &source_safe.module_address)
            .await
            .context("failed to approve scenario source safe module")?;
        self.open_channel(source, destination, opts.stake, &source_safe.module_address)
            .await
            .context("failed to open scenario channel")?;

        let (secret, module) = match opts.connect_as {
            ChannelParty::Source => (source.secret_bytes(), &source_safe.module_address),
            ChannelParty::Destination => (destination.secret_bytes(), &destination_safe.module_address),
        };
        let connector = connect_node(self.client().clone(), &secret, Address::from_str(module)?)
            .await
            .context("failed to connect scenario node")?;

        let source_addr = node_chain_keypair(&source.secret_bytes())?.public().to_address();
        let destination_addr = node_chain_keypair(&destination.secret_bytes())?.public().to_address();

        let initial = await_channel(
            &connector,
            source_addr,
            destination_addr,
            self.timeouts().visibility,
            "scenario channel visible",
        )
        .await
        .context("scenario channel never became visible")?;

        Ok(ChannelScenario {
            connector,
            source_safe,
            destination_safe,
            source_addr,
            destination_addr,
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
    poll_until(description, timeout, Duration::from_millis(500), || {
        let connector = connector.clone();
        let predicate = predicate.clone();
        async move {
            Ok(connector
                .channel_by_parties(&from, &to)?
                .filter(|channel| predicate(channel)))
        }
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
    poll_stable(description, window, Duration::from_secs(1), || {
        let connector = connector.clone();
        let predicate = predicate.clone();
        async move {
            Ok(connector
                .channel_by_parties(&from, &to)?
                .filter(|channel| predicate(channel)))
        }
    })
    .await
}
