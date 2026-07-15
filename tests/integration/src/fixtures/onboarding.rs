use std::{str::FromStr, time::Duration};

use anyhow::Result;
use blokli_client::api::{AccountSelector, BlokliQueryClient, SafeSelector, types::Safe};
use hopr_bindings::exports::alloy::primitives::U256;
use hopr_types::{
    chain::{
        payload::{BasicPayloadGenerator, PayloadGenerator, SafePayloadGenerator},
        prelude::SignableTransaction,
    },
    internal::{Multiaddr, announcement::AnnouncementData},
    primitive::{
        prelude::{Address as HoprAddress, HoprBalance},
        traits::IntoEndian,
    },
};
use tracing::debug;

use crate::anvil::AnvilAccount;

use super::{IntegrationFixture, poll_until};

impl IntegrationFixture {
    async fn deploy_safe(&self, owner: &AnvilAccount, amount: HoprBalance) -> Result<[u8; 32]> {
        let nonce = self.nonce(owner).await?;
        let contracts = self.contract_addresses();
        let payload = hopli_lib::payloads::edge_node_deploy_safe_module_and_maybe_include_node(
            contracts.node_stake_factory,
            contracts.token,
            contracts.channels,
            U256::from(nonce),
            U256::from_be_bytes(amount.to_be_bytes()),
            vec![owner.to_alloy_address()],
            true,
        )?;
        let bytes = payload
            .sign_and_encode_to_eip2718(nonce, self.chain_id(), None, &owner.keypair)
            .await?;
        self.submit_and_confirm_tx(&bytes, self.config().tx_confirmations).await
    }

    async fn deploy_or_get_safe(&self, owner: &AnvilAccount, amount: HoprBalance) -> Result<Safe> {
        let existing = self
            .client()
            .query_safe(SafeSelector::ChainKey(owner.to_alloy_address().into()))
            .await?
            .into_iter()
            .next();

        match existing {
            Some(safe) => Ok(safe),
            None => {
                self.deploy_safe(owner, amount).await?;
                let selector = SafeSelector::ChainKey(owner.to_alloy_address().into());
                let client = self.client().clone();
                let safe = poll_until(
                    "safe indexing",
                    self.config().timeouts.indexing,
                    Duration::from_millis(500),
                    || {
                        let client = client.clone();
                        let selector = selector.clone();
                        async move { Ok(client.query_safe(selector).await?.into_iter().next()) }
                    },
                )
                .await?;
                self.register_safe(owner, &safe.address).await?;
                Ok(safe)
            }
        }
    }

    async fn register_safe(&self, owner: &AnvilAccount, safe_address: &str) -> Result<[u8; 32]> {
        let nonce = self.nonce(owner).await?;
        let generator = BasicPayloadGenerator::new(owner.address, *self.contract_addresses());
        let payload = generator.register_safe_by_node(HoprAddress::from_str(safe_address)?)?;
        let bytes = payload
            .sign_and_encode_to_eip2718(nonce, self.chain_id(), None, &owner.keypair)
            .await?;
        self.submit_and_confirm_tx(&bytes, self.config().tx_confirmations).await
    }

    async fn announce_account(&self, account: &AnvilAccount, module: &str) -> Result<[u8; 32]> {
        let nonce = self.nonce(account).await?;
        let generator = SafePayloadGenerator::new(
            &account.keypair,
            *self.contract_addresses(),
            HoprAddress::from_str(module)?,
        );
        let multiaddress: Multiaddr = "/ip4/127.0.0.1/udp/3001".parse()?;
        let binding_fee = "0.01 wxHOPR".parse()?;
        let payload = generator.announce(
            AnnouncementData::new(account.keybinding(), Some(multiaddress))?,
            binding_fee,
        )?;
        let bytes = payload
            .sign_and_encode_to_eip2718(nonce, self.chain_id(), None, &account.keypair)
            .await?;
        self.submit_and_confirm_tx(&bytes, self.config().tx_confirmations).await
    }

    async fn announce_or_get_account(&self, account: &AnvilAccount, module: &str) -> Result<()> {
        let selector = AccountSelector::Address(account.to_alloy_address().into());
        if !self.client().query_accounts(selector.clone()).await?.is_empty() {
            return Ok(());
        }

        debug!("account not found, proceeding to announce");
        self.announce_account(account, module).await?;
        let client = self.client().clone();
        poll_until(
            "account indexing after announcement",
            self.config().timeouts.indexing,
            Duration::from_millis(500),
            || {
                let client = client.clone();
                let selector = selector.clone();
                async move {
                    let accounts = client.query_accounts(selector).await?;
                    Ok((!accounts.is_empty()).then_some(()))
                }
            },
        )
        .await
    }

    pub async fn approve(&self, owner: &AnvilAccount, amount: HoprBalance, module: &str) -> Result<[u8; 32]> {
        let nonce = self.nonce(owner).await?;
        let spender = HoprAddress::from_str(&self.contract_addresses().channels.to_string())?;
        let generator = SafePayloadGenerator::new(
            &owner.keypair,
            *self.contract_addresses(),
            HoprAddress::from_str(module)?,
        );
        let payload = generator.approve(spender, amount)?;
        let bytes = payload
            .sign_and_encode_to_eip2718(nonce, self.chain_id(), None, &owner.keypair)
            .await?;
        self.submit_and_confirm_tx(&bytes, self.config().tx_confirmations).await
    }

    pub async fn deploy_safe_and_announce(&self, owner: &AnvilAccount, amount: HoprBalance) -> Result<Safe> {
        let safe = self.deploy_or_get_safe(owner, amount).await?;
        self.announce_or_get_account(owner, &safe.module_address).await?;
        Ok(safe)
    }
}
