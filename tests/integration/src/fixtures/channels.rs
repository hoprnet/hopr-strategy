use std::str::FromStr;

use anyhow::Result;
use hopr_types::{
    chain::{
        payload::{PayloadGenerator, SafePayloadGenerator},
        prelude::SignableTransaction,
    },
    primitive::prelude::{Address as HoprAddress, HoprBalance},
};

use super::IntegrationFixture;
use crate::anvil::AnvilAccount;

impl IntegrationFixture {
    pub async fn open_channel(
        &self,
        from: &AnvilAccount,
        to: &AnvilAccount,
        amount: HoprBalance,
        module: &str,
    ) -> Result<[u8; 32]> {
        let nonce = self.nonce(from).await?;
        let generator = SafePayloadGenerator::new(
            &from.keypair,
            *self.contract_addresses(),
            HoprAddress::from_str(module)?,
        );
        let payload = generator.fund_channel(to.address, amount)?;
        let bytes = payload
            .sign_and_encode_to_eip2718(nonce, self.chain_id(), None, &from.keypair)
            .await?;
        self.submit_and_confirm_tx(&bytes, self.config().tx_confirmations).await
    }

    pub async fn initiate_outgoing_channel_closure(
        &self,
        from: &AnvilAccount,
        to: &AnvilAccount,
        module: &str,
    ) -> Result<[u8; 32]> {
        let nonce = self.nonce(from).await?;
        let generator = SafePayloadGenerator::new(
            &from.keypair,
            *self.contract_addresses(),
            HoprAddress::from_str(module)?,
        );
        let payload = generator.initiate_outgoing_channel_closure(to.address)?;
        let bytes = payload
            .sign_and_encode_to_eip2718(nonce, self.chain_id(), None, &from.keypair)
            .await?;
        self.submit_and_confirm_tx(&bytes, self.config().tx_confirmations).await
    }
}
