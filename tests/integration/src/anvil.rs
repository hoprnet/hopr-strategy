use std::str::FromStr;

use anyhow::{Context, Result};
use hopr_bindings::exports::alloy::primitives::Address as AlloyAddress;
use hopr_types::{
    crypto::keypairs::{ChainKeypair, Keypair, OffchainKeypair},
    internal::announcement::KeyBinding,
    primitive::prelude::Address,
};

#[derive(Clone, Debug)]
pub struct AnvilAccount {
    pub keypair: ChainKeypair,
    pub address: Address,
}

impl AnvilAccount {
    pub(crate) fn new(private_key: String, address: String) -> Result<Self> {
        let parsed_private_key = hex::decode(private_key.strip_prefix("0x").unwrap_or(&private_key))
            .context("invalid Anvil private key hex")?;

        let keypair = ChainKeypair::from_secret(&parsed_private_key).context("invalid Anvil private key")?;

        let parsed_address = Address::from_str(&address).context("invalid Anvil account address")?;

        Ok(Self {
            keypair,
            address: parsed_address,
        })
    }

    /// Raw secret bytes of the account key. Used to reconstruct the equivalent
    /// key in the `hopr-api` 1.15 type-world for the strategy connector.
    pub fn secret_bytes(&self) -> Vec<u8> {
        self.keypair.secret().as_ref().to_vec()
    }

    pub(crate) fn to_alloy_address(&self) -> AlloyAddress {
        AlloyAddress::from_str(&self.address.to_string()).expect("Invalid address hex")
    }

    pub(crate) fn keybinding(&self) -> KeyBinding {
        KeyBinding::new(self.address, &self.offchain_keypair())
    }

    fn offchain_keypair(&self) -> OffchainKeypair {
        OffchainKeypair::from_secret(self.keypair.secret().as_ref()).expect("Invalid private key hex")
    }
}
