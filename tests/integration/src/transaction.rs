use anyhow::{Context, Result};
use hopr_bindings::exports::alloy::{
    consensus::{SignableTransaction, TxEip1559},
    eips::eip2718::Encodable2718,
    primitives::{Address as AlloyAddress, Bytes, TxKind, U256},
    signers::{Signer, local::PrivateKeySigner},
};
use hopr_types::crypto::keypairs::{ChainKeypair, Keypair};

/// Default EIP-1559 gas parameters for raw transactions submitted through blokli.
pub const DEFAULT_MAX_FEE_PER_GAS: u128 = 2_000_000_000;
pub const DEFAULT_MAX_PRIORITY_FEE_PER_GAS: u128 = 1_000_000_000;
pub const DEFAULT_GAS_LIMIT: u64 = 10_000_000;

pub struct TransactionBuilder {
    signer: PrivateKeySigner,
}

impl TransactionBuilder {
    pub fn new(keypair: &ChainKeypair) -> Result<Self> {
        let signer: PrivateKeySigner = hex::encode(keypair.secret().as_ref()).parse()?;
        Ok(Self { signer })
    }

    /// Builds and signs an EIP-1559 contract-call transaction, returning the raw
    /// 2718-encoded bytes ready to submit through the blokli client.
    pub async fn build_call_tx(
        &self,
        chain_id: u64,
        nonce: u64,
        to: AlloyAddress,
        value: U256,
        input: Bytes,
    ) -> Result<Vec<u8>> {
        let tx = TxEip1559 {
            chain_id,
            nonce,
            max_fee_per_gas: DEFAULT_MAX_FEE_PER_GAS,
            max_priority_fee_per_gas: DEFAULT_MAX_PRIORITY_FEE_PER_GAS,
            gas_limit: DEFAULT_GAS_LIMIT,
            to: TxKind::Call(to),
            value,
            access_list: Default::default(),
            input,
        };

        let tx_hash = tx.signature_hash();
        let signature = self
            .signer
            .sign_hash(&tx_hash)
            .await
            .context("failed to sign transaction hash")?;
        let signed = tx.into_signed(signature);

        let mut encoded = Vec::new();
        signed.encode_2718(&mut encoded);
        Ok(encoded)
    }
}
