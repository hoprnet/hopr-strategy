//! Calldata for spending from the node's Safe through its permission module.
//!
//! A direct shield has to originate from the address that holds the wxHOPR, because the vault
//! pulls with `safeTransferFrom(msg.sender_of_the_aggregator_call, vault, amount)`. That address
//! is the node's Safe, and the Safe acts only through
//! `HoprNodeManagementModule.execTransactionFromModule`, which forwards to the Safe and so makes
//! the Safe the `msg.sender` of the inner call. The float therefore never leaves Safe custody —
//! which is the whole point of shielding this way rather than through an EOA.
//!
//! `hopr-api` exposes no generic "execute a call through the Safe" operation, and the encoders in
//! `hopr-types` are private, so the two payloads are built here. Both are plain ABI encodings of
//! well-known signatures, pinned by the golden vectors in this module's tests.
//!
//! ### What the module permits
//!
//! `execTransactionFromModule` is `nodeOnly` — the node's own chain key must sign it — and every
//! inner call is checked against the module's target set:
//!
//! * the target must be **scoped**, or the call reverts `NonExistentKey()`. wxHOPR already is; the Curvy aggregator has
//!   to be added once per Safe with `scopeTargetToken`, which accepts any address and, at
//!   `TargetPermission::ALLOW_ALL`, any selector.
//! * `value` must be zero unless the target is a `SEND` target, so this only ever moves ERC-20 value.
//! * `DelegateCall` is rejected unless the target is exactly the module's configured MultiSend — which is why
//!   [`CurvyDepositPoolConfig::safe_multisend_address`](super::CurvyDepositPoolConfig::safe_multisend_address) is
//!   configurable rather than compiled in.

use std::sync::Arc;

use blokli_client::api::{BlokliQueryClient, BlokliTransactionClient};
use hopr_api::{
    ChainKeypair,
    types::{chain::payload::GasEstimation, crypto::prelude::Keypair, primitive::prelude::Address},
};

use super::sdk::ShieldLanded;
use crate::errors::StrategyError;

/// `execTransactionFromModule(address,uint256,bytes,uint8)`.
const EXEC_TRANSACTION_FROM_MODULE: [u8; 4] = [0x46, 0x87, 0x21, 0xa7];
/// `multiSend(bytes)`.
const MULTI_SEND: [u8; 4] = [0x8d, 0x80, 0xff, 0x0a];
/// `approve(address,uint256)`.
const ERC20_APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];

/// Gnosis Safe `Enum.Operation`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Call = 0,
    DelegateCall = 1,
}

fn word(value: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&value.to_be_bytes());
    out
}

fn address_word(address: &Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(address.as_ref());
    out
}

/// Right-pads to the next 32-byte boundary, as the ABI requires for a dynamic tail.
fn pad_to_word(out: &mut Vec<u8>, len: usize) {
    out.extend(std::iter::repeat_n(0u8, (32 - len % 32) % 32));
}

/// `IERC20.approve(spender, amount)`.
pub fn encode_approve(spender: &Address, amount: u128) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 64);
    out.extend_from_slice(&ERC20_APPROVE);
    out.extend_from_slice(&address_word(spender));
    out.extend_from_slice(&word(amount));
    out
}

/// One entry of a MultiSend blob: `operation ‖ to ‖ value ‖ data.len ‖ data`, tightly packed.
///
/// Packed rather than ABI-encoded — MultiSend walks the blob with explicit offsets — so this is
/// the one payload here that is *not* a standard encoding.
fn multisend_entry(to: &Address, data: &[u8], operation: Operation) -> Vec<u8> {
    let mut out = Vec::with_capacity(85 + data.len());
    out.push(operation as u8);
    out.extend_from_slice(to.as_ref());
    out.extend_from_slice(&word(0));
    out.extend_from_slice(&word(data.len() as u128));
    out.extend_from_slice(data);
    out
}

/// `MultiSend.multiSend(transactions)` over the given calls, each an `Operation::Call`.
pub fn encode_multi_send(calls: &[(Address, Vec<u8>)]) -> Vec<u8> {
    let blob: Vec<u8> = calls
        .iter()
        .flat_map(|(to, data)| multisend_entry(to, data, Operation::Call))
        .collect();
    let mut out = Vec::with_capacity(4 + 64 + blob.len() + 32);
    out.extend_from_slice(&MULTI_SEND);
    // Offset to the single dynamic argument: one head word, so always 32.
    out.extend_from_slice(&word(32));
    out.extend_from_slice(&word(blob.len() as u128));
    out.extend_from_slice(&blob);
    pad_to_word(&mut out, blob.len());
    out
}

/// `HoprNodeManagementModule.execTransactionFromModule(to, value, data, operation)`.
///
/// `value` is always zero: the module refuses a non-zero value for anything but a `SEND` target,
/// and nothing here moves native currency.
pub fn encode_exec_from_module(to: &Address, data: &[u8], operation: Operation) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 128 + data.len() + 32);
    out.extend_from_slice(&EXEC_TRANSACTION_FROM_MODULE);
    out.extend_from_slice(&address_word(to));
    out.extend_from_slice(&word(0));
    // Offset to `data`: four head words.
    out.extend_from_slice(&word(4 * 32));
    out.extend_from_slice(&word(operation as u128));
    out.extend_from_slice(&word(data.len() as u128));
    out.extend_from_slice(data);
    pad_to_word(&mut out, data.len());
    out
}

/// The atomic `approve` + `directShield` bundle, as the module call that runs it.
///
/// One transaction rather than two, so no allowance outlives the shield it was granted for. The
/// bundle is a `DelegateCall` to `multisend`, which is the only target the module permits one
/// for; `multisend` must therefore be the module's own configured address.
pub fn encode_safe_direct_shield(
    multisend: &Address,
    token: &Address,
    vault: &Address,
    aggregator: &Address,
    gross: u128,
    direct_shield_calldata: Vec<u8>,
) -> Vec<u8> {
    let bundle = encode_multi_send(&[
        (*token, encode_approve(vault, gross)),
        (*aggregator, direct_shield_calldata),
    ]);
    encode_exec_from_module(multisend, &bundle, Operation::DelegateCall)
}

/// Signs and submits one `execTransactionFromModule` call with the node's own chain key.
///
/// A miniature transaction sequencer, and deliberately so. `hopr-chain-connector`'s real one —
/// which owns nonce caching, gas estimation and confirmation — lives behind a private module, and
/// `hopr-api` exposes no operation that would carry an arbitrary call through the Safe, so there
/// is nothing to delegate to.
///
/// ### Sharing the node's nonce
///
/// `execTransactionFromModule` is `nodeOnly`, so this must be signed by the node's own chain
/// key — the same key the node's connector uses for announcements, channel operations and ticket
/// redemptions, through a nonce cache this code cannot see. Two independent nonce sources on one
/// key can therefore pick the same value.
///
/// The mitigation is to **never raise the gas price**. A same-nonce transaction that does not
/// outbid the pending one is rejected as underpriced rather than replacing it, so the worst case
/// is that this shield fails and is retried — never that a node transaction is displaced. The
/// retry below re-queries the nonce rather than incrementing a local guess, for the same reason,
/// and only after the contested nonce is mined and the call is confirmed not to have executed:
/// see [`submit_reconciling_nonce_conflicts`].
///
/// The exposure is one transaction, once: the shield happens lazily on the first deposit and the
/// pool is funded thereafter.
pub struct SafeModuleSubmitter<C> {
    client: Arc<C>,
    chain_key: ChainKeypair,
    module: Address,
}

/// How many times to re-query the nonce and resubmit before giving up.
const NONCE_RETRIES: usize = 3;
/// How long to wait for a contested nonce to be mined before deciding whether to resubmit.
///
/// Whatever holds the nonce was priced at the chain's own quote, so it normally mines within a
/// block or two; a minute is generous. Running out is not a failure of the shield, only a refusal
/// to guess: nothing is resubmitted while the earlier transaction's outcome is unknown.
const NONCE_SETTLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const NONCE_SETTLE_POLL: std::time::Duration = std::time::Duration::from_secs(1);

impl<C> SafeModuleSubmitter<C>
where
    C: BlokliQueryClient + BlokliTransactionClient + Send + Sync + 'static,
{
    pub fn new(client: Arc<C>, chain_key: ChainKeypair, module: Address) -> Self {
        Self {
            client,
            chain_key,
            module,
        }
    }

    /// Submits `calldata` to the module and waits for one confirmation.
    ///
    /// Returns `Ok` either when this call's own transaction confirmed or when, after a nonce
    /// conflict, `already_executed` reports that an earlier copy of the call took effect. A
    /// confirmation says only that the *module call* was mined: the Safe reports a failed inner
    /// call without reverting, so the caller still has to check the effect itself.
    pub async fn submit(
        &self,
        calldata: Vec<u8>,
        gas_limit: u64,
        already_executed: ShieldLanded,
    ) -> Result<(), StrategyError> {
        let signer = self.chain_key.public().to_address();
        let transaction_count = || async move {
            self.client
                .query_transaction_count(&signer.into())
                .await
                .map_err(|error| StrategyError::other(anyhow::anyhow!("querying the node's nonce: {error}")))
        };
        let send = |nonce: u64| {
            let calldata = calldata.clone();
            async move {
                let (chain_id, gas) = self
                    .chain_parameters(gas_limit)
                    .await
                    .map_err(|error| error.to_string())?;
                let signed = curvy_abi::sign_eip1559_call(curvy_abi::Eip1559Call {
                    signer_secret: self.chain_key.secret().as_ref(),
                    to: self.module.into(),
                    calldata,
                    value: 0,
                    nonce,
                    gas_limit: gas.gas_limit,
                    max_fee_per_gas: gas.max_fee_per_gas,
                    max_priority_fee_per_gas: gas.max_priority_fee_per_gas,
                    chain_id,
                })
                .map_err(|error| format!("signing the Safe module call: {error}"))?;
                self.client
                    .submit_and_confirm_transaction(&signed.0, 1)
                    .await
                    .map(|receipt| format!("0x{}", const_hex::encode(receipt)))
                    .map_err(|error| error.to_string())
            }
        };
        submit_reconciling_nonce_conflicts(
            transaction_count,
            send,
            already_executed,
            NONCE_SETTLE_TIMEOUT,
            NONCE_SETTLE_POLL,
        )
        .await
    }

    /// Chain id and gas, taken from Blokli exactly as the node's own connector takes them so that
    /// this transaction is priced like every other one the node sends — never above.
    async fn chain_parameters(&self, gas_limit: u64) -> Result<(u64, GasEstimation), StrategyError> {
        let info = self
            .client
            .query_chain_info()
            .await
            .map_err(|error| StrategyError::other(anyhow::anyhow!("querying chain info: {error}")))?;
        let defaults = GasEstimation::default();
        let max_fee_per_gas = info
            .max_fee_per_gas
            .as_deref()
            .and_then(|raw| raw.parse::<u128>().ok())
            .unwrap_or(defaults.max_fee_per_gas);
        let max_priority_fee_per_gas = info
            .max_priority_fee_per_gas
            .as_deref()
            .and_then(|raw| raw.parse::<u128>().ok())
            .unwrap_or(defaults.max_priority_fee_per_gas)
            .min(max_fee_per_gas);
        let chain_id = u64::try_from(info.chain_id)
            .map_err(|_| StrategyError::other(anyhow::anyhow!("Blokli reported a negative chain id")))?;
        Ok((
            chain_id,
            GasEstimation {
                gas_limit,
                max_fee_per_gas,
                max_priority_fee_per_gas,
            },
        ))
    }
}

/// Whether a submission error is the nonce race described on [`SafeModuleSubmitter`], rather than
/// a fault worth surfacing.
///
/// Matched on text because the underlying client reports it as an opaque message; a node's own
/// transaction winning the nonce is normal and must not read as a shield failure.
fn is_nonce_conflict(message: &str) -> bool {
    let lowered = message.to_ascii_lowercase();
    ["nonce too low", "already known", "replacement transaction underpriced"]
        .iter()
        .any(|marker| lowered.contains(marker))
}

/// The retry policy of [`SafeModuleSubmitter::submit`], apart from the signing, so it can be
/// driven without a chain.
///
/// A nonce conflict is not proof that this call did not execute. "Already known" means an
/// identical transaction — an earlier copy of this very call — is pending; "replacement
/// underpriced" means *something* is pending at the nonce, possibly that copy; "nonce too low"
/// means the nonce was mined, possibly by that copy. Signing the same call again at the next nonce
/// in any of these cases could execute it twice, which for a shield pulls the float twice.
///
/// So before resubmitting, the contested nonce is waited out until it is mined (the transaction
/// count is Blokli's `latest`, not `pending`, count), and only then is the chain asked whether the
/// call took effect. Once the nonce is final, a copy that did not land by then never will.
async fn submit_reconciling_nonce_conflicts<N, NF, S, SF>(
    transaction_count: N,
    send: S,
    already_executed: ShieldLanded,
    settle_timeout: std::time::Duration,
    settle_poll: std::time::Duration,
) -> Result<(), StrategyError>
where
    N: Fn() -> NF,
    NF: Future<Output = Result<u64, StrategyError>>,
    S: Fn(u64) -> SF,
    SF: Future<Output = Result<String, String>>,
{
    let mut last_error = None;
    for attempt in 0..NONCE_RETRIES {
        let nonce = transaction_count().await?;
        let message = match send(nonce).await {
            Ok(hash) => {
                tracing::info!(tx = %hash, nonce, "the Safe module call confirmed");
                return Ok(());
            }
            Err(message) if is_nonce_conflict(&message) => message,
            Err(message) => {
                return Err(StrategyError::other(anyhow::anyhow!(
                    "submitting the Safe module call: {message}"
                )));
            }
        };
        tracing::debug!(
            attempt = attempt + 1,
            nonce,
            %message,
            "nonce {nonce} is contested; waiting for it to be mined before deciding whether to resubmit"
        );
        let deadline = tokio::time::Instant::now() + settle_timeout;
        while transaction_count().await? <= nonce {
            if tokio::time::Instant::now() >= deadline {
                return Err(StrategyError::other(anyhow::anyhow!(
                    "nonce {nonce} was still pending after {settle_timeout:?} ({message}); not resubmitting the Safe \
                     module call while an earlier copy of it may yet land"
                )));
            }
            tokio::time::sleep(settle_poll).await;
        }
        if already_executed()
            .await
            .map_err(|error| StrategyError::other(anyhow::anyhow!("checking whether the call executed: {error}")))?
        {
            tracing::info!(
                nonce,
                "an earlier copy of the Safe module call executed; not resubmitting"
            );
            return Ok(());
        }
        last_error = Some(message);
    }
    Err(StrategyError::other(anyhow::anyhow!(
        "the Safe module call lost the nonce race {NONCE_RETRIES} times, most recently: {}",
        last_error.unwrap_or_else(|| "unknown".to_owned())
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // The vectors below were produced by an independent reference encoder rather than by this
    // code, so they check the encoding itself and not merely that it has not changed.

    mod nonce_conflicts {
        use std::{
            sync::atomic::{AtomicBool, AtomicU64, Ordering},
            time::Duration,
        };

        use parking_lot::Mutex;

        use super::*;

        const SETTLE: Duration = Duration::from_secs(60);
        const POLL: Duration = Duration::from_secs(1);

        /// A chain whose latest nonce is `count`, recording every nonce a transaction was sent at.
        struct Chain {
            count: AtomicU64,
            sent: Mutex<Vec<u64>>,
            executed: Arc<AtomicBool>,
        }

        impl Chain {
            fn new(count: u64) -> Arc<Self> {
                Arc::new(Self {
                    count: AtomicU64::new(count),
                    sent: Mutex::new(Vec::new()),
                    executed: Arc::new(AtomicBool::new(false)),
                })
            }

            fn landed(&self) -> ShieldLanded {
                let executed = Arc::clone(&self.executed);
                Arc::new(move || {
                    let executed = executed.load(Ordering::SeqCst);
                    Box::pin(async move { Ok(executed) })
                })
            }

            async fn run(
                self: &Arc<Self>,
                outcome: impl Fn(&Self, u64) -> Result<String, String>,
            ) -> Result<(), StrategyError> {
                submit_reconciling_nonce_conflicts(
                    || async { Ok(self.count.load(Ordering::SeqCst)) },
                    |nonce| {
                        self.sent.lock().push(nonce);
                        let result = outcome(self, nonce);
                        async move { result }
                    },
                    self.landed(),
                    SETTLE,
                    POLL,
                )
                .await
            }
        }

        #[tokio::test(start_paused = true)]
        async fn an_earlier_copy_that_lands_is_not_resubmitted() -> anyhow::Result<()> {
            let chain = Chain::new(5);
            // Our own earlier copy is pending at nonce 5; it mines a few seconds later.
            let miner = {
                let chain = Arc::clone(&chain);
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    chain.executed.store(true, Ordering::SeqCst);
                    chain.count.store(6, Ordering::SeqCst);
                })
            };
            chain.run(|_, _| Err("already known".to_owned())).await?;
            miner.await?;
            assert_eq!(*chain.sent.lock(), vec![5], "signed once, never at nonce 6");
            Ok(())
        }

        #[tokio::test(start_paused = true)]
        async fn a_nonce_taken_by_another_transaction_is_retried_at_the_next() -> anyhow::Result<()> {
            let chain = Chain::new(5);
            chain
                .run(|chain, nonce| {
                    if nonce == 5 {
                        // The node's connector mined something else at 5 first.
                        chain.count.store(6, Ordering::SeqCst);
                        Err("nonce too low".to_owned())
                    } else {
                        Ok("0xabc".to_owned())
                    }
                })
                .await?;
            assert_eq!(*chain.sent.lock(), vec![5, 6]);
            Ok(())
        }

        #[tokio::test(start_paused = true)]
        async fn a_nonce_that_never_settles_is_not_resubmitted() {
            let chain = Chain::new(5);
            let error = chain
                .run(|_, _| Err("replacement transaction underpriced".to_owned()))
                .await
                .unwrap_err();
            assert!(error.to_string().contains("still pending"), "{error}");
            assert_eq!(*chain.sent.lock(), vec![5]);
        }

        #[tokio::test(start_paused = true)]
        async fn any_other_failure_is_reported_as_is() {
            let chain = Chain::new(5);
            let error = chain
                .run(|_, _| Err("execution reverted".to_owned()))
                .await
                .unwrap_err();
            assert!(error.to_string().contains("execution reverted"), "{error}");
            assert_eq!(*chain.sent.lock(), vec![5]);
        }
    }

    #[test]
    fn a_module_call_matches_the_reference_encoding() {
        let mut shield = vec![0xde, 0xad, 0xbe, 0xef];
        shield.extend_from_slice(&word(7));
        let encoded = encode_exec_from_module(&addr(0xcc), &shield, Operation::Call);
        assert_eq!(
            hex(&encoded),
            "468721a7\
             000000000000000000000000cccccccccccccccccccccccccccccccccccccccc\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000080\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000024\
             deadbeef0000000000000000000000000000000000000000000000000000000000000007\
             00000000000000000000000000000000000000000000000000000000"
                .replace(['\n', ' '], "")
        );
    }

    #[test]
    fn the_atomic_bundle_matches_the_reference_encoding() {
        let mut shield = vec![0xde, 0xad, 0xbe, 0xef];
        shield.extend_from_slice(&word(7));
        let encoded = encode_safe_direct_shield(
            &Address::from(hex_literal::hex!("38869bf66a61cf6bdb996a6ae40d5853fd43b526")),
            &addr(0xaa),
            &addr(0xbb),
            &addr(0xcc),
            1000,
            shield,
        );
        let expected = concat!(
            "468721a700000000000000000000000038869bf66a61cf6bdb996a6ae40d5853fd43b526000000000000000000000000",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000",
            "00000000000000000000000000000000000001648d80ff0a000000000000000000000000000000000000000000000000",
            "0000000000000020000000000000000000000000000000000000000000000000000000000000011200aaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000044095ea7b3000000000000000000000000bbbbbb",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00000000000000000000000000000000000000000000000000000000000003",
            "e800cccccccccccccccccccccccccccccccccccccccc0000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000000000000024deadbeef000000000000",
            "000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000",
        );
        assert_eq!(hex(&encoded), expected);
    }

    #[test]
    fn the_bundle_blob_matches_the_reference_encoding() {
        let mut shield = vec![0xde, 0xad, 0xbe, 0xef];
        shield.extend_from_slice(&word(7));
        let blob = encode_multi_send(&[(addr(0xaa), encode_approve(&addr(0xbb), 1000)), (addr(0xcc), shield)]);
        assert_eq!(
            hex(&blob),
            "8d80ff0a\
             0000000000000000000000000000000000000000000000000000000000000020\
             0000000000000000000000000000000000000000000000000000000000000112\
             00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000044\
             095ea7b3000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\
             00000000000000000000000000000000000000000000000000000000000003e8\
             00cccccccccccccccccccccccccccccccccccccccc\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000024\
             deadbeef0000000000000000000000000000000000000000000000000000000000000007\
             0000000000000000000000000000"
                .replace(['\n', ' '], "")
        );
    }

    #[test]
    fn the_bundle_delegatecalls_only_to_multisend() {
        // The module rejects a DelegateCall to anything but its own MultiSend, so the operation
        // byte and the target must travel together. A regression that made this a plain `Call`
        // would revert inside MultiSend instead, which is far harder to read from a receipt.
        let multisend = addr(0x11);
        let encoded = encode_safe_direct_shield(&multisend, &addr(0xaa), &addr(0xbb), &addr(0xcc), 1, vec![0xff]);
        assert_eq!(&encoded[..4], &EXEC_TRANSACTION_FROM_MODULE);
        assert_eq!(&encoded[4 + 12..4 + 32], multisend.as_ref());
        // Fourth head word is the operation.
        assert_eq!(encoded[4 + 4 * 32 - 1], Operation::DelegateCall as u8);
    }

    #[test]
    fn an_approval_names_the_vault_not_the_aggregator() {
        // The aggregator forwards its caller as `from`; the vault is what pulls. Approving the
        // aggregator would leave the shield reverting inside the vault.
        let vault = addr(0xbb);
        let encoded = encode_approve(&vault, 42);
        assert_eq!(&encoded[..4], &ERC20_APPROVE);
        assert_eq!(&encoded[4 + 12..4 + 32], vault.as_ref());
        assert_eq!(encoded[4 + 32..], word(42));
    }
}
