//! Calldata for spending from the node's Safe through its permission module.
//!
//! A direct shield is paid from the node's Safe, which acts only through
//! `HoprNodeManagementModule.execTransactionFromModule`. The Safe does not call the Curvy aggregator
//! itself: it ERC-777-`send`s the float to Curvy's shield router, whose `tokensReceived` hook calls
//! `directShield` in the same transaction —
//!
//! ```text
//! Safe ──wxHOPR.send(router, gross, aggregator ‖ note)──▶ router.tokensReceived ──▶ aggregator.directShield(note)
//! ```
//!
//! — so the float goes from the Safe straight into the vault, all or nothing: any failure in the
//! hook reverts the `send`, and the wxHOPR stays in the Safe.
//!
//! `hopr-api` exposes no generic "execute a call through the Safe" operation, and the encoders in
//! `hopr-types` are private, so the payloads are built here. They are plain ABI encodings of
//! well-known signatures, pinned by the golden vectors in this module's tests.
//!
//! ### What the module permits
//!
//! `execTransactionFromModule` is `nodeOnly` — the node's own chain key must sign it — and every
//! inner call is checked against the module's target set. The only target here is wxHOPR, which
//! every node Safe scopes at deployment with target-level `ALLOW_ALL` (and `send` allowed even
//! without it), so the shield needs **no** change to the Safe or its module. Calling the aggregator
//! directly would: it is not a scoped target, and scoping it takes a transaction signed by the
//! Safe's owner.

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
/// ERC-777 `send(address,uint256,bytes)`.
const ERC777_SEND: [u8; 4] = [0x9b, 0xd9, 0xbb, 0xc6];
/// `CurvyAggregatorAlphaV2.directShield((uint256,uint256,uint256,uint256[2],uint16))`.
const DIRECT_SHIELD: [u8; 4] = [0x39, 0xf8, 0xb8, 0x5d];
/// The `directShield` arguments: one `Note`, six static words.
const NOTE_LEN: usize = 6 * 32;

/// Gnosis Safe `Enum.Operation`. Only `Call` is ever used: the module rejects a `DelegateCall`
/// to anything but its own MultiSend, and nothing here needs one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Call = 0,
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

/// ERC-777 `send(recipient, amount, data)`.
pub fn encode_erc777_send(recipient: &Address, amount: u128, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 128 + data.len() + 32);
    out.extend_from_slice(&ERC777_SEND);
    out.extend_from_slice(&address_word(recipient));
    out.extend_from_slice(&word(amount));
    // Offset to `data`: three head words.
    out.extend_from_slice(&word(3 * 32));
    out.extend_from_slice(&word(data.len() as u128));
    out.extend_from_slice(data);
    pad_to_word(&mut out, data.len());
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

/// The shield router's `userData`: `abi.encode(aggregator, note)`, i.e. the aggregator word
/// followed by the `directShield` arguments — the calldata the SDK prepared, minus its selector.
///
/// Checked rather than sliced blindly: the router reverts on any other length, but only after
/// the Safe has paid for the transaction.
pub fn router_user_data(aggregator: &Address, direct_shield_calldata: &[u8]) -> Result<Vec<u8>, StrategyError> {
    match direct_shield_calldata.split_first_chunk::<4>() {
        Some((selector, note)) if *selector == DIRECT_SHIELD && note.len() == NOTE_LEN => {
            let mut out = Vec::with_capacity(32 + NOTE_LEN);
            out.extend_from_slice(&address_word(aggregator));
            out.extend_from_slice(note);
            Ok(out)
        }
        _ => Err(StrategyError::other(anyhow::anyhow!(
            "the SDK's direct-shield calldata is not `directShield(Note)` ({} bytes)",
            direct_shield_calldata.len()
        ))),
    }
}

/// The routed direct shield, as the module call that runs it: the Safe `send`s `gross` of
/// `token` to `router`, whose hook shields it into `aggregator` as the prepared note.
///
/// A plain `Call` to the token — the one target every node Safe already scopes.
pub fn encode_safe_router_shield(
    token: &Address,
    router: &Address,
    aggregator: &Address,
    gross: u128,
    direct_shield_calldata: &[u8],
) -> Result<Vec<u8>, StrategyError> {
    let user_data = router_user_data(aggregator, direct_shield_calldata)?;
    Ok(encode_exec_from_module(
        token,
        &encode_erc777_send(router, gross, &user_data),
        Operation::Call,
    ))
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

    /// `directShield((1, 2, 1000, [4, 5], 6))`, as the SDK prepares it.
    fn direct_shield_calldata() -> Vec<u8> {
        const_hex::decode(concat!(
            "39f8b85d0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000",
            "000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000",
            "000003e80000000000000000000000000000000000000000000000000000000000000004000000000000000000000000",
            "000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000",
            "00000006",
        ))
        .unwrap()
    }

    #[test]
    fn the_routed_shield_matches_the_reference_encoding() -> anyhow::Result<()> {
        let encoded =
            encode_safe_router_shield(&addr(0xaa), &addr(0xbb), &addr(0xcc), 1000, &direct_shield_calldata())?;
        let expected = concat!(
            "468721a7000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000000000000000000000",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000000001649bd9bbc6000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbb",
            "bbbbbbbbbbbbbbbb00000000000000000000000000000000000000000000000000000000000003e80000000000000000",
            "000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000",
            "00000000000000e0000000000000000000000000cccccccccccccccccccccccccccccccccccccccc0000000000000000",
            "000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000",
            "000000000000000200000000000000000000000000000000000000000000000000000000000003e80000000000000000",
            "000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000",
            "000000000000000500000000000000000000000000000000000000000000000000000000000000060000000000000000",
            "0000000000000000000000000000000000000000",
        );
        assert_eq!(hex(&encoded), expected);
        Ok(())
    }

    #[test]
    fn the_routed_shield_is_a_plain_call_to_the_token() -> anyhow::Result<()> {
        // The token is the one target every node Safe already scopes; a `DelegateCall`, or any
        // other target, would need a change to the Safe's module.
        let token = addr(0xaa);
        let encoded = encode_safe_router_shield(&token, &addr(0xbb), &addr(0xcc), 1, &direct_shield_calldata())?;
        assert_eq!(&encoded[..4], &EXEC_TRANSACTION_FROM_MODULE);
        assert_eq!(&encoded[4 + 12..4 + 32], token.as_ref());
        // Fourth head word is the operation.
        assert_eq!(encoded[4 + 4 * 32 - 1], Operation::Call as u8);
        Ok(())
    }

    #[test]
    fn the_router_user_data_is_the_aggregator_then_the_note() -> anyhow::Result<()> {
        // What the router decodes as `abi.encode(address aggregator, Note note)`, and exactly the
        // 224 bytes it accepts.
        let calldata = direct_shield_calldata();
        let user_data = router_user_data(&addr(0xcc), &calldata)?;
        assert_eq!(user_data.len(), 224);
        assert_eq!(&user_data[..32], &address_word(&addr(0xcc)));
        assert_eq!(&user_data[32..], &calldata[4..]);
        Ok(())
    }

    #[test]
    fn anything_but_a_direct_shield_is_refused_before_it_reaches_the_safe() {
        let calldata = direct_shield_calldata();
        let mut wrong_selector = calldata.clone();
        wrong_selector[0] ^= 0xff;
        for bad in [
            Vec::new(),
            calldata[..calldata.len() - 1].to_vec(),
            [calldata.clone(), vec![0]].concat(),
            wrong_selector,
        ] {
            assert!(router_user_data(&addr(0xcc), &bad).is_err(), "{} bytes", bad.len());
        }
    }
}
