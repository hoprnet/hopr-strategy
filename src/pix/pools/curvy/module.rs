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
//!   to be added once per Safe with `scopeTargetToken`, which accepts any address and, at `TargetPermission::ALLOW_ALL`,
//!   any selector.
//! * `value` must be zero unless the target is a `SEND` target, so this only ever moves ERC-20 value.
//! * `DelegateCall` is rejected unless the target is exactly the module's configured MultiSend — which is why
//!   [`CurvyDepositPoolConfig::safe_multisend_address`](super::CurvyDepositPoolConfig::safe_multisend_address) is
//!   configurable rather than compiled in.

use hopr_api::types::primitive::prelude::Address;

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
        let blob = encode_multi_send(&[
            (addr(0xaa), encode_approve(&addr(0xbb), 1000)),
            (addr(0xcc), shield),
        ]);
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
