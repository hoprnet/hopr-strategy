//! The shield router's `userData` for a direct shield.
//!
//! A direct shield is paid from the node's Safe. The Safe does not call the Curvy aggregator
//! itself: it ERC-777-`send`s the float to Curvy's shield router, whose `tokensReceived` hook calls
//! `directShield` in the same transaction —
//!
//! ```text
//! Safe ──wxHOPR.send(router, gross, aggregator ‖ note)──▶ router.tokensReceived ──▶ aggregator.directShield(note)
//! ```
//!
//! — so the float goes from the Safe straight into the vault, all or nothing: any failure in the
//! hook reverts the `send`, and the wxHOPR stays in the Safe. The `send` itself is built and
//! submitted by the node's chain API; only its `data` is built here.

use hopr_api::types::primitive::prelude::Address;

use crate::errors::StrategyError;

/// `CurvyAggregatorAlphaV2.directShield((uint256,uint256,uint256,uint256[2],uint16))`.
const DIRECT_SHIELD: [u8; 4] = [0x39, 0xf8, 0xb8, 0x5d];
/// The `directShield` arguments: one `Note`, six static words.
const NOTE_LEN: usize = 6 * 32;

fn address_word(address: &Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(address.as_ref());
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

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::from([byte; 20])
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
