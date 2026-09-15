//! Ownership detection for Blokli-published Curvy pending notes, and the key-format bridges
//! between the HOPR key types and Curvy's stealth API.
//!
//! Blokli deliberately exposes the *global* Curvy note index: every pending note anyone ever
//! sent. What makes a note *ours* is decided here, locally, and never leaves the node:
//!
//! 1. the per-SSA viewer (`v` + `K`, a [`CurvyScanSecret`]) scans the note's announcement with [`stealth::viewer_scan`]
//!    — a view-tag match means the note was sent to *this* scan identity, and the scan yields the shared secret needed
//!    to decrypt amount and token;
//! 2. the note id is then **recomputed** from the SSA-derived owner point and that shared secret, and only a match
//!    proves the note is spendable by the reconstructed SSA key.
//!
//! Step 2 is what keeps the viewer scan-only: the viewer can *identify and decrypt* a note, but the
//! spending authority is the Baby JubJub key the SSA protocol reconstructs, and the id check ties
//! the two together without the pool ever holding that key before recovery.
//!
//! ## Key formats
//!
//! Curvy's stealth primitives speak strings: points as `"x.y"` in decimal, scalars as big-endian
//! hex. HOPR's types are compressed bytes. The bridges at the bottom of this module are the only
//! place the two meet; everything else in the pool works on the HOPR types.

use babyjubjub_ec::group::GroupEncoding;
use blokli_client::api::types::CurvyPendingNote;
use curvy_core::{
    babyjubjub::BabyJubPoint,
    cipher::decrypt_amount_token,
    eddsa::ScalarSigningKey,
    field::{Bn254Fr, fr_from_be_32_checked, fr_from_be_bytes_mod, fr_to_biguint},
    stealth,
    witness::KnownOwner,
};
use hopr_api::{
    node::PixAddressId,
    types::{
        crypto::prelude::{
            BjjKeypair, BjjPublicKey, Bn254G1Affine, Bn254G1Projective, Bn254PublicKey, CurvyScanPublicKey,
            CurvyScanSecret, Keypair, PublicKey,
        },
        primitive::prelude::{HoprBalance, IntoEndian, U256},
    },
};

use super::{DetectedCurvyNote, OwnedCurvyDeposit};

/// Errors produced while validating a Blokli candidate with `curvy-core`.
#[derive(Debug, thiserror::Error)]
pub enum CurvyDetectionError {
    #[error("invalid Curvy detection candidate: {0}")]
    InvalidCandidate(String),
}

/// `curvy-core`-backed Curvy ownership and integrity validator.
///
/// Restricted to one Curvy vault token: a note that decrypts to another token is somebody else's
/// business even if the scan matched, and is skipped rather than reported.
pub struct RsCoreCurvyNoteDetector {
    expected_token: Bn254Fr,
}

impl RsCoreCurvyNoteDetector {
    /// Creates a detector restricted to one Curvy token identifier.
    pub fn new(expected_token: Bn254Fr) -> Self {
        Self { expected_token }
    }

    /// Constructs a detector for a Curvy vault token id.
    pub fn for_token(expected_token: u64) -> Self {
        Self::new(Bn254Fr::from_fr(curvy_core::Fr::from(expected_token)))
    }

    /// Decides whether `candidate` belongs to one of the `watched_allocations`.
    ///
    /// Returns the complete witness note on a match, `Ok(None)` when the note is not ours, and an
    /// error only when the *public* event is malformed — which the caller quarantines rather than
    /// retries, since the event will not change.
    pub(super) fn detect_owned_note(
        &self,
        candidate: &CurvyPendingNote,
        watched_allocations: &[(PixAddressId, BjjPublicKey, CurvyScanSecret)],
    ) -> Result<Option<DetectedCurvyNote>, CurvyDetectionError> {
        let note_id = parse_curvy_note_id(&candidate.note_id.0)?;
        let encrypted_amount = parse_curvy_field(&candidate.amount.0, "amount")?;
        let encrypted_token = parse_curvy_field(&candidate.token_id.0, "token")?;
        let [ephemeral_x, ephemeral_y] = candidate.ephemeral_key.as_slice() else {
            return Err(CurvyDetectionError::InvalidCandidate(
                "ephemeral key must contain exactly two coordinates".to_owned(),
            ));
        };
        let ephemeral_x = parse_curvy_field(&ephemeral_x.0, "ephemeral key x")?;
        let ephemeral_y = parse_curvy_field(&ephemeral_y.0, "ephemeral key y")?;
        let view_tag_value = u8::try_from(candidate.view_tag)
            .map_err(|_| CurvyDetectionError::InvalidCandidate("view tag must fit into one byte".to_owned()))?;
        let view_tag = Bn254Fr::from_fr(curvy_core::Fr::from(u64::from(view_tag_value)));
        let announcement = format!("{}.{}", ephemeral_x.to_dec(), ephemeral_y.to_dec());
        let scan_tag = format!("{view_tag_value:02x}");

        // The per-SSA viewer can identify and decrypt the candidate, but it has no BJJ signing
        // secret. Integrity is established separately by recomputing the note ID with the
        // SSA-derived public owner.
        for (id, address, scan_secret) in watched_allocations {
            let expected_owner = bjj_point(address)
                .map_err(|error| CurvyDetectionError::InvalidCandidate(format!("invalid owner key: {error}")))?;
            let spend_meta_key = spend_meta_key_dec(scan_secret.spend_meta_key());
            let view_secret = view_secret_hex(scan_secret);
            let matches = stealth::viewer_scan(
                &view_secret,
                &spend_meta_key,
                std::slice::from_ref(&announcement),
                std::slice::from_ref(&scan_tag),
            )
            .map_err(|error| CurvyDetectionError::InvalidCandidate(format!("Curvy viewer scan failed: {error}")))?;
            let Some(scan_match) = matches.first() else {
                continue;
            };
            if scan_match.index != 0 {
                return Err(CurvyDetectionError::InvalidCandidate(
                    "single-note Curvy viewer scan returned an invalid match index".to_owned(),
                ));
            }
            let shared_secret = shared_secret_from_scan_match(&scan_match.spending_pub_key)?;
            let (amount, token) = decrypt_candidate_amount_token(
                encrypted_amount,
                encrypted_token,
                shared_secret,
                ephemeral_x,
                ephemeral_y,
                candidate.is_plaintext,
            );
            if token != self.expected_token {
                continue;
            }

            let note = KnownOwner::new(expected_owner, shared_secret).note(
                amount.into_inner(),
                token.into_inner(),
                (ephemeral_x.into_inner(), ephemeral_y.into_inner()),
                view_tag.into_inner(),
            );
            if note.id() == note_id.into_inner() {
                let amount = U256::from_big_endian(&fr_to_biguint(&amount.into_inner()).to_bytes_be());
                return Ok(Some(DetectedCurvyNote {
                    deposit: OwnedCurvyDeposit {
                        id: *id,
                        address: *address,
                        amount: HoprBalance::from(amount),
                    },
                    note,
                }));
            }
        }

        Ok(None)
    }
}

fn decrypt_candidate_amount_token(
    encrypted_amount: Bn254Fr,
    encrypted_token: Bn254Fr,
    shared_secret: Bn254Fr,
    ephemeral_x: Bn254Fr,
    ephemeral_y: Bn254Fr,
    is_plaintext: bool,
) -> (Bn254Fr, Bn254Fr) {
    if is_plaintext {
        (encrypted_amount, encrypted_token)
    } else {
        let (amount, token) = decrypt_amount_token(
            encrypted_amount.into_inner(),
            encrypted_token.into_inner(),
            &fr_to_biguint(&shared_secret.into_inner()),
            (
                &fr_to_biguint(&ephemeral_x.into_inner()),
                &fr_to_biguint(&ephemeral_y.into_inner()),
            ),
        );
        (Bn254Fr::from_fr(amount), Bn254Fr::from_fr(token))
    }
}

/// The shared secret is the `x` coordinate of the stealth spending public key the scan yields.
pub(super) fn shared_secret_from_scan_match(spending_public_key: &str) -> Result<Bn254Fr, CurvyDetectionError> {
    let (x, y) = spending_public_key.split_once('.').ok_or_else(|| {
        CurvyDetectionError::InvalidCandidate("Curvy scan returned a malformed spending public key".to_owned())
    })?;
    let x = U256::from_str_radix(x, 10).map_err(|error| {
        CurvyDetectionError::InvalidCandidate(format!("invalid scanned spending public key x: {error}"))
    })?;
    U256::from_str_radix(y, 10).map_err(|error| {
        CurvyDetectionError::InvalidCandidate(format!("invalid scanned spending public key y: {error}"))
    })?;
    Ok(Bn254Fr::from_fr(fr_from_be_bytes_mod(&x.to_be_bytes())))
}

fn parse_curvy_field(value: &str, field: &str) -> Result<Bn254Fr, CurvyDetectionError> {
    Bn254Fr::try_from_dec(value)
        .map_err(|error| CurvyDetectionError::InvalidCandidate(format!("invalid {field}: {error}")))
}

/// Parses a Blokli `Hex32` note id into a canonical BN254 field element.
pub(super) fn parse_curvy_note_id(value: &str) -> Result<Bn254Fr, CurvyDetectionError> {
    let encoded = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or_else(|| {
            CurvyDetectionError::InvalidCandidate("deposit note id must use 0x-prefixed Hex32 encoding".to_owned())
        })?;
    if encoded.len() != 64 {
        return Err(CurvyDetectionError::InvalidCandidate(
            "deposit note id must contain exactly 32 bytes".to_owned(),
        ));
    }
    let note_id = U256::from_str_radix(encoded, 16)
        .map_err(|error| CurvyDetectionError::InvalidCandidate(format!("invalid deposit note id: {error}")))?;
    fr_from_be_32_checked(&note_id.to_be_bytes())
        .map(Bn254Fr::from_fr)
        .ok_or_else(|| {
            CurvyDetectionError::InvalidCandidate("deposit note id is not a canonical BN254 field element".to_owned())
        })
}

// ---------------------------------------------------------------------------
// Key-format bridges
// ---------------------------------------------------------------------------

/// A HOPR compressed Baby JubJub public key as a Curvy owner point.
pub(super) fn bjj_point(address: &BjjPublicKey) -> Result<BabyJubPoint, &'static str> {
    let bytes: [u8; 32] = address
        .as_ref()
        .try_into()
        .map_err(|_| "invalid compressed-key length")?;
    let point = Option::<babyjubjub_ec::ProjectivePoint>::from(babyjubjub_ec::ProjectivePoint::from_bytes(
        &babyjubjub_ec::GroupRepr(bytes),
    ))
    .ok_or("invalid compressed point")?;
    let affine = babyjubjub_ec::AffinePoint::from(point);
    BabyJubPoint::try_from_dec(&affine.x().to_string(), &affine.y().to_string())
        .map_err(|_| "point is not in the Curvy BabyJubJub subgroup")
}

/// The SSA-reconstructed Baby JubJub secret as a Curvy signing key.
///
/// HOPR deposit secrets are big-endian; Curvy's signing-key boundary is little-endian. The two
/// libraries agree on the scalar itself (pinned by a test below), so this is a byte reversal and
/// nothing else.
pub(super) fn bjj_secret(key: &BjjKeypair) -> Result<ScalarSigningKey, String> {
    let mut bytes: [u8; 32] = key
        .secret()
        .as_ref()
        .try_into()
        .map_err(|_| "secret must contain 32 bytes".to_owned())?;
    bytes.reverse();
    ScalarSigningKey::from_le_bytes(bytes).map_err(|error| error.to_string())
}

/// `"x.y"` decimal form of the secp256k1 spend meta-key `K`, as Curvy's stealth API takes it.
pub(super) fn spend_meta_key_dec(key: &PublicKey) -> String {
    // SEC1 uncompressed: `0x04 || x || y`, both coordinates big-endian.
    let bytes = key.to_uncompressed_bytes();
    let x = U256::from_big_endian(&bytes[1..33]);
    let y = U256::from_big_endian(&bytes[33..65]);
    format!("{x}.{y}")
}

/// `"x.y"` decimal form of the BN254 G1 view key `V`.
pub(super) fn view_key_dec(key: &Bn254PublicKey) -> Result<String, String> {
    let point = Bn254G1Projective::try_from(key).map_err(|error| error.to_string())?;
    let affine = Bn254G1Affine::from(point);
    // `ark-ff` prints field elements as their canonical decimal representation.
    Ok(format!("{}.{}", affine.x, affine.y))
}

/// The view scalar `v` as big-endian hex, as [`stealth::viewer_scan`] takes it.
pub(super) fn view_secret_hex(secret: &CurvyScanSecret) -> String {
    const_hex::encode(secret.view().secret_be().as_ref())
}

/// The public `(K, V)` pair in Curvy's string forms: `(K "x.y", V "x.y")`.
pub(super) fn scan_public_key_dec(key: &CurvyScanPublicKey) -> Result<(String, String), String> {
    Ok((spend_meta_key_dec(key.spend_meta_key()), view_key_dec(key.view_key())?))
}

/// Builds a HOPR [`PublicKey`] from Curvy's `"x.y"` decimal form of a secp256k1 point.
pub(super) fn public_key_from_dec(point: &str) -> Result<PublicKey, String> {
    let (x, y) = point_coordinates(point)?;
    let mut sec1 = [0u8; PublicKey::SIZE_UNCOMPRESSED];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(&x);
    sec1[33..65].copy_from_slice(&y);
    PublicKey::try_from(sec1.as_slice()).map_err(|error| error.to_string())
}

/// Splits Curvy's `"x.y"` decimal point form into big-endian coordinate bytes.
pub(super) fn point_coordinates(point: &str) -> Result<([u8; 32], [u8; 32]), String> {
    let (x, y) = point
        .split_once('.')
        .ok_or_else(|| format!("malformed Curvy point {point:?}"))?;
    let x = U256::from_str_radix(x, 10).map_err(|error| format!("invalid Curvy point x: {error}"))?;
    let y = U256::from_str_radix(y, 10).map_err(|error| format!("invalid Curvy point y: {error}"))?;
    Ok((x.to_be_bytes(), y.to_be_bytes()))
}

#[cfg(test)]
mod tests {
    use hopr_api::types::crypto::prelude::Bn254Keypair;

    use super::*;

    #[test]
    fn hopr_and_curvy_core_use_the_same_babyjubjub_scalar_profile() -> anyhow::Result<()> {
        let mut scalar = [0_u8; 32];
        scalar[31] = 1;
        let hopr = BjjKeypair::from_secret(&scalar)?;
        let hopr_point = bjj_point(hopr.public()).map_err(anyhow::Error::msg)?;
        let curvy = bjj_secret(&hopr).map_err(anyhow::Error::msg)?;

        assert_eq!(hopr_point.as_tuple(), curvy.verifying_key().as_tuple());
        Ok(())
    }

    #[test]
    fn secp256k1_meta_key_round_trips_through_curvy_decimal_form() -> anyhow::Result<()> {
        let (big_k, _) = stealth::get_meta("01", "02")?;
        let key = public_key_from_dec(&big_k).map_err(anyhow::Error::msg)?;
        assert_eq!(spend_meta_key_dec(&key), big_k);
        Ok(())
    }

    #[test]
    fn bn254_view_key_round_trips_through_curvy_decimal_form() -> anyhow::Result<()> {
        let (_, big_v) = stealth::get_meta("01", "02")?;
        let mut v = [0u8; 32];
        v[31] = 2;
        let view = Bn254Keypair::from_secret_be(&v)?;
        assert_eq!(view_key_dec(view.public()).map_err(anyhow::Error::msg)?, big_v);
        Ok(())
    }

    #[test]
    fn note_id_parsing_rejects_non_canonical_values() {
        assert!(parse_curvy_note_id("1234").is_err());
        assert!(parse_curvy_note_id(&format!("0x{}", "f".repeat(64))).is_err());
        assert!(parse_curvy_note_id(&format!("0x{:064x}", 7)).is_ok());
    }
}
