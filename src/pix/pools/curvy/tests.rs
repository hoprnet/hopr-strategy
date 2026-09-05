//! Tests for the Curvy pool, from the detector up to the [`DepositPool`] contract.
//!
//! Everything below the SDK seam is real: Curvy announcements are produced with `curvy-core`'s
//! own stealth primitives and detected with the same code the node runs, notes are persisted in
//! a real redb file, and the pool is driven through its actual trait. What is faked is the chain:
//! a scripted note index in place of Blokli, and an adapter that records what it was asked to
//! shield, allocate and withdraw instead of proving and submitting it.

use std::{
    collections::HashSet,
    num::NonZeroU32,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use async_trait::async_trait;
use blokli_client::api::types::{
    CurvyCommittedNote, CurvyEventCursor, CurvyEventPosition, CurvyPendingNote, Hex32, Uint64, Uint256,
};
use curvy_core::{
    eddsa::ScalarSigningKey,
    field::{Bn254Fr, fr_to_biguint},
    stealth,
    witness::KnownOwner,
};
use hopr_api::{
    ChainKeypair,
    chain::DepositPool,
    node::{PixAddressId, PixDepositData},
    types::{
        crypto::prelude::{BjjKeypair, Bn254Keypair, CurvyScanPublicKey, CurvyScanSecret, Keypair},
        crypto_random::Randomizable,
        internal::prelude::HoprPseudonym,
        primitive::prelude::{Address, HoprBalance, IntoEndian, U256, XDaiBalance},
    },
};

use super::{
    detect::{bjj_point, public_key_from_dec, scan_public_key_dec, shared_secret_from_scan_match},
    lifecycle::CurvyLifecycleTracker,
    *,
};
use crate::testing::{BlokliTestStateBuilder, ChainNode, create_test_blokli_connector};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn pix_id(index: u32) -> PixAddressId {
    PixAddressId::new(
        &HoprPseudonym::random(),
        NonZeroU32::new(index).expect("non-zero PIX allocation index"),
    )
}

fn position(block: u64) -> CurvyEventPosition {
    CurvyEventPosition {
        transaction_hash: Hex32(format!("0x{:064x}", block + 1)),
        block_hash: Hex32(format!("0x{:064x}", block + 2)),
        block: Uint64(block.to_string()),
        transaction_index: Uint64("0".to_owned()),
        log_index: Uint64("0".to_owned()),
        event_item_index: Uint64("0".to_owned()),
    }
}

/// A scan secret from explicit Curvy private keys, in the hopr-types shape.
fn scan_secret(spend_private_key: &str, view_private_key: &str) -> anyhow::Result<CurvyScanSecret> {
    let (spend_meta_key, _) = stealth::get_meta(spend_private_key, view_private_key)?;
    let v_bytes = const_hex::decode(view_private_key)?;
    let mut v = [0u8; 32];
    v[32 - v_bytes.len()..].copy_from_slice(&v_bytes);
    Ok(CurvyScanSecret::new(
        Bn254Keypair::from_secret_be(&v)?,
        public_key_from_dec(&spend_meta_key).map_err(anyhow::Error::msg)?,
    ))
}

struct OwnedCandidateFixture {
    id: PixAddressId,
    address: BjjPublicKey,
    detector: RsCoreCurvyNoteDetector,
    scan_secret: CurvyScanSecret,
    note: CurvyPendingNote,
    note_id: String,
}

/// A real Curvy announcement for `scan_key`, sealed to `owner`, encrypted the way the aggregator
/// publishes it — i.e. exactly what Blokli would index for an allocation the Entry made.
fn pending_note_for(
    scan_key: &CurvyScanPublicKey,
    owner: &BjjPublicKey,
    amount: u64,
    token: u64,
    ephemeral_r: &str,
    block: u64,
) -> anyhow::Result<(CurvyPendingNote, String)> {
    let (big_k, big_v) = scan_public_key_dec(scan_key).map_err(anyhow::Error::msg)?;
    let announcement = stealth::send_with_r(ephemeral_r, &big_k, &big_v)?;
    let (ephemeral_x, ephemeral_y) = announcement
        .big_r
        .split_once('.')
        .ok_or_else(|| anyhow::anyhow!("malformed Curvy fixture announcement"))?;
    let ephemeral_x_field = Bn254Fr::try_from_dec(ephemeral_x)?;
    let ephemeral_y_field = Bn254Fr::try_from_dec(ephemeral_y)?;
    let shared_secret = shared_secret_from_scan_match(&announcement.spending_pub_key).map_err(anyhow::Error::new)?;
    let amount = Bn254Fr::from_fr(curvy_core::Fr::from(amount));
    let token = Bn254Fr::from_fr(curvy_core::Fr::from(token));
    let view_tag_value = u16::from_str_radix(&announcement.view_tag, 16)?;
    let view_tag = Bn254Fr::from_fr(curvy_core::Fr::from(u64::from(view_tag_value)));
    let owner_point = bjj_point(owner).map_err(anyhow::Error::msg)?;
    let owned_note = KnownOwner::new(owner_point, shared_secret).note(
        amount.into_inner(),
        token.into_inner(),
        (ephemeral_x_field.into_inner(), ephemeral_y_field.into_inner()),
        view_tag.into_inner(),
    );
    let note_id = format!(
        "0x{:064x}",
        U256::from_be_bytes(curvy_core::field::fr_to_be_32(&owned_note.id()))
    );
    let encrypted = curvy_core::cipher::encrypt_amount_token(
        amount.into_inner(),
        token.into_inner(),
        &fr_to_biguint(&shared_secret.into_inner()),
        (
            &fr_to_biguint(&ephemeral_x_field.into_inner()),
            &fr_to_biguint(&ephemeral_y_field.into_inner()),
        ),
    );
    Ok((
        CurvyPendingNote {
            note_id: Hex32(note_id.clone()),
            ephemeral_key: vec![Uint256(ephemeral_x.to_owned()), Uint256(ephemeral_y.to_owned())],
            view_tag: i32::from(view_tag_value),
            token_id: Uint256(curvy_core::field::fr_to_dec(&encrypted.encrypted_token)),
            amount: Uint256(curvy_core::field::fr_to_dec(&encrypted.encrypted_amount)),
            is_plaintext: false,
            position: position(block),
        },
        note_id,
    ))
}

fn owned_candidate(block: u64) -> anyhow::Result<OwnedCandidateFixture> {
    let id = pix_id(1);
    let mut secret = [0_u8; 32];
    secret[31] = 1;
    let keypair = BjjKeypair::from_secret(&secret)?;
    let address = *keypair.public();
    let scan_secret = scan_secret("01", "02")?;
    let (note, note_id) = pending_note_for(&scan_secret.public(), &address, 10, 4, "3", block)?;
    Ok(OwnedCandidateFixture {
        id,
        address,
        detector: RsCoreCurvyNoteDetector::for_token(4),
        scan_secret,
        note,
        note_id,
    })
}

fn completion(note_id: &str, block: u64) -> CurvyCommittedNote {
    CurvyCommittedNote {
        note_id: Hex32(note_id.to_owned()),
        batch_index: Hex32(format!("0x{:064x}", 1)),
        leaf_index: Uint64("7".to_owned()),
        position: position(block),
    }
}

fn ten() -> HoprBalance {
    HoprBalance::from(U256::from(10_u8))
}

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

#[test]
fn per_ssa_viewer_discovers_note_without_the_bjj_secret() -> anyhow::Result<()> {
    let fixture = owned_candidate(1)?;
    let detected = fixture
        .detector
        .detect_owned_note(
            &fixture.note,
            &[(fixture.id, fixture.address, fixture.scan_secret.clone())],
        )?
        .ok_or_else(|| anyhow::anyhow!("viewer-owned allocation was not detected"))?;

    assert_eq!(detected.deposit.id, fixture.id);
    assert_eq!(detected.deposit.address, fixture.address);
    assert_eq!(detected.deposit.amount, ten());

    // Another viewer does not see it...
    let unrelated_scan_key = scan_secret("03", "04")?;
    assert!(
        fixture
            .detector
            .detect_owned_note(&fixture.note, &[(pix_id(2), fixture.address, unrelated_scan_key)])?
            .is_none()
    );
    // ...and the right viewer with the wrong owner is not fooled by a matching view tag either.
    let other_owner = *BjjKeypair::random().public();
    assert!(
        fixture
            .detector
            .detect_owned_note(&fixture.note, &[(pix_id(3), other_owner, fixture.scan_secret.clone())])?
            .is_none()
    );
    Ok(())
}

#[test]
fn detector_skips_notes_of_another_token() -> anyhow::Result<()> {
    let fixture = owned_candidate(1)?;
    let other_token = RsCoreCurvyNoteDetector::for_token(5);
    assert!(
        other_token
            .detect_owned_note(&fixture.note, &[(fixture.id, fixture.address, fixture.scan_secret)])?
            .is_none()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[test]
fn redb_state_recovers_complete_notes_for_withdrawal_after_restart() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("curvy-pix.redb");
    let fixture = owned_candidate(1)?;
    let id = fixture.id;
    let address = fixture.address;
    let detected = fixture
        .detector
        .detect_owned_note(&fixture.note, &[(id, address, fixture.scan_secret.clone())])?
        .ok_or_else(|| anyhow::anyhow!("fixture note was not detected"))?;
    let amount = detected.deposit.amount;
    let expected_note_id = detected.note.id();
    let candidate_cursor = CurvyEventCursor::from(&position(1));
    let completion_cursor = CurvyEventCursor::from(&position(2));

    {
        let state = RedbCurvyDepositState::open(&path)?;
        state.record_owned_candidate(&fixture.note_id, detected, &candidate_cursor)?;
        assert_eq!(state.cursor(CurvyEventKind::Pending)?, Some(candidate_cursor));
        assert_eq!(state.committed_amount(&id)?, HoprBalance::zero());
        assert_eq!(state.owned_note_ids()?, vec![fixture.note_id.clone()]);

        assert_eq!(
            state
                .record_completion(&fixture.note_id, 7, &completion_cursor)?
                .map(|note| (note.deposit, note.leaf_index)),
            Some((OwnedCurvyDeposit { id, address, amount }, 7))
        );
        assert_eq!(state.committed_amount(&id)?, amount);
    }

    let reopened = RedbCurvyDepositState::open(&path)?;
    assert_eq!(reopened.cursor(CurvyEventKind::Committed)?, Some(completion_cursor));
    assert_eq!(reopened.committed_amount(&id)?, amount);
    let notes = reopened.committed_notes(&id)?;
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].note.id(), expected_note_id);
    assert_eq!(notes[0].leaf_index, 7);
    reopened.remove_spent_notes(&id, &[fixture.note_id])?;
    drop(reopened);

    let spent_reopened = RedbCurvyDepositState::open(&path)?;
    assert_eq!(spent_reopened.committed_amount(&id)?, HoprBalance::zero());
    assert!(spent_reopened.committed_notes(&id)?.is_empty());
    assert!(spent_reopened.owned_note_ids()?.is_empty());
    Ok(())
}

#[test]
fn scan_secrets_survive_a_restart_and_are_removed_on_request() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("curvy-pix.redb");
    let id = pix_id(1);
    let secret = scan_secret("05", "06")?;

    {
        let state = RedbCurvyDepositState::open(&path)?;
        assert!(state.scan_secret(&id)?.is_none());
        state.store_scan_secret(&id, &secret)?;
    }

    let reopened = RedbCurvyDepositState::open(&path)?;
    let stored = reopened.scan_secret(&id)?.expect("the secret was persisted");
    assert_eq!(stored.public(), secret.public());
    assert_eq!(stored.view().secret_be().as_ref(), secret.view().secret_be().as_ref());
    reopened.remove_scan_secret(&id)?;
    assert!(reopened.scan_secret(&id)?.is_none());
    Ok(())
}

#[test]
fn wiping_chain_state_leaves_an_empty_usable_store() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let state = RedbCurvyDepositState::open(dir.path().join("curvy-pix.redb"))?;
    let fixture = owned_candidate(1)?;
    let detected = fixture
        .detector
        .detect_owned_note(
            &fixture.note,
            &[(fixture.id, fixture.address, fixture.scan_secret.clone())],
        )?
        .expect("detected");
    state.record_owned_candidate(&fixture.note_id, detected, &CurvyEventCursor::from(&position(1)))?;
    state.store_scan_secret(&fixture.id, &fixture.scan_secret)?;

    state.wipe_chain_state()?;

    assert_eq!(state.cursor(CurvyEventKind::Pending)?, None);
    assert!(state.owned_note_ids()?.is_empty());
    assert!(state.scan_secret(&fixture.id)?.is_none());
    // Still writable afterwards.
    state.store_scan_secret(&fixture.id, &fixture.scan_secret)?;
    assert!(state.scan_secret(&fixture.id)?.is_some());
    Ok(())
}

// ---------------------------------------------------------------------------
// Tracker
// ---------------------------------------------------------------------------

#[test_log::test(tokio::test)]
async fn tracker_filters_correlates_and_notifies_locally() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let state = Arc::new(RedbCurvyDepositState::open(dir.path().join("curvy-pix.redb"))?);
    let fixture = owned_candidate(2)?;
    let id = fixture.id;
    let address = fixture.address;
    let tracker = CurvyLifecycleTracker::new(Arc::new(fixture.detector), state.clone());
    let receiver = tracker.watch(id, address, fixture.scan_secret.clone(), ten())?;

    let unrelated_cursor = CurvyEventCursor::from(&position(1));
    let mut unrelated = fixture.note.clone();
    unrelated.note_id = Hex32(format!("0x{:064x}", 0));
    unrelated.position = position(1);
    assert!(tracker.process_candidate(unrelated).await?);
    assert_eq!(state.cursor(CurvyEventKind::Pending)?, Some(unrelated_cursor));

    let candidate_cursor = CurvyEventCursor::from(&position(2));
    assert!(tracker.process_candidate(fixture.note).await?);
    assert_eq!(state.cursor(CurvyEventKind::Pending)?, Some(candidate_cursor));
    assert_eq!(state.committed_amount(&id)?, HoprBalance::zero());

    let completion_cursor = CurvyEventCursor::from(&position(3));
    tracker.process_completion(completion(&fixture.note_id, 3)).await?;
    assert_eq!(receiver.await?, ten());
    assert_eq!(state.cursor(CurvyEventKind::Committed)?, Some(completion_cursor));
    assert_eq!(state.committed_amount(&id)?, ten());
    Ok(())
}

#[tokio::test]
async fn tracker_does_not_advance_without_registered_addresses() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let state = Arc::new(RedbCurvyDepositState::open(dir.path().join("curvy-pix.redb"))?);
    let fixture = owned_candidate(1)?;
    let tracker = CurvyLifecycleTracker::new(Arc::new(fixture.detector), state.clone());

    assert!(!tracker.process_candidate(fixture.note).await?);
    assert_eq!(state.cursor(CurvyEventKind::Pending)?, None);
    Ok(())
}

#[tokio::test]
async fn tracker_quarantines_malformed_public_candidates() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let state = Arc::new(RedbCurvyDepositState::open(dir.path().join("curvy-pix.redb"))?);
    let mut fixture = owned_candidate(4)?;
    let tracker = CurvyLifecycleTracker::new(Arc::new(fixture.detector), state.clone());
    let _receiver = tracker.watch(fixture.id, fixture.address, fixture.scan_secret.clone(), ten())?;
    fixture.note.view_tag = 256;
    let cursor = CurvyEventCursor::from(&fixture.note.position);

    assert!(tracker.process_candidate(fixture.note).await?);
    assert_eq!(state.cursor(CurvyEventKind::Pending)?, Some(cursor));
    Ok(())
}

#[test]
fn registering_an_address_requests_a_historical_lifecycle_pass() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let state = Arc::new(RedbCurvyDepositState::open(dir.path().join("curvy-pix.redb"))?);
    let fixture = owned_candidate(1)?;
    let tracker = CurvyLifecycleTracker::new(Arc::new(fixture.detector), state);

    let _receiver = tracker.watch(fixture.id, fixture.address, fixture.scan_secret.clone(), ten())?;

    assert!(tracker.replay_history.load(Ordering::Acquire));
    Ok(())
}

#[test]
fn interrupted_historical_pass_remains_requested() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let state = Arc::new(RedbCurvyDepositState::open(dir.path().join("curvy-pix.redb"))?);
    let fixture = owned_candidate(1)?;
    let tracker = CurvyLifecycleTracker::new(Arc::new(fixture.detector), state);

    let _receiver = tracker.watch(fixture.id, fixture.address, fixture.scan_secret.clone(), ten())?;
    let replay_history = tracker.replay_history.swap(false, Ordering::AcqRel);
    assert!(replay_history);
    assert!(!tracker.replay_history.load(Ordering::Acquire));

    tracker.restore_failed_replay(replay_history);
    assert!(tracker.replay_history.load(Ordering::Acquire));

    // A non-historical failure must not clear a newer registration's request.
    tracker.restore_failed_replay(false);
    assert!(tracker.replay_history.load(Ordering::Acquire));
    Ok(())
}

#[test_log::test(tokio::test)]
async fn late_registration_replays_pending_and_committed_history() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let state = Arc::new(RedbCurvyDepositState::open(dir.path().join("curvy-pix.redb"))?);
    let fixture = owned_candidate(2)?;
    let id = fixture.id;
    let address = fixture.address;
    let tracker = CurvyLifecycleTracker::new(Arc::new(fixture.detector), state.clone());

    // A completion can be skipped while a different allocation is active,
    // advancing the shared committed cursor before this allocation is known.
    tracker.process_completion(completion(&fixture.note_id, 3)).await?;
    assert_eq!(
        state.cursor(CurvyEventKind::Committed)?,
        Some(CurvyEventCursor::from(&position(3)))
    );
    assert_eq!(state.committed_amount(&id)?, HoprBalance::zero());

    let receiver = tracker.watch(id, address, fixture.scan_secret.clone(), ten())?;
    let replay_history = tracker.replay_history.swap(false, Ordering::AcqRel);
    assert!(replay_history);
    assert_eq!(tracker.catch_up_cursor(CurvyEventKind::Pending, replay_history)?, None);
    assert_eq!(
        tracker.catch_up_cursor(CurvyEventKind::Committed, replay_history)?,
        None
    );

    // The worker performs these in this order during the historical pass.
    assert!(tracker.process_candidate(fixture.note).await?);
    tracker.process_completion(completion(&fixture.note_id, 3)).await?;

    assert_eq!(receiver.await?, ten());
    assert_eq!(state.committed_amount(&id)?, ten());
    Ok(())
}

// ---------------------------------------------------------------------------
// Deposit data
// ---------------------------------------------------------------------------

#[test]
fn deposit_data_round_trips_through_the_wire_form() -> anyhow::Result<()> {
    let id = pix_id(1);
    let secret = scan_secret("07", "08")?;
    let data = CurvyDepositData::new(id, secret.public());

    let wire: PixDepositData = data.clone().try_into()?;
    assert_eq!(wire.id, id);
    assert_eq!(wire.data.len(), 65);

    let back = CurvyDepositData::try_from(wire)?;
    assert_eq!(back, data);
    assert_eq!(back.scan_key(), &secret.public());

    // Not a scan identity: refused at the boundary, before any pool logic runs.
    let garbage = PixDepositData {
        id,
        data: vec![7u8; 65].into(),
    };
    assert!(CurvyDepositData::try_from(garbage).is_err());
    let empty = PixDepositData {
        id,
        data: Box::default(),
    };
    assert!(CurvyDepositData::try_from(empty).is_err());
    Ok(())
}

// ---------------------------------------------------------------------------
// The pool over a scripted chain
// ---------------------------------------------------------------------------

/// A note index the test writes to directly, standing in for Blokli.
#[derive(Default)]
struct ScriptedIndex {
    pending: parking_lot::Mutex<Vec<CurvyPendingNote>>,
    committed: parking_lot::Mutex<Vec<CurvyCommittedNote>>,
    head: parking_lot::Mutex<(u64, u64)>,
    spent_nullifiers: parking_lot::Mutex<HashSet<String>>,
    known_notes: parking_lot::Mutex<Option<HashSet<String>>>,
}

fn ordinal(position: &CurvyEventPosition) -> (u64, u64, u64, u64) {
    let read = |value: &Uint64| value.0.parse::<u64>().expect("numeric position");
    (
        read(&position.block),
        read(&position.transaction_index),
        read(&position.log_index),
        read(&position.event_item_index),
    )
}

fn cursor_ordinal(cursor: &CurvyEventCursor) -> (u64, u64, u64, u64) {
    let read = |value: &Uint64| value.0.parse::<u64>().expect("numeric cursor");
    (
        read(&cursor.block),
        read(&cursor.transaction_index),
        read(&cursor.log_index),
        read(&cursor.event_item_index),
    )
}

#[async_trait]
impl CurvyIndexSource for ScriptedIndex {
    async fn pending_notes(
        &self,
        after: Option<CurvyEventCursor>,
        first: u32,
    ) -> Result<Vec<CurvyPendingNote>, String> {
        let after = after.as_ref().map(cursor_ordinal);
        Ok(self
            .pending
            .lock()
            .iter()
            .filter(|note| after.is_none_or(|after| ordinal(&note.position) > after))
            .take(first as usize)
            .cloned()
            .collect())
    }

    async fn committed_notes(
        &self,
        after: Option<CurvyEventCursor>,
        first: u32,
    ) -> Result<Vec<CurvyCommittedNote>, String> {
        let after = after.as_ref().map(cursor_ordinal);
        Ok(self
            .committed
            .lock()
            .iter()
            .filter(|note| after.is_none_or(|after| ordinal(&note.position) > after))
            .take(first as usize)
            .cloned()
            .collect())
    }

    async fn indexed_head(&self) -> Result<(u64, u64), String> {
        Ok(*self.head.lock())
    }

    async fn nullifier_spent(&self, nullifier: String) -> Result<bool, String> {
        Ok(self.spent_nullifiers.lock().contains(&nullifier))
    }

    async fn note_known(&self, note_id: String) -> Result<bool, String> {
        Ok(self
            .known_notes
            .lock()
            .as_ref()
            .is_none_or(|known| known.contains(&note_id)))
    }
}

/// Records what the pool asked of the SDK instead of proving and submitting it.
#[derive(Default)]
struct RecordingAdapter {
    funded: parking_lot::Mutex<Vec<(HoprBalance, Address)>>,
    allocations: parking_lot::Mutex<Vec<(PixAddressId, BjjPublicKey, CurvyScanPublicKey, HoprBalance)>>,
    withdrawals: parking_lot::Mutex<Vec<(Address, usize)>>,
    consistent: parking_lot::Mutex<bool>,
    resets: parking_lot::Mutex<usize>,
}

impl RecordingAdapter {
    fn consistent() -> Self {
        Self {
            consistent: parking_lot::Mutex::new(true),
            ..Default::default()
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("scripted adapter failure")]
struct ScriptedFailure;

#[async_trait]
impl CurvySdkAdapter for RecordingAdapter {
    type Error = ScriptedFailure;

    async fn ensure_funded(&self, gross: HoprBalance, recovery_address: Address) -> Result<(), Self::Error> {
        self.funded.lock().push((gross, recovery_address));
        Ok(())
    }

    async fn allocate(
        &self,
        deposits: Vec<(PixAddressId, BjjPublicKey, CurvyScanPublicKey, HoprBalance)>,
    ) -> Result<(), Self::Error> {
        self.allocations.lock().extend(deposits);
        Ok(())
    }

    async fn withdraw(
        &self,
        _secret: &ScalarSigningKey,
        notes: Vec<CommittedCurvyNote>,
        dst: Address,
        _amount: Option<HoprBalance>,
    ) -> Result<CurvyWithdrawalOutcome, Self::Error> {
        self.withdrawals.lock().push((dst, notes.len()));
        let withdrawn = notes
            .iter()
            .fold(HoprBalance::zero(), |total, note| total + note.deposit.amount);
        Ok(CurvyWithdrawalOutcome {
            spent_note_ids: notes
                .iter()
                .map(|note| {
                    format!(
                        "0x{:064x}",
                        U256::from_be_bytes(curvy_core::field::fr_to_be_32(&note.note.id()))
                    )
                })
                .collect(),
            withdrawn,
        })
    }

    async fn chain_state_is_consistent(&self) -> Result<bool, Self::Error> {
        Ok(*self.consistent.lock())
    }

    fn reset_chain_state(&self) -> Result<(), Self::Error> {
        *self.resets.lock() += 1;
        Ok(())
    }
}

const SAFE: [u8; 20] = [0x5a; 20];

type ChainNodeOf = ChainNode<Arc<crate::testing::TestChainConnector<crate::testing::FullStateEmulator>>>;

/// A node over a real chain connector, so that the `HasChainApi` bound is met by the same kind
/// of type production uses. The chain itself is never touched by these tests.
async fn test_node() -> anyhow::Result<Arc<ChainNodeOf>> {
    let me = ChainKeypair::from_secret(&hex_literal::hex!(
        "492057cf93e99b31d2a85bc5e98a9c3aa0021feec52c227cc8170e8f7d047775"
    ))?;
    let sim = BlokliTestStateBuilder::default()
        .with_generated_accounts(
            &[&me.public().to_address()],
            false,
            XDaiBalance::new_base(1),
            HoprBalance::new_base(1000),
        )
        .build_dynamic_client(Address::from(SAFE));
    let connector = create_test_blokli_connector(&me, sim, Address::from(SAFE)).await?;
    Ok(Arc::new(ChainNode(Arc::new(connector))))
}

struct Harness {
    pool: CurvyDepositPool<ChainNodeOf, ScriptedIndex, RecordingAdapter, RedbCurvyDepositState>,
    index: Arc<ScriptedIndex>,
    adapter: Arc<RecordingAdapter>,
    _dir: tempfile::TempDir,
}

async fn harness(adapter: RecordingAdapter, tracking_time: Duration) -> anyhow::Result<Harness> {
    let dir = tempfile::tempdir()?;
    let state = RedbCurvyDepositState::open(dir.path().join("curvy-pix.redb"))?;
    let node = test_node().await?;
    let cfg = CurvyDepositPoolConfig {
        max_deposit_tracking_time: tracking_time,
        token: 4,
        ..Default::default()
    };
    let pool = CurvyDepositPool::with_parts(
        node,
        cfg,
        HoprBalance::new_base(100),
        ScriptedIndex::default(),
        adapter,
        RsCoreCurvyNoteDetector::for_token(4),
        state,
    );
    Ok(Harness {
        index: Arc::clone(&pool.index),
        adapter: Arc::clone(&pool.adapter),
        pool,
        _dir: dir,
    })
}

#[test_log::test(tokio::test)]
async fn pool_round_trip_generate_deposit_notify_and_sweep() -> anyhow::Result<()> {
    let harness = harness(RecordingAdapter::consistent(), Duration::from_secs(5)).await?;
    let pool = &harness.pool;
    let id = pix_id(1);
    let owner = BjjKeypair::random();
    let address = *owner.public();

    // Exit: the deposit data is a fresh scan identity whose secret is durable before it is
    // handed out, and asking again yields the same identity.
    let data = pool.generate_deposit_data(&id).await?;
    assert_eq!(data.id(), &id);
    let stored = pool.state().scan_secret(&id)?.expect("the secret is persisted");
    assert_eq!(&stored.public(), data.scan_key());
    assert_eq!(pool.generate_deposit_data(&id).await?, data);

    // Entry: the first deposit shields the float from the Safe (the portal's recovery address is
    // the node's Safe, whatever the node says it is), then allocates.
    pool.deposit_funds_to(&id, &address, ten(), data.clone()).await?;
    let safe = pool.node.identity().safe_address;
    assert_eq!(
        harness.adapter.funded.lock().as_slice(),
        &[(HoprBalance::new_base(100), safe)]
    );
    assert_eq!(
        harness.adapter.allocations.lock().as_slice(),
        &[(id, address, *data.scan_key(), ten())]
    );

    // The chain publishes the allocation the Entry made, sealed for that scan identity.
    let (pending, note_id) = pending_note_for(data.scan_key(), &address, 10, 4, "11", 5)?;
    harness.index.pending.lock().push(pending);

    // Exit: waits for it to be committed and final.
    let notification = pool.notify_deposit(id, address, ten())?;
    harness.index.committed.lock().push(completion(&note_id, 6));
    *harness.index.head.lock() = (8, 1);
    let (confirmed_id, confirmed_address, confirmed) = notification.await?;
    assert_eq!((confirmed_id, confirmed_address, confirmed), (id, address, ten()));
    assert_eq!(pool.state().committed_amount(&id)?, ten());

    // Exit: sweeps with the reconstructed key, to the Safe.
    pool.withdraw_deposit(&id, &owner, Address::from(SAFE), None).await?;
    assert_eq!(
        harness.adapter.withdrawals.lock().as_slice(),
        &[(Address::from(SAFE), 1)]
    );
    assert!(pool.state().committed_notes(&id)?.is_empty());
    assert!(pool.state().scan_secret(&id)?.is_none());
    Ok(())
}

#[tokio::test]
async fn sweeping_an_allocation_with_nothing_committed_keeps_the_key() -> anyhow::Result<()> {
    let harness = harness(RecordingAdapter::consistent(), Duration::from_secs(5)).await?;
    let id = pix_id(1);

    // `CriteriaNotSatisfied` rather than `Ok`: the strategy deletes the recovery key on `Ok`.
    let result = harness
        .pool
        .withdraw_deposit(&id, &BjjKeypair::random(), Address::from(SAFE), None)
        .await;
    assert!(matches!(result, Err(StrategyError::CriteriaNotSatisfied)), "{result:?}");
    assert!(harness.adapter.withdrawals.lock().is_empty());
    Ok(())
}

#[tokio::test]
async fn already_spent_notes_are_reconciled_away_before_sweeping() -> anyhow::Result<()> {
    let harness = harness(RecordingAdapter::consistent(), Duration::from_secs(5)).await?;
    let pool = &harness.pool;
    let id = pix_id(1);
    let owner = BjjKeypair::random();
    let address = *owner.public();
    let data = pool.generate_deposit_data(&id).await?;
    let (pending, note_id) = pending_note_for(data.scan_key(), &address, 10, 4, "12", 5)?;
    harness.index.pending.lock().push(pending);
    let notification = pool.notify_deposit(id, address, ten())?;
    harness.index.committed.lock().push(completion(&note_id, 6));
    *harness.index.head.lock() = (8, 1);
    notification.await?;

    // The chain already knows the nullifier: a sweep whose outcome was lost.
    let note = &pool.state().committed_notes(&id)?[0];
    let nullifier = U256::from_be_bytes(curvy_core::field::fr_to_be_32(&note.note.nullifier()));
    harness
        .index
        .spent_nullifiers
        .lock()
        .insert(format!("{nullifier:#066x}"));

    let result = pool.withdraw_deposit(&id, &owner, Address::from(SAFE), None).await;
    assert!(matches!(result, Err(StrategyError::CriteriaNotSatisfied)), "{result:?}");
    assert!(harness.adapter.withdrawals.lock().is_empty());
    assert!(pool.state().committed_notes(&id)?.is_empty());
    Ok(())
}

#[tokio::test]
async fn notify_deposit_needs_the_deposit_data_generated_here() -> anyhow::Result<()> {
    let harness = harness(RecordingAdapter::consistent(), Duration::from_secs(5)).await?;
    let result = harness
        .pool
        .notify_deposit(pix_id(1), *BjjKeypair::random().public(), ten());
    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn notify_deposit_times_out_when_nothing_arrives() -> anyhow::Result<()> {
    let harness = harness(RecordingAdapter::consistent(), Duration::from_secs(1)).await?;
    let id = pix_id(1);
    let address = *BjjKeypair::random().public();
    harness.pool.generate_deposit_data(&id).await?;

    let result = harness.pool.notify_deposit(id, address, ten())?.await;
    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn mismatched_deposit_data_is_refused_before_anything_moves() -> anyhow::Result<()> {
    let harness = harness(RecordingAdapter::consistent(), Duration::from_secs(5)).await?;
    let data = harness.pool.generate_deposit_data(&pix_id(1)).await?;

    let result = harness
        .pool
        .deposit_funds_to(&pix_id(2), BjjKeypair::random().public(), ten(), data)
        .await;
    assert!(result.is_err());
    assert!(harness.adapter.funded.lock().is_empty());
    assert!(harness.adapter.allocations.lock().is_empty());
    Ok(())
}

#[tokio::test]
async fn a_batch_is_one_allocation_call() -> anyhow::Result<()> {
    let harness = harness(RecordingAdapter::consistent(), Duration::from_secs(5)).await?;
    let pool = &harness.pool;
    let first = pix_id(1);
    let second = pix_id(2);
    let deposits = vec![
        (
            first,
            *BjjKeypair::random().public(),
            ten(),
            pool.generate_deposit_data(&first).await?,
        ),
        (
            second,
            *BjjKeypair::random().public(),
            ten(),
            pool.generate_deposit_data(&second).await?,
        ),
        // Filed under the wrong allocation: refused individually, without failing the batch.
        (
            pix_id(3),
            *BjjKeypair::random().public(),
            ten(),
            pool.generate_deposit_data(&first).await?,
        ),
    ];

    let outcomes = pool.deposit_funds_to_multiple(&deposits).await?;
    assert_eq!(outcomes.len(), 3);
    assert!(matches!(outcomes[0], Ok((id, ())) if id == first));
    assert!(matches!(outcomes[1], Ok((id, ())) if id == second));
    assert!(outcomes[2].is_err());
    assert_eq!(harness.adapter.allocations.lock().len(), 2);
    assert_eq!(harness.adapter.funded.lock().len(), 1);
    Ok(())
}

#[tokio::test]
async fn state_from_another_chain_is_discarded_on_first_use() -> anyhow::Result<()> {
    let harness = harness(RecordingAdapter::consistent(), Duration::from_secs(5)).await?;
    let pool = &harness.pool;
    let fixture = owned_candidate(1)?;
    let detected = fixture
        .detector
        .detect_owned_note(
            &fixture.note,
            &[(fixture.id, fixture.address, fixture.scan_secret.clone())],
        )?
        .expect("detected");
    pool.state()
        .record_owned_candidate(&fixture.note_id, detected, &CurvyEventCursor::from(&position(1)))?;
    pool.state().store_scan_secret(&fixture.id, &fixture.scan_secret)?;
    // The endpoint has never heard of that note.
    *harness.index.known_notes.lock() = Some(HashSet::new());
    *harness.index.head.lock() = (10, 1);

    pool.generate_deposit_data(&pix_id(9)).await?;

    assert!(pool.state().owned_note_ids()?.is_empty());
    assert!(pool.state().scan_secret(&fixture.id)?.is_none());
    assert_eq!(*harness.adapter.resets.lock(), 1);
    // Once per process: the fresh data written above survives the next call.
    pool.generate_deposit_data(&pix_id(10)).await?;
    assert!(pool.state().scan_secret(&pix_id(9)).is_ok());
    assert_eq!(*harness.adapter.resets.lock(), 1);
    Ok(())
}

#[tokio::test]
async fn state_from_the_same_chain_is_kept() -> anyhow::Result<()> {
    let harness = harness(RecordingAdapter::consistent(), Duration::from_secs(5)).await?;
    let pool = &harness.pool;
    let fixture = owned_candidate(1)?;
    let detected = fixture
        .detector
        .detect_owned_note(
            &fixture.note,
            &[(fixture.id, fixture.address, fixture.scan_secret.clone())],
        )?
        .expect("detected");
    pool.state()
        .record_owned_candidate(&fixture.note_id, detected, &CurvyEventCursor::from(&position(1)))?;
    *harness.index.known_notes.lock() = Some(HashSet::from([fixture.note_id.clone()]));
    *harness.index.head.lock() = (10, 1);

    pool.generate_deposit_data(&pix_id(9)).await?;

    assert_eq!(pool.state().owned_note_ids()?, vec![fixture.note_id]);
    assert_eq!(*harness.adapter.resets.lock(), 0);
    Ok(())
}

#[tokio::test]
async fn pool_transfer_is_not_supported() -> anyhow::Result<()> {
    let harness = harness(RecordingAdapter::consistent(), Duration::from_secs(5)).await?;
    let dst_id = pix_id(2);
    let data = harness.pool.generate_deposit_data(&dst_id).await?;
    let result = harness
        .pool
        .pool_transfer(
            &pix_id(1),
            &BjjKeypair::random(),
            &dst_id,
            *BjjKeypair::random().public(),
            data,
            None,
        )
        .await;
    assert!(result.is_err());
    Ok(())
}
