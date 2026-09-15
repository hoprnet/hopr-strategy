//! Durable state of the Curvy pool: query cursors, owned notes and their commitment status, and
//! the per-SSA scan secrets — everything that must survive a restart for a deposit to remain
//! discoverable and, later, sweepable.
//!
//! The store is a [`redb`] database. Two invariants the encodings and transactions below exist
//! to keep:
//!
//! * **An ownership decision and the cursor that produced it commit together.** A crash between "this note is ours" and
//!   "advance past it" would either replay the note (harmless, the record is idempotent) or — the other way round —
//!   skip it forever. The two are one write transaction.
//! * **A scan secret is durable before its public half is ever sent.** [`generate_deposit_data`] persists the secret
//!   first and returns the public identity second, so the Entry can never hold a scan identity the Exit has already
//!   lost.
//!
//! Owned notes stay stored after commitment. Reopening the same database therefore makes them
//! available to both [`notify_deposit`] and withdrawal after a restart.
//!
//! [`generate_deposit_data`]: hopr_api::chain::DepositPool::generate_deposit_data
//! [`notify_deposit`]: hopr_api::chain::DepositPool::notify_deposit

use std::{path::Path, sync::Arc};

use blokli_client::api::types::{CurvyEventCursor, Hex32, Uint64};
use curvy_core::{
    field::{fr_from_be_32_checked, fr_to_be_32},
    witness::Note,
};
use hopr_api::{
    node::PixAddressId,
    types::{
        crypto::prelude::{BjjPublicKey, CurvyScanSecret},
        primitive::prelude::{BytesRepresentable, HoprBalance, IntoEndian, U256},
    },
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use super::{CommittedCurvyNote, DetectedCurvyNote, OwnedCurvyDeposit, detect::parse_curvy_note_id};

const CURSOR_TABLE: TableDefinition<u8, Vec<u8>> = TableDefinition::new("curvy_pix_cursor");
const NOTE_ID_SIZE: usize = 32;
const OWNED_NOTE_KEY_SIZE: usize = PixAddressId::SIZE + NOTE_ID_SIZE;
const OWNED_NOTES_TABLE: TableDefinition<[u8; OWNED_NOTE_KEY_SIZE], Vec<u8>> =
    TableDefinition::new("curvy_pix_owned_notes_v2");
const NOTE_SESSIONS_TABLE: TableDefinition<[u8; NOTE_ID_SIZE], [u8; PixAddressId::SIZE]> =
    TableDefinition::new("curvy_pix_note_sessions");
/// Per-SSA scan secrets, keyed by allocation. See the module docs for the ordering they rely on.
const SCAN_SECRETS_TABLE: TableDefinition<[u8; PixAddressId::SIZE], Vec<u8>> =
    TableDefinition::new("curvy_pix_scan_secrets");
const PENDING_CURSOR_KEY: u8 = 0;
const COMMITTED_CURSOR_KEY: u8 = 1;
const CURSOR_SIZE_WITHOUT_HASH: usize = 32;
const OWNED_NOTE_VERSION: u8 = 1;
const OWNED_NOTE_SIZE: usize = 344;

/// Persistent state errors for the Curvy lifecycle tracker.
#[derive(Debug, thiserror::Error)]
pub enum CurvyStateError {
    #[error("Curvy PIX state database error: {0}")]
    Database(String),
    #[error("corrupt Curvy PIX state: {0}")]
    Corrupt(String),
}

fn state_db_error(error: impl std::fmt::Display) -> CurvyStateError {
    CurvyStateError::Database(error.to_string())
}

/// The fixed-size encoding of an allocation id, as the tables key on it.
pub(super) fn id_bytes(id: &PixAddressId) -> [u8; PixAddressId::SIZE] {
    let mut bytes = [0u8; PixAddressId::SIZE];
    bytes.copy_from_slice(id.as_ref());
    bytes
}

/// Independently checkpointed Curvy event families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CurvyEventKind {
    /// Pending notes that still require local ownership detection.
    Pending,
    /// Committed notes that are correlated against retained owned IDs.
    Committed,
}

impl CurvyEventKind {
    fn cursor_key(self) -> u8 {
        match self {
            Self::Pending => PENDING_CURSOR_KEY,
            Self::Committed => COMMITTED_CURSOR_KEY,
        }
    }
}

pub(super) fn cursor_component(value: &Uint64, name: &str) -> Result<u64, CurvyStateError> {
    value
        .0
        .parse()
        .map_err(|error| CurvyStateError::Corrupt(format!("invalid Curvy cursor {name}: {error}")))
}

fn encode_cursor(cursor: &CurvyEventCursor) -> Result<Vec<u8>, CurvyStateError> {
    let mut encoded =
        Vec::with_capacity(CURSOR_SIZE_WITHOUT_HASH + cursor.block_hash.as_ref().map_or(0, |hash| hash.0.len()));
    encoded.extend_from_slice(&cursor_component(&cursor.block, "block")?.to_be_bytes());
    encoded.extend_from_slice(&cursor_component(&cursor.transaction_index, "transaction index")?.to_be_bytes());
    encoded.extend_from_slice(&cursor_component(&cursor.log_index, "log index")?.to_be_bytes());
    encoded.extend_from_slice(&cursor_component(&cursor.event_item_index, "event item index")?.to_be_bytes());
    if let Some(hash) = &cursor.block_hash {
        encoded.extend_from_slice(hash.0.as_bytes());
    }
    Ok(encoded)
}

fn decode_cursor(encoded: &[u8]) -> Result<CurvyEventCursor, CurvyStateError> {
    if encoded.len() < CURSOR_SIZE_WITHOUT_HASH {
        return Err(CurvyStateError::Corrupt(format!(
            "Curvy cursor has {} bytes, expected at least {CURSOR_SIZE_WITHOUT_HASH}",
            encoded.len()
        )));
    }
    let read_u64 = |offset: usize| {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&encoded[offset..offset + 8]);
        u64::from_be_bytes(bytes)
    };
    let mut cursor = CurvyEventCursor::new(read_u64(0), read_u64(8), read_u64(16), read_u64(24));
    if encoded.len() > CURSOR_SIZE_WITHOUT_HASH {
        cursor.block_hash = Some(Hex32(
            String::from_utf8(encoded[CURSOR_SIZE_WITHOUT_HASH..].to_vec())
                .map_err(|error| CurvyStateError::Corrupt(format!("cursor block hash is not UTF-8: {error}")))?,
        ));
    }
    Ok(cursor)
}

#[derive(Clone)]
struct StoredOwnedNote {
    detected: DetectedCurvyNote,
    committed: bool,
    leaf_index: Option<u64>,
}

fn encode_note_field(encoded: &mut Vec<u8>, value: &curvy_core::Fr) {
    encoded.extend_from_slice(&fr_to_be_32(value));
}

fn decode_note_field(encoded: &[u8], offset: &mut usize, name: &str) -> Result<curvy_core::Fr, CurvyStateError> {
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&encoded[*offset..*offset + 32]);
    *offset += 32;
    fr_from_be_32_checked(&bytes)
        .ok_or_else(|| CurvyStateError::Corrupt(format!("owned-note {name} is not a canonical BN254 field element")))
}

fn encode_owned_note(note: &StoredOwnedNote) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(OWNED_NOTE_SIZE);
    encoded.push(OWNED_NOTE_VERSION);
    encoded.extend_from_slice(&id_bytes(&note.detected.deposit.id));
    encoded.extend_from_slice(note.detected.deposit.address.as_ref());
    encoded.extend_from_slice(&note.detected.deposit.amount.amount().to_be_bytes());
    encode_note_field(&mut encoded, &note.detected.note.amount);
    encode_note_field(&mut encoded, &note.detected.note.token);
    encode_note_field(&mut encoded, &note.detected.note.owner_pub.0);
    encode_note_field(&mut encoded, &note.detected.note.owner_pub.1);
    encode_note_field(&mut encoded, &note.detected.note.shared_secret);
    encode_note_field(&mut encoded, &note.detected.note.ephemeral_key.0);
    encode_note_field(&mut encoded, &note.detected.note.ephemeral_key.1);
    encode_note_field(&mut encoded, &note.detected.note.view_tag);
    encoded.push(u8::from(note.committed));
    encoded.extend_from_slice(&note.leaf_index.unwrap_or(u64::MAX).to_be_bytes());
    encoded
}

fn decode_owned_note(encoded: &[u8]) -> Result<StoredOwnedNote, CurvyStateError> {
    if encoded.len() != OWNED_NOTE_SIZE {
        return Err(CurvyStateError::Corrupt(format!(
            "owned-note record has {} bytes, expected {OWNED_NOTE_SIZE}",
            encoded.len()
        )));
    }

    if encoded[0] != OWNED_NOTE_VERSION {
        return Err(CurvyStateError::Corrupt(format!(
            "unsupported owned-note record version {}",
            encoded[0]
        )));
    }

    let id = PixAddressId::try_from(&encoded[1..1 + PixAddressId::SIZE])
        .map_err(|error| CurvyStateError::Corrupt(format!("invalid PIX allocation ID: {error}")))?;
    let address_offset = 1 + PixAddressId::SIZE;
    let amount_offset = address_offset + 32;
    let address = BjjPublicKey::try_from(&encoded[address_offset..amount_offset])
        .map_err(|error| CurvyStateError::Corrupt(format!("invalid BJJ address: {error}")))?;
    let fields_offset = amount_offset + 32;
    let amount = HoprBalance::from(U256::from_be_bytes(&encoded[amount_offset..fields_offset]));
    let mut offset = fields_offset;
    let note = Note {
        amount: decode_note_field(encoded, &mut offset, "amount")?,
        token: decode_note_field(encoded, &mut offset, "token")?,
        owner_pub: (
            decode_note_field(encoded, &mut offset, "owner x")?,
            decode_note_field(encoded, &mut offset, "owner y")?,
        ),
        shared_secret: decode_note_field(encoded, &mut offset, "shared secret")?,
        ephemeral_key: (
            decode_note_field(encoded, &mut offset, "ephemeral key x")?,
            decode_note_field(encoded, &mut offset, "ephemeral key y")?,
        ),
        view_tag: decode_note_field(encoded, &mut offset, "view tag")?,
    };
    let committed = match encoded[offset] {
        0 => false,
        1 => true,
        value => {
            return Err(CurvyStateError::Corrupt(format!(
                "invalid owned-note committed flag {value}"
            )));
        }
    };
    let mut leaf_index_bytes = [0_u8; 8];
    leaf_index_bytes.copy_from_slice(&encoded[offset + 1..offset + 9]);
    let raw_leaf_index = u64::from_be_bytes(leaf_index_bytes);
    let leaf_index = (raw_leaf_index != u64::MAX).then_some(raw_leaf_index);
    if committed != leaf_index.is_some() {
        return Err(CurvyStateError::Corrupt(
            "owned-note commitment flag and leaf index disagree".to_owned(),
        ));
    }

    Ok(StoredOwnedNote {
        detected: DetectedCurvyNote {
            deposit: OwnedCurvyDeposit { id, address, amount },
            note,
        },
        committed,
        leaf_index,
    })
}

pub(super) fn note_id_key(note_id: &str) -> Result<[u8; NOTE_ID_SIZE], CurvyStateError> {
    parse_curvy_note_id(note_id)
        .map(|note_id| fr_to_be_32(&note_id.into_inner()))
        .map_err(|error| CurvyStateError::Corrupt(error.to_string()))
}

fn owned_note_key(id: &PixAddressId, note_id: &str) -> Result<[u8; OWNED_NOTE_KEY_SIZE], CurvyStateError> {
    let mut key = [0_u8; OWNED_NOTE_KEY_SIZE];
    key[..PixAddressId::SIZE].copy_from_slice(&id_bytes(id));
    key[PixAddressId::SIZE..].copy_from_slice(&note_id_key(note_id)?);
    Ok(key)
}

fn session_note_range(id: &PixAddressId) -> ([u8; OWNED_NOTE_KEY_SIZE], [u8; OWNED_NOTE_KEY_SIZE]) {
    let mut start = [0_u8; OWNED_NOTE_KEY_SIZE];
    let mut end = [u8::MAX; OWNED_NOTE_KEY_SIZE];
    let id = id_bytes(id);
    start[..PixAddressId::SIZE].copy_from_slice(&id);
    end[..PixAddressId::SIZE].copy_from_slice(&id);
    (start, end)
}

/// Storage used by the Curvy pool for crash-safe query resumption, note correlation and scan
/// secrets.
pub trait CurvyDepositState: Send + Sync + 'static {
    fn cursor(&self, kind: CurvyEventKind) -> Result<Option<CurvyEventCursor>, CurvyStateError>;

    /// Records an owned candidate and advances the cursor atomically.
    fn record_owned_candidate(
        &self,
        note_id: &str,
        note: DetectedCurvyNote,
        cursor: &CurvyEventCursor,
    ) -> Result<(), CurvyStateError>;

    /// Marks a known note committed and advances the cursor atomically.
    fn record_completion(
        &self,
        note_id: &str,
        leaf_index: u64,
        cursor: &CurvyEventCursor,
    ) -> Result<Option<CommittedCurvyNote>, CurvyStateError>;

    /// Advances past an event which does not belong to this node.
    fn advance_cursor(&self, kind: CurvyEventKind, cursor: &CurvyEventCursor) -> Result<(), CurvyStateError>;

    /// Returns the total value of all committed notes owned by one PIX allocation.
    fn committed_amount(&self, id: &PixAddressId) -> Result<HoprBalance, CurvyStateError>;

    /// Loads complete committed notes for a reconstructed PIX allocation.
    fn committed_notes(&self, id: &PixAddressId) -> Result<Vec<CommittedCurvyNote>, CurvyStateError>;

    /// Removes notes after their nullifiers have been accepted by the SDK submission flow.
    fn remove_spent_notes(&self, id: &PixAddressId, note_ids: &[String]) -> Result<(), CurvyStateError>;

    /// The ids (`0x`-prefixed 32-byte hex) of every note this store believes it owns.
    fn owned_note_ids(&self) -> Result<Vec<String>, CurvyStateError>;

    /// Persists the Exit-side scan secret for `id`, generated with the deposit data for that
    /// allocation. Must be durable before the public half leaves the node.
    fn store_scan_secret(&self, id: &PixAddressId, secret: &CurvyScanSecret) -> Result<(), CurvyStateError>;

    /// The scan secret stored for `id`, if [`store_scan_secret`](Self::store_scan_secret) ran.
    fn scan_secret(&self, id: &PixAddressId) -> Result<Option<CurvyScanSecret>, CurvyStateError>;

    /// Forgets the scan secret for `id`, once nothing can arrive for it any more.
    fn remove_scan_secret(&self, id: &PixAddressId) -> Result<(), CurvyStateError>;

    /// Drops everything that describes a particular chain — cursors, notes and scan secrets — so
    /// the store can be reused against a chain that knows none of it. See
    /// [`CurvyDepositPool`](super::CurvyDepositPool) for when that is decided.
    fn wipe_chain_state(&self) -> Result<(), CurvyStateError>;
}

/// Redb-backed Curvy lifecycle state.
pub struct RedbCurvyDepositState {
    db: Arc<redb::Database>,
}

impl RedbCurvyDepositState {
    /// Opens (or creates) the durable note store at a node-stable path.
    ///
    /// The path must be reused across restarts; an ephemeral path loses the private note state
    /// that makes committed deposits sweepable.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CurvyStateError> {
        let db = redb::Database::create(path).map_err(state_db_error)?;
        let write = db.begin_write().map_err(state_db_error)?;
        write.open_table(CURSOR_TABLE).map_err(state_db_error)?;
        write.open_table(OWNED_NOTES_TABLE).map_err(state_db_error)?;
        write.open_table(NOTE_SESSIONS_TABLE).map_err(state_db_error)?;
        write.open_table(SCAN_SECRETS_TABLE).map_err(state_db_error)?;
        write.commit().map_err(state_db_error)?;
        Ok(Self { db: Arc::new(db) })
    }

    /// The database, shared with the SDK bridge so its state lives in the same file and is wiped
    /// together with this one.
    pub(super) fn shared_database(&self) -> Arc<redb::Database> {
        Arc::clone(&self.db)
    }

    fn put_cursor(
        cursor_table: &mut redb::Table<'_, u8, Vec<u8>>,
        kind: CurvyEventKind,
        cursor: &CurvyEventCursor,
    ) -> Result<(), CurvyStateError> {
        cursor_table
            .insert(kind.cursor_key(), encode_cursor(cursor)?)
            .map_err(state_db_error)?;
        Ok(())
    }
}

impl CurvyDepositState for RedbCurvyDepositState {
    fn cursor(&self, kind: CurvyEventKind) -> Result<Option<CurvyEventCursor>, CurvyStateError> {
        let read = self.db.begin_read().map_err(state_db_error)?;
        let table = read.open_table(CURSOR_TABLE).map_err(state_db_error)?;
        table
            .get(kind.cursor_key())
            .map_err(state_db_error)?
            .map(|value| decode_cursor(&value.value()))
            .transpose()
    }

    fn record_owned_candidate(
        &self,
        note_id: &str,
        note: DetectedCurvyNote,
        cursor: &CurvyEventCursor,
    ) -> Result<(), CurvyStateError> {
        let id = note.deposit.id;
        let note_id_key = note_id_key(note_id)?;
        let owned_note_key = owned_note_key(&id, note_id)?;
        let write = self.db.begin_write().map_err(state_db_error)?;
        {
            let mut notes = write.open_table(OWNED_NOTES_TABLE).map_err(state_db_error)?;
            if notes.get(owned_note_key).map_err(state_db_error)?.is_none() {
                notes
                    .insert(
                        owned_note_key,
                        encode_owned_note(&StoredOwnedNote {
                            detected: note,
                            committed: false,
                            leaf_index: None,
                        }),
                    )
                    .map_err(state_db_error)?;
            }
            let mut sessions = write.open_table(NOTE_SESSIONS_TABLE).map_err(state_db_error)?;
            sessions.insert(note_id_key, id_bytes(&id)).map_err(state_db_error)?;
            let mut cursor_table = write.open_table(CURSOR_TABLE).map_err(state_db_error)?;
            Self::put_cursor(&mut cursor_table, CurvyEventKind::Pending, cursor)?;
        }
        write.commit().map_err(state_db_error)
    }

    fn record_completion(
        &self,
        note_id: &str,
        leaf_index: u64,
        cursor: &CurvyEventCursor,
    ) -> Result<Option<CommittedCurvyNote>, CurvyStateError> {
        let note_id_key = note_id_key(note_id)?;
        let write = self.db.begin_write().map_err(state_db_error)?;
        let detected = {
            let sessions = write.open_table(NOTE_SESSIONS_TABLE).map_err(state_db_error)?;
            let id = sessions
                .get(note_id_key)
                .map_err(state_db_error)?
                .map(|value| PixAddressId::try_from(value.value().as_slice()))
                .transpose()
                .map_err(|error| CurvyStateError::Corrupt(format!("invalid note session ID: {error}")))?;
            let mut notes = write.open_table(OWNED_NOTES_TABLE).map_err(state_db_error)?;
            let key = id.as_ref().map(|id| owned_note_key(id, note_id)).transpose()?;
            let stored = if let Some(key) = key {
                notes
                    .get(key)
                    .map_err(state_db_error)?
                    .map(|value| decode_owned_note(&value.value()))
                    .transpose()?
            } else {
                None
            };

            let detected = stored.as_ref().map(|note| CommittedCurvyNote {
                deposit: note.detected.deposit,
                note: note.detected.note.clone(),
                leaf_index,
            });
            if let (Some(key), Some(note)) = (key, stored) {
                notes
                    .insert(
                        key,
                        encode_owned_note(&StoredOwnedNote {
                            committed: true,
                            leaf_index: Some(leaf_index),
                            ..note
                        }),
                    )
                    .map_err(state_db_error)?;
            }
            let mut cursor_table = write.open_table(CURSOR_TABLE).map_err(state_db_error)?;
            Self::put_cursor(&mut cursor_table, CurvyEventKind::Committed, cursor)?;
            detected
        };
        write.commit().map_err(state_db_error)?;
        Ok(detected)
    }

    fn advance_cursor(&self, kind: CurvyEventKind, cursor: &CurvyEventCursor) -> Result<(), CurvyStateError> {
        let write = self.db.begin_write().map_err(state_db_error)?;
        {
            let mut table = write.open_table(CURSOR_TABLE).map_err(state_db_error)?;
            Self::put_cursor(&mut table, kind, cursor)?;
        }
        write.commit().map_err(state_db_error)
    }

    fn committed_amount(&self, id: &PixAddressId) -> Result<HoprBalance, CurvyStateError> {
        let read = self.db.begin_read().map_err(state_db_error)?;
        let table = read.open_table(OWNED_NOTES_TABLE).map_err(state_db_error)?;
        let mut total = HoprBalance::zero();
        let (start, end) = session_note_range(id);
        for entry in table.range(start..=end).map_err(state_db_error)? {
            let (_, value) = entry.map_err(state_db_error)?;
            let note = decode_owned_note(&value.value())?;
            if note.committed {
                total += note.detected.deposit.amount;
            }
        }
        Ok(total)
    }

    fn committed_notes(&self, id: &PixAddressId) -> Result<Vec<CommittedCurvyNote>, CurvyStateError> {
        let read = self.db.begin_read().map_err(state_db_error)?;
        let table = read.open_table(OWNED_NOTES_TABLE).map_err(state_db_error)?;
        let mut notes = Vec::new();
        let (start, end) = session_note_range(id);
        for entry in table.range(start..=end).map_err(state_db_error)? {
            let (_, value) = entry.map_err(state_db_error)?;
            let stored = decode_owned_note(&value.value())?;
            if let Some(leaf_index) = stored.leaf_index {
                notes.push(CommittedCurvyNote {
                    deposit: stored.detected.deposit,
                    note: stored.detected.note,
                    leaf_index,
                });
            }
        }
        Ok(notes)
    }

    fn remove_spent_notes(&self, id: &PixAddressId, note_ids: &[String]) -> Result<(), CurvyStateError> {
        let write = self.db.begin_write().map_err(state_db_error)?;
        {
            let mut notes = write.open_table(OWNED_NOTES_TABLE).map_err(state_db_error)?;
            let mut sessions = write.open_table(NOTE_SESSIONS_TABLE).map_err(state_db_error)?;
            for note_id in note_ids {
                notes.remove(owned_note_key(id, note_id)?).map_err(state_db_error)?;
                sessions.remove(note_id_key(note_id)?).map_err(state_db_error)?;
            }
        }
        write.commit().map_err(state_db_error)
    }

    fn owned_note_ids(&self) -> Result<Vec<String>, CurvyStateError> {
        let read = self.db.begin_read().map_err(state_db_error)?;
        let table = read.open_table(NOTE_SESSIONS_TABLE).map_err(state_db_error)?;
        let mut ids = Vec::new();
        for entry in table.iter().map_err(state_db_error)? {
            let (key, _) = entry.map_err(state_db_error)?;
            ids.push(format!("0x{}", const_hex::encode(key.value())));
        }
        Ok(ids)
    }

    fn store_scan_secret(&self, id: &PixAddressId, secret: &CurvyScanSecret) -> Result<(), CurvyStateError> {
        let write = self.db.begin_write().map_err(state_db_error)?;
        {
            let mut table = write.open_table(SCAN_SECRETS_TABLE).map_err(state_db_error)?;
            table
                .insert(id_bytes(id), secret.to_bytes().as_ref().to_vec())
                .map_err(state_db_error)?;
        }
        write.commit().map_err(state_db_error)
    }

    fn scan_secret(&self, id: &PixAddressId) -> Result<Option<CurvyScanSecret>, CurvyStateError> {
        let read = self.db.begin_read().map_err(state_db_error)?;
        let table = read.open_table(SCAN_SECRETS_TABLE).map_err(state_db_error)?;
        table
            .get(id_bytes(id))
            .map_err(state_db_error)?
            .map(|value| {
                CurvyScanSecret::try_from(value.value().as_slice())
                    .map_err(|error| CurvyStateError::Corrupt(format!("invalid stored Curvy scan secret: {error}")))
            })
            .transpose()
    }

    fn remove_scan_secret(&self, id: &PixAddressId) -> Result<(), CurvyStateError> {
        let write = self.db.begin_write().map_err(state_db_error)?;
        {
            let mut table = write.open_table(SCAN_SECRETS_TABLE).map_err(state_db_error)?;
            table.remove(id_bytes(id)).map_err(state_db_error)?;
        }
        write.commit().map_err(state_db_error)
    }

    fn wipe_chain_state(&self) -> Result<(), CurvyStateError> {
        let write = self.db.begin_write().map_err(state_db_error)?;
        write.delete_table(CURSOR_TABLE).map_err(state_db_error)?;
        write.delete_table(OWNED_NOTES_TABLE).map_err(state_db_error)?;
        write.delete_table(NOTE_SESSIONS_TABLE).map_err(state_db_error)?;
        write.delete_table(SCAN_SECRETS_TABLE).map_err(state_db_error)?;
        write.open_table(CURSOR_TABLE).map_err(state_db_error)?;
        write.open_table(OWNED_NOTES_TABLE).map_err(state_db_error)?;
        write.open_table(NOTE_SESSIONS_TABLE).map_err(state_db_error)?;
        write.open_table(SCAN_SECRETS_TABLE).map_err(state_db_error)?;
        write.commit().map_err(state_db_error)
    }
}
