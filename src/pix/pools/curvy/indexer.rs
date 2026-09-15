//! Curvy's shared indexer as the pool's note source, in place of Blokli's Curvy index.
//!
//! Blokli indexes the aggregator's events straight from the chain, which is the default and the
//! self-contained choice. Curvy also runs an indexer of its own — the one its SDKs sync from —
//! and exposes it per deployment under the gateway's `/sync` prefix: a finalized *checkpoint* and,
//! pinned to it, the committed notes in leaf order, the pending notes, the nullifiers and the
//! shard roots. When a node's Blokli has not indexed Curvy (or is still catching up on everything
//! else), this module lets the pool read notes from that service instead, selected by
//! [`CurvyDepositPoolConfig::note_source`](super::CurvyDepositPoolConfig::note_source).
//!
//! It fills the two roles the pool reads notes through, and nothing else:
//!
//! * [`CurvyIndexSource`] — what discovery polls: pending notes to scan for ownership, committed notes to confirm them,
//!   and the two spot checks.
//! * rs-sdk's [`NoteIndexSource`] — what the SDK rebuilds the committed-notes tree from before it proves a withdrawal.
//!   `/sync/meta` plus `/sync/notes` is exactly a [`NotesTreeSnapshot`], the same fast path `curvy-chain-blokli` takes.
//!
//! Everything else — discovering the deployment, fee and note-status reads, nonces, submission —
//! still goes through Blokli; the indexer has no view of the chain beyond the aggregator's logs.
//!
//! ### How the API maps onto cursors
//!
//! `/sync/notes` and `/sync/nullifiers` are indexed by position in the tree, which is stable, so
//! a committed-note cursor is its **leaf index**, carried in the cursor's `event_item_index`.
//! `/sync/pending` is paged by *offset over the set of notes still pending*, which shrinks as
//! notes are committed — an offset is not a cursor. Pending notes are therefore always read as a
//! whole and the `after` cursor is ignored: the tracker tolerates replays by design (a late
//! registration forces one anyway), and a deployment has few pending notes at any moment.
//!
//! Every read is pinned to the indexer's latest *finalized* checkpoint, so nothing here can be
//! reorganised away and the head this source reports needs no further finality.
//!
//! ### Formats
//!
//! The indexer speaks 0x-hex for ids, keys and tokens and decimal for amounts; Blokli speaks
//! hex for ids and decimal for everything else, and that is what the detector and the SDK
//! expect. The conversions live in one place, [`hex_to_dec`], and are pinned by the tests.

use std::sync::Arc;

use async_trait::async_trait;
use blokli_client::{
    api::{
        BlokliQueryClient,
        types::{CurvyCommittedNote, CurvyEventCursor, CurvyEventPosition, CurvyPendingNote, Hex32, Uint64, Uint256},
    },
    exports::Url,
};
use curvy_chain_api::{ChainError, NoteIndexSource, Result as ChainResult};
use curvy_types::{CommittedNotesEvent, CommittedNullifiersEvent, NotesTreeSnapshot, PendingNotesEvent};
use hopr_api::types::primitive::prelude::U256;
use serde::Deserialize;

use super::lifecycle::CurvyIndexSource;

/// Largest page the indexer serves (`limit` is capped at 2000 server-side).
const PAGE_SIZE: u32 = 2000;

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// The one HTTP operation this module needs, behind a trait so the mapping is testable without a
/// server: `GET <base>/<path>` returning the JSON body.
#[async_trait]
pub trait SyncApi: Send + Sync + 'static {
    async fn get_json(&self, path_and_query: &str) -> Result<serde_json::Value, String>;
}

/// [`SyncApi`] over `reqwest`, against the gateway host (`https://api.curvy.dev`); the `/sync`
/// prefix is part of each path.
pub struct HttpSyncApi {
    base_url: Url,
    http: reqwest::Client,
}

impl HttpSyncApi {
    pub fn new(base_url: Url, request_timeout: std::time::Duration) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(request_timeout)
            .build()
            .map_err(|error| format!("building the Curvy indexer client: {error}"))?;
        Ok(Self { base_url, http })
    }
}

#[async_trait]
impl SyncApi for HttpSyncApi {
    async fn get_json(&self, path_and_query: &str) -> Result<serde_json::Value, String> {
        let url = self
            .base_url
            .join(path_and_query)
            .map_err(|error| format!("{path_and_query} is not a valid path under the indexer URL: {error}"))?;
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|error| format!("Curvy indexer {path_and_query}: {error}"))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|error| format!("reading the Curvy indexer's response to {path_and_query}: {error}"))?;
        if !status.is_success() {
            let summary: String = body.chars().take(300).collect();
            return Err(format!("Curvy indexer {path_and_query} answered {status}: {summary}"));
        }
        serde_json::from_str(&body).map_err(|error| format!("Curvy indexer {path_and_query}: not JSON: {error}"))
    }
}

/// Where the chain id for the indexer's `chainId` parameter comes from.
///
/// The pool learns it from Blokli's `chain_info` during discovery, which happens after the pool
/// is built; the SDK-side role is built after discovery and knows it outright.
#[async_trait]
pub trait ChainIdSource: Send + Sync + 'static {
    async fn chain_id(&self) -> Result<u64, String>;
}

#[async_trait]
impl ChainIdSource for u64 {
    async fn chain_id(&self) -> Result<u64, String> {
        Ok(*self)
    }
}

/// Reads the chain id from Blokli once and keeps it.
pub struct BlokliChainId<C> {
    client: Arc<C>,
    cached: tokio::sync::OnceCell<u64>,
}

impl<C> BlokliChainId<C> {
    pub fn new(client: Arc<C>) -> Self {
        Self {
            client,
            cached: tokio::sync::OnceCell::new(),
        }
    }
}

#[async_trait]
impl<C> ChainIdSource for BlokliChainId<C>
where
    C: BlokliQueryClient + Send + Sync + 'static,
{
    async fn chain_id(&self) -> Result<u64, String> {
        self.cached
            .get_or_try_init(|| async {
                let info = self
                    .client
                    .query_chain_info()
                    .await
                    .map_err(|error| error.to_string())?;
                u64::try_from(info.chain_id).map_err(|_| "Blokli reported a negative chain id".to_owned())
            })
            .await
            .copied()
    }
}

// ---------------------------------------------------------------------------
// Wire format (`packages/services/indexer/src/schemas/sync.ts`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyncMeta {
    checkpoint: String,
    finalized_block_number: u64,
    notes_root: String,
    note_count: u64,
    nullifier_count: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Page<T> {
    checkpoint: String,
    next_index: u64,
    total: u64,
    #[serde(alias = "notes", alias = "nullifiers")]
    items: Vec<T>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PendingRow {
    note_id: String,
    ephemeral_key: Option<[String; 2]>,
    view_tag: Option<u64>,
    amount: Option<String>,
    token: Option<String>,
    is_plaintext: Option<bool>,
    block_number: u64,
    block_hash: String,
    request_tx_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommittedRow {
    index: u64,
    note_id: String,
    batch_run_id: Option<String>,
    commit_block_number: u64,
    commit_block_hash: String,
    commit_tx_hash: String,
    // What the detector scans, as the row carries it alongside the commit: a committed note
    // can be discovered here when its pending announcement was never served (see
    // `committed_candidate`).
    ephemeral_key: Option<[String; 2]>,
    view_tag: Option<u64>,
    amount: Option<String>,
    token: Option<String>,
    is_plaintext: Option<bool>,
    block_number: Option<u64>,
    request_block_hash: Option<String>,
    request_tx_hash: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NullifierRow {
    index: u64,
    nullifier: String,
    block_number: Option<u64>,
    tx_hash: Option<String>,
}

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

/// A 0x-hex quantity of at most 32 bytes as the decimal string Blokli, the detector and the SDK
/// use for field elements and amounts. Decimal input passes through unchanged.
pub fn hex_to_dec(value: &str) -> Result<String, String> {
    let Some(digits) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) else {
        if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
            return Ok(value.to_owned());
        }
        return Err(format!("expected a 0x-hex or decimal quantity, got {value:?}"));
    };
    if digits.is_empty() || digits.len() > 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("expected at most 32 hex bytes, got {value:?}"));
    }
    U256::from_str_radix(digits, 16)
        .map(|quantity| quantity.to_string())
        .map_err(|error| format!("{value:?} is not a hex quantity: {error}"))
}

/// Canonical 32-byte hex: lowercase, 0x-prefixed, zero-padded, so ids compare byte-for-byte.
pub fn canonical_hex32(value: &str) -> Result<Hex32, String> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if digits.is_empty() || digits.len() > 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("expected a 32-byte hex value, got {value:?}"));
    }
    Ok(Hex32(format!("0x{:0>64}", digits.to_ascii_lowercase())))
}

fn uint64(value: u64) -> Uint64 {
    Uint64(value.to_string())
}

fn pending_note(row: &PendingRow, item_index: u64) -> Result<CurvyPendingNote, String> {
    let ephemeral_key = row
        .ephemeral_key
        .as_ref()
        .ok_or_else(|| format!("pending note {} has no ephemeral key", row.note_id))?;
    Ok(CurvyPendingNote {
        note_id: canonical_hex32(&row.note_id)?,
        ephemeral_key: vec![
            Uint256(hex_to_dec(&ephemeral_key[0])?),
            Uint256(hex_to_dec(&ephemeral_key[1])?),
        ],
        view_tag: i32::try_from(row.view_tag.unwrap_or(0)).map_err(|_| "view tag does not fit i32".to_owned())?,
        token_id: Uint256(hex_to_dec(row.token.as_deref().unwrap_or("0"))?),
        amount: Uint256(hex_to_dec(row.amount.as_deref().unwrap_or("0"))?),
        is_plaintext: row.is_plaintext.unwrap_or(false),
        position: CurvyEventPosition {
            transaction_hash: canonical_hex32(&row.request_tx_hash)?,
            block_hash: canonical_hex32(&row.block_hash)?,
            block: uint64(row.block_number),
            transaction_index: uint64(0),
            log_index: uint64(0),
            event_item_index: uint64(item_index),
        },
    })
}

/// A committed row as a discovery candidate — the shape `/sync/pending` serves, positioned at
/// the announcement and cursored by the leaf index — or `None` when the row carries no delivery
/// data to scan.
fn committed_candidate(row: &CommittedRow) -> Result<Option<CurvyPendingNote>, String> {
    let Some(ephemeral_key) = row.ephemeral_key.as_ref() else {
        return Ok(None);
    };
    Ok(Some(CurvyPendingNote {
        note_id: canonical_hex32(&row.note_id)?,
        ephemeral_key: vec![
            Uint256(hex_to_dec(&ephemeral_key[0])?),
            Uint256(hex_to_dec(&ephemeral_key[1])?),
        ],
        view_tag: i32::try_from(row.view_tag.unwrap_or(0)).map_err(|_| "view tag does not fit i32".to_owned())?,
        token_id: Uint256(hex_to_dec(row.token.as_deref().unwrap_or("0"))?),
        amount: Uint256(hex_to_dec(row.amount.as_deref().unwrap_or("0"))?),
        is_plaintext: row.is_plaintext.unwrap_or(false),
        position: CurvyEventPosition {
            transaction_hash: canonical_hex32(row.request_tx_hash.as_deref().unwrap_or(&row.commit_tx_hash))?,
            block_hash: canonical_hex32(row.request_block_hash.as_deref().unwrap_or(&row.commit_block_hash))?,
            block: uint64(row.block_number.unwrap_or(row.commit_block_number)),
            transaction_index: uint64(0),
            log_index: uint64(0),
            event_item_index: uint64(row.index),
        },
    }))
}

fn committed_note(row: &CommittedRow) -> Result<CurvyCommittedNote, String> {
    Ok(CurvyCommittedNote {
        batch_index: canonical_hex32(row.batch_run_id.as_deref().unwrap_or("0x0"))
            .unwrap_or_else(|_| Hex32(format!("0x{:0>64}", "0"))),
        note_id: canonical_hex32(&row.note_id)?,
        leaf_index: uint64(row.index),
        position: CurvyEventPosition {
            transaction_hash: canonical_hex32(&row.commit_tx_hash)?,
            block_hash: canonical_hex32(&row.commit_block_hash)?,
            block: uint64(row.commit_block_number),
            transaction_index: uint64(0),
            log_index: uint64(0),
            // The leaf index is the stable cursor: `/sync/notes?fromIndex=` resumes from it.
            event_item_index: uint64(row.index),
        },
    })
}

fn cursor_item_index(cursor: &CurvyEventCursor) -> Result<u64, String> {
    cursor.event_item_index.0.parse().map_err(|error| {
        format!(
            "invalid Curvy cursor item index {:?}: {error}",
            cursor.event_item_index.0
        )
    })
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// Typed reads over the indexer's `/sync` API for one chain.
pub struct CurvyIndexerClient<A = HttpSyncApi> {
    api: A,
    chain: Arc<dyn ChainIdSource>,
}

impl<A: SyncApi> CurvyIndexerClient<A> {
    pub fn new(api: A, chain: Arc<dyn ChainIdSource>) -> Self {
        Self { api, chain }
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str, query: &str) -> Result<T, String> {
        let chain_id = self.chain.chain_id().await?;
        let value = self.api.get_json(&format!("{path}?chainId={chain_id}{query}")).await?;
        serde_json::from_value(value).map_err(|error| format!("Curvy indexer {path}: unexpected shape: {error}"))
    }

    async fn meta(&self) -> Result<SyncMeta, String> {
        self.get("/sync/meta", "").await
    }

    /// One page of a positional collection, pinned to `at` when given so a multi-page read is
    /// consistent.
    async fn page<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        from_index: u64,
        limit: u32,
        at: Option<&str>,
    ) -> Result<Page<T>, String> {
        let mut query = format!("&fromIndex={from_index}&limit={}", limit.clamp(1, PAGE_SIZE));
        if let Some(at) = at {
            query.push_str(&format!("&at={at}"));
        }
        self.get(path, &query).await
    }

    /// Every item of a positional collection at one checkpoint.
    async fn all<T: serde::de::DeserializeOwned>(&self, path: &str, at: &str, total: u64) -> Result<Vec<T>, String> {
        let mut items = Vec::with_capacity(usize::try_from(total).unwrap_or(0));
        let mut from = 0;
        while from < total {
            let page: Page<T> = self.page(path, from, PAGE_SIZE, Some(at)).await?;
            if page.checkpoint != at {
                return Err(format!("Curvy indexer {path} changed checkpoint mid-read"));
            }
            if page.items.is_empty() || page.next_index <= from {
                return Err(format!("Curvy indexer {path} stopped advancing at {from} of {total}"));
            }
            from = page.next_index;
            items.extend(page.items);
        }
        Ok(items)
    }

    /// All notes still pending at the latest finalized checkpoint, in announcement order.
    async fn pending_all(&self) -> Result<Vec<PendingRow>, String> {
        let first: Page<PendingRow> = self.page("/sync/pending", 0, PAGE_SIZE, None).await?;
        if first.next_index >= first.total {
            return Ok(first.items);
        }
        let mut rows = first.items;
        rows.extend(
            self.all::<PendingRow>("/sync/pending", &first.checkpoint, first.total)
                .await?
                .into_iter()
                .skip(rows.len()),
        );
        Ok(rows)
    }
}

// ---------------------------------------------------------------------------
// The pool's discovery role
// ---------------------------------------------------------------------------

/// [`CurvyIndexSource`] over Curvy's indexer. See the module docs for the cursor semantics.
pub struct CurvyIndexerSource<A = HttpSyncApi>(pub CurvyIndexerClient<A>);

#[async_trait]
impl<A: SyncApi> CurvyIndexSource for CurvyIndexerSource<A> {
    async fn pending_notes(
        &self,
        _after: Option<CurvyEventCursor>,
        first: u32,
    ) -> Result<Vec<CurvyPendingNote>, String> {
        // Offsets over a shrinking set are not cursors; read the whole set (see module docs).
        let rows = self.0.pending_all().await?;
        rows.iter()
            .enumerate()
            .take(first as usize)
            .map(|(index, row)| pending_note(row, index as u64))
            .collect()
    }

    async fn committed_notes(
        &self,
        after: Option<CurvyEventCursor>,
        first: u32,
    ) -> Result<Vec<CurvyCommittedNote>, String> {
        let from = match after {
            Some(cursor) => cursor_item_index(&cursor)? + 1,
            None => 0,
        };
        let page: Page<CommittedRow> = self.0.page("/sync/notes", from, first, None).await?;
        page.items.iter().map(committed_note).collect()
    }

    async fn committed_candidates(
        &self,
        after: Option<CurvyEventCursor>,
        first: u32,
    ) -> Result<Vec<CurvyPendingNote>, String> {
        let from = match after {
            Some(cursor) => cursor_item_index(&cursor)? + 1,
            None => 0,
        };
        let page: Page<CommittedRow> = self.0.page("/sync/notes", from, first, None).await?;
        page.items
            .iter()
            .filter_map(|row| committed_candidate(row).transpose())
            .collect()
    }

    async fn indexed_head(&self) -> Result<(u64, u64), String> {
        // Everything the indexer serves is already finalized, so no confirmations are held back.
        let meta = self.0.meta().await?;
        Ok((meta.finalized_block_number, 0))
    }

    async fn nullifier_spent(&self, nullifier: String) -> Result<bool, String> {
        let wanted = canonical_hex32(&nullifier)?;
        let meta = self.0.meta().await?;
        let rows: Vec<NullifierRow> = self
            .0
            .all("/sync/nullifiers", &meta.checkpoint, meta.nullifier_count)
            .await?;
        Ok(rows
            .iter()
            .any(|row| canonical_hex32(&row.nullifier).is_ok_and(|seen| seen == wanted)))
    }

    async fn note_known(&self, note_id: String) -> Result<bool, String> {
        let wanted = canonical_hex32(&note_id)?;
        if self
            .0
            .pending_all()
            .await?
            .iter()
            .any(|row| canonical_hex32(&row.note_id).is_ok_and(|seen| seen == wanted))
        {
            return Ok(true);
        }
        let meta = self.0.meta().await?;
        let rows: Vec<CommittedRow> = self.0.all("/sync/notes", &meta.checkpoint, meta.note_count).await?;
        Ok(rows
            .iter()
            .any(|row| canonical_hex32(&row.note_id).is_ok_and(|seen| seen == wanted)))
    }
}

// ---------------------------------------------------------------------------
// The SDK's note-index role
// ---------------------------------------------------------------------------

/// rs-sdk's [`NoteIndexSource`] over Curvy's indexer, for `CurvyClient`'s tree rebuild and
/// nullifier checks.
pub struct CurvyIndexerNotes<A = HttpSyncApi>(pub CurvyIndexerClient<A>);

fn chain_error(error: String) -> ChainError {
    ChainError::Transport(error)
}

#[async_trait]
impl<A: SyncApi> NoteIndexSource for CurvyIndexerNotes<A> {
    async fn pending_notes(&self, from_block: u64, to_block: u64) -> ChainResult<Vec<PendingNotesEvent>> {
        let rows = self.0.pending_all().await.map_err(chain_error)?;
        let mut events = Vec::<PendingNotesEvent>::new();
        let mut last_tx: Option<String> = None;
        for row in rows
            .iter()
            .filter(|row| (from_block..=to_block).contains(&row.block_number))
        {
            let tx_hash = canonical_hex32(&row.request_tx_hash).map_err(chain_error)?.0;
            if last_tx.as_deref() != Some(tx_hash.as_str()) {
                events.push(PendingNotesEvent {
                    block_number: row.block_number,
                    tx_hash: tx_hash.clone(),
                    ..Default::default()
                });
                last_tx = Some(tx_hash);
            }
            let event = events.last_mut().expect("pushed above");
            let key = row
                .ephemeral_key
                .as_ref()
                .ok_or_else(|| chain_error(format!("pending note {} has no ephemeral key", row.note_id)))?;
            event.note_ids.push(hex_to_dec(&row.note_id).map_err(chain_error)?);
            event.ephemeral_keys[0].push(hex_to_dec(&key[0]).map_err(chain_error)?);
            event.ephemeral_keys[1].push(hex_to_dec(&key[1]).map_err(chain_error)?);
            event.view_tags.push(row.view_tag.unwrap_or(0));
            event
                .tokens
                .push(hex_to_dec(row.token.as_deref().unwrap_or("0")).map_err(chain_error)?);
            event
                .amounts
                .push(hex_to_dec(row.amount.as_deref().unwrap_or("0")).map_err(chain_error)?);
            event.is_plaintext.push(row.is_plaintext.unwrap_or(false));
        }
        Ok(events)
    }

    async fn committed_notes(&self, from_block: u64, to_block: u64) -> ChainResult<Vec<CommittedNotesEvent>> {
        let meta = self.0.meta().await.map_err(chain_error)?;
        let rows: Vec<CommittedRow> = self
            .0
            .all("/sync/notes", &meta.checkpoint, meta.note_count)
            .await
            .map_err(chain_error)?;
        // One event per commit transaction, keyed by its first leaf so the SDK's
        // `sort_by_key(batch_index)` reproduces leaf order.
        let mut events = Vec::<CommittedNotesEvent>::new();
        let mut last_tx: Option<String> = None;
        for row in rows
            .iter()
            .filter(|row| (from_block..=to_block).contains(&row.commit_block_number))
        {
            if last_tx.as_deref() != Some(row.commit_tx_hash.as_str()) {
                events.push(CommittedNotesEvent {
                    batch_index: row.index,
                    block_number: row.commit_block_number,
                    ..Default::default()
                });
                last_tx = Some(row.commit_tx_hash.clone());
            }
            events
                .last_mut()
                .expect("pushed above")
                .note_ids
                .push(hex_to_dec(&row.note_id).map_err(chain_error)?);
        }
        Ok(events)
    }

    async fn committed_nullifiers(&self, from_block: u64, to_block: u64) -> ChainResult<Vec<CommittedNullifiersEvent>> {
        let meta = self.0.meta().await.map_err(chain_error)?;
        let rows: Vec<NullifierRow> = self
            .0
            .all("/sync/nullifiers", &meta.checkpoint, meta.nullifier_count)
            .await
            .map_err(chain_error)?;
        let mut events = Vec::<CommittedNullifiersEvent>::new();
        let mut last_tx: Option<String> = None;
        for row in rows.iter().filter(|row| {
            row.block_number
                .is_none_or(|block| (from_block..=to_block).contains(&block))
        }) {
            let tx = row.tx_hash.clone().unwrap_or_default();
            if last_tx.as_deref() != Some(tx.as_str()) {
                events.push(CommittedNullifiersEvent {
                    batch_index: row.index,
                    block_number: row.block_number.unwrap_or(0),
                    ..Default::default()
                });
                last_tx = Some(tx);
            }
            events
                .last_mut()
                .expect("pushed above")
                .nullifiers
                .push(hex_to_dec(&row.nullifier).map_err(chain_error)?);
        }
        Ok(events)
    }

    async fn head_block(&self) -> ChainResult<u64> {
        Ok(self.0.meta().await.map_err(chain_error)?.finalized_block_number)
    }

    async fn notes_tree_snapshot(&self) -> ChainResult<Option<NotesTreeSnapshot>> {
        let meta = self.0.meta().await.map_err(chain_error)?;
        let rows: Vec<CommittedRow> = self
            .0
            .all("/sync/notes", &meta.checkpoint, meta.note_count)
            .await
            .map_err(chain_error)?;
        let mut leaves = Vec::with_capacity(rows.len());
        for (expected, row) in rows.iter().enumerate() {
            if row.index != expected as u64 {
                return Err(ChainError::Decode(format!(
                    "Curvy indexer notes are not dense: leaf {expected} is at index {}",
                    row.index
                )));
            }
            leaves.push(hex_to_dec(&row.note_id).map_err(chain_error)?);
        }
        Ok(Some(NotesTreeSnapshot {
            checkpoint: meta.checkpoint,
            notes_root: meta.notes_root,
            leaves,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// Canned `/sync` responses keyed by path (query stripped), as the staging indexer returned
    /// them on 2026-09-13 for Arbitrum — the shapes the Zod schemas in
    /// `packages/services/indexer/src/schemas/sync.ts` describe.
    struct FakeSyncApi(HashMap<&'static str, serde_json::Value>);

    #[async_trait]
    impl SyncApi for FakeSyncApi {
        async fn get_json(&self, path_and_query: &str) -> Result<serde_json::Value, String> {
            let path = path_and_query.split('?').next().unwrap_or(path_and_query);
            assert!(
                path_and_query.contains("chainId=42161"),
                "chain id must be passed: {path_and_query}"
            );
            self.0
                .get(path)
                .cloned()
                .ok_or_else(|| format!("no canned response for {path}"))
        }
    }

    const CHECKPOINT: &str = "0xb2d83d973a3268d0225d2992c7ff3c8c0eb37c510aab9ccbfb6e1a454e03b6c7";

    fn canned() -> FakeSyncApi {
        FakeSyncApi(HashMap::from([
            (
                "/sync/meta",
                serde_json::json!({
                    "checkpoint": CHECKPOINT, "chainId": 42161,
                    "contractAddress": "0xcffcfd5b1e082b3924cd7dd34a49c99ef080f953", "treeVersion": 1,
                    "finalizedBlockNumber": 504771934, "finalizedBlockHash": CHECKPOINT,
                    "notesRoot": "6621953892210890700977734075619161549681870583602506577322887929272868790788",
                    "noteCount": 2, "nullifierCount": 2, "pendingCount": 1,
                    "shardHeight": 14, "shardSize": 16384, "shardCount": 0
                }),
            ),
            (
                "/sync/pending",
                serde_json::json!({
                    "checkpoint": CHECKPOINT, "fromIndex": 0, "nextIndex": 1, "total": 1,
                    "notes": [{
                        "index": 0,
                        "noteId": "0x17bd35b593bd7c27f9233afcdc4c776194104135cfb9f061ea22ef683bdb0f92",
                        "ephemeralKey": [
                            "0x1527b38226b3377e43525862e2d43531cedbf8493dc181232eb982f7d467e66b",
                            "0x1ced083df0cff441d5b26c373d81abe4289ced6093c3217be78bb82e3a74dcc2"
                        ],
                        "viewTag": 43, "amount": "1098900",
                        "token": "0x0000000000000000000000000000000000000000000000000000000000000003",
                        "isPlaintext": true, "blockNumber": 479247301,
                        "blockHash": "0xcc93542ca021cf7516349201302815aef83ee12297a14edd52f04c97e42dbca1",
                        "requestTxHash": "0xc10b29fa9ef41bd22193a5631523ea14a9d37a0f141dfbe5f6f6c2cda88febfd"
                    }]
                }),
            ),
            (
                "/sync/notes",
                serde_json::json!({
                    "checkpoint": CHECKPOINT, "fromIndex": 0, "nextIndex": 2, "total": 2,
                    "notes": [
                        {
                            "index": 0,
                            "noteId": "0x010500f858617e38120921b1eb86a5d7cd896a22a0f1b92f032bbdc11a421412",
                            "ephemeralKey": ["0x01", "0x02"], "viewTag": 75, "amount": "1198800",
                            "token": "0x0000000000000000000000000000000000000000000000000000000000000003",
                            "isPlaintext": true, "batchRunId": null, "blockNumber": 479247300,
                            "requestBlockHash": "0xcc93542ca021cf7516349201302815aef83ee12297a14edd52f04c97e42dbca1",
                            "requestTxHash": "0xc10b29fa9ef41bd22193a5631523ea14a9d37a0f141dfbe5f6f6c2cda88febfd",
                            "commitBlockNumber": 479248392,
                            "commitBlockHash": "0x2b58841bea5e5afd5cc2dfbc9372bd8a14f35b0cbdc37e57cc6625aced8e5637",
                            "commitTxHash": "0xfed5f6143e756e6bbb3a752e6bec52b12510ff33e524ecc2d99c0ee5e1e7eab8"
                        },
                        {
                            "index": 1,
                            "noteId": "0x0000000000000000000000000000000000000000000000000000000000000007",
                            "ephemeralKey": ["0x03", "0x04"], "viewTag": 1, "amount": "5",
                            "token": "0x03", "isPlaintext": true, "batchRunId": null,
                            "blockNumber": 479247300,
                            "requestBlockHash": "0xcc93542ca021cf7516349201302815aef83ee12297a14edd52f04c97e42dbca1",
                            "requestTxHash": "0xc10b29fa9ef41bd22193a5631523ea14a9d37a0f141dfbe5f6f6c2cda88febfd",
                            "commitBlockNumber": 479248392,
                            "commitBlockHash": "0x2b58841bea5e5afd5cc2dfbc9372bd8a14f35b0cbdc37e57cc6625aced8e5637",
                            "commitTxHash": "0xfed5f6143e756e6bbb3a752e6bec52b12510ff33e524ecc2d99c0ee5e1e7eab8"
                        }
                    ]
                }),
            ),
            (
                "/sync/nullifiers",
                serde_json::json!({
                    "checkpoint": CHECKPOINT, "fromIndex": 0, "nextIndex": 2, "total": 2,
                    "nullifiers": [
                        {"index": 0, "nullifier": "0x0c404c024b172e2076dd39d102aec4dd81a56e54ad98dedc59d72438dfc93425",
                         "blockNumber": 480652462, "blockHash": "0x3b", "txHash": "0x0a3d591542a1a33676e48567bc10e910943028389d68e0fb1befa151ac5aa321"},
                        {"index": 1, "nullifier": "0x2b187619a2e63fb4d4492073778c2d97ef4ea4bd4b448f09c9ff01f52dcfebfd",
                         "blockNumber": 480652462, "blockHash": "0x3b", "txHash": "0x0a3d591542a1a33676e48567bc10e910943028389d68e0fb1befa151ac5aa321"}
                    ]
                }),
            ),
        ]))
    }

    fn client() -> CurvyIndexerClient<FakeSyncApi> {
        CurvyIndexerClient::new(canned(), Arc::new(42161u64))
    }

    // `python3 -c 'print(int("1527b38226b3377e43525862e2d43531cedbf8493dc181232eb982f7d467e66b",16))'`
    const EPHEMERAL_X_DEC: &str = "9568715777239685971697952391314644729094157095419485064759779852301864789611";

    #[test]
    fn hex_quantities_become_the_decimal_strings_the_detector_expects() {
        assert_eq!(hex_to_dec("0x03").unwrap(), "3");
        assert_eq!(
            hex_to_dec("0x0000000000000000000000000000000000000000000000000000000000000003").unwrap(),
            "3"
        );
        assert_eq!(
            hex_to_dec("0x1527b38226b3377e43525862e2d43531cedbf8493dc181232eb982f7d467e66b").unwrap(),
            EPHEMERAL_X_DEC
        );
        assert_eq!(hex_to_dec("1098900").unwrap(), "1098900", "decimal passes through");
        assert!(hex_to_dec("0x").is_err());
        assert!(hex_to_dec("abc").is_err());
        assert!(
            hex_to_dec(&format!("0x{}", "f".repeat(65))).is_err(),
            "more than 32 bytes"
        );
    }

    #[test]
    fn note_ids_are_canonicalised_for_byte_comparison() {
        assert_eq!(
            canonical_hex32("0X07").unwrap().0,
            "0x0000000000000000000000000000000000000000000000000000000000000007"
        );
        assert_eq!(
            canonical_hex32("0xABCD").unwrap().0,
            format!("0x{}abcd", "0".repeat(60))
        );
    }

    #[tokio::test]
    async fn pending_notes_carry_what_the_detector_scans() -> anyhow::Result<()> {
        let source = CurvyIndexerSource(client());
        let notes = source.pending_notes(None, 100).await.map_err(anyhow::Error::msg)?;
        assert_eq!(notes.len(), 1);
        let note = &notes[0];
        assert_eq!(
            note.note_id.0,
            "0x17bd35b593bd7c27f9233afcdc4c776194104135cfb9f061ea22ef683bdb0f92"
        );
        assert_eq!(note.ephemeral_key[0].0, EPHEMERAL_X_DEC);
        assert_eq!(note.token_id.0, "3");
        assert_eq!(note.amount.0, "1098900");
        assert_eq!(note.view_tag, 43);
        assert!(note.is_plaintext);
        assert_eq!(note.position.block.0, "479247301");
        assert_eq!(
            note.position.transaction_hash.0,
            "0xc10b29fa9ef41bd22193a5631523ea14a9d37a0f141dfbe5f6f6c2cda88febfd"
        );
        // The cursor is ignored on purpose: the same snapshot comes back.
        let again = source
            .pending_notes(Some(CurvyEventCursor::from(&note.position)), 100)
            .await
            .map_err(anyhow::Error::msg)?;
        assert_eq!(again.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn committed_rows_double_as_candidates_positioned_at_the_announcement() -> anyhow::Result<()> {
        // A note the batch prover commits before its announcement finalizes is never served
        // pending, so the committed row must be scannable on its own.
        let source = CurvyIndexerSource(client());
        let candidates = source
            .committed_candidates(None, 100)
            .await
            .map_err(anyhow::Error::msg)?;
        assert_eq!(candidates.len(), 2);
        assert_eq!(
            candidates[0].note_id.0,
            "0x010500f858617e38120921b1eb86a5d7cd896a22a0f1b92f032bbdc11a421412"
        );
        assert_eq!(candidates[0].view_tag, 75);
        assert_eq!(candidates[0].amount.0, "1198800");
        assert_eq!(candidates[0].position.block.0, "479247300", "the announcement block");
        assert_eq!(
            candidates[0].position.event_item_index.0, "0",
            "cursored by the leaf index"
        );
        assert_eq!(candidates[1].position.event_item_index.0, "1");
        // The fake serves one canned page whatever the query; the resume is the same
        // `fromIndex` arithmetic `committed_notes` is pinned on above.
        Ok(())
    }

    #[tokio::test]
    async fn committed_notes_use_the_leaf_index_as_cursor() -> anyhow::Result<()> {
        let source = CurvyIndexerSource(client());
        let notes = source.committed_notes(None, 100).await.map_err(anyhow::Error::msg)?;
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[0].leaf_index.0, "0");
        assert_eq!(notes[1].leaf_index.0, "1");
        assert_eq!(notes[1].position.event_item_index.0, "1");
        assert_eq!(
            notes[0].position.block.0, "479248392",
            "the commit block, not the announcement"
        );
        assert_eq!(
            notes[1].note_id.0,
            "0x0000000000000000000000000000000000000000000000000000000000000007"
        );
        let cursor = CurvyEventCursor::from(&notes[1].position);
        assert_eq!(cursor_item_index(&cursor).unwrap(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn the_head_is_the_finalized_checkpoint_with_no_extra_finality() -> anyhow::Result<()> {
        let source = CurvyIndexerSource(client());
        assert_eq!(source.indexed_head().await.map_err(anyhow::Error::msg)?, (504771934, 0));
        Ok(())
    }

    #[tokio::test]
    async fn spot_checks_scan_the_pinned_collections() -> anyhow::Result<()> {
        let source = CurvyIndexerSource(client());
        let spent = source
            .nullifier_spent("0x0C404C024B172E2076DD39D102AEC4DD81A56E54AD98DEDC59D72438DFC93425".to_owned())
            .await
            .map_err(anyhow::Error::msg)?;
        assert!(spent, "case-insensitive match");
        assert!(
            !source
                .nullifier_spent("0x01".to_owned())
                .await
                .map_err(anyhow::Error::msg)?
        );
        assert!(
            source.note_known("0x07".to_owned()).await.map_err(anyhow::Error::msg)?,
            "committed"
        );
        assert!(
            source
                .note_known("0x17bd35b593bd7c27f9233afcdc4c776194104135cfb9f061ea22ef683bdb0f92".to_owned())
                .await
                .map_err(anyhow::Error::msg)?,
            "pending"
        );
        assert!(!source.note_known("0x09".to_owned()).await.map_err(anyhow::Error::msg)?);
        Ok(())
    }

    #[tokio::test]
    async fn the_sdk_sees_a_dense_snapshot_and_grouped_events() -> anyhow::Result<()> {
        let notes = CurvyIndexerNotes(client());
        let snapshot = notes
            .notes_tree_snapshot()
            .await?
            .expect("the indexer always has a checkpoint");
        assert_eq!(snapshot.checkpoint, CHECKPOINT);
        assert_eq!(
            snapshot.leaves,
            vec![
                hex_to_dec("0x010500f858617e38120921b1eb86a5d7cd896a22a0f1b92f032bbdc11a421412").unwrap(),
                "7".to_owned()
            ]
        );
        assert_eq!(notes.head_block().await?, 504771934);

        let committed = notes.committed_notes(0, u64::MAX).await?;
        assert_eq!(committed.len(), 1, "both leaves share one commit transaction");
        assert_eq!(committed[0].batch_index, 0);
        assert_eq!(committed[0].note_ids.len(), 2);
        assert!(
            notes.committed_notes(0, 479248391).await?.is_empty(),
            "block range is honoured"
        );

        let pending = notes.pending_notes(0, u64::MAX).await?;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].ephemeral_keys[0], vec![EPHEMERAL_X_DEC.to_owned()]);
        assert_eq!(pending[0].tokens, vec!["3".to_owned()]);

        let nullifiers = notes.committed_nullifiers(0, u64::MAX).await?;
        assert_eq!(nullifiers.len(), 1);
        assert_eq!(nullifiers[0].nullifiers.len(), 2);
        Ok(())
    }
}
