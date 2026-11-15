//! Discovery of Curvy notes through Blokli, and the waiting that
//! [`notify_deposit`](hopr_api::chain::DepositPool::notify_deposit) does on it.
//!
//! Blokli indexes two event families for the Curvy aggregator: *pending* notes (an aggregation
//! was mined) and *committed* notes (the operator folded them into the notes tree). A deposit is
//! confirmed for PIX only once it is **committed and final** — a pending note can still be
//! rejected, and a committed one can still be reorganised away until `finality` blocks have
//! passed.
//!
//! The watcher is one task per pool, started on the first registration and aborted when the pool
//! is dropped. Each pass catches pending notes up *first*, then committed ones, so that a
//! commitment can only ever correlate against an ownership decision that is already durable.
//! Committed events are consumed only up to `indexed_block − finality`.
//!
//! Every allocation registers its own scan secret, so the watcher's candidate set is exactly the
//! set of allocations somebody is waiting on. While that set is empty the pending cursor is
//! deliberately **not** advanced: an event skipped with nobody watching would otherwise be lost
//! to an allocation registered a moment later. A late registration also requests a replay of both
//! families, because the shared cursors may already have moved past its note. The replay starts at
//! the allocation's replay floor (see [`CurvyDepositState::replay_floor`]) — genesis when it has none
//! — and is bounded by the durable cursors, which it never moves. Within each family a pass
//! first scans what is new since the durable cursor and only then replays the window behind it;
//! all pending phases still precede all committed ones, so a fresh deposit is not delayed by
//! history. Foreign notes cost one cursor commit per page, not one each.

use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use blokli_client::api::{
    BlokliQueryClient,
    types::{CurvyCommittedNote, CurvyEventCursor, CurvyPendingNote},
};
use hopr_api::{
    node::PixAddressId,
    types::{
        crypto::prelude::{BjjPublicKey, CurvyScanSecret},
        primitive::prelude::HoprBalance,
    },
};

use super::{
    detect::{CurvyDetectionError, RsCoreCurvyNoteDetector, bjj_point},
    state::{CurvyDepositState, CurvyEventKind, CurvyStateError, cursor_component, note_id_key, unanchored_before},
    token::VaultToken,
};

const QUERY_PAGE_SIZE: u32 = 1_000;
/// Normal polling interval between successful passes over the index.
///
/// Short, because it sits directly on the confirmation latency: a commitment becomes final one
/// block after it lands, and every pass that starts just before that block wastes a whole
/// interval. Blokli answers these pages locally, so the cost of asking often is small.
const RECONNECT_DELAY: Duration = Duration::from_millis(250);

/// A pending-note traversal step. Snapshot sources return their entire pinned snapshot
/// with `has_more = false`; event streams can continue from the last note's cursor.
pub struct PendingNotesPage {
    pub notes: Vec<CurvyPendingNote>,
    pub has_more: bool,
}

impl PendingNotesPage {
    pub fn paged(notes: Vec<CurvyPendingNote>, first: u32) -> Self {
        Self {
            has_more: notes.len() == first as usize,
            notes,
        }
    }
}

/// The slice of Blokli's Curvy API that discovery reads through.
///
/// Narrow on purpose: it is what a test has to fake to drive the whole pool without a Blokli, and
/// it is implemented for any [`BlokliQueryClient`] by [`BlokliIndex`].
#[async_trait]
pub trait CurvyIndexSource: Send + Sync + 'static {
    /// Pending events after `after`, or one complete pinned snapshot for snapshot sources.
    async fn pending_notes(&self, after: Option<CurvyEventCursor>, first: u32) -> Result<PendingNotesPage, String>;

    /// One page of committed notes strictly after `after`, oldest first.
    async fn committed_notes(
        &self,
        after: Option<CurvyEventCursor>,
        first: u32,
    ) -> Result<Vec<CurvyCommittedNote>, String>;

    /// The highest block the indexer has processed, and the number of confirmations it treats as
    /// final.
    async fn indexed_head(&self) -> Result<(u64, u64), String>;

    /// Whether the chain has already seen `nullifier` (a `0x`-prefixed 32-byte hex string).
    async fn nullifier_spent(&self, nullifier: String) -> Result<bool, String>;

    /// Whether the aggregator knows `note_id` (a `0x`-prefixed 32-byte hex string) at all —
    /// pending or committed. An unknown note can also mean the index is still catching up.
    async fn note_known(&self, note_id: String) -> Result<bool, String>;

    /// Committed notes strictly after `after`, carrying what the detector scans, for sources
    /// whose pending view can miss a note. Curvy's indexer serves finalized checkpoints only, so
    /// a note the batch prover commits before its announcement finalizes is never seen pending —
    /// and a note is only ever discovered as a candidate. A source whose pending stream is
    /// complete, like Blokli, serves the empty page. Deliberately not defaulted: a wrapper that
    /// forgets to delegate it would silently lose every such note.
    async fn committed_candidates(
        &self,
        after: Option<CurvyEventCursor>,
        first: u32,
    ) -> Result<Vec<CurvyPendingNote>, String>;
}

/// [`CurvyIndexSource`] over a real Blokli client.
pub struct BlokliIndex<C>(pub Arc<C>);

#[async_trait]
impl<C> CurvyIndexSource for BlokliIndex<C>
where
    C: BlokliQueryClient + Send + Sync + 'static,
{
    async fn pending_notes(&self, after: Option<CurvyEventCursor>, first: u32) -> Result<PendingNotesPage, String> {
        self.0
            .query_curvy_pending_notes(None, after, first)
            .await
            .map(|page| PendingNotesPage::paged(page.notes, first))
            .map_err(|error| error.to_string())
    }

    async fn committed_notes(
        &self,
        after: Option<CurvyEventCursor>,
        first: u32,
    ) -> Result<Vec<CurvyCommittedNote>, String> {
        self.0
            .query_curvy_committed_notes(None, after, first)
            .await
            .map(|page| page.notes)
            .map_err(|error| error.to_string())
    }

    async fn indexed_head(&self) -> Result<(u64, u64), String> {
        let chain_info = self.0.query_chain_info().await.map_err(|error| error.to_string())?;
        let indexed_block = u64::try_from(chain_info.block_number)
            .map_err(|_| "Blokli returned a negative indexed block number".to_owned())?;
        let finality = cursor_component(&chain_info.finality, "finality").map_err(|error| error.to_string())?;
        Ok((indexed_block, finality))
    }

    async fn nullifier_spent(&self, nullifier: String) -> Result<bool, String> {
        self.0
            .query_curvy_nullifier_spent(nullifier)
            .await
            .map_err(|error| error.to_string())
    }

    async fn note_known(&self, note_id: String) -> Result<bool, String> {
        self.0
            .query_curvy_note_status(note_id)
            .await
            .map(|status| status.status != 0)
            .map_err(|error| error.to_string())
    }

    async fn committed_candidates(
        &self,
        _after: Option<CurvyEventCursor>,
        _first: u32,
    ) -> Result<Vec<CurvyPendingNote>, String> {
        // Blokli's pending stream is complete: every note is served pending before committed.
        Ok(Vec::new())
    }
}

#[derive(Debug)]
struct DepositWaiter {
    minimum: HoprBalance,
    sender: futures::channel::oneshot::Sender<HoprBalance>,
}

#[derive(Debug)]
struct WatchedAllocation {
    address: BjjPublicKey,
    scan_secret: CurvyScanSecret,
    waiters: Vec<DepositWaiter>,
}

#[derive(Debug, thiserror::Error)]
pub enum CurvyLifecycleError {
    #[error(transparent)]
    Detection(#[from] CurvyDetectionError),
    #[error(transparent)]
    State(#[from] CurvyStateError),
    #[error("could not resolve the Curvy vault token id: {0}")]
    VaultToken(String),
}

/// Where a tracker's detector comes from.
enum Detector {
    /// Handed in ready-made.
    Given(Arc<RsCoreCurvyNoteDetector>),
    /// Built the first time a note has to be judged, for the vault token the pool resolves.
    ///
    /// A detector is restricted to one token, and when the operator did not state its id that
    /// is a lookup. The tracker is constructed synchronously, so the lookup waits until the
    /// watcher — which is not — needs the answer.
    ForVaultToken {
        token: VaultToken,
        built: tokio::sync::OnceCell<RsCoreCurvyNoteDetector>,
    },
}

/// The historical replay a pass owes, per family: the position to start after, `None` being genesis.
#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct ReplayFrom {
    pub(super) pending: Option<CurvyEventCursor>,
    pub(super) committed: Option<CurvyEventCursor>,
}

/// Position of a cursor in the index order, `(block, transaction, log, item)`.
fn cursor_order(cursor: &CurvyEventCursor) -> Result<(u64, u64, u64, u64), CurvyStateError> {
    Ok((
        cursor_component(&cursor.block, "block")?,
        cursor_component(&cursor.transaction_index, "transaction index")?,
        cursor_component(&cursor.log_index, "log index")?,
        cursor_component(&cursor.event_item_index, "event item index")?,
    ))
}

/// The earlier of two replay starts; a start that cannot be ordered counts as genesis (`None`).
fn earlier(a: Option<CurvyEventCursor>, b: Option<CurvyEventCursor>) -> Option<CurvyEventCursor> {
    let (a, b) = (a?, b?);
    match (cursor_order(&a), cursor_order(&b)) {
        (Ok(order_a), Ok(order_b)) => Some(if order_b < order_a { b } else { a }),
        _ => None,
    }
}

/// Whether `cursor` lies after `end`. A position that cannot be ordered counts as in range.
fn is_beyond(cursor: &CurvyEventCursor, end: Option<&CurvyEventCursor>) -> bool {
    let Some(end) = end else { return false };
    matches!((cursor_order(cursor), cursor_order(end)), (Ok(cursor), Ok(end)) if cursor > end)
}

impl ReplayFrom {
    pub(super) fn merge(self, other: Self) -> Self {
        Self {
            pending: earlier(self.pending, other.pending),
            committed: earlier(self.committed, other.committed),
        }
    }
}

/// Correlates Blokli's public note events with the allocations this node is waiting on.
pub struct CurvyLifecycleTracker<S> {
    detector: Detector,
    pub(super) state: Arc<S>,
    waiters: parking_lot::Mutex<HashMap<PixAddressId, WatchedAllocation>>,
    pub(super) replay: parking_lot::Mutex<Option<ReplayFrom>>,
}

impl<S> CurvyLifecycleTracker<S>
where
    S: CurvyDepositState,
{
    pub(super) fn new(detector: Arc<RsCoreCurvyNoteDetector>, state: Arc<S>) -> Self {
        Self::with_detector(Detector::Given(detector), state)
    }

    /// A tracker whose detector is built for `token` once that is known.
    pub(super) fn for_vault_token(token: VaultToken, state: Arc<S>) -> Self {
        Self::with_detector(
            Detector::ForVaultToken {
                token,
                built: tokio::sync::OnceCell::new(),
            },
            state,
        )
    }

    fn with_detector(detector: Detector, state: Arc<S>) -> Self {
        Self {
            detector,
            state,
            waiters: Default::default(),
            replay: Default::default(),
        }
    }

    /// The detector, built first if this is the first note to be judged.
    ///
    /// A failed lookup builds nothing, so the next note asks again.
    async fn detector(&self) -> Result<&RsCoreCurvyNoteDetector, CurvyLifecycleError> {
        match &self.detector {
            Detector::Given(detector) => Ok(detector),
            Detector::ForVaultToken { token, built } => {
                built
                    .get_or_try_init(|| async {
                        token
                            .resolve()
                            .await
                            .map(RsCoreCurvyNoteDetector::for_token)
                            .map_err(CurvyLifecycleError::VaultToken)
                    })
                    .await
            }
        }
    }

    /// Registers interest in `id` reaching `minimum` committed value.
    ///
    /// Resolves immediately from durable state when the amount is already there — a restart
    /// between commitment and notification must not wait for an event that will not come again.
    pub(super) fn watch(
        &self,
        id: PixAddressId,
        address: BjjPublicKey,
        scan_secret: CurvyScanSecret,
        minimum: HoprBalance,
    ) -> Result<futures::channel::oneshot::Receiver<HoprBalance>, CurvyStateError> {
        bjj_point(&address).map_err(|error| CurvyStateError::Corrupt(format!("invalid watch owner: {error}")))?;
        let (sender, receiver) = futures::channel::oneshot::channel();
        // Serialize the persisted-state check with completion notifications. This
        // prevents a completion from landing between the check and waiter insert.
        let mut waiters = self.waiters.lock();
        let committed = self.state.committed_amount(&id)?;
        if committed >= minimum {
            let _ = sender.send(committed);
        } else {
            let request = ReplayFrom {
                pending: self.state.replay_floor(&id, CurvyEventKind::Pending)?,
                committed: self.state.replay_floor(&id, CurvyEventKind::Committed)?,
            };
            match waiters.entry(id) {
                Entry::Occupied(mut entry) => {
                    if entry.get().address != address {
                        return Err(CurvyStateError::Corrupt(
                            "PIX allocation ID was registered with two different addresses".to_owned(),
                        ));
                    }
                    if entry.get().scan_secret.public() != scan_secret.public() {
                        return Err(CurvyStateError::Corrupt(
                            "PIX allocation ID was registered with two different Curvy scan identities".to_owned(),
                        ));
                    }
                    entry.get_mut().waiters.push(DepositWaiter { minimum, sender });
                }
                Entry::Vacant(entry) => {
                    entry.insert(WatchedAllocation {
                        address,
                        scan_secret,
                        waiters: vec![DepositWaiter { minimum, sender }],
                    });
                }
            }
            // A shared stream cursor may already have advanced past this address's
            // allocation. Request one historical pass with the complete current watch
            // set, from the allocation's replay floor. If registration races a pass,
            // the worker observes the request on the next outer iteration.
            self.restore_failed_replay(Some(request));
        }
        Ok(receiver)
    }

    pub(super) fn watched_allocations(&self) -> Vec<(PixAddressId, BjjPublicKey, CurvyScanSecret)> {
        let mut waiters = self.waiters.lock();
        waiters.retain(|_, allocation| {
            allocation.waiters.retain(|waiter| !waiter.sender.is_canceled());
            !allocation.waiters.is_empty()
        });
        waiters
            .iter()
            .map(|(id, allocation)| (*id, allocation.address, allocation.scan_secret.clone()))
            .collect()
    }

    /// Takes the pending historical replay request, if any.
    pub(super) fn take_replay(&self) -> Option<ReplayFrom> {
        self.replay.lock().take()
    }

    /// A historical replay is an at-least-once request. If any indexer or state
    /// operation interrupts the pass, merge the request back so the next worker
    /// iteration replays at least as much again.
    pub(super) fn restore_failed_replay(&self, replay: Option<ReplayFrom>) {
        if let Some(replay) = replay {
            let mut slot = self.replay.lock();
            *slot = Some(match slot.take() {
                Some(existing) => existing.merge(replay),
                None => replay,
            });
        }
    }

    fn notify_waiters(&self, id: PixAddressId, committed: HoprBalance) {
        let mut waiters = self.waiters.lock();
        let mut remove_allocation = false;
        if let Some(allocation) = waiters.get_mut(&id) {
            let mut pending = Vec::with_capacity(allocation.waiters.len());
            for waiter in allocation.waiters.drain(..) {
                if committed >= waiter.minimum {
                    let _ = waiter.sender.send(committed);
                } else if !waiter.sender.is_canceled() {
                    pending.push(waiter);
                }
            }
            allocation.waiters = pending;
            remove_allocation = allocation.waiters.is_empty();
        }
        if remove_allocation {
            waiters.remove(&id);
        }
    }

    /// Returns `false` when processing must pause because no deposit address is
    /// currently registered. In that case the cursor is intentionally left
    /// untouched so the event is replayed after a waiter is added.
    ///
    /// Foreign and quarantined events write no cursor; the caller commits one per page. An owned
    /// note is recorded together with `hold`, the durable cursor to keep (the note's own position
    /// when `None`), so a replay never moves the cursor backwards.
    pub(super) async fn process_candidate(
        &self,
        candidate: CurvyPendingNote,
        hold: Option<&CurvyEventCursor>,
    ) -> Result<bool, CurvyLifecycleError> {
        let watched = self.watched_allocations();
        if watched.is_empty() {
            return Ok(false);
        }

        let cursor = CurvyEventCursor::from(&candidate.position);

        // Without a detector the event is neither ours nor not
        // ours, so a failure here leaves it to be judged again on the next pass.
        let detector = self.detector().await?;
        let detected = match detector.detect_owned_note(&candidate, &watched) {
            Ok(detected) => detected,
            Err(CurvyDetectionError::InvalidCandidate(error)) => {
                tracing::error!(
                    note_id = %candidate.note_id.0,
                    %error,
                    "quarantining malformed public Curvy pending-note event"
                );
                return Ok(true);
            }
        };

        if let Some(note) = detected {
            let allocation = note.deposit.id;
            self.state
                .record_owned_candidate(&candidate.note_id.0, note, hold.unwrap_or(&cursor))
                .map_err(CurvyLifecycleError::from)?;
            tracing::info!(
                note_id = %candidate.note_id.0,
                allocation = ?allocation,
                "discovered Curvy PIX pending note through Blokli"
            );
        }
        Ok(true)
    }

    /// Like [`process_candidate`](Self::process_candidate): malformed events are quarantined
    /// without a cursor write, and `hold` is the committed cursor to keep.
    pub(super) async fn process_completion(
        &self,
        completion: CurvyCommittedNote,
        hold: Option<&CurvyEventCursor>,
    ) -> Result<(), CurvyLifecycleError> {
        let cursor = CurvyEventCursor::from(&completion.position);
        let leaf_index = match completion.leaf_index.0.parse() {
            Ok(leaf_index) => leaf_index,
            Err(error) => {
                tracing::error!(
                    note_id = %completion.note_id.0,
                    %error,
                    "quarantining malformed public Curvy committed-note leaf index"
                );
                return Ok(());
            }
        };
        if let Err(error) = note_id_key(&completion.note_id.0) {
            tracing::error!(
                note_id = %completion.note_id.0,
                %error,
                "quarantining malformed public Curvy committed-note ID"
            );
            return Ok(());
        }
        if let Some(note) = self
            .state
            .record_completion(&completion.note_id.0, leaf_index, hold.unwrap_or(&cursor))?
        {
            tracing::info!(
                note_id = %completion.note_id.0,
                allocation = ?note.deposit.id,
                leaf_index,
                "correlated committed Curvy PIX note through Blokli"
            );
            let committed = self.state.committed_amount(&note.deposit.id)?;
            self.notify_waiters(note.deposit.id, committed);
        }
        Ok(())
    }
}

/// One pending-family phase. Forward (`replay == false`) starts after `start`, hold-free, and
/// commits the cursor once per page; a replay stops after `window_end` and holds the durable
/// cursor instead. Returns `false` when the watch set ran empty and the pass must stop.
async fn pending_phase<I, S>(
    client: &I,
    tracker: &CurvyLifecycleTracker<S>,
    start: Option<CurvyEventCursor>,
    window_end: Option<&CurvyEventCursor>,
    replay: bool,
) -> Result<bool, String>
where
    I: CurvyIndexSource,
    S: CurvyDepositState,
{
    let hold = if replay {
        tracker
            .state
            .cursor(CurvyEventKind::Pending)
            .map_err(|e| e.to_string())?
    } else {
        None
    };
    let mut after = start;
    loop {
        let page = client.pending_notes(after.clone(), QUERY_PAGE_SIZE).await?;
        let has_more = page.has_more;
        let mut last = None;
        let mut stopped = false;
        let mut watching = true;
        for note in page.notes {
            let position = CurvyEventCursor::from(&note.position);
            if replay && is_beyond(&position, window_end) {
                stopped = true;
                break;
            }
            watching = tracker
                .process_candidate(note, hold.as_ref())
                .await
                .map_err(|error| error.to_string())?;
            if !watching {
                stopped = true;
                break;
            }
            after = Some(position.clone());
            last = Some(position);
        }
        // Only what was actually processed is committed, also when the pass stops early.
        if let (false, Some(last)) = (replay, &last) {
            tracker
                .state
                .advance_cursor(CurvyEventKind::Pending, last)
                .map_err(|error| error.to_string())?;
        }
        if stopped || !has_more {
            return Ok(watching);
        }
    }
}

/// One committed-family phase, shaped like [`pending_phase`]. Only notes this store owns (or
/// whose ids are malformed, to be quarantined) are correlated; the rest are skipped.
async fn committed_phase<I, S>(
    client: &I,
    tracker: &CurvyLifecycleTracker<S>,
    start: Option<CurvyEventCursor>,
    window_end: Option<&CurvyEventCursor>,
    finalized_through: u64,
    replay: bool,
) -> Result<bool, String>
where
    I: CurvyIndexSource,
    S: CurvyDepositState,
{
    let hold = if replay {
        tracker
            .state
            .cursor(CurvyEventKind::Committed)
            .map_err(|e| e.to_string())?
    } else {
        None
    };
    let mut after = start;
    loop {
        let page = client.committed_notes(after.clone(), QUERY_PAGE_SIZE).await?;
        let page_len = page.len();
        // Notes committed before this watcher ever saw them pending get their discovery here,
        // over the very leaves this page completes, before the cursor moves past them. The
        // candidates are read after the page and bounded to it, so a checkpoint advancing
        // between the two reads can only widen the candidates, never leave a completed leaf
        // unscanned. Recording a candidate twice is harmless. They hold the durable pending
        // cursor, which this phase must not move.
        if page_len > 0 {
            let candidates = client.committed_candidates(after.clone(), page_len as u32).await?;
            for candidate in candidates {
                let pending = tracker
                    .state
                    .cursor(CurvyEventKind::Pending)
                    .map_err(|error| error.to_string())?;
                if !tracker
                    .process_candidate(candidate, pending.as_ref())
                    .await
                    .map_err(|error| error.to_string())?
                {
                    return Ok(false);
                }
            }
        }
        // Read after the candidates, which may have added owned notes.
        let owned: HashSet<_> = if page_len > 0 {
            tracker
                .state
                .owned_note_ids()
                .map_err(|error| error.to_string())?
                .iter()
                .filter_map(|id| note_id_key(id).ok())
                .collect()
        } else {
            HashSet::new()
        };
        let mut stop = false;
        let mut last = None;
        for note in page {
            let event_block =
                cursor_component(&note.position.block, "completion block").map_err(|error| error.to_string())?;
            let position = CurvyEventCursor::from(&note.position);
            if event_block > finalized_through || (replay && is_beyond(&position, window_end)) {
                stop = true;
                break;
            }
            if note_id_key(&note.note_id.0).map_or(true, |key| owned.contains(&key)) {
                tracker
                    .process_completion(note, hold.as_ref())
                    .await
                    .map_err(|error| error.to_string())?;
            }
            after = Some(position.clone());
            last = Some(position);
        }
        if let (false, Some(last)) = (replay, &last) {
            tracker
                .state
                .advance_cursor(CurvyEventKind::Committed, last)
                .map_err(|error| error.to_string())?;
        }
        if stop || page_len < QUERY_PAGE_SIZE as usize {
            return Ok(true);
        }
    }
}

/// Runs `phase` from `start`, and once more from [`unanchored_before`] `start` if it fails from
/// an anchored start.
///
/// An anchored start (a durable cursor, or a committed replay floor) names a block, and the index
/// refuses it once that block was reorganised away — on every pass, and again after a restart,
/// since the start is persisted. The retry re-reads a margin of blocks before it without the
/// anchor, so the events of replacement blocks are seen, the old position's included; a forward
/// phase also replaces its durable cursor with canonical positions as it goes. The error cannot
/// be told apart from an outage, so an outage costs one more query: a second failure is returned.
async fn recovering_anchor<F, Fut>(
    family: &'static str,
    start: Option<CurvyEventCursor>,
    mut phase: F,
) -> Result<bool, String>
where
    F: FnMut(Option<CurvyEventCursor>) -> Fut,
    Fut: Future<Output = Result<bool, String>>,
{
    let anchored = start.as_ref().filter(|cursor| cursor.block_hash.is_some()).cloned();
    match (phase(start).await, anchored) {
        (Err(error), Some(anchored)) => {
            tracing::warn!(%error, family, "Curvy event start was rejected; rescanning from before it without its anchor");
            phase(unanchored_before(&anchored).unwrap_or(None)).await
        }
        (result, _) => result,
    }
}

/// One catch-up pass over both event families. See the module docs for the ordering.
///
/// The forward phases consume what is new since the durable cursors; the replay phases, when
/// `replay` is requested, then revisit the window `(replay start, durable cursor before this
/// pass]` for the allocations registered since. All pending phases precede all committed ones.
/// Every phase recovers from a start whose block was reorganised away: see [`recovering_anchor`].
pub(super) async fn catch_up<I, S>(
    client: &I,
    tracker: &CurvyLifecycleTracker<S>,
    replay: Option<&ReplayFrom>,
) -> Result<(), String>
where
    I: CurvyIndexSource,
    S: CurvyDepositState,
{
    let p0 = tracker
        .state
        .cursor(CurvyEventKind::Pending)
        .map_err(|error| error.to_string())?;
    let p0_end = p0.as_ref();
    if !recovering_anchor("pending", p0.clone(), move |from| {
        pending_phase(client, tracker, from, None, false)
    })
    .await?
    {
        return Ok(());
    }
    if let (Some(replay), Some(_)) = (replay, p0_end)
        && !recovering_anchor("pending", replay.pending.clone(), move |from| {
            pending_phase(client, tracker, from, p0_end, true)
        })
        .await?
    {
        return Ok(());
    }

    let (indexed_block, finality) = client.indexed_head().await?;
    let finalized_through = indexed_block.saturating_sub(finality);
    let c0 = tracker
        .state
        .cursor(CurvyEventKind::Committed)
        .map_err(|error| error.to_string())?;
    let c0_end = c0.as_ref();
    if !recovering_anchor("committed", c0.clone(), move |from| {
        committed_phase(client, tracker, from, None, finalized_through, false)
    })
    .await?
    {
        return Ok(());
    }
    if let (Some(replay), Some(_)) = (replay, c0_end) {
        recovering_anchor("committed", replay.committed.clone(), move |from| {
            committed_phase(client, tracker, from, c0_end, finalized_through, true)
        })
        .await?;
    }
    Ok(())
}

/// The watcher loop: polls Blokli while anybody is waiting, and idles otherwise.
///
/// Runs until aborted. Captures only the client and the tracker — never the pool — so that
/// dropping the pool is what ends it (see `CurvyDepositPool`'s `Drop`).
pub(super) async fn run_watcher<I, S>(client: Arc<I>, tracker: Arc<CurvyLifecycleTracker<S>>, tracking_budget: Duration)
where
    I: CurvyIndexSource,
    S: CurvyDepositState,
{
    // Keep several retry opportunities within even a short deposit tracking budget.
    let cap = (tracking_budget / 10).clamp(RECONNECT_DELAY, Duration::from_secs(5));
    let mut retry_delay = RECONNECT_DELAY;
    loop {
        if tracker.watched_allocations().is_empty() {
            retry_delay = RECONNECT_DELAY;
            tokio::time::sleep(RECONNECT_DELAY).await;
            continue;
        }

        let replay = tracker.take_replay();
        let delay = match catch_up(client.as_ref(), tracker.as_ref(), replay.as_ref()).await {
            Ok(()) => {
                retry_delay = RECONNECT_DELAY;
                RECONNECT_DELAY
            }
            Err(error) => {
                let replayed = replay.is_some();
                tracker.restore_failed_replay(replay);
                let delay = retry_delay;
                retry_delay = retry_delay.saturating_mul(2).min(cap);
                tracing::warn!(%error, replayed, retry_in = ?delay,
                    "failed to catch up Curvy PIX notes; retrying without losing historical replay");
                delay
            }
        };
        tokio::time::sleep(delay).await;
    }
}
