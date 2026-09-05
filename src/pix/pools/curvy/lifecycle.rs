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
//! to an allocation registered a moment later. A late registration also forces one pass over both
//! families from genesis, because the shared cursors may already have moved past its note.

use std::{
    collections::{HashMap, hash_map::Entry},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
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
    detect::{CurvyDetectionError, RsCoreCurvyNoteDetector},
    state::{CurvyDepositState, CurvyEventKind, CurvyStateError, cursor_component, note_id_key},
};

const QUERY_PAGE_SIZE: u32 = 1_000;
/// Pause between two passes over the index, and after a failed one.
///
/// Short, because it sits directly on the confirmation latency: a commitment becomes final one
/// block after it lands, and every pass that starts just before that block wastes a whole
/// interval. Blokli answers these pages locally, so the cost of asking often is small.
const RECONNECT_DELAY: Duration = Duration::from_millis(250);

/// The slice of Blokli's Curvy API that discovery reads through.
///
/// Narrow on purpose: it is what a test has to fake to drive the whole pool without a Blokli, and
/// it is implemented for any [`BlokliQueryClient`] by [`BlokliIndex`].
#[async_trait]
pub trait CurvyIndexSource: Send + Sync + 'static {
    /// One page of pending notes strictly after `after`, oldest first.
    async fn pending_notes(&self, after: Option<CurvyEventCursor>, first: u32)
    -> Result<Vec<CurvyPendingNote>, String>;

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
    /// pending or committed. A chain that has never seen a note this node recorded is not the
    /// chain the record came from.
    async fn note_known(&self, note_id: String) -> Result<bool, String>;
}

/// [`CurvyIndexSource`] over a real Blokli client.
pub struct BlokliIndex<C>(pub Arc<C>);

#[async_trait]
impl<C> CurvyIndexSource for BlokliIndex<C>
where
    C: BlokliQueryClient + Send + Sync + 'static,
{
    async fn pending_notes(
        &self,
        after: Option<CurvyEventCursor>,
        first: u32,
    ) -> Result<Vec<CurvyPendingNote>, String> {
        self.0
            .query_curvy_pending_notes(None, after, first)
            .await
            .map(|page| page.notes)
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
}

/// Correlates Blokli's public note events with the allocations this node is waiting on.
pub struct CurvyLifecycleTracker<S> {
    detector: Arc<RsCoreCurvyNoteDetector>,
    pub(super) state: Arc<S>,
    waiters: parking_lot::Mutex<HashMap<PixAddressId, WatchedAllocation>>,
    pub(super) replay_history: AtomicBool,
}

impl<S> CurvyLifecycleTracker<S>
where
    S: CurvyDepositState,
{
    pub(super) fn new(detector: Arc<RsCoreCurvyNoteDetector>, state: Arc<S>) -> Self {
        Self {
            detector,
            state,
            waiters: Default::default(),
            replay_history: AtomicBool::new(false),
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
        let (sender, receiver) = futures::channel::oneshot::channel();
        // Serialize the persisted-state check with completion notifications. This
        // prevents a completion from landing between the check and waiter insert.
        let mut waiters = self.waiters.lock();
        let committed = self.state.committed_amount(&id)?;
        if committed >= minimum {
            let _ = sender.send(committed);
        } else {
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
            // allocation. Force one historical pass with the complete current watch
            // set. An epoch-like boolean is sufficient: if registration races a pass,
            // the worker observes it on the next outer iteration.
            self.replay_history.store(true, Ordering::Release);
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

    /// Starts both event families from genesis when a newly registered
    /// allocation requests historical recovery. Replaying only pending events is
    /// insufficient: the committed cursor may already have advanced past the
    /// recovered note while another allocation was being watched.
    pub(super) fn catch_up_cursor(
        &self,
        kind: CurvyEventKind,
        replay_history: bool,
    ) -> Result<Option<CurvyEventCursor>, CurvyStateError> {
        if replay_history {
            Ok(None)
        } else {
            self.state.cursor(kind)
        }
    }

    /// A historical replay is an at-least-once request. If any indexer or state
    /// operation interrupts the pass, retain the request so the next worker
    /// iteration starts both event families from genesis again.
    pub(super) fn restore_failed_replay(&self, replay_history: bool) {
        if replay_history {
            self.replay_history.store(true, Ordering::Release);
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
    pub(super) async fn process_candidate(&self, candidate: CurvyPendingNote) -> Result<bool, CurvyLifecycleError> {
        let watched = self.watched_allocations();
        if watched.is_empty() {
            return Ok(false);
        }

        let cursor = CurvyEventCursor::from(&candidate.position);

        let detected = match self.detector.detect_owned_note(&candidate, &watched) {
            Ok(detected) => detected,
            Err(CurvyDetectionError::InvalidCandidate(error)) => {
                tracing::error!(
                    note_id = %candidate.note_id.0,
                    %error,
                    "quarantining malformed public Curvy pending-note event"
                );
                self.state.advance_cursor(CurvyEventKind::Pending, &cursor)?;
                return Ok(true);
            }
        };

        match detected {
            Some(note) => {
                let allocation = note.deposit.id;
                self.state
                    .record_owned_candidate(&candidate.note_id.0, note, &cursor)
                    .map_err(CurvyLifecycleError::from)?;
                tracing::info!(
                    note_id = %candidate.note_id.0,
                    allocation = ?allocation,
                    "discovered Curvy PIX pending note through Blokli"
                );
            }
            None => self.state.advance_cursor(CurvyEventKind::Pending, &cursor)?,
        };
        Ok(true)
    }

    pub(super) async fn process_completion(&self, completion: CurvyCommittedNote) -> Result<(), CurvyLifecycleError> {
        let cursor = CurvyEventCursor::from(&completion.position);
        let leaf_index = match completion.leaf_index.0.parse() {
            Ok(leaf_index) => leaf_index,
            Err(error) => {
                tracing::error!(
                    note_id = %completion.note_id.0,
                    %error,
                    "quarantining malformed public Curvy committed-note leaf index"
                );
                self.state.advance_cursor(CurvyEventKind::Committed, &cursor)?;
                return Ok(());
            }
        };
        if let Err(error) = note_id_key(&completion.note_id.0) {
            tracing::error!(
                note_id = %completion.note_id.0,
                %error,
                "quarantining malformed public Curvy committed-note ID"
            );
            self.state.advance_cursor(CurvyEventKind::Committed, &cursor)?;
            return Ok(());
        }
        if let Some(note) = self
            .state
            .record_completion(&completion.note_id.0, leaf_index, &cursor)?
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

/// One catch-up pass over both event families. See the module docs for the ordering.
async fn catch_up<I, S>(client: &I, tracker: &CurvyLifecycleTracker<S>, replay_history: bool) -> Result<(), String>
where
    I: CurvyIndexSource,
    S: CurvyDepositState,
{
    let mut pending_after = tracker
        .catch_up_cursor(CurvyEventKind::Pending, replay_history)
        .map_err(|error| error.to_string())?;
    loop {
        let page = client.pending_notes(pending_after.clone(), QUERY_PAGE_SIZE).await?;
        let page_len = page.len();
        for note in page {
            pending_after = Some(CurvyEventCursor::from(&note.position));
            if !tracker
                .process_candidate(note)
                .await
                .map_err(|error| error.to_string())?
            {
                return Ok(());
            }
        }
        if page_len < QUERY_PAGE_SIZE as usize {
            break;
        }
    }

    let (indexed_block, finality) = client.indexed_head().await?;
    let finalized_through = indexed_block.saturating_sub(finality);
    let mut committed_after = tracker
        .catch_up_cursor(CurvyEventKind::Committed, replay_history)
        .map_err(|error| error.to_string())?;
    loop {
        let page = client.committed_notes(committed_after.clone(), QUERY_PAGE_SIZE).await?;
        let page_len = page.len();
        let mut reached_unfinalized = false;
        for note in page {
            let event_block =
                cursor_component(&note.position.block, "completion block").map_err(|error| error.to_string())?;
            if event_block > finalized_through {
                reached_unfinalized = true;
                break;
            }
            let cursor = CurvyEventCursor::from(&note.position);
            tracker
                .process_completion(note)
                .await
                .map_err(|error| error.to_string())?;
            committed_after = Some(cursor);
        }
        if reached_unfinalized || page_len < QUERY_PAGE_SIZE as usize {
            break;
        }
    }
    Ok(())
}

/// The watcher loop: polls Blokli while anybody is waiting, and idles otherwise.
///
/// Runs until aborted. Captures only the client and the tracker — never the pool — so that
/// dropping the pool is what ends it (see `CurvyDepositPool`'s `Drop`).
pub(super) async fn run_watcher<I, S>(client: Arc<I>, tracker: Arc<CurvyLifecycleTracker<S>>)
where
    I: CurvyIndexSource,
    S: CurvyDepositState,
{
    loop {
        if tracker.watched_allocations().is_empty() {
            tokio::time::sleep(RECONNECT_DELAY).await;
            continue;
        }

        let replay_history = tracker.replay_history.swap(false, Ordering::AcqRel);
        if let Err(error) = catch_up(client.as_ref(), tracker.as_ref(), replay_history).await {
            tracker.restore_failed_replay(replay_history);
            tracing::warn!(
                %error,
                replay_history,
                "failed to catch up Curvy PIX notes; retrying without losing historical replay"
            );
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}
