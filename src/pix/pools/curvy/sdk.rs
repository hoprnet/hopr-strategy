//! The bridge to `curvy-sdk`: proofs, contract payloads and the node's private funding pool.
//!
//! The split with the rest of the pool is deliberate. Everything *this* module does needs the SDK
//! — Groth16 proving, calldata, the aggregator's fee arithmetic — and everything the rest does
//! (discovery, correlation, durable state, the [`DepositPool`] contract) does not. The seam is
//! [`CurvySdkAdapter`], which is also what a test fakes to drive the pool without a chain.
//!
//! ## Where the money is
//!
//! A PIX deposit is a Curvy *allocation*: the Entry spends a note it owns in the shielded pool and
//! the aggregator emits a note owned by the SSA's Baby JubJub key, discoverable only by the Exit's
//! scan identity. Before any of that the Entry needs a note to spend, which is the **shield**:
//! wxHOPR moved into the pool through a deterministic entry portal.
//!
//! | movement | signed by | paid by |
//! |---|---|---|
//! | funding the shield portal | the node's connector (Safe module) | the **Safe** |
//! | deploying + shielding the portal, committing notes | operator key | the operator account (gas) |
//! | allocations (PIX deposits) | operator key | the shielded note (value), operator (gas) |
//! | sweep of a recovered allocation | the SSA key (proof), operator key (gas) | the note |
//!
//! The Safe funds the portal for the same reason the plain pool deposits from it: that is where
//! the node's PIX float lives. The pool itself never holds an EVM key of its own — the *funder*
//! is a callback built over the node's chain API — so the only EVM key it does hold is the
//! operator's, which the Curvy deployment requires for its role-gated calls anyway.
//!
//! The Curvy *spender* — the account that owns the shielded funding note and receives change — is
//! generated once per node and persisted alongside the rest of the state. It is not derived from
//! the node's chain key, which the pool does not have and does not need.
//!
//! ## Durability
//!
//! Every step that spends or commits something is recorded before it is submitted and reconciled
//! afterwards: a shield is resumable from `Prepared`/`Funded`, an allocation is idempotent per
//! [`PixAddressId`], and an aggregation whose outcome was lost marks the state *ambiguous* until
//! Blokli has indexed one of its outputs — the alternative is a double spend.
//! A rejected replay, forgotten request, or three inclusion timeouts without progress permit
//! replacement using the same inputs and allocations. Progress and timeout counts survive
//! restarts; authentication and rate-limit errors do not trigger replacement. Every uncertain
//! proof keeps its private outputs in the journal until a winner is finalized;
//! reaching the attempt limit pauses new proofs without evicting recovery data. Checking
//! deployment consistency only reads notes, while funding operations resolve these attempts.
//! Finality checks take one snapshot at most every five seconds, returning between checks so
//! the pool can wait without holding the chain lock. An unavailable checkpoint is explicit.
//!
//! [`DepositPool`]: hopr_api::chain::DepositPool

use std::{fmt::Write, str::FromStr, sync::Arc};

use async_trait::async_trait;
use blokli_client::api::BlokliQueryClient;
use curvy_core::{
    eddsa::ScalarSigningKey,
    field::{Bn254Fr, Fr, fr_to_be_32, fr_to_biguint, fr_to_dec},
    stealth,
};
use curvy_sdk::{
    Account, CircuitFamily, CircuitRef, CurvyClient, Identity, OwnedNote, PreparedDeposit, PreparedDirectShield, Route,
    ScanRecipient, TxLedger, ViewerIdentity,
};
use curvy_types::OnchainNote;
use futures::future::BoxFuture;
use hopr_api::{
    node::PixAddressId,
    types::{
        chain::prelude::{CurvyErc777Payload, CurvyNote, Erc777Payload},
        crypto::prelude::{BjjPublicKey, CurvyScanPublicKey},
        primitive::prelude::{Address, BytesRepresentable, HoprBalance, U256},
    },
};
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};

use super::{
    CommittedCurvyNote, CurvyNoteSource, CurvyShielding, CurvySubmission, CurvyWithdrawalOutcome, Url,
    detect::{bjj_point, scan_public_key_dec},
    indexer,
    relayer::{self, RelayClient},
    state::{RedbCurvyDepositState, SPENDER_AAD, id_bytes},
    token::VaultToken,
};
use crate::pix::store::sealed::Sealer;

const SDK_STATE_TABLE: TableDefinition<u8, Vec<u8>> = TableDefinition::new("curvy_pix_sdk_state");
const SDK_STATE_KEY: u8 = 0;
const SDK_ALLOCATIONS_TABLE: TableDefinition<[u8; PixAddressId::SIZE], Vec<u8>> =
    TableDefinition::new("curvy_pix_sdk_allocations");
/// Verifier profile `(2, 9)`: nine regular outputs, one reserved for change.
const MAX_ALLOCATIONS_PER_PROOF: usize = 7;
/// The pending-commitment circuit's batch: the most note ids one commit proof takes.
const MAX_COMMITMENTS_PER_PROOF: usize = curvy_sdk::MAX_COMMIT_NOTES;
/// The PIX withdrawal profile takes at most ten notes.
const MAX_WITHDRAWAL_INPUTS: usize = 10;
/// An aggregation spends one or two committed input notes.
const MAX_ALLOCATION_INPUTS: usize = 2;
/// How many times, and how far apart, to look for a confirmed direct shield's note.
const DIRECT_SHIELD_OBSERVATIONS: usize = 3;
const DIRECT_SHIELD_OBSERVATION_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
/// Search budget for an exact whole-note withdrawal; see `select_notes`.
/// The default of `CurvyDepositPoolConfig::direct_shield_settle_grace`: three minutes, the
/// operator's allowance for Gnosis finality; see there for the trade-off.
pub(super) const DEFAULT_SHIELD_SETTLE_GRACE: std::time::Duration = std::time::Duration::from_secs(180);
const MAX_NOTE_SELECTION_STEPS: usize = 1 << 16;
/// Never evict an uncertain proof to make room: its private outputs may still be needed.
const MAX_RELAY_AGGREGATION_ATTEMPTS: usize = 8;
/// Three full inclusion waits without observed progress permit a replacement on the next call.
const MAX_RELAY_TIMEOUTS_WITHOUT_PROGRESS: u8 = 3;
/// A finality check runs once per call, with backoff between full snapshots.
const RELAY_FINALITY_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
const RELAY_FINALITY_CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Transfers `amount` of wxHOPR to a shield portal, resolving once the transfer is confirmed.
///
/// Built by the pool over the node's chain API — see the module docs for why the Safe pays.
///
/// Answers like a [`DirectShielder`], and for the same reason: whether the transfer was broadcast is
/// known only when its confirmation arrives, and the journal needs to tell a refusal from a lost
/// answer. A [`Confirmed`] is a transfer that took effect.
pub type PortalFunder =
    Arc<dyn Fn(Address, HoprBalance) -> BoxFuture<'static, Result<Confirmed, ShieldFailure>> + Send + Sync>;

/// Performs a direct shield on behalf of the account that holds the float.
///
/// Takes the shield router's ERC-777 payload plus the router, and is responsible for making the
/// `send` originate from the fund-holding account — the node's Safe. A callback rather than a
/// method so the pool keeps no chain key of its own and the SDK bridge stays ignorant of how the
/// Safe is driven.
///
/// Arguments: the payload (the aggregator and the note the router shields), the shield router to
/// `send` it to, and the gross amount.
///
/// One future for the whole of it, because the connector only enqueues a transaction when it is
/// handed over: whether it is broadcast — every refusal before that, by Blokli or by the RPC node —
/// is known only when the confirmation arrives. The outcome is therefore a [`ShieldFailure`], which
/// says what the Safe's float is left in, or [`Confirmed`].
///
/// A confirmation is a shield that took effect: the connector turns a failed inner call of the
/// Safe into an error ([`ShieldFailure::Reverted`]), so a [`Confirmed`] whose note the aggregator
/// does not know yet is the aggregator lagging, not a failed shield.
pub type DirectShielder =
    Arc<dyn Fn(Erc777Payload, Address, u128) -> BoxFuture<'static, Result<Confirmed, ShieldFailure>> + Send + Sync>;

/// A shield's transaction — a direct shield, or the Safe's transfer to a portal — confirmed on chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Confirmed {
    /// The transaction hash.
    pub tx: String,
}

/// How a shield's transaction failed, as far as the float is concerned.
#[derive(Debug, thiserror::Error)]
pub enum ShieldFailure {
    /// Refused before anything was broadcast: nothing moved and no nonce was consumed.
    #[error("{0}")]
    NotSubmitted(String),
    /// Rejected by the chain, or the Safe's inner call failed: the float did not move.
    #[error("{reason}")]
    Reverted { reason: String },
    /// No answer — a tracking timeout, a transport failure: the transaction may have been
    /// broadcast, and may still land.
    #[error("{0}")]
    Unconfirmed(String),
}

/// What one allocation can draw on from funding notes listed largest first: the sum of the
/// largest [`MAX_ALLOCATION_INPUTS`] of them. Shared by the allocation, which selects those notes,
/// and the balance, which reports what they hold.
fn spendable_total(largest_first: impl IntoIterator<Item = u128>) -> Result<u128, RsSdkCurvyAdapterError> {
    largest_first
        .into_iter()
        .take(MAX_ALLOCATION_INPUTS)
        .try_fold(0_u128, |total, amount| {
            total
                .checked_add(amount)
                .ok_or_else(|| RsSdkCurvyAdapterError::InvalidValue("funding total overflows u128".to_owned()))
        })
}

/// A Unix time for a message, which may be unknown.
fn unix_time(time: Option<u64>) -> String {
    time.map_or_else(|| "an unknown time".to_owned(), |time| format!("{time} (Unix seconds)"))
}

/// Seconds since the Unix epoch, or `None` when the clock is not usable (set before the epoch).
pub(super) fn unix_now() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

/// The spends whose outcome is not settled yet — every relayed attempt, every operator attempt and
/// the ambiguous allocation — as their inputs and the change they journal. Only a journal written
/// by an earlier version can still carry an ambiguous set: nothing writes one now, and the
/// reconciliation only clears it, but such a journal must still be read as it was meant. Their inputs stay in
/// `funding` at full value until the outcome is observed.
fn in_flight_spends(state: &SdkState) -> Vec<(&[StoredNote], &StoredNote)> {
    state
        .relay_aggregations
        .iter()
        .map(|attempt| (attempt.inputs.as_slice(), &attempt.change))
        .chain(
            state
                .operator_aggregations
                .iter()
                .map(|attempt| (attempt.inputs.as_slice(), &attempt.change)),
        )
        .chain(
            state
                .ambiguous_change
                .as_ref()
                .filter(|_| state.ambiguous_allocation && !state.ambiguous_inputs.is_empty())
                .map(|change| (state.ambiguous_inputs.as_slice(), change)),
        )
        .collect()
}

/// Which in-flight shield a journal write is for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShieldJournal {
    /// The direct shield, through the shield router.
    Direct,
    /// The portal shield, whose Safe transaction funds the portal.
    Portal,
}

/// Records how far the Safe's transaction for the in-flight shield got. Never the stage: a
/// confirmation can be of a transaction whose inner transfer failed, when Blokli omits the Safe's
/// execution result, so only a balance read decides that a portal is funded.
fn journal_submission(
    state: &parking_lot::Mutex<SdkState>,
    store: &RedbCurvySdkStore,
    journal: ShieldJournal,
    submission: ShieldSubmission,
) -> Result<(), RsSdkCurvyAdapterError> {
    let mut state = state.lock();
    match journal {
        ShieldJournal::Direct => {
            if let Some(in_flight) = state.direct_shield_in_flight.as_mut() {
                in_flight.submission = submission;
            }
        }
        ShieldJournal::Portal => {
            if let Some(in_flight) = state.shield_in_flight.as_mut() {
                in_flight.submission = submission;
            }
        }
    }
    store.save(&state)
}

/// Runs the Safe's transaction between the journal writes that bracket it: `Unknown` from `since`
/// before, so that a crash or a dropped caller inside reads as "handed to the chain at `since`",
/// and what the outcome shows after. Run in a task of its own, so that nothing can stop it between
/// the two.
async fn shield_journalled(
    state: &parking_lot::Mutex<SdkState>,
    store: &RedbCurvySdkStore,
    journal: ShieldJournal,
    shield: BoxFuture<'static, Result<Confirmed, ShieldFailure>>,
) -> Result<(Result<Confirmed, ShieldFailure>, Option<u64>), RsSdkCurvyAdapterError> {
    journal_submission(state, store, journal, ShieldSubmission::Unknown { since: unix_now() })?;
    let outcome = shield.await;
    // When the outcome arrived, not when the call began: the sequencer's queue and the connector's
    // tracking window come before it, and a grace measured from the call would have spent them.
    let at = unix_now();
    match &outcome {
        Ok(confirmed) => journal_submission(
            state,
            store,
            journal,
            ShieldSubmission::Submitted {
                tx: confirmed.tx.clone(),
                at,
            },
        )?,
        // The float did not move: the next funding sends.
        Err(ShieldFailure::NotSubmitted(_) | ShieldFailure::Reverted { .. }) => {
            journal_submission(state, store, journal, ShieldSubmission::NotSubmitted)?
        }
        // It may have been broadcast: unknown from now, which is what the grace runs from.
        Err(ShieldFailure::Unconfirmed(_)) => {
            journal_submission(state, store, journal, ShieldSubmission::Unknown { since: at })?
        }
    }
    Ok((outcome, at))
}

/// The one stage transition of a portal shield: the portal is funded. Called only once a balance
/// read has shown the portal holding the shield's amount.
fn journal_portal_funded(
    state: &parking_lot::Mutex<SdkState>,
    store: &RedbCurvySdkStore,
) -> Result<(), RsSdkCurvyAdapterError> {
    let mut state = state.lock();
    if let Some(in_flight) = state.shield_in_flight.as_mut() {
        in_flight.stage = StoredShieldStage::Funded;
    }
    store.save(&state)
}

/// The shield router's ERC-777 payload for a direct shield: `abi.encode(aggregator, note)`, with
/// the note as the aggregator's `directShield` takes it, carrying the gross amount.
fn direct_shield_payload(aggregator: Address, note: &OnchainNote) -> Result<Erc777Payload, RsSdkCurvyAdapterError> {
    let word = |name: &str, value: &str| {
        U256::from_dec_str(value).map_err(|error| RsSdkCurvyAdapterError::InvalidValue(format!("note {name}: {error}")))
    };
    Ok(Erc777Payload::Curvy(CurvyErc777Payload::DirectShield {
        aggregator,
        note: CurvyNote {
            owner_hash: word("owner hash", &note.owner_hash)?,
            token: word("token", &note.token)?,
            amount: word("amount", &note.amount)?,
            ephemeral_key: [
                word("ephemeral key[0]", &note.ephemeral_key[0])?,
                word("ephemeral key[1]", &note.ephemeral_key[1])?,
            ],
            view_tag: u16::try_from(note.view_tag)
                .map_err(|_| RsSdkCurvyAdapterError::InvalidValue(format!("note view tag: {}", note.view_tag)))?,
        },
    }))
}

/// Curvy chain operations that require SDK knowledge.
///
/// The pool owns note retrieval, durable note state, cursors, correlation and the
/// [`DepositPool`](hopr_api::chain::DepositPool) behaviour. Proof generation and contract payload
/// construction are delegated to the Curvy SDK through this narrow adapter.
#[async_trait]
pub trait CurvySdkAdapter: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Shields `gross` wxHOPR from the Safe into the pool's funding, adding to whatever is there;
    /// `recovery_address` is the portal's recovery address where a portal is used.
    ///
    /// Crash-resumable, not idempotent: an interrupted shield is resumed rather than started
    /// again, with the amount (and recovery address) it was journalled with — the arguments only
    /// size a new shield, so a changed amount cannot wedge funding — but once a shield has landed
    /// and been journalled, the next call shields again. A direct shield whose Safe
    /// transaction was handed to the chain without an answer is looked for on every call and sent
    /// again only after a grace, failing as settling until then. An error after
    /// the note is journalled — committing it did not go through — is not one, so that a retry
    /// cannot shield twice for one failure.
    async fn fund(&self, gross: HoprBalance, recovery_address: Address) -> Result<(), Self::Error>;

    /// What one allocation can draw on from the pool's funding notes, as the pool's own ledger
    /// has them, net of allocations.
    ///
    /// An allocation spends at most two committed notes, so this is the sum of the largest ones,
    /// not of every note: funding left in many small notes cannot pay one deposit, and reporting
    /// its total would stop a top-up that is needed.
    ///
    /// A note counts from the moment its shield is journalled, before it is committed and
    /// spendable, so what is reported can run ahead of what an allocation can draw on right now.
    /// A spend still in flight — an aggregation whose outcome is not observed yet, under either
    /// submission mode — counts for what the next allocation will find once it settles: its inputs
    /// are out and its journalled change is in. With several attempts at the same spend that is
    /// the smallest change, which every one of them leaves at least.
    async fn available_balance(&self) -> Result<HoprBalance, Self::Error>;

    /// Allocates the given amounts to the given Baby JubJub owners, each discoverable by its scan
    /// identity. Succeeds or fails as a whole per proof.
    async fn allocate(
        &self,
        deposits: Vec<(PixAddressId, BjjPublicKey, CurvyScanPublicKey, HoprBalance)>,
    ) -> Result<(), Self::Error>;

    /// Withdraws committed notes owned by the recovered PIX secret to `dst`.
    async fn withdraw(
        &self,
        secret: &ScalarSigningKey,
        notes: Vec<CommittedCurvyNote>,
        dst: Address,
        amount: Option<HoprBalance>,
    ) -> Result<CurvyWithdrawalOutcome, Self::Error>;

    /// Whether the chain still knows the notes this adapter believes it owns.
    ///
    /// `false` can mean the endpoint is behind. It never authorizes discarding recovery state.
    async fn chain_state_is_consistent(&self) -> Result<bool, Self::Error>;

    /// Discards everything chain-specific, keeping only the node's Curvy identity.
    fn reset_chain_state(&self) -> Result<(), Self::Error>;
}

/// Runtime configuration for the rs-sdk allocation and withdrawal bridge.
pub struct RsSdkCurvyAdapterConfig {
    /// Curvy operator EVM key: role-gated portal deployment and pending-note commitment, and the
    /// submitter of allocation and withdrawal calls.
    ///
    /// Required for operator submission or portal shielding. Empty only when direct shielding
    /// is paired with relayed proof submission.
    pub operator_private_key: String,
    /// Token identifier used by all pool notes: stated, or resolved through Blokli on first use.
    pub token: VaultToken,
    /// Transaction route for locally-submitted calls. Production should use [`Route::Blokli`].
    ///
    /// Orthogonal to [`Self::submission`]: this picks *how* a self-submitted transaction reaches
    /// the chain, while `submission` decides whether this node submits at all.
    pub route: Route,
    /// The protocol fee collector, required when the aggregator charges a non-zero fee. Unset,
    /// the collector the gateway publishes at `/protocol` is used under relayed submission.
    pub fee_recipient: Option<Identity>,
    /// How the float is moved into the vault. See [`CurvyShielding`].
    pub shielding: CurvyShielding,
    /// Who puts proofs on chain, and therefore who commits pending notes. See
    /// [`CurvySubmission`].
    pub submission: CurvySubmission,
    /// Base URL of the Curvy relayer, required under [`CurvySubmission::Relayer`].
    pub relayer_url: Option<Url>,
    /// How long to wait for a relayed submission to reach the chain. Three completed waits
    /// without a new status or transaction hash permit an aggregation replacement.
    pub relay_timeout: std::time::Duration,
    /// Where the SDK reads notes from when it rebuilds the committed-notes tree. See
    /// [`CurvyNoteSource`].
    pub note_source: CurvyNoteSource,
    /// Curvy's shared indexer, required under [`CurvyNoteSource::CurvyIndexer`].
    pub curvy_indexer_url: Option<Url>,
    /// How long a direct shield whose outcome is unknown is waited for before it is sent again.
    /// See `CurvyDepositPoolConfig::direct_shield_settle_grace`.
    pub direct_shield_settle_grace: std::time::Duration,
}

impl RsSdkCurvyAdapterConfig {
    /// Self-submitting configuration: portal shielding, proofs signed with `operator_private_key`.
    ///
    /// This is what the localcluster runs, and what every caller got before the modes existed.
    pub fn new(operator_private_key: String, token: impl Into<VaultToken>) -> Self {
        Self {
            operator_private_key,
            token: token.into(),
            route: Route::Blokli,
            fee_recipient: None,
            shielding: CurvyShielding::Portal,
            submission: CurvySubmission::Operator,
            relayer_url: None,
            relay_timeout: std::time::Duration::from_secs(120),
            note_source: CurvyNoteSource::Blokli,
            curvy_indexer_url: None,
            direct_shield_settle_grace: DEFAULT_SHIELD_SETTLE_GRACE,
        }
    }

    /// Sets how long a direct shield of unknown outcome is waited for before it is sent again.
    pub fn with_direct_shield_settle_grace(mut self, grace: std::time::Duration) -> Self {
        self.direct_shield_settle_grace = grace;
        self
    }

    /// Applies the pool's configured modes.
    /// Selects where the SDK reads notes from; `curvy_indexer_url` is required for
    /// [`CurvyNoteSource::CurvyIndexer`] and validated by the pool before this is reached.
    pub fn with_note_source(mut self, note_source: CurvyNoteSource, curvy_indexer_url: Option<Url>) -> Self {
        self.note_source = note_source;
        self.curvy_indexer_url = curvy_indexer_url;
        self
    }

    pub fn with_modes(
        mut self,
        shielding: CurvyShielding,
        submission: CurvySubmission,
        relayer_url: Option<Url>,
    ) -> Self {
        self.shielding = shielding;
        self.submission = submission;
        self.relayer_url = relayer_url;
        self
    }

    fn validate_signer(&self) -> Result<(), RsSdkCurvyAdapterError> {
        if self.submission == CurvySubmission::Operator || self.shielding == CurvyShielding::Portal {
            curvy_abi::address_of(&self.operator_private_key).map_err(|_| {
                RsSdkCurvyAdapterError::InvalidValue(
                    "a valid EVM signing key is required for operator submission or portal shielding".to_owned(),
                )
            })?;
        }
        Ok(())
    }

    /// Whether this node commits its own pending notes.
    ///
    /// Only when it submits its own proofs. Under [`CurvySubmission::Relayer`] the deployment's
    /// shared batch-prover commits, and the relayer refuses `commitPendingNotes` anyway.
    pub fn commits_locally(&self) -> bool {
        self.submission == CurvySubmission::Operator
    }
}

/// Errors raised by the rs-sdk bridge.
#[derive(Debug, thiserror::Error)]
pub enum RsSdkCurvyAdapterError {
    #[error(transparent)]
    Sdk(#[from] anyhow::Error),
    #[error(transparent)]
    Relay(#[from] relayer::RelayError),
    #[error(
        "a legacy relayer aggregation lacks saved output notes; preserve this database and recover its intent before \
         spending"
    )]
    IncompleteRelayRecovery,
    #[error("invalid Curvy adapter value: {0}")]
    InvalidValue(String),
    /// No committed note can fund the request.
    ///
    /// Raised before this item's aggregation is built, so it proves that item moved no funds.
    /// When an earlier chunk of the same call already submitted one, [`Self::AfterSubmission`] is
    /// used instead, because then the *call* moved funds even though this item did not.
    #[error("the private pool has no committed note large enough to fund {required} wei")]
    NoFunding { required: u128 },
    /// A failure raised after an aggregation in the same call was submitted, so it does not prove
    /// the call moved no funds.
    ///
    /// `out_of_funding` keeps the exhaustion meaning of a tagged [`Self::NoFunding`], so a pool
    /// running dry is still recognisable by [`super::is_out_of_funding`] after an earlier chunk
    /// submitted.
    #[error("Curvy allocation failed after an earlier chunk was submitted: {source}")]
    AfterSubmission {
        source: anyhow::Error,
        out_of_funding: bool,
    },
    #[error("the requested withdrawal is {requested}, but only {available} is stored")]
    InsufficientNotes { requested: u128, available: u128 },
    #[error(
        "the requested withdrawal is {requested}, but the selected whole notes total {selected}; Curvy cannot produce \
         change"
    )]
    InexactWithdrawal { requested: u128, selected: u128 },
    #[error("PIX allocation ID was reused with a different address, scan identity, or amount")]
    ConflictingAllocation,
    #[error("an earlier Curvy allocation has an ambiguous outcome and must be reconciled")]
    AmbiguousAllocation,
    #[error(
        "Curvy aggregation has {MAX_RELAY_AGGREGATION_ATTEMPTS} unresolved attempts; waiting for an existing attempt \
         to settle"
    )]
    RelayAttemptLimit,
    #[error("waiting for the winning Curvy aggregation outputs to become finalized; all attempts are retained")]
    RelayFinalityPending,
    #[error("cannot confirm Curvy aggregation finality: {0}; all attempts are retained")]
    RelayFinalityUnavailable(String),
    #[error(
        "the shield of {gross} base units (note {note}) was handed to the chain at {} and has not shown yet (the \
         Curvy aggregator does not know its note, or the portal holds no funds); it is looked for again on the next \
         funding, and sent again if it has not shown by {}",
        unix_time(*since),
        unix_time(*resend_after)
    )]
    ShieldSettling {
        note: String,
        gross: u128,
        since: Option<u64>,
        resend_after: Option<u64>,
    },
    #[error(
        "the shield of {gross} base units (note {note}) confirmed in transaction {tx}, but it has not shown yet (the \
         Curvy aggregator has not indexed its note, or the portal's balance is read from behind); it is not sent \
         again within the grace, which ends at {}, and is looked for again on the next funding",
        unix_time(*resend_after)
    )]
    ShieldConfirmedUnindexed {
        note: String,
        gross: u128,
        tx: String,
        /// When the grace ends: what a caller that waits for the shield to show must not outlast.
        resend_after: Option<u64>,
    },
    #[error(
        "the Curvy shield portal {portal} contains {actual} base units instead of the expected {required}; check its \
         balance and the transactions that funded it: the portal's recovery address can reclaim what it holds"
    )]
    UnexpectedShieldFunding {
        portal: String,
        actual: u128,
        required: u128,
    },
    #[error(
        "the Safe's transfer of {gross} base units to the Curvy shield portal {portal} has not shown within the \
         grace (transaction {}, handed to the chain at {}), and is not sent again, since the first copy may still \
         land and a portal holding twice the amount cannot be shielded: check the portal's balance and the \
         transaction; the portal's recovery address can reclaim a portal's funds",
        tx.as_deref().unwrap_or("unknown"),
        unix_time(*since)
    )]
    PortalFundingUnresolved {
        portal: String,
        gross: u128,
        tx: Option<String>,
        since: Option<u64>,
    },
    #[error("funding the Curvy shield portal from the Safe failed: {0}")]
    Funding(String),
    #[error("Blokli does not expose the Curvy deployment: {0}")]
    Discovery(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct StoredNote {
    owner_pub: [String; 2],
    shared_secret: String,
    ephemeral_key: [String; 2],
    view_tag: u16,
    amount: String,
    token: String,
}

impl From<&OwnedNote> for StoredNote {
    fn from(note: &OwnedNote) -> Self {
        Self {
            owner_pub: [fr_to_dec(&note.owner_pub.0), fr_to_dec(&note.owner_pub.1)],
            shared_secret: fr_to_dec(&note.shared_secret),
            ephemeral_key: [fr_to_dec(&note.ephemeral_key.0), fr_to_dec(&note.ephemeral_key.1)],
            view_tag: note.view_tag,
            amount: fr_to_dec(&note.amount),
            token: fr_to_dec(&note.token),
        }
    }
}

impl TryFrom<&StoredNote> for OwnedNote {
    type Error = RsSdkCurvyAdapterError;

    fn try_from(note: &StoredNote) -> Result<Self, Self::Error> {
        let field = |value: &str, name: &str| {
            Bn254Fr::try_from_dec(value)
                .map(Bn254Fr::into_inner)
                .map_err(|error| RsSdkCurvyAdapterError::InvalidValue(format!("{name}: {error}")))
        };
        Ok(Self {
            owner_pub: (
                field(&note.owner_pub[0], "owner x")?,
                field(&note.owner_pub[1], "owner y")?,
            ),
            shared_secret: field(&note.shared_secret, "shared secret")?,
            ephemeral_key: (
                field(&note.ephemeral_key[0], "ephemeral x")?,
                field(&note.ephemeral_key[1], "ephemeral y")?,
            ),
            view_tag: note.view_tag,
            amount: field(&note.amount, "amount")?,
            token: field(&note.token, "token")?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum StoredShieldStage {
    Prepared,
    Funded,
}

/// A relayer submission whose outcome is not yet known.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct StoredRelayIntent {
    intent: String,
    action: String,
    /// What the submission spends, so a resolved intent can be matched to its allocations.
    spend_key: String,
}

/// Everything needed to replay the same proof and recover its private change after a crash.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredRelayAggregation {
    intent: String,
    chain_id: u64,
    aggregator: String,
    max_inputs: usize,
    proof: curvy_abi::curvy_types::Groth16Proof,
    /// The calldata words the proof is bound to, sent as the relayer's `publicSignals`. The
    /// relayer recomputes the proof's commitment from them, so it is not journalled.
    public_signals: Vec<String>,
    request_key: String,
    spend_key: String,
    inputs: Vec<StoredNote>,
    change: StoredNote,
    emitted: Vec<StoredNote>,
    allocation_ids: Vec<[u8; PixAddressId::SIZE]>,
    /// Written before POST. Only a first-attempt rejection can safely release the inputs.
    attempted: bool,
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    transaction_hash: Option<String>,
    /// A rejected, forgotten or stalled request needs a fresh proof, but an earlier POST may still land.
    #[serde(default)]
    rebuild: bool,
    #[serde(default)]
    last_status: Option<relayer::RelayStatus>,
    #[serde(default)]
    timeouts_without_progress: u8,
    /// The circuit family version the proof was made for. Records written before circuit versions
    /// load as `None`; the aggregator refuses their proofs.
    #[serde(default)]
    circuit: Option<CircuitRef>,
}

impl StoredRelayAggregation {
    fn observe_progress(&mut self, status: relayer::RelayStatus, transaction_hash: Option<String>) {
        if self.last_status != Some(status)
            || transaction_hash
                .as_ref()
                .is_some_and(|hash| Some(hash) != self.transaction_hash.as_ref())
        {
            self.timeouts_without_progress = 0;
        }
        self.last_status = Some(status);
        self.transaction_hash = transaction_hash.or(self.transaction_hash.take());
    }
}

/// Accept the single-attempt journal written by earlier versions, including `null`.
fn deserialize_relay_aggregations<'de, D>(deserializer: D) -> Result<Vec<StoredRelayAggregation>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Journal {
        Attempts(Vec<StoredRelayAggregation>),
        Legacy(Option<Box<StoredRelayAggregation>>),
    }
    Ok(match Journal::deserialize(deserializer)? {
        Journal::Attempts(attempts) => attempts,
        Journal::Legacy(attempt) => attempt.into_iter().map(|attempt| *attempt).collect(),
    })
}

/// One self-submitted aggregation, journalled with its private outputs before broadcast.
///
/// The operator path's counterpart to [`StoredRelayAggregation`]. Every attempt for one logical
/// spend uses the same inputs and allocations, so the nullifiers let at most one of them land;
/// the journal keeps each attempt's change and emitted notes until the winner is known, because
/// until then any of them may be the one whose secrets are needed.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredOperatorAggregation {
    chain_id: u64,
    aggregator: String,
    inputs: Vec<StoredNote>,
    change: StoredNote,
    emitted: Vec<StoredNote>,
    allocation_ids: Vec<[u8; PixAddressId::SIZE]>,
}

#[derive(Debug)]
struct RelayAggregationOutcome {
    request_id: Option<String>,
    transaction_hash: Option<String>,
    allocations: usize,
}

/// A direct shield in flight.
///
/// Fewer stages than [`StoredShield`]: nothing is funded ahead of time, so there is no
/// funded-but-not-shielded window to resume from. The record exists so that a crash between
/// submitting and observing the note does not shield twice — the note id is checked against the
/// chain before a resubmission.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredDirectShield {
    note: StoredNote,
    gross: String,
    /// How far the Safe's transaction got; see [`ShieldSubmission`].
    #[serde(default)]
    submission: ShieldSubmission,
}

/// What the journal knows of the Safe's transaction for a direct shield in flight.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum ShieldSubmission {
    /// Not known: handed to the chain at `since` (Unix seconds) with no outcome recorded, or from a
    /// journal that predates this record, where `since` is unknown. Resumed by looking at the chain
    /// first; if the note is not there, the transaction is given `direct_shield_settle_grace` from
    /// `since` to land before it is sent again.
    Unknown {
        #[serde(default)]
        since: Option<u64>,
    },
    /// Refused before it was broadcast, or rejected by the chain: the float did not move, and
    /// sending is safe.
    NotSubmitted,
    /// Confirmed on chain at `at` (Unix seconds), which means the Safe's inner call succeeded: the
    /// shield took effect, and it is not sent again while the aggregator may still be indexing its
    /// note — for `direct_shield_settle_grace` from `at`. That bound exists because the connector
    /// reports a failed inner call only when Blokli fills in the Safe's execution result; without
    /// it, a failed shield looks confirmed and its note never appears. Past the grace, or with no
    /// `at` (a journal from before it was recorded), the shield is treated as a failed inner call
    /// and sent again.
    Submitted {
        tx: String,
        #[serde(default)]
        at: Option<u64>,
    },
}

impl Default for ShieldSubmission {
    fn default() -> Self {
        Self::Unknown { since: None }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredShield {
    note: StoredNote,
    gross: String,
    recovery: String,
    portal_address: String,
    stage: StoredShieldStage,
    /// How far the Safe's transfer to the portal got, which a pre-upgrade journal reads as
    /// unknown; see [`ShieldSubmission`], whose rules apply with "the portal holds `gross`" in
    /// place of "the aggregator knows the note".
    #[serde(default)]
    submission: ShieldSubmission,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum StoredAllocationStage {
    Prepared,
    Completed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct StoredAllocation {
    id: [u8; PixAddressId::SIZE],
    address: [u8; 32],
    #[serde(default)]
    scan_key: Vec<u8>,
    amount: String,
    stage: StoredAllocationStage,
}

impl StoredAllocation {
    fn recipient(
        address: &BjjPublicKey,
        scan_key: CurvyScanPublicKey,
    ) -> Result<ScanRecipient, RsSdkCurvyAdapterError> {
        let owner = bjj_point(address).map_err(|error| RsSdkCurvyAdapterError::InvalidValue(error.to_owned()))?;
        // Curvy addresses the recipient by affine coordinates, so both compressed
        // halves of the advertised scan identity are decompressed here.
        let (big_k, big_v) = scan_public_key_dec(&scan_key).map_err(RsSdkCurvyAdapterError::InvalidValue)?;
        let viewer = ViewerIdentity::new(big_k, big_v)?;
        Ok(ScanRecipient::new(viewer, owner.as_tuple()))
    }

    /// The same recipient and base-unit amount passed to the original aggregation prover.
    fn prover_allocation(&self) -> Result<(ScanRecipient, u128), RsSdkCurvyAdapterError> {
        let address = BjjPublicKey::try_from(self.address.as_slice())
            .map_err(|error| RsSdkCurvyAdapterError::InvalidValue(error.to_string()))?;
        let scan_key = CurvyScanPublicKey::try_from(self.scan_key.as_slice())
            .map_err(|error| RsSdkCurvyAdapterError::InvalidValue(error.to_string()))?;
        let amount = self
            .amount
            .parse::<u128>()
            .map_err(|error| RsSdkCurvyAdapterError::InvalidValue(error.to_string()))?;
        Ok((Self::recipient(&address, scan_key)?, amount))
    }

    fn new(
        id: PixAddressId,
        address: &BjjPublicKey,
        scan_key: CurvyScanPublicKey,
        amount: HoprBalance,
    ) -> Result<Self, RsSdkCurvyAdapterError> {
        let scan_key: [u8; hopr_api::types::crypto::prelude::CURVY_SCAN_PUBLIC_KEY_SIZE] = scan_key.into();
        Ok(Self {
            id: id_bytes(&id),
            address: address
                .as_ref()
                .try_into()
                .map_err(|_| RsSdkCurvyAdapterError::InvalidValue("BJJ address must be 32 bytes".to_owned()))?,
            scan_key: scan_key.to_vec(),
            amount: amount.amount().to_string(),
            stage: StoredAllocationStage::Prepared,
        })
    }

    fn matches(&self, address: &BjjPublicKey, scan_key: CurvyScanPublicKey, amount: HoprBalance) -> bool {
        let scan_key: [u8; hopr_api::types::crypto::prelude::CURVY_SCAN_PUBLIC_KEY_SIZE] = scan_key.into();
        self.address.as_slice() == address.as_ref()
            && self.scan_key == scan_key
            && self.amount == amount.amount().to_string()
    }
}

impl StoredShield {
    fn prepared(&self) -> Result<PreparedDeposit, RsSdkCurvyAdapterError> {
        let gross = self
            .gross
            .parse()
            .map_err(|error| RsSdkCurvyAdapterError::InvalidValue(format!("shield gross: {error}")))?;
        Ok(PreparedDeposit::from_recovery_parts(
            OwnedNote::try_from(&self.note)?,
            gross,
            self.recovery.clone(),
            self.portal_address.clone(),
        ))
    }
}

/// The node's Curvy identity: the stealth private keys `(k, v)` the spender account is derived
/// from. Generated once, then persisted.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredSpender {
    k: String,
    v: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SdkState {
    /// The spender identity, sealed under the PIX recovery password: hex of what
    /// [`RedbCurvySdkStore::set_spender`] produced. Read through [`RedbCurvySdkStore::spender`].
    #[serde(default)]
    sealed_spender: Option<String>,
    /// Read only for the atomic migration of databases written while the identity was stored in
    /// the clear; [`RedbCurvySdkStore::load`] seals it and the clear copy is never written again.
    #[serde(default, rename = "spender", skip_serializing)]
    legacy_spender: Option<StoredSpender>,
    funding: Vec<StoredNote>,
    /// Emitted notes that must be committed before their change can fund another allocation.
    pending: Vec<StoredNote>,
    /// Set after an ambiguous aggregation to prevent accidental double spending.
    ambiguous_allocation: bool,
    #[serde(default)]
    ambiguous_inputs: Vec<StoredNote>,
    #[serde(default)]
    ambiguous_change: Option<StoredNote>,
    #[serde(default)]
    ambiguous_emitted: Vec<StoredNote>,
    #[serde(default)]
    shield_in_flight: Option<StoredShield>,
    #[serde(default)]
    direct_shield_in_flight: Option<StoredDirectShield>,
    /// Relayer submissions whose outcome we have not confirmed, keyed by our own intent id.
    ///
    /// Written *before* the submission is sent, which is what makes a lost response
    /// recoverable: the relayer can be asked what became of an intent it may never have
    /// received, where a `requestId` we never saw would tell us nothing.
    #[serde(default)]
    relay_intents: Vec<StoredRelayIntent>,
    /// Competing proofs for one logical spend, all using the same inputs and allocations.
    #[serde(
        default,
        alias = "relay_aggregation",
        deserialize_with = "deserialize_relay_aggregations"
    )]
    relay_aggregations: Vec<StoredRelayAggregation>,
    /// Read only for atomic migration of databases written before the keyed table.
    #[serde(default, rename = "allocations", skip_serializing)]
    legacy_allocations: Vec<StoredAllocation>,
    #[serde(default)]
    ambiguous_allocation_ids: Vec<[u8; PixAddressId::SIZE]>,
    /// Self-submitted aggregations whose outcome is not yet known; see
    /// [`StoredOperatorAggregation`].
    #[serde(default)]
    operator_aggregations: Vec<StoredOperatorAggregation>,
}

#[derive(Clone)]
struct RedbCurvySdkStore {
    db: Arc<redb::Database>,
    sealer: Sealer,
}

impl RedbCurvySdkStore {
    fn new(state: &RedbCurvyDepositState) -> Result<Self, RsSdkCurvyAdapterError> {
        let db = state.shared_database();
        let write = db.begin_write().map_err(db_error)?;
        write.open_table(SDK_STATE_TABLE).map_err(db_error)?;
        write.open_table(SDK_ALLOCATIONS_TABLE).map_err(db_error)?;
        write.commit().map_err(db_error)?;
        Ok(Self {
            db,
            sealer: state.sealer(),
        })
    }

    /// The spender identity `state` carries, opened; `None` until one was generated.
    fn spender(&self, state: &SdkState) -> Result<Option<StoredSpender>, RsSdkCurvyAdapterError> {
        state
            .sealed_spender
            .as_deref()
            .map(|sealed| {
                let sealed = const_hex::decode(sealed).map_err(|error| {
                    RsSdkCurvyAdapterError::InvalidValue(format!("sealed spender identity: {error}"))
                })?;
                let opened = self.sealer.open(SPENDER_AAD, &sealed).map_err(|error| {
                    RsSdkCurvyAdapterError::InvalidValue(format!("sealed spender identity: {error}"))
                })?;
                serde_json::from_slice(&opened)
                    .map_err(|error| RsSdkCurvyAdapterError::InvalidValue(format!("sealed spender identity: {error}")))
            })
            .transpose()
    }

    /// Seals `spender` into `state`; durable once `state` is saved.
    fn set_spender(&self, state: &mut SdkState, spender: &StoredSpender) -> Result<(), RsSdkCurvyAdapterError> {
        let encoded = serde_json::to_vec(spender).map_err(anyhow::Error::new)?;
        let sealed = self
            .sealer
            .seal(SPENDER_AAD, &encoded)
            .map_err(|error| RsSdkCurvyAdapterError::Sdk(anyhow::anyhow!("sealing the spender identity: {error}")))?;
        state.sealed_spender = Some(const_hex::encode(sealed));
        Ok(())
    }

    fn load(&self) -> Result<SdkState, RsSdkCurvyAdapterError> {
        let mut state: SdkState = {
            let read = self.db.begin_read().map_err(db_error)?;
            let table = read.open_table(SDK_STATE_TABLE).map_err(db_error)?;
            table
                .get(SDK_STATE_KEY)
                .map_err(db_error)?
                .map(|value| serde_json::from_slice(&value.value()).map_err(anyhow::Error::new))
                .transpose()?
                .unwrap_or_default()
        };
        let legacy = std::mem::take(&mut state.legacy_allocations);
        let legacy_spender = std::mem::take(&mut state.legacy_spender);
        if let Some(spender) = &legacy_spender
            && state.sealed_spender.is_none()
        {
            self.set_spender(&mut state, spender)?;
        }
        if !legacy.is_empty() || legacy_spender.is_some() {
            // The records, the sealed identity and the removal of the clear copies become
            // durable together. "Removal" from the live state only: the pages the clear
            // identity sat in are freed, not overwritten (see the `state` module docs).
            self.save_update(&state, &legacy, &[])?;
            if legacy_spender.is_some() {
                tracing::info!("sealed the Curvy spender identity of a pre-sealing state database");
            }
        }
        Ok(state)
    }

    fn allocation(&self, id: &[u8; PixAddressId::SIZE]) -> Result<Option<StoredAllocation>, RsSdkCurvyAdapterError> {
        let read = self.db.begin_read().map_err(db_error)?;
        let table = read.open_table(SDK_ALLOCATIONS_TABLE).map_err(db_error)?;
        Ok(table
            .get(*id)
            .map_err(db_error)?
            .map(|value| serde_json::from_slice(&value.value()).map_err(anyhow::Error::new))
            .transpose()?)
    }

    fn completed_allocations(
        &self,
        ids: &[[u8; PixAddressId::SIZE]],
    ) -> Result<Vec<StoredAllocation>, RsSdkCurvyAdapterError> {
        ids.iter()
            .map(|id| {
                let mut allocation = self.allocation(id)?.ok_or_else(|| {
                    RsSdkCurvyAdapterError::InvalidValue("missing prepared allocation record".to_owned())
                })?;
                allocation.stage = StoredAllocationStage::Completed;
                Ok(allocation)
            })
            .collect()
    }

    fn save(&self, state: &SdkState) -> Result<(), RsSdkCurvyAdapterError> {
        self.save_update(state, &[], &[])
    }

    fn save_update(
        &self,
        state: &SdkState,
        allocations: &[StoredAllocation],
        remove: &[[u8; PixAddressId::SIZE]],
    ) -> Result<(), RsSdkCurvyAdapterError> {
        let encoded = serde_json::to_vec(state).map_err(anyhow::Error::new)?;
        let write = self.db.begin_write().map_err(db_error)?;
        {
            let mut table = write.open_table(SDK_STATE_TABLE).map_err(db_error)?;
            table.insert(SDK_STATE_KEY, encoded).map_err(db_error)?;
            let mut records = write.open_table(SDK_ALLOCATIONS_TABLE).map_err(db_error)?;
            for allocation in allocations {
                let encoded = serde_json::to_vec(allocation).map_err(anyhow::Error::new)?;
                records.insert(allocation.id, encoded).map_err(db_error)?;
            }
            for id in remove {
                records.remove(*id).map_err(db_error)?;
            }
        }
        write.commit().map_err(db_error)?;
        Ok(())
    }

    fn reset(&self, state: &SdkState) -> Result<(), RsSdkCurvyAdapterError> {
        let encoded = serde_json::to_vec(state).map_err(anyhow::Error::new)?;
        let write = self.db.begin_write().map_err(db_error)?;
        write.delete_table(SDK_ALLOCATIONS_TABLE).map_err(db_error)?;
        write.open_table(SDK_ALLOCATIONS_TABLE).map_err(db_error)?;
        write
            .open_table(SDK_STATE_TABLE)
            .map_err(db_error)?
            .insert(SDK_STATE_KEY, encoded)
            .map_err(db_error)?;
        write.commit().map_err(db_error)?;
        Ok(())
    }
}

/// An [`Identity`] from the public keys the gateway spells out: `S`, `V` and the BabyJubJub owner
/// key, each `"x.y"` decimal — the spelling `Identity` uses for its meta-keys. `who` names the
/// key in errors.
fn stealth_identity(keys: &relayer::CurvyPublicKeys, who: &str) -> Result<Identity, RsSdkCurvyAdapterError> {
    let (x, y) = keys.bjj_public_key.split_once('.').ok_or_else(|| {
        RsSdkCurvyAdapterError::InvalidValue(format!("{who} {:?} is not an `x.y` point", keys.bjj_public_key))
    })?;
    let coordinate = |value: &str, name: &str| {
        Bn254Fr::try_from_dec(value)
            .map(Bn254Fr::into_inner)
            .map_err(|error| RsSdkCurvyAdapterError::InvalidValue(format!("{who} {name}: {error}")))
    };
    Ok(Identity {
        big_k: keys.spend_public_key.clone(),
        big_v: keys.view_public_key.clone(),
        bjj_pub: (coordinate(x, "x")?, coordinate(y, "y")?),
    })
}

/// Marks an otherwise fund-free-looking error as following a submission in the same call.
///
/// An error that is already unambiguously not fund-free is left alone, so its own variant still
/// tells the caller what happened.
pub(crate) fn tag_after_submission(error: RsSdkCurvyAdapterError) -> RsSdkCurvyAdapterError {
    let (fund_free_looking, out_of_funding) = match &error {
        RsSdkCurvyAdapterError::NoFunding { .. } => (true, true),
        RsSdkCurvyAdapterError::Sdk(inner) => (super::is_pre_submission_refusal(&inner.to_string()), false),
        _ => (false, false),
    };
    if fund_free_looking {
        RsSdkCurvyAdapterError::AfterSubmission {
            source: anyhow::anyhow!("{error}"),
            out_of_funding,
        }
    } else {
        error
    }
}

fn relay_error(error: relayer::RelayError) -> RsSdkCurvyAdapterError {
    RsSdkCurvyAdapterError::Relay(error)
}

/// A random v4 UUID, which is the only shape the relayer accepts for an intent id.
///
/// Hand-rolled rather than pulling in a crate for one call site: this needs no parsing, no
/// formatting variants and no ordering, only 122 random bits in the documented layout.
fn uuid_v4() -> String {
    let mut bytes = hopr_api::types::crypto_random::random_bytes::<16>();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn db_error(error: impl std::fmt::Display) -> RsSdkCurvyAdapterError {
    RsSdkCurvyAdapterError::Sdk(anyhow::anyhow!(error.to_string()))
}

/// The Curvy deployment behind a Blokli endpoint, read from `chain_info` rather than configured.
#[derive(Clone, Debug)]
pub struct CurvyChainEndpoints {
    pub aggregator: String,
    /// The entry-portal factory, absent on a portal-less deployment.
    ///
    /// `None` when Blokli does not name one, or names the zero address — which is exactly how a
    /// direct-shield-only deployment is configured (`portalFactory` left at `address(0)`, making
    /// `portalShield` permanently unreachable). Required only for
    /// [`CurvyShielding::Portal`].
    pub portal_factory: Option<String>,
    /// The vault, which pulls a shield's funds from whoever calls the aggregator.
    pub vault: String,
    /// The shield router a direct shield is `send` to. `None` when Blokli does not name one — it
    /// names it only once it has found code at the router's canonical address.
    pub shield_router: Option<String>,
    pub token_address: String,
    pub chain_id: u64,
}

impl CurvyChainEndpoints {
    /// Reads the Curvy contract addresses and chain id from Blokli.
    pub async fn discover<C: BlokliQueryClient + Send + Sync>(client: &C) -> Result<Self, RsSdkCurvyAdapterError> {
        let chain_info = client
            .query_chain_info()
            .await
            .map_err(|error| RsSdkCurvyAdapterError::Discovery(error.to_string()))?;
        let contracts: std::collections::HashMap<String, String> =
            serde_json::from_str(&chain_info.contract_addresses.0)
                .map_err(|error| RsSdkCurvyAdapterError::Discovery(format!("contract address map: {error}")))?;
        let contract = |name: &str| {
            contracts
                .get(name)
                .cloned()
                .ok_or_else(|| RsSdkCurvyAdapterError::Discovery(format!("no `{name}` contract in chain_info")))
        };
        // A named-but-zero address is how a portal-less deployment states "no factory", so it
        // is folded into the same `None` as an absent key rather than being carried as a
        // plausible-looking address that every call to it would silently fail against.
        let optional_contract = |name: &str| contracts.get(name).filter(|address| !is_zero_address(address)).cloned();
        Ok(Self {
            aggregator: contract("curvy_aggregator")?,
            portal_factory: optional_contract("curvy_portal_factory"),
            vault: contract("curvy_vault")?,
            shield_router: optional_contract("curvy_shield_router"),
            token_address: contract("token")?,
            chain_id: u64::try_from(chain_info.chain_id)
                .map_err(|_| RsSdkCurvyAdapterError::Discovery("negative chain id".to_owned()))?,
        })
    }
}

/// Whether a hex address string is the zero address, ignoring case and an optional `0x`.
fn is_zero_address(address: &str) -> bool {
    let trimmed = address
        .strip_prefix("0x")
        .or_else(|| address.strip_prefix("0X"))
        .unwrap_or(address);
    !trimmed.is_empty() && trimmed.chars().all(|c| c == '0')
}

impl CurvyChainEndpoints {
    /// The shield router, or a diagnostic saying why a direct shield cannot run without it.
    pub fn require_shield_router(&self) -> Result<&str, RsSdkCurvyAdapterError> {
        self.shield_router.as_deref().ok_or_else(|| {
            RsSdkCurvyAdapterError::Discovery(
                "Blokli names no Curvy shield router (`curvy_shield_router`), so `shielding: direct` cannot run: the \
                 router is not deployed on this network, or this Blokli predates it. Nothing was sent — a `send` to \
                 an undeployed router would strand the float."
                    .to_owned(),
            )
        })
    }

    /// The portal factory, or a diagnostic naming the mode that needs it.
    pub fn require_portal_factory(&self) -> Result<&str, RsSdkCurvyAdapterError> {
        self.portal_factory.as_deref().ok_or_else(|| {
            RsSdkCurvyAdapterError::Discovery(
                "this Curvy deployment has no entry-portal factory, so `shielding: portal` cannot work against it; \
                 use `shielding: direct`"
                    .to_owned(),
            )
        })
    }
}

/// Constructs a Curvy client whose reads and submissions go through Blokli — except, when
/// `notes` is given, the note index the SDK rebuilds its tree from (see
/// [`CurvyNoteSource::CurvyIndexer`]).
pub fn blokli_curvy_client(
    blokli_url: impl Into<String>,
    endpoints: &CurvyChainEndpoints,
    notes: Option<Arc<dyn curvy_chain_api::NoteIndexSource>>,
) -> Arc<CurvyClient> {
    let blokli = Arc::new(curvy_chain_blokli::BlokliChain::new(blokli_url));
    let notes: Arc<dyn curvy_chain_api::NoteIndexSource> = notes.unwrap_or_else(|| blokli.clone());
    Arc::new(CurvyClient::new(
        blokli.clone(),
        blokli.clone(),
        notes,
        blokli.clone(),
        blokli.clone(),
        blokli.clone(),
        blokli,
        endpoints.aggregator.clone(),
        // The SDK still wants a factory address. On a portal-less deployment there is none, and
        // the zero address is the honest stand-in: every portal call would revert anyway, and
        // `require_portal_factory` is what stops one being attempted.
        endpoints
            .portal_factory
            .clone()
            .unwrap_or_else(|| format!("0x{}", "0".repeat(40))),
        endpoints.chain_id,
    ))
}

/// Concrete [`CurvySdkAdapter`] backed directly by `curvy-sdk`.
///
/// The Curvy client is built on first use rather than at construction, because learning the
/// deployment's contract addresses is a query and construction is synchronous.
pub struct RsSdkCurvyAdapter<C> {
    blokli: Arc<C>,
    blokli_url: String,
    config: RsSdkCurvyAdapterConfig,
    funder: PortalFunder,
    /// Present only for [`CurvyShielding::Direct`]; the portal path never uses it.
    shielder: Option<DirectShielder>,
    /// Present only for [`CurvySubmission::Relayer`].
    relay: Option<Arc<RelayClient>>,
    store: RedbCurvySdkStore,
    state: Arc<parking_lot::Mutex<SdkState>>,
    spender: Account,
    client: tokio::sync::OnceCell<(Arc<CurvyClient>, CurvyChainEndpoints)>,
    /// Serialises everything that submits a transaction or spends a note.
    chain: Arc<tokio::sync::Mutex<()>>,
    /// Prevent repeated funding calls from downloading the notes tree in a tight loop.
    next_relay_finality_check: parking_lot::Mutex<Option<tokio::time::Instant>>,
}

impl<C> RsSdkCurvyAdapter<C>
where
    C: BlokliQueryClient + Send + Sync + 'static,
{
    /// Creates the bridge, loading — or generating and persisting — the node's Curvy identity.
    pub fn new(
        blokli: Arc<C>,
        blokli_url: impl Into<String>,
        config: RsSdkCurvyAdapterConfig,
        funder: PortalFunder,
        shielder: Option<DirectShielder>,
        relay: Option<Arc<RelayClient>>,
        state: &RedbCurvyDepositState,
    ) -> Result<Self, RsSdkCurvyAdapterError> {
        config.validate_signer()?;
        let store = RedbCurvySdkStore::new(state)?;
        let mut persisted = store.load()?;
        let spender = match store.spender(&persisted)? {
            Some(spender) => Account::from_meta_keys(&full_width_key(&spender.k), &full_width_key(&spender.v))?,
            None => {
                let (k, v, ..) =
                    stealth::new_meta().map_err(|error| RsSdkCurvyAdapterError::Sdk(anyhow::anyhow!("{error}")))?;
                let (k, v) = (full_width_key(&k), full_width_key(&v));
                let spender = Account::from_meta_keys(&k, &v)?;
                store.set_spender(&mut persisted, &StoredSpender { k, v })?;
                store.save(&persisted)?;
                tracing::info!("generated this node's Curvy spender identity");
                spender
            }
        };
        // The SDK's chain adapter appends `/graphql` to whatever it is given, and a doubled slash
        // is a 404 on Blokli — so the base is normalised here rather than trusting every caller.
        let blokli_url = blokli_url.into().trim_end_matches('/').to_owned();
        Ok(Self {
            blokli,
            blokli_url,
            config,
            funder,
            shielder,
            relay,
            store,
            state: Arc::new(parking_lot::Mutex::new(persisted)),
            spender,
            client: tokio::sync::OnceCell::new(),
            chain: Arc::new(tokio::sync::Mutex::new(())),
            next_relay_finality_check: parking_lot::Mutex::new(None),
        })
    }

    async fn client(&self) -> Result<&(Arc<CurvyClient>, CurvyChainEndpoints), RsSdkCurvyAdapterError> {
        self.client
            .get_or_try_init(|| async {
                let endpoints = CurvyChainEndpoints::discover(self.blokli.as_ref()).await?;
                tracing::info!(
                    aggregator = %endpoints.aggregator,
                    portal_factory = endpoints.portal_factory.as_deref().unwrap_or("<none: direct-shield only>"),
                    shield_router = endpoints.shield_router.as_deref().unwrap_or("<none: no direct shielding>"),
                    vault = %endpoints.vault,
                    token = %endpoints.token_address,
                    chain_id = endpoints.chain_id,
                    "discovered the Curvy deployment through Blokli"
                );
                let notes: Option<Arc<dyn curvy_chain_api::NoteIndexSource>> = match self.config.note_source {
                    CurvyNoteSource::Blokli => None,
                    CurvyNoteSource::CurvyIndexer => {
                        let url = self.config.curvy_indexer_url.clone().ok_or_else(|| {
                            RsSdkCurvyAdapterError::InvalidValue(
                                "`note_source: curvy_indexer` needs `curvy_indexer_url`".to_owned(),
                            )
                        })?;
                        let api = indexer::HttpSyncApi::new(url, super::INDEXER_REQUEST_TIMEOUT)
                            .map_err(RsSdkCurvyAdapterError::InvalidValue)?;
                        tracing::info!(
                            chain_id = endpoints.chain_id,
                            "reading Curvy notes from Curvy's indexer"
                        );
                        Some(Arc::new(indexer::CurvyIndexerNotes(indexer::CurvyIndexerClient::new(
                            api,
                            Arc::new(endpoints.chain_id),
                        ))))
                    }
                };
                let client = blokli_curvy_client(self.blokli_url.clone(), &endpoints, notes);
                Ok((client, endpoints))
            })
            .await
    }

    /// The vault token id every note of this pool carries, looked up the first time it is needed
    /// when the operator did not state one.
    async fn token(&self) -> Result<u64, RsSdkCurvyAdapterError> {
        if let Some(token) = self.config.token.get() {
            return Ok(token);
        }
        // The lookup matches on the token the Safe holds, which discovery has already read.
        let (_, endpoints) = self.client().await?;
        self.config
            .token
            .resolve_for(&endpoints.token_address)
            .await
            .map_err(RsSdkCurvyAdapterError::Discovery)
    }

    /// Shields without an entry portal, paid by whatever account the [`DirectShielder`] drives —
    /// the node's Safe.
    ///
    /// Takes the chain lock, held by the caller, so that the submission can keep it past this
    /// future being dropped.
    ///
    /// The note is journalled **before** submission, and so is how far the Safe's transaction got
    /// ([`ShieldSubmission`]): a journalled note is looked for on chain before it would be shielded
    /// again, a transaction that was submitted is never sent again, and one that was refused or
    /// reverted is. The submission itself runs to the end of its journalling in a task of its own,
    /// so that dropping this future cannot leave a submitted transaction journalled as unknown.
    async fn direct_shield(
        &self,
        requested: u128,
        chain: tokio::sync::OwnedMutexGuard<()>,
    ) -> Result<Vec<TxLedger>, RsSdkCurvyAdapterError> {
        let Some(shielder) = self.shielder.clone() else {
            return Err(RsSdkCurvyAdapterError::InvalidValue(
                "direct shielding was selected but the pool was built without a shielder".to_owned(),
            ));
        };
        let (client, endpoints) = self.client().await?;

        // Resume an in-flight shield rather than preparing a second one: the note is
        // deterministic in its inputs, but a fresh `prepare_direct_shield` would seal a new one.
        //
        // The router and token checks come before anything is prepared or journalled, but only
        // once a journalled note has been checked against the chain: a shield that landed under
        // an earlier version, or against a Blokli that predates the router, needs no router to be
        // recorded, and refusing it here would leave it journalled for good.
        //
        // The journalled amount is authoritative for a shield in flight: the requested one only
        // sizes a new shield. Holding the two to each other would wedge funding for good after a
        // crash followed by a change of the configured top-up.
        let mut router: Option<Address> = None;
        let in_flight = self.state.lock().direct_shield_in_flight.clone();
        let (gross, prepared, submission) = match in_flight {
            Some(stored) => {
                let journalled = stored.gross.parse::<u128>().map_err(|error| {
                    RsSdkCurvyAdapterError::InvalidValue(format!("journalled direct shield amount: {error}"))
                })?;
                if journalled != requested {
                    tracing::warn!(
                        %requested,
                        %journalled,
                        "resuming the journalled direct shield with its own amount; the requested amount applies to the next funding"
                    );
                }
                let note = OwnedNote::try_from(&stored.note)?;
                (
                    journalled,
                    PreparedDirectShield::from_recovery_parts(note, journalled),
                    stored.submission,
                )
            }
            None => {
                router = Some(self.shield_router_checked(endpoints).await?);
                let prepared = client
                    .prepare_direct_shield(&self.spender, requested, self.token().await?)
                    .await?;
                let mut state = self.state.lock();
                state.direct_shield_in_flight = Some(StoredDirectShield {
                    note: StoredNote::from(&prepared.note),
                    gross: requested.to_string(),
                    submission: ShieldSubmission::NotSubmitted,
                });
                self.store.save(&state)?;
                (requested, prepared, ShieldSubmission::NotSubmitted)
            }
        };

        // The chain lock, from here to the end: the submission task hands it back, and what
        // follows — recording the funding note and committing it — needs it held, or a concurrent
        // allocation could select a note that is not committed yet.
        let mut held = Some(chain);

        // A note the aggregator already knows was shielded by an earlier attempt whose outcome we
        // lost. Shielding again would spend the float twice.
        let first = client.note_status(&prepared.note.note_id()).await?;
        let mut observed = Some(first).filter(|status| matches!(status, 1 | 2));
        if observed.is_none() {
            match &submission {
                ShieldSubmission::NotSubmitted => {}
                // Confirmed on chain, so the shield took effect and is never sent again; the
                // aggregator indexes it when it does, and the next funding reads again.
                ShieldSubmission::Submitted { tx, at } => {
                    let grace = self.config.direct_shield_settle_grace.as_secs();
                    // A clock that cannot be read cannot say the grace is over.
                    if at.is_some_and(|at| unix_now().is_none_or(|now| now < at.saturating_add(grace))) {
                        return Err(RsSdkCurvyAdapterError::ShieldConfirmedUnindexed {
                            note: note_id(&prepared.note),
                            gross,
                            tx: tx.clone(),
                            resend_after: at.map(|at| at.saturating_add(grace)),
                        });
                    }
                    tracing::warn!(
                        %tx,
                        note = %note_id(&prepared.note),
                        %gross,
                        "a confirmed direct shield's note never appeared within the grace; treating it as a failed \
                         inner call of the Safe, and sending it again"
                    );
                    journal_submission(
                        &self.state,
                        &self.store,
                        ShieldJournal::Direct,
                        ShieldSubmission::NotSubmitted,
                    )?;
                }
                // Handed to the chain with no outcome recorded. Within the grace it is only looked
                // for, once per funding, which the read above was; the full observation is for
                // deciding what to do once the grace is over.
                ShieldSubmission::Unknown { since } => {
                    let grace = self.config.direct_shield_settle_grace.as_secs();
                    // A clock that cannot be read cannot say the grace is over.
                    if let Some(since) =
                        since.filter(|since| unix_now().is_none_or(|now| now < since.saturating_add(grace)))
                    {
                        return Err(RsSdkCurvyAdapterError::ShieldSettling {
                            note: note_id(&prepared.note),
                            gross,
                            since: Some(since),
                            resend_after: Some(since.saturating_add(grace)),
                        });
                    }
                    observed = self.observe_direct_shield(client, &prepared.note, true).await?;
                    if observed.is_none() {
                        match since {
                            Some(since) => tracing::warn!(
                                note = %note_id(&prepared.note),
                                %gross,
                                since,
                                grace = ?self.config.direct_shield_settle_grace,
                                "the journalled direct shield's grace has elapsed and its note is unknown; sending it again"
                            ),
                            None => tracing::warn!(
                                note = %note_id(&prepared.note),
                                %gross,
                                "the journalled direct shield has no record of a submission and its note is unknown; \
                                 sending it again"
                            ),
                        }
                    }
                }
            }
        }
        let observed = match observed {
            Some(observed) => observed,
            None => {
                let router = match router {
                    Some(router) => router,
                    None => self.shield_router_checked(endpoints).await?,
                };
                let aggregator: Address = endpoints
                    .aggregator
                    .parse()
                    .map_err(|error| RsSdkCurvyAdapterError::InvalidValue(format!("aggregator address: {error}")))?;
                let payload = direct_shield_payload(aggregator, &prepared.onchain_note)?;
                tracing::info!(%gross, %router, "shielding the Curvy funding note from the Safe through the shield router");
                let shield = shielder(payload, router, gross);
                let (state, store) = (Arc::clone(&self.state), self.store.clone());
                let guard = held.take().expect("held above");
                let (outcome, guard) = tokio::spawn(async move {
                    let outcome = shield_journalled(&state, &store, ShieldJournal::Direct, shield).await;
                    (outcome, guard)
                })
                .await
                .map_err(|error| {
                    RsSdkCurvyAdapterError::InvalidValue(format!("the direct shield submission: {error}"))
                })?;
                held = Some(guard);
                let (outcome, at) = outcome?;
                match outcome {
                    Ok(confirmed) => {
                        tracing::info!(tx = %confirmed.tx, "the direct shield confirmed on chain");
                        match self.observe_direct_shield(client, &prepared.note, false).await? {
                            Some(observed) => observed,
                            // Confirmed is journalled `Submitted` and stays so: the aggregator is
                            // behind, and the next funding reads again.
                            None => {
                                return Err(RsSdkCurvyAdapterError::ShieldConfirmedUnindexed {
                                    note: note_id(&prepared.note),
                                    gross,
                                    tx: confirmed.tx,
                                    resend_after: at
                                        .map(|at| at.saturating_add(self.config.direct_shield_settle_grace.as_secs())),
                                });
                            }
                        }
                    }
                    Err(ShieldFailure::NotSubmitted(reason) | ShieldFailure::Reverted { reason }) => {
                        return Err(RsSdkCurvyAdapterError::Funding(reason));
                    }
                    Err(ShieldFailure::Unconfirmed(reason)) => {
                        tracing::warn!(%reason, "the direct shield's outcome is unknown; not sent again until its grace is over");
                        return Err(RsSdkCurvyAdapterError::ShieldSettling {
                            note: note_id(&prepared.note),
                            gross,
                            since: at,
                            resend_after: at
                                .map(|since| since.saturating_add(self.config.direct_shield_settle_grace.as_secs())),
                        });
                    }
                }
            }
        };

        let _chain = held;
        {
            let mut state = self.state.lock();
            let stored = StoredNote::from(&prepared.note);
            let prepared_id = note_id(&prepared.note);
            let already_funding = state
                .funding
                .iter()
                .map(OwnedNote::try_from)
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .any(|note| note_id(note) == prepared_id);
            if !already_funding {
                state.funding.push(stored.clone());
            }
            if observed != 2 && !state.pending.iter().any(|note| note == &stored) {
                state.pending.push(stored);
            }
            state.direct_shield_in_flight = None;
            self.store.save(&state)?;
        }
        // As in `shield`: journalled is funded, and committing is retried by every reconciliation.
        match self.recover_pending().await {
            Ok(ledger) => Ok(ledger),
            Err(error) => {
                tracing::warn!(%error, "the funding note is journalled but could not be committed yet; the next reconciliation retries");
                Ok(Vec::new())
            }
        }
    }

    /// The router a direct shield sends through, once the deployment is known to have one and the
    /// configured token to be the one the Safe sends. Both before the Safe is asked to send
    /// anything: without a router there is nowhere safe to send the float, and a note naming the
    /// wrong token would only revert in the router after the Safe had paid for the transaction.
    async fn shield_router_checked(&self, endpoints: &CurvyChainEndpoints) -> Result<Address, RsSdkCurvyAdapterError> {
        let router: Address = endpoints
            .require_shield_router()?
            .parse()
            .map_err(|error| RsSdkCurvyAdapterError::InvalidValue(format!("shield router address: {error}")))?;
        self.check_vault_token(endpoints).await?;
        Ok(router)
    }

    /// Refuses a direct shield whose note would name a different token than the one the Safe
    /// sends — a wrong [`RsSdkCurvyAdapterConfig`] token id — before anything reaches the chain.
    async fn check_vault_token(&self, endpoints: &CurvyChainEndpoints) -> Result<(), RsSdkCurvyAdapterError> {
        let token = self.token().await?;
        // An id the pool resolved was picked by this very comparison. Only a stated one can
        // disagree with the deployment.
        if !self.config.token.is_configured() {
            return Ok(());
        }
        let vault_token = self
            .blokli
            .query_curvy_vault_token(token.to_string())
            .await
            .map_err(|error| RsSdkCurvyAdapterError::Discovery(format!("vault token {token}: {error}")))?;
        if !vault_token.token_address.eq_ignore_ascii_case(&endpoints.token_address) {
            return Err(RsSdkCurvyAdapterError::InvalidValue(format!(
                "Curvy vault token {token} is {}, but the Safe holds {}: the configured token id is wrong for this \
                 deployment",
                vault_token.token_address, endpoints.token_address
            )));
        }
        Ok(())
    }

    /// The note's status once a direct shield has confirmed, or `None` if the aggregator still
    /// does not know it after a few reads. `first_read_missed` carries a read the caller already
    /// made and missed with, so that it is not made twice.
    ///
    /// The aggregator is asked a few times, so that nothing is recorded as funding on the strength
    /// of a receipt alone, and since its index may be a block behind the chain.
    async fn observe_direct_shield(
        &self,
        client: &CurvyClient,
        note: &OwnedNote,
        first_read_missed: bool,
    ) -> Result<Option<u8>, RsSdkCurvyAdapterError> {
        for attempt in usize::from(first_read_missed)..DIRECT_SHIELD_OBSERVATIONS {
            if attempt > 0 {
                tokio::time::sleep(DIRECT_SHIELD_OBSERVATION_INTERVAL).await;
            }
            let status = client.note_status(&note.note_id()).await?;
            if matches!(status, 1 | 2) {
                return Ok(Some(status));
            }
        }
        Ok(None)
    }

    /// Shields `gross` into the pool as one more funding note. A journalled shield is resumed
    /// first, with its own amount (and recovery address) rather than the requested ones.
    async fn shield(&self, gross: u128, recovery_address: &str) -> Result<Vec<TxLedger>, RsSdkCurvyAdapterError> {
        let chain = Arc::clone(&self.chain).lock_owned().await;
        let (client, endpoints) = self.client().await?;
        self.reconcile_relay_aggregation().await?;
        self.recover_pending().await?;
        if self.config.shielding == CurvyShielding::Direct {
            return self.direct_shield(gross, chain).await;
        }
        // Held to the end, and handed to the task that funds the portal.
        let mut held = Some(chain);
        // As for a direct shield, the journalled amount and recovery address are authoritative for
        // a shield in flight; the caller's only size a new one.
        let shield = if let Some(shield) = self.state.lock().shield_in_flight.clone() {
            if shield.gross != gross.to_string() || shield.recovery != recovery_address {
                tracing::warn!(
                    requested = %gross,
                    journalled = %shield.gross,
                    journalled_recovery = %shield.recovery,
                    "resuming the journalled shield with its own amount and recovery address; the requested ones apply to the next funding"
                );
            }
            shield
        } else {
            let prepared = client
                .prepare_deposit(&self.spender, gross, self.token().await?, recovery_address)
                .await?;
            let shield = StoredShield {
                note: StoredNote::from(&prepared.note),
                gross: prepared.gross.to_string(),
                recovery: prepared.recovery,
                portal_address: prepared.portal_address,
                stage: StoredShieldStage::Prepared,
                submission: ShieldSubmission::NotSubmitted,
            };
            let mut state = self.state.lock();
            state.shield_in_flight = Some(shield.clone());
            self.store.save(&state)?;
            shield
        };
        let prepared = shield.prepared()?;
        // From here on the journalled amount, which is `gross` unless the shield was resumed.
        let gross = prepared.gross;
        let observed_status = client.note_status(&prepared.note.note_id()).await?;
        let mut ledger = Vec::new();
        if !matches!(observed_status, 1 | 2) {
            if shield.stage == StoredShieldStage::Prepared {
                let portal_balance = client
                    .erc20_balance(&endpoints.token_address, &prepared.portal_address)
                    .await?;
                let grace = self.config.direct_shield_settle_grace.as_secs();
                let within = |since: u64| unix_now().is_none_or(|now| now < since.saturating_add(grace));
                // As for a direct shield, with "the portal holds the funds" for "the aggregator
                // knows the note": whether the Safe sends again follows from how far its last
                // transfer got.
                let portal = Address::from_str(&prepared.portal_address)
                    .map_err(|error| RsSdkCurvyAdapterError::InvalidValue(format!("shield portal address: {error}")))?;
                // Unlike a direct shield, a portal funding is never sent again on a guess: the
                // first copy may land after the grace, and a portal holding twice `gross` can
                // never be shielded, so past the grace the operator is asked instead.
                let unresolved = |tx: Option<String>, since: Option<u64>| {
                    tracing::warn!(
                        note = %note_id(&prepared.note),
                        %gross,
                        ?tx,
                        ?since,
                        grace = ?self.config.direct_shield_settle_grace,
                        "the portal funding has not shown within the grace; it is not sent again"
                    );
                    RsSdkCurvyAdapterError::PortalFundingUnresolved {
                        portal: portal.to_string(),
                        gross,
                        tx,
                        since,
                    }
                };
                let send = match &shield.submission {
                    ShieldSubmission::NotSubmitted => portal_balance == 0,
                    // Confirmed, so it took effect; a portal that reads empty is the read being
                    // behind, until the grace says it is not.
                    ShieldSubmission::Submitted { tx, at } => {
                        if portal_balance != 0 {
                            false
                        } else if at.is_some_and(within) {
                            return Err(RsSdkCurvyAdapterError::ShieldConfirmedUnindexed {
                                note: note_id(&prepared.note),
                                gross,
                                tx: tx.clone(),
                                resend_after: at.map(|at| at.saturating_add(grace)),
                            });
                        } else {
                            return Err(unresolved(Some(tx.clone()), *at));
                        }
                    }
                    // Handed to the chain with no outcome recorded: looked for once per funding,
                    // which the read above was. A journal that never recorded when has nothing to
                    // wait for, and nothing was ever sent that the balance does not show.
                    ShieldSubmission::Unknown { since } => {
                        if portal_balance != 0 {
                            false
                        } else if let Some(since) = *since {
                            if within(since) {
                                return Err(RsSdkCurvyAdapterError::ShieldSettling {
                                    note: note_id(&prepared.note),
                                    gross,
                                    since: Some(since),
                                    resend_after: Some(since.saturating_add(grace)),
                                });
                            }
                            return Err(unresolved(None, Some(since)));
                        } else {
                            true
                        }
                    }
                };
                if send {
                    tracing::info!(%portal, gross, "funding the Curvy shield portal from the Safe");
                    // In a task of its own, holding the chain lock: a Safe transaction cannot be
                    // un-sent, and a caller that is dropped while it is in flight (an API request
                    // whose client went away) would otherwise lose it with the journal still at
                    // `Prepared`, and a retry would fund the portal a second time. The task runs it
                    // to the end of its journalling — how far the transfer got — because a balance
                    // read by a parent that may be gone by then is no record of what the Safe sent.
                    // The stage is not part of it: only a balance read says the portal is funded.
                    let funding = (self.funder)(portal, HoprBalance::from(U256::from(gross)));
                    let (state, store) = (Arc::clone(&self.state), self.store.clone());
                    let guard = held.take().expect("held above");
                    let (outcome, guard) = tokio::spawn(async move {
                        let outcome = shield_journalled(&state, &store, ShieldJournal::Portal, funding).await;
                        (outcome, guard)
                    })
                    .await
                    .map_err(|error| RsSdkCurvyAdapterError::InvalidValue(format!("the portal funding: {error}")))?;
                    held = Some(guard);
                    let (outcome, at) = outcome?;
                    match outcome {
                        Ok(confirmed) => {
                            // A portal that reads empty is the read being behind, or a Safe call that
                            // failed inside a confirmed transaction: the journal stays `Prepared`
                            // with the confirmation, and the grace decides on a later call. One
                            // holding anything but `gross` is not the shield this journal describes.
                            let actual = client
                                .erc20_balance(&endpoints.token_address, &prepared.portal_address)
                                .await?;
                            if actual == 0 {
                                return Err(RsSdkCurvyAdapterError::ShieldConfirmedUnindexed {
                                    note: note_id(&prepared.note),
                                    gross,
                                    tx: confirmed.tx,
                                    resend_after: at.map(|at| at.saturating_add(grace)),
                                });
                            }
                            if actual != gross {
                                return Err(RsSdkCurvyAdapterError::UnexpectedShieldFunding {
                                    portal: portal.to_string(),
                                    actual,
                                    required: gross,
                                });
                            }
                        }
                        Err(ShieldFailure::NotSubmitted(reason) | ShieldFailure::Reverted { reason }) => {
                            return Err(RsSdkCurvyAdapterError::Funding(reason));
                        }
                        Err(ShieldFailure::Unconfirmed(reason)) => {
                            tracing::warn!(%reason, "the portal funding's outcome is unknown; not sent again until its grace is over");
                            return Err(RsSdkCurvyAdapterError::ShieldSettling {
                                note: note_id(&prepared.note),
                                gross,
                                since: at,
                                resend_after: at.map(|since| since.saturating_add(grace)),
                            });
                        }
                    }
                } else {
                    if portal_balance != gross {
                        return Err(RsSdkCurvyAdapterError::UnexpectedShieldFunding {
                            portal: portal.to_string(),
                            actual: portal_balance,
                            required: gross,
                        });
                    }
                }
                journal_portal_funded(&self.state, &self.store)?;
            }
            let entry = client
                .shield_prepared_deposit(&prepared, &self.config.operator_private_key, self.config.route)
                .await?;
            tracing::info!(tx = %entry.tx_hash, backend = %entry.backend, "shielded the Curvy funding note");
            ledger.push(entry);
        }
        let _chain = held;
        {
            let mut state = self.state.lock();
            let stored = StoredNote::from(&prepared.note);
            let prepared_id = note_id(&prepared.note);
            let already_funding = state
                .funding
                .iter()
                .map(OwnedNote::try_from)
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .any(|note| note_id(note) == prepared_id);
            if !already_funding {
                state.funding.push(stored.clone());
            }
            if observed_status != 2 && !state.pending.iter().any(|note| note == &stored) {
                state.pending.push(stored);
            }
            state.shield_in_flight = None;
            self.store.save(&state)?;
        }
        // The note is journalled: the shield is done whatever happens to committing it, and a
        // retry of `fund` on this error would shield a second time. Every reconciliation retries
        // the commitment instead.
        match self.recover_pending().await {
            Ok(entries) => ledger.extend(entries),
            Err(error) => {
                tracing::warn!(%error, "the funding note is journalled but could not be committed yet; the next reconciliation retries")
            }
        }
        Ok(ledger)
    }

    /// Reconciles an ambiguous aggregation after Blokli has indexed at least one output.
    ///
    /// Returning `Ok(false)` keeps allocation blocked because an all-unknown result
    /// cannot distinguish a rejected transaction from one that has not been indexed yet.
    async fn reconcile_ambiguous_allocation(&self) -> Result<bool, RsSdkCurvyAdapterError> {
        let (client, _) = self.client().await?;
        let (inputs, change, emitted, allocation_ids) = {
            let state = self.state.lock();
            if !state.ambiguous_allocation {
                return Ok(true);
            }
            if state.ambiguous_inputs.is_empty() {
                return Ok(false);
            }
            let Some(change) = state.ambiguous_change.clone() else {
                return Ok(false);
            };
            (
                state.ambiguous_inputs.clone(),
                change,
                state.ambiguous_emitted.clone(),
                state.ambiguous_allocation_ids.clone(),
            )
        };
        let emitted_notes = emitted.iter().map(OwnedNote::try_from).collect::<Result<Vec<_>, _>>()?;
        let mut observed = false;
        for note in &emitted_notes {
            if matches!(client.note_status(&note.note_id()).await?, 1 | 2) {
                observed = true;
                break;
            }
        }
        if !observed {
            return Ok(false);
        }
        {
            let mut state = self.state.lock();
            state.funding.retain(|note| !inputs.contains(note));
            state.funding.push(change);
            state.pending.extend(emitted);
            state.ambiguous_allocation = false;
            state.ambiguous_inputs.clear();
            state.ambiguous_change = None;
            state.ambiguous_emitted.clear();
            let completed = self.store.completed_allocations(&allocation_ids)?;
            state.ambiguous_allocation_ids.clear();
            self.store.save_update(&state, &completed, &[])?;
        }
        self.recover_pending().await?;
        Ok(true)
    }

    /// Commits every emitted note Blokli has not yet seen committed. Must be called with the
    /// chain lock held.
    async fn recover_pending(&self) -> Result<Vec<TxLedger>, RsSdkCurvyAdapterError> {
        // Committing is the deployment's job wherever a relayer runs: the relayer refuses
        // `commitPendingNotes`, and the shared batch-prover alongside it commits every pending
        // note anyway. Doing it here too would be a second party racing the same transaction.
        // The pool does not depend on who commits — discovery waits for "committed and final"
        // through Blokli either way — so this only stops us paying for it twice.
        if self.config.submission == CurvySubmission::Relayer {
            let mut state = self.state.lock();
            if !state.pending.is_empty() {
                tracing::debug!(
                    notes = state.pending.len(),
                    "leaving pending Curvy notes to the deployment's batch-prover"
                );
                state.pending.clear();
                self.store.save(&state)?;
            }
            return Ok(Vec::new());
        }
        let pending = self.state.lock().pending.clone();
        if pending.is_empty() {
            return Ok(Vec::new());
        }
        let (client, _) = self.client().await?;
        let notes = pending.iter().map(OwnedNote::try_from).collect::<Result<Vec<_>, _>>()?;
        let mut ledger = Vec::new();
        for chunk in notes.chunks(MAX_COMMITMENTS_PER_PROOF) {
            let mut ids = Vec::new();
            for note in chunk {
                if client.note_status(&note.note_id()).await? != 2 {
                    ids.push(note.note_id());
                }
            }
            if !ids.is_empty() {
                let entries = client
                    .commit(
                        &ids,
                        CircuitFamily::Pix,
                        &self.config.operator_private_key,
                        self.config.route,
                    )
                    .await?;
                for entry in &entries {
                    tracing::info!(tx = %entry.tx_hash, notes = ids.len(), "committed pending Curvy notes");
                }
                ledger.extend(entries);
            }
        }
        let mut state = self.state.lock();
        state.pending.clear();
        self.store.save(&state)?;
        Ok(ledger)
    }

    /// The relayer operator's identity, as the recipient of an aggregation's gas-reimbursement
    /// note, together with what that note must be worth.
    ///
    /// `Ok(None)` when the deployment runs no paymaster: aggregations are then accepted without a
    /// fee note, and adding one would give the operator money for nothing.
    async fn relay_fee_recipient(
        relay: &RelayClient,
        chain_id: u64,
        token: u64,
    ) -> Result<Option<(Identity, u128)>, RsSdkCurvyAdapterError> {
        let Some(info) = relay.paymaster(chain_id).await.map_err(relay_error)? else {
            return Ok(None);
        };
        // A fee note in a token the operator does not take is refused after we have paid to prove
        // it, so it is worth catching here.
        if let Some(accepted) = &info.accepted_vault_token_ids
            && !accepted.iter().any(|id| id == &token.to_string())
        {
            return Err(RsSdkCurvyAdapterError::InvalidValue(format!(
                "the Curvy relayer does not accept fee notes in vault token {token}; it takes {}",
                accepted.join(", ")
            )));
        }
        // The quote is native gas; the note is paid in the vault token, so it is converted at
        // the gateway's USD prices the way the relayer's gate converts it.
        let network = relay.network(chain_id).await.map_err(relay_error)?;
        let (native, fee_token) = relayer::fee_note_valuations(&network, token).map_err(|error| {
            RsSdkCurvyAdapterError::InvalidValue(format!("pricing the relayer's fee note: {error}"))
        })?;
        let amount = info.required_fee_in_token(&native, &fee_token).map_err(|error| {
            RsSdkCurvyAdapterError::InvalidValue(format!("pricing the relayer's fee note: {error}"))
        })?;
        let identity = stealth_identity(&info.operator, "the relayer's operator key")?;
        Ok(Some((identity, amount)))
    }

    /// The protocol fee collector an aggregation's fee note is sealed to: the configured identity,
    /// else the one the gateway publishes at `/protocol`. `Ok(None)` when neither names one; the
    /// SDK then builds a fee-free aggregation, or refuses a fee it would have to seal to nobody.
    async fn fee_recipient(&self) -> Result<Option<Identity>, RsSdkCurvyAdapterError> {
        if let Some(identity) = &self.config.fee_recipient {
            return Ok(Some(identity.clone()));
        }
        let Some(relay) = self.relay.as_ref() else {
            return Ok(None);
        };
        let info = relay.protocol().await.map_err(relay_error)?;
        info.fee_collector
            .as_ref()
            .map(|keys| stealth_identity(keys, "the protocol fee collector's key"))
            .transpose()
    }

    fn prepare_relay_aggregation(
        &self,
        request: &curvy_sdk::PixAggregationRequest,
        endpoints: &CurvyChainEndpoints,
        inputs: &[OwnedNote],
        allocations: &[StoredAllocation],
    ) -> Result<(), RsSdkCurvyAdapterError> {
        let mut current = self.state.lock();
        let inputs = inputs.iter().map(StoredNote::from).collect::<Vec<_>>();
        let allocation_ids = allocations.iter().map(|row| row.id).collect::<Vec<_>>();
        if let Some(previous) = current.relay_aggregations.last() {
            if !previous.rebuild {
                return Err(RsSdkCurvyAdapterError::AmbiguousAllocation);
            }
            // The nullifier guarantee only applies to replacements of this exact spend.
            if previous.inputs != inputs
                || previous.allocation_ids != allocation_ids
                || previous.spend_key != request.spend_key
                || previous.chain_id != endpoints.chain_id
                || !previous.aggregator.eq_ignore_ascii_case(&endpoints.aggregator)
            {
                return Err(RsSdkCurvyAdapterError::InvalidValue(
                    "a replacement aggregation must preserve its deployment, inputs and allocations".to_owned(),
                ));
            }
            for allocation in allocations {
                if self.store.allocation(&allocation.id)?.as_ref() != Some(allocation) {
                    return Err(RsSdkCurvyAdapterError::ConflictingAllocation);
                }
            }
        }
        if current.relay_aggregations.len() >= MAX_RELAY_AGGREGATION_ATTEMPTS {
            return Err(RsSdkCurvyAdapterError::RelayAttemptLimit);
        }
        let mut next = current.clone();
        next.relay_aggregations.push(StoredRelayAggregation {
            intent: uuid_v4(),
            chain_id: endpoints.chain_id,
            aggregator: endpoints.aggregator.clone(),
            max_inputs: request.max_inputs,
            proof: request.proof.clone(),
            public_signals: request.public_signals.clone(),
            request_key: request.request_key.clone(),
            spend_key: request.spend_key.clone(),
            inputs,
            change: StoredNote::from(&request.change),
            emitted: request
                .emitted_notes
                .iter()
                .filter(|note| note.amount != Fr::from(0u8))
                .map(StoredNote::from)
                .collect(),
            allocation_ids,
            attempted: false,
            request_id: None,
            transaction_hash: None,
            rebuild: false,
            last_status: None,
            timeouts_without_progress: 0,
            circuit: Some(request.circuit),
        });
        self.store.save_update(&next, allocations, &[])?;
        *current = next;
        Ok(())
    }

    /// Refresh fees and witnesses without selecting new inputs or changing the recipients.
    async fn rebuild_relay_aggregation(&self) -> Result<(), RsSdkCurvyAdapterError> {
        let pending = self
            .state
            .lock()
            .relay_aggregations
            .last()
            .cloned()
            .ok_or(RsSdkCurvyAdapterError::AmbiguousAllocation)?;
        let inputs = pending
            .inputs
            .iter()
            .map(OwnedNote::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let records = pending
            .allocation_ids
            .iter()
            .map(|id| {
                self.store.allocation(id)?.ok_or_else(|| {
                    RsSdkCurvyAdapterError::InvalidValue("missing prepared allocation record".to_owned())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let allocations = records
            .iter()
            .map(StoredAllocation::prover_allocation)
            .collect::<Result<Vec<_>, RsSdkCurvyAdapterError>>()?;
        let (client, endpoints) = self.client().await?;
        let relay = self.relay.as_ref().ok_or_else(|| {
            RsSdkCurvyAdapterError::InvalidValue("configure the relayer to recover the pending aggregation".to_owned())
        })?;
        let relay_fee = Self::relay_fee_recipient(relay, endpoints.chain_id, self.token().await?).await?;
        let fee_recipient = self.fee_recipient().await?;
        let request = client
            .build_pix_aggregation(
                &self.spender,
                &inputs,
                &allocations,
                relay_fee.as_ref().map(|(identity, amount)| (identity, *amount)),
                fee_recipient.as_ref(),
            )
            .await?;
        self.prepare_relay_aggregation(&request, endpoints, &inputs, &records)
    }

    /// A shared spend key alone does not prove that a conflicting submission has our outputs.
    async fn relay_outputs_known(&self, pending: &StoredRelayAggregation) -> Result<bool, RsSdkCurvyAdapterError> {
        self.notes_known(&pending.emitted).await
    }

    async fn notes_known(&self, notes: &[StoredNote]) -> Result<bool, RsSdkCurvyAdapterError> {
        if notes.is_empty() {
            return Ok(false);
        }
        let (client, _) = self.client().await?;
        for stored in notes {
            let note = OwnedNote::try_from(stored)?;
            if !matches!(client.note_status(&note.note_id()).await?, 1 | 2) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Both supported note sources pin snapshots to finalized checkpoints. Keep every
    /// competing change note until the winning outputs are in that finalized tree.
    async fn check_relay_outputs_finalized(
        &self,
        pending: &StoredRelayAggregation,
    ) -> Result<(), RsSdkCurvyAdapterError> {
        self.check_outputs_finalized(&pending.emitted).await
    }

    async fn check_outputs_finalized(&self, emitted: &[StoredNote]) -> Result<(), RsSdkCurvyAdapterError> {
        let (client, _) = self.client().await?;
        let ids = emitted
            .iter()
            .map(|stored| Ok(fr_to_dec(&OwnedNote::try_from(stored)?.note_id())))
            .collect::<Result<Vec<_>, RsSdkCurvyAdapterError>>()?;
        {
            let mut next = self.next_relay_finality_check.lock();
            if next.is_some_and(|next| tokio::time::Instant::now() < next) {
                return Err(RsSdkCurvyAdapterError::RelayFinalityPending);
            }
            *next = Some(tokio::time::Instant::now() + RELAY_FINALITY_CHECK_INTERVAL);
        }
        let snapshot = tokio::time::timeout(RELAY_FINALITY_CHECK_TIMEOUT, client.notes.notes_tree_snapshot())
            .await
            .map_err(|_| RsSdkCurvyAdapterError::RelayFinalityUnavailable("the note source timed out".to_owned()))?
            .map_err(|error| RsSdkCurvyAdapterError::Sdk(error.into()))?
            .ok_or_else(|| {
                RsSdkCurvyAdapterError::RelayFinalityUnavailable(
                    "the note source returned no finalized checkpoint; retry when a checkpoint is available".to_owned(),
                )
            })?;
        let leaves = snapshot.leaves.iter().collect::<std::collections::HashSet<_>>();
        if ids.iter().all(|id| leaves.contains(id)) {
            Ok(())
        } else {
            Err(RsSdkCurvyAdapterError::RelayFinalityPending)
        }
    }

    fn save_relay_attempt(&self, index: usize, pending: StoredRelayAggregation) -> Result<(), RsSdkCurvyAdapterError> {
        let mut current = self.state.lock();
        let mut next = current.clone();
        next.relay_aggregations[index] = pending;
        self.store.save(&next)?;
        *current = next;
        Ok(())
    }

    fn finish_relay_aggregation(
        &self,
        winner: Option<usize>,
    ) -> Result<Option<RelayAggregationOutcome>, RsSdkCurvyAdapterError> {
        let mut current = self.state.lock();
        if winner.is_none() && current.relay_aggregations.len() > 1 {
            return Err(RsSdkCurvyAdapterError::AmbiguousAllocation);
        }
        let Some(pending) = current.relay_aggregations.get(winner.unwrap_or(0)) else {
            return Ok(None);
        };
        let mut next = current.clone();
        let completed = if winner.is_some() {
            next.funding.retain(|note| !pending.inputs.contains(note));
            if OwnedNote::try_from(&pending.change)?.amount != Fr::from(0u8) {
                next.funding.push(pending.change.clone());
            }
            next.pending.extend(pending.emitted.clone());
            self.store.completed_allocations(&pending.allocation_ids)?
        } else {
            Vec::new()
        };
        let outcome = winner.map(|_| RelayAggregationOutcome {
            request_id: pending.request_id.clone(),
            transaction_hash: pending.transaction_hash.clone(),
            allocations: pending.allocation_ids.len(),
        });
        next.relay_aggregations.clear();
        let remove = if winner.is_some() {
            &[][..]
        } else {
            &pending.allocation_ids[..]
        };
        self.store.save_update(&next, &completed, remove)?;
        *current = next;
        *self.next_relay_finality_check.lock() = None;
        if let Some(outcome) = &outcome {
            tracing::info!(
                request_id = outcome.request_id.as_deref(),
                tx = outcome.transaction_hash.as_deref(),
                allocations = outcome.allocations,
                relayed = true,
                "aggregated Curvy PIX allocations"
            );
        }
        Ok(outcome)
    }

    async fn relay_winner(&self, attempts: &[StoredRelayAggregation]) -> Result<Option<usize>, RsSdkCurvyAdapterError> {
        for (index, attempt) in attempts.iter().enumerate() {
            if attempt.attempted && self.relay_outputs_known(attempt).await? {
                return Ok(Some(index));
            }
        }
        Ok(None)
    }

    /// Called with the chain lock held before funding operations, never by the read-only
    /// deployment consistency check. At most one replacement is proved per invocation.
    async fn reconcile_relay_aggregation(&self) -> Result<Option<RelayAggregationOutcome>, RsSdkCurvyAdapterError> {
        self.reconcile_relay_aggregation_with(|| self.rebuild_relay_aggregation())
            .await
    }

    async fn reconcile_relay_aggregation_with<F, Fut>(
        &self,
        mut rebuild: F,
    ) -> Result<Option<RelayAggregationOutcome>, RsSdkCurvyAdapterError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<(), RsSdkCurvyAdapterError>>,
    {
        let mut rebuilt = false;
        loop {
            let attempts = {
                let state = self.state.lock();
                if state
                    .relay_intents
                    .iter()
                    .any(|intent| intent.action.eq_ignore_ascii_case("aggregation"))
                {
                    return Err(RsSdkCurvyAdapterError::IncompleteRelayRecovery);
                }
                state.relay_aggregations.clone()
            };
            let Some(mut pending) = attempts.last().cloned() else {
                return Ok(None);
            };
            let (_, endpoints) = self.client().await?;
            if attempts.iter().any(|attempt| {
                endpoints.chain_id != attempt.chain_id
                    || !endpoints.aggregator.eq_ignore_ascii_case(&attempt.aggregator)
            }) {
                return Err(RsSdkCurvyAdapterError::InvalidValue(
                    "pending aggregation belongs to another deployment".to_owned(),
                ));
            }
            if let Some(winner) = self.relay_winner(&attempts).await? {
                if attempts.len() > 1 {
                    self.check_relay_outputs_finalized(&attempts[winner]).await?;
                }
                return self.finish_relay_aggregation(Some(winner));
            }
            // A proof made before circuit versions is refused by the aggregator. One never posted is
            // proved again rather than replayed; one already posted is left to the relayer's verdict,
            // since it may have landed before the upgrade.
            if pending.circuit.is_none() && !pending.attempted && !pending.rebuild {
                pending.rebuild = true;
                self.save_relay_attempt(attempts.len() - 1, pending.clone())?;
            }
            if pending.rebuild {
                if attempts.len() >= MAX_RELAY_AGGREGATION_ATTEMPTS {
                    return Err(RsSdkCurvyAdapterError::RelayAttemptLimit);
                }
                rebuild().await?;
                rebuilt = true;
                continue;
            }
            let relay = self.relay.as_ref().ok_or_else(|| {
                RsSdkCurvyAdapterError::InvalidValue(
                    "configure the relayer to recover the pending aggregation".to_owned(),
                )
            })?;
            let index = attempts.len() - 1;
            let lookup = if let Some(id) = &pending.request_id {
                match relay.status(id).await {
                    // The intent may outlive the request-id lookup. Consult it before proving again.
                    Err(error @ relayer::RelayError::MissingRequest(_)) => relay
                        .by_intent(&pending.intent, pending.chain_id)
                        .await
                        .and_then(|found| found.map(Some).ok_or(error)),
                    result => result.map(Some),
                }
            } else if pending.attempted {
                relay.by_intent(&pending.intent, pending.chain_id).await
            } else {
                Ok(None)
            };
            let known = match lookup {
                Ok(known) => known,
                Err(error) => {
                    if error.permits_replacement() {
                        pending.rebuild = true;
                        self.save_relay_attempt(index, pending)?;
                        if !rebuilt {
                            continue;
                        }
                    }
                    return Err(error.into());
                }
            };
            let submission = if let Some(known) = known {
                known
            } else {
                // The relayer does not hold it, and a proof without a circuit version cannot be
                // posted again: prove it again.
                let Some(circuit) = pending.circuit else {
                    pending.rebuild = true;
                    self.save_relay_attempt(index, pending)?;
                    continue;
                };
                let was_attempted = pending.attempted;
                pending.attempted = true;
                self.save_relay_attempt(index, pending.clone())?;
                match relay
                    .submit(
                        curvy_abi::RelayAction::Aggregation,
                        pending.chain_id,
                        pending.max_inputs,
                        circuit,
                        &pending.proof,
                        &pending.public_signals,
                        &pending.request_key,
                        &pending.spend_key,
                        &pending.intent,
                    )
                    .await
                {
                    Ok(submission) => submission,
                    Err(error) => {
                        if matches!(error, relayer::RelayError::Rejected(_)) {
                            if !was_attempted && attempts.len() == 1 {
                                self.finish_relay_aggregation(None)?;
                            } else {
                                if was_attempted {
                                    pending.rebuild = true;
                                    self.save_relay_attempt(index, pending)?;
                                } else {
                                    // This candidate's only POST was definitively refused.
                                    // Keep the older uncertain proofs, but do not fill the
                                    // journal with replacements that were never accepted.
                                    let mut current = self.state.lock();
                                    let mut next = current.clone();
                                    next.relay_aggregations.pop();
                                    self.store.save(&next)?;
                                    *current = next;
                                }
                                if !rebuilt {
                                    continue;
                                }
                            }
                        }
                        return Err(error.into());
                    }
                }
            };
            pending.request_id = Some(submission.request_id.clone());
            pending.observe_progress(submission.status, submission.transaction_hash.clone());
            self.save_relay_attempt(index, pending.clone())?;
            let landed = match relay.await_inclusion(submission, self.config.relay_timeout).await {
                Ok(landed) => landed,
                Err(error) => {
                    if error.permits_replacement() {
                        pending.rebuild = true;
                        self.save_relay_attempt(index, pending)?;
                        if !rebuilt {
                            continue;
                        }
                    } else if let relayer::RelayError::Timeout {
                        status,
                        transaction_hash,
                        progressed,
                        ..
                    } = &error
                    {
                        pending.observe_progress(*status, transaction_hash.clone());
                        if *progressed {
                            pending.timeouts_without_progress = 0;
                        }
                        pending.timeouts_without_progress = pending.timeouts_without_progress.saturating_add(1);
                        pending.rebuild = pending.timeouts_without_progress >= MAX_RELAY_TIMEOUTS_WITHOUT_PROGRESS;
                        self.save_relay_attempt(index, pending)?;
                    } else if matches!(error, relayer::RelayError::Failed(_)) {
                        if attempts.len() == 1 {
                            self.finish_relay_aggregation(None)?;
                        } else {
                            // Failure of one candidate says nothing about the other proofs.
                            pending.rebuild = true;
                            self.save_relay_attempt(index, pending)?;
                        }
                    }
                    return Err(error.into());
                }
            };
            pending.observe_progress(landed.status, landed.transaction_hash.clone());
            let transaction_hash = pending.transaction_hash.clone();
            self.save_relay_attempt(index, pending)?;
            // A 409 can refer to an older candidate. Identify the winner by its outputs.
            let attempts = self.state.lock().relay_aggregations.clone();
            let Some(winner) = self.relay_winner(&attempts).await? else {
                return Err(RsSdkCurvyAdapterError::AmbiguousAllocation);
            };
            // Persist metadata before waiting for finality, including a conflict that
            // identified an older candidate whose original POST response was lost.
            let mut winning_attempt = attempts[winner].clone();
            winning_attempt.request_id = Some(landed.request_id);
            winning_attempt.transaction_hash = transaction_hash.or(winning_attempt.transaction_hash);
            self.save_relay_attempt(winner, winning_attempt.clone())?;
            if attempts.len() > 1 {
                self.check_relay_outputs_finalized(&winning_attempt).await?;
            }
            return self.finish_relay_aggregation(Some(winner));
        }
    }

    /// Journals a self-submitted aggregation, then submits it.
    ///
    /// The attempt's inputs and private outputs — and the allocation records — become durable
    /// *before* the SDK broadcasts, so a crash at any later point leaves something to reconcile
    /// against the chain instead of an allocation with no recovery data. A replacement must
    /// preserve the inputs and allocations of the attempts it competes with: that is what lets
    /// the nullifiers guarantee at most one of them lands.
    async fn submit_operator_aggregation(
        &self,
        client: &CurvyClient,
        endpoints: &CurvyChainEndpoints,
        request: curvy_sdk::PixAggregationRequest,
        inputs: &[OwnedNote],
        records: &[StoredAllocation],
    ) -> Result<Vec<TxLedger>, RsSdkCurvyAdapterError> {
        let index = {
            let mut current = self.state.lock();
            let attempt = StoredOperatorAggregation {
                chain_id: endpoints.chain_id,
                aggregator: endpoints.aggregator.clone(),
                inputs: inputs.iter().map(StoredNote::from).collect(),
                change: StoredNote::from(&request.change),
                emitted: request
                    .emitted_notes
                    .iter()
                    .filter(|note| note.amount != Fr::from(0u8))
                    .map(StoredNote::from)
                    .collect(),
                allocation_ids: records.iter().map(|record| record.id).collect(),
            };
            if let Some(previous) = current.operator_aggregations.last()
                && (previous.inputs != attempt.inputs
                    || previous.allocation_ids != attempt.allocation_ids
                    || previous.chain_id != attempt.chain_id
                    || !previous.aggregator.eq_ignore_ascii_case(&attempt.aggregator))
            {
                return Err(RsSdkCurvyAdapterError::InvalidValue(
                    "a replacement aggregation must preserve its deployment, inputs and allocations".to_owned(),
                ));
            }
            if current.operator_aggregations.len() >= MAX_RELAY_AGGREGATION_ATTEMPTS {
                return Err(RsSdkCurvyAdapterError::RelayAttemptLimit);
            }
            let mut next = current.clone();
            next.operator_aggregations.push(attempt);
            self.store.save_update(&next, records, &[])?;
            *current = next;
            current.operator_aggregations.len() - 1
        };
        match client
            .submit_pix_aggregation(request, &self.config.operator_private_key, self.config.route)
            .await
        {
            Ok(result) => {
                if index > 0 {
                    // Earlier attempts spent the same inputs; only a finalized tree rules out a
                    // reorg that lets one of them win after all.
                    let emitted = self.state.lock().operator_aggregations[index].emitted.clone();
                    self.check_outputs_finalized(&emitted).await?;
                }
                self.finish_operator_aggregation(Some(index))?;
                for entry in &result.ledger {
                    tracing::info!(tx = %entry.tx_hash, allocations = records.len(), "aggregated Curvy PIX allocations");
                }
                Ok(result.ledger)
            }
            Err(error) => {
                if curvy_sdk::ambiguous_pix_aggregation(&error).is_none()
                    && curvy_sdk::ambiguous_submission(&error).is_none()
                {
                    // The SDK knows this attempt did not land. Earlier ones still may.
                    self.drop_operator_attempt(index)?;
                }
                Err(error.into())
            }
        }
    }

    /// Settles the journal: `Some(winner)` books that attempt's outputs and completes its
    /// allocations; `None` releases the inputs and forgets the allocations, which is only sound
    /// when no attempt can land.
    fn finish_operator_aggregation(&self, winner: Option<usize>) -> Result<(), RsSdkCurvyAdapterError> {
        let mut current = self.state.lock();
        let Some(attempt) = current.operator_aggregations.get(winner.unwrap_or(0)).cloned() else {
            return Ok(());
        };
        let mut next = current.clone();
        next.operator_aggregations.clear();
        let (completed, remove) = if winner.is_some() {
            next.funding.retain(|note| !attempt.inputs.contains(note));
            if OwnedNote::try_from(&attempt.change)?.amount != Fr::from(0u8) {
                next.funding.push(attempt.change.clone());
            }
            next.pending.extend(attempt.emitted.clone());
            (self.store.completed_allocations(&attempt.allocation_ids)?, Vec::new())
        } else {
            (Vec::new(), attempt.allocation_ids.clone())
        };
        self.store.save_update(&next, &completed, &remove)?;
        *current = next;
        Ok(())
    }

    /// Forgets one attempt the SDK reported as definitively failed; the last one out also
    /// releases the inputs and allocations.
    fn drop_operator_attempt(&self, index: usize) -> Result<(), RsSdkCurvyAdapterError> {
        if self.state.lock().operator_aggregations.len() == 1 {
            return self.finish_operator_aggregation(None);
        }
        let mut current = self.state.lock();
        let mut next = current.clone();
        next.operator_aggregations.remove(index);
        self.store.save(&next)?;
        *current = next;
        Ok(())
    }

    /// Resolves a journalled self-submitted aggregation before anything else spends funding.
    ///
    /// An attempt whose outputs the chain knows is the winner and is booked. When none is
    /// known — the process stopped after journalling, before or after broadcast — a replacement
    /// is proved over the same inputs and allocations and submitted: if an earlier copy is still
    /// on its way, the two share nullifiers and only one can land, and the journal keeps both
    /// sets of outputs until the chain says which. Called with the chain lock held.
    async fn reconcile_operator_aggregation(&self) -> Result<(), RsSdkCurvyAdapterError> {
        self.reconcile_operator_aggregation_with(|| async { self.retry_operator_aggregation().await.map(|_| ()) })
            .await
    }

    async fn reconcile_operator_aggregation_with<F, Fut>(&self, retry: F) -> Result<(), RsSdkCurvyAdapterError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(), RsSdkCurvyAdapterError>>,
    {
        let attempts = self.state.lock().operator_aggregations.clone();
        if attempts.is_empty() {
            return Ok(());
        }
        let (_, endpoints) = self.client().await?;
        if attempts.iter().any(|attempt| {
            endpoints.chain_id != attempt.chain_id || !endpoints.aggregator.eq_ignore_ascii_case(&attempt.aggregator)
        }) {
            return Err(RsSdkCurvyAdapterError::InvalidValue(
                "pending aggregation belongs to another deployment".to_owned(),
            ));
        }
        for (index, attempt) in attempts.iter().enumerate() {
            if self.notes_known(&attempt.emitted).await? {
                if attempts.len() > 1 {
                    self.check_outputs_finalized(&attempt.emitted).await?;
                }
                self.finish_operator_aggregation(Some(index))?;
                tracing::info!(
                    allocations = attempt.allocation_ids.len(),
                    "a journalled Curvy PIX aggregation landed"
                );
                return self.recover_pending().await.map(|_| ());
            }
        }
        if attempts.len() >= MAX_RELAY_AGGREGATION_ATTEMPTS {
            return Err(RsSdkCurvyAdapterError::RelayAttemptLimit);
        }
        retry().await
    }

    /// Proves and submits a replacement for the journalled aggregation, over its inputs.
    async fn retry_operator_aggregation(&self) -> Result<Vec<TxLedger>, RsSdkCurvyAdapterError> {
        let pending = self
            .state
            .lock()
            .operator_aggregations
            .last()
            .cloned()
            .ok_or(RsSdkCurvyAdapterError::AmbiguousAllocation)?;
        let inputs = pending
            .inputs
            .iter()
            .map(OwnedNote::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let records = pending
            .allocation_ids
            .iter()
            .map(|id| {
                self.store.allocation(id)?.ok_or_else(|| {
                    RsSdkCurvyAdapterError::InvalidValue("missing prepared allocation record".to_owned())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let allocations = records
            .iter()
            .map(StoredAllocation::prover_allocation)
            .collect::<Result<Vec<_>, RsSdkCurvyAdapterError>>()?;
        let (client, endpoints) = self.client().await?;
        let fee_recipient = self.fee_recipient().await?;
        tracing::info!(
            attempts = self.state.lock().operator_aggregations.len(),
            "no journalled Curvy PIX aggregation landed; proving a replacement over the same inputs"
        );
        let request = client
            .build_pix_aggregation(&self.spender, &inputs, &allocations, None, fee_recipient.as_ref())
            .await?;
        let mut ledger = self
            .submit_operator_aggregation(client, endpoints, request, &inputs, &records)
            .await?;
        ledger.extend(self.recover_pending().await?);
        Ok(ledger)
    }

    /// Records an intent before submitting under it, and clears it once the outcome is known.
    fn journal_intent(&self, intent: &str, action: &str, spend_key: &str) -> Result<(), RsSdkCurvyAdapterError> {
        let mut state = self.state.lock();
        state.relay_intents.push(StoredRelayIntent {
            intent: intent.to_owned(),
            action: action.to_owned(),
            spend_key: spend_key.to_owned(),
        });
        self.store.save(&state)
    }

    fn clear_intent(&self, intent: &str) -> Result<(), RsSdkCurvyAdapterError> {
        let mut state = self.state.lock();
        state.relay_intents.retain(|stored| stored.intent != intent);
        self.store.save(&state)
    }

    /// Submits a proof through the relayer and waits for it to land.
    ///
    /// The intent id is ours and is journalled first, so a lost response is recoverable: the
    /// relayer can be asked what became of that intent even though we never saw a `requestId`.
    #[allow(clippy::too_many_arguments)]
    async fn relay_submit(
        &self,
        relay: &RelayClient,
        chain_id: u64,
        action: curvy_abi::RelayAction,
        max_inputs: usize,
        circuit: CircuitRef,
        proof: &curvy_abi::curvy_types::Groth16Proof,
        public_signals: &[String],
        request_key: &str,
        spend_key: &str,
    ) -> Result<(), RsSdkCurvyAdapterError> {
        let intent = uuid_v4();
        self.journal_intent(&intent, action.as_str(), spend_key)?;
        let submitted = relay
            .submit(
                action,
                chain_id,
                max_inputs,
                circuit,
                proof,
                public_signals,
                request_key,
                spend_key,
                &intent,
            )
            .await;
        let submission = match submitted {
            Ok(submission) => submission,
            Err(error) => {
                // The submission may still have arrived, so ask by intent before deciding.
                match relay.by_intent(&intent, chain_id).await {
                    Ok(Some(recovered)) => recovered,
                    // Definitively never arrived: nothing was spent, so the intent is noise.
                    Ok(None) => {
                        self.clear_intent(&intent)?;
                        return Err(relay_error(error));
                    }
                    // Could not tell. Leave the intent journalled for the next start to resolve.
                    Err(_) => return Err(relay_error(error)),
                }
            }
        };
        let outcome = relay
            .await_inclusion(submission, self.config.relay_timeout)
            .await
            .map_err(relay_error);
        match outcome {
            Ok(landed) => {
                tracing::info!(
                    tx = landed.transaction_hash.as_deref().unwrap_or("<unreported>"),
                    action = action.as_str(),
                    "the Curvy relayer submitted a PIX proof"
                );
                self.clear_intent(&intent)?;
                Ok(())
            }
            // Deliberately keeps the intent: a timeout is not a refusal, and the submission may
            // land after we stop watching.
            Err(error) => Err(error),
        }
    }

    async fn allocate_all(
        &self,
        deposits: &[(PixAddressId, BjjPublicKey, CurvyScanPublicKey, HoprBalance)],
    ) -> Result<Vec<TxLedger>, RsSdkCurvyAdapterError> {
        let _chain = self.chain.lock().await;
        let (client, endpoints) = self.client().await?;
        // Reconciliation resumes an aggregation an earlier run may have broadcast, and a rebuild
        // re-proves one it may still land. Whatever the error, it is not a pre-submission
        // refusal, so it is tagged as such rather than read as fund-free.
        self.reconcile_relay_aggregation().await.map_err(tag_after_submission)?;
        let ambiguous = self.state.lock().ambiguous_allocation;
        if ambiguous && !self.reconcile_ambiguous_allocation().await? {
            return Err(RsSdkCurvyAdapterError::AmbiguousAllocation);
        }
        self.reconcile_operator_aggregation()
            .await
            .map_err(tag_after_submission)?;
        let (deposits, completed_earlier) = {
            // Every journal has been reconciled above, so a prepared record none of them names
            // was never submitted: its preparation was interrupted before the attempt was
            // journalled. It is prepared again rather than blocking the allocation for good.
            let journalled = {
                let state = self.state.lock();
                state
                    .relay_aggregations
                    .iter()
                    .flat_map(|attempt| attempt.allocation_ids.iter())
                    .chain(
                        state
                            .operator_aggregations
                            .iter()
                            .flat_map(|attempt| attempt.allocation_ids.iter()),
                    )
                    .chain(state.ambiguous_allocation_ids.iter())
                    .copied()
                    .collect::<std::collections::HashSet<_>>()
            };
            let mut pending = Vec::new();
            let mut completed_earlier = false;
            for (id, address, scan_key, amount) in deposits {
                if let Some(existing) = self.store.allocation(&id_bytes(id))? {
                    if !existing.matches(address, *scan_key, *amount) {
                        return Err(RsSdkCurvyAdapterError::ConflictingAllocation);
                    }
                    match existing.stage {
                        StoredAllocationStage::Completed => {
                            completed_earlier = true;
                            continue;
                        }
                        StoredAllocationStage::Prepared if journalled.contains(&existing.id) => {
                            return Err(RsSdkCurvyAdapterError::AmbiguousAllocation);
                        }
                        StoredAllocationStage::Prepared => {
                            tracing::info!(allocation = ?id, "re-preparing an allocation that was never submitted");
                        }
                    }
                }
                pending.push((*id, *address, *scan_key, *amount));
            }
            (pending, completed_earlier)
        };
        let mut receipts = self.recover_pending().await?;
        // Whether any aggregation has been submitted (or reconciled) ahead of the current chunk.
        // Once true, no later error proves the call moved no funds: a chunk it follows may land.
        //
        // A deposit that is already `Completed` counts as well. `allocate` re-runs the whole batch
        // after tree lag, so this can be the retry of a call whose first chunk landed; its
        // deposits are skipped here, but the caller fans a failure out to every deposit it handed
        // in, and would refund theirs.
        let mut submitted = !receipts.is_empty() || completed_earlier;
        for chunk in deposits.chunks(MAX_ALLOCATIONS_PER_PROOF) {
            let chunk_result = self.allocate_chunk(client, endpoints, chunk).await;
            // A failure here may follow an aggregation a previous chunk (or this one, before the
            // failure) already submitted, so it does not prove the call moved no funds.
            let chunk_result =
                chunk_result.map_err(|error| if submitted { tag_after_submission(error) } else { error });
            submitted = true;
            receipts.extend(chunk_result?);
        }
        Ok(receipts)
    }

    /// Allocates one chunk, the body of [`Self::allocate_all`]'s loop.
    async fn allocate_chunk(
        &self,
        client: &CurvyClient,
        endpoints: &CurvyChainEndpoints,
        chunk: &[(PixAddressId, BjjPublicKey, CurvyScanPublicKey, HoprBalance)],
    ) -> Result<Vec<TxLedger>, RsSdkCurvyAdapterError> {
        let mut receipts = Vec::new();
        {
            // A relayed aggregation carries a gas-reimbursement note for the relayer's operator;
            // a self-submitted one pays its own gas and carries none.
            let relay_fee = match (self.config.submission, self.relay.as_ref()) {
                (CurvySubmission::Relayer, Some(relay)) => {
                    Self::relay_fee_recipient(relay, endpoints.chain_id, self.token().await?).await?
                }
                (CurvySubmission::Relayer, None) => {
                    return Err(RsSdkCurvyAdapterError::InvalidValue(
                        "relayed submission was selected but the pool was built without a relayer".to_owned(),
                    ));
                }
                (CurvySubmission::Operator, _) => None,
            };
            let fee_recipient = self.fee_recipient().await?;

            let allocations = chunk
                .iter()
                .map(|(_id, address, scan_key, amount)| {
                    let amount = balance_u128(*amount)?;
                    Ok((StoredAllocation::recipient(address, *scan_key)?, amount))
                })
                .collect::<Result<Vec<_>, RsSdkCurvyAdapterError>>()?;
            let total = allocations.iter().try_fold(0_u128, |total, (_, amount)| {
                total
                    .checked_add(*amount)
                    .ok_or_else(|| RsSdkCurvyAdapterError::InvalidValue("allocation total overflows u128".to_owned()))
            })?;
            let minimum = client
                .pix_minimum_input(&Fr::from(self.token().await?), total, 0)
                .await?;
            let funding = {
                let state = self.state.lock();
                let mut candidates = state
                    .funding
                    .iter()
                    .map(|stored| {
                        let note = OwnedNote::try_from(stored)?;
                        let amount = fr_to_biguint(&note.amount).try_into().map_err(|_| {
                            RsSdkCurvyAdapterError::InvalidValue("funding amount does not fit u128".to_owned())
                        })?;
                        Ok((stored.clone(), note, amount))
                    })
                    .collect::<Result<Vec<(_, _, u128)>, RsSdkCurvyAdapterError>>()?;
                candidates.sort_unstable_by_key(|candidate| std::cmp::Reverse(candidate.2));
                if let Some(single) = candidates.iter().find(|candidate| candidate.2 >= minimum) {
                    vec![single.clone()]
                } else {
                    let selected = candidates.into_iter().take(MAX_ALLOCATION_INPUTS).collect::<Vec<_>>();
                    let available = spendable_total(selected.iter().map(|candidate| candidate.2))?;
                    if available < minimum {
                        return Err(RsSdkCurvyAdapterError::NoFunding { required: minimum });
                    }
                    selected
                }
            };
            let allocation_records = chunk
                .iter()
                .map(|(id, address, scan_key, amount)| StoredAllocation::new(*id, address, *scan_key, *amount))
                .collect::<Result<Vec<_>, _>>()?;
            let funding_notes = funding.iter().map(|(_, note, _)| note.clone()).collect::<Vec<_>>();
            let request = client
                .build_pix_aggregation(
                    &self.spender,
                    &funding_notes,
                    &allocations,
                    relay_fee.as_ref().map(|(identity, amount)| (identity, *amount)),
                    fee_recipient.as_ref(),
                )
                .await?;
            if self.config.submission == CurvySubmission::Relayer {
                self.prepare_relay_aggregation(&request, endpoints, &funding_notes, &allocation_records)?;
                // Past this point the aggregation may have been POSTed: a rebuild inside the
                // reconcile re-proves it and can refuse on a rotated fee key or a re-quoted fee,
                // which looks fund-free but is not. Tagged here because the caller's per-chunk
                // rule only applies from the *second* chunk on. Errors retain the request and
                // its outputs.
                self.reconcile_relay_aggregation().await.map_err(tag_after_submission)?;
            } else {
                receipts.extend(
                    self.submit_operator_aggregation(client, endpoints, request, &funding_notes, &allocation_records)
                        .await?,
                );
            }
            receipts.extend(self.recover_pending().await?);
        }
        Ok(receipts)
    }

    fn owned_note(note: &CommittedCurvyNote) -> Result<OwnedNote, RsSdkCurvyAdapterError> {
        let view_tag: u8 = fr_to_biguint(&note.note.view_tag)
            .try_into()
            .map_err(|_| RsSdkCurvyAdapterError::InvalidValue("note view tag does not fit one byte".to_owned()))?;
        Ok(OwnedNote {
            owner_pub: note.note.owner_pub,
            shared_secret: note.note.shared_secret,
            ephemeral_key: note.note.ephemeral_key,
            view_tag: view_tag.into(),
            amount: note.note.amount,
            token: note.note.token,
        })
    }

    /// Picks the notes to withdraw. Curvy cannot make change on a withdrawal, so a partial
    /// `amount` has to be an exact sum of whole notes.
    ///
    /// The exact subset is searched for rather than taken as a descending prefix: `[7, 5]` for
    /// `5` must pick the `5`, which a greedy prefix never reaches. The search is bounded by
    /// [`MAX_NOTE_SELECTION_STEPS`], because a deposit address holds a handful of notes and an
    /// unbounded subset-sum over a pathological one is not worth stalling a sweep for. When
    /// nothing exact is found, the greedy prefix is still what the error reports.
    ///
    /// Zero-amount notes are left out: the withdrawal refuses them as inputs, and the scan stores
    /// none, but a store written before it may hold some.
    fn select_notes(
        notes: Vec<CommittedCurvyNote>,
        amount: Option<HoprBalance>,
    ) -> Result<Vec<OwnedNote>, RsSdkCurvyAdapterError> {
        let mut notes = notes.iter().map(Self::owned_note).collect::<Result<Vec<_>, _>>()?;
        notes.retain(|note| note.amount != Fr::from(0u8));
        let Some(target) = amount else {
            return Ok(notes);
        };
        let target = balance_u128(target)?;
        notes.sort_by_key(|note| std::cmp::Reverse(fr_to_biguint(&note.amount)));
        let values = notes
            .iter()
            .map(|note| {
                u128::try_from(fr_to_biguint(&note.amount))
                    .map_err(|_| RsSdkCurvyAdapterError::InvalidValue("note amount does not fit u128".to_owned()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let available = values.iter().try_fold(0_u128, |total, value| {
            total
                .checked_add(*value)
                .ok_or_else(|| RsSdkCurvyAdapterError::InvalidValue("note total overflows u128".to_owned()))
        })?;
        if available < target {
            return Err(RsSdkCurvyAdapterError::InsufficientNotes {
                requested: target,
                available,
            });
        }
        if let Some(indices) = exact_note_subset(&values, target, MAX_NOTE_SELECTION_STEPS) {
            let mut notes = notes.into_iter().map(Some).collect::<Vec<_>>();
            return Ok(indices.into_iter().filter_map(|index| notes[index].take()).collect());
        }
        let mut selected = 0_u128;
        for value in &values {
            if selected >= target {
                break;
            }
            selected += value;
        }
        Err(RsSdkCurvyAdapterError::InexactWithdrawal {
            requested: target,
            selected,
        })
    }

    async fn withdraw_notes(
        &self,
        secret: &ScalarSigningKey,
        notes: Vec<OwnedNote>,
        destination: Address,
    ) -> Result<CurvyWithdrawalOutcome, RsSdkCurvyAdapterError> {
        let _chain = self.chain.lock().await;
        let (client, endpoints) = self.client().await?;
        let mut spent_note_ids = Vec::new();
        let mut withdrawn = 0_u128;
        for chunk in notes.chunks(MAX_WITHDRAWAL_INPUTS) {
            let spends = chunk.iter().map(|note| (secret, note)).collect::<Vec<_>>();
            let request = client.build_pix_withdrawal(&spends, &destination.to_string()).await?;
            // No fee note here, unlike an aggregation: the vault reimburses the submitter's gas
            // on chain, which is why the relayer does not price withdrawals at all.
            let amount = match (self.config.submission, self.relay.as_ref()) {
                (CurvySubmission::Relayer, Some(relay)) => {
                    self.relay_submit(
                        relay,
                        endpoints.chain_id,
                        curvy_abi::RelayAction::Withdrawal,
                        request.max_inputs,
                        request.circuit,
                        &request.proof,
                        &request.public_signals,
                        &request.request_key,
                        &request.spend_key,
                    )
                    .await?;
                    tracing::info!(
                        notes = chunk.len(),
                        amount = request.delivered,
                        "relayed a Curvy PIX withdrawal"
                    );
                    request.delivered
                }
                (CurvySubmission::Relayer, None) => {
                    return Err(RsSdkCurvyAdapterError::InvalidValue(
                        "relayed submission was selected but the pool was built without a relayer".to_owned(),
                    ));
                }
                (CurvySubmission::Operator, _) => {
                    let (amount, ledger) = client
                        .submit_pix_withdrawal(&request, &self.config.operator_private_key, self.config.route)
                        .await?;
                    for entry in &ledger {
                        tracing::info!(tx = %entry.tx_hash, notes = chunk.len(), amount, "withdrew Curvy PIX notes");
                    }
                    amount
                }
            };
            withdrawn = withdrawn.saturating_add(amount);
            spent_note_ids.extend(chunk.iter().map(note_id));
        }
        Ok(CurvyWithdrawalOutcome {
            spent_note_ids,
            withdrawn: HoprBalance::from(U256::from(withdrawn)),
        })
    }
}

#[async_trait]
impl<C> CurvySdkAdapter for RsSdkCurvyAdapter<C>
where
    C: BlokliQueryClient + Send + Sync + 'static,
{
    type Error = RsSdkCurvyAdapterError;

    async fn fund(&self, gross: HoprBalance, recovery_address: Address) -> Result<(), Self::Error> {
        self.shield(balance_u128(gross)?, &recovery_address.to_string())
            .await
            .map(|_| ())
    }

    async fn available_balance(&self) -> Result<HoprBalance, Self::Error> {
        // `state.funding` keeps the inputs of an aggregation at full value until its outcome
        // settles, and only then swaps them for the change. What the next allocation will find is
        // the funding without those inputs, and with the journalled change in their place. Not
        // filtered by note status — a note shielded a moment ago is listed before it is committed
        // — which is what the trait documents.
        let mut amounts = {
            let state = self.state.lock();
            let spends = in_flight_spends(&state);
            // The amount alone, as the decimal it is stored in: rebuilding the whole note would
            // convert five field elements per note on every flush, and a note whose other fields
            // do not parse would fail a balance that only needs its amount.
            let amount = |note: &StoredNote| {
                note.amount.parse::<u128>().map_err(|error| {
                    RsSdkCurvyAdapterError::InvalidValue(format!("funding amount does not fit u128: {error}"))
                })
            };
            let mut amounts = state
                .funding
                .iter()
                .filter(|note| !spends.iter().any(|(inputs, _)| inputs.contains(note)))
                .map(amount)
                .collect::<Result<Vec<u128>, _>>()?;
            // Attempts that share their inputs are rivals for one spend: whichever wins leaves at
            // least the smallest change. A change of zero is no note at all.
            let mut changes: Vec<(&[StoredNote], u128)> = Vec::new();
            for (inputs, change) in &spends {
                let change = amount(change)?;
                if change == 0 {
                    continue;
                }
                match changes.iter_mut().find(|(rival, _)| rival == inputs) {
                    Some((_, smallest)) => *smallest = (*smallest).min(change),
                    None => changes.push((inputs, change)),
                }
            }
            amounts.extend(changes.into_iter().map(|(_, change)| change));
            amounts
        };
        // The largest notes are what `allocate_all` picks when no single note suffices.
        amounts.sort_unstable_by_key(|amount| std::cmp::Reverse(*amount));
        Ok(HoprBalance::from(U256::from(spendable_total(amounts)?)))
    }

    async fn allocate(
        &self,
        deposits: Vec<(PixAddressId, BjjPublicKey, CurvyScanPublicKey, HoprBalance)>,
    ) -> Result<(), Self::Error> {
        self.allocate_all(&deposits).await.map(|_| ())
    }

    async fn withdraw(
        &self,
        secret: &ScalarSigningKey,
        notes: Vec<CommittedCurvyNote>,
        dst: Address,
        amount: Option<HoprBalance>,
    ) -> Result<CurvyWithdrawalOutcome, Self::Error> {
        self.withdraw_notes(secret, Self::select_notes(notes, amount)?, dst)
            .await
    }

    async fn chain_state_is_consistent(&self) -> Result<bool, Self::Error> {
        // Take one immutable snapshot without waiting behind proof generation/submission.
        // A pending spend is still from this deployment if its inputs or any candidate's
        // outputs are known. Resolving which candidate won belongs to the funding path.
        let (funding, pending, attempts) = {
            let state = self.state.lock();
            let spends = in_flight_spends(&state);
            (
                state
                    .funding
                    .iter()
                    .filter(|note| !spends.iter().any(|(inputs, _)| inputs.contains(note)))
                    .cloned()
                    .collect::<Vec<_>>(),
                state.pending.clone(),
                state.relay_aggregations.clone(),
            )
        };
        if let Some(first) = attempts.first() {
            let (_, endpoints) = self.client().await?;
            if attempts.iter().any(|attempt| {
                attempt.chain_id != endpoints.chain_id
                    || !attempt.aggregator.eq_ignore_ascii_case(&endpoints.aggregator)
            }) {
                return Ok(false);
            }
            if !self.notes_known(&first.inputs).await? {
                let mut outputs_known = false;
                for attempt in &attempts {
                    if attempt.attempted && self.relay_outputs_known(attempt).await? {
                        outputs_known = true;
                        break;
                    }
                }
                if !outputs_known {
                    return Ok(false);
                }
            }
        }
        if funding.is_empty() && pending.is_empty() {
            return Ok(true);
        }
        let (client, _) = self.client().await?;
        for stored in funding.iter().chain(pending.iter()) {
            let note = OwnedNote::try_from(stored)?;
            if client.note_status(&note.note_id()).await? == 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn reset_chain_state(&self) -> Result<(), Self::Error> {
        let mut state = self.state.lock();
        *state = SdkState {
            sealed_spender: state.sealed_spender.clone(),
            ..Default::default()
        };
        self.store.reset(&state)
    }
}

fn balance_u128(balance: HoprBalance) -> Result<u128, RsSdkCurvyAdapterError> {
    u128::try_from(balance.amount())
        .map_err(|_| RsSdkCurvyAdapterError::InvalidValue(format!("{balance} does not fit u128")))
}

/// Indices of a subset of `values` summing exactly to `target`, or `None` when there is none or
/// the search runs out of `budget` steps.
///
/// `values` must be sorted descending and their total must fit `u128`. Depth-first over
/// include/exclude, pruning a branch as soon as the values left cannot reach the target.
fn exact_note_subset(values: &[u128], target: u128, budget: usize) -> Option<Vec<usize>> {
    fn search(
        values: &[u128],
        suffix: &[u128],
        start: usize,
        remaining: u128,
        steps: &mut usize,
        picked: &mut Vec<usize>,
    ) -> bool {
        if remaining == 0 {
            return true;
        }
        for index in start..values.len() {
            if suffix[index] < remaining || *steps == 0 {
                return false;
            }
            *steps -= 1;
            if values[index] > remaining {
                continue;
            }
            picked.push(index);
            if search(values, suffix, index + 1, remaining - values[index], steps, picked) {
                return true;
            }
            picked.pop();
        }
        false
    }

    // suffix[i] = values[i..].sum(); the trailing zero makes the bound total for every index.
    let mut suffix = vec![0_u128; values.len() + 1];
    for index in (0..values.len()).rev() {
        suffix[index] = suffix[index + 1] + values[index];
    }
    let mut steps = budget;
    let mut picked = Vec::new();
    search(values, &suffix, 0, target, &mut steps, &mut picked).then_some(picked)
}

/// Left-pads a stealth private key to the 64 hex digits the SDK requires.
///
/// `stealth::new_meta` used to print a scalar without its leading zero bytes, so roughly one spend key
/// in 256 and one view key in 48 came out shorter than 32 bytes, and nodes have persisted such keys.
/// `Account::from_meta_keys` parses the spend key as exactly 32 bytes, and from `curvy-core` 0.1.1 on the
/// view key as well — a node then fails to start depending on its random draw. The padding changes the
/// encoding only: the scalar, and so every key derived from it, is the same.
fn full_width_key(key: &str) -> String {
    format!("{key:0>64}")
}

fn note_id(note: &OwnedNote) -> String {
    fr_to_be_32(&note.note_id())
        .iter()
        .fold(String::from("0x"), |mut encoded, byte| {
            let _ = write!(encoded, "{byte:02x}");
            encoded
        })
}

#[cfg(test)]
mod tests {
    /// A shield whose transaction has confirmed.
    fn confirmed_shield() -> Confirmed {
        Confirmed {
            tx: format!("0x{}", "ab".repeat(32)),
        }
    }

    /// The payload the chain API encodes is the note as the SDK prepared it, word for word, and
    /// the same note is what `directShield(note)` would take.
    #[test]
    fn the_direct_shield_payload_is_the_sdk_note() -> anyhow::Result<()> {
        let note = OnchainNote {
            owner_hash: "1".to_owned(),
            token: "2".to_owned(),
            amount: "1000".to_owned(),
            ephemeral_key: ["4".to_owned(), "5".to_owned()],
            view_tag: 6,
        };
        let aggregator = Address::from([0xcc; 20]);
        assert_eq!(
            direct_shield_payload(aggregator, &note)?,
            Erc777Payload::Curvy(CurvyErc777Payload::DirectShield {
                aggregator,
                note: CurvyNote {
                    owner_hash: 1.into(),
                    token: 2.into(),
                    amount: 1000.into(),
                    ephemeral_key: [4.into(), 5.into()],
                    view_tag: 6,
                },
            })
        );
        let mut wide = note.clone();
        wide.view_tag = u64::from(u16::MAX) + 1;
        assert!(
            direct_shield_payload(aggregator, &wide).is_err(),
            "a view tag wider than uint16 is refused"
        );
        Ok(())
    }

    use curvy_core::{field::Fr, witness::Note};
    use hopr_api::{
        ChainKeypair,
        types::{
            crypto::prelude::{BjjKeypair, Bn254Keypair, Keypair},
            crypto_random::Randomizable,
            internal::prelude::HoprPseudonym,
        },
    };

    use super::{super::state::TEST_PASSWORD, *};
    use crate::pix::pools::curvy::{
        OwnedCurvyDeposit,
        detect::{public_key_from_dec, spend_meta_key_dec, view_key_dec},
    };

    type Adapter = RsSdkCurvyAdapter<blokli_client::BlokliClient>;

    /// Funding scattered over more notes than one allocation can spend is not available to it:
    /// three notes of 40 report 80, what the two largest pay, not 120.
    #[tokio::test]
    async fn the_available_balance_is_what_one_allocation_can_draw_on() -> anyhow::Result<()> {
        let state = RedbCurvyDepositState::in_memory()?;
        let server = relayer::http_tests::Server::new(|_, _| panic!("no chain access needed")).await;
        let adapter = test_adapter(&state, server.url.clone())?;
        let note = |amount: u128| StoredNote {
            owner_pub: ["1".to_owned(), "2".to_owned()],
            shared_secret: "3".to_owned(),
            ephemeral_key: ["4".to_owned(), "5".to_owned()],
            view_tag: 6,
            amount: amount.to_string(),
            token: "7".to_owned(),
        };
        let balance = |amount: u128| HoprBalance::from(U256::from(amount));

        adapter.state.lock().funding = vec![note(40), note(40), note(40)];
        assert_eq!(
            adapter.available_balance().await?,
            balance(80),
            "the two largest of three"
        );

        adapter.state.lock().funding = vec![note(40), note(100)];
        assert_eq!(adapter.available_balance().await?, balance(140), "two notes: both");

        adapter.state.lock().funding.clear();
        assert_eq!(adapter.available_balance().await?, balance(0), "no notes: nothing");
        Ok(())
    }

    fn test_adapter(state: &RedbCurvyDepositState, url: Url) -> anyhow::Result<Adapter> {
        test_adapter_with_shielder(state, url, None)
    }

    fn test_adapter_with_shielder(
        state: &RedbCurvyDepositState,
        url: Url,
        shielder: Option<DirectShielder>,
    ) -> anyhow::Result<Adapter> {
        test_adapter_with(state, url, shielder, CurvySubmission::Relayer)
    }

    /// Self-submitting, with no relayer at all.
    fn operator_adapter(state: &RedbCurvyDepositState, url: Url) -> anyhow::Result<Adapter> {
        test_adapter_with(state, url, None, CurvySubmission::Operator)
    }

    fn test_adapter_with(
        state: &RedbCurvyDepositState,
        url: Url,
        shielder: Option<DirectShielder>,
        submission: CurvySubmission,
    ) -> anyhow::Result<Adapter> {
        // Stable full-width keys keep recovery tests independent of random SDK key
        // encodings that can omit leading zero bytes on a subsequent reload.
        let store = RedbCurvySdkStore::new(state)?;
        let mut persisted = store.load()?;
        if store.spender(&persisted)?.is_none() {
            store.set_spender(
                &mut persisted,
                &StoredSpender {
                    k: "01".repeat(32),
                    v: "02".repeat(32),
                },
            )?;
            store.save(&persisted)?;
        }
        let blokli = Arc::new(blokli_client::BlokliClient::new(url.clone(), Default::default()));
        let operator_key = match submission {
            CurvySubmission::Relayer => String::new(),
            CurvySubmission::Operator => format!("0x{}", "11".repeat(32)),
        };
        let config = RsSdkCurvyAdapterConfig::new(operator_key, 4).with_modes(
            CurvyShielding::Direct,
            submission,
            Some(url.clone()),
        );
        let adapter = Adapter::new(
            blokli,
            url.to_string(),
            config,
            Arc::new(|_, _| Box::pin(async { panic!("unexpected funding call") })),
            shielder,
            match submission {
                CurvySubmission::Relayer => Some(Arc::new(RelayClient::new(
                    url.clone(),
                    std::time::Duration::from_secs(2),
                )?)),
                CurvySubmission::Operator => None,
            },
            state,
        )?;
        let endpoints = CurvyChainEndpoints {
            aggregator: format!("0x{}", "01".repeat(20)),
            portal_factory: None,
            vault: format!("0x{}", "02".repeat(20)),
            shield_router: Some(format!("0x{}", "05".repeat(20))),
            token_address: format!("0x{}", "03".repeat(20)),
            chain_id: 100,
        };
        assert!(
            adapter
                .client
                .set((
                    blokli_curvy_client(url.as_str().trim_end_matches('/'), &endpoints, None),
                    endpoints
                ))
                .is_ok()
        );
        Ok(adapter)
    }

    /// A confirmed direct shield is recorded as funding once the aggregator knows its note, and
    /// until then it is waited for, never sent again.
    #[tokio::test]
    async fn a_confirmed_direct_shield_counts_only_once_its_note_is_on_chain() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
        for inner_call_succeeds in [false, true] {
            let state = RedbCurvyDepositState::in_memory()?;
            // Resume a journalled shield, so the test needs no fee quote to prepare one.
            let note = Adapter::owned_note(&fixture(7))?;
            let store = RedbCurvySdkStore::new(&state)?;
            let mut persisted = store.load()?;
            persisted.direct_shield_in_flight = Some(StoredDirectShield {
                note: StoredNote::from(&note),
                gross: "7".to_owned(),
                submission: ShieldSubmission::NotSubmitted,
            });
            store.save(&persisted)?;

            let landed = Arc::new(AtomicBool::new(false));
            let submissions = Arc::new(AtomicUsize::new(0));
            let last_gross = Arc::new(AtomicU64::new(0));
            let server = relayer::http_tests::Server::new({
                let landed = landed.clone();
                move |path, body| {
                    assert_eq!(path, "/graphql");
                    let query = body["query"].as_str().unwrap();
                    if query.contains("curvyVaultToken") {
                        return Some(vault_token_response(&"03".repeat(20)));
                    }
                    assert!(query.contains("curvyNoteStatus"));
                    Some(note_status_response(landed.load(Ordering::SeqCst)))
                }
            })
            .await;
            let shielder: DirectShielder = {
                let landed = landed.clone();
                let submissions = submissions.clone();
                let last_gross = last_gross.clone();
                Arc::new(move |_, _, gross| {
                    submissions.fetch_add(1, Ordering::SeqCst);
                    last_gross.store(gross as u64, Ordering::SeqCst);
                    // The transaction confirms either way; only the inner call differs.
                    landed.store(inner_call_succeeds, Ordering::SeqCst);
                    Box::pin(async { Ok(confirmed_shield()) })
                })
            };
            let adapter = test_adapter_with_shielder(&state, server.url.clone(), Some(shielder.clone()))?;
            let safe = Address::from([9_u8; 20]);

            if inner_call_succeeds {
                adapter.fund(HoprBalance::from(U256::from(7_u8)), safe).await?;
                let stored = store.load()?;
                assert_eq!(stored.funding, vec![StoredNote::from(&note)]);
                assert!(stored.direct_shield_in_flight.is_none(), "the journal is settled");
                assert_eq!(submissions.load(Ordering::SeqCst), 1);

                // Funding adds: a second shield — journalled here in place of preparing one, which
                // would need a fee quote, and picked up by a fresh adapter as after a restart —
                // lands as a second note beside the first, and while it is in flight it is resumed
                // with its journalled amount whatever amount is requested.
                let second = Adapter::owned_note(&fixture(8))?;
                let mut persisted = store.load()?;
                persisted.direct_shield_in_flight = Some(StoredDirectShield {
                    note: StoredNote::from(&second),
                    gross: "7".to_owned(),
                    submission: ShieldSubmission::NotSubmitted,
                });
                store.save(&persisted)?;
                landed.store(false, Ordering::SeqCst);
                let restarted = test_adapter_with_shielder(&state, server.url.clone(), Some(shielder))?;
                restarted.fund(HoprBalance::from(U256::from(8_u8)), safe).await?;
                assert_eq!(
                    last_gross.load(Ordering::SeqCst),
                    7,
                    "the journalled amount is resumed, not the requested one"
                );
                let stored = store.load()?;
                assert_eq!(
                    stored.funding,
                    vec![StoredNote::from(&note), StoredNote::from(&second)],
                    "the second funding is added, not substituted"
                );
                assert_eq!(submissions.load(Ordering::SeqCst), 2);
            } else {
                // Confirmed, and the aggregator does not know the note: never sent again.
                for _ in 0..2 {
                    let error = adapter
                        .fund(HoprBalance::from(U256::from(7_u8)), safe)
                        .await
                        .unwrap_err();
                    assert!(
                        matches!(error, RsSdkCurvyAdapterError::ShieldConfirmedUnindexed { gross: 7, .. }),
                        "{error}"
                    );
                    assert_eq!(
                        submissions.load(Ordering::SeqCst),
                        1,
                        "a confirmed shield is not resent"
                    );
                }
                let stored = store.load()?;
                assert!(stored.funding.is_empty(), "no phantom funding note");
                assert!(
                    matches!(
                        stored.direct_shield_in_flight.map(|shield| shield.submission),
                        Some(ShieldSubmission::Submitted { .. })
                    ),
                    "journalled as confirmed"
                );
                // The aggregator catches up, and the shield settles without a second send.
                landed.store(true, Ordering::SeqCst);
                adapter.fund(HoprBalance::from(U256::from(7_u8)), safe).await?;
                assert_eq!(submissions.load(Ordering::SeqCst), 1);
                assert_eq!(store.load()?.funding, vec![StoredNote::from(&note)]);
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn fee_discovery_failures_do_not_prepare_allocations() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicBool, Ordering};
        for failed_path in ["/relay/paymaster", "/protocol"] {
            let fail = Arc::new(AtomicBool::new(true));
            let queried_chain = Arc::new(AtomicBool::new(false));
            let server = relayer::http_tests::Server::new({
                let fail = fail.clone();
                let queried_chain = queried_chain.clone();
                move |path, _| {
                    if path.starts_with(failed_path) && fail.load(Ordering::SeqCst) {
                        return Some((500, serde_json::json!({"error":"RPC_ERROR"})));
                    }
                    Some(if path.starts_with("/relay/paymaster") {
                        (404, serde_json::Value::Null)
                    } else if path == "/protocol" {
                        (200, serde_json::json!({"data":{"feeCollector":null}}))
                    } else {
                        assert_eq!(path, "/graphql");
                        queried_chain.store(true, Ordering::SeqCst);
                        (500, serde_json::json!({"error":"stop before proving"}))
                    })
                }
            })
            .await;
            let state = RedbCurvyDepositState::in_memory()?;
            let adapter = test_adapter(&state, server.url.clone())?;
            let note = fixture(7);
            let deposits = [(
                note.deposit.id,
                note.deposit.address,
                scan_key("07", "0b")?,
                note.deposit.amount,
            )];
            assert!(adapter.allocate_all(&deposits).await.is_err());
            assert!(adapter.store.allocation(&id_bytes(&note.deposit.id))?.is_none());
            assert!(!queried_chain.load(Ordering::SeqCst));
            fail.store(false, Ordering::SeqCst);
            let result = adapter.allocate_all(&deposits).await;
            assert!(!matches!(result, Err(RsSdkCurvyAdapterError::AmbiguousAllocation)));
            assert!(
                queried_chain.load(Ordering::SeqCst),
                "retry reached preparation with the same allocation ID"
            );
            assert!(adapter.store.allocation(&id_bytes(&note.deposit.id))?.is_none());
        }
        Ok(())
    }

    fn stored_fixture(amount: u64) -> anyhow::Result<StoredAllocation> {
        let note = fixture(amount);
        Ok(StoredAllocation::new(
            note.deposit.id,
            &note.deposit.address,
            scan_key("07", "0b")?,
            note.deposit.amount,
        )?)
    }

    #[test]
    fn persisted_allocations_rebuild_the_original_prover_inputs() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("state.redb");
        let mut expected = Vec::new();
        {
            let state = RedbCurvyDepositState::open(&path, TEST_PASSWORD)?;
            let store = RedbCurvySdkStore::new(&state)?;
            let mut records = Vec::new();
            for (id, spend, view, amount) in [
                (1, "07", "0b", 1u128),
                (2, "0d", "11", (1u128 << 96) + 123),
                (3, "13", "17", u128::MAX),
            ] {
                let note = fixture(id);
                let scan_key = scan_key(spend, view)?;
                let balance = HoprBalance::from(U256::from(amount));
                // Exactly the conversion used by allocate_all, before the database round trip.
                expected.push((
                    id_bytes(&note.deposit.id),
                    StoredAllocation::recipient(&note.deposit.address, scan_key)?,
                    balance_u128(balance)?,
                ));
                records.push(StoredAllocation::new(
                    note.deposit.id,
                    &note.deposit.address,
                    scan_key,
                    balance,
                )?);
            }
            store.save_update(&SdkState::default(), &records, &[])?;
        }
        let state = RedbCurvyDepositState::open(&path, TEST_PASSWORD)?;
        let store = RedbCurvySdkStore::new(&state)?;
        for (id, original, amount) in expected {
            let record = store.allocation(&id)?.unwrap();
            let (restored, restored_amount) = record.prover_allocation()?;
            assert_eq!(restored.owner_pub, original.owner_pub);
            assert_eq!(restored.viewer, original.viewer);
            assert_eq!(restored_amount, amount);
        }
        // A corrupt journal must fail before calling the prover with another recipient/value.
        for field in ["scan_key", "amount"] {
            let mut record = stored_fixture(7)?;
            if field == "scan_key" {
                record.scan_key.clear();
            } else {
                record.amount = U256::MAX.to_string();
            }
            assert!(record.prover_allocation().is_err());
        }
        Ok(())
    }

    #[test]
    fn a_clear_spender_identity_is_sealed_on_load_and_survives_reopening() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("state.redb");
        let (k, v) = ("01".repeat(32), "02".repeat(32));
        {
            let db = RedbCurvyDepositState::open(&path, TEST_PASSWORD)?;
            let store = RedbCurvySdkStore::new(&db)?;
            // What a node wrote before the identity was sealed: the keys in the clear.
            let mut legacy = serde_json::to_value(SdkState::default())?;
            legacy["spender"] = serde_json::json!({ "k": k, "v": v });
            let write = store.db.begin_write()?;
            write
                .open_table(SDK_STATE_TABLE)?
                .insert(SDK_STATE_KEY, serde_json::to_vec(&legacy)?)?;
            write.commit()?;

            let loaded = store.load()?;
            assert!(loaded.legacy_spender.is_none());
            let spender = store.spender(&loaded)?.expect("the identity survived sealing");
            assert_eq!((spender.k, spender.v), (k.clone(), v.clone()));
            let read = store.db.begin_read()?;
            let bytes = read.open_table(SDK_STATE_TABLE)?.get(SDK_STATE_KEY)?.unwrap().value();
            let json = serde_json::from_slice::<serde_json::Value>(&bytes)?;
            assert!(json.get("spender").is_none(), "the clear copy is gone");
            assert!(json.get("sealed_spender").is_some());
            let text = String::from_utf8(bytes)?;
            assert!(
                !text.contains(&k) && !text.contains(&v),
                "the keys are not on disk in the clear"
            );
        }
        let db = RedbCurvyDepositState::open(&path, TEST_PASSWORD)?;
        let store = RedbCurvySdkStore::new(&db)?;
        let spender = store.spender(&store.load()?)?.expect("sealed identity reopens");
        assert_eq!((spender.k, spender.v), (k, v));
        Ok(())
    }

    #[test]
    fn allocation_history_migrates_atomically_and_survives_reopening() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("state.redb");
        let mut completed = stored_fixture(7)?;
        completed.stage = StoredAllocationStage::Completed;
        let prepared = stored_fixture(8)?;
        {
            let db = RedbCurvyDepositState::open(&path, TEST_PASSWORD)?;
            let store = RedbCurvySdkStore::new(&db)?;
            let mut legacy = serde_json::to_value(SdkState::default())?;
            legacy["allocations"] = serde_json::json!([completed, prepared]);
            let write = store.db.begin_write()?;
            write
                .open_table(SDK_STATE_TABLE)?
                .insert(SDK_STATE_KEY, serde_json::to_vec(&legacy)?)?;
            write.commit()?;
            let loaded = store.load()?;
            assert!(loaded.legacy_allocations.is_empty());
            assert_eq!(store.allocation(&completed.id)?, Some(completed.clone()));
            assert_eq!(store.allocation(&prepared.id)?, Some(prepared.clone()));
            let read = store.db.begin_read()?;
            let bytes = read.open_table(SDK_STATE_TABLE)?.get(SDK_STATE_KEY)?.unwrap().value();
            assert!(
                serde_json::from_slice::<serde_json::Value>(&bytes)?
                    .get("allocations")
                    .is_none()
            );
        }
        let db = RedbCurvyDepositState::open(&path, TEST_PASSWORD)?;
        let store = RedbCurvySdkStore::new(&db)?;
        store.load()?;
        assert_eq!(store.allocation(&completed.id)?, Some(completed));
        assert_eq!(store.allocation(&prepared.id)?, Some(prepared));
        Ok(())
    }

    #[test]
    fn saving_active_state_does_not_rewrite_allocation_history() -> anyhow::Result<()> {
        let db = RedbCurvyDepositState::in_memory()?;
        let store = RedbCurvySdkStore::new(&db)?;
        let state = SdkState::default();
        let record = stored_fixture(7)?;
        let records = (0u64..10_000)
            .map(|n| {
                let mut row = record.clone();
                row.id[..8].copy_from_slice(&n.to_be_bytes());
                row.stage = StoredAllocationStage::Completed;
                row
            })
            .collect::<Vec<_>>();
        store.save_update(&state, &records, &[])?;
        store.save(&state)?;
        assert_eq!(store.allocation(&records[0].id)?, Some(records[0].clone()));
        assert_eq!(store.allocation(&records[9999].id)?, Some(records[9999].clone()));
        let read = store.db.begin_read()?;
        let encoded = read.open_table(SDK_STATE_TABLE)?.get(SDK_STATE_KEY)?.unwrap().value();
        assert_eq!(encoded, serde_json::to_vec(&state)?);
        assert!(encoded.len() < 1000);
        Ok(())
    }

    /// An operator attempt journalled with the given inputs, outputs and allocations.
    fn operator_attempt(
        inputs: &[u64],
        change: u64,
        emitted: &[u64],
        allocation_ids: Vec<[u8; PixAddressId::SIZE]>,
    ) -> anyhow::Result<StoredOperatorAggregation> {
        let stored = |amount: u64| -> anyhow::Result<StoredNote> {
            Ok(StoredNote::from(&Adapter::owned_note(&fixture(amount))?))
        };
        Ok(StoredOperatorAggregation {
            chain_id: 100,
            aggregator: format!("0x{}", "01".repeat(20)),
            inputs: inputs.iter().map(|amount| stored(*amount)).collect::<Result<_, _>>()?,
            change: stored(change)?,
            emitted: emitted.iter().map(|amount| stored(*amount)).collect::<Result<_, _>>()?,
            allocation_ids,
        })
    }

    /// A relayed attempt journalled with the given inputs and change.
    fn relay_attempt(inputs: &[u64], change: u64) -> anyhow::Result<StoredRelayAggregation> {
        let stored = |amount: u64| -> anyhow::Result<StoredNote> {
            Ok(StoredNote::from(&Adapter::owned_note(&fixture(amount))?))
        };
        Ok(StoredRelayAggregation {
            intent: "intent".to_owned(),
            chain_id: 100,
            aggregator: format!("0x{}", "01".repeat(20)),
            max_inputs: 2,
            proof: relayer::http_tests::proof(),
            public_signals: vec!["1".to_owned()],
            request_key: "relay".to_owned(),
            spend_key: "0x1".to_owned(),
            inputs: inputs.iter().map(|amount| stored(*amount)).collect::<Result<_, _>>()?,
            change: stored(change)?,
            emitted: Vec::new(),
            allocation_ids: Vec::new(),
            attempted: true,
            request_id: None,
            transaction_hash: None,
            rebuild: false,
            last_status: None,
            timeouts_without_progress: 0,
            circuit: Some(relayer::http_tests::PIX_1),
        })
    }

    /// An adapter whose funding is `amounts`, as notes that are in no way alike.
    async fn adapter_funded_with(
        state: &RedbCurvyDepositState,
        amounts: &[u64],
    ) -> anyhow::Result<(Adapter, relayer::http_tests::Server)> {
        let server = relayer::http_tests::Server::new(|_, _| panic!("no chain access needed")).await;
        let adapter = test_adapter(state, server.url.clone())?;
        adapter.state.lock().funding = amounts
            .iter()
            .map(|amount| Ok(StoredNote::from(&Adapter::owned_note(&fixture(*amount))?)))
            .collect::<anyhow::Result<_>>()?;
        Ok((adapter, server))
    }

    fn base_units(amount: u128) -> HoprBalance {
        HoprBalance::from(U256::from(amount))
    }

    /// The inputs of a relayed spend are still in the funding until it settles, but the next
    /// allocation will not find them: it finds the change, which the policy must see or it skips
    /// the top-up that allocation needs.
    #[tokio::test]
    async fn a_relayed_spend_in_flight_counts_for_its_change() -> anyhow::Result<()> {
        let state = RedbCurvyDepositState::in_memory()?;
        let (adapter, _server) = adapter_funded_with(&state, &[100]).await?;
        assert_eq!(adapter.available_balance().await?, base_units(100));

        adapter.state.lock().relay_aggregations = vec![relay_attempt(&[100], 10)?];
        assert_eq!(adapter.available_balance().await?, base_units(10));

        adapter.state.lock().relay_aggregations.clear();
        assert_eq!(
            adapter.available_balance().await?,
            base_units(100),
            "settled: the list again"
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_operator_spend_in_flight_counts_for_its_change() -> anyhow::Result<()> {
        let state = RedbCurvyDepositState::in_memory()?;
        let (adapter, _server) = adapter_funded_with(&state, &[100]).await?;

        adapter.state.lock().operator_aggregations = vec![operator_attempt(&[100], 10, &[], Vec::new())?];
        assert_eq!(adapter.available_balance().await?, base_units(10));

        adapter.state.lock().operator_aggregations.clear();
        assert_eq!(
            adapter.available_balance().await?,
            base_units(100),
            "settled: the list again"
        );
        Ok(())
    }

    /// Nothing writes an ambiguous set any more, so this is a journal from an earlier version.
    #[tokio::test]
    async fn an_ambiguous_set_from_an_earlier_version_counts_for_its_change() -> anyhow::Result<()> {
        let state = RedbCurvyDepositState::in_memory()?;
        let (adapter, _server) = adapter_funded_with(&state, &[100]).await?;
        let attempt = operator_attempt(&[100], 10, &[], Vec::new())?;

        {
            let mut state = adapter.state.lock();
            state.ambiguous_allocation = true;
            state.ambiguous_inputs = attempt.inputs;
            state.ambiguous_change = Some(attempt.change);
        }
        assert_eq!(adapter.available_balance().await?, base_units(10));

        // A cleared flag with stale fields counts nothing: the inputs are at full value.
        adapter.state.lock().ambiguous_allocation = false;
        assert_eq!(
            adapter.available_balance().await?,
            base_units(100),
            "flag clear: ignored"
        );

        {
            let mut state = adapter.state.lock();
            state.ambiguous_allocation = false;
            state.ambiguous_inputs.clear();
            state.ambiguous_change = None;
        }
        assert_eq!(
            adapter.available_balance().await?,
            base_units(100),
            "settled: the list again"
        );
        Ok(())
    }

    /// Replacement attempts spend the same inputs, and whichever wins leaves at least the smallest
    /// of their changes. Notes the spend does not touch are counted as they are.
    #[tokio::test]
    async fn rival_attempts_at_one_spend_count_for_the_smallest_change() -> anyhow::Result<()> {
        let state = RedbCurvyDepositState::in_memory()?;
        let (adapter, _server) = adapter_funded_with(&state, &[100, 50]).await?;

        adapter.state.lock().relay_aggregations = vec![relay_attempt(&[100], 10)?, relay_attempt(&[100], 8)?];

        assert_eq!(
            adapter.available_balance().await?,
            base_units(58),
            "8 for the spend, 50 untouched"
        );
        Ok(())
    }

    fn prepared_record(
        amount: u64,
    ) -> anyhow::Result<(
        StoredAllocation,
        (PixAddressId, BjjPublicKey, CurvyScanPublicKey, HoprBalance),
    )> {
        let note = fixture(amount);
        let key = scan_key("07", "0b")?;
        let record = StoredAllocation::new(note.deposit.id, &note.deposit.address, key, note.deposit.amount)?;
        Ok((
            record,
            (note.deposit.id, note.deposit.address, key, note.deposit.amount),
        ))
    }

    /// A process that stopped while proving leaves a prepared record and no journal: nothing was
    /// broadcast, so the allocation is prepared again instead of being refused for good.
    #[tokio::test]
    async fn an_interrupted_operator_preparation_is_prepared_again() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicBool, Ordering};
        let reached_chain = Arc::new(AtomicBool::new(false));
        let server = relayer::http_tests::Server::new({
            let reached_chain = reached_chain.clone();
            move |_, _| {
                reached_chain.store(true, Ordering::SeqCst);
                Some((500, serde_json::json!({"error": "stop here"})))
            }
        })
        .await;
        let state = RedbCurvyDepositState::in_memory()?;
        let (record, deposit) = prepared_record(7)?;
        {
            let adapter = operator_adapter(&state, server.url.clone())?;
            adapter.store.save_update(&adapter.state.lock(), &[record], &[])?;
        }
        // Reopened, as after a restart.
        let adapter = operator_adapter(&state, server.url.clone())?;
        let error = adapter.allocate_all(&[deposit]).await.unwrap_err();
        assert!(!matches!(error, RsSdkCurvyAdapterError::AmbiguousAllocation), "{error}");
        assert!(reached_chain.load(Ordering::SeqCst), "went on to price the allocation");
        Ok(())
    }

    /// The attempt, its private outputs and its allocation records are durable before the SDK
    /// sends anything; a definitive failure then releases them again.
    #[tokio::test]
    async fn an_operator_aggregation_is_journalled_before_it_is_broadcast() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicBool, Ordering};
        let state = RedbCurvyDepositState::in_memory()?;
        let store = RedbCurvySdkStore::new(&state)?;
        let (record, _) = prepared_record(7)?;
        let journalled = Arc::new(AtomicBool::new(false));
        let server = relayer::http_tests::Server::new({
            let journalled = journalled.clone();
            let store = RedbCurvySdkStore::new(&state)?;
            let id = record.id;
            move |_, _| {
                // The first thing the SDK does on the way to broadcasting is ask the chain.
                let persisted = store.load().unwrap();
                let recorded = store.allocation(&id).unwrap();
                if persisted.operator_aggregations.len() == 1
                    && recorded.is_some_and(|record| record.stage == StoredAllocationStage::Prepared)
                {
                    journalled.store(true, Ordering::SeqCst);
                }
                Some((500, serde_json::json!({"error": "rejected before broadcast"})))
            }
        })
        .await;
        let adapter = operator_adapter(&state, server.url.clone())?;
        let input = Adapter::owned_note(&fixture(20))?;
        let request = curvy_sdk::PixAggregationRequest {
            proof: relayer::http_tests::proof(),
            public_signals: vec!["1".to_owned()],
            commitment: "0".to_owned(),
            circuit: relayer::http_tests::PIX_1,
            max_inputs: 2,
            allocations: vec![Adapter::owned_note(&fixture(7))?],
            change: Adapter::owned_note(&fixture(13))?,
            relayer: None,
            emitted_notes: vec![Adapter::owned_note(&fixture(7))?],
            request_key: "operator".to_owned(),
            spend_key: "0x1".to_owned(),
        };
        let (client, endpoints) = adapter.client().await?;
        let error = adapter
            .submit_operator_aggregation(client, endpoints, request, &[input], std::slice::from_ref(&record))
            .await
            .unwrap_err();
        assert!(
            journalled.load(Ordering::SeqCst),
            "journalled before the first chain request: {error}"
        );
        let persisted = store.load()?;
        assert!(
            persisted.operator_aggregations.is_empty(),
            "a definitive failure is released"
        );
        assert!(store.allocation(&record.id)?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn a_journalled_operator_aggregation_that_landed_is_booked_on_restart() -> anyhow::Result<()> {
        let state = RedbCurvyDepositState::in_memory()?;
        let store = RedbCurvySdkStore::new(&state)?;
        let (record, _) = prepared_record(7)?;
        let attempt = operator_attempt(&[20], 13, &[7], vec![record.id])?;
        let mut persisted = store.load()?;
        persisted.funding = attempt.inputs.clone();
        persisted.operator_aggregations = vec![attempt.clone()];
        store.save_update(&persisted, std::slice::from_ref(&record), &[])?;

        let known = attempt.emitted.clone();
        let server =
            relayer::http_tests::Server::new(move |_, body| Some(recovery_chain_response(&body, &known, true))).await;
        let adapter = operator_adapter(&state, server.url.clone())?;
        adapter
            .reconcile_operator_aggregation_with(|| async { panic!("a landed attempt is not replaced") })
            .await?;
        let persisted = store.load()?;
        assert_eq!(persisted.funding, vec![attempt.change], "inputs spent, change booked");
        assert!(persisted.operator_aggregations.is_empty());
        assert_eq!(
            store.allocation(&record.id)?.unwrap().stage,
            StoredAllocationStage::Completed
        );
        Ok(())
    }

    /// Nothing landed: whether the process stopped before or after broadcast is unknowable, so a
    /// replacement over the same inputs is proved, and the earlier outputs are kept meanwhile.
    #[tokio::test]
    async fn a_journalled_operator_aggregation_that_did_not_land_is_replaced_over_the_same_inputs() -> anyhow::Result<()>
    {
        let state = RedbCurvyDepositState::in_memory()?;
        let store = RedbCurvySdkStore::new(&state)?;
        let (record, _) = prepared_record(7)?;
        let attempt = operator_attempt(&[20], 13, &[7], vec![record.id])?;
        let mut persisted = store.load()?;
        persisted.funding = attempt.inputs.clone();
        persisted.operator_aggregations = vec![attempt.clone()];
        store.save_update(&persisted, std::slice::from_ref(&record), &[])?;

        let server = relayer::http_tests::Server::new(|_, body| Some(recovery_chain_response(&body, &[], true))).await;
        let adapter = operator_adapter(&state, server.url.clone())?;
        let retried = std::sync::atomic::AtomicBool::new(false);
        let error = adapter
            .reconcile_operator_aggregation_with(|| async {
                retried.store(true, std::sync::atomic::Ordering::SeqCst);
                Err(RsSdkCurvyAdapterError::AmbiguousAllocation)
            })
            .await
            .unwrap_err();
        assert!(matches!(error, RsSdkCurvyAdapterError::AmbiguousAllocation));
        assert!(retried.load(std::sync::atomic::Ordering::SeqCst));
        let persisted = store.load()?;
        assert_eq!(
            persisted.operator_aggregations.len(),
            1,
            "the earlier outputs stay journalled"
        );
        assert_eq!(persisted.funding, attempt.inputs, "the inputs stay reserved");
        assert_eq!(
            store.allocation(&record.id)?.unwrap().stage,
            StoredAllocationStage::Prepared
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_replacement_keeps_the_earlier_attempt() -> anyhow::Result<()> {
        let server = relayer::http_tests::Server::new(|_, _| panic!("no chain access needed")).await;
        let state = RedbCurvyDepositState::in_memory()?;
        let adapter = operator_adapter(&state, server.url.clone())?;
        let (record, _) = prepared_record(7)?;
        let first = operator_attempt(&[20], 13, &[7], vec![record.id])?;
        let second = operator_attempt(&[20], 14, &[7], vec![record.id])?;
        {
            let mut current = adapter.state.lock();
            current.funding = first.inputs.clone();
            current.operator_aggregations = vec![first.clone(), second];
            adapter
                .store
                .save_update(&current, std::slice::from_ref(&record), &[])?;
        }
        adapter.drop_operator_attempt(1)?;
        let persisted = adapter.store.load()?;
        assert_eq!(persisted.operator_aggregations.len(), 1);
        assert_eq!(persisted.operator_aggregations[0].change, first.change);
        assert!(adapter.store.allocation(&record.id)?.is_some());
        // The last attempt out releases the allocation; the inputs were never spent.
        adapter.drop_operator_attempt(0)?;
        let persisted = adapter.store.load()?;
        assert!(persisted.operator_aggregations.is_empty());
        assert_eq!(persisted.funding, first.inputs);
        assert!(adapter.store.allocation(&record.id)?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn completed_allocations_still_prevent_duplicate_funding() -> anyhow::Result<()> {
        let server = relayer::http_tests::Server::new(|_, _| panic!("a duplicate must make no HTTP requests")).await;
        let state = RedbCurvyDepositState::in_memory()?;
        let adapter = test_adapter(&state, server.url.clone())?;
        let note = fixture(7);
        let key = scan_key("07", "0b")?;
        let mut record = StoredAllocation::new(note.deposit.id, &note.deposit.address, key, note.deposit.amount)?;
        record.stage = StoredAllocationStage::Completed;
        adapter.store.save_update(&adapter.state.lock(), &[record], &[])?;
        let deposits = [(note.deposit.id, note.deposit.address, key, note.deposit.amount)];
        assert!(adapter.allocate_all(&deposits).await?.is_empty());
        let changed = [(
            note.deposit.id,
            note.deposit.address,
            key,
            HoprBalance::from(U256::from(9)),
        )];
        assert!(matches!(
            adapter.allocate_all(&changed).await,
            Err(RsSdkCurvyAdapterError::ConflictingAllocation)
        ));
        Ok(())
    }

    /// The state `allocate` retries into after tree lag: an earlier attempt's first chunk landed,
    /// so its deposits are `Completed`, and the rest of the batch then fails a fund-free check.
    ///
    /// The caller fans that one error out to every deposit it handed in, the landed ones
    /// included, so it must not read as fund-free.
    #[tokio::test]
    async fn a_failure_after_a_landed_chunk_is_not_fund_free() -> anyhow::Result<()> {
        // Prices an allocation at exactly its total, with no fees and no per-token gas, so an
        // empty funding store fails with `NoFunding`.
        let server = relayer::http_tests::Server::new(|path, body| {
            if path != "/graphql" || !body["query"].as_str().unwrap_or_default().contains("curvyVaultFees") {
                return Some((
                    500,
                    serde_json::json!({ "error": format!("unexpected request to {path}") }),
                ));
            }
            Some((
                200,
                serde_json::json!({ "data": {
                    "curvyVaultFees": { "__typename": "CurvyVaultFees", "depositFee": "0", "withdrawalFee": "0" },
                    "curvyAggregatorFees": {
                        "__typename": "CurvyAggregatorFees",
                        "protocolFeePerThousand": "0",
                        "commitmentFeeRoot": "0x01",
                        "feeNotePublicKey": ["1", "2"],
                    },
                    "curvyVaultTokenCount": { "__typename": "CurvyVaultTokenCount", "count": "0" },
                }}),
            ))
        })
        .await;
        let state = RedbCurvyDepositState::in_memory()?;
        let adapter = operator_adapter(&state, server.url.clone())?;
        let key = scan_key("07", "0b")?;
        let deposit = |note: &CommittedCurvyNote| (note.deposit.id, note.deposit.address, key, note.deposit.amount);
        let (landed, rest) = (fixture(7), fixture(8));

        // With nothing completed, the drain is a plain `NoFunding`, which is fund-free.
        let error = adapter.allocate_all(&[deposit(&rest)]).await.unwrap_err();
        assert!(matches!(error, RsSdkCurvyAdapterError::NoFunding { .. }), "{error}");

        let mut record = StoredAllocation::new(landed.deposit.id, &landed.deposit.address, key, landed.deposit.amount)?;
        record.stage = StoredAllocationStage::Completed;
        adapter.store.save_update(&adapter.state.lock(), &[record], &[])?;

        let error = adapter
            .allocate_all(&[deposit(&landed), deposit(&rest)])
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                RsSdkCurvyAdapterError::AfterSubmission {
                    out_of_funding: true,
                    ..
                }
            ),
            "{error}"
        );
        assert!(!crate::pix::pools::curvy::CurvyDepositPoolError::Adapter(error.into()).moved_no_funds());
        Ok(())
    }

    /// `is_pre_submission_refusal` recognises the SDK's validation failures by their text, so each
    /// one is produced here from the SDK in use. A reworded message fails this test rather than
    /// silently turning a fund-free failure into a counted one.
    ///
    /// Every case trips one local check in `build_pix_aggregation`, before it reads the tree; the
    /// fee-key mismatch comes from `fee_note`, which `build_pix_aggregation` calls once proving.
    #[tokio::test]
    async fn the_sdk_pre_submission_refusals_are_still_recognised() -> anyhow::Result<()> {
        let server = relayer::http_tests::Server::new(|path, _| {
            Some((
                500,
                serde_json::json!({ "error": format!("validation reached {path}") }),
            ))
        })
        .await;
        let state = RedbCurvyDepositState::in_memory()?;
        let adapter = operator_adapter(&state, server.url.clone())?;
        let (client, _) = adapter.client().await?;
        let spender = &adapter.spender;
        let own = spender.identity();

        // A valid input and allocation; each case below breaks exactly one thing.
        let mut input = Adapter::owned_note(&fixture(100))?;
        input.owner_pub = spender.bjj_pub;
        input.token = Fr::from(4u64);
        let mut recipient = StoredAllocation::recipient(&fixture(7).deposit.address, scan_key("07", "0b")?)?;
        recipient.owner_pub = (Fr::from(5u64), Fr::from(6u64));
        let allocation = (recipient.clone(), 7u128);

        let zero_input = OwnedNote {
            amount: Fr::from(0u64),
            ..input.clone()
        };
        let other_token = OwnedNote {
            token: Fr::from(9u64),
            ..input.clone()
        };
        let foreign_input = OwnedNote {
            owner_pub: (Fr::from(5u64), Fr::from(6u64)),
            ..input.clone()
        };
        let to_self = (
            curvy_sdk::account::ScanRecipient::new(recipient.viewer.clone(), spender.bjj_pub),
            7u128,
        );

        #[allow(clippy::type_complexity)]
        let cases: Vec<(&str, Vec<OwnedNote>, Vec<_>, Option<(&Identity, u128)>)> = vec![
            (
                "PIX aggregation requires one or two",
                vec![],
                vec![allocation.clone()],
                None,
            ),
            (
                "PIX aggregation requires between one and",
                vec![input.clone()],
                vec![],
                None,
            ),
            (
                "PIX relayer note must carry a non-zero gas reimbursement",
                vec![input.clone()],
                vec![allocation.clone()],
                Some((&own, 0)),
            ),
            (
                "PIX aggregation inputs must have non-zero amounts",
                vec![zero_input],
                vec![allocation.clone()],
                None,
            ),
            (
                "PIX aggregation inputs must use one token",
                vec![input.clone(), other_token],
                vec![allocation.clone()],
                None,
            ),
            (
                "PIX aggregation input is not owned by the funding account",
                vec![foreign_input],
                vec![allocation.clone()],
                None,
            ),
            (
                "PIX allocation amounts must be non-zero",
                vec![input.clone()],
                vec![(recipient.clone(), 0)],
                None,
            ),
            (
                "PIX allocation owner must differ from the funding account",
                vec![input.clone()],
                vec![to_self],
                None,
            ),
            (
                "PIX relayer owner must differ from the funding account",
                vec![input.clone()],
                vec![allocation.clone()],
                Some((&own, 1)),
            ),
        ];
        for (expected, inputs, allocations, relayer) in cases {
            let message = client
                .build_pix_aggregation(spender, &inputs, &allocations, relayer, None)
                .await
                .expect_err(expected)
                .to_string();
            assert!(message.contains(expected), "expected {expected:?}, got {message:?}");
            assert!(super::super::is_pre_submission_refusal(&message), "{message:?}");
        }

        let message = curvy_sdk::send::fee_note(
            Some(&own),
            (Fr::from(5u64), Fr::from(6u64)),
            Fr::from(1u64),
            input.token,
            b"seed",
        )
        .expect_err("a fee note sealed to the wrong collector")
        .to_string();
        assert!(super::super::is_pre_submission_refusal(&message), "{message:?}");
        Ok(())
    }

    fn prepare_recovery_fixture(adapter: &Adapter) -> anyhow::Result<(StoredAllocation, StoredNote)> {
        let record = stored_fixture(7)?;
        let mut input = Adapter::owned_note(&fixture(100))?;
        input.shared_secret = Fr::from(101u64);
        let mut change = input.clone();
        change.amount = Fr::from(90u64);
        change.shared_secret = Fr::from(102u64);
        let allocated = Adapter::owned_note(&fixture(7))?;
        let request = curvy_sdk::PixAggregationRequest {
            proof: relayer::http_tests::proof(),
            public_signals: vec!["1".to_owned()],
            commitment: "0".to_owned(),
            circuit: relayer::http_tests::PIX_1,
            max_inputs: 2,
            allocations: vec![allocated.clone()],
            change: change.clone(),
            relayer: None,
            emitted_notes: vec![allocated, change.clone()],
            request_key: "exact-proof".to_owned(),
            spend_key: "same-inputs".to_owned(),
        };
        {
            let mut state = adapter.state.lock();
            state.funding = vec![StoredNote::from(&input)];
            adapter.store.save(&state)?;
        }
        adapter.prepare_relay_aggregation(
            &request,
            &adapter.client.get().unwrap().1,
            &[input],
            std::slice::from_ref(&record),
        )?;
        Ok((record, StoredNote::from(&change)))
    }

    /// Blokli's answer to `curvyVaultToken`: the vault's token `0x<hex_address>`.
    fn vault_token_response(hex_address: &str) -> (u16, serde_json::Value) {
        let zero = format!("0x{}", "0".repeat(64));
        (
            200,
            serde_json::json!({"data":{"curvyVaultToken":{
                "__typename":"CurvyVaultToken",
                "tokenAddress": format!("0x{hex_address}"),
                "gasFees":{"tokenId":zero,"portalDeployment":zero,"pendingNoteCommitment":zero,"withdrawal":zero}
            }}}),
        )
    }

    fn note_status_response(known: bool) -> (u16, serde_json::Value) {
        (
            200,
            serde_json::json!({"data":{"curvyNoteStatus":{"__typename":"CurvyNoteStatus","status":if known {2} else {0}}}}),
        )
    }

    /// Stand in for the expensive prover while exercising the real recovery state machine.
    fn prepare_replacement_fixture(adapter: &Adapter) -> Result<(), RsSdkCurvyAdapterError> {
        let attempts = adapter.store.load()?.relay_aggregations;
        let previous = attempts.last().unwrap();
        let mut emitted = previous
            .emitted
            .iter()
            .map(OwnedNote::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        for note in &mut emitted {
            note.shared_secret += Fr::from(100u64);
        }
        let mut change = OwnedNote::try_from(&previous.change)?;
        change.shared_secret += Fr::from(100u64);
        let inputs = previous
            .inputs
            .iter()
            .map(OwnedNote::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let records = previous
            .allocation_ids
            .iter()
            .map(|id| Ok(adapter.store.allocation(id)?.unwrap()))
            .collect::<Result<Vec<_>, RsSdkCurvyAdapterError>>()?;
        let request = curvy_sdk::PixAggregationRequest {
            proof: relayer::http_tests::proof(),
            public_signals: vec![attempts.len().to_string()],
            commitment: "0".to_owned(),
            circuit: relayer::http_tests::PIX_1,
            max_inputs: previous.max_inputs,
            allocations: vec![emitted[0].clone()],
            change,
            relayer: None,
            emitted_notes: emitted,
            request_key: format!("replacement-{}", attempts.len()),
            spend_key: previous.spend_key.clone(),
        };
        adapter.prepare_relay_aggregation(&request, &adapter.client.get().unwrap().1, &inputs, &records)
    }

    fn recovery_chain_response(
        body: &serde_json::Value,
        known: &[StoredNote],
        finalized: bool,
    ) -> (u16, serde_json::Value) {
        let query = body["query"].as_str().unwrap();
        let ids = known
            .iter()
            .map(|stored| note_id(&OwnedNote::try_from(stored).unwrap()))
            .collect::<Vec<_>>();
        if query.contains("curvySyncCheckpoint") {
            return (
                200,
                serde_json::json!({"data":{"curvySyncCheckpoint":{
                    "__typename":"CurvySyncCheckpoint", "blockHash":"0x1234", "notesRoot":"0x0",
                    "noteCount":if finalized {ids.len()} else {0}, "treeDepth":30
                }}}),
            );
        }
        if query.contains("curvySyncNotes") {
            let notes = ids
                .iter()
                .enumerate()
                .map(|(index, id)| {
                    serde_json::json!({
                        "leafIndex":index, "noteId":id
                    })
                })
                .collect::<Vec<_>>();
            return (
                200,
                serde_json::json!({"data":{"curvySyncNotes":{
                    "__typename":"CurvySyncNotePage", "checkpoint":"0x1234", "total":notes.len(), "notes":notes
                }}}),
            );
        }
        assert!(query.contains("curvyNoteStatus"));
        note_status_response(
            ids.iter()
                .any(|id| Some(id.as_str()) == body["variables"]["noteId"].as_str()),
        )
    }

    #[tokio::test]
    async fn lost_or_rejected_status_lookups_rebuild_without_losing_either_candidate() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        for failure in ["status404", "status410", "intent400", "poll404", "poll410"] {
            for winner in [0, 1] {
                let state = RedbCurvyDepositState::in_memory()?;
                let store = RedbCurvySdkStore::new(&state)?;
                let notes = Arc::new(parking_lot::Mutex::new(Vec::new()));
                let posts = Arc::new(AtomicUsize::new(0));
                let reads = AtomicUsize::new(0);
                let server = relayer::http_tests::Server::new({
                    let notes = notes.clone();
                    let posts = posts.clone();
                    move |path, body| {
                        if path == "/graphql" {
                            return Some(recovery_chain_response(&body, &notes.lock(), true));
                        }
                        if path.starts_with("/relay/intent/") {
                            return Some((if failure == "intent400" { 400 } else { 404 }, serde_json::Value::Null));
                        }
                        if path == "/relay/submission/original/status" {
                            if failure.starts_with("poll") && reads.fetch_add(1, Ordering::SeqCst) == 0 {
                                return Some((200, serde_json::json!({"requestId":"original", "status":"queued"})));
                            }
                            return Some((
                                if failure.ends_with("410") { 410 } else { 404 },
                                serde_json::Value::Null,
                            ));
                        }
                        assert_eq!(path, "/relay/submit");
                        assert_eq!(posts.fetch_add(1, Ordering::SeqCst), 0);
                        let attempts = store.load().unwrap().relay_aggregations;
                        assert_eq!(attempts.len(), 2);
                        assert!(attempts.iter().all(|attempt| attempt.attempted));
                        assert_eq!(attempts[0].inputs, attempts[1].inputs);
                        assert_eq!(attempts[0].allocation_ids, attempts[1].allocation_ids);
                        assert_eq!(body["spendKey"], attempts[0].spend_key);
                        *notes.lock() = attempts[winner].emitted.clone();
                        Some((
                            if winner == 0 { 409 } else { 200 },
                            serde_json::json!({
                                "requestId":"winner", "status":"included", "transactionHash":"0xabc"
                            }),
                        ))
                    }
                })
                .await;
                let adapter = test_adapter(&state, server.url.clone())?;
                let (record, _) = prepare_recovery_fixture(&adapter)?;
                {
                    let mut current = adapter.state.lock();
                    let attempt = &mut current.relay_aggregations[0];
                    attempt.attempted = true;
                    if failure != "intent400" {
                        attempt.request_id = Some("original".into());
                    }
                    adapter.store.save(&current)?;
                }
                let builds = AtomicUsize::new(0);
                let outcome = adapter
                    .reconcile_relay_aggregation_with(|| async {
                        builds.fetch_add(1, Ordering::SeqCst);
                        prepare_replacement_fixture(&adapter)
                    })
                    .await?
                    .unwrap();
                assert_eq!(builds.load(Ordering::SeqCst), 1);
                assert_eq!(posts.load(Ordering::SeqCst), 1);
                assert_eq!(outcome.request_id.as_deref(), Some("winner"));
                assert!(adapter.store.load()?.relay_aggregations.is_empty());
                let completed = adapter.store.allocation(&record.id)?.unwrap();
                assert_eq!(completed.stage, StoredAllocationStage::Completed);
                assert!(notes.lock().contains(&adapter.store.load()?.funding[0]));
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_proof_without_a_circuit_version_is_proved_again() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        // Never posted, and posted but unknown to the relayer: neither is posted again.
        for attempted in [false, true] {
            let state = RedbCurvyDepositState::in_memory()?;
            let store = RedbCurvySdkStore::new(&state)?;
            let notes = Arc::new(parking_lot::Mutex::new(Vec::new()));
            let posts = Arc::new(AtomicUsize::new(0));
            let server = relayer::http_tests::Server::new({
                let notes = notes.clone();
                let posts = posts.clone();
                move |path, body| {
                    if path == "/graphql" {
                        return Some(recovery_chain_response(&body, &notes.lock(), true));
                    }
                    if path.starts_with("/relay/intent/") {
                        assert!(attempted);
                        return Some((404, serde_json::json!({"error":"not found"})));
                    }
                    assert_eq!(path, "/relay/submit");
                    assert_eq!(posts.fetch_add(1, Ordering::SeqCst), 0);
                    let attempts = store.load().unwrap().relay_aggregations;
                    // Only the replacement is posted.
                    assert_eq!(attempts.len(), 2);
                    assert!(attempts[0].attempted == attempted && attempts[0].rebuild);
                    assert_eq!(attempts[1].circuit, Some(relayer::http_tests::PIX_1));
                    assert_eq!(body["requestKey"], attempts[1].request_key);
                    assert_eq!(body["circuitFamily"], "pix");
                    *notes.lock() = attempts[1].emitted.clone();
                    Some((
                        200,
                        serde_json::json!({"requestId":"versioned", "status":"included", "transactionHash":"0xabc"}),
                    ))
                }
            })
            .await;
            let adapter = test_adapter(&state, server.url.clone())?;
            prepare_recovery_fixture(&adapter)?;
            {
                let mut current = adapter.state.lock();
                current.relay_aggregations[0].circuit = None;
                current.relay_aggregations[0].attempted = attempted;
                adapter.store.save(&current)?;
            }
            let builds = AtomicUsize::new(0);
            let outcome = adapter
                .reconcile_relay_aggregation_with(|| async {
                    builds.fetch_add(1, Ordering::SeqCst);
                    prepare_replacement_fixture(&adapter)
                })
                .await?
                .unwrap();
            assert_eq!(builds.load(Ordering::SeqCst), 1);
            assert_eq!(posts.load(Ordering::SeqCst), 1);
            assert_eq!(outcome.request_id.as_deref(), Some("versioned"));
        }
        Ok(())
    }

    #[tokio::test]
    async fn intent_lookup_recovers_a_forgotten_request_without_reproving() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicBool, Ordering};
        let landed = Arc::new(AtomicBool::new(false));
        let server = relayer::http_tests::Server::new({
            let landed = landed.clone();
            move |path, _| {
                Some(if path == "/graphql" {
                    note_status_response(landed.load(Ordering::SeqCst))
                } else if path.starts_with("/relay/intent/") {
                    landed.store(true, Ordering::SeqCst);
                    (200, serde_json::json!({"requestId":"recovered", "status":"included"}))
                } else {
                    assert_eq!(path, "/relay/submission/original/status");
                    (404, serde_json::Value::Null)
                })
            }
        })
        .await;
        let state = RedbCurvyDepositState::in_memory()?;
        let adapter = test_adapter(&state, server.url.clone())?;
        prepare_recovery_fixture(&adapter)?;
        {
            let mut current = adapter.state.lock();
            current.relay_aggregations[0].attempted = true;
            current.relay_aggregations[0].request_id = Some("original".into());
            adapter.store.save(&current)?;
        }
        let outcome = adapter
            .reconcile_relay_aggregation_with(|| async { panic!("intent lookup should recover the existing proof") })
            .await?
            .unwrap();
        assert_eq!(outcome.request_id.as_deref(), Some("recovered"));
        assert!(adapter.store.load()?.relay_aggregations.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn operational_relayer_errors_never_trigger_replacement() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        for phase in ["status", "intent", "post", "poll"] {
            for code in [401, 403, 429] {
                let reads = AtomicUsize::new(0);
                let server = relayer::http_tests::Server::new(move |path, _| {
                    if path == "/graphql" {
                        return Some(note_status_response(false));
                    }
                    if phase == "post" && path.starts_with("/relay/intent/") {
                        return Some((404, serde_json::Value::Null));
                    }
                    if phase == "poll" && reads.fetch_add(1, Ordering::SeqCst) == 0 {
                        return Some((200, serde_json::json!({"requestId":"saved", "status":"queued"})));
                    }
                    Some((code, serde_json::json!({"error":"operational error"})))
                })
                .await;
                let state = RedbCurvyDepositState::in_memory()?;
                let adapter = test_adapter(&state, server.url.clone())?;
                prepare_recovery_fixture(&adapter)?;
                {
                    let mut current = adapter.state.lock();
                    let attempt = &mut current.relay_aggregations[0];
                    attempt.attempted = true;
                    if matches!(phase, "status" | "poll") {
                        attempt.request_id = Some("saved".into());
                    }
                    attempt.last_status = Some(relayer::RelayStatus::Queued);
                    adapter.store.save(&current)?;
                }
                let before = serde_json::to_value(adapter.store.load()?)?;
                let error = adapter
                    .reconcile_relay_aggregation_with(|| async {
                        panic!("access and rate-limit errors must not trigger proving")
                    })
                    .await
                    .unwrap_err();
                assert!(matches!(
                    error,
                    RsSdkCurvyAdapterError::Relay(
                        relayer::RelayError::AccessDenied(_) | relayer::RelayError::RateLimited(_)
                    )
                ));
                assert_eq!(serde_json::to_value(adapter.store.load()?)?, before);
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn forgotten_replacements_stop_after_one_new_proof_per_call() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let builds = AtomicUsize::new(0);
        let server = relayer::http_tests::Server::new(|path, _| {
            Some(if path == "/graphql" {
                note_status_response(false)
            } else if path == "/relay/submit" {
                (
                    200,
                    serde_json::json!({"requestId":"forgotten-again", "status":"queued"}),
                )
            } else {
                (404, serde_json::Value::Null)
            })
        })
        .await;
        let state = RedbCurvyDepositState::in_memory()?;
        let adapter = test_adapter(&state, server.url.clone())?;
        prepare_recovery_fixture(&adapter)?;
        {
            let mut current = adapter.state.lock();
            current.relay_aggregations[0].attempted = true;
            current.relay_aggregations[0].request_id = Some("original".into());
            adapter.store.save(&current)?;
        }
        let error = adapter
            .reconcile_relay_aggregation_with(|| async {
                builds.fetch_add(1, Ordering::SeqCst);
                prepare_replacement_fixture(&adapter)
            })
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            RsSdkCurvyAdapterError::Relay(relayer::RelayError::MissingRequest(_))
        ));
        assert_eq!(builds.load(Ordering::SeqCst), 1);
        let attempts = adapter.store.load()?.relay_aggregations;
        assert_eq!(attempts.len(), 2);
        assert!(attempts.iter().all(|attempt| attempt.rebuild));
        Ok(())
    }

    #[tokio::test]
    async fn stalled_requests_rebuild_after_bounded_timeouts_and_survive_restart() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("state.redb");
        let mut state = RedbCurvyDepositState::open(&path, TEST_PASSWORD)?;
        let database = Arc::new(parking_lot::Mutex::new(Some(state.shared_database())));
        let sealer = state.sealer();
        let progress = Arc::new(AtomicUsize::new(0));
        let posts = Arc::new(AtomicUsize::new(0));
        let notes = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let server = relayer::http_tests::Server::new({
            let database = database.clone();
            let sealer = sealer.clone();
            let progress = progress.clone();
            let posts = posts.clone();
            let notes = notes.clone();
            move |route, body| {
                if route == "/graphql" {
                    return Some(recovery_chain_response(&body, &notes.lock(), true));
                }
                if route == "/relay/submit" {
                    posts.fetch_add(1, Ordering::SeqCst);
                    let store = RedbCurvySdkStore {
                        db: database.lock().as_ref().unwrap().clone(),
                        sealer: sealer.clone(),
                    };
                    let attempts = store.load().unwrap().relay_aggregations;
                    assert_eq!(attempts.len(), 2);
                    assert!(attempts.iter().all(|attempt| attempt.attempted));
                    *notes.lock() = attempts[1].emitted.clone();
                    return Some((200, serde_json::json!({"requestId":"replacement", "status":"included"})));
                }
                assert_eq!(route, "/relay/submission/original/status");
                Some((
                    200,
                    match progress.load(Ordering::SeqCst) {
                        0 => serde_json::json!({"requestId":"original", "status":"queued"}),
                        1 => serde_json::json!({"requestId":"original", "status":"submitted", "transactionHash":"0xa"}),
                        _ => serde_json::json!({"requestId":"original", "status":"submitted", "transactionHash":"0xb"}),
                    },
                ))
            }
        })
        .await;
        let mut adapter = test_adapter(&state, server.url.clone())?;
        adapter.config.relay_timeout = std::time::Duration::ZERO;
        let (record, _) = prepare_recovery_fixture(&adapter)?;
        {
            let mut current = adapter.state.lock();
            current.relay_aggregations[0].attempted = true;
            current.relay_aggregations[0].request_id = Some("original".into());
            adapter.store.save(&current)?;
        }
        // Both a changed status and a new transaction hash restart the budget.
        for (phase, timeouts) in [(0, 1), (0, 2), (1, 1), (1, 2), (2, 1), (2, 2), (2, 3)] {
            progress.store(phase, Ordering::SeqCst);
            assert!(matches!(
                adapter
                    .reconcile_relay_aggregation_with(|| async {
                        panic!("a replacement should not be proved before the timeout budget expires")
                    })
                    .await,
                Err(RsSdkCurvyAdapterError::Relay(relayer::RelayError::Timeout { .. }))
            ));
            let durable = adapter.store.load()?;
            assert_eq!(durable.relay_aggregations.len(), 1);
            assert_eq!(durable.relay_aggregations[0].timeouts_without_progress, timeouts);
            assert_eq!(
                durable.relay_aggregations[0].rebuild,
                timeouts == MAX_RELAY_TIMEOUTS_WITHOUT_PROGRESS
            );
            assert_eq!(durable.funding, durable.relay_aggregations[0].inputs);
            assert_eq!(
                adapter.store.allocation(&record.id)?.unwrap().stage,
                StoredAllocationStage::Prepared
            );
            *database.lock() = None;
            drop(adapter);
            drop(state);
            state = RedbCurvyDepositState::open(&path, TEST_PASSWORD)?;
            *database.lock() = Some(state.shared_database());
            adapter = test_adapter(&state, server.url.clone())?;
            adapter.config.relay_timeout = std::time::Duration::ZERO;
        }
        assert_eq!(posts.load(Ordering::SeqCst), 0);
        let outcome = adapter
            .reconcile_relay_aggregation_with(|| async { prepare_replacement_fixture(&adapter) })
            .await?
            .unwrap();
        assert_eq!(outcome.request_id.as_deref(), Some("replacement"));
        assert_eq!(posts.load(Ordering::SeqCst), 1);
        assert!(adapter.store.load()?.relay_aggregations.is_empty());
        assert_eq!(
            adapter.store.allocation(&record.id)?.unwrap().stage,
            StoredAllocationStage::Completed
        );
        Ok(())
    }

    #[tokio::test]
    async fn finality_checks_return_promptly_back_off_and_keep_all_outputs_until_finalized() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let mode = Arc::new(AtomicUsize::new(0));
        let snapshots = Arc::new(AtomicUsize::new(0));
        let notes = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let server = relayer::http_tests::Server::new({
            let mode = mode.clone();
            let snapshots = snapshots.clone();
            let notes = notes.clone();
            move |route, body| {
                assert_eq!(route, "/graphql", "finality never needs the relayer");
                if body["query"].as_str().unwrap().contains("curvySyncCheckpoint") {
                    snapshots.fetch_add(1, Ordering::SeqCst);
                    if mode.load(Ordering::SeqCst) == 0 {
                        return Some((
                            200,
                            serde_json::json!({"data":{"curvySyncCheckpoint":{
                                "__typename":"QueryFailedError", "code":"NOT_FOUND", "message":"no checkpoint yet"
                            }}}),
                        ));
                    }
                    if mode.load(Ordering::SeqCst) == 3 {
                        return Some((
                            200,
                            serde_json::json!({"errors":[{
                                "message":"Cannot query field curvySyncCheckpoint"
                            }]}),
                        ));
                    }
                }
                Some(recovery_chain_response(
                    &body,
                    &notes.lock(),
                    mode.load(Ordering::SeqCst) == 2,
                ))
            }
        })
        .await;
        let state = RedbCurvyDepositState::in_memory()?;
        let adapter = test_adapter(&state, server.url.clone())?;
        prepare_recovery_fixture(&adapter)?;
        {
            let mut current = adapter.state.lock();
            current.relay_aggregations[0].attempted = true;
            current.relay_aggregations[0].rebuild = true;
            adapter.store.save(&current)?;
        }
        prepare_replacement_fixture(&adapter)?;
        {
            let mut current = adapter.state.lock();
            current.relay_aggregations[1].attempted = true;
            *notes.lock() = current.relay_aggregations[1].emitted.clone();
            adapter.store.save(&current)?;
        }
        let before = serde_json::to_value(adapter.store.load()?)?;
        for (index, phase) in [0, 1, 3].into_iter().enumerate() {
            mode.store(phase, Ordering::SeqCst);
            // Simulate the next scheduled retry without making this test sleep for five seconds.
            *adapter.next_relay_finality_check.lock() = Some(tokio::time::Instant::now());
            let error = tokio::time::timeout(std::time::Duration::from_secs(1), adapter.allocate_all(&[]))
                .await?
                .unwrap_err();
            if phase == 0 {
                assert!(matches!(error, RsSdkCurvyAdapterError::RelayFinalityUnavailable(_)));
                assert!(error.to_string().contains("no finalized checkpoint"));
            } else if phase == 1 {
                assert!(matches!(error, RsSdkCurvyAdapterError::RelayFinalityPending));
            } else {
                assert!(matches!(error, RsSdkCurvyAdapterError::Sdk(_)));
                assert!(error.to_string().contains("Cannot query field curvySyncCheckpoint"));
            }
            assert!(
                adapter.chain.try_lock().is_ok(),
                "funding calls release the chain lock between checks"
            );
            for _ in 0..3 {
                assert!(matches!(
                    adapter.allocate_all(&[]).await,
                    Err(RsSdkCurvyAdapterError::RelayFinalityPending)
                ));
            }
            assert_eq!(snapshots.load(Ordering::SeqCst), index + 1);
            assert_eq!(serde_json::to_value(adapter.store.load()?)?, before);
        }
        mode.store(2, Ordering::SeqCst);
        *adapter.next_relay_finality_check.lock() = Some(tokio::time::Instant::now());
        adapter.reconcile_relay_aggregation().await?;
        assert_eq!(snapshots.load(Ordering::SeqCst), 4);
        assert!(adapter.store.load()?.relay_aggregations.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn rejected_replays_preserve_both_attempts_until_either_winner_is_finalized() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        for (winner, lost_replacement_response) in [(0, false), (1, false), (0, true), (1, true)] {
            let dir = tempfile::tempdir()?;
            let path = dir.path().join("state.redb");
            let state = RedbCurvyDepositState::open(&path, TEST_PASSWORD)?;
            let database = Arc::new(parking_lot::Mutex::new(Some(state.shared_database())));
            let sealer = state.sealer();
            let chain_notes = Arc::new(parking_lot::Mutex::new(Vec::new()));
            let finalized = Arc::new(AtomicBool::new(false));
            let sent = Arc::new(parking_lot::Mutex::new(Vec::new()));
            let builds = AtomicUsize::new(0);
            let server = relayer::http_tests::Server::new({
                let database = database.clone();
                let sealer = sealer.clone();
                let chain_notes = chain_notes.clone();
                let finalized = finalized.clone();
                let sent = sent.clone();
                move |route, body| {
                    if route == "/graphql" {
                        return Some(recovery_chain_response(
                            &body,
                            &chain_notes.lock(),
                            finalized.load(Ordering::SeqCst),
                        ));
                    }
                    if route.starts_with("/relay/intent/") {
                        return Some((404, serde_json::Value::Null));
                    }
                    assert_eq!(route, "/relay/submit");
                    let mut sent = sent.lock();
                    sent.push(body);
                    match sent.len() {
                        1 => None,
                        2 => Some((400, serde_json::json!({"error":"fee note below the new minimum"}))),
                        3 => {
                            // Every candidate's private outputs are durable before sending its proof.
                            let store = RedbCurvySdkStore {
                                db: database.lock().as_ref().unwrap().clone(),
                                sealer: sealer.clone(),
                            };
                            let durable = store.load().unwrap();
                            assert_eq!(durable.relay_aggregations.len(), 2);
                            let old = &durable.relay_aggregations[0];
                            let new = &durable.relay_aggregations[1];
                            assert!(old.attempted && new.attempted);
                            assert_ne!(old.change, new.change);
                            assert_eq!(old.inputs, new.inputs);
                            assert_eq!(old.allocation_ids, new.allocation_ids);
                            assert_eq!(
                                store.allocation(&old.allocation_ids[0]).unwrap().unwrap().stage,
                                StoredAllocationStage::Prepared
                            );
                            *chain_notes.lock() = durable.relay_aggregations[winner].emitted.clone();
                            if lost_replacement_response {
                                None
                            } else {
                                Some((
                                    if winner == 0 { 409 } else { 200 },
                                    serde_json::json!({
                                        "requestId":"winner", "status":"included", "transactionHash":"0xabc"
                                    }),
                                ))
                            }
                        }
                        _ => panic!("recovery should use chain outputs without further submissions"),
                    }
                }
            })
            .await;
            let mut adapter = test_adapter(&state, server.url.clone())?;
            adapter.config.relay_timeout = std::time::Duration::ZERO;
            let (record, _) = prepare_recovery_fixture(&adapter)?;
            assert!(adapter.reconcile_relay_aggregation().await.is_err());
            let result = adapter
                .reconcile_relay_aggregation_with(|| async {
                    builds.fetch_add(1, Ordering::SeqCst);
                    prepare_replacement_fixture(&adapter)
                })
                .await;
            if lost_replacement_response {
                assert!(matches!(
                    result,
                    Err(RsSdkCurvyAdapterError::Relay(relayer::RelayError::Transport(_)))
                ));
            } else {
                assert!(
                    matches!(result, Err(RsSdkCurvyAdapterError::RelayFinalityPending)),
                    "{result:?}"
                );
            }
            assert_eq!(builds.load(Ordering::SeqCst), 1);
            let durable = adapter.store.load()?;
            assert_eq!(durable.relay_aggregations.len(), 2);
            assert_eq!(durable.funding, durable.relay_aggregations[0].inputs);
            let winning_change = durable.relay_aggregations[winner].change.clone();
            {
                let requests = sent.lock();
                assert_eq!(requests.len(), 3);
                assert_eq!(requests[0], requests[1]);
                assert_eq!(requests[0]["spendKey"], requests[2]["spendKey"]);
                assert_ne!(requests[0]["intentId"], requests[2]["intentId"]);
                assert_ne!(requests[0]["requestKey"], requests[2]["requestKey"]);
            }
            // Closing the database and restarting must preserve the losing candidate too.
            *database.lock() = None;
            drop(adapter);
            drop(state);
            let state = RedbCurvyDepositState::open(&path, TEST_PASSWORD)?;
            *database.lock() = Some(state.shared_database());
            let adapter = test_adapter(&state, server.url.clone())?;
            finalized.store(true, Ordering::SeqCst);
            let outcome = adapter.reconcile_relay_aggregation().await?.unwrap();
            assert_eq!(outcome.allocations, 1);
            if !lost_replacement_response {
                assert_eq!(outcome.request_id.as_deref(), Some("winner"));
                assert_eq!(outcome.transaction_hash.as_deref(), Some("0xabc"));
            }
            assert_eq!(adapter.store.load()?.funding, vec![winning_change]);
            assert!(adapter.store.load()?.relay_aggregations.is_empty());
            assert_eq!(
                adapter.store.allocation(&record.id)?.unwrap().stage,
                StoredAllocationStage::Completed
            );
            assert!(adapter.reconcile_relay_aggregation().await?.is_none());
            assert_eq!(adapter.store.load()?.funding.len(), 1);
        }
        Ok(())
    }

    #[tokio::test]
    async fn consistency_checks_neither_wait_for_the_chain_lock_nor_contact_the_relayer() -> anyhow::Result<()> {
        let known = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let server = relayer::http_tests::Server::new({
            let known = known.clone();
            move |path, body| {
                assert_eq!(path, "/graphql", "a consistency check must not contact the relayer");
                Some(recovery_chain_response(&body, &known.lock(), false))
            }
        })
        .await;
        let state = RedbCurvyDepositState::in_memory()?;
        let adapter = test_adapter(&state, server.url.clone())?;
        prepare_recovery_fixture(&adapter)?;
        {
            let mut current = adapter.state.lock();
            current.relay_aggregations[0].attempted = true;
            current.relay_aggregations[0].rebuild = true;
            adapter.store.save(&current)?;
        }
        prepare_replacement_fixture(&adapter)?;
        {
            let mut current = adapter.state.lock();
            current.relay_aggregations[1].attempted = true;
            adapter.store.save(&current)?;
        }
        let before = adapter.store.load()?;
        let _chain = adapter.chain.lock().await;
        for (notes, consistent) in [
            (before.funding.clone(), true),
            (before.relay_aggregations[0].emitted.clone(), true),
            (before.relay_aggregations[1].emitted.clone(), true),
            (Vec::new(), false),
        ] {
            *known.lock() = notes;
            assert_eq!(
                tokio::time::timeout(std::time::Duration::from_secs(1), adapter.chain_state_is_consistent()).await??,
                consistent
            );
        }
        assert_eq!(
            serde_json::to_value(before)?,
            serde_json::to_value(adapter.store.load()?)?
        );
        Ok(())
    }

    #[tokio::test]
    async fn replacement_failure_cannot_release_an_earlier_uncertain_spend() -> anyhow::Result<()> {
        let server = relayer::http_tests::Server::new(|path, _| {
            Some(if path == "/graphql" {
                note_status_response(false)
            } else {
                (
                    200,
                    serde_json::json!({"requestId":"failed-new", "status":"failed", "error":"reverted"}),
                )
            })
        })
        .await;
        let state = RedbCurvyDepositState::in_memory()?;
        let adapter = test_adapter(&state, server.url.clone())?;
        let (record, _) = prepare_recovery_fixture(&adapter)?;
        {
            let mut current = adapter.state.lock();
            current.relay_aggregations[0].attempted = true;
            current.relay_aggregations[0].rebuild = true;
            adapter.store.save(&current)?;
        }
        let original = adapter.store.load()?.funding;
        assert!(matches!(
            adapter
                .reconcile_relay_aggregation_with(|| async { prepare_replacement_fixture(&adapter) })
                .await,
            Err(RsSdkCurvyAdapterError::Relay(relayer::RelayError::Failed(_)))
        ));
        let durable = adapter.store.load()?;
        assert_eq!(durable.funding, original);
        assert_eq!(durable.relay_aggregations.len(), 2);
        assert_eq!(
            adapter.store.allocation(&record.id)?.unwrap().stage,
            StoredAllocationStage::Prepared
        );
        Ok(())
    }

    #[tokio::test]
    async fn first_rejections_of_replacements_do_not_accumulate_or_erase_uncertain_attempts() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let posts = Arc::new(AtomicUsize::new(0));
        let server = relayer::http_tests::Server::new({
            let posts = posts.clone();
            move |path, _| {
                if path == "/graphql" {
                    return Some(note_status_response(false));
                }
                assert_eq!(path, "/relay/submit");
                posts.fetch_add(1, Ordering::SeqCst);
                Some((400, serde_json::json!({"error":"fee still insufficient"})))
            }
        })
        .await;
        let state = RedbCurvyDepositState::in_memory()?;
        let adapter = test_adapter(&state, server.url.clone())?;
        let (record, _) = prepare_recovery_fixture(&adapter)?;
        {
            let mut current = adapter.state.lock();
            current.relay_aggregations[0].attempted = true;
            current.relay_aggregations[0].rebuild = true;
            adapter.store.save(&current)?;
        }
        let before = serde_json::to_value(adapter.store.load()?)?;
        for _ in 0..3 {
            assert!(matches!(
                adapter
                    .reconcile_relay_aggregation_with(|| async { prepare_replacement_fixture(&adapter) })
                    .await,
                Err(RsSdkCurvyAdapterError::Relay(relayer::RelayError::Rejected(_)))
            ));
            assert_eq!(serde_json::to_value(adapter.store.load()?)?, before);
            assert_eq!(
                adapter.store.allocation(&record.id)?.unwrap().stage,
                StoredAllocationStage::Prepared
            );
        }
        assert_eq!(posts.load(Ordering::SeqCst), 3, "at most one new proof per invocation");
        Ok(())
    }

    #[tokio::test]
    async fn replacement_fee_discovery_failure_keeps_the_original_recovery_journal() -> anyhow::Result<()> {
        let server = relayer::http_tests::Server::new(|path, _| {
            Some(if path == "/graphql" {
                note_status_response(false)
            } else {
                assert!(path.starts_with("/relay/paymaster"));
                (503, serde_json::json!({"error":"quote unavailable"}))
            })
        })
        .await;
        let state = RedbCurvyDepositState::in_memory()?;
        let adapter = test_adapter(&state, server.url.clone())?;
        prepare_recovery_fixture(&adapter)?;
        {
            let mut current = adapter.state.lock();
            current.relay_aggregations[0].attempted = true;
            current.relay_aggregations[0].rebuild = true;
            adapter.store.save(&current)?;
        }
        let before = serde_json::to_value(adapter.store.load()?)?;
        assert!(matches!(
            adapter.reconcile_relay_aggregation().await,
            Err(RsSdkCurvyAdapterError::Relay(relayer::RelayError::Transport(_)))
        ));
        assert_eq!(serde_json::to_value(adapter.store.load()?)?, before);
        Ok(())
    }

    #[tokio::test]
    async fn reaching_the_attempt_limit_preserves_every_candidate() -> anyhow::Result<()> {
        let server = relayer::http_tests::Server::new(|path, _| {
            assert_eq!(path, "/graphql");
            Some(note_status_response(false))
        })
        .await;
        let state = RedbCurvyDepositState::in_memory()?;
        let adapter = test_adapter(&state, server.url.clone())?;
        prepare_recovery_fixture(&adapter)?;
        for index in 0..MAX_RELAY_AGGREGATION_ATTEMPTS {
            {
                let mut current = adapter.state.lock();
                current.relay_aggregations[index].attempted = true;
                current.relay_aggregations[index].rebuild = true;
                adapter.store.save(&current)?;
            }
            if index + 1 < MAX_RELAY_AGGREGATION_ATTEMPTS {
                prepare_replacement_fixture(&adapter)?;
            }
        }
        let before = serde_json::to_value(adapter.store.load()?)?;
        assert!(matches!(
            adapter.reconcile_relay_aggregation().await,
            Err(RsSdkCurvyAdapterError::RelayAttemptLimit)
        ));
        assert_eq!(serde_json::to_value(adapter.store.load()?)?, before);
        Ok(())
    }

    #[tokio::test]
    async fn legacy_single_attempt_journals_load_without_losing_outputs() -> anyhow::Result<()> {
        let server = relayer::http_tests::Server::new(|_, _| panic!("no network needed")).await;
        let state = RedbCurvyDepositState::in_memory()?;
        let adapter = test_adapter(&state, server.url.clone())?;
        prepare_recovery_fixture(&adapter)?;
        let mut encoded = serde_json::to_value(adapter.store.load()?)?;
        let attempts = encoded.as_object_mut().unwrap().remove("relay_aggregations").unwrap();
        let mut legacy = attempts[0].clone();
        legacy.as_object_mut().unwrap().remove("rebuild");
        legacy.as_object_mut().unwrap().remove("transaction_hash");
        legacy.as_object_mut().unwrap().remove("last_status");
        legacy.as_object_mut().unwrap().remove("timeouts_without_progress");
        legacy.as_object_mut().unwrap().remove("circuit");
        encoded["relay_aggregation"] = legacy;
        let write = adapter.store.db.begin_write()?;
        write
            .open_table(SDK_STATE_TABLE)?
            .insert(SDK_STATE_KEY, serde_json::to_vec(&encoded)?)?;
        write.commit()?;
        let recovered = adapter.store.load()?;
        assert_eq!(recovered.relay_aggregations.len(), 1);
        assert_eq!(
            recovered.relay_aggregations[0].change,
            adapter.state.lock().relay_aggregations[0].change
        );
        assert!(!recovered.relay_aggregations[0].rebuild);
        assert!(recovered.relay_aggregations[0].circuit.is_none());
        assert_eq!(recovered.relay_aggregations[0].timeouts_without_progress, 0);
        assert!(recovered.relay_aggregations[0].last_status.is_none());
        adapter.store.save(&recovered)?;
        assert_eq!(adapter.store.load()?.relay_aggregations.len(), 1);
        encoded["relay_aggregation"] = serde_json::Value::Null;
        assert!(
            serde_json::from_value::<SdkState>(encoded)?
                .relay_aggregations
                .is_empty()
        );
        Ok(())
    }

    #[tokio::test]
    async fn relayed_aggregations_recover_after_uncertain_responses_and_restart() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicBool, Ordering};
        for failure in ["lost_post", "poll_error", "timeout", "missing_intent"] {
            let recovering = Arc::new(AtomicBool::new(false));
            let landed = Arc::new(AtomicBool::new(false));
            let requests = Arc::new(parking_lot::Mutex::new(Vec::new()));
            let server = relayer::http_tests::Server::new({
                let recovering = recovering.clone();
                let landed = landed.clone();
                let requests = requests.clone();
                move |path, body| {
                    if path == "/graphql" {
                        return Some(note_status_response(landed.load(Ordering::SeqCst)));
                    }
                    if path == "/relay/submit" {
                        requests.lock().push(body);
                        if recovering.load(Ordering::SeqCst) {
                            landed.store(true, Ordering::SeqCst);
                            return Some((200, serde_json::json!({"requestId":"saved","status":"included"})));
                        }
                        if failure == "lost_post" || failure == "missing_intent" {
                            return None;
                        }
                        return Some((200, serde_json::json!({"requestId":"saved","status":"queued"})));
                    }
                    if recovering.load(Ordering::SeqCst) {
                        if failure == "missing_intent" && path.starts_with("/relay/intent/") {
                            return Some((404, serde_json::Value::Null));
                        }
                        landed.store(true, Ordering::SeqCst);
                        return Some((200, serde_json::json!({"requestId":"saved","status":"included"})));
                    }
                    Some((500, serde_json::json!({"error":"temporarily unavailable"})))
                }
            })
            .await;
            let dir = tempfile::tempdir()?;
            let path = dir.path().join("state.redb");
            let state = RedbCurvyDepositState::open(&path, TEST_PASSWORD)?;
            let mut adapter = test_adapter(&state, server.url.clone())?;
            if failure == "timeout" {
                adapter.config.relay_timeout = std::time::Duration::ZERO;
            }
            let (record, change) = prepare_recovery_fixture(&adapter)?;
            let before = adapter.store.load()?.relay_aggregations.into_iter().next().unwrap();
            assert!(!before.attempted);
            let result = adapter.reconcile_relay_aggregation().await;
            assert!(
                matches!(result, Err(RsSdkCurvyAdapterError::Relay(_))),
                "{failure}: {result:?}"
            );
            let durable = adapter.store.load()?;
            let pending = durable.relay_aggregations.into_iter().next().unwrap();
            assert_eq!(pending.change, change);
            assert_eq!(pending.intent, before.intent);
            assert_eq!(pending.inputs, durable.funding);
            assert_eq!(
                adapter.store.allocation(&record.id)?.unwrap().stage,
                StoredAllocationStage::Prepared
            );
            drop(adapter);
            drop(state);

            // The restarted process loads every output before checking status or retransmitting.
            recovering.store(true, Ordering::SeqCst);
            let state = RedbCurvyDepositState::open(&path, TEST_PASSWORD)?;
            let adapter = test_adapter(&state, server.url.clone())?;
            adapter.reconcile_relay_aggregation().await?;
            let recovered = adapter.store.load()?;
            assert!(recovered.relay_aggregations.is_empty());
            assert_eq!(recovered.funding, vec![change]);
            assert_eq!(
                adapter.store.allocation(&record.id)?.unwrap().stage,
                StoredAllocationStage::Completed
            );
            adapter.reconcile_relay_aggregation().await?;
            assert_eq!(adapter.store.load()?.funding, recovered.funding);
            let sent = requests.lock();
            if failure == "missing_intent" {
                assert_eq!(sent.len(), 2);
                assert_eq!(sent[0], sent[1]);
            } else {
                assert_eq!(sent.len(), 1);
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn relayed_aggregation_is_durable_before_post_and_recovers_without_the_relayer() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicBool, Ordering};
        let state = RedbCurvyDepositState::in_memory()?;
        let landed = Arc::new(AtomicBool::new(false));
        let server = relayer::http_tests::Server::new({
            let db = state.shared_database();
            let sealer = state.sealer();
            let landed = landed.clone();
            move |path, _| {
                if path == "/graphql" {
                    return Some(note_status_response(landed.load(Ordering::SeqCst)));
                }
                let store = RedbCurvySdkStore {
                    db: db.clone(),
                    sealer: sealer.clone(),
                };
                let pending = store.load().unwrap().relay_aggregations.into_iter().next().unwrap();
                assert!(pending.attempted);
                assert!(!pending.inputs.is_empty());
                assert!(!pending.emitted.is_empty());
                assert_eq!(
                    store.allocation(&pending.allocation_ids[0]).unwrap().unwrap().stage,
                    StoredAllocationStage::Prepared
                );
                // The transaction lands, but the process gets no response to save.
                landed.store(true, Ordering::SeqCst);
                None
            }
        })
        .await;
        let adapter = test_adapter(&state, server.url.clone())?;
        let (_, change) = prepare_recovery_fixture(&adapter)?;
        assert!(adapter.reconcile_relay_aggregation().await.is_err());
        drop(adapter);
        let adapter = test_adapter(&state, server.url.clone())?;
        adapter.reconcile_relay_aggregation().await?;
        assert_eq!(adapter.store.load()?.funding, vec![change]);
        Ok(())
    }

    #[tokio::test]
    async fn relayed_conflict_with_other_outputs_never_replaces_funding() -> anyhow::Result<()> {
        let server = relayer::http_tests::Server::new(|path, _| {
            Some(if path == "/graphql" {
                note_status_response(false)
            } else {
                (
                    if path == "/relay/submit" { 409 } else { 200 },
                    serde_json::json!({"requestId":"other","status":"included"}),
                )
            })
        })
        .await;
        let state = RedbCurvyDepositState::in_memory()?;
        let adapter = test_adapter(&state, server.url.clone())?;
        let (record, _) = prepare_recovery_fixture(&adapter)?;
        let original = adapter.store.load()?.funding;
        assert!(matches!(
            adapter.reconcile_relay_aggregation().await,
            Err(RsSdkCurvyAdapterError::AmbiguousAllocation)
        ));
        assert!(adapter.store.load()?.relay_aggregations.len() == 1);
        assert_eq!(adapter.store.load()?.funding, original);
        assert_eq!(
            adapter.store.allocation(&record.id)?.unwrap().stage,
            StoredAllocationStage::Prepared
        );
        // A new operation must stop at recovery rather than reusing the old inputs.
        assert!(matches!(
            adapter.allocate_all(&[]).await,
            Err(RsSdkCurvyAdapterError::AmbiguousAllocation)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn relayed_initial_rejection_releases_prepared_allocations() -> anyhow::Result<()> {
        let server =
            relayer::http_tests::Server::new(|_, _| Some((400, serde_json::json!({"error":"invalid proof"})))).await;
        let state = RedbCurvyDepositState::in_memory()?;
        let adapter = test_adapter(&state, server.url.clone())?;
        let (record, _) = prepare_recovery_fixture(&adapter)?;
        let original = adapter.store.load()?.funding;
        assert!(matches!(
            adapter.reconcile_relay_aggregation().await,
            Err(RsSdkCurvyAdapterError::Relay(relayer::RelayError::Rejected(_)))
        ));
        assert!(adapter.store.load()?.relay_aggregations.is_empty());
        assert!(adapter.store.allocation(&record.id)?.is_none());
        assert_eq!(adapter.store.load()?.funding, original);
        Ok(())
    }

    #[tokio::test]
    async fn relayed_terminal_failure_releases_inputs_without_losing_funding() -> anyhow::Result<()> {
        let server = relayer::http_tests::Server::new(|_, _| {
            Some((
                200,
                serde_json::json!({"requestId":"failed","status":"failed","error":"transaction reverted"}),
            ))
        })
        .await;
        let state = RedbCurvyDepositState::in_memory()?;
        let adapter = test_adapter(&state, server.url.clone())?;
        let (record, _) = prepare_recovery_fixture(&adapter)?;
        let original = adapter.store.load()?.funding;
        assert!(matches!(
            adapter.reconcile_relay_aggregation().await,
            Err(RsSdkCurvyAdapterError::Relay(relayer::RelayError::Failed(_)))
        ));
        assert!(adapter.store.load()?.relay_aggregations.is_empty());
        assert!(adapter.store.allocation(&record.id)?.is_none());
        assert_eq!(adapter.store.load()?.funding, original);
        Ok(())
    }

    #[tokio::test]
    async fn legacy_relay_metadata_cannot_be_silently_discarded() -> anyhow::Result<()> {
        let server = relayer::http_tests::Server::new(|_, _| panic!("legacy recovery must fail before spending")).await;
        let state = RedbCurvyDepositState::in_memory()?;
        let adapter = test_adapter(&state, server.url.clone())?;
        adapter.journal_intent("legacy", "aggregation", "inputs")?;
        assert!(matches!(
            adapter.reconcile_relay_aggregation().await,
            Err(RsSdkCurvyAdapterError::IncompleteRelayRecovery)
        ));
        assert_eq!(adapter.store.load()?.relay_intents.len(), 1);
        Ok(())
    }

    #[test]
    fn portal_signer_is_required_independently_of_submission_mode() {
        for shielding in [CurvyShielding::Direct, CurvyShielding::Portal] {
            for submission in [CurvySubmission::Operator, CurvySubmission::Relayer] {
                let needs_key = shielding == CurvyShielding::Portal || submission == CurvySubmission::Operator;
                for key in [
                    "",
                    "invalid",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                ] {
                    let cfg = RsSdkCurvyAdapterConfig::new(key.to_owned(), 3).with_modes(shielding, submission, None);
                    assert_eq!(cfg.validate_signer().is_err(), needs_key);
                }
                let cfg = RsSdkCurvyAdapterConfig::new("01".repeat(32), 3).with_modes(shielding, submission, None);
                assert!(cfg.validate_signer().is_ok());
            }
        }
    }

    #[test]
    fn the_gateway_fee_collector_becomes_a_sealing_identity() -> anyhow::Result<()> {
        // Curvy staging's `/protocol` fee collector, whose owner key is the Gnosis aggregator's
        // `feeNotePublicKey`.
        let keys = relayer::CurvyPublicKeys {
            spend_public_key: "98196467739045737361624042364526845165893723256538881225564237194894305749964.\
                               85819546747324778252702861357825104568382762224457080263515028979058114370157"
                .to_owned(),
            view_public_key: "21579150582945393796432405977169743203548565927228117293904839000735742388195.\
                              2199873391156304912266865805931783414728595814770346143973990126650821750981"
                .to_owned(),
            bjj_public_key: "6696655508272513187635510409223451359447854228192370110374659020120287021020.\
                             14667705991255323606553352965901746640607929945787383727539340760340072797708"
                .to_owned(),
        };
        let identity = stealth_identity(&keys, "the protocol fee collector's key")?;
        assert_eq!(identity.big_k, keys.spend_public_key);
        assert_eq!(identity.big_v, keys.view_public_key);
        assert_eq!(
            identity.bjj_pub.0,
            Bn254Fr::try_from_dec("6696655508272513187635510409223451359447854228192370110374659020120287021020")?
                .into_inner()
        );
        assert_eq!(
            identity.bjj_pub.1,
            Bn254Fr::try_from_dec("14667705991255323606553352965901746640607929945787383727539340760340072797708")?
                .into_inner()
        );

        let error = match stealth_identity(
            &relayer::CurvyPublicKeys {
                bjj_public_key: "not-a-point".to_owned(),
                ..keys
            },
            "the protocol fee collector's key",
        ) {
            Ok(_) => panic!("a key without a dot is not a point"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("the protocol fee collector's key"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn an_intent_id_is_a_v4_uuid() {
        let intent = uuid_v4();
        // The relayer's schema is `z.string().uuid()`, so a malformed id is a 400 before the
        // proof is even looked at.
        assert_eq!(intent.len(), 36, "{intent}");
        let parts = intent.split('-').collect::<Vec<_>>();
        assert_eq!(
            parts.iter().map(|part| part.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12],
            "{intent}"
        );
        assert!(intent.chars().all(|c| c.is_ascii_hexdigit() || c == '-'), "{intent}");
        // Version 4 and the RFC 4122 variant, which a strict parser checks.
        assert_eq!(parts[2].chars().next(), Some('4'), "{intent}");
        assert!(
            matches!(parts[3].chars().next(), Some('8' | '9' | 'a' | 'b')),
            "{intent}"
        );
    }

    #[test]
    fn intent_ids_do_not_repeat() {
        // A repeated intent would make two distinct submissions look like one retry of the same.
        let ids = (0..64).map(|_| uuid_v4()).collect::<std::collections::HashSet<_>>();
        assert_eq!(ids.len(), 64);
    }

    #[test]
    fn committing_is_the_deployments_job_only_when_a_relayer_runs() {
        // The relayer refuses `commitPendingNotes` and its batch-prover does the work, so a
        // relayed node must not also submit them; a self-submitting one has nobody else to do it.
        let relayed = RsSdkCurvyAdapterConfig::new(String::new(), 3).with_modes(
            CurvyShielding::Direct,
            CurvySubmission::Relayer,
            Some("https://api.curvy.box".parse().expect("valid URL")),
        );
        assert!(!relayed.commits_locally());

        let self_submitted = RsSdkCurvyAdapterConfig::new("0xkey".to_owned(), 3);
        assert!(self_submitted.commits_locally());
    }

    #[test]
    fn the_zero_address_is_recognised_in_every_spelling() {
        for zero in [
            "0x0000000000000000000000000000000000000000",
            "0X0000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000",
            "0x0",
        ] {
            assert!(is_zero_address(zero), "{zero} is the zero address");
        }
        for real in [
            "0x0000000000000000000000000000000000000001",
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "",
        ] {
            assert!(!is_zero_address(real), "{real} is not the zero address");
        }
    }

    #[test]
    fn a_portal_less_deployment_refuses_portal_shielding_by_name() {
        let endpoints = CurvyChainEndpoints {
            aggregator: "0x01".to_owned(),
            portal_factory: None,
            vault: "0x02".to_owned(),
            shield_router: None,
            token_address: "0x03".to_owned(),
            chain_id: 100,
        };
        let error = endpoints
            .require_portal_factory()
            .expect_err("a portal-less deployment cannot portal-shield");
        let message = error.to_string();
        // The message has to name the way out, not just the fact of failure: an operator seeing
        // this has picked the wrong mode for their deployment.
        assert!(message.contains("shielding: direct"), "{message}");
    }

    #[test]
    fn a_portal_deployment_hands_back_its_factory() -> anyhow::Result<()> {
        let endpoints = CurvyChainEndpoints {
            aggregator: "0x01".to_owned(),
            portal_factory: Some("0xfac".to_owned()),
            vault: "0x02".to_owned(),
            shield_router: None,
            token_address: "0x03".to_owned(),
            chain_id: 100,
        };
        assert_eq!(endpoints.require_portal_factory()?, "0xfac");
        Ok(())
    }

    #[test]
    fn a_deployment_without_a_router_refuses_direct_shielding_by_name() {
        let endpoints = CurvyChainEndpoints {
            aggregator: "0x01".to_owned(),
            portal_factory: None,
            vault: "0x02".to_owned(),
            shield_router: None,
            token_address: "0x03".to_owned(),
            chain_id: 100,
        };
        let message = endpoints
            .require_shield_router()
            .expect_err("no router, no direct shield")
            .to_string();
        assert!(message.contains("curvy_shield_router"), "{message}");
    }

    /// The two refusals that must happen before the Safe is asked to send anything: no router to
    /// send to, or a note that would name another token than the one being sent.
    #[tokio::test]
    async fn a_direct_shield_is_refused_before_the_safe_sends_anything() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        for (router, vault_token, expected) in [
            (None, "03".repeat(20), "curvy_shield_router"),
            (
                Some(format!("0x{}", "05".repeat(20))),
                "04".repeat(20),
                "token id is wrong",
            ),
        ] {
            let state = RedbCurvyDepositState::in_memory()?;
            let server = relayer::http_tests::Server::new(move |path, body| {
                assert_eq!(path, "/graphql");
                assert!(body["query"].as_str().unwrap().contains("curvyVaultToken"));
                Some(vault_token_response(&vault_token))
            })
            .await;
            let submissions = Arc::new(AtomicUsize::new(0));
            let shielder: DirectShielder = {
                let submissions = submissions.clone();
                Arc::new(move |_, _, _| {
                    submissions.fetch_add(1, Ordering::SeqCst);
                    Box::pin(async { Ok(confirmed_shield()) })
                })
            };
            let mut adapter = test_adapter_with_shielder(&state, server.url.clone(), Some(shielder))?;
            adapter
                .client
                .get_mut()
                .expect("set by the test adapter")
                .1
                .shield_router = router;

            let error = adapter
                .fund(HoprBalance::from(U256::from(7_u8)), Address::from([9_u8; 20]))
                .await
                .unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
            assert_eq!(submissions.load(Ordering::SeqCst), 0, "the Safe sent nothing");
            assert!(
                adapter.store.load()?.direct_shield_in_flight.is_none(),
                "nothing was journalled"
            );
        }
        Ok(())
    }

    /// The bridge with no token id stated. It takes the id from the vault, matching on the Safe's
    /// token it already knows from discovery, and does not then check the answer it was given.
    #[tokio::test]
    async fn an_unstated_token_id_is_resolved_from_the_vault_once() -> anyhow::Result<()> {
        let state = RedbCurvyDepositState::in_memory()?;
        let queries = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let server = relayer::http_tests::Server::new({
            let queries = queries.clone();
            move |path, body| {
                assert_eq!(path, "/graphql");
                let query = body["query"].as_str().unwrap();
                if query.contains("curvyVaultTokenCount") {
                    queries.lock().push("count");
                    return Some((
                        200,
                        serde_json::json!({"data":{"curvyVaultTokenCount":{
                            "__typename":"CurvyVaultTokenCount","count":"2"
                        }}}),
                    ));
                }
                assert!(query.contains("curvyVaultToken"), "{query}");
                queries.lock().push("token");
                // The token the test adapter's Safe holds.
                Some(vault_token_response(&"03".repeat(20)))
            }
        })
        .await;
        let mut adapter = test_adapter_with_shielder(&state, server.url.clone(), None)?;
        adapter.config.token = VaultToken::from_blokli(adapter.blokli.clone());

        assert_eq!(adapter.token().await?, 2);
        let (_, endpoints) = adapter.client().await?;
        adapter.check_vault_token(endpoints).await?;
        assert_eq!(adapter.token().await?, 2);
        assert_eq!(
            *queries.lock(),
            ["count", "token"],
            "one lookup, and no second read to check its own answer"
        );
        Ok(())
    }

    /// A shield journalled by an earlier version landed through the aggregator directly, and the
    /// node now runs against a Blokli that predates the router. Recording it needs no router: the
    /// chain already holds the note, so nothing is sent and nothing is refused.
    #[tokio::test]
    async fn a_landed_shield_is_recorded_without_a_router() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let state = RedbCurvyDepositState::in_memory()?;
        let note = Adapter::owned_note(&fixture(7))?;
        let store = RedbCurvySdkStore::new(&state)?;
        let mut persisted = store.load()?;
        persisted.direct_shield_in_flight = Some(StoredDirectShield {
            note: StoredNote::from(&note),
            gross: "7".to_owned(),
            submission: ShieldSubmission::NotSubmitted,
        });
        store.save(&persisted)?;

        let server = relayer::http_tests::Server::new(move |path, body| {
            assert_eq!(path, "/graphql");
            let query = body["query"].as_str().unwrap();
            assert!(
                query.contains("curvyNoteStatus"),
                "only the note's status is needed to record a landed shield, not {query}"
            );
            Some(note_status_response(true))
        })
        .await;
        let submissions = Arc::new(AtomicUsize::new(0));
        let shielder: DirectShielder = {
            let submissions = submissions.clone();
            Arc::new(move |_, _, _| {
                submissions.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(confirmed_shield()) })
            })
        };
        let mut adapter = test_adapter_with_shielder(&state, server.url.clone(), Some(shielder))?;
        adapter
            .client
            .get_mut()
            .expect("set by the test adapter")
            .1
            .shield_router = None;

        adapter
            .fund(HoprBalance::from(U256::from(7_u8)), Address::from([9_u8; 20]))
            .await?;
        let stored = store.load()?;
        assert_eq!(
            stored.funding,
            vec![StoredNote::from(&note)],
            "the landed shield is the funding note"
        );
        assert!(stored.direct_shield_in_flight.is_none(), "the journal is settled");
        assert_eq!(submissions.load(Ordering::SeqCst), 0, "the Safe sent nothing");
        Ok(())
    }

    /// A shield that is not journalled is a new one, and the requested amount sizes it.
    #[tokio::test]
    async fn a_fresh_direct_shield_sends_the_requested_amount() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        let landed = Arc::new(AtomicBool::new(false));
        let sent_gross = Arc::new(AtomicU64::new(0));
        let server = relayer::http_tests::Server::new({
            let landed = landed.clone();
            move |path, body| {
                assert_eq!(path, "/graphql");
                let query = body["query"].as_str().unwrap();
                if query.contains("curvyVaultFees") {
                    return Some((
                        200,
                        serde_json::json!({ "data": {
                            "curvyVaultFees": { "__typename": "CurvyVaultFees", "depositFee": "0", "withdrawalFee": "0" },
                            "curvyAggregatorFees": {
                                "__typename": "CurvyAggregatorFees",
                                "protocolFeePerThousand": "0",
                                "commitmentFeeRoot": "0x01",
                                "feeNotePublicKey": ["1", "2"],
                            },
                            "curvyVaultTokenCount": { "__typename": "CurvyVaultTokenCount", "count": "0" },
                        }}),
                    ));
                }
                if query.contains("curvyVaultToken") {
                    return Some(vault_token_response(&"03".repeat(20)));
                }
                assert!(query.contains("curvyNoteStatus"), "{query}");
                Some(note_status_response(landed.load(Ordering::SeqCst)))
            }
        })
        .await;
        let shielder: DirectShielder = {
            let landed = landed.clone();
            let sent_gross = sent_gross.clone();
            Arc::new(move |_, _, gross| {
                sent_gross.store(gross as u64, Ordering::SeqCst);
                landed.store(true, Ordering::SeqCst);
                Box::pin(async { Ok(confirmed_shield()) })
            })
        };
        let state = RedbCurvyDepositState::in_memory()?;
        let adapter = test_adapter_with_shielder(&state, server.url.clone(), Some(shielder))?;

        adapter
            .fund(HoprBalance::from(U256::from(100_u8)), Address::from([9_u8; 20]))
            .await?;

        assert_eq!(sent_gross.load(Ordering::SeqCst), 100);
        let stored = RedbCurvySdkStore::new(&state)?.load()?;
        assert_eq!(stored.funding.len(), 1);
        assert!(stored.direct_shield_in_flight.is_none(), "the journal is settled");
        Ok(())
    }

    /// An aggregator that answers note-status reads from `landed` and counts them.
    async fn note_status_server(
        landed: &Arc<std::sync::atomic::AtomicBool>,
        reads: &Arc<std::sync::atomic::AtomicUsize>,
    ) -> relayer::http_tests::Server {
        use std::sync::atomic::Ordering;
        let (landed, reads) = (landed.clone(), reads.clone());
        relayer::http_tests::Server::new(move |path, body| {
            assert_eq!(path, "/graphql");
            let query = body["query"].as_str().unwrap();
            if query.contains("curvyVaultToken") {
                return Some(vault_token_response(&"03".repeat(20)));
            }
            assert!(query.contains("curvyNoteStatus"), "{query}");
            reads.fetch_add(1, Ordering::SeqCst);
            Some(note_status_response(landed.load(Ordering::SeqCst)))
        })
        .await
    }

    /// What a scripted shielder does with one submission.
    #[derive(Clone, Copy)]
    enum Outcome {
        /// Refused before anything was broadcast.
        Refuse,
        /// Mined and failed.
        Revert,
        /// No answer: the note does not land, as far as anyone can tell.
        Unconfirmed,
        /// No answer, after a wait of real time over a second: the call and the outcome differ.
        SlowUnconfirmed,
        /// Confirmed, and the note lands.
        Confirm,
    }

    /// A shielder that counts its submissions and answers each from `script`, then confirms.
    fn scripted_shielder(
        landed: &Arc<std::sync::atomic::AtomicBool>,
        submissions: &Arc<std::sync::atomic::AtomicUsize>,
        script: Vec<Outcome>,
    ) -> DirectShielder {
        use std::sync::atomic::Ordering;
        let (landed, submissions) = (landed.clone(), submissions.clone());
        Arc::new(move |_, _, _| {
            let attempt = submissions.fetch_add(1, Ordering::SeqCst);
            match script.get(attempt).copied().unwrap_or(Outcome::Confirm) {
                Outcome::Refuse => {
                    Box::pin(async { Err(ShieldFailure::NotSubmitted("the Safe holds too little".to_owned())) })
                }
                Outcome::Revert => Box::pin(async {
                    Err(ShieldFailure::Reverted {
                        reason: "reverted".to_owned(),
                    })
                }),
                Outcome::Unconfirmed => {
                    Box::pin(async { Err(ShieldFailure::Unconfirmed("tracking timed out".to_owned())) })
                }
                Outcome::SlowUnconfirmed => Box::pin(async {
                    std::thread::sleep(std::time::Duration::from_millis(1100));
                    Err(ShieldFailure::Unconfirmed("tracking timed out".to_owned()))
                }),
                Outcome::Confirm => {
                    landed.store(true, Ordering::SeqCst);
                    Box::pin(async { Ok(confirmed_shield()) })
                }
            }
        })
    }

    fn journal_direct_shield(
        state: &RedbCurvyDepositState,
        gross: &str,
        submission: Option<ShieldSubmission>,
    ) -> anyhow::Result<(OwnedNote, RedbCurvySdkStore)> {
        let note = Adapter::owned_note(&fixture(7))?;
        let store = RedbCurvySdkStore::new(state)?;
        let mut persisted = store.load()?;
        let mut journal = serde_json::json!({ "note": StoredNote::from(&note), "gross": gross });
        if let Some(submission) = submission {
            journal["submission"] = serde_json::to_value(submission)?;
        }
        // Through JSON, so that a journal without the field is exactly what a legacy one is.
        persisted.direct_shield_in_flight = Some(serde_json::from_value(journal)?);
        store.save(&persisted)?;
        Ok((note, store))
    }

    /// The harness the shield tests share: a journalled shield, an aggregator, a scripted shielder.
    struct ShieldRig {
        state: RedbCurvyDepositState,
        note: OwnedNote,
        store: RedbCurvySdkStore,
        landed: Arc<std::sync::atomic::AtomicBool>,
        reads: Arc<std::sync::atomic::AtomicUsize>,
        submissions: Arc<std::sync::atomic::AtomicUsize>,
        adapter: Adapter,
        _server: relayer::http_tests::Server,
    }

    async fn shield_rig(
        gross: &str,
        submission: Option<ShieldSubmission>,
        note_is_there: bool,
        script: Vec<Outcome>,
    ) -> anyhow::Result<ShieldRig> {
        use std::sync::atomic::{AtomicBool, AtomicUsize};
        let state = RedbCurvyDepositState::in_memory()?;
        let (note, store) = journal_direct_shield(&state, gross, submission)?;
        let (landed, reads, submissions) = (
            Arc::new(AtomicBool::new(note_is_there)),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
        );
        let server = note_status_server(&landed, &reads).await;
        let shielder = scripted_shielder(&landed, &submissions, script);
        let adapter = test_adapter_with_shielder(&state, server.url.clone(), Some(shielder))?;
        Ok(ShieldRig {
            state,
            note,
            store,
            landed,
            reads,
            submissions,
            adapter,
            _server: server,
        })
    }

    impl ShieldRig {
        async fn fund(&self) -> Result<(), RsSdkCurvyAdapterError> {
            self.adapter
                .fund(HoprBalance::from(U256::from(7_u8)), Address::from([9_u8; 20]))
                .await
        }

        fn sent(&self) -> usize {
            self.submissions.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn journal(&self) -> anyhow::Result<Option<ShieldSubmission>> {
            Ok(self
                .store
                .load()?
                .direct_shield_in_flight
                .map(|stored| stored.submission))
        }
    }

    /// A refusal before anything was broadcast moves nothing and wedges nothing: the next funding
    /// sends.
    #[tokio::test]
    async fn a_refused_direct_shield_is_sent_again() -> anyhow::Result<()> {
        let rig = shield_rig("7", Some(ShieldSubmission::NotSubmitted), false, vec![Outcome::Refuse]).await?;

        let error = rig.fund().await.unwrap_err();
        assert!(matches!(error, RsSdkCurvyAdapterError::Funding(_)), "{error}");
        assert_eq!(rig.journal()?, Some(ShieldSubmission::NotSubmitted));

        rig.fund().await?;
        assert_eq!(rig.sent(), 2);
        assert_eq!(rig.store.load()?.funding, vec![StoredNote::from(&rig.note)]);
        Ok(())
    }

    /// A transaction the chain rejected did not move the float either.
    #[tokio::test]
    async fn a_reverted_direct_shield_is_sent_again() -> anyhow::Result<()> {
        let rig = shield_rig("7", Some(ShieldSubmission::NotSubmitted), false, vec![Outcome::Revert]).await?;

        let error = rig.fund().await.unwrap_err();
        assert!(matches!(error, RsSdkCurvyAdapterError::Funding(_)), "{error}");
        assert_eq!(rig.journal()?, Some(ShieldSubmission::NotSubmitted));

        rig.fund().await?;
        assert_eq!(rig.sent(), 2);
        Ok(())
    }

    /// A transaction with no answer may still land: it is waited for through its grace, looked for
    /// on every funding, and only sent again after it.
    #[tokio::test(start_paused = true)]
    async fn an_unconfirmed_direct_shield_settles_before_it_is_sent_again() -> anyhow::Result<()> {
        let rig = shield_rig(
            "7",
            Some(ShieldSubmission::NotSubmitted),
            false,
            vec![Outcome::Unconfirmed, Outcome::Confirm],
        )
        .await?;

        let error = rig.fund().await.unwrap_err();
        assert!(
            matches!(error, RsSdkCurvyAdapterError::ShieldSettling { gross: 7, .. }),
            "{error}"
        );
        assert!(error.to_string().contains(&note_id(&rig.note)), "{error}");
        assert!(matches!(
            rig.journal()?,
            Some(ShieldSubmission::Unknown { since: Some(_) })
        ));

        // Within the grace: looked for, not sent.
        let error = rig.fund().await.unwrap_err();
        assert!(
            matches!(error, RsSdkCurvyAdapterError::ShieldSettling { .. }),
            "{error}"
        );
        assert_eq!(rig.sent(), 1, "nothing is sent within the grace");

        // Past it, from the journal's own `since`.
        let mut persisted = rig.store.load()?;
        persisted.direct_shield_in_flight.as_mut().unwrap().submission = ShieldSubmission::Unknown {
            since: Some(unix_now().unwrap() - 3600),
        };
        rig.store.save(&persisted)?;
        // The adapter reads its own copy of the state: a restarted one picks the journal up.
        let restarted = {
            let server = note_status_server(&rig.landed, &rig.reads).await;
            let shielder = scripted_shielder(&rig.landed, &rig.submissions, vec![Outcome::Confirm; 3]);
            (
                test_adapter_with_shielder(&rig.state, server.url.clone(), Some(shielder))?,
                server,
            )
        };
        restarted
            .0
            .fund(HoprBalance::from(U256::from(7_u8)), Address::from([9_u8; 20]))
            .await?;
        assert_eq!(rig.sent(), 2, "sent again once the grace was over");
        assert!(
            rig.store.load()?.direct_shield_in_flight.is_none(),
            "the journal is settled"
        );
        Ok(())
    }

    /// The grace runs from when the outcome arrived, not from when the call was made: the
    /// sequencer's queue and the connector's tracking window come in between.
    #[tokio::test]
    async fn an_unconfirmed_direct_shield_is_dated_from_its_outcome() -> anyhow::Result<()> {
        let rig = shield_rig(
            "7",
            Some(ShieldSubmission::NotSubmitted),
            false,
            vec![Outcome::SlowUnconfirmed],
        )
        .await?;
        let before = unix_now().unwrap();

        let error = rig.fund().await.unwrap_err();

        let Some(ShieldSubmission::Unknown { since: Some(since) }) = rig.journal()? else {
            panic!("journalled as unknown: {error}");
        };
        assert!(
            since > before,
            "dated from the outcome ({since}), not the call ({before})"
        );
        assert!(
            matches!(error, RsSdkCurvyAdapterError::ShieldSettling { since: Some(reported), .. } if reported == since),
            "{error}"
        );
        Ok(())
    }

    /// A transaction confirmed on chain is not sent again while the aggregator may be indexing its
    /// note: it is read once per funding, and the shield settles when the aggregator catches up.
    /// Past the grace the note's absence is taken for a failed inner call of the Safe, and it is
    /// sent again.
    #[tokio::test(start_paused = true)]
    async fn a_confirmed_direct_shield_with_no_note_is_not_resent_within_its_grace() -> anyhow::Result<()> {
        let tx = confirmed_shield().tx;
        let at = Some(unix_now().unwrap());
        let submitted = ShieldSubmission::Submitted { tx: tx.clone(), at };
        let rig = shield_rig("7", Some(submitted.clone()), false, vec![]).await?;

        let error = rig.fund().await.unwrap_err();

        assert!(
            matches!(error, RsSdkCurvyAdapterError::ShieldConfirmedUnindexed { gross: 7, .. }),
            "{error}"
        );
        let grace = rig.adapter.config.direct_shield_settle_grace.as_secs();
        assert!(
            matches!(
                error,
                RsSdkCurvyAdapterError::ShieldConfirmedUnindexed { resend_after, .. }
                    if resend_after == at.map(|at| at + grace)
            ),
            "the error says when the grace ends: {error}"
        );
        assert!(error.to_string().contains(&tx), "{error}");
        assert_eq!(rig.sent(), 0, "nothing is sent within the grace");
        assert_eq!(
            rig.reads.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "one read per funding"
        );
        assert_eq!(rig.journal()?, Some(submitted));

        rig.landed.store(true, std::sync::atomic::Ordering::SeqCst);
        rig.fund().await?;
        assert_eq!(rig.sent(), 0);
        assert_eq!(rig.store.load()?.funding, vec![StoredNote::from(&rig.note)]);
        Ok(())
    }

    /// Past the grace — or with no time recorded — a confirmed shield whose note never appeared is
    /// treated as a failed inner call, and sent again.
    #[tokio::test(start_paused = true)]
    async fn a_confirmed_direct_shield_with_no_note_is_resent_after_its_grace() -> anyhow::Result<()> {
        for at in [Some(unix_now().unwrap() - 3600), None] {
            let rig = shield_rig(
                "7",
                Some(ShieldSubmission::Submitted {
                    tx: confirmed_shield().tx,
                    at,
                }),
                false,
                vec![],
            )
            .await?;

            rig.fund().await?;

            assert_eq!(rig.sent(), 1, "sent again, {at:?}");
            assert_eq!(rig.store.load()?.funding, vec![StoredNote::from(&rig.note)]);
        }
        Ok(())
    }

    /// A transaction confirmed on chain whose note is there is simply recorded.
    #[tokio::test]
    async fn a_confirmed_direct_shield_is_recorded_without_sending() -> anyhow::Result<()> {
        let rig = shield_rig(
            "7",
            Some(ShieldSubmission::Submitted {
                tx: confirmed_shield().tx,
                at: None,
            }),
            true,
            vec![],
        )
        .await?;

        rig.fund().await?;

        assert_eq!(rig.sent(), 0);
        assert_eq!(rig.store.load()?.funding, vec![StoredNote::from(&rig.note)]);
        Ok(())
    }

    /// A journal from before the submission was recorded reads as unknown, with no time: the chain
    /// is looked at first, and the Safe sends only if the note is not there.
    #[tokio::test(start_paused = true)]
    async fn a_legacy_direct_shield_journal_is_looked_for_before_it_is_sent() -> anyhow::Result<()> {
        for note_is_there in [true, false] {
            let rig = shield_rig("7", None, note_is_there, vec![]).await?;
            assert_eq!(
                rig.journal()?,
                Some(ShieldSubmission::Unknown { since: None }),
                "a missing field is unknown"
            );

            rig.fund().await?;

            assert_eq!(
                rig.sent(),
                usize::from(!note_is_there),
                "sent only when the note was not there"
            );
            assert_eq!(rig.store.load()?.funding, vec![StoredNote::from(&rig.note)]);
        }
        Ok(())
    }

    /// As for a direct shield, the portal shield's journal is authoritative: a different amount
    /// or recovery address resumes it rather than refusing it.
    #[tokio::test]
    async fn a_journalled_portal_shield_is_resumed_with_its_own_amount() -> anyhow::Result<()> {
        let state = RedbCurvyDepositState::in_memory()?;
        let note = Adapter::owned_note(&fixture(7))?;
        let store = RedbCurvySdkStore::new(&state)?;
        let mut persisted = store.load()?;
        persisted.shield_in_flight = Some(StoredShield {
            note: StoredNote::from(&note),
            gross: "7".to_owned(),
            recovery: format!("0x{}", "aa".repeat(20)),
            portal_address: format!("0x{}", "bb".repeat(20)),
            stage: StoredShieldStage::Funded,
            submission: ShieldSubmission::NotSubmitted,
        });
        store.save(&persisted)?;
        let server = relayer::http_tests::Server::new(|path, body| {
            assert_eq!(path, "/graphql");
            assert!(body["query"].as_str().unwrap().contains("curvyNoteStatus"));
            Some(note_status_response(true))
        })
        .await;
        let mut adapter = test_adapter(&state, server.url.clone())?;
        adapter.config.shielding = CurvyShielding::Portal;

        adapter
            .fund(HoprBalance::from(U256::from(8_u8)), Address::from([9_u8; 20]))
            .await?;

        let stored = store.load()?;
        assert_eq!(
            stored.funding,
            vec![StoredNote::from(&note)],
            "the journalled shield landed"
        );
        assert!(stored.shield_in_flight.is_none(), "the journal is settled");
        Ok(())
    }

    /// What the portal tests share: a journalled portal shield at `stage`, and an aggregator that
    /// knows no note and reports `portal_balance` for the portal.
    struct PortalRig {
        _state: RedbCurvyDepositState,
        store: RedbCurvySdkStore,
        portal_balance: Arc<std::sync::atomic::AtomicU64>,
        adapter: Adapter,
        _server: relayer::http_tests::Server,
    }

    async fn portal_rig(
        stage: StoredShieldStage,
        submission: ShieldSubmission,
        funder: PortalFunder,
    ) -> anyhow::Result<PortalRig> {
        use std::sync::atomic::{AtomicU64, Ordering};
        let state = RedbCurvyDepositState::in_memory()?;
        let note = Adapter::owned_note(&fixture(7))?;
        let store = RedbCurvySdkStore::new(&state)?;
        let mut persisted = store.load()?;
        persisted.shield_in_flight = Some(StoredShield {
            note: StoredNote::from(&note),
            gross: "7".to_owned(),
            recovery: format!("0x{}", "aa".repeat(20)),
            portal_address: format!("0x{}", "bb".repeat(20)),
            stage,
            submission,
        });
        store.save(&persisted)?;
        let portal_balance = Arc::new(AtomicU64::new(0));
        let balance = portal_balance.clone();
        let server = relayer::http_tests::Server::new(move |path, body| {
            assert_eq!(path, "/graphql");
            let query = body["query"].as_str().unwrap();
            if query.contains("hoprBalance") {
                return Some((
                    200,
                    serde_json::json!({"data":{
                        "hoprBalance":{
                            "__typename":"HoprBalance",
                            "address":format!("0x{}", "bb".repeat(20)),
                            "balance":format!("0.{:018} wxHOPR", balance.load(Ordering::SeqCst)),
                        },
                        "chainInfo":{
                            "__typename":"ChainInfo",
                            "contractAddresses":serde_json::json!({"token": format!("0x{}", "03".repeat(20))}).to_string(),
                        },
                    }}),
                ));
            }
            assert!(query.contains("curvyNoteStatus"), "{query}");
            Some(note_status_response(false))
        })
        .await;
        let mut adapter = test_adapter(&state, server.url.clone())?;
        adapter.config.shielding = CurvyShielding::Portal;
        adapter.funder = funder;
        Ok(PortalRig {
            _state: state,
            store,
            portal_balance,
            adapter,
            _server: server,
        })
    }

    impl PortalRig {
        async fn fund(&self) -> Result<(), RsSdkCurvyAdapterError> {
            self.adapter
                .fund(HoprBalance::from(U256::from(7_u8)), Address::from([9_u8; 20]))
                .await
        }

        fn stage(&self) -> anyhow::Result<Option<StoredShieldStage>> {
            Ok(self.store.load()?.shield_in_flight.map(|stored| stored.stage))
        }
    }

    /// The Safe's transfer to the portal is journalled by the task that makes it, not by the
    /// caller that awaits it: a caller dropped between the transfer and the write would otherwise
    /// leave the journal not knowing it happened, and a retry would fund the portal twice. The
    /// retry reads the portal, finds it funded, and moves on without the Safe.
    #[tokio::test]
    async fn a_portal_funding_is_journalled_even_if_the_caller_is_dropped() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Notify::new());
        let funder: PortalFunder = {
            let (calls, gate) = (calls.clone(), gate.clone());
            Arc::new(move |_, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                let gate = gate.clone();
                Box::pin(async move {
                    gate.notified().await;
                    Ok(confirmed_shield())
                })
            })
        };
        let rig = portal_rig(StoredShieldStage::Prepared, ShieldSubmission::NotSubmitted, funder).await?;

        // The caller gives up while the transfer is in flight.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), rig.fund())
                .await
                .is_err()
        );
        assert_eq!(rig.stage()?, Some(StoredShieldStage::Prepared), "still in flight");
        rig.portal_balance.store(7, Ordering::SeqCst);
        gate.notify_one();
        for _ in 0..100 {
            if matches!(submission_of(&rig)?, Some(ShieldSubmission::Submitted { .. })) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            matches!(submission_of(&rig)?, Some(ShieldSubmission::Submitted { .. })),
            "the task journalled the confirmation"
        );

        // Whatever the retry goes on to do, it does not fund the portal again.
        let _ = rig.fund().await;
        assert_eq!(
            rig.stage()?,
            Some(StoredShieldStage::Funded),
            "the balance read says funded"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "the portal is funded once");
        Ok(())
    }

    /// A portal funder that counts its transfers and answers each from `script`, then confirms. A
    /// confirmed transfer leaves `gross` in the portal when `lands` says so.
    fn scripted_funder(
        portal_balance: &Arc<std::sync::atomic::AtomicU64>,
        calls: &Arc<std::sync::atomic::AtomicUsize>,
        lands: bool,
        script: Vec<Outcome>,
    ) -> PortalFunder {
        use std::sync::atomic::Ordering;
        let (balance, calls) = (portal_balance.clone(), calls.clone());
        Arc::new(move |_, _| {
            let attempt = calls.fetch_add(1, Ordering::SeqCst);
            match script.get(attempt).copied().unwrap_or(Outcome::Confirm) {
                Outcome::Refuse => {
                    Box::pin(async { Err(ShieldFailure::NotSubmitted("the Safe holds too little".to_owned())) })
                }
                Outcome::Revert => Box::pin(async {
                    Err(ShieldFailure::Reverted {
                        reason: "reverted".to_owned(),
                    })
                }),
                Outcome::Unconfirmed | Outcome::SlowUnconfirmed => {
                    Box::pin(async { Err(ShieldFailure::Unconfirmed("tracking timed out".to_owned())) })
                }
                Outcome::Confirm => {
                    if lands {
                        balance.store(7, Ordering::SeqCst);
                    }
                    Box::pin(async { Ok(confirmed_shield()) })
                }
            }
        })
    }

    /// A portal rig around a scripted funder; `lands` is whether its confirmed transfers show in
    /// the portal's balance.
    async fn scripted_portal_rig(
        submission: ShieldSubmission,
        lands: bool,
        script: Vec<Outcome>,
    ) -> anyhow::Result<(PortalRig, Arc<std::sync::atomic::AtomicUsize>)> {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let placeholder: PortalFunder = Arc::new(|_, _| Box::pin(async { panic!("unexpected funding call") }));
        let mut rig = portal_rig(StoredShieldStage::Prepared, submission, placeholder).await?;
        // Built after the rig, for the balance its aggregator reports.
        rig.adapter.funder = scripted_funder(&rig.portal_balance, &calls, lands, script);
        Ok((rig, calls))
    }

    fn submission_of(rig: &PortalRig) -> anyhow::Result<Option<ShieldSubmission>> {
        Ok(rig.store.load()?.shield_in_flight.map(|stored| stored.submission))
    }

    /// A refusal before anything was broadcast moves nothing and wedges nothing: the next funding
    /// sends, as for a direct shield.
    #[tokio::test]
    async fn a_refused_portal_funding_is_sent_again() -> anyhow::Result<()> {
        use std::sync::atomic::Ordering;
        let (rig, calls) = scripted_portal_rig(ShieldSubmission::NotSubmitted, true, vec![Outcome::Refuse]).await?;

        let error = rig.fund().await.unwrap_err();

        assert!(matches!(error, RsSdkCurvyAdapterError::Funding(_)), "{error}");
        assert_eq!(submission_of(&rig)?, Some(ShieldSubmission::NotSubmitted));
        assert_eq!(rig.stage()?, Some(StoredShieldStage::Prepared));
        let _ = rig.fund().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2, "sent again");
        Ok(())
    }

    /// A transaction the chain rejected moved nothing either.
    #[tokio::test]
    async fn a_reverted_portal_funding_is_sent_again() -> anyhow::Result<()> {
        use std::sync::atomic::Ordering;
        let (rig, calls) = scripted_portal_rig(ShieldSubmission::NotSubmitted, true, vec![Outcome::Revert]).await?;

        let error = rig.fund().await.unwrap_err();

        assert!(matches!(error, RsSdkCurvyAdapterError::Funding(_)), "{error}");
        assert_eq!(submission_of(&rig)?, Some(ShieldSubmission::NotSubmitted));
        let _ = rig.fund().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2, "sent again");
        Ok(())
    }

    /// A transfer with no answer may still land: it is waited for within the grace, and sent
    /// again once the grace is over.
    #[tokio::test]
    async fn an_unconfirmed_portal_funding_settles_within_the_grace_and_is_reported_unresolved_after_it()
    -> anyhow::Result<()> {
        use std::sync::atomic::Ordering;
        let (rig, calls) =
            scripted_portal_rig(ShieldSubmission::NotSubmitted, true, vec![Outcome::Unconfirmed]).await?;

        let error = rig.fund().await.unwrap_err();
        assert!(
            matches!(error, RsSdkCurvyAdapterError::ShieldSettling { .. }),
            "{error}"
        );
        assert!(matches!(
            submission_of(&rig)?,
            Some(ShieldSubmission::Unknown { since: Some(_) })
        ));

        let error = rig.fund().await.unwrap_err();
        assert!(
            matches!(error, RsSdkCurvyAdapterError::ShieldSettling { .. }),
            "{error}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "not sent again within the grace");

        // The grace is over.
        journal_submission(
            &rig.adapter.state,
            &rig.store,
            ShieldJournal::Portal,
            ShieldSubmission::Unknown {
                since: Some(unix_now().unwrap() - 3600),
            },
        )?;
        let error = rig.fund().await.unwrap_err();
        assert!(
            matches!(error, RsSdkCurvyAdapterError::PortalFundingUnresolved { tx: None, .. }),
            "{error}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "not sent again: the first copy may still land"
        );
        Ok(())
    }

    /// A pre-upgrade journal has no record of a submission: the portal is looked at before the
    /// Safe sends, and not sent to when it already holds the funds.
    #[tokio::test]
    async fn a_legacy_portal_journal_is_looked_at_before_it_is_sent() -> anyhow::Result<()> {
        use std::sync::atomic::Ordering;
        for funded in [true, false] {
            let (rig, calls) = scripted_portal_rig(ShieldSubmission::Unknown { since: None }, true, vec![]).await?;
            rig.portal_balance.store(if funded { 7 } else { 0 }, Ordering::SeqCst);
            let _ = rig.fund().await;
            assert_eq!(calls.load(Ordering::SeqCst), usize::from(!funded));
            assert_eq!(rig.stage()?, Some(StoredShieldStage::Funded));
        }
        Ok(())
    }

    /// A confirmed transfer whose balance reads zero may be the read being behind: it is waited
    /// for, never sent again within the grace, and funded once the read shows the balance. The
    /// stage stays `Prepared` meanwhile, because only a balance read says the portal is funded.
    #[tokio::test]
    async fn a_confirmed_portal_funding_that_reads_empty_is_waited_for() -> anyhow::Result<()> {
        use std::sync::atomic::Ordering;
        let (rig, calls) = scripted_portal_rig(ShieldSubmission::NotSubmitted, false, vec![]).await?;
        for _ in 0..2 {
            let error = rig.fund().await.unwrap_err();
            assert!(
                matches!(error, RsSdkCurvyAdapterError::ShieldConfirmedUnindexed { .. }),
                "{error}"
            );
            assert_eq!(
                rig.stage()?,
                Some(StoredShieldStage::Prepared),
                "not funded on a confirmation"
            );
            assert!(matches!(submission_of(&rig)?, Some(ShieldSubmission::Submitted { .. })));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "not sent again within the grace");

        rig.portal_balance.store(7, Ordering::SeqCst);
        let _ = rig.fund().await;

        assert_eq!(
            rig.stage()?,
            Some(StoredShieldStage::Funded),
            "funded once the read shows it"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "sent once, in all");
        Ok(())
    }

    /// Confirmed, yet not showing within the grace, may be a failed inner call of the Safe or a
    /// read that is still behind. The portal is not funded again either way: a first copy that
    /// lands after all would leave twice `gross` in it, and nothing can shield that. The operator
    /// is asked instead.
    #[tokio::test]
    async fn a_confirmed_portal_funding_that_never_shows_is_reported_unresolved_not_sent_again() -> anyhow::Result<()> {
        use std::sync::atomic::Ordering;
        let (rig, calls) = scripted_portal_rig(ShieldSubmission::NotSubmitted, false, vec![]).await?;
        let error = rig.fund().await.unwrap_err();
        assert!(
            matches!(error, RsSdkCurvyAdapterError::ShieldConfirmedUnindexed { .. }),
            "{error}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // The grace is over.
        journal_submission(
            &rig.adapter.state,
            &rig.store,
            ShieldJournal::Portal,
            ShieldSubmission::Submitted {
                tx: "0xabc".to_owned(),
                at: Some(unix_now().unwrap() - 3600),
            },
        )?;
        for _ in 0..2 {
            let error = rig.fund().await.unwrap_err();
            assert!(
                matches!(&error, RsSdkCurvyAdapterError::PortalFundingUnresolved { tx: Some(tx), .. } if tx == "0xabc"),
                "{error}"
            );
            assert!(error.to_string().contains("recovery address"), "{error}");
        }

        assert_eq!(calls.load(Ordering::SeqCst), 1, "not sent again");
        assert!(
            matches!(submission_of(&rig)?, Some(ShieldSubmission::Submitted { .. })),
            "the journal is kept as it was"
        );
        Ok(())
    }

    #[test]
    fn sdk_note_conversion_preserves_the_complete_note() -> anyhow::Result<()> {
        let committed = fixture(7);
        let converted = Adapter::owned_note(&committed)?;
        let converted = converted.to_core();
        assert_eq!(converted.owner_pub, committed.note.owner_pub);
        assert_eq!(converted.shared_secret, committed.note.shared_secret);
        assert_eq!(converted.ephemeral_key, committed.note.ephemeral_key);
        assert_eq!(converted.view_tag, committed.note.view_tag);
        assert_eq!(converted.amount, committed.note.amount);
        assert_eq!(converted.token, committed.note.token);
        Ok(())
    }

    #[test]
    fn sdk_note_conversion_rejects_a_non_byte_view_tag() {
        let mut committed = fixture(7);
        committed.note.view_tag = Fr::from(256_u64);

        assert!(matches!(
            Adapter::owned_note(&committed),
            Err(RsSdkCurvyAdapterError::InvalidValue(_))
        ));
    }

    /// A valid compressed scan identity, derived from real Curvy meta-keys because the
    /// type rejects byte strings that are not curve points.
    fn scan_key(spend_private_key: &str, view_private_key: &str) -> anyhow::Result<CurvyScanPublicKey> {
        let (spend_meta_key, _) =
            stealth::get_meta(&full_width_key(spend_private_key), &full_width_key(view_private_key))?;
        let mut v = [0u8; 32];
        let v_bytes = const_hex::decode(view_private_key)?;
        v[32 - v_bytes.len()..].copy_from_slice(&v_bytes);
        let view = hopr_api::types::crypto::prelude::Bn254Keypair::from_secret_be(&v)?;
        Ok(CurvyScanPublicKey::new(
            public_key_from_dec(&spend_meta_key).map_err(anyhow::Error::msg)?,
            *view.public(),
        ))
    }

    #[test]
    fn stored_allocation_binds_id_address_and_amount() -> anyhow::Result<()> {
        let committed = fixture(7);
        let bound = scan_key("07", "0b")?;
        let other = scan_key("08", "0d")?;
        let allocation = StoredAllocation::new(
            committed.deposit.id,
            &committed.deposit.address,
            bound,
            committed.deposit.amount,
        )?;

        assert!(allocation.matches(&committed.deposit.address, bound, committed.deposit.amount));
        assert!(!allocation.matches(&committed.deposit.address, bound, HoprBalance::from(U256::from(8_u8))));
        assert!(!allocation.matches(&committed.deposit.address, other, committed.deposit.amount));
        Ok(())
    }

    #[test]
    fn recipient_decompresses_both_halves_of_the_scan_identity() -> anyhow::Result<()> {
        let committed = fixture(7);
        let key = scan_key("07", "0b")?;
        let (big_k, big_v) = stealth::get_meta(&full_width_key("07"), &full_width_key("0b"))?;
        let recipient = StoredAllocation::recipient(&committed.deposit.address, key)?;
        assert_eq!(recipient.viewer.big_k, big_k);
        assert_eq!(recipient.viewer.big_v, big_v);
        Ok(())
    }

    /// The public keys `(K, V)` of the 31-byte scalars `01…01` and `02…02`, derived by HOPR's own
    /// key types rather than through Curvy's hex parsing.
    fn short_key_identity() -> anyhow::Result<(String, String)> {
        let (mut k, mut v) = ([1u8; 32], [2u8; 32]);
        (k[0], v[0]) = (0, 0);
        Ok((
            spend_meta_key_dec(ChainKeypair::from_secret(&k)?.public()),
            view_key_dec(Bn254Keypair::from_secret_be(&v)?.public()).map_err(anyhow::Error::msg)?,
        ))
    }

    #[test]
    fn short_keys_are_padded_to_the_width_the_sdk_parses() -> anyhow::Result<()> {
        // Valid scalars whose top byte is zero, as `new_meta` used to print them: 31 bytes.
        let (short_spend, short_view) = ("01".repeat(31), "02".repeat(31));
        assert!(Account::from_meta_keys(&short_spend, &"02".repeat(32)).is_err());
        let (k, v) = (full_width_key(&short_spend), full_width_key(&short_view));
        assert_eq!(k, format!("00{short_spend}"));
        assert_eq!(v, format!("00{short_view}"));
        let account = Account::from_meta_keys(&k, &v)?;
        let (big_k, big_v) = short_key_identity()?;
        assert_eq!(account.big_k, big_k);
        assert_eq!(account.big_v, big_v);
        assert_eq!(full_width_key(&k), k);
        Ok(())
    }

    /// A node that persisted its identity while `new_meta` still printed short keys must keep
    /// starting: `curvy-core` 0.1.1 rejects a short view key where earlier releases accepted one.
    #[tokio::test]
    async fn a_persisted_short_spender_identity_still_loads() -> anyhow::Result<()> {
        let server =
            relayer::http_tests::Server::new(|_, _| panic!("loading an identity makes no HTTP requests")).await;
        let state = RedbCurvyDepositState::in_memory()?;
        let store = RedbCurvySdkStore::new(&state)?;
        let mut persisted = store.load()?;
        store.set_spender(
            &mut persisted,
            &StoredSpender {
                k: "01".repeat(31),
                v: "02".repeat(31),
            },
        )?;
        store.save(&persisted)?;

        let adapter = test_adapter(&state, server.url.clone())?;
        let (big_k, big_v) = short_key_identity()?;
        assert_eq!(adapter.spender.big_k, big_k);
        assert_eq!(adapter.spender.big_v, big_v);
        Ok(())
    }

    #[test]
    fn withdrawals_leave_out_zero_amount_notes() -> anyhow::Result<()> {
        let amounts = |selected: Vec<OwnedNote>| {
            selected
                .iter()
                .map(|note| u128::try_from(fr_to_biguint(&note.amount)).unwrap())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            amounts(Adapter::select_notes(vec![fixture(7), fixture(0)], None)?),
            vec![7]
        );
        assert!(Adapter::select_notes(vec![fixture(0)], None)?.is_empty());
        assert_eq!(
            amounts(Adapter::select_notes(
                vec![fixture(0), fixture(5), fixture(7)],
                Some(HoprBalance::from(U256::from(5_u8)))
            )?),
            vec![5]
        );
        Ok(())
    }

    #[test]
    fn partial_withdrawal_rejects_an_inexact_whole_note_total() {
        let result = Adapter::select_notes(
            vec![fixture(3), fixture(8), fixture(5)],
            Some(HoprBalance::from(U256::from(10_u8))),
        );
        assert!(matches!(
            result,
            Err(RsSdkCurvyAdapterError::InexactWithdrawal {
                requested: 10,
                selected: 13
            })
        ));
    }

    #[test]
    fn partial_withdrawal_accepts_an_exact_whole_note_total() -> anyhow::Result<()> {
        let selected = Adapter::select_notes(
            vec![fixture(3), fixture(8), fixture(5)],
            Some(HoprBalance::from(U256::from(13_u8))),
        )?;
        let total = selected
            .iter()
            .map(|note| u128::try_from(fr_to_biguint(&note.amount)).unwrap())
            .sum::<u128>();
        assert_eq!(total, 13);
        Ok(())
    }

    #[test]
    fn partial_withdrawal_finds_an_exact_note_outside_the_descending_prefix() -> anyhow::Result<()> {
        let selected = Adapter::select_notes(vec![fixture(7), fixture(5)], Some(HoprBalance::from(U256::from(5_u8))))?;
        let amounts = selected
            .iter()
            .map(|note| u128::try_from(fr_to_biguint(&note.amount)).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(amounts, vec![5]);
        Ok(())
    }

    #[test]
    fn partial_withdrawal_finds_an_exact_combination_that_skips_the_largest_note() -> anyhow::Result<()> {
        let selected = Adapter::select_notes(
            vec![fixture(9), fixture(6), fixture(4), fixture(3)],
            Some(HoprBalance::from(U256::from(10_u8))),
        )?;
        let mut amounts = selected
            .iter()
            .map(|note| u128::try_from(fr_to_biguint(&note.amount)).unwrap())
            .collect::<Vec<_>>();
        amounts.sort_unstable();
        assert_eq!(amounts, vec![4, 6]);
        Ok(())
    }

    #[test]
    fn exact_note_subset_gives_up_when_the_budget_runs_out() {
        assert_eq!(exact_note_subset(&[9, 6, 4, 3], 10, 1_000), Some(vec![1, 2]));
        assert_eq!(exact_note_subset(&[9, 6, 4, 3], 10, 2), None);
        assert_eq!(exact_note_subset(&[9, 6, 4, 3], 11, 1_000), None);
    }

    fn fixture(amount: u64) -> CommittedCurvyNote {
        let address = *BjjKeypair::from_secret(&[1_u8; 32]).unwrap().public();
        CommittedCurvyNote {
            deposit: OwnedCurvyDeposit {
                id: PixAddressId::new(&HoprPseudonym::random(), std::num::NonZeroU32::new(1).unwrap()),
                address,
                amount: HoprBalance::from(U256::from(amount)),
            },
            note: Note {
                owner_pub: (Fr::from(1_u8), Fr::from(2_u8)),
                shared_secret: Fr::from(amount),
                ephemeral_key: (Fr::from(4_u8), Fr::from(5_u8)),
                view_tag: Fr::from(6_u8),
                amount: Fr::from(amount),
                token: Fr::from(1_u8),
            },
            leaf_index: amount,
        }
    }
}
