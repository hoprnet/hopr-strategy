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
    Account, CurvyClient, Identity, OwnedNote, PreparedDeposit, PreparedDirectShield, Route, ScanRecipient, TxLedger,
    ViewerIdentity,
};
use futures::future::BoxFuture;
use hopr_api::{
    node::PixAddressId,
    types::{
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
    state::{RedbCurvyDepositState, id_bytes},
};

const SDK_STATE_TABLE: TableDefinition<u8, Vec<u8>> = TableDefinition::new("curvy_pix_sdk_state");
const SDK_STATE_KEY: u8 = 0;
const SDK_ALLOCATIONS_TABLE: TableDefinition<[u8; PixAddressId::SIZE], Vec<u8>> =
    TableDefinition::new("curvy_pix_sdk_allocations");
/// Verifier profile `(2, 9)`: nine regular outputs, one reserved for change.
const MAX_ALLOCATIONS_PER_PROOF: usize = 7;
/// The pending-commitment profile takes at most five note ids.
const MAX_COMMITMENTS_PER_PROOF: usize = 5;
/// The PIX withdrawal profile takes at most ten notes.
const MAX_WITHDRAWAL_INPUTS: usize = 10;
/// An aggregation spends one or two committed input notes.
const MAX_ALLOCATION_INPUTS: usize = 2;
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
pub type PortalFunder = Arc<dyn Fn(Address, HoprBalance) -> BoxFuture<'static, Result<(), String>> + Send + Sync>;

/// Performs a direct shield on behalf of the account that holds the float.
///
/// Takes the `directShield` calldata plus the addresses the bundled approval needs, and is
/// responsible for making the call originate from the fund-holding account — the node's Safe.
/// A callback rather than a method so the pool keeps no chain key of its own and the SDK bridge
/// stays ignorant of how the Safe is driven.
///
/// Arguments: the `directShield` calldata, the token, the vault to approve, the aggregator to
/// call, and the gross amount to approve.
pub type DirectShielder =
    Arc<dyn Fn(Vec<u8>, Address, Address, Address, u128) -> BoxFuture<'static, Result<(), String>> + Send + Sync>;

/// Curvy chain operations that require SDK knowledge.
///
/// The pool owns note retrieval, durable note state, cursors, correlation and the
/// [`DepositPool`](hopr_api::chain::DepositPool) behaviour. Proof generation and contract payload
/// construction are delegated to the Curvy SDK through this narrow adapter.
#[async_trait]
pub trait CurvySdkAdapter: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Shields `gross` into the private pool if no durable funding exists yet, with
    /// `recovery_address` as the portal's recovery address. Idempotent and crash-resumable.
    async fn ensure_funded(&self, gross: HoprBalance, recovery_address: Address) -> Result<(), Self::Error>;

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
    /// Token identifier used by all pool notes.
    pub token: u64,
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
}

impl RsSdkCurvyAdapterConfig {
    /// Self-submitting configuration: portal shielding, proofs signed with `operator_private_key`.
    ///
    /// This is what the localcluster runs, and what every caller got before the modes existed.
    pub fn new(operator_private_key: String, token: u64) -> Self {
        Self {
            operator_private_key,
            token,
            route: Route::Blokli,
            fee_recipient: None,
            shielding: CurvyShielding::Portal,
            submission: CurvySubmission::Operator,
            relayer_url: None,
            relay_timeout: std::time::Duration::from_secs(120),
            note_source: CurvyNoteSource::Blokli,
            curvy_indexer_url: None,
        }
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
    #[error("the private pool has no committed note large enough to fund {required} wei")]
    NoFunding { required: u128 },
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
    #[error("a different Curvy shield deposit is already in progress")]
    ShieldInProgress,
    #[error("the Curvy shield portal contains {actual} base units instead of the expected {required}")]
    UnexpectedShieldFunding { actual: u128, required: u128 },
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredShield {
    note: StoredNote,
    gross: String,
    recovery: String,
    portal_address: String,
    stage: StoredShieldStage,
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
    #[serde(default)]
    spender: Option<StoredSpender>,
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
}

struct RedbCurvySdkStore {
    db: Arc<redb::Database>,
}

impl RedbCurvySdkStore {
    fn new(state: &RedbCurvyDepositState) -> Result<Self, RsSdkCurvyAdapterError> {
        let db = state.shared_database();
        let write = db.begin_write().map_err(db_error)?;
        write.open_table(SDK_STATE_TABLE).map_err(db_error)?;
        write.open_table(SDK_ALLOCATIONS_TABLE).map_err(db_error)?;
        write.commit().map_err(db_error)?;
        Ok(Self { db })
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
        if !legacy.is_empty() {
            // The records and removal of the old JSON history become durable together.
            self.save_update(&state, &legacy, &[])?;
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
    /// The vault, which is the `approve` target of a direct shield: the aggregator forwards its
    /// caller as `from` and the vault is what calls `safeTransferFrom`.
    pub vault: String,
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
    state: parking_lot::Mutex<SdkState>,
    spender: Account,
    client: tokio::sync::OnceCell<(Arc<CurvyClient>, CurvyChainEndpoints)>,
    /// Serialises everything that submits a transaction or spends a note.
    chain: tokio::sync::Mutex<()>,
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
        let spender = match &persisted.spender {
            Some(spender) => Account::from_meta_keys(&spender.k, &spender.v)?,
            None => {
                let (k, v, ..) =
                    stealth::new_meta().map_err(|error| RsSdkCurvyAdapterError::Sdk(anyhow::anyhow!("{error}")))?;
                let spender = Account::from_meta_keys(&k, &v)?;
                persisted.spender = Some(StoredSpender { k, v });
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
            state: parking_lot::Mutex::new(persisted),
            spender,
            client: tokio::sync::OnceCell::new(),
            chain: tokio::sync::Mutex::new(()),
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

    /// Shields without an entry portal, paid by whatever account the [`DirectShielder`] drives —
    /// the node's Safe.
    ///
    /// Must be called with the chain lock held.
    ///
    /// The note is journalled **before** submission, and a journalled note is checked against the
    /// chain before it would be shielded again: the shielder cannot report an ambiguous outcome
    /// the way the SDK's own submission path can, so a crash between submitting and recording
    /// success is indistinguishable from a crash before submitting, and only the chain can say
    /// which happened.
    async fn direct_shield(&self, gross: u128) -> Result<Vec<TxLedger>, RsSdkCurvyAdapterError> {
        let Some(shielder) = self.shielder.clone() else {
            return Err(RsSdkCurvyAdapterError::InvalidValue(
                "direct shielding was selected but the pool was built without a shielder".to_owned(),
            ));
        };
        let (client, endpoints) = self.client().await?;

        // Resume an in-flight shield rather than preparing a second one: the note is
        // deterministic in its inputs, but a fresh `prepare_direct_shield` would seal a new one.
        let in_flight = self.state.lock().direct_shield_in_flight.clone();
        let prepared = match in_flight {
            Some(stored) if stored.gross == gross.to_string() => {
                let note = OwnedNote::try_from(&stored.note)?;
                PreparedDirectShield::from_recovery_parts(note, gross)
            }
            Some(_) => return Err(RsSdkCurvyAdapterError::ShieldInProgress),
            None => {
                let prepared = client
                    .prepare_direct_shield(&self.spender, gross, self.config.token)
                    .await?;
                let mut state = self.state.lock();
                state.direct_shield_in_flight = Some(StoredDirectShield {
                    note: StoredNote::from(&prepared.note),
                    gross: gross.to_string(),
                });
                self.store.save(&state)?;
                prepared
            }
        };

        // A note the aggregator already knows was shielded by an earlier attempt whose outcome we
        // lost. Shielding again would spend the float twice.
        let observed = client.note_status(&prepared.note.note_id()).await?;
        if !matches!(observed, 1 | 2) {
            let token: Address = endpoints
                .token_address
                .parse()
                .map_err(|error| RsSdkCurvyAdapterError::InvalidValue(format!("token address: {error}")))?;
            let vault: Address = endpoints
                .vault
                .parse()
                .map_err(|error| RsSdkCurvyAdapterError::InvalidValue(format!("vault address: {error}")))?;
            let aggregator: Address = endpoints
                .aggregator
                .parse()
                .map_err(|error| RsSdkCurvyAdapterError::InvalidValue(format!("aggregator address: {error}")))?;
            let calldata = prepared.calldata()?;
            tracing::info!(%gross, %vault, "shielding the Curvy funding note directly from the Safe");
            shielder(calldata, token, vault, aggregator, gross)
                .await
                // A revert here is most often the one setup step nothing performs automatically,
                // so the error says which rather than leaving an operator to decode a receipt.
                .map_err(|error| {
                    RsSdkCurvyAdapterError::Funding(format!(
                        "{error}\n\nA direct shield reverts until the node's Safe is allowed to call the Curvy \
                         aggregator ({aggregator}). Grant it once per Safe with `scripts/scope-curvy-aggregator.sh`, \
                         or check that the deployment has `directShieldEnabled` set."
                    ))
                })?;
        }

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
        self.recover_pending().await
    }

    /// Shields initial private-pool funding if no durable funding already exists.
    async fn shield(&self, gross: u128, recovery_address: &str) -> Result<Vec<TxLedger>, RsSdkCurvyAdapterError> {
        let _chain = self.chain.lock().await;
        let (client, endpoints) = self.client().await?;
        self.reconcile_relay_aggregation().await?;
        self.recover_pending().await?;
        let already_funded = {
            let state = self.state.lock();
            !state.funding.is_empty() && state.shield_in_flight.is_none() && state.direct_shield_in_flight.is_none()
        };
        if already_funded {
            return Ok(Vec::new());
        }
        if self.config.shielding == CurvyShielding::Direct {
            return self.direct_shield(gross).await;
        }
        let mut shield = if let Some(shield) = self.state.lock().shield_in_flight.clone() {
            if shield.gross != gross.to_string() || shield.recovery != recovery_address {
                return Err(RsSdkCurvyAdapterError::ShieldInProgress);
            }
            shield
        } else {
            let prepared = client
                .prepare_deposit(&self.spender, gross, self.config.token, recovery_address)
                .await?;
            let shield = StoredShield {
                note: StoredNote::from(&prepared.note),
                gross: prepared.gross.to_string(),
                recovery: prepared.recovery,
                portal_address: prepared.portal_address,
                stage: StoredShieldStage::Prepared,
            };
            let mut state = self.state.lock();
            state.shield_in_flight = Some(shield.clone());
            self.store.save(&state)?;
            shield
        };
        let prepared = shield.prepared()?;
        let observed_status = client.note_status(&prepared.note.note_id()).await?;
        let mut ledger = Vec::new();
        if !matches!(observed_status, 1 | 2) {
            if shield.stage == StoredShieldStage::Prepared {
                let mut portal_balance = client
                    .erc20_balance(&endpoints.token_address, &prepared.portal_address)
                    .await?;
                if portal_balance == 0 {
                    let portal = Address::from_str(&prepared.portal_address).map_err(|error| {
                        RsSdkCurvyAdapterError::InvalidValue(format!("shield portal address: {error}"))
                    })?;
                    tracing::info!(%portal, gross, "funding the Curvy shield portal from the Safe");
                    (self.funder)(portal, HoprBalance::from(U256::from(gross)))
                        .await
                        .map_err(RsSdkCurvyAdapterError::Funding)?;
                    portal_balance = client
                        .erc20_balance(&endpoints.token_address, &prepared.portal_address)
                        .await?;
                }
                if portal_balance != gross {
                    return Err(RsSdkCurvyAdapterError::UnexpectedShieldFunding {
                        actual: portal_balance,
                        required: gross,
                    });
                }
                shield.stage = StoredShieldStage::Funded;
                let mut state = self.state.lock();
                state.shield_in_flight = Some(shield.clone());
                self.store.save(&state)?;
            }
            let entry = client
                .shield_prepared_deposit(&prepared, &self.config.operator_private_key, self.config.route)
                .await?;
            tracing::info!(tx = %entry.tx_hash, backend = %entry.backend, "shielded the Curvy funding note");
            ledger.push(entry);
        }
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
        ledger.extend(self.recover_pending().await?);
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
                    .commit(&ids, &self.config.operator_private_key, self.config.route)
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
        let relay_fee = Self::relay_fee_recipient(relay, endpoints.chain_id, self.config.token).await?;
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
        let (client, _) = self.client().await?;
        let ids = pending
            .emitted
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
                let was_attempted = pending.attempted;
                pending.attempted = true;
                self.save_relay_attempt(index, pending.clone())?;
                match relay
                    .submit(
                        curvy_abi::RelayAction::Aggregation,
                        pending.chain_id,
                        pending.max_inputs,
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
        self.reconcile_relay_aggregation().await?;
        let ambiguous = self.state.lock().ambiguous_allocation;
        if ambiguous && !self.reconcile_ambiguous_allocation().await? {
            return Err(RsSdkCurvyAdapterError::AmbiguousAllocation);
        }
        let deposits = {
            let mut pending = Vec::new();
            for (id, address, scan_key, amount) in deposits {
                if let Some(existing) = self.store.allocation(&id_bytes(id))? {
                    if !existing.matches(address, *scan_key, *amount) {
                        return Err(RsSdkCurvyAdapterError::ConflictingAllocation);
                    }
                    match existing.stage {
                        StoredAllocationStage::Completed => continue,
                        StoredAllocationStage::Prepared => {
                            return Err(RsSdkCurvyAdapterError::AmbiguousAllocation);
                        }
                    }
                }
                pending.push((*id, *address, *scan_key, *amount));
            }
            pending
        };
        let mut receipts = self.recover_pending().await?;
        for chunk in deposits.chunks(MAX_ALLOCATIONS_PER_PROOF) {
            // A relayed aggregation carries a gas-reimbursement note for the relayer's operator;
            // a self-submitted one pays its own gas and carries none.
            let relay_fee = match (self.config.submission, self.relay.as_ref()) {
                (CurvySubmission::Relayer, Some(relay)) => {
                    Self::relay_fee_recipient(relay, endpoints.chain_id, self.config.token).await?
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
            let minimum = client.pix_minimum_input(&Fr::from(self.config.token), total, 0).await?;
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
                    let available = selected.iter().try_fold(0_u128, |total, candidate| {
                        total.checked_add(candidate.2).ok_or_else(|| {
                            RsSdkCurvyAdapterError::InvalidValue("funding total overflows u128".to_owned())
                        })
                    })?;
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
            if self.config.submission == CurvySubmission::Operator {
                let state = self.state.lock();
                self.store.save_update(&state, &allocation_records, &[])?;
            }
            let funding_notes = funding.iter().map(|(_, note, _)| note.clone()).collect::<Vec<_>>();
            let aggregated = client
                .build_pix_aggregation(
                    &self.spender,
                    &funding_notes,
                    &allocations,
                    relay_fee.as_ref().map(|(identity, amount)| (identity, *amount)),
                    fee_recipient.as_ref(),
                )
                .await;
            let aggregated = match aggregated {
                Ok(request) => match (self.config.submission, self.relay.as_ref()) {
                    (CurvySubmission::Relayer, Some(_)) => {
                        self.prepare_relay_aggregation(&request, endpoints, &funding_notes, &allocation_records)?;
                        // Errors retain the exact request and its outputs. They must not enter
                        // the operator SDK's generic cleanup path below.
                        self.reconcile_relay_aggregation().await?;
                        receipts.extend(self.recover_pending().await?);
                        continue;
                    }
                    _ => {
                        client
                            .submit_pix_aggregation(request, &self.config.operator_private_key, self.config.route)
                            .await
                    }
                },
                Err(error) => Err(error),
            };
            let result = match aggregated {
                Ok(result) => result,
                Err(error) => {
                    if let Some(ambiguous) = curvy_sdk::ambiguous_pix_aggregation(&error) {
                        let mut state = self.state.lock();
                        state.ambiguous_allocation = true;
                        state.ambiguous_inputs = funding.iter().map(|(stored, ..)| stored.clone()).collect();
                        state.ambiguous_change = Some(StoredNote::from(&ambiguous.result.change));
                        state.ambiguous_emitted = ambiguous
                            .result
                            .emitted_notes
                            .iter()
                            .filter(|note| note.amount != Fr::from(0_u8))
                            .map(StoredNote::from)
                            .collect();
                        state.ambiguous_allocation_ids = allocation_records.iter().map(|record| record.id).collect();
                        self.store.save(&state)?;
                    } else if curvy_sdk::ambiguous_submission(&error).is_some() {
                        let mut state = self.state.lock();
                        state.ambiguous_allocation = true;
                        state.ambiguous_allocation_ids = allocation_records.iter().map(|record| record.id).collect();
                        self.store.save(&state)?;
                    } else {
                        let state = self.state.lock();
                        let ids = allocation_records.iter().map(|record| record.id).collect::<Vec<_>>();
                        self.store.save_update(&state, &[], &ids)?;
                    }
                    return Err(error.into());
                }
            };
            {
                let mut state = self.state.lock();
                state
                    .funding
                    .retain(|note| !funding.iter().any(|(stored, ..)| stored == note));
                state.funding.push(StoredNote::from(&result.change));
                state.pending.extend(
                    result
                        .emitted_notes
                        .iter()
                        .filter(|note| note.amount != Fr::from(0_u8))
                        .map(StoredNote::from),
                );
                let ids = allocation_records.iter().map(|record| record.id).collect::<Vec<_>>();
                let completed = self.store.completed_allocations(&ids)?;
                self.store.save_update(&state, &completed, &[])?;
            }
            for entry in &result.ledger {
                tracing::info!(
                    tx = %entry.tx_hash,
                    allocations = chunk.len(),
                    "aggregated Curvy PIX allocations"
                );
            }
            let mut ledger = result.ledger;
            ledger.extend(self.recover_pending().await?);
            receipts.extend(ledger);
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
    fn select_notes(
        notes: Vec<CommittedCurvyNote>,
        amount: Option<HoprBalance>,
    ) -> Result<Vec<OwnedNote>, RsSdkCurvyAdapterError> {
        let mut notes = notes.iter().map(Self::owned_note).collect::<Result<Vec<_>, _>>()?;
        let Some(target) = amount else {
            return Ok(notes);
        };
        let target = balance_u128(target)?;
        notes.sort_by_key(|note| std::cmp::Reverse(fr_to_biguint(&note.amount)));
        let mut selected = Vec::new();
        let mut total = 0_u128;
        for note in notes {
            if total >= target {
                break;
            }
            let value: u128 = fr_to_biguint(&note.amount)
                .try_into()
                .map_err(|_| RsSdkCurvyAdapterError::InvalidValue("note amount does not fit u128".to_owned()))?;
            total = total
                .checked_add(value)
                .ok_or_else(|| RsSdkCurvyAdapterError::InvalidValue("note total overflows u128".to_owned()))?;
            selected.push(note);
        }
        if total < target {
            return Err(RsSdkCurvyAdapterError::InsufficientNotes {
                requested: target,
                available: total,
            });
        }
        if total != target {
            return Err(RsSdkCurvyAdapterError::InexactWithdrawal {
                requested: target,
                selected: total,
            });
        }
        Ok(selected)
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

    async fn ensure_funded(&self, gross: HoprBalance, recovery_address: Address) -> Result<(), Self::Error> {
        self.shield(balance_u128(gross)?, &recovery_address.to_string())
            .await
            .map(|_| ())
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
            (
                state
                    .funding
                    .iter()
                    .filter(|note| {
                        !state
                            .relay_aggregations
                            .iter()
                            .any(|attempt| attempt.inputs.contains(note))
                    })
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
            spender: state.spender.clone(),
            ..Default::default()
        };
        self.store.reset(&state)
    }
}

fn balance_u128(balance: HoprBalance) -> Result<u128, RsSdkCurvyAdapterError> {
    u128::try_from(balance.amount())
        .map_err(|_| RsSdkCurvyAdapterError::InvalidValue(format!("{balance} does not fit u128")))
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
    use curvy_core::{field::Fr, witness::Note};
    use hopr_api::types::{
        crypto::prelude::{BjjKeypair, Keypair},
        crypto_random::Randomizable,
        internal::prelude::HoprPseudonym,
    };

    use super::*;
    use crate::pix::pools::curvy::{OwnedCurvyDeposit, detect::public_key_from_dec};

    type Adapter = RsSdkCurvyAdapter<blokli_client::BlokliClient>;

    fn test_adapter(state: &RedbCurvyDepositState, url: Url) -> anyhow::Result<Adapter> {
        // Stable full-width keys keep recovery tests independent of random SDK key
        // encodings that can omit leading zero bytes on a subsequent reload.
        let store = RedbCurvySdkStore::new(state)?;
        let mut persisted = store.load()?;
        if persisted.spender.is_none() {
            persisted.spender = Some(StoredSpender {
                k: "01".repeat(32),
                v: "02".repeat(32),
            });
            store.save(&persisted)?;
        }
        let blokli = Arc::new(blokli_client::BlokliClient::new(url.clone(), Default::default()));
        let config = RsSdkCurvyAdapterConfig::new(String::new(), 4).with_modes(
            CurvyShielding::Direct,
            CurvySubmission::Relayer,
            Some(url.clone()),
        );
        let adapter = Adapter::new(
            blokli,
            url.to_string(),
            config,
            Arc::new(|_, _| Box::pin(async { panic!("unexpected funding call") })),
            None,
            Some(Arc::new(RelayClient::new(
                url.clone(),
                std::time::Duration::from_secs(2),
            )?)),
            state,
        )?;
        let endpoints = CurvyChainEndpoints {
            aggregator: format!("0x{}", "01".repeat(20)),
            portal_factory: None,
            vault: format!("0x{}", "02".repeat(20)),
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
            let state = RedbCurvyDepositState::open(&path)?;
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
        let state = RedbCurvyDepositState::open(&path)?;
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
    fn allocation_history_migrates_atomically_and_survives_reopening() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("state.redb");
        let mut completed = stored_fixture(7)?;
        completed.stage = StoredAllocationStage::Completed;
        let prepared = stored_fixture(8)?;
        {
            let db = RedbCurvyDepositState::open(&path)?;
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
        let db = RedbCurvyDepositState::open(&path)?;
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
        let mut state = RedbCurvyDepositState::open(&path)?;
        let database = Arc::new(parking_lot::Mutex::new(Some(state.shared_database())));
        let progress = Arc::new(AtomicUsize::new(0));
        let posts = Arc::new(AtomicUsize::new(0));
        let notes = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let server = relayer::http_tests::Server::new({
            let database = database.clone();
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
            state = RedbCurvyDepositState::open(&path)?;
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
            let state = RedbCurvyDepositState::open(&path)?;
            let database = Arc::new(parking_lot::Mutex::new(Some(state.shared_database())));
            let chain_notes = Arc::new(parking_lot::Mutex::new(Vec::new()));
            let finalized = Arc::new(AtomicBool::new(false));
            let sent = Arc::new(parking_lot::Mutex::new(Vec::new()));
            let builds = AtomicUsize::new(0);
            let server = relayer::http_tests::Server::new({
                let database = database.clone();
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
            let state = RedbCurvyDepositState::open(&path)?;
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
            let state = RedbCurvyDepositState::open(&path)?;
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
            let state = RedbCurvyDepositState::open(&path)?;
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
            let landed = landed.clone();
            move |path, _| {
                if path == "/graphql" {
                    return Some(note_status_response(landed.load(Ordering::SeqCst)));
                }
                let store = RedbCurvySdkStore { db: db.clone() };
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
            token_address: "0x03".to_owned(),
            chain_id: 100,
        };
        assert_eq!(endpoints.require_portal_factory()?, "0xfac");
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
        let (spend_meta_key, _) = stealth::get_meta(spend_private_key, view_private_key)?;
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
        let (big_k, big_v) = stealth::get_meta("07", "0b")?;
        let recipient = StoredAllocation::recipient(&committed.deposit.address, key)?;
        assert_eq!(recipient.viewer.big_k, big_k);
        assert_eq!(recipient.viewer.big_v, big_v);
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
