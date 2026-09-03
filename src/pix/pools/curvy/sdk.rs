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
    Account, CurvyClient, Identity, OwnedNote, PreparedDeposit, Route, ScanRecipient, TxLedger, ViewerIdentity,
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
    CommittedCurvyNote, CurvyWithdrawalOutcome,
    detect::{bjj_point, scan_public_key_dec},
    state::{RedbCurvyDepositState, id_bytes},
};

const SDK_STATE_TABLE: TableDefinition<u8, Vec<u8>> = TableDefinition::new("curvy_pix_sdk_state");
const SDK_STATE_KEY: u8 = 0;
/// Verifier profile `(2, 9)`: nine regular outputs, one reserved for change.
const MAX_ALLOCATIONS_PER_PROOF: usize = 7;
/// The pending-commitment profile takes at most five note ids.
const MAX_COMMITMENTS_PER_PROOF: usize = 5;
/// The PIX withdrawal profile takes at most ten notes.
const MAX_WITHDRAWAL_INPUTS: usize = 10;
/// An aggregation spends one or two committed input notes.
const MAX_ALLOCATION_INPUTS: usize = 2;

/// Transfers `amount` of wxHOPR to a shield portal, resolving once the transfer is confirmed.
///
/// Built by the pool over the node's chain API — see the module docs for why the Safe pays.
pub type PortalFunder = Arc<dyn Fn(Address, HoprBalance) -> BoxFuture<'static, Result<(), String>> + Send + Sync>;

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
    /// `false` means the durable state describes a different chain than the one behind the
    /// endpoint (a re-created development chain, typically) and must be discarded.
    async fn chain_state_is_consistent(&self) -> Result<bool, Self::Error>;

    /// Discards everything chain-specific, keeping only the node's Curvy identity.
    fn reset_chain_state(&self) -> Result<(), Self::Error>;
}

/// Runtime configuration for the rs-sdk allocation and withdrawal bridge.
pub struct RsSdkCurvyAdapterConfig {
    /// Curvy relayer/operator EVM key: role-gated portal deployment and pending-note commitment,
    /// and the submitter of allocation and withdrawal calls.
    pub operator_private_key: String,
    /// Token identifier used by all pool notes.
    pub token: u64,
    /// Transaction route. Production should use [`Route::Blokli`].
    pub route: Route,
    /// Fee collector identity required when the configured protocol fee is non-zero.
    pub fee_recipient: Option<Identity>,
}

impl RsSdkCurvyAdapterConfig {
    pub fn new(operator_private_key: String, token: u64) -> Self {
        Self {
            operator_private_key,
            token,
            route: Route::Blokli,
            fee_recipient: None,
        }
    }
}

/// Errors raised by the rs-sdk bridge.
#[derive(Debug, thiserror::Error)]
pub enum RsSdkCurvyAdapterError {
    #[error(transparent)]
    Sdk(#[from] anyhow::Error),
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
    allocations: Vec<StoredAllocation>,
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
        write.commit().map_err(db_error)?;
        Ok(Self { db })
    }

    fn load(&self) -> Result<SdkState, RsSdkCurvyAdapterError> {
        let read = self.db.begin_read().map_err(db_error)?;
        let table = read.open_table(SDK_STATE_TABLE).map_err(db_error)?;
        table
            .get(SDK_STATE_KEY)
            .map_err(db_error)?
            .map(|value| serde_json::from_slice(&value.value()).map_err(anyhow::Error::new))
            .transpose()?
            .map_or_else(|| Ok(SdkState::default()), Ok)
    }

    fn save(&self, state: &SdkState) -> Result<(), RsSdkCurvyAdapterError> {
        let encoded = serde_json::to_vec(state).map_err(anyhow::Error::new)?;
        let write = self.db.begin_write().map_err(db_error)?;
        {
            let mut table = write.open_table(SDK_STATE_TABLE).map_err(db_error)?;
            table.insert(SDK_STATE_KEY, encoded).map_err(db_error)?;
        }
        write.commit().map_err(db_error)?;
        Ok(())
    }
}

fn db_error(error: impl std::fmt::Display) -> RsSdkCurvyAdapterError {
    RsSdkCurvyAdapterError::Sdk(anyhow::anyhow!(error.to_string()))
}

/// The Curvy deployment behind a Blokli endpoint, read from `chain_info` rather than configured.
#[derive(Clone, Debug)]
pub struct CurvyChainEndpoints {
    pub aggregator: String,
    pub portal_factory: String,
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
        Ok(Self {
            aggregator: contract("curvy_aggregator")?,
            portal_factory: contract("curvy_portal_factory")?,
            token_address: contract("token")?,
            chain_id: u64::try_from(chain_info.chain_id)
                .map_err(|_| RsSdkCurvyAdapterError::Discovery("negative chain id".to_owned()))?,
        })
    }
}

/// Constructs a Curvy client whose reads and submissions all go through Blokli.
pub fn blokli_curvy_client(blokli_url: impl Into<String>, endpoints: &CurvyChainEndpoints) -> Arc<CurvyClient> {
    let blokli = Arc::new(curvy_chain_blokli::BlokliChain::new(blokli_url));
    Arc::new(CurvyClient::new(
        blokli.clone(),
        blokli.clone(),
        blokli.clone(),
        blokli.clone(),
        blokli.clone(),
        blokli.clone(),
        blokli,
        endpoints.aggregator.clone(),
        endpoints.portal_factory.clone(),
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
    store: RedbCurvySdkStore,
    state: parking_lot::Mutex<SdkState>,
    spender: Account,
    client: tokio::sync::OnceCell<(Arc<CurvyClient>, CurvyChainEndpoints)>,
    /// Serialises everything that submits a transaction or spends a note.
    chain: tokio::sync::Mutex<()>,
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
        state: &RedbCurvyDepositState,
    ) -> Result<Self, RsSdkCurvyAdapterError> {
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
            store,
            state: parking_lot::Mutex::new(persisted),
            spender,
            client: tokio::sync::OnceCell::new(),
            chain: tokio::sync::Mutex::new(()),
        })
    }

    async fn client(&self) -> Result<&(Arc<CurvyClient>, CurvyChainEndpoints), RsSdkCurvyAdapterError> {
        self.client
            .get_or_try_init(|| async {
                let endpoints = CurvyChainEndpoints::discover(self.blokli.as_ref()).await?;
                tracing::info!(
                    aggregator = %endpoints.aggregator,
                    portal_factory = %endpoints.portal_factory,
                    token = %endpoints.token_address,
                    chain_id = endpoints.chain_id,
                    "discovered the Curvy deployment through Blokli"
                );
                let client = blokli_curvy_client(self.blokli_url.clone(), &endpoints);
                Ok((client, endpoints))
            })
            .await
    }

    /// Shields initial private-pool funding if no durable funding already exists.
    async fn shield(&self, gross: u128, recovery_address: &str) -> Result<Vec<TxLedger>, RsSdkCurvyAdapterError> {
        let _chain = self.chain.lock().await;
        let (client, endpoints) = self.client().await?;
        self.recover_pending().await?;
        let already_funded = {
            let state = self.state.lock();
            !state.funding.is_empty() && state.shield_in_flight.is_none()
        };
        if already_funded {
            return Ok(Vec::new());
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
            for allocation in &mut state.allocations {
                if allocation_ids.contains(&allocation.id) {
                    allocation.stage = StoredAllocationStage::Completed;
                }
            }
            state.ambiguous_allocation_ids.clear();
            self.store.save(&state)?;
        }
        self.recover_pending().await?;
        Ok(true)
    }

    /// Commits every emitted note Blokli has not yet seen committed. Must be called with the
    /// chain lock held.
    async fn recover_pending(&self) -> Result<Vec<TxLedger>, RsSdkCurvyAdapterError> {
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

    async fn allocate_all(
        &self,
        deposits: &[(PixAddressId, BjjPublicKey, CurvyScanPublicKey, HoprBalance)],
    ) -> Result<Vec<TxLedger>, RsSdkCurvyAdapterError> {
        let _chain = self.chain.lock().await;
        let (client, _) = self.client().await?;
        if self.state.lock().ambiguous_allocation && !self.reconcile_ambiguous_allocation().await? {
            return Err(RsSdkCurvyAdapterError::AmbiguousAllocation);
        }
        let deposits = {
            let state = self.state.lock();
            let mut pending = Vec::new();
            for (id, address, scan_key, amount) in deposits {
                if let Some(existing) = state
                    .allocations
                    .iter()
                    .find(|allocation| allocation.id == id_bytes(id))
                {
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
        let mut receipts = Vec::new();
        self.recover_pending().await?;
        for chunk in deposits.chunks(MAX_ALLOCATIONS_PER_PROOF) {
            let allocations = chunk
                .iter()
                .map(|(_id, address, scan_key, amount)| {
                    let amount = balance_u128(*amount)?;
                    Ok((Self::recipient(address, *scan_key)?, amount))
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
            {
                let mut state = self.state.lock();
                state.allocations.extend(allocation_records.clone());
                self.store.save(&state)?;
            }
            let funding_notes = funding.iter().map(|(_, note, _)| note.clone()).collect::<Vec<_>>();
            let aggregated = client
                .aggregate_pix_allocations(
                    &self.spender,
                    &funding_notes,
                    &allocations,
                    None,
                    self.config.fee_recipient.as_ref(),
                    &self.config.operator_private_key,
                    self.config.route,
                )
                .await;
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
                        let mut state = self.state.lock();
                        state
                            .allocations
                            .retain(|allocation| !allocation_records.iter().any(|record| record.id == allocation.id));
                        self.store.save(&state)?;
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
                for allocation in &mut state.allocations {
                    if allocation_records.iter().any(|record| record.id == allocation.id) {
                        allocation.stage = StoredAllocationStage::Completed;
                    }
                }
                self.store.save(&state)?;
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
        let (client, _) = self.client().await?;
        let mut spent_note_ids = Vec::new();
        let mut withdrawn = 0_u128;
        for chunk in notes.chunks(MAX_WITHDRAWAL_INPUTS) {
            let spends = chunk.iter().map(|note| (secret, note)).collect::<Vec<_>>();
            let (amount, ledger) = client
                .withdraw_pix_multi_owner(
                    &spends,
                    &destination.to_string(),
                    &self.config.operator_private_key,
                    self.config.route,
                )
                .await?;
            for entry in &ledger {
                tracing::info!(tx = %entry.tx_hash, notes = chunk.len(), amount, "withdrew Curvy PIX notes");
            }
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
        let (funding, pending) = {
            let state = self.state.lock();
            (state.funding.clone(), state.pending.clone())
        };
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
        self.store.save(&state)
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
        let recipient = Adapter::recipient(&committed.deposit.address, key)?;
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
