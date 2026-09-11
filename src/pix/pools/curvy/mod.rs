//! ## Curvy [`DepositPool`] implementation — anonymous settlement through the Curvy shielded pool
//!
//! [`CurvyDepositPool`] is the counterpart to `plain::NonAnonymousDepositPool` for the Baby JubJub
//! instantiation of `HoprPixSpec`, where a deposit address is a curve point rather than an
//! Ethereum account. Deposits are Curvy *allocations* inside a shielded pool, recovered deposits
//! are withdrawn from it, and nothing on chain links the two to each other or to this node.
//!
//! ### Two keys per SSA
//!
//! The PIX deposit address stays what the SSA protocol makes it: the Baby JubJub public key whose
//! private key the Exit reconstructs from shares. That key is the note's **owner** and the only
//! spending authority. What Curvy adds is *discovery*: the Exit cannot scan the whole pool with a
//! key it does not have yet, so for every SSA it mints a throwaway **scan identity** `(K, V)` — a
//! stealth meta-key pair whose spend scalar is discarded on the spot. The public half travels to
//! the Entry as the allocation's deposit data; the view scalar `v` stays at the Exit, persisted
//! keyed by the allocation, and is what later recognises the note among everyone else's.
//!
//! | event | who | what this pool does |
//! |---|---|---|
//! | `DepositDataRequest` | Exit | mints `(K, V)`, **persists the secret**, returns the public half as [`CurvyDepositData`] |
//! | `NewDepositAddress` | Entry | shields the float from the Safe on first use, then allocates the priced amount to the SSA owner, discoverable by `(K, V)` |
//! | `DepositAddressReceived` | Exit | watches Blokli's note index with `v` until the allocation is committed and final |
//! | `PrivateKeyRecovered` | Exit | withdraws the committed notes with the reconstructed key, to the Safe |
//!
//! ### Two independent choices
//!
//! How the float enters the pool and how proofs reach the chain are separate settings, because
//! the Curvy relayer never handles deposits — a shield is a self-signed transaction either way.
//!
//! | | default | alternative |
//! |---|---|---|
//! | [`CurvyDepositPoolConfig::shielding`] | `direct` — the Safe calls `directShield`, no portal | `portal` — fund a deterministic entry portal, then deploy and shield it |
//! | [`CurvyDepositPoolConfig::submission`] | `relayer` — hand proofs to Curvy's off-chain relayer | `operator` — sign and submit them here |
//!
//! Both defaults describe a production deployment. The localcluster runs
//! `submission: operator`, since it has no off-chain Curvy infrastructure at all.
//!
//! **A direct shield never takes the float out of the Safe.** The vault pulls with
//! `safeTransferFrom(msg.sender_of_the_aggregator_call, ...)`, so the Safe itself calls
//! `directShield`, through its permission module, in one transaction that also approves the
//! vault. That needs a one-time grant per Safe — see *Setup* below — and the node's own chain key
//! to sign the module call, which is why the builder takes one.
//!
//! **Under `submission: relayer` the pool commits nothing.** The relayer refuses
//! `commitPendingNotes`, and the deployment's shared batch-prover commits every pending note
//! anyway. Discovery is unaffected: it waits for *committed and final* through Blokli, and does
//! not care who committed.
//!
//! ### Setup, once per Safe
//!
//! A direct shield reverts with `NonExistentKey()` until the node's Safe is allowed to call the
//! Curvy aggregator. Nothing does this automatically:
//!
//! ```text
//! ./scripts/scope-curvy-aggregator.sh --module 0xMODULE --aggregator 0xAGGREGATOR
//! ```
//!
//! which prints the Safe transaction to execute. The grant is `ALLOW_ALL` on that one address —
//! the module's selector whitelist is hardcoded and cannot express `directShield` any other way —
//! so point it at an aggregator you have verified. See the script for what that permits.
//!
//! ### What it needs at runtime
//!
//! * A **Blokli endpoint** ([`CurvyDepositPoolConfig::blokli_url`]) whose `chain_info` names the Curvy deployment
//!   (`curvy_aggregator`, `curvy_vault`, `token`, and `curvy_portal_factory` where one exists) and that indexes Curvy
//!   notes. Reads go through it, and so do submissions under `submission: operator`.
//! * A **relayer endpoint** ([`CurvyDepositPoolConfig::relayer_url`]) under `submission: relayer` —
//!   `https://api.curvy.box` in production, `https://api.curvy.dev` for staging. No default: pointing a misconfigured
//!   node at a production relayer is worse than refusing to start.
//! * The **Curvy operator key**, from the environment variable named by
//!   [`CurvyDepositPoolConfig::operator_key_env`] — **only under `submission: operator`**, where it signs and pays for
//!   allocations, withdrawals and note commitments. A relayed node needs no EVM key of its own: the relayer submits,
//!   the batch-prover commits, and the shield is signed by the node's existing chain key.
//! * The Curvy **proving artifacts**: every allocation, commitment and withdrawal is a Groth16 proof made in-process,
//!   and the SDK loads each circuit's zkey and witness graph from `CURVY_ZK_KEYS_DIR` (flat, one zkey and one
//!   `*.signet.zst` graph per circuit, digest-checked; a `CURVY_*_ZKEY` / `CURVY_*_GRAPH` pair per circuit overrides
//!   the directory). All ten files ship with each SDK release. Without them the first deposit fails with "location is
//!   not configured".
//! * A **Safe with wxHOPR** (Entry): the shield is funded from it through the node's own chain API, like the plain
//!   pool's deposits. The amount is [`CurvyDepositPoolConfig::initial_funding`], overridable through
//!   [`INITIAL_FUNDING_ENV`], and it is shielded **lazily** — on the first deposit, not at startup — so a node that
//!   never deposits never moves anything.
//! * A **state file** ([`CurvyDepositPoolConfig::state_path`]) that survives restarts: it holds the node's Curvy
//!   identity, the funding notes, every discovered note and the scan secrets. Losing it loses the ability to sweep what
//!   has not been swept yet.
//!
//! ### Restarts and stale state
//!
//! The state file describes one particular chain. Against a re-created development chain — the
//! localcluster does exactly that on every run — the same file would make the Entry believe it is
//! funded and the Exit skip events it has not seen. So the first operation after a start checks
//! the state against the endpoint: a cursor past the indexer's head, or a note the aggregator has
//! never heard of, means a different chain, and everything chain-specific is discarded (the
//! node's Curvy identity is kept).
//!
//! Enabled by `strategy-pix-curvy`, to be paired with `hopr-lib/pix-bjj` (the default) so that
//! `HoprPixSpec` produces the `BjjPublicKey` deposit addresses this pool settles to. Built through
//! [`PixStrategy::build_curvy`](crate::pix::strategy::PixStrategy::build_curvy).
//!
//! [`DepositPool`]: hopr_api::chain::DepositPool

mod detect;
mod lifecycle;
mod module;
pub mod relayer;
mod sdk;
mod state;
#[cfg(test)]
mod tests;

use std::{path::PathBuf, str::FromStr, sync::Arc, time::Duration};

use blokli_client::{BlokliClient, BlokliClientConfig, exports::Url};
use curvy_core::{eddsa::ScalarSigningKey, field::fr_to_be_32, stealth, witness::Note};
pub use detect::RsCoreCurvyNoteDetector;
use futures::future::BoxFuture;
use hopr_api::{
    chain::{BatchOutcomes, ChainWriteAccountOperations, DepositNotification, DepositPool},
    node::{HasChainApi, PixAddressId, PixDepositData},
    types::{
        crypto::prelude::{
            BjjKeypair, BjjPublicKey, Bn254Keypair, CURVY_SCAN_PUBLIC_KEY_SIZE, CurvyScanPublicKey, CurvyScanSecret,
            Keypair,
        },
        primitive::prelude::{Address, HoprBalance, IntoEndian, U256},
    },
};
pub use lifecycle::{BlokliIndex, CurvyIndexSource};
pub use sdk::{
    CurvyChainEndpoints, CurvySdkAdapter, DirectShielder, PortalFunder, RsSdkCurvyAdapter, RsSdkCurvyAdapterConfig,
    RsSdkCurvyAdapterError,
};
use serde_with::{DisplayFromStr, serde_as};
pub use state::{CurvyDepositState, CurvyEventKind, CurvyStateError, RedbCurvyDepositState};
use validator::Validate;
use zeroize::Zeroizing;

use self::lifecycle::CurvyLifecycleTracker;
use crate::errors::StrategyError;

// ---------------------------------------------------------------------------
// Module-level aliases
// ---------------------------------------------------------------------------

/// This pool's keypair — the `K` in [`DepositPool`], whose `K::Public` is the deposit address it
/// settles to.
///
/// The upstream [`BjjKeypair`] directly: unlike the plain pool, which needs a newtype because a
/// secp256k1 public key is not an Ethereum address, a Baby JubJub deposit address *is* the public
/// key. The `pix::pools::plain` module exports the same names for its own pool, so the two coexist
/// and the choice is made by which one is imported.
pub type PoolKeypair = BjjKeypair;

/// This pool's configuration type.
///
/// Passed to [`PixStrategy::build_curvy`](crate::pix::strategy::PixStrategy::build_curvy) rather
/// than carried in `PixStrategyConfig`, so that a value meant for one pool cannot silently reach
/// the other.
pub type PoolConfig = CurvyDepositPoolConfig;

/// The deposit address this pool settles to — [`BjjPublicKey`], via [`PoolKeypair`].
///
/// A projection rather than `BjjPublicKey` directly, for the reason given on
/// `plain::DepositAddress`: it derives the
/// [`DepositAddressOf`](crate::pix::DepositAddressOf) impl below from the keypair instead of
/// restating it, so the impl cannot claim an address type this pool does not settle to.
pub type DepositAddress = <PoolKeypair as hopr_api::types::crypto::prelude::Keypair>::Public;

/// Naming [`DepositAddress`] (i.e. `BjjPublicKey`) in
/// [`PixStrategy::build_curvy`](crate::pix::strategy::PixStrategy::build_curvy) is therefore
/// accepted, and naming any other address type is a compile error at that call site.
impl crate::pix::DepositAddressOf<PoolKeypair> for DepositAddress {}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Environment variable that overrides [`CurvyDepositPoolConfig::initial_funding`].
///
/// The shield is the one Safe debit this pool makes, and a deployment may size it per run rather
/// than per config file — the PIX soak test, for one, budgets the Entry to the wxHOPR it expects
/// to see leave the Safe.
pub const INITIAL_FUNDING_ENV: &str = "HOPRD_CURVY_INITIAL_FUNDING";

/// Environment variable that overrides [`CurvyDepositPoolConfig::shielding`].
///
/// Accepts `direct` or `portal`. Present for the same reason as [`SUBMISSION_ENV`]: the
/// localcluster harness builds its PIX stanza from the *plain* pool's config type, so a
/// Curvy-only YAML key is unreachable from there.
pub const SHIELDING_ENV: &str = "HOPRD_CURVY_SHIELDING";

/// Environment variable that overrides [`CurvyDepositPoolConfig::submission`].
///
/// Accepts `relayer` or `operator`.
pub const SUBMISSION_ENV: &str = "HOPRD_CURVY_SUBMISSION";

/// Environment variable that overrides [`CurvyDepositPoolConfig::relayer_url`].
pub const RELAYER_URL_ENV: &str = "HOPRD_CURVY_RELAYER_URL";

/// How the pool moves the node's float into the shielded vault.
///
/// Independent of [`CurvySubmission`]: the Curvy relayer never handles deposits, so a shield is a
/// self-signed transaction whichever way proofs are submitted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CurvyShielding {
    /// `CurvyAggregatorAlphaV2.directShield`, paid straight from the Safe. No portal is deployed,
    /// so the deployment's `portalDeployment` gas-fee leg is not charged.
    ///
    /// The default, and the only option on a portal-less deployment — where `portalFactory` is
    /// `address(0)` and `portalShield` is permanently unreachable.
    #[default]
    Direct,
    /// The deterministic entry-portal flow: fund a CREATE2 portal address from the Safe, then
    /// deploy and shield it. For deployments that still carry a portal factory.
    Portal,
}

/// How the pool gets its Groth16 proofs on chain.
///
/// Also decides who commits pending notes: under [`CurvySubmission::Relayer`] the deployment's
/// shared batch-prover does it, and this pool does not. Under [`CurvySubmission::Operator`] the
/// pool commits with its own key, which is what the localcluster needs — it runs no off-chain
/// Curvy infrastructure at all.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CurvySubmission {
    /// Hand the proof to the Curvy off-chain relayer, which submits and pays gas, reimbursed by
    /// an output note addressed to its operator. The node never appears as a transaction sender.
    #[default]
    Relayer,
    /// Sign and submit every proof locally with the Curvy operator key.
    Operator,
}

impl FromStr for CurvyShielding {
    type Err = StrategyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "direct" => Ok(Self::Direct),
            "portal" => Ok(Self::Portal),
            other => Err(StrategyError::InvalidConfiguration(format!(
                "Curvy shielding must be `direct` or `portal`, got `{other}`"
            ))),
        }
    }
}

impl FromStr for CurvySubmission {
    type Err = StrategyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "relayer" => Ok(Self::Relayer),
            "operator" => Ok(Self::Operator),
            other => Err(StrategyError::InvalidConfiguration(format!(
                "Curvy submission must be `relayer` or `operator`, got `{other}`"
            ))),
        }
    }
}

fn default_blokli_url() -> Url {
    "http://localhost:8080/".parse().expect("valid static URL")
}

fn default_max_deposit_tracking_time() -> Duration {
    Duration::from_secs(60)
}

fn default_token() -> u64 {
    3
}

fn default_initial_funding() -> HoprBalance {
    HoprBalance::new_base(100)
}

fn default_operator_key_env() -> String {
    "HOPRD_CURVY_OPERATOR_PRIVATE_KEY".to_owned()
}

/// The Gnosis Safe MultiSend deployment the node's permission module accepts a `DelegateCall`
/// to — the same address `hopr-types` builds its own Safe bundles against.
///
/// Deterministically deployed, hence identical across chains, but a value the module reads from
/// its own storage rather than a constant of the protocol. Overridable for that reason: a
/// deployment whose module names a different MultiSend would otherwise reject every bundle, and
/// nothing available here can read `module.multisend()` back to check.
const SAFE_MULTI_SEND_ADDRESS: [u8; 20] = [
    0x38, 0x86, 0x9b, 0xf6, 0x6a, 0x61, 0xcf, 0x6b, 0xdb, 0x99, 0x6a, 0x6a, 0xe4, 0x0d, 0x58, 0x53, 0xfd, 0x43, 0xb5,
    0x26,
];

fn default_safe_multisend_address() -> Address {
    Address::from(SAFE_MULTI_SEND_ADDRESS)
}

/// Cross-field validation: relayed submission needs somewhere to submit to.
///
/// Deliberately **not** a `#[validate(schema(...))]` on the config struct, and this is load-
/// bearing rather than stylistic. `hoprd` validates its whole configuration as it parses the
/// file, which happens before [`CurvyDepositPool::new`] applies the `HOPRD_CURVY_*` overrides —
/// so a derive here rejects a file that an override was about to make valid. That is exactly the
/// localcluster's shape: it cannot write `submission` into its YAML (the harness builds the PIX
/// stanza from the *plain* pool's config type, which has no such field), so it sets
/// `HOPRD_CURVY_SUBMISSION=operator` in the environment and omits `relayer_url` because nothing
/// relayed runs there. As a derive, that configuration killed all four nodes at startup.
///
/// Called from `new` instead, once the overrides are in, so it judges the configuration the pool
/// will actually run with rather than the one on disk.
fn validate_mode_requirements(cfg: &CurvyDepositPoolConfig) -> Result<(), StrategyError> {
    if cfg.submission == CurvySubmission::Relayer && cfg.relayer_url.is_none() {
        return Err(StrategyError::InvalidConfiguration(format!(
            "`submission: relayer` needs `relayer_url`; set it, or select `submission: operator` \
             (or {SUBMISSION_ENV}=operator) to sign and submit from this node"
        )));
    }
    Ok(())
}

fn validate_min_1sec(duration: &Duration) -> Result<(), validator::ValidationError> {
    if duration.as_secs() < 1 {
        return Err(validator::ValidationError::new("must be at least 1 second"));
    }
    Ok(())
}

/// Configuration for [`CurvyDepositPool`].
///
/// Deliberately **without** `deny_unknown_fields`: a config written for the plain pool carries
/// keys this pool has no use for (`gas_xdai_per_sweep`, ...), and a binary built with this pool
/// should read such a file rather than refuse it — the fields the two share (`blokli_url`,
/// `max_deposit_tracking_time`) mean the same thing in both.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, smart_default::SmartDefault, Validate)]
pub struct CurvyDepositPoolConfig {
    /// Blokli endpoint the pool discovers the Curvy deployment through, reads the note index
    /// from and submits its transactions to. Default: `http://localhost:8080/`, a placeholder an
    /// operator must replace.
    #[serde_as(as = "DisplayFromStr")]
    #[serde(default = "default_blokli_url")]
    #[default(default_blokli_url())]
    pub blokli_url: Url,

    /// How long [`DepositPool::notify_deposit`]'s future waits for the allocation to be committed
    /// and final before resolving to an error. Default: 60 seconds.
    ///
    /// Size it for the chain: an allocation is a proof plus an aggregation transaction plus the
    /// operator's commitment, and the first one of a run also carries the shield.
    #[default(default_max_deposit_tracking_time())]
    #[serde(with = "humantime_serde", default = "default_max_deposit_tracking_time")]
    #[validate(custom(function = "validate_min_1sec"))]
    pub max_deposit_tracking_time: Duration,

    /// The Curvy vault token id of wxHOPR. Default: 3, which is what Blokli's local Curvy
    /// deployment registers it as.
    ///
    /// **A real deployment almost certainly needs another value.** Ids are assigned sequentially
    /// by `CurvyVaultV2.registerToken`, starting at 2 because id 1 is the vault's pre-seeded
    /// native currency — so on Gnosis, where wxHOPR is the first registered ERC-20, it is **2**.
    /// Getting this wrong does not fail loudly: the pool would allocate against whatever token
    /// that id names. Read it back with Blokli's `curvyVaultToken` before deploying.
    #[default(default_token())]
    #[serde(default = "default_token")]
    #[validate(range(min = 1))]
    pub token: u64,

    /// wxHOPR shielded from the Safe into the private pool on the first deposit, gross of the
    /// deployment's shield fees. Default: 100 wxHOPR. Overridden by [`INITIAL_FUNDING_ENV`].
    ///
    /// Deposits are allocated out of this until it runs out, at which point they fail with
    /// [`StrategyError::CriteriaNotSatisfied`]; the pool does not top itself up.
    #[default(default_initial_funding())]
    #[serde_as(as = "DisplayFromStr")]
    #[serde(default = "default_initial_funding")]
    pub initial_funding: HoprBalance,

    /// Where the pool's durable state lives. Default: `curvy-pix-<node address>.redb` in the
    /// working directory — the address keeps two nodes started from one directory apart.
    ///
    /// Must be the same path on every start; see the module docs for what is lost otherwise.
    #[serde(default)]
    pub state_path: Option<PathBuf>,

    /// Name of the environment variable holding the Curvy operator's EVM private key (hex).
    /// Default: `HOPRD_CURVY_OPERATOR_PRIVATE_KEY`.
    ///
    /// An indirection rather than the key itself, so that no config file ever holds it.
    #[default(default_operator_key_env())]
    #[serde(default = "default_operator_key_env")]
    pub operator_key_env: String,

    /// How the float reaches the shielded vault. Default: [`CurvyShielding::Direct`] — no entry
    /// portal. Overridden by [`SHIELDING_ENV`].
    #[serde(default)]
    pub shielding: CurvyShielding,

    /// How proofs reach the chain. Default: [`CurvySubmission::Relayer`]. Overridden by
    /// [`SUBMISSION_ENV`].
    ///
    /// [`CurvySubmission::Operator`] is what a deployment without Curvy's off-chain services
    /// uses, the localcluster included; it is also what makes [`Self::operator_key_env`]
    /// mandatory.
    #[serde(default)]
    pub submission: CurvySubmission,

    /// Base URL of the Curvy relayer — `https://api.curvy.box` in production,
    /// `https://api.curvy.dev` for staging. The service sits behind the gateway's `/relay`
    /// prefix, which the client appends; give the host only.
    ///
    /// Required when [`Self::submission`] is [`CurvySubmission::Relayer`], and deliberately
    /// without a default: silently pointing a misconfigured node at a production relayer is worse
    /// than refusing to start. Overridden by [`RELAYER_URL_ENV`].
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(default)]
    pub relayer_url: Option<Url>,

    /// The Safe MultiSend the node's permission module delegate-calls for a bundled transaction.
    ///
    /// Only consulted for [`CurvyShielding::Direct`], which bundles the vault approval and the
    /// shield into one transaction so that no allowance outlives the shield it was granted for.
    /// Defaults to the canonical deterministic deployment,
    /// `0x38869bf66a61cf6bdb996a6ae40d5853fd43b526` — the same one `hopr-types` builds its own
    /// Safe bundles against.
    #[serde_as(as = "DisplayFromStr")]
    #[default(default_safe_multisend_address())]
    #[serde(default = "default_safe_multisend_address")]
    pub safe_multisend_address: Address,
}

// ---------------------------------------------------------------------------
// Deposit data
// ---------------------------------------------------------------------------

/// This pool's [`PoolDepositData`](DepositPool::PoolDepositData): the public scan identity `(K, V)`
/// of one allocation.
///
/// Generated by the Exit, carried to the Entry inside the SSA request, and used there to seal the
/// allocation so that only the holder of `v` can find it. Sixty-five bytes on the wire — both
/// points compressed — which is what lets a full batch of nine fit the request's payload budget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurvyDepositData {
    id: PixAddressId,
    scan_key: CurvyScanPublicKey,
}

impl CurvyDepositData {
    pub fn new(id: PixAddressId, scan_key: CurvyScanPublicKey) -> Self {
        Self { id, scan_key }
    }

    /// The allocation this payload belongs to.
    pub fn id(&self) -> &PixAddressId {
        &self.id
    }

    /// The public scan identity the allocation is sealed for.
    pub fn scan_key(&self) -> &CurvyScanPublicKey {
        &self.scan_key
    }
}

impl TryFrom<PixDepositData> for CurvyDepositData {
    type Error = StrategyError;

    fn try_from(data: PixDepositData) -> Result<Self, Self::Error> {
        // Validated once, here: a scan key that decompresses is a scan key every later step can
        // use without re-checking.
        let scan_key = CurvyScanPublicKey::try_from(&*data.data).map_err(|error| {
            StrategyError::other(anyhow::anyhow!(
                "PIX deposit data for {:?} is not a Curvy scan identity: {error}",
                data.id
            ))
        })?;
        Ok(Self { id: data.id, scan_key })
    }
}

impl TryFrom<CurvyDepositData> for PixDepositData {
    type Error = StrategyError;

    fn try_from(value: CurvyDepositData) -> Result<Self, Self::Error> {
        let bytes: [u8; CURVY_SCAN_PUBLIC_KEY_SIZE] = value.scan_key.into();
        Ok(Self {
            id: value.id,
            data: bytes.into(),
        })
    }
}

// ---------------------------------------------------------------------------
// Types shared by the submodules
// ---------------------------------------------------------------------------

/// Deposit metadata retained for correlation and notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedCurvyDeposit {
    /// PIX allocation to which the note belongs.
    pub id: PixAddressId,
    /// PIX deposit address (the note's owner) to which the note belongs.
    pub address: BjjPublicKey,
    /// Amount contained in the note.
    pub amount: HoprBalance,
}

/// A complete owned Curvy note validated by the detector.
#[derive(Clone)]
pub struct DetectedCurvyNote {
    /// HOPR-facing deposit metadata.
    pub deposit: OwnedCurvyDeposit,
    /// Full Curvy witness note required for a later reconstructed-key withdrawal.
    pub note: Note,
}

/// An owned note that has appeared in the committed Curvy tree.
#[derive(Clone)]
pub struct CommittedCurvyNote {
    /// HOPR-facing deposit metadata.
    pub deposit: OwnedCurvyDeposit,
    /// Full note required by Curvy withdrawal witness construction.
    pub note: Note,
    /// Leaf index reported by Blokli when the note was committed.
    pub leaf_index: u64,
}

/// Result of an SDK withdrawal.
pub struct CurvyWithdrawalOutcome {
    /// Note identifiers that must be removed from the spendable set.
    pub spent_note_ids: Vec<String>,
    /// What the withdrawal moved to the destination, before the deployment's withdrawal fees.
    pub withdrawn: HoprBalance,
}

// ---------------------------------------------------------------------------
// The pool
// ---------------------------------------------------------------------------

/// Errors specific to the Curvy pool, wrapped into [`StrategyError::Other`] at the trait boundary.
#[derive(Debug, thiserror::Error)]
pub enum CurvyDepositPoolError {
    #[error("Curvy SDK operation failed: {0}")]
    Adapter(anyhow::Error),
    #[error(transparent)]
    State(#[from] CurvyStateError),
    #[error("invalid reconstructed Baby JubJub PIX withdrawal key: {0}")]
    InvalidReconstructedSecret(String),
    #[error("no Curvy scan secret is stored for PIX allocation {0:?}; its deposit data was never generated here")]
    MissingScanSecret(PixAddressId),
    #[error("PIX deposit data is filed under {actual:?} but the deposit is for {expected:?}")]
    MismatchedDepositData {
        expected: PixAddressId,
        actual: PixAddressId,
    },
    #[error("Curvy deposit watcher stopped before the deposit was committed")]
    WatcherStopped,
    #[error("Curvy indexer query failed: {0}")]
    Indexer(String),
    #[error("timed out waiting for a Curvy deposit to be committed")]
    DepositTimeout,
    #[error("could not generate a Curvy scan identity: {0}")]
    ScanIdentity(String),
    #[error(
        "Curvy pool-to-pool transfer is not supported; PIX settlement withdraws reconstructed deposits to the Safe"
    )]
    UnsupportedPoolTransfer,
}

impl From<CurvyDepositPoolError> for StrategyError {
    fn from(error: CurvyDepositPoolError) -> Self {
        StrategyError::other(error)
    }
}

/// A [`DirectShielder`] that makes the node's **Safe** approve the vault and call
/// `directShield`, in one transaction, through the Safe's permission module.
///
/// This is what keeps a direct deposit non-custodial: the vault pulls from whoever calls
/// `directShield`, so that caller must be the account holding the float. Routing the float
/// through an EOA first would work equally well on chain and would put the node's whole PIX
/// budget behind a hot key.
///
/// Signed with the node's own chain key, which is what the module's `nodeOnly` check requires —
/// no new key material. See [`module::SafeModuleSubmitter`] for the nonce it shares with the
/// node's connector, and why that is safe.
fn safe_direct_shielder<C>(
    client: Arc<C>,
    chain_key: hopr_api::ChainKeypair,
    module_address: Address,
    multisend: Address,
) -> DirectShielder
where
    C: blokli_client::api::BlokliQueryClient + blokli_client::api::BlokliTransactionClient + Send + Sync + 'static,
{
    let submitter = Arc::new(module::SafeModuleSubmitter::new(client, chain_key, module_address));
    Arc::new(
        move |calldata: Vec<u8>, token: Address, vault: Address, aggregator: Address, gross: u128| {
            let submitter = Arc::clone(&submitter);
            Box::pin(async move {
                let bundle =
                    module::encode_safe_direct_shield(&multisend, &token, &vault, &aggregator, gross, calldata);
                submitter
                    .submit(bundle, SAFE_DIRECT_SHIELD_GAS)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }) as BoxFuture<'static, Result<(), String>>
        },
    )
}

/// Gas for the bundled approval and shield.
///
/// The shield is a Groth16-free call — the proving happens off chain — but it deploys nothing and
/// writes one pending note, so this is generous rather than measured. An over-estimate costs
/// nothing but the block's unused gas.
const SAFE_DIRECT_SHIELD_GAS: u64 = 1_500_000;

/// How long a single relayer HTTP request may take.
///
/// Separate from the deadline for a submission to reach the chain: this bounds one round trip,
/// while the submission is queued and polled for much longer.
const RELAYER_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A [`PortalFunder`] that pays from the node's Safe through its chain API.
///
/// [`ChainWriteAccountOperations::withdraw`] settles through the Safe module, which is exactly
/// what funding the shield from the PIX float needs. `withdraw`'s pending future borrows the API,
/// so the API is cloned into the funding future rather than referenced.
fn safe_funder<Api>(api: Api) -> PortalFunder
where
    Api: ChainWriteAccountOperations + Clone + Send + Sync + 'static,
{
    Arc::new(
        move |portal: Address, amount: HoprBalance| -> BoxFuture<'static, Result<(), String>> {
            let api = api.clone();
            Box::pin(async move {
                let pending = api.withdraw(amount, &portal).await.map_err(|error| error.to_string())?;
                pending.await.map_err(|error| error.to_string())?;
                Ok(())
            })
        },
    )
}

/// A [`DepositPool`] settling through the Curvy shielded pool. See the module documentation.
///
/// Deliberately **not** [`Clone`]: the discovery task is aborted on drop, and a clone that goes
/// out of scope would take it down under the pool still in use. The strategy builder wraps it in
/// an [`Arc`] instead.
pub struct CurvyDepositPool<
    N,
    I = BlokliIndex<BlokliClient>,
    A = RsSdkCurvyAdapter<BlokliClient>,
    S = RedbCurvyDepositState,
> {
    node: Arc<N>,
    index: Arc<I>,
    adapter: Arc<A>,
    tracker: Arc<CurvyLifecycleTracker<S>>,
    cfg: CurvyDepositPoolConfig,
    initial_funding: HoprBalance,
    reconciled: tokio::sync::OnceCell<()>,
    watcher: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl<N> CurvyDepositPool<N>
where
    N: HasChainApi + Send + Sync + 'static,
{
    /// Creates the production pool: a Blokli client from `cfg.blokli_url`, the state file from
    /// `cfg.state_path`, the operator key from the environment, and the Safe as the shield's
    /// funding source.
    ///
    /// Fails — rather than deferring to the first deposit — when the operator key is not set, the
    /// state file cannot be opened, or an environment override does not parse.
    pub fn new(
        node: Arc<N>,
        node_key: hopr_api::ChainKeypair,
        mut cfg: CurvyDepositPoolConfig,
    ) -> Result<Self, StrategyError> {
        // Environment overrides are applied before validation, so an override that contradicts
        // the file is caught here rather than at the first deposit.
        if let Ok(raw) = std::env::var(SHIELDING_ENV) {
            cfg.shielding = raw.parse()?;
        }
        if let Ok(raw) = std::env::var(SUBMISSION_ENV) {
            cfg.submission = raw.parse()?;
        }
        if let Ok(raw) = std::env::var(RELAYER_URL_ENV) {
            cfg.relayer_url = Some(Url::parse(&raw).map_err(|error| {
                StrategyError::InvalidConfiguration(format!("{RELAYER_URL_ENV} must be a URL: {error}"))
            })?);
        }
        StrategyError::validate_config(&cfg)?;
        // After the overrides, so an env-selected mode is judged rather than the file's default.
        validate_mode_requirements(&cfg)?;

        // The operator key signs proofs only when this node submits them itself. A relayed node
        // needs no EVM key of its own: the relayer submits aggregations and withdrawals, the
        // deployment's batch-prover commits, and the shield is paid by the Safe.
        let operator_key = match cfg.submission {
            CurvySubmission::Operator => std::env::var(&cfg.operator_key_env).map_err(|_| {
                StrategyError::InvalidConfiguration(format!(
                    "environment variable {} must hold the Curvy operator's private key when submission is \
                     `operator`",
                    cfg.operator_key_env
                ))
            })?,
            CurvySubmission::Relayer => String::new(),
        };
        let initial_funding = match std::env::var(INITIAL_FUNDING_ENV) {
            Ok(raw) => HoprBalance::from_str(&raw).map_err(|error| {
                StrategyError::InvalidConfiguration(format!("{INITIAL_FUNDING_ENV} must be a wxHOPR amount: {error}"))
            })?,
            Err(_) => cfg.initial_funding,
        };
        let state_path = cfg
            .state_path
            .clone()
            .unwrap_or_else(|| PathBuf::from(format!("curvy-pix-{}.redb", node.identity().node_address)));
        let state = RedbCurvyDepositState::open(&state_path)
            .map_err(|error| StrategyError::other(anyhow::anyhow!("{}: {error}", state_path.display())))?;
        let blokli = Arc::new(BlokliClient::new(cfg.blokli_url.clone(), BlokliClientConfig::default()));
        let adapter = RsSdkCurvyAdapter::new(
            Arc::clone(&blokli),
            cfg.blokli_url.to_string(),
            RsSdkCurvyAdapterConfig::new(operator_key, cfg.token).with_modes(
                cfg.shielding,
                cfg.submission,
                cfg.relayer_url.clone(),
            ),
            safe_funder(node.chain_api().clone()),
            match cfg.shielding {
                // The node's own chain key, because the module's `nodeOnly` check accepts no
                // other signer; nothing new is minted or stored here.
                CurvyShielding::Direct => Some(safe_direct_shielder(
                    Arc::clone(&blokli),
                    node_key,
                    node.identity().module_address,
                    cfg.safe_multisend_address,
                )),
                CurvyShielding::Portal => None,
            },
            match cfg.submission {
                CurvySubmission::Relayer => {
                    let url = cfg
                        .relayer_url
                        .clone()
                        .expect("validated: `relayer_url` is required for relayed submission");
                    Some(Arc::new(relayer::RelayClient::new(url, RELAYER_REQUEST_TIMEOUT)?))
                }
                CurvySubmission::Operator => None,
            },
            &state,
        )
        .map_err(StrategyError::other)?;
        tracing::info!(
            state = %state_path.display(),
            blokli = %cfg.blokli_url,
            %initial_funding,
            token = cfg.token,
            shielding = ?cfg.shielding,
            submission = ?cfg.submission,
            relayer = cfg.relayer_url.as_ref().map(|url| url.to_string()),
            "Curvy PIX deposit pool ready"
        );
        let detector = RsCoreCurvyNoteDetector::for_token(cfg.token);
        Ok(Self::with_parts(
            node,
            cfg,
            initial_funding,
            BlokliIndex(blokli),
            adapter,
            detector,
            state,
        ))
    }
}

impl<N, I, A, S> CurvyDepositPool<N, I, A, S>
where
    N: HasChainApi + Send + Sync + 'static,
    I: CurvyIndexSource,
    A: CurvySdkAdapter,
    S: CurvyDepositState,
{
    /// Assembles a pool from its parts — the note index, the SDK bridge, the detector and the
    /// state — bypassing [`Self::new`]'s environment and endpoint wiring.
    ///
    /// This is how tests drive the whole pool without a chain: a scripted index, a fake adapter
    /// and a temporary state file, with the real detector, tracker and watcher in between.
    pub fn with_parts(
        node: Arc<N>,
        cfg: CurvyDepositPoolConfig,
        initial_funding: HoprBalance,
        index: I,
        adapter: A,
        detector: RsCoreCurvyNoteDetector,
        state: S,
    ) -> Self {
        Self {
            node,
            index: Arc::new(index),
            adapter: Arc::new(adapter),
            tracker: Arc::new(CurvyLifecycleTracker::new(Arc::new(detector), Arc::new(state))),
            cfg,
            initial_funding,
            reconciled: tokio::sync::OnceCell::new(),
            watcher: parking_lot::Mutex::new(None),
        }
    }

    /// The durable state, for inspection.
    pub fn state(&self) -> &S {
        &self.tracker.state
    }

    /// Runs the stale-state check once per process. See the module docs.
    async fn ensure_reconciled(&self) -> Result<(), CurvyDepositPoolError> {
        self.reconciled
            .get_or_try_init(|| async {
                if self.state_is_stale().await? {
                    tracing::warn!(
                        "the Curvy PIX state describes a chain other than the one behind the endpoint; discarding it \
                         and starting over"
                    );
                    self.tracker.state.wipe_chain_state()?;
                    self.adapter
                        .reset_chain_state()
                        .map_err(|error| CurvyDepositPoolError::Adapter(error.into()))?;
                }
                Ok(())
            })
            .await
            .map(|_| ())
    }

    async fn state_is_stale(&self) -> Result<bool, CurvyDepositPoolError> {
        let (head, _) = self
            .index
            .indexed_head()
            .await
            .map_err(CurvyDepositPoolError::Indexer)?;
        for kind in [CurvyEventKind::Pending, CurvyEventKind::Committed] {
            if let Some(cursor) = self.tracker.state.cursor(kind)? {
                let block = cursor
                    .block
                    .0
                    .parse::<u64>()
                    .map_err(|error| CurvyStateError::Corrupt(format!("invalid Curvy cursor block: {error}")))?;
                if block > head {
                    return Ok(true);
                }
            }
        }
        for note_id in self.tracker.state.owned_note_ids()? {
            if !self
                .index
                .note_known(note_id)
                .await
                .map_err(CurvyDepositPoolError::Indexer)?
            {
                return Ok(true);
            }
        }
        self.adapter
            .chain_state_is_consistent()
            .await
            .map(|consistent| !consistent)
            .map_err(|error| CurvyDepositPoolError::Adapter(error.into()))
    }

    /// A fresh scan identity: `(K, V)` from Curvy's stealth key generation, with the spend scalar
    /// `k` discarded immediately. The Exit keeps `v` and `K`; the Entry gets `K` and `V`.
    fn generate_scan_secret() -> Result<CurvyScanSecret, CurvyDepositPoolError> {
        let (k, v, big_k, big_v) =
            stealth::new_meta().map_err(|error| CurvyDepositPoolError::ScanIdentity(error.to_string()))?;
        // Never a spending key of anything: dropped as soon as it exists.
        drop(Zeroizing::new(k));
        let v = Zeroizing::new(v);
        let v_bytes = Zeroizing::new(
            const_hex::decode(v.as_str()).map_err(|error| CurvyDepositPoolError::ScanIdentity(error.to_string()))?,
        );
        if v_bytes.len() > 32 {
            return Err(CurvyDepositPoolError::ScanIdentity(
                "view scalar exceeds 32 bytes".to_owned(),
            ));
        }
        let mut v_be = Zeroizing::new([0u8; 32]);
        v_be[32 - v_bytes.len()..].copy_from_slice(&v_bytes);
        let view = Bn254Keypair::from_secret_be(v_be.as_ref())
            .map_err(|error| CurvyDepositPoolError::ScanIdentity(error.to_string()))?;
        let spend_meta_key = detect::public_key_from_dec(&big_k).map_err(CurvyDepositPoolError::ScanIdentity)?;
        let secret = CurvyScanSecret::new(view, spend_meta_key);
        // The two libraries must agree on `V`, or the Entry seals notes the Exit cannot find.
        let advertised = detect::view_key_dec(secret.view().public()).map_err(CurvyDepositPoolError::ScanIdentity)?;
        if advertised != big_v {
            return Err(CurvyDepositPoolError::ScanIdentity(
                "derived view key does not match Curvy's".to_owned(),
            ));
        }
        Ok(secret)
    }

    fn bjj_secret(key: &BjjKeypair) -> Result<ScalarSigningKey, CurvyDepositPoolError> {
        detect::bjj_secret(key).map_err(CurvyDepositPoolError::InvalidReconstructedSecret)
    }

    /// Drops notes whose nullifiers the chain has already seen — a sweep that was submitted but
    /// whose outcome was lost — and returns the rest.
    async fn reconcile_spent_notes(
        &self,
        id: &PixAddressId,
        notes: Vec<CommittedCurvyNote>,
    ) -> Result<Vec<CommittedCurvyNote>, CurvyDepositPoolError> {
        let mut spent_ids = Vec::new();
        let mut unspent = Vec::with_capacity(notes.len());
        for note in notes {
            let nullifier = U256::from_be_bytes(fr_to_be_32(&note.note.nullifier()));
            if self
                .index
                .nullifier_spent(format!("{nullifier:#066x}"))
                .await
                .map_err(CurvyDepositPoolError::Indexer)?
            {
                let note_id = U256::from_be_bytes(fr_to_be_32(&note.note.id()));
                spent_ids.push(format!("{note_id:#066x}"));
            } else {
                unspent.push(note);
            }
        }
        if !spent_ids.is_empty() {
            self.remove_spent_notes_retry(id, &spent_ids)?;
        }
        Ok(unspent)
    }

    fn remove_spent_notes_retry(&self, id: &PixAddressId, note_ids: &[String]) -> Result<(), CurvyDepositPoolError> {
        let mut last_error = None;
        for _ in 0..3 {
            match self.tracker.state.remove_spent_notes(id, note_ids) {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.expect("at least one cleanup attempt was made").into())
    }

    /// Waits — up to [`CurvyDepositPoolConfig::max_deposit_tracking_time`] — for any committed
    /// note to appear for `id`, using the same discovery path as
    /// [`notify_deposit`](DepositPool::notify_deposit). Resolves at once if one is already there.
    ///
    /// Only possible on the node that generated the allocation's deposit data, since that is
    /// where the scan secret lives; anywhere else there is nothing to wait with.
    async fn await_commitment(&self, id: &PixAddressId, address: BjjPublicKey) -> Result<(), CurvyDepositPoolError> {
        let Some(scan_secret) = self.tracker.state.scan_secret(id)? else {
            return Ok(());
        };
        let receiver = self
            .tracker
            .watch(*id, address, scan_secret, HoprBalance::from(U256::one()))?;
        self.ensure_watcher();
        match tokio::time::timeout(self.cfg.max_deposit_tracking_time, receiver).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(_)) => Err(CurvyDepositPoolError::WatcherStopped),
            Err(_) => {
                tracing::debug!(allocation = ?id, "gave up waiting for the allocation to be committed");
                Ok(())
            }
        }
    }

    /// Starts the discovery task if it is not running. Needs a Tokio runtime, which every caller
    /// has: it is reached from the strategy's event loop.
    fn ensure_watcher(&self) {
        let mut watcher = self.watcher.lock();
        if watcher.as_ref().is_some_and(|handle| !handle.is_finished()) {
            return;
        }
        // Only the index and the tracker are captured — never `self` — so that dropping the pool
        // is what ends the task (see `Drop`) rather than the task keeping the pool alive.
        let index = Arc::clone(&self.index);
        let tracker = Arc::clone(&self.tracker);
        *watcher = Some(tokio::spawn(lifecycle::run_watcher(index, tracker)));
    }

    async fn allocate(
        &self,
        deposits: Vec<(PixAddressId, BjjPublicKey, CurvyScanPublicKey, HoprBalance)>,
    ) -> Result<(), StrategyError> {
        self.ensure_reconciled().await?;
        let safe_address = self.node.identity().safe_address;
        self.adapter
            .ensure_funded(self.initial_funding, safe_address)
            .await
            .map_err(|error| StrategyError::other(CurvyDepositPoolError::Adapter(error.into())))?;
        self.adapter.allocate(deposits).await.map_err(|error| {
            let message = error.to_string();
            // Out of shielded funds is the expected end of a run, not a fault: the strategy's
            // budget usually gets there first, and either way the kill switch ends the Session.
            if message.contains("no committed note large enough") {
                tracing::warn!(%error, "the Curvy pool has no funding left for this deposit");
                StrategyError::CriteriaNotSatisfied
            } else {
                StrategyError::other(CurvyDepositPoolError::Adapter(error.into()))
            }
        })
    }
}

impl<N, I, A, S> Drop for CurvyDepositPool<N, I, A, S> {
    fn drop(&mut self) {
        if let Some(handle) = self.watcher.lock().take() {
            handle.abort();
        }
    }
}

#[async_trait::async_trait]
impl<N, I, A, S> DepositPool<BjjKeypair> for CurvyDepositPool<N, I, A, S>
where
    N: HasChainApi + Send + Sync + 'static,
    I: CurvyIndexSource,
    A: CurvySdkAdapter,
    S: CurvyDepositState,
{
    type Error = StrategyError;
    type PoolDepositData = CurvyDepositData;
    type Receipt = ();

    /// Mints the allocation's scan identity and persists its secret **before** returning the
    /// public half. Idempotent: asking twice for one allocation returns the same identity.
    async fn generate_deposit_data(&self, id: &PixAddressId) -> Result<Self::PoolDepositData, Self::Error> {
        self.ensure_reconciled().await?;
        let secret = match self
            .tracker
            .state
            .scan_secret(id)
            .map_err(CurvyDepositPoolError::from)?
        {
            Some(existing) => existing,
            None => {
                let secret = Self::generate_scan_secret()?;
                self.tracker
                    .state
                    .store_scan_secret(id, &secret)
                    .map_err(CurvyDepositPoolError::from)?;
                secret
            }
        };
        Ok(CurvyDepositData::new(*id, secret.public()))
    }

    async fn deposit_funds_to(
        &self,
        id: &PixAddressId,
        dst: &BjjPublicKey,
        amount: HoprBalance,
        additional_data: Self::PoolDepositData,
    ) -> Result<Self::Receipt, Self::Error> {
        if additional_data.id() != id {
            return Err(CurvyDepositPoolError::MismatchedDepositData {
                expected: *id,
                actual: *additional_data.id(),
            }
            .into());
        }
        self.allocate(vec![(*id, *dst, *additional_data.scan_key(), amount)])
            .await
    }

    /// One proof for the whole batch (up to the aggregator's output budget per proof).
    async fn deposit_funds_to_multiple(
        &self,
        deposits: &[(PixAddressId, BjjPublicKey, HoprBalance, Self::PoolDepositData)],
    ) -> Result<BatchOutcomes<Self::Receipt, Self::Error>, Self::Error> {
        let mut valid = Vec::with_capacity(deposits.len());
        let mut outcomes: Vec<Option<Result<(PixAddressId, ()), StrategyError>>> =
            deposits.iter().map(|_| None).collect();
        for (index, (id, dst, amount, data)) in deposits.iter().enumerate() {
            if data.id() != id {
                outcomes[index] = Some(Err(CurvyDepositPoolError::MismatchedDepositData {
                    expected: *id,
                    actual: *data.id(),
                }
                .into()));
            } else {
                valid.push((index, (*id, *dst, *data.scan_key(), *amount)));
            }
        }
        let batch = valid.iter().map(|(_, deposit)| *deposit).collect::<Vec<_>>();
        let result = if batch.is_empty() {
            Ok(())
        } else {
            self.allocate(batch).await
        };
        for (index, (id, ..)) in valid {
            outcomes[index] = Some(match &result {
                Ok(()) => Ok((id, ())),
                Err(StrategyError::CriteriaNotSatisfied) => Err(StrategyError::CriteriaNotSatisfied),
                Err(error) => Err(StrategyError::other(anyhow::anyhow!("{error}"))),
            });
        }
        Ok(outcomes
            .into_iter()
            .map(|outcome| outcome.expect("every batch slot is filled"))
            .collect())
    }

    /// Registers the allocation with the discovery task and resolves once its notes are committed
    /// and final, or fails after [`CurvyDepositPoolConfig::max_deposit_tracking_time`].
    fn notify_deposit(
        &self,
        id: PixAddressId,
        dst: BjjPublicKey,
        min_amount: HoprBalance,
    ) -> Result<DepositNotification<'static, BjjPublicKey, Self::Error>, Self::Error> {
        let scan_secret = self
            .tracker
            .state
            .scan_secret(&id)
            .map_err(CurvyDepositPoolError::from)?
            .ok_or(CurvyDepositPoolError::MissingScanSecret(id))?;
        let receiver = self
            .tracker
            .watch(id, dst, scan_secret, min_amount)
            .map_err(CurvyDepositPoolError::from)?;
        let timeout = self.cfg.max_deposit_tracking_time;
        self.ensure_watcher();
        Ok(Box::pin(async move {
            match tokio::time::timeout(timeout, receiver).await {
                Ok(Ok(amount)) => Ok((id, dst, amount)),
                Ok(Err(_)) => Err(CurvyDepositPoolError::WatcherStopped.into()),
                Err(_) => Err(CurvyDepositPoolError::DepositTimeout.into()),
            }
        }))
    }

    /// Withdraws the allocation's committed notes with the reconstructed key.
    ///
    /// An allocation with nothing committed yet fails with [`StrategyError::CriteriaNotSatisfied`]
    /// — never `Ok` — because the strategy deletes the persisted recovery key on success, and a
    /// note that commits later would then be unsweepable.
    async fn withdraw_deposit(
        &self,
        id: &PixAddressId,
        key: &BjjKeypair,
        dst: Address,
        amount: Option<HoprBalance>,
    ) -> Result<Self::Receipt, Self::Error> {
        self.ensure_reconciled().await?;
        let secret = Self::bjj_secret(key)?;
        let committed = self
            .tracker
            .state
            .committed_notes(id)
            .map_err(CurvyDepositPoolError::from)?;
        let mut notes = self.reconcile_spent_notes(id, committed).await?;
        if notes.is_empty() {
            // The key is routinely recovered before the allocation is committed: the Exit
            // collects shares while the Entry is still proving and the operator still committing.
            // The pool owns its retries, so wait for the commitment here — bounded by the same
            // deadline a deposit gets — rather than failing a sweep that would succeed a few
            // seconds later.
            self.await_commitment(id, *key.public()).await?;
            let committed = self
                .tracker
                .state
                .committed_notes(id)
                .map_err(CurvyDepositPoolError::from)?;
            notes = self.reconcile_spent_notes(id, committed).await?;
        }
        if notes.is_empty() {
            tracing::debug!(allocation = ?id, "no committed Curvy notes to sweep yet");
            return Err(StrategyError::CriteriaNotSatisfied);
        }
        let outcome = self
            .adapter
            .withdraw(&secret, notes, dst, amount)
            .await
            .map_err(|error| CurvyDepositPoolError::Adapter(error.into()))?;
        self.remove_spent_notes_retry(id, &outcome.spent_note_ids)?;
        // Best effort: the secret is useless once the allocation is swept, but a leftover one
        // costs nothing but bytes.
        if let Err(error) = self.tracker.state.remove_scan_secret(id) {
            tracing::debug!(allocation = ?id, %error, "could not remove the swept allocation's scan secret");
        }
        #[cfg(all(feature = "telemetry", not(test)))]
        crate::pix::strategy::METRIC_PIX_LAST_SWEEP.set(
            // Whole wxHOPR, as the gauge's name says; `amount()` is wei.
            u128::try_from(outcome.withdrawn.amount())
                .map(|wei| wei as f64 / 1e18)
                .unwrap_or(f64::MAX),
        );
        tracing::info!(allocation = ?id, withdrawn = %outcome.withdrawn, %dst, "swept a Curvy PIX allocation");
        Ok(())
    }

    /// Sequential rather than concurrent: every sweep is a proof and a transaction from one
    /// operator account, and concurrent submissions would race on its nonce.
    async fn withdraw_multiple_deposits(
        &self,
        keys: &[(PixAddressId, BjjKeypair)],
        dst: Address,
    ) -> Result<BatchOutcomes<Self::Receipt, Self::Error>, Self::Error> {
        let mut outcomes = Vec::with_capacity(keys.len());
        for (id, key) in keys {
            outcomes.push(
                self.withdraw_deposit(id, key, dst, None)
                    .await
                    .map(|receipt| (*id, receipt)),
            );
        }
        Ok(outcomes)
    }

    async fn pool_transfer(
        &self,
        _src_id: &PixAddressId,
        _key: &BjjKeypair,
        _dst_id: &PixAddressId,
        _dst: BjjPublicKey,
        _additional_dst_data: Self::PoolDepositData,
        _amount: Option<HoprBalance>,
    ) -> Result<Self::Receipt, Self::Error> {
        Err(CurvyDepositPoolError::UnsupportedPoolTransfer.into())
    }
}
