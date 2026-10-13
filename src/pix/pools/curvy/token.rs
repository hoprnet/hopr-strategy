//! The Curvy vault token id this pool's notes carry, and how it is found.
//!
//! A Curvy note names its token by the *id* the deployment's vault registered it under, not by
//! the token's address. Ids are handed out in registration order, so the same wxHOPR is 3 on
//! Blokli's local chain and 2 on Gnosis, and a pool given the wrong one prepares notes in a
//! token the Safe does not hold.
//!
//! The deployment already knows the answer. Blokli's chain info names the token the node's Safe
//! holds, and the vault can be asked which address each of its ids stands for, so the id is the
//! one whose address is the Safe's token. [`VaultToken`] does that lookup once and is shared by
//! the two halves of the pool that need the id: the SDK bridge, which stamps it on every note it
//! prepares, and the tracker, which builds its detector for it.
//!
//! An operator can still state the id ([`CurvyDepositPoolConfig::token`]). A stated id is used as
//! given and never looked up; a direct shield checks it against the deployment before the Safe
//! sends anything.
//!
//! [`CurvyDepositPoolConfig::token`]: super::CurvyDepositPoolConfig::token

use std::{fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use blokli_client::api::BlokliQueryClient;

use super::sdk::CurvyChainEndpoints;

/// How many of the vault's tokens one lookup reads, newest first, before it gives up.
///
/// The read that matters is normally the first: a HOPR deployment registers wxHOPR last, or
/// close to it. The bound is for a vault that is not shaped like that, where an unbounded scan
/// would be one query per registered token in front of the first deposit.
const MAX_SCANNED_TOKENS: u64 = 64;

/// How long "the vault does not have the Safe's token" is taken to still be true.
///
/// That answer comes from an endpoint that is working, so asking again at once returns it again.
/// The watcher retries a failed pass every few seconds for as long as an allocation is watched,
/// and without this each of those retries would repeat the whole lookup.
const UNREGISTERED_RECHECK: Duration = Duration::from_secs(60);

/// The vault's token table, as far as resolving one id needs it. Blokli in production, a
/// scripted table in tests.
#[async_trait]
pub(super) trait VaultTokenTable: Send + Sync + 'static {
    /// Address of the token the node's Safe holds.
    async fn safe_token(&self) -> Result<String, String>;

    /// How many tokens the vault has registered. Their ids run from 1 to this number.
    async fn token_count(&self) -> Result<u64, String>;

    /// Address of the token registered under `id`.
    async fn token_address(&self, id: u64) -> Result<String, String>;
}

struct BlokliVault<C>(Arc<C>);

#[async_trait]
impl<C> VaultTokenTable for BlokliVault<C>
where
    C: BlokliQueryClient + Send + Sync + 'static,
{
    async fn safe_token(&self) -> Result<String, String> {
        CurvyChainEndpoints::discover(self.0.as_ref())
            .await
            .map(|endpoints| endpoints.token_address)
            .map_err(|error| error.to_string())
    }

    async fn token_count(&self) -> Result<u64, String> {
        let count = self
            .0
            .query_curvy_vault_token_count()
            .await
            .map_err(|error| format!("vault token count: {error}"))?
            .count
            .0;
        count
            .parse()
            .map_err(|error| format!("vault token count `{count}`: {error}"))
    }

    async fn token_address(&self, id: u64) -> Result<String, String> {
        self.0
            .query_curvy_vault_token(id.to_string())
            .await
            .map(|token| token.token_address)
            .map_err(|error| format!("vault token {id}: {error}"))
    }
}

struct Inner {
    id: tokio::sync::OnceCell<u64>,
    /// `None` for a configured id, which is never looked up.
    table: Option<Arc<dyn VaultTokenTable>>,
    /// When the vault last turned out not to have the Safe's token, and the error that said so.
    unregistered: parking_lot::Mutex<Option<(tokio::time::Instant, String)>>,
}

/// The Curvy vault token id of the token the node's Safe holds: configured, or resolved through
/// Blokli. See the module documentation.
///
/// Cloning shares the resolution, so the id is looked up at most once per pool however many
/// parts of it hold a handle.
#[derive(Clone)]
pub struct VaultToken(Arc<Inner>);

impl VaultToken {
    /// An id stated by the operator. Used as given.
    pub fn configured(id: u64) -> Self {
        Self(Arc::new(Inner {
            id: tokio::sync::OnceCell::new_with(Some(id)),
            table: None,
            unregistered: Default::default(),
        }))
    }

    /// The id the deployment's vault registers the Safe's token under, asked of Blokli when it is
    /// first needed.
    ///
    /// Not at construction: that is a query, and the pool is built synchronously.
    pub fn from_blokli<C>(client: Arc<C>) -> Self
    where
        C: BlokliQueryClient + Send + Sync + 'static,
    {
        Self::from_table(Arc::new(BlokliVault(client)))
    }

    pub(super) fn from_table(table: Arc<dyn VaultTokenTable>) -> Self {
        Self(Arc::new(Inner {
            id: tokio::sync::OnceCell::new(),
            table: Some(table),
            unregistered: Default::default(),
        }))
    }

    /// Whether the operator stated the id, as opposed to the pool resolving it.
    pub fn is_configured(&self) -> bool {
        self.0.table.is_none()
    }

    /// The id, if it is known without asking: configured, or already resolved.
    pub fn get(&self) -> Option<u64> {
        self.0.id.get().copied()
    }

    /// The id, resolving it first if nothing has yet.
    ///
    /// A lookup that failed on the way to an answer is not remembered, so the next call asks
    /// again: an endpoint that is still starting up must not pin the pool to an error for the
    /// rest of the process. "The vault does not have this token" *is* an answer, and is kept for
    /// a minute before the vault is asked again.
    pub async fn resolve(&self) -> Result<u64, String> {
        self.lookup(None).await
    }

    /// [`Self::resolve`] for a caller that already knows which token the Safe holds, sparing the
    /// lookup the chain-info read that would tell it.
    pub async fn resolve_for(&self, safe_token: &str) -> Result<u64, String> {
        self.lookup(Some(safe_token)).await
    }

    async fn lookup(&self, safe_token: Option<&str>) -> Result<u64, String> {
        self.0
            .id
            .get_or_try_init(|| async {
                let Some(table) = &self.0.table else {
                    return Err("the Curvy vault token id is neither configured nor resolvable".to_owned());
                };
                let unregistered = self.0.unregistered.lock().clone();
                if let Some((since, error)) = unregistered
                    && since.elapsed() < UNREGISTERED_RECHECK
                {
                    return Err(error);
                }
                let safe_token = match safe_token {
                    Some(address) => address.to_owned(),
                    None => table.safe_token().await?,
                };
                let count = table.token_count().await?;
                let oldest_scanned = count.saturating_sub(MAX_SCANNED_TOKENS) + 1;
                for id in (oldest_scanned..=count).rev() {
                    if table.token_address(id).await?.eq_ignore_ascii_case(&safe_token) {
                        tracing::info!(token = id, address = %safe_token, "resolved the Curvy vault token id through Blokli");
                        return Ok(id);
                    }
                }
                let error = if oldest_scanned > 1 {
                    format!(
                        "{safe_token}, the token the Safe holds, is not among the {MAX_SCANNED_TOKENS} most recently \
                         registered of the Curvy vault's {count} tokens: state its id as `token`"
                    )
                } else {
                    format!(
                        "none of the Curvy vault's {count} tokens is {safe_token}, the token the Safe holds: this \
                         deployment cannot shield it"
                    )
                };
                *self.0.unregistered.lock() = Some((tokio::time::Instant::now(), error.clone()));
                Err(error)
            })
            .await
            .copied()
    }
}

impl From<u64> for VaultToken {
    fn from(id: u64) -> Self {
        Self::configured(id)
    }
}

/// The id, or `auto` while it is still to be resolved.
impl fmt::Display for VaultToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.get() {
            Some(id) => write!(f, "{id}"),
            None => f.write_str("auto"),
        }
    }
}

impl fmt::Debug for VaultToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("VaultToken").field(&self.get()).finish()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::{
        super::{is_retryable_lag, relayer::http_tests::Server, sdk::RsSdkCurvyAdapterError},
        *,
    };

    const WXHOPR: &str = "0xD4fdec44DB9D44B8f2b6d529620f9C0C7066A2c1";
    const NATIVE: &str = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const OTHER: &str = "0x1111111111111111111111111111111111111111";

    /// A vault whose ids are the positions in `tokens`, counted from 1.
    struct ScriptedVault {
        safe_token: String,
        tokens: parking_lot::Mutex<Vec<String>>,
        /// Lookups started, counted where each one begins: at the token count.
        lookups: AtomicUsize,
        /// Token addresses read.
        reads: AtomicUsize,
        /// Times the Safe's token had to be asked for rather than being given.
        safe_token_reads: AtomicUsize,
        unavailable: AtomicBool,
    }

    impl ScriptedVault {
        fn new(safe_token: &str, tokens: &[&str]) -> Arc<Self> {
            Arc::new(Self {
                safe_token: safe_token.to_owned(),
                tokens: parking_lot::Mutex::new(tokens.iter().map(|token| (*token).to_owned()).collect()),
                lookups: AtomicUsize::new(0),
                reads: AtomicUsize::new(0),
                safe_token_reads: AtomicUsize::new(0),
                unavailable: AtomicBool::new(false),
            })
        }
    }

    #[async_trait]
    impl VaultTokenTable for ScriptedVault {
        async fn safe_token(&self) -> Result<String, String> {
            self.safe_token_reads.fetch_add(1, Ordering::SeqCst);
            Ok(self.safe_token.clone())
        }

        async fn token_count(&self) -> Result<u64, String> {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            if self.unavailable.load(Ordering::SeqCst) {
                return Err("connection refused".to_owned());
            }
            Ok(self.tokens.lock().len() as u64)
        }

        async fn token_address(&self, id: u64) -> Result<String, String> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(self.tokens.lock()[id as usize - 1].clone())
        }
    }

    /// The two deployments that exist: wxHOPR is the first registered ERC-20 on Gnosis and the
    /// second on Blokli's local chain, behind the vault's pre-seeded native currency in both.
    #[tokio::test]
    async fn the_id_is_the_one_the_vault_registers_the_safes_token_under() {
        for (tokens, expected) in [(vec![NATIVE, WXHOPR], 2), (vec![NATIVE, OTHER, WXHOPR], 3)] {
            let vault = ScriptedVault::new(WXHOPR, &tokens);
            let token = VaultToken::from_table(vault.clone());
            assert!(!token.is_configured());
            assert_eq!(token.get(), None);
            assert_eq!(token.to_string(), "auto");
            assert_eq!(token.resolve().await, Ok(expected));
            assert_eq!(token.get(), Some(expected));
            assert_eq!(token.to_string(), expected.to_string());
            // Newest first, and wxHOPR is the newest in both.
            assert_eq!(vault.reads.load(Ordering::SeqCst), 1);
        }
    }

    /// Blokli and the vault do not agree on checksum casing, and neither is wrong.
    #[tokio::test]
    async fn addresses_are_compared_without_regard_to_case() {
        let vault = ScriptedVault::new(&WXHOPR.to_ascii_lowercase(), &[NATIVE, WXHOPR]);
        assert_eq!(VaultToken::from_table(vault).resolve().await, Ok(2));
    }

    /// The SDK bridge has read the chain info already by the time it needs the id.
    #[tokio::test]
    async fn a_caller_that_knows_the_safes_token_spares_the_lookup_that_read() {
        let vault = ScriptedVault::new(OTHER, &[NATIVE, WXHOPR]);
        let token = VaultToken::from_table(vault.clone());
        assert_eq!(token.resolve_for(WXHOPR).await, Ok(2));
        assert_eq!(vault.safe_token_reads.load(Ordering::SeqCst), 0);
    }

    /// Every part of the pool holds a clone, and they must share one lookup rather than each
    /// asking Blokli for the same answer.
    #[tokio::test]
    async fn clones_resolve_once_between_them() {
        let vault = ScriptedVault::new(WXHOPR, &[NATIVE, WXHOPR]);
        let token = VaultToken::from_table(vault.clone());
        let clone = token.clone();
        assert_eq!(token.resolve().await, Ok(2));
        assert_eq!(clone.get(), Some(2));
        assert_eq!(clone.resolve().await, Ok(2));
        assert_eq!(vault.lookups.load(Ordering::SeqCst), 1);
    }

    /// A node can be up before its Blokli is. The first failure must not be the answer forever.
    #[tokio::test]
    async fn a_lookup_that_could_not_be_made_is_retried_by_the_next_call() {
        let vault = ScriptedVault::new(WXHOPR, &[NATIVE, WXHOPR]);
        vault.unavailable.store(true, Ordering::SeqCst);
        let token = VaultToken::from_table(vault.clone());
        assert_eq!(token.resolve().await, Err("connection refused".to_owned()));
        assert_eq!(token.get(), None);

        vault.unavailable.store(false, Ordering::SeqCst);
        assert_eq!(token.resolve().await, Ok(2));
        assert_eq!(vault.lookups.load(Ordering::SeqCst), 2);
    }

    /// The watcher retries a failed pass every few seconds. A vault that does not have the token
    /// says so each time, so the answer is kept for a while instead of being fetched again — and
    /// only for a while, because a vault can register a token later.
    #[tokio::test(start_paused = true)]
    async fn a_vault_without_the_safes_token_is_not_asked_again_at_once() {
        let vault = ScriptedVault::new(WXHOPR, &[NATIVE, OTHER]);
        let token = VaultToken::from_table(vault.clone());
        let error = token.resolve().await.expect_err("no id stands for the Safe's token");
        assert!(error.contains(WXHOPR), "{error}");
        assert!(error.contains("2 tokens"), "{error}");

        tokio::time::advance(UNREGISTERED_RECHECK / 2).await;
        assert_eq!(token.resolve().await, Err(error));
        assert_eq!(vault.lookups.load(Ordering::SeqCst), 1, "the answer was reused");

        vault.tokens.lock().push(WXHOPR.to_owned());
        tokio::time::advance(UNREGISTERED_RECHECK).await;
        assert_eq!(token.resolve().await, Ok(3));
        assert_eq!(vault.lookups.load(Ordering::SeqCst), 2);
    }

    /// A lookup reads a bounded number of tokens, and says how to get past the bound.
    #[tokio::test]
    async fn a_lookup_reads_only_the_most_recently_registered_tokens() {
        let mut tokens = vec![OTHER; MAX_SCANNED_TOKENS as usize + 6];
        tokens[2] = WXHOPR;
        let vault = ScriptedVault::new(WXHOPR, &tokens);
        let error = VaultToken::from_table(vault.clone())
            .resolve()
            .await
            .expect_err("the Safe's token is older than the lookup reaches");
        assert!(error.contains("state its id as `token`"), "{error}");
        assert_eq!(vault.reads.load(Ordering::SeqCst), MAX_SCANNED_TOKENS as usize);
    }

    #[tokio::test]
    async fn a_configured_id_is_used_as_given() {
        let token = VaultToken::from(7);
        assert!(token.is_configured());
        assert_eq!(token.get(), Some(7));
        assert_eq!(token.resolve().await, Ok(7));
        assert_eq!(token.to_string(), "7");
    }

    /// The same lookup over the real client, against Blokli's own answers.
    #[tokio::test]
    async fn the_lookup_reads_the_vault_through_blokli() {
        let queries = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let server = Server::new({
            let queries = queries.clone();
            move |path, body| {
                assert_eq!(path, "/graphql");
                let query = body["query"].as_str().expect("a GraphQL query");
                if query.contains("curvyVaultTokenCount") {
                    queries.lock().push("count".to_owned());
                    return Some((
                        200,
                        serde_json::json!({"data":{"curvyVaultTokenCount":{
                            "__typename":"CurvyVaultTokenCount","count":"3"
                        }}}),
                    ));
                }
                assert!(query.contains("curvyVaultToken"), "{query}");
                let id = body["variables"]
                    .as_object()
                    .and_then(|variables| variables.values().next())
                    .and_then(|id| id.as_str())
                    .expect("the token id variable")
                    .to_owned();
                let address = if id == "2" { WXHOPR } else { OTHER };
                queries.lock().push(id);
                let zero = format!("0x{}", "0".repeat(64));
                Some((
                    200,
                    serde_json::json!({"data":{"curvyVaultToken":{
                        "__typename":"CurvyVaultToken",
                        "tokenAddress": address,
                        "gasFees":{"tokenId":zero,"portalDeployment":zero,"pendingNoteCommitment":zero,"withdrawal":zero}
                    }}}),
                ))
            }
        })
        .await;
        let client = Arc::new(blokli_client::BlokliClient::new(server.url.clone(), Default::default()));

        assert_eq!(VaultToken::from_blokli(client).resolve_for(WXHOPR).await, Ok(2));
        assert_eq!(*queries.lock(), ["count", "3", "2"]);
    }

    /// The first deposit is where the lookup usually runs, inside the pool's allocation loop,
    /// which waits out a chain read that failed in transit and fails the deposit on anything
    /// else. Blokli passing on a rate limit from its RPC has to land on the waiting side.
    #[tokio::test]
    async fn a_lookup_that_hit_a_failing_chain_read_is_one_the_pool_waits_out() {
        let server = Server::new(|_, _| {
            Some((
                200,
                serde_json::json!({"data":{"curvyVaultTokenCount":{
                    "__typename":"QueryFailedError", "code":"RPC_ERROR",
                    "message":"RPC error during query Curvy Vault token count: Max retries exceeded HTTP error 429 \
                               with body: 429 Too Many Requests"
                }}}),
            ))
        })
        .await;
        let client = Arc::new(blokli_client::BlokliClient::new(server.url.clone(), Default::default()));

        let token = VaultToken::from_blokli(client);
        let error = token
            .resolve_for(WXHOPR)
            .await
            .expect_err("Blokli's RPC was rate limited");
        let reported = RsSdkCurvyAdapterError::Discovery(error).to_string();
        assert!(is_retryable_lag(&reported), "{reported}");
        assert!(
            token.0.unregistered.lock().is_none(),
            "not an answer about the vault, so not one to keep"
        );
    }
}
