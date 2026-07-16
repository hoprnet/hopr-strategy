use std::{
    future::Future,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use blokli_client::{
    BlokliClient, BlokliClientConfig,
    api::{BlokliQueryClient, BlokliTransactionClient},
};
use hopr_bindings::{
    exports::alloy::{
        primitives::{Address as AlloyAddress, U256},
        sol_types::SolCall,
    },
    hopr_token::HoprToken::transferCall,
};
use hopr_types::chain::ContractAddresses;
use rstest::fixture;
use tracing::{info, warn};
use url::Url;

use crate::{
    TestTimeouts,
    anvil::AnvilAccount,
    config::TestConfig,
    docker::{DockerEnvironment, load_anvil_accounts},
    transaction::TransactionBuilder,
};

mod channels;
mod onboarding;
mod scenario;

pub use scenario::{
    ChannelParty, ChannelScenario, ScenarioOpts, assert_channel_never, await_channel, await_channel_where,
};

/// wxHOPR distributed to each test account at bootstrap (they start with native
/// funds but no wxHOPR).
const PER_ACCOUNT_TOKEN_AMOUNT: u128 = 1_000_000_000_000_000_000_000; // 1000 wxHOPR

/// Per-binary integration stack: the `bloklid-anvil` container plus the chain state derived from it.
struct SharedStack {
    config: Arc<TestConfig>,
    accounts: Vec<AnvilAccount>,
    bloklid_url: Url,
    chain_id: u64,
    contract_addrs: ContractAddresses,
    next_account: AtomicUsize,
    docker: Option<DockerEnvironment>,
}

pub struct IntegrationFixture {
    stack: &'static SharedStack,
    client: BlokliClient,
}

const READY_POLL_INTERVAL: Duration = Duration::from_millis(250);
/// 20-byte chain address of an anvil account (blokli's `ChainAddress`).
fn chain_addr(account: &AnvilAccount) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(account.address.as_ref());
    out
}

// Accessor methods
impl IntegrationFixture {
    pub(crate) fn config(&self) -> &TestConfig {
        &self.stack.config
    }

    /// Reserves a disjoint set of accounts for one integration scenario.
    /// Account zero is retained as the token-distribution deployer.
    pub fn claim_accounts<const N: usize>(&self) -> [&AnvilAccount; N] {
        let start = self.stack.next_account.fetch_add(N, Ordering::Relaxed);
        let end = start + N;
        assert!(
            end <= self.stack.config.funded_accounts + 1,
            "not enough funded integration accounts; increase BLOKLI_TEST_FUNDED_ACCOUNTS"
        );
        std::array::from_fn(|offset| &self.stack.accounts[start + offset])
    }

    pub fn client(&self) -> &BlokliClient {
        &self.client
    }

    pub fn timeouts(&self) -> TestTimeouts {
        self.stack.config.timeouts
    }

    pub(crate) fn contract_addresses(&self) -> &ContractAddresses {
        &self.stack.contract_addrs
    }

    pub(crate) fn chain_id(&self) -> u64 {
        self.stack.chain_id
    }

    /// Current transaction count (nonce) for `account`, via bloklid.
    pub(crate) async fn nonce(&self, account: &AnvilAccount) -> Result<u64> {
        Ok(self.client().query_transaction_count(&chain_addr(account)).await?)
    }
}

// Transaction submission helpers
impl IntegrationFixture {
    /// Submits the signed transaction and waits for the specified number of confirmations.
    pub(crate) async fn submit_and_confirm_tx(&self, signed_bytes: &[u8], confirmations: usize) -> Result<[u8; 32]> {
        self.client()
            .submit_and_confirm_transaction(signed_bytes, confirmations)
            .await
            .context("blokli client failed to submit transaction")
    }
}

async fn wait_for_blokli_ready(client: &BlokliClient, timeout: Duration) -> Result<()> {
    // Poll `query_chain_info` until bloklid responds — that means the API is up and
    // serving indexed state (bloklid-anvil deploys contracts on startup).
    let deadline = Instant::now() + timeout;

    loop {
        match client.query_chain_info().await {
            Ok(_) => {
                info!(base_url = %client.base_url(), "integration stack is ready");
                return Ok(());
            }
            Err(error) => {
                if Instant::now() >= deadline {
                    return Err(anyhow::anyhow!(
                        "timed out waiting for blokli readiness after {}s (last observation: {error})",
                        timeout.as_secs(),
                    ));
                }
            }
        }

        tokio::time::sleep(READY_POLL_INTERVAL).await;
    }
}

/// Polls a check function until it returns `Some(T)`, with timeout.
pub async fn poll_until<F, Fut, T>(description: &str, timeout: Duration, interval: Duration, mut check: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Option<T>>>,
{
    let deadline = Instant::now() + timeout;
    let mut last_error: Option<anyhow::Error> = None;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(remaining, check()).await {
            Err(_) => break,
            Ok(Ok(Some(result))) => return Ok(result),
            Ok(Ok(None)) => last_error = None,
            Ok(Err(error)) => last_error = Some(error),
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        tokio::time::sleep(interval.min(remaining)).await;
    }

    match last_error {
        Some(error) => Err(error.context(format!("{description} did not complete within {timeout:?}"))),
        None => anyhow::bail!("{description} did not complete within {timeout:?}"),
    }
}

/// Watches `check` for the whole `window`, failing if it ever returns `Some`
pub async fn poll_stable<F, Fut, T>(description: &str, window: Duration, interval: Duration, mut check: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Option<T>>>,
{
    let deadline = Instant::now() + window;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(());
        }

        match tokio::time::timeout(remaining, check()).await {
            Err(_) => return Ok(()),
            Ok(Err(error)) => return Err(error.context(format!("{description}: check failed"))),
            Ok(Ok(Some(_))) => anyhow::bail!("{description}: forbidden state observed within {window:?}"),
            Ok(Ok(None)) => {}
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(());
        }
        tokio::time::sleep(interval.min(remaining)).await;
    }
}

/// Distributes wxHOPR from the deployer (anvil account 0, pre-minted 10M by the
/// image) to every other test account, via raw ERC-20 `transfer` transactions
/// submitted through the blokli client — no direct anvil RPC.
async fn distribute_tokens(
    client: &BlokliClient,
    accounts: &[AnvilAccount],
    token: AlloyAddress,
    chain_id: u64,
    confirmations: usize,
) -> Result<()> {
    let deployer = &accounts[0];
    let tx_builder = TransactionBuilder::new(&deployer.keypair)?;
    let base_nonce = client.query_transaction_count(&chain_addr(deployer)).await?;
    let amount = U256::from(PER_ACCOUNT_TOKEN_AMOUNT);

    // Pre-sign one transfer per recipient with sequential nonces.
    let mut signed_txs = Vec::with_capacity(accounts.len().saturating_sub(1));
    for (offset, recipient) in accounts.iter().enumerate().skip(1) {
        let calldata = transferCall {
            recipient: recipient.to_alloy_address(),
            amount,
        }
        .abi_encode();
        let signed = tx_builder
            .build_call_tx(
                chain_id,
                base_nonce + (offset as u64 - 1),
                token,
                U256::ZERO,
                calldata.into(),
            )
            .await?;
        signed_txs.push(signed);
    }

    futures::future::try_join_all(
        signed_txs
            .iter()
            .map(|signed| client.submit_and_confirm_transaction(signed, confirmations)),
    )
    .await
    .context("failed to distribute wxHOPR to test accounts")?;

    Ok(())
}

/// Builds a `BlokliClient` for `url`.
fn make_client(url: Url) -> BlokliClient {
    let blokli_config = BlokliClientConfig {
        auto_compatibility_check: false,
        ..Default::default()
    };
    BlokliClient::new(url, blokli_config)
}

async fn build_shared_stack() -> Result<SharedStack> {
    let config: Arc<TestConfig> = Arc::new(TestConfig::load()?);
    let mut docker = config.manages_docker().then(|| DockerEnvironment::new(config.clone()));

    if let Some(docker) = docker.as_mut() {
        docker.ensure_image_available()?;
        docker.run()?;
    }

    let bloklid_url = match docker.as_ref() {
        Some(docker) => docker.bloklid_url()?.clone(),
        None => config
            .external_blokli_url()
            .expect("external URL validated by TestConfig")
            .clone(),
    };
    let client = make_client(bloklid_url.clone());
    info!(
        seconds = config.timeouts.startup.as_secs(),
        base_url = %client.base_url(),
        "waiting for integration stack readiness"
    );
    wait_for_blokli_ready(&client, config.timeouts.startup).await?;
    let accounts = match docker.as_ref() {
        Some(docker) => docker.fetch_anvil_accounts()?,
        None => load_anvil_accounts(
            config
                .external_anvil_logs()
                .expect("external account logs validated by TestConfig"),
        )?,
    };

    // Contracts are already deployed by the image entrypoint; read chain id + their
    // addresses from bloklid rather than deploying our own set.
    let chain_info = client.query_chain_info().await.context("failed to query chain info")?;
    let chain_id = u64::try_from(chain_info.chain_id).context("negative chain id from chain info")?;
    let contract_addrs: ContractAddresses = serde_json::from_str(&chain_info.contract_addresses.0)
        .context("failed to parse contract addresses from chain info")?;

    info!(?contract_addrs, chain_id, "resolved deployed contract addresses");

    let token = AlloyAddress::from_slice(contract_addrs.token.as_ref());
    let account_count = config.funded_accounts + 1;
    let funded_accounts = accounts.get(..account_count).with_context(|| {
        format!(
            "requested {} funded test accounts, but Anvil exposed only {}",
            config.funded_accounts,
            accounts.len().saturating_sub(1)
        )
    })?;
    distribute_tokens(&client, funded_accounts, token, chain_id, config.tx_confirmations).await?;

    info!("distributed wxHOPR to test accounts");

    Ok(SharedStack {
        config,
        accounts,
        bloklid_url,
        chain_id,
        contract_addrs,
        next_account: AtomicUsize::new(1),
        docker,
    })
}

/// The per-binary integration stack, initialised on first access.
static STACK: OnceLock<SharedStack> = OnceLock::new();

/// Stops the shared container when the test binary exits. Rust never drops
/// `static`s, so the `DockerEnvironment::drop` cleanup (which only fires on a
/// setup-failure, when the value is still a local) does not run for the shared
/// stack — collect its logs explicitly here before removing the container.
#[ctor::dtor]
fn teardown_shared_stack() {
    if let Some(docker) = STACK.get().and_then(|stack| stack.docker.as_ref()) {
        if let Err(error) = docker.collect_logs(chrono::Utc::now()) {
            warn!(?error, "failed to collect container logs at teardown");
        }
        docker.force_remove();
    }
}

/// Returns the shared stack, building it on first call. Setup runs on a
/// dedicated thread with its own runtime: this fixture is awaited from inside a
/// `#[tokio::test]` runtime, and `Runtime::block_on` panics if nested, so we
/// cannot drive the async setup on the caller's runtime.
fn shared_stack() -> &'static SharedStack {
    STACK.get_or_init(|| {
        std::thread::spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build integration setup runtime");
            runtime
                .block_on(build_shared_stack())
                .expect("failed to set up integration fixture")
        })
        .join()
        .expect("integration setup thread panicked")
    })
}

#[fixture]
pub async fn integration_fixture() -> IntegrationFixture {
    let stack = shared_stack();
    IntegrationFixture {
        stack,
        client: make_client(stack.bloklid_url.clone()),
    }
}
