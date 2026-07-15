use std::{
    future::Future,
    sync::{
        Arc,
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
use tracing::info;

use crate::{
    TestTimeouts,
    anvil::AnvilAccount,
    config::TestConfig,
    docker::{DockerEnvironment, load_anvil_accounts},
    transaction::TransactionBuilder,
};

mod channels;
mod onboarding;

/// wxHOPR distributed to each test account at bootstrap (they start with native
/// funds but no wxHOPR).
const PER_ACCOUNT_TOKEN_AMOUNT: u128 = 1_000_000_000_000_000_000_000; // 1000 wxHOPR

pub struct IntegrationFixture {
    config: Arc<TestConfig>,
    accounts: Vec<AnvilAccount>,
    client: BlokliClient,
    chain_id: u64,
    _docker: Option<DockerEnvironment>,
    contract_addrs: ContractAddresses,
    next_account: AtomicUsize,
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
        &self.config
    }

    /// Reserves a disjoint set of accounts for one integration scenario.
    /// Account zero is retained as the token-distribution deployer.
    pub fn claim_accounts<const N: usize>(&self) -> [&AnvilAccount; N] {
        let start = self.next_account.fetch_add(N, Ordering::Relaxed);
        let end = start + N;
        assert!(
            end <= self.config.funded_accounts + 1,
            "not enough funded integration accounts; increase BLOKLI_TEST_FUNDED_ACCOUNTS"
        );
        std::array::from_fn(|offset| &self.accounts[start + offset])
    }

    pub fn client(&self) -> &BlokliClient {
        &self.client
    }

    pub fn timeouts(&self) -> TestTimeouts {
        self.config.timeouts
    }

    pub(crate) fn contract_addresses(&self) -> &ContractAddresses {
        &self.contract_addrs
    }

    pub(crate) fn chain_id(&self) -> u64 {
        self.chain_id
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
        client
            .submit_and_confirm_transaction(&signed, confirmations)
            .await
            .context("failed to distribute wxHOPR to test account")?;
    }
    Ok(())
}

async fn build_integration_fixture() -> Result<IntegrationFixture> {
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
    let blokli_config = BlokliClientConfig {
        auto_compatibility_check: false,
        ..Default::default()
    };
    let client = BlokliClient::new(bloklid_url, blokli_config);
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

    Ok(IntegrationFixture {
        config,
        accounts,
        client,
        chain_id,
        _docker: docker,
        contract_addrs,
        next_account: AtomicUsize::new(1),
    })
}

#[fixture]
pub async fn integration_fixture() -> IntegrationFixture {
    build_integration_fixture()
        .await
        .expect("failed to set up integration fixture")
}
