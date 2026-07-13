use std::{
    future::Future,
    str::FromStr,
    sync::{Arc, Mutex, Once},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use blokli_client::{
    BlokliClient, BlokliClientConfig,
    api::{AccountSelector, BlokliQueryClient, BlokliTransactionClient, SafeSelector, types::Safe},
};
use hopr_bindings::{
    exports::alloy::{
        primitives::{Address as AlloyAddress, U256},
        sol_types::SolCall,
    },
    hopr_token::HoprToken::transferCall,
};
use hopr_types::{
    chain::{
        ContractAddresses,
        payload::{BasicPayloadGenerator, PayloadGenerator, SafePayloadGenerator},
        prelude::SignableTransaction,
    },
    crypto::{
        keypairs::Keypair,
        types::{HalfKey, Hash, Response},
    },
    internal::{Multiaddr, announcement::AnnouncementData, tickets::TicketBuilder},
    primitive::{
        prelude::{Address as HoprAddress, HoprBalance},
        traits::IntoEndian,
    },
};
use libc::atexit;
use rand::seq::IndexedRandom;
use rstest::fixture;
use tokio::sync::OnceCell;
use tracing::{debug, info};

use crate::fixture::{
    anvil::AnvilAccount, config::TestConfig, constants::STACK_STARTUP_WAIT, docker::DockerEnvironment,
    transaction::TransactionBuilder,
};

/// wxHOPR distributed to each test account at bootstrap (they start with native
/// funds but no wxHOPR).
const PER_ACCOUNT_TOKEN_AMOUNT: u128 = 1_000_000_000_000_000_000_000; // 1000 wxHOPR

#[derive(Clone)]
pub struct IntegrationFixture {
    inner: Arc<IntegrationFixtureInner>,
}

struct IntegrationFixtureInner {
    config: Arc<TestConfig>,
    accounts: Vec<AnvilAccount>,
    client: BlokliClient,
    chain_id: u64,
    docker: Mutex<Option<DockerEnvironment>>,
    contract_addrs: ContractAddresses,
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
    pub fn config(&self) -> &TestConfig {
        &self.inner.config
    }

    pub fn accounts(&self) -> &[AnvilAccount] {
        &self.inner.accounts
    }

    pub fn sample_accounts<const N: usize>(&self) -> [&AnvilAccount; N] {
        assert!(self.inner.accounts.len() >= N, "not enough accounts available");

        let selected = self.inner.accounts.sample(&mut rand::rng(), N);
        let mut iter = selected.into_iter();
        let result: [&AnvilAccount; N] = std::array::from_fn(|_| iter.next().unwrap());
        result
    }

    pub fn client(&self) -> &BlokliClient {
        &self.inner.client
    }

    pub fn contract_addresses(&self) -> &ContractAddresses {
        &self.inner.contract_addrs
    }

    pub fn chain_id(&self) -> u64 {
        self.inner.chain_id
    }

    /// Current transaction count (nonce) for `account`, via bloklid.
    pub async fn nonce(&self, account: &AnvilAccount) -> Result<u64> {
        Ok(self.client().query_transaction_count(&chain_addr(account)).await?)
    }
}

// Transaction submission helpers
impl IntegrationFixture {
    /// Submits the signed transaction blindly.
    pub async fn submit_tx(&self, signed_bytes: &[u8]) -> Result<[u8; 32]> {
        self.client()
            .submit_transaction(signed_bytes)
            .await
            .context("blokli client failed to submit transaction")
    }

    /// Submits the signed transaction and returns the tracking id.
    pub async fn submit_and_track_tx(&self, signed_bytes: &[u8]) -> Result<String> {
        self.client()
            .submit_and_track_transaction(signed_bytes)
            .await
            .context("blokli client failed to submit transaction")
    }

    /// Submits the signed transaction and waits for the specified number of confirmations.
    pub async fn submit_and_confirm_tx(&self, signed_bytes: &[u8], confirmations: usize) -> Result<[u8; 32]> {
        self.client()
            .submit_and_confirm_transaction(signed_bytes, confirmations)
            .await
            .context("blokli client failed to submit transaction")
    }
}

// Safe related helpers
impl IntegrationFixture {
    /// Deploys a safe for the specified owner.
    async fn deploy_safe(&self, owner: &AnvilAccount, amount: HoprBalance) -> Result<[u8; 32]> {
        let nonce = self.nonce(owner).await?;

        let contract_addresses = self.contract_addresses();
        let payload = hopli_lib::payloads::edge_node_deploy_safe_module_and_maybe_include_node(
            contract_addresses.node_stake_factory,
            contract_addresses.token,
            contract_addresses.channels,
            U256::from(nonce),
            U256::from_be_bytes(amount.to_be_bytes()),
            vec![owner.to_alloy_address()],
            true,
        )?;

        let payload_bytes = payload
            .sign_and_encode_to_eip2718(nonce, self.chain_id(), None, &owner.keypair)
            .await?;

        self.submit_and_confirm_tx(&payload_bytes, self.config().tx_confirmations)
            .await
    }

    /// Deploys and returns a safe for the specified owner if not already deployed, otherwise retrieves the existing
    /// safe.
    pub async fn deploy_or_get_safe(&self, owner: &AnvilAccount, amount: HoprBalance) -> Result<Safe> {
        let maybe_safe = self
            .client()
            .query_safe(SafeSelector::ChainKey(owner.to_alloy_address().into()))
            .await?
            .into_iter()
            .next();

        match maybe_safe {
            Some(s) => Ok(s),
            None => {
                self.deploy_safe(owner, amount).await?;

                let selector = SafeSelector::ChainKey(owner.to_alloy_address().into());
                let client = self.client().clone();
                let safe = poll_until(
                    "safe indexing",
                    Duration::from_secs(30),
                    Duration::from_millis(500),
                    || {
                        let client = client.clone();
                        let selector = selector.clone();
                        async move { Ok(client.query_safe(selector).await?.into_iter().next()) }
                    },
                )
                .await?;

                self.register_safe(owner, &safe.address).await?;

                Ok(safe)
            }
        }
    }

    pub async fn register_safe(&self, owner: &AnvilAccount, safe_address: &str) -> Result<[u8; 32]> {
        let nonce = self.nonce(owner).await?;

        let payload_generator = BasicPayloadGenerator::new(owner.address, *self.contract_addresses());
        let payload = payload_generator.register_safe_by_node(HoprAddress::from_str(safe_address)?)?;

        let payload_bytes = payload
            .sign_and_encode_to_eip2718(nonce, self.chain_id(), None, &owner.keypair)
            .await?;

        self.submit_and_confirm_tx(&payload_bytes, self.config().tx_confirmations)
            .await
    }
}

// Account related helpers
impl IntegrationFixture {
    /// Announces the account using the specified safe module.
    pub async fn announce_account(&self, account: &AnvilAccount, module: &str) -> Result<[u8; 32]> {
        let nonce = self.nonce(account).await?;

        let payload_generator = SafePayloadGenerator::new(
            &account.keypair,
            *self.contract_addresses(),
            HoprAddress::from_str(module)?,
        );
        let multiaddress: Multiaddr = "/ip4/127.0.0.1/udp/3001".parse().expect("multiaddress parsing failed");
        let binding_fee = "0.01 wxHOPR".parse().expect("failed parsing the binding fee");

        let payload = payload_generator.announce(
            AnnouncementData::new(account.keybinding(), Some(multiaddress))?,
            binding_fee,
        )?;

        let payload_bytes = payload
            .sign_and_encode_to_eip2718(nonce, self.chain_id(), None, &account.keypair)
            .await?;

        self.submit_and_confirm_tx(&payload_bytes, self.config().tx_confirmations)
            .await
    }

    /// Announces the account if not announced yet. If already announced, does nothing.
    pub async fn announce_or_get_account(&self, account: &AnvilAccount, module: &str) -> Result<()> {
        let maybe_account = self
            .client()
            .query_accounts(AccountSelector::Address(account.to_alloy_address().into()))
            .await?;

        match maybe_account.first() {
            Some(_) => Ok(()),
            None => {
                debug!("account not found, proceeding to announce");
                self.announce_account(account, module).await?;

                let selector = AccountSelector::Address(account.to_alloy_address().into());
                let client = self.client().clone();
                poll_until(
                    "account indexing after announcement",
                    Duration::from_secs(30),
                    Duration::from_millis(500),
                    || {
                        let client = client.clone();
                        let selector = selector.clone();
                        async move {
                            let accounts = client.query_accounts(selector).await?;
                            if accounts.is_empty() { Ok(None) } else { Ok(Some(())) }
                        }
                    },
                )
                .await?;
                Ok(())
            }
        }
    }
}

// Ticket related helpers
impl IntegrationFixture {
    /// Generates a redeemable ticket and submits the redemption transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn redeem_ticket(
        &self,
        issuer: &AnvilAccount,
        redeemer: &AnvilAccount,
        amount: HoprBalance,
        module: &str,
        ticket_index: u64,
        channel_epoch: u32,
    ) -> Result<[u8; 32]> {
        let nonce = self.nonce(redeemer).await?;

        let domain_separator = self
            .client()
            .query_chain_info()
            .await?
            .channel_dst
            .context("missing channel domain separator in chain info")?;
        let domain_separator =
            Hash::from_str(&domain_separator).context("failed to parse channel domain separator from chain info")?;

        let issuer_half_key =
            HalfKey::try_from(issuer.keypair.secret().as_ref()).context("failed to derive issuer half key")?;
        let redeemer_half_key =
            HalfKey::try_from(redeemer.keypair.secret().as_ref()).context("failed to derive redeemer half key")?;
        let response = Response::from_half_keys(&issuer_half_key, &redeemer_half_key)?;

        let ticket = TicketBuilder::default()
            .counterparty(redeemer.address)
            .balance(amount)
            .index(ticket_index)
            .channel_epoch(channel_epoch)
            .challenge(response.to_challenge()?)
            .build_signed(&issuer.keypair, &domain_separator)?
            .into_acknowledged(response)
            .into_redeemable(&redeemer.keypair, &domain_separator)?;

        let payload_generator = SafePayloadGenerator::new(
            &redeemer.keypair,
            *self.contract_addresses(),
            HoprAddress::from_str(module)?,
        );
        let payload = payload_generator.redeem_ticket(ticket)?;

        let payload_bytes = payload
            .sign_and_encode_to_eip2718(nonce, self.chain_id(), None, &redeemer.keypair)
            .await?;

        self.submit_and_confirm_tx(&payload_bytes, self.config().tx_confirmations)
            .await
    }
}

// Token related helpers
impl IntegrationFixture {
    /// Approves the safe module to spend `amount` of wxHOPR on behalf of `owner`.
    pub async fn approve(&self, owner: &AnvilAccount, amount: HoprBalance, module: &str) -> Result<[u8; 32]> {
        let nonce = self.nonce(owner).await?;
        let spender = HoprAddress::from_str(&self.contract_addresses().channels.to_string())
            .expect("Invalid spender address hex");

        let payload_generator = SafePayloadGenerator::new(
            &owner.keypair,
            *self.contract_addresses(),
            HoprAddress::from_str(module)?,
        );
        let payload = payload_generator.approve(spender, amount)?;

        let payload_bytes = payload
            .sign_and_encode_to_eip2718(nonce, self.chain_id(), None, &owner.keypair)
            .await?;

        self.submit_and_confirm_tx(&payload_bytes, self.config().tx_confirmations)
            .await
    }
}

impl IntegrationFixture {
    pub async fn deploy_safe_and_announce(&self, owner: &AnvilAccount, amount: HoprBalance) -> Result<Safe> {
        let safe = self.deploy_or_get_safe(owner, amount).await?;
        self.announce_or_get_account(owner, &safe.module_address).await?;
        Ok(safe)
    }
}

// Channel related helpers
impl IntegrationFixture {
    /// Opens a channel from `from` to `to` with the specified `amount`.
    pub async fn open_channel(
        &self,
        from: &AnvilAccount,
        to: &AnvilAccount,
        amount: HoprBalance,
        module: &str,
        nonce: Option<u64>,
    ) -> Result<[u8; 32]> {
        let nonce = self.nonce(from).await?.max(nonce.unwrap_or(0));

        let payload_generator = SafePayloadGenerator::new(
            &from.keypair,
            *self.contract_addresses(),
            HoprAddress::from_str(module)?,
        );
        let payload = payload_generator.fund_channel(to.address, amount)?;

        let payload_bytes = payload
            .sign_and_encode_to_eip2718(nonce, self.chain_id(), None, &from.keypair)
            .await?;

        self.submit_and_confirm_tx(&payload_bytes, self.config().tx_confirmations)
            .await
    }

    /// Starts closing an outgoing channel from `from` to `to`.
    pub async fn initiate_outgoing_channel_closure(
        &self,
        from: &AnvilAccount,
        to: &AnvilAccount,
        module: &str,
    ) -> Result<[u8; 32]> {
        let nonce = self.nonce(from).await?;

        let payload_generator = SafePayloadGenerator::new(
            &from.keypair,
            *self.contract_addresses(),
            HoprAddress::from_str(module)?,
        );
        let payload = payload_generator.initiate_outgoing_channel_closure(to.address)?;

        let payload_bytes = payload
            .sign_and_encode_to_eip2718(nonce, self.chain_id(), None, &from.keypair)
            .await?;

        self.submit_and_confirm_tx(&payload_bytes, self.config().tx_confirmations)
            .await
    }

    /// Finalizes closure of an outgoing channel from `from` to `to`.
    pub async fn finalize_outgoing_channel_closure(
        &self,
        from: &AnvilAccount,
        to: &AnvilAccount,
        module: &str,
    ) -> Result<[u8; 32]> {
        let nonce = self.nonce(from).await?;

        let payload_generator = SafePayloadGenerator::new(
            &from.keypair,
            *self.contract_addresses(),
            HoprAddress::from_str(module)?,
        );
        let payload = payload_generator.finalize_outgoing_channel_closure(to.address)?;

        let payload_bytes = payload
            .sign_and_encode_to_eip2718(nonce, self.chain_id(), None, &from.keypair)
            .await?;

        self.submit_and_confirm_tx(&payload_bytes, self.config().tx_confirmations)
            .await
    }

    /// Fully closes an outgoing channel from `from` to `to` (initiates then finalizes).
    pub async fn close_outgoing_channel(&self, from: &AnvilAccount, to: &AnvilAccount, module: &str) -> Result<()> {
        self.initiate_outgoing_channel_closure(from, to, module).await?;
        self.finalize_outgoing_channel_closure(from, to, module).await?;
        Ok(())
    }

    fn teardown(&self) {
        self.inner.teardown();
    }
}

impl IntegrationFixtureInner {
    fn teardown(&self) {
        let mut docker_guard = self
            .docker
            .lock()
            .expect("integration docker environment mutex poisoned");

        if docker_guard.is_some() {
            info!("tearing down docker stack for integration tests");
        }

        docker_guard.take();
    }
}

async fn wait_for_blokli_ready(client: &BlokliClient) -> Result<()> {
    // Poll `query_chain_info` until bloklid responds — that means the API is up and
    // serving indexed state (bloklid-anvil deploys contracts on startup).
    let deadline = Instant::now() + STACK_STARTUP_WAIT;

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
                        STACK_STARTUP_WAIT.as_secs(),
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
    let start = Instant::now();
    let mut last_error: Option<anyhow::Error> = None;
    loop {
        match check().await {
            Ok(Some(result)) => return Ok(result),
            Ok(None) => {}
            Err(e) => last_error = Some(e),
        }
        if start.elapsed() > timeout {
            if let Some(e) = last_error {
                return Err(e.context(format!("{description} did not complete within {timeout:?}")));
            }
            anyhow::bail!("{description} did not complete within {timeout:?}");
        }
        tokio::time::sleep(interval).await;
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

pub async fn build_integration_fixture() -> Result<IntegrationFixture> {
    let config: Arc<TestConfig> = Arc::new(TestConfig::load()?);
    let mut docker = DockerEnvironment::new(config.clone());

    docker.ensure_image_available()?;
    docker.run()?;

    let blokli_config = BlokliClientConfig {
        auto_compatibility_check: false,
        ..Default::default()
    };
    let client = BlokliClient::new(config.bloklid_url().clone(), blokli_config);
    info!(
        seconds = STACK_STARTUP_WAIT.as_secs(),
        base_url = %client.base_url(),
        "waiting for integration stack readiness"
    );
    wait_for_blokli_ready(&client).await?;
    let accounts = docker.fetch_anvil_accounts()?;

    // Contracts are already deployed by the image entrypoint; read chain id + their
    // addresses from bloklid rather than deploying our own set.
    let chain_info = client.query_chain_info().await.context("failed to query chain info")?;
    let chain_id = u64::try_from(chain_info.chain_id).context("negative chain id from chain info")?;
    let contract_addrs: ContractAddresses = serde_json::from_str(&chain_info.contract_addresses.0)
        .context("failed to parse contract addresses from chain info")?;

    info!(?contract_addrs, chain_id, "resolved deployed contract addresses");

    let token = AlloyAddress::from_slice(contract_addrs.token.as_ref());
    distribute_tokens(&client, &accounts, token, chain_id, config.tx_confirmations).await?;

    info!("distributed wxHOPR to test accounts");

    let fixture = IntegrationFixture {
        inner: Arc::new(IntegrationFixtureInner {
            config,
            accounts,
            client,
            chain_id,
            docker: Mutex::new(Some(docker)),
            contract_addrs,
        }),
    };

    register_shutdown_hook();

    Ok(fixture)
}

static SHARED_FIXTURE: OnceCell<IntegrationFixture> = OnceCell::const_new();
static SHUTDOWN_HOOK: Once = Once::new();

extern "C" fn teardown_shared_fixture() {
    if let Some(fixture) = SHARED_FIXTURE.get() {
        fixture.teardown();
    }
}

fn register_shutdown_hook() {
    SHUTDOWN_HOOK.call_once(|| unsafe {
        let result = atexit(teardown_shared_fixture);
        if result != 0 {
            panic!("failed to register integration fixture teardown hook");
        }
    });
}

#[fixture]
pub async fn integration_fixture() -> IntegrationFixture {
    SHARED_FIXTURE
        .get_or_try_init(|| async { build_integration_fixture().await })
        .await
        .expect("failed to set up integration fixture")
        .clone()
}
