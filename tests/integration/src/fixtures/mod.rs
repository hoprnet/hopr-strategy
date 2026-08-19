use std::{
    future::Future,
    sync::atomic::{AtomicU8, Ordering},
    time::{Duration, Instant},
};

use anyhow::Result;
use hopr_api::types::{
    crypto::prelude::{ChainKeypair, Keypair},
    primitive::prelude::{Address, BytesRepresentable},
};
use rstest::fixture;

mod pix;
mod scenario;

pub use pix::{PixScenario, PixScenarioOpts, deposit_secret, pix_address_id};
pub use scenario::{
    ChannelParty, ChannelScenario, MultiChannelScenario, ScenarioOpts, assert_channel_never, await_channel,
    await_channel_where,
};

/// Address of the Safe module every scenario deploys its node against.
pub(crate) fn module_address() -> Address {
    Address::new(&[1u8; Address::SIZE])
}

/// Simple test account with a deterministic keypair.
pub struct TestAccount {
    pub keypair: ChainKeypair,
    pub address: Address,
}

impl TestAccount {
    pub fn from_seed(seed: u8) -> anyhow::Result<Self> {
        let secret = [seed; 32];
        let keypair = ChainKeypair::from_secret(&secret)?;
        let address = keypair.public().to_address();
        Ok(Self { keypair, address })
    }

    pub fn secret_bytes(&self) -> &[u8] {
        self.keypair.secret().as_ref()
    }
}

/// Hardcoded timeouts for stub-based tests (fast, no network).
#[derive(Clone, Copy)]
pub struct TestTimeouts {
    pub action: Duration,
    pub stable: Duration,
    pub visibility: Duration,
}

impl Default for TestTimeouts {
    fn default() -> Self {
        Self {
            action: Duration::from_secs(5),
            stable: Duration::from_secs(2),
            visibility: Duration::from_secs(5),
        }
    }
}

pub struct IntegrationFixture {
    timeouts: TestTimeouts,
    next_seed: AtomicU8,
}

impl IntegrationFixture {
    pub fn timeouts(&self) -> TestTimeouts {
        self.timeouts
    }

    pub fn claim_accounts<const N: usize>(&self) -> [TestAccount; N] {
        let start = self.next_seed.fetch_add(N as u8, Ordering::Relaxed);
        std::array::from_fn(|i| TestAccount::from_seed(start + i as u8 + 1).expect("valid seed"))
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

#[fixture]
pub fn integration_fixture() -> IntegrationFixture {
    IntegrationFixture {
        timeouts: TestTimeouts::default(),
        next_seed: AtomicU8::new(0),
    }
}
