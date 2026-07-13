use anyhow::Result;
use clap::Parser;
use url::Url;

/// Self-contained image bundling anvil + contract deployment + bloklid.
const DEFAULT_IMAGE: &str = "europe-west3-docker.pkg.dev/hoprassociation/docker-images/bloklid-anvil:latest";

/// Base host port for the bloklid API. Each stack offsets from this using a
/// deterministic value derived from the process ID so parallel test binaries do
/// not collide.
const BASE_BLOKLID_PORT: u16 = 18081;

/// bloklid API port inside the bundled container.
pub const CONTAINER_API_PORT: u16 = 8080;

/// Generates a short stack identifier from the process ID.
fn default_stack_id() -> String {
    format!("{:04x}", std::process::id() % 0xFFFF)
}

/// Computes a deterministic port offset (0..255) from a stack ID string.
fn port_offset(stack_id: &str) -> u16 {
    let hash: u16 = stack_id.bytes().fold(0u16, |acc, b| acc.wrapping_add(b as u16));
    hash % 256
}

#[derive(Parser, Debug, Clone)]
pub struct TestConfig {
    /// Bundled bloklid-anvil image to run.
    #[arg(long, env = "BLOKLI_TEST_REMOTE_IMAGE", default_value = DEFAULT_IMAGE)]
    pub image: String,

    /// Override the bloklid API URL (default: derived from the stack port offset).
    #[arg(long, env = "BLOKLI_TEST_BLOKLID_URL")]
    pub bloklid_url: Option<Url>,

    #[arg(long, env = "BLOKLI_TEST_CONFIRMATIONS", default_value_t = 1)]
    pub tx_confirmations: usize,

    #[arg(long, env = "BLOKLI_TEST_STACK_ID", default_value_t = default_stack_id())]
    pub stack_id: String,
}

impl TestConfig {
    pub fn load() -> Result<Self> {
        let mut cfg = TestConfig::parse_from(["blokli-integration-config"]);
        cfg.finalize();
        Ok(cfg)
    }

    fn finalize(&mut self) {
        if self.bloklid_url.is_none() {
            let offset = port_offset(&self.stack_id);
            self.bloklid_url = Some(Url::parse(&format!("http://localhost:{}", BASE_BLOKLID_PORT + offset)).unwrap());
        }
    }

    pub fn bloklid_url(&self) -> &Url {
        self.bloklid_url.as_ref().expect("bloklid_url not initialized")
    }

    pub fn container_name(&self) -> String {
        format!("blokli-{}", self.stack_id)
    }

    pub fn host_api_port(&self) -> u16 {
        self.bloklid_url().port_or_known_default().unwrap_or(BASE_BLOKLID_PORT)
    }
}
