use std::{
    env,
    fmt::Display,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use url::Url;

const DEFAULT_IMAGE: &str = "europe-west3-docker.pkg.dev/hoprassociation/docker-images/bloklid-anvil:latest";
const DEFAULT_PLATFORM: &str = "linux/amd64";

pub const CONTAINER_API_PORT: u16 = 8080;

#[derive(Clone, Copy, Debug)]
pub struct TestTimeouts {
    pub startup: Duration,
    pub indexing: Duration,
    pub visibility: Duration,
    pub action: Duration,
    pub stable: Duration,
}

impl TestTimeouts {
    fn load() -> Result<Self> {
        Ok(Self {
            startup: duration_from_env("BLOKLI_TEST_STARTUP_TIMEOUT_SECS", 120)?,
            indexing: duration_from_env("BLOKLI_TEST_INDEXING_TIMEOUT_SECS", 30)?,
            visibility: duration_from_env("BLOKLI_TEST_VISIBILITY_TIMEOUT_SECS", 60)?,
            action: duration_from_env("BLOKLI_TEST_ACTION_TIMEOUT_SECS", 90)?,
            stable: duration_from_env("BLOKLI_TEST_STABLE_WINDOW_SECS", 5)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct TestConfig {
    pub image: String,
    pub platform: String,
    pub pull_image: bool,
    external_blokli_url: Option<Url>,
    external_anvil_logs: Option<PathBuf>,
    host_api_port: Option<u16>,
    pub tx_confirmations: usize,
    pub funded_accounts: usize,
    pub stack_id: String,
    pub stale_container_max_age: Duration,
    pub timeouts: TestTimeouts,
}

impl TestConfig {
    pub fn load() -> Result<Self> {
        let external_blokli_url = env_value("BLOKLI_TEST_EXTERNAL_BLOKLID_URL")?
            .map(|value| Url::parse(&value).context("invalid BLOKLI_TEST_EXTERNAL_BLOKLID_URL"))
            .transpose()?;
        let external_anvil_logs = env_value("BLOKLI_TEST_EXTERNAL_ANVIL_LOGS")?.map(PathBuf::from);
        let host_api_port = parse_env("BLOKLI_TEST_HOST_PORT")?;

        match (&external_blokli_url, &external_anvil_logs) {
            (Some(_), Some(_)) => {}
            (Some(_), None) => {
                bail!("BLOKLI_TEST_EXTERNAL_ANVIL_LOGS is required with BLOKLI_TEST_EXTERNAL_BLOKLID_URL")
            }
            (None, Some(_)) => {
                bail!("BLOKLI_TEST_EXTERNAL_ANVIL_LOGS is only valid with BLOKLI_TEST_EXTERNAL_BLOKLID_URL")
            }
            (None, None) => {}
        }
        if external_blokli_url.is_some() && host_api_port.is_some() {
            bail!("BLOKLI_TEST_HOST_PORT is only valid for a managed Docker stack");
        }

        Ok(Self {
            image: env_value("BLOKLI_TEST_REMOTE_IMAGE")?.unwrap_or_else(|| DEFAULT_IMAGE.to_owned()),
            platform: env_value("BLOKLI_TEST_PLATFORM")?.unwrap_or_else(|| DEFAULT_PLATFORM.to_owned()),
            pull_image: parse_env("BLOKLI_TEST_PULL_IMAGE")?.unwrap_or(false),
            external_blokli_url,
            external_anvil_logs,
            host_api_port,
            tx_confirmations: parse_env("BLOKLI_TEST_CONFIRMATIONS")?.unwrap_or(1),
            funded_accounts: parse_env("BLOKLI_TEST_FUNDED_ACCOUNTS")?.unwrap_or(8),
            stack_id: env_value("BLOKLI_TEST_STACK_ID")?.unwrap_or_else(|| format!("{:x}", std::process::id())),
            stale_container_max_age: Duration::from_secs(
                parse_env::<u64>("BLOKLI_TEST_STALE_CONTAINER_MAX_AGE_HOURS")?.unwrap_or(24) * 60 * 60,
            ),
            timeouts: TestTimeouts::load()?,
        })
    }

    pub fn manages_docker(&self) -> bool {
        self.external_blokli_url.is_none()
    }

    pub fn external_blokli_url(&self) -> Option<&Url> {
        self.external_blokli_url.as_ref()
    }

    pub fn external_anvil_logs(&self) -> Option<&Path> {
        self.external_anvil_logs.as_deref()
    }

    pub fn host_api_port(&self) -> Option<u16> {
        self.host_api_port
    }

    pub fn container_name(&self) -> String {
        format!("blokli-{}", self.stack_id)
    }
}

fn env_value(name: &str) -> Result<Option<String>> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => bail!("{name} contains non-Unicode data"),
    }
}

fn parse_env<T>(name: &str) -> Result<Option<T>>
where
    T: FromStr,
    T::Err: Display,
{
    env_value(name)?
        .map(|value| {
            value
                .parse()
                .map_err(|error| anyhow::anyhow!("invalid {name}: {error}"))
        })
        .transpose()
}

fn duration_from_env(name: &str, default_seconds: u64) -> Result<Duration> {
    Ok(Duration::from_secs(parse_env(name)?.unwrap_or(default_seconds)))
}
