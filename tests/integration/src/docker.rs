use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use tracing::{info, warn};
use url::Url;

use crate::{
    anvil::AnvilAccount,
    config::{CONTAINER_API_PORT, TestConfig},
    util::{build_command, capture_command, run_command},
};

/// Runs the self-contained `bloklid-anvil` image (anvil + HOPR contract
/// deployment + bloklid in a single container) and exposes the bloklid API to
/// the host. Everything the tests need (contract addresses, nonces, token
/// distribution, onboarding) goes through the bloklid API — anvil's JSON-RPC is
/// never contacted directly, so only the API port is published.
pub struct DockerEnvironment {
    config: Arc<TestConfig>,
    running: bool,
    bloklid_url: Option<Url>,
}

const PROJECT_LABEL: &str = "org.hopr.integration.project=hopr-strategy";

impl DockerEnvironment {
    pub fn new(config: Arc<TestConfig>) -> Self {
        Self {
            config,
            running: false,
            bloklid_url: None,
        }
    }

    pub fn ensure_image_available(&self) -> Result<()> {
        if !self.config.pull_image {
            let inspect = build_command("docker", &["image", "inspect", &self.config.image]);
            if run_command(inspect, "docker inspect bloklid-anvil image").is_ok() {
                info!(image = %self.config.image, "using cached bloklid-anvil image");
                return Ok(());
            }
        }

        info!(image = %self.config.image, "pulling bloklid-anvil image");
        let cmd = build_command(
            "docker",
            &["pull", "--platform", &self.config.platform, &self.config.image],
        );
        run_command(cmd, "docker pull bloklid-anvil image")
    }

    pub fn run(&mut self) -> Result<()> {
        self.cleanup_stale_containers()?;

        // Remove any stale container from a previous aborted run.
        let _ = run_command(
            build_command("docker", &["rm", "-f", &self.config.container_name()]),
            "docker rm stale container",
        );

        let api_pub = self.config.host_api_port().map_or_else(
            || format!("127.0.0.1::{CONTAINER_API_PORT}"),
            |port| format!("127.0.0.1:{port}:{CONTAINER_API_PORT}"),
        );
        let stack_label = format!("org.hopr.integration.stack={}", self.config.stack_id);

        info!(
            container = %self.config.container_name(),
            image = %self.config.image,
            "starting bloklid-anvil container"
        );
        let cmd = build_command(
            "docker",
            &[
                "run",
                "-d",
                "--name",
                &self.config.container_name(),
                "--platform",
                &self.config.platform,
                "--label",
                PROJECT_LABEL,
                "--label",
                &stack_label,
                "-p",
                &api_pub,
                &self.config.image,
            ],
        );
        run_command(cmd, "docker run bloklid-anvil")?;
        self.running = true;

        let mapping = capture_command(
            build_command(
                "docker",
                &[
                    "port",
                    &self.config.container_name(),
                    &format!("{CONTAINER_API_PORT}/tcp"),
                ],
            ),
            "docker discover bloklid-anvil API port",
        )?;
        let port = mapping
            .lines()
            .next()
            .and_then(|line| line.rsplit(':').next())
            .context("Docker did not return a mapped bloklid API port")?
            .parse::<u16>()
            .context("Docker returned an invalid bloklid API port")?;
        self.bloklid_url = Some(Url::parse(&format!("http://127.0.0.1:{port}"))?);
        Ok(())
    }

    pub fn bloklid_url(&self) -> Result<&Url> {
        self.bloklid_url
            .as_ref()
            .context("managed Docker stack has not been started")
    }

    pub fn stop(&mut self) -> Result<()> {
        if !self.running {
            return Ok(());
        }
        info!(container = %self.config.container_name(), "stopping bloklid-anvil container");
        run_command(
            build_command("docker", &["rm", "-f", &self.config.container_name()]),
            "docker rm container",
        )?;
        self.running = false;
        self.bloklid_url = None;
        Ok(())
    }

    /// Force-removes this instance's container, ignoring errors.
    pub fn force_remove(&self) {
        let _ = run_command(
            build_command("docker", &["rm", "-f", &self.config.container_name()]),
            "docker rm container at exit",
        );
    }

    fn cleanup_stale_containers(&self) -> Result<()> {
        let filter = format!("label={PROJECT_LABEL}");
        let containers = capture_command(
            build_command("docker", &["ps", "-aq", "--filter", &filter]),
            "docker list stale HOPR integration containers",
        )?;

        for container in containers.lines().filter(|line| !line.is_empty()) {
            // Another integration-test process sharing PROJECT_LABEL may remove a
            // container between the `docker ps` listing above and this inspect/rm.
            // Tolerate that race instead of aborting the whole fixture setup.
            let created = match capture_command(
                build_command("docker", &["inspect", "--format", "{{.Created}}", container]),
                "docker inspect integration container creation time",
            ) {
                Ok(value) => value,
                Err(_) => continue, // removed concurrently
            };
            let created = DateTime::parse_from_rfc3339(&created)?.with_timezone(&Utc);
            let age = Utc::now().signed_duration_since(created).to_std().unwrap_or_default();
            if age >= self.config.stale_container_max_age {
                info!(container, ?age, "removing stale HOPR integration container");
                let _ = run_command(
                    build_command("docker", &["rm", "-f", container]),
                    "docker remove stale HOPR integration container",
                );
            }
        }
        Ok(())
    }

    pub fn collect_logs(&self, timestamp: DateTime<Utc>) -> Result<PathBuf> {
        if !self.running {
            bail!("container not running");
        }
        let container = self.config.container_name();
        let logs = capture_command(
            build_command("docker", &["logs", &container]),
            &format!("docker logs {container}"),
        )?;
        let timestamp = timestamp.format("%Y%m%d_%H%M%S");
        let log_dir = std::env::temp_dir().join("hopr-strategy-integration").join(&container);
        fs::create_dir_all(&log_dir)?;
        let log_path = log_dir.join(format!("{timestamp}.log"));
        fs::write(&log_path, logs)?;
        info!(path = %log_path.display(), "saved container logs");
        Ok(log_path)
    }

    pub fn fetch_anvil_accounts(&self) -> Result<Vec<AnvilAccount>> {
        let container = self.config.container_name();
        let logs = capture_command(
            build_command("docker", &["logs", &container]),
            &format!("docker logs {container}"),
        )?;
        parse_anvil_accounts(&logs)
    }
}

pub fn load_anvil_accounts(path: &Path) -> Result<Vec<AnvilAccount>> {
    let logs = fs::read_to_string(path)?;
    parse_anvil_accounts(&logs)
}

impl Drop for DockerEnvironment {
    fn drop(&mut self) {
        if self.running {
            if let Err(err) = self.collect_logs(Utc::now()) {
                warn!(error = ?err, "failed to collect container logs");
            }
            if let Err(err) = self.stop() {
                warn!(error = ?err, "failed to stop container");
            }
        }
    }
}

fn parse_anvil_accounts(logs: &str) -> Result<Vec<AnvilAccount>> {
    let addresses = extract_section_values(logs, "Available Accounts");
    let keys = extract_section_values(logs, "Private Keys");

    if addresses.is_empty() {
        bail!("Failed to parse Anvil addresses from logs");
    }
    if addresses.len() != keys.len() {
        bail!("Mismatch between addresses and private keys in Anvil logs");
    }

    let accounts: Vec<AnvilAccount> = addresses
        .into_iter()
        .zip(keys)
        .map(|(address, private_key)| AnvilAccount::new(private_key, address))
        .collect::<Result<_>>()?;

    if accounts.is_empty() {
        bail!("Failed to parse Anvil private keys from logs");
    }

    Ok(accounts)
}

fn extract_section_values(logs: &str, marker: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut in_section = false;

    for line in logs.lines() {
        let clean_line = strip_ansi_codes(line).trim().to_string();
        if clean_line.is_empty() {
            if in_section && !result.is_empty() {
                break;
            }
            continue;
        }

        if clean_line.contains(marker) {
            in_section = true;
            continue;
        }

        if in_section && clean_line.starts_with('(') {
            if let Some(pos) = clean_line.find("0x") {
                let value = clean_line[pos..]
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                result.push(value);
            }
        } else if in_section && clean_line.starts_with("===") {
            continue;
        }
    }

    result
}

fn strip_ansi_codes(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            for next in chars.by_ref() {
                if next == 'm' {
                    break;
                }
            }
        } else {
            output.push(ch);
        }
    }

    output
}
