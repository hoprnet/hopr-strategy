use std::{fs, path::PathBuf, sync::Arc};

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use tracing::{info, warn};

use crate::fixture::{
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
}

impl DockerEnvironment {
    pub fn new(config: Arc<TestConfig>) -> Self {
        Self { config, running: false }
    }

    pub fn ensure_image_available(&self) -> Result<()> {
        info!(image = %self.config.image, "pulling bloklid-anvil image");
        let cmd = build_command("docker", &["pull", "--platform", "linux/amd64", &self.config.image]);
        run_command(cmd, true, "docker pull bloklid-anvil image")
    }

    pub fn run(&mut self) -> Result<()> {
        // Remove any stale container from a previous aborted run.
        let _ = run_command(
            build_command("docker", &["rm", "-f", &self.config.container_name()]),
            true,
            "docker rm stale container",
        );

        let api_pub = format!("{}:{CONTAINER_API_PORT}", self.config.host_api_port());

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
                "linux/amd64",
                "-p",
                &api_pub,
                &self.config.image,
            ],
        );
        run_command(cmd, true, "docker run bloklid-anvil")?;
        self.running = true;
        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        if !self.running {
            return Ok(());
        }
        info!(container = %self.config.container_name(), "stopping bloklid-anvil container");
        run_command(
            build_command("docker", &["rm", "-f", &self.config.container_name()]),
            true,
            "docker rm container",
        )?;
        self.running = false;
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
        let log_path = PathBuf::from("/tmp").join(format!("hopr-strategy-integration/{container}/{timestamp}.log"));
        fs::create_dir_all(log_path.parent().unwrap())?;
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
        .collect();

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
