use std::process::Command;

use anyhow::{Context, Result};
use tracing::debug;

pub fn run_command(mut command: Command, description: &str) -> Result<()> {
    debug!(description, "run command");
    let output = command
        .output()
        .with_context(|| format!("Failed to run {description}"))?;

    if !output.status.success() {
        anyhow::bail!(
            "{description} exited with status {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(())
}

pub fn capture_command(mut command: Command, description: &str) -> Result<String> {
    let output = command
        .output()
        .with_context(|| format!("Failed to run {description}"))?;

    if !output.status.success() {
        anyhow::bail!(
            "{description} exited with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn build_command(cmd: &str, args: &[&str]) -> Command {
    let mut command = Command::new(cmd);
    for arg in args {
        command.arg(arg);
    }
    command
}
