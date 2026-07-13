//! Integration-test harness for driving `hopr-strategy` strategies against a
//! single self-contained Blokli-Anvil docker image.
//!
//! Two type-worlds meet here, bridged by the shared `blokli-client`:
//! - **on-chain onboarding** ([`fixtures`], [`anvil`], [`transaction`]): distributes wxHOPR and onboards nodes (deploy
//!   Safe, announce, approve, open channels) by submitting raw signed transactions through the blokli client — no
//!   direct anvil RPC. Uses the `hopr-types` 1.11 line pulled in by `blokli-client`/`hopli`.
//! - **strategy driving** ([`strategy_node`]): wraps the real `hopr-chain-connector` in the node adapter strategies
//!   expect, in the same `hopr-api` 1.15 world as `hopr-strategy`.

pub mod anvil;
pub mod config;
pub mod constants;
mod docker;
pub mod fixtures;
pub mod strategy_node;
pub mod transaction;
mod util;
