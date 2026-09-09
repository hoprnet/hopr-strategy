//! Client for Curvy's off-chain relayer: the node hands over a proof and the relayer puts it on
//! chain, paying gas and appearing as the sender.
//!
//! The node is then not a transaction sender at all for the two operations that would otherwise
//! link it to its deposits. What it still signs is the shield, which the relayer does not accept —
//! and, on a self-submitting deployment, its own note commitments.
//!
//! ### The shape of a submission
//!
//! `POST /relay/submit` takes proof, public signals, and two derived keys. It answers immediately
//! with a `requestId` rather than a transaction hash, because the submission is queued: the
//! relayer's worker claims it, submits it, and the status walks `queued → submitting → submitted
//! → included → finalized`. [`RelayClient::await_inclusion`] polls that to `included`, which is
//! the first status that means the proof is on chain.
//!
//! Two failure modes are not failures:
//!
//! * a **duplicate `requestKey`** returns the original submission, so a resubmission after a lost response is
//!   idempotent rather than a double spend;
//! * a **`409` on `spendKey`** means an equivalent submission is already in flight. The notes are being spent exactly
//!   once, which is what we wanted, so this resolves to the in-flight submission instead of an error.
//!
//! ### Fees
//!
//! An aggregation must carry an output note addressed to the relayer's operator, worth at least
//! its live gas quote — [`RelayClient::paymaster`] is what prices it. A withdrawal carries none:
//! the vault reimburses the submitter on chain, so the relayer does not gate withdrawals on a
//! quote at all.

use std::time::Duration;

use blokli_client::exports::Url;
use serde::Deserialize;

use crate::errors::StrategyError;

/// How often to ask whether a queued submission has landed.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// What a submission is doing, as the relayer reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RelayStatus {
    Queued,
    Submitting,
    Submitted,
    /// On chain. The first status that means the proof took effect.
    Included,
    Finalized,
    /// Reorged out after inclusion; the relayer retries it itself.
    Reorged,
    Failed,
}

impl RelayStatus {
    /// Whether the proof is on chain and will stay there absent a reorg.
    pub fn is_on_chain(self) -> bool {
        matches!(self, Self::Included | Self::Finalized)
    }

    /// Whether waiting any longer is pointless.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Included | Self::Finalized | Self::Failed)
    }
}

/// One submission's state.
#[derive(Clone, Debug, Deserialize)]
pub struct RelaySubmission {
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub status: RelayStatus,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: Option<String>,
    pub error: Option<String>,
}

/// The relayer operator's stealth identity and its live gas quote.
///
/// Everything needed to build the fee note an aggregation must carry, and to size it. The
/// operator's own tolerance is included so a caller can match the floor the relayer will apply
/// rather than guess at it.
#[derive(Clone, Debug, Deserialize)]
pub struct PaymasterInfo {
    pub operator: PaymasterOperator,
    /// Vault token ids the operator accepts a fee note in; `None` means any.
    #[serde(rename = "acceptedVaultTokenIds")]
    pub accepted_vault_token_ids: Option<Vec<String>>,
    #[serde(rename = "submitAggregationGasUnits")]
    pub submit_aggregation_gas_units: String,
    #[serde(rename = "gasPriceWei")]
    pub gas_price_wei: String,
    /// Headroom the client should add, in basis points.
    #[serde(rename = "clientBufferBps")]
    pub client_buffer_bps: u64,
    /// Headroom the relayer itself allows below its quote, in basis points.
    #[serde(rename = "relayerToleranceBps")]
    pub relayer_tolerance_bps: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PaymasterOperator {
    #[serde(rename = "S")]
    pub spend_public_key: String,
    #[serde(rename = "V")]
    pub view_public_key: String,
    #[serde(rename = "babyJubjubPublicKey")]
    pub bjj_public_key: String,
}

impl PaymasterInfo {
    /// The fee note's value: the operator's quote plus the buffer it asks clients to add.
    ///
    /// Erring high on purpose. The relayer rejects an aggregation whose fee note is below its
    /// floor *before* queueing it, so an under-priced note costs a whole round trip and a
    /// re-proof; the excess is the operator's, not lost.
    pub fn required_fee(&self) -> Result<u128, StrategyError> {
        let units: u128 = self.submit_aggregation_gas_units.parse().map_err(|error| {
            StrategyError::other(anyhow::anyhow!("relayer quoted an unparseable gas unit count: {error}"))
        })?;
        let price: u128 = self
            .gas_price_wei
            .parse()
            .map_err(|error| StrategyError::other(anyhow::anyhow!("relayer quoted an unparseable gas price: {error}")))?;
        let base = units
            .checked_mul(price)
            .ok_or_else(|| StrategyError::other(anyhow::anyhow!("the relayer's gas quote overflows")))?;
        let buffered = base
            .checked_mul(10_000u128.saturating_add(self.client_buffer_bps as u128))
            .map(|scaled| scaled / 10_000)
            .ok_or_else(|| StrategyError::other(anyhow::anyhow!("the relayer's buffered gas quote overflows")))?;
        Ok(buffered)
    }
}

/// Errors the relayer reports that a caller must distinguish.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    /// The relayer refused the submission outright — a fee note it will not accept, or a payload
    /// it cannot read. Re-submitting the same proof will fail the same way.
    #[error("the Curvy relayer rejected the submission: {0}")]
    Rejected(String),
    /// The relayer could not be reached, or answered in a way we could not read. Worth retrying.
    #[error("the Curvy relayer is unreachable: {0}")]
    Transport(String),
    /// The submission landed but the transaction failed on chain.
    #[error("the Curvy relayer reported a failed submission: {0}")]
    Failed(String),
    /// Nothing terminal happened within the deadline. The submission may still land.
    #[error("timed out waiting for the Curvy relayer to submit {request_id}, last status {status:?}")]
    Timeout { request_id: String, status: RelayStatus },
}

impl From<RelayError> for StrategyError {
    fn from(error: RelayError) -> Self {
        StrategyError::other(error)
    }
}

/// A client for one relayer deployment.
pub struct RelayClient {
    base_url: Url,
    http: reqwest::Client,
}

impl RelayClient {
    /// `base_url` is the gateway host — `https://api.curvy.box` in production — not the `/relay`
    /// prefix, which this appends.
    pub fn new(base_url: Url, request_timeout: Duration) -> Result<Self, StrategyError> {
        let http = reqwest::Client::builder()
            .timeout(request_timeout)
            .build()
            .map_err(|error| StrategyError::other(anyhow::anyhow!("building the relayer client: {error}")))?;
        Ok(Self { base_url, http })
    }

    fn endpoint(&self, path: &str) -> Result<Url, RelayError> {
        self.base_url
            .join(path)
            .map_err(|error| RelayError::Transport(format!("{path} is not a valid path under the relayer URL: {error}")))
    }

    /// The operator's identity and gas quote, for building an aggregation's fee note.
    ///
    /// A `404` means the deployment runs no paymaster and accepts aggregations without a fee
    /// note; that is reported as `Ok(None)` rather than an error.
    pub async fn paymaster(&self, chain_id: u64) -> Result<Option<PaymasterInfo>, RelayError> {
        let url = self.endpoint(&format!("/relay/paymaster?chainId={chain_id}"))?;
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|error| RelayError::Transport(error.to_string()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Self::decode(response).await.map(Some)
    }

    /// Queues a proof for submission.
    ///
    /// Resolves to the submission's current state, which is normally `queued` — use
    /// [`await_inclusion`](Self::await_inclusion) to wait for it to land. A `409` on the spend key
    /// resolves to the in-flight submission rather than an error: the notes are being spent
    /// exactly once, which is the outcome we wanted.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit(
        &self,
        action: curvy_abi::RelayAction,
        chain_id: u64,
        max_inputs: usize,
        proof: &curvy_abi::curvy_types::Groth16Proof,
        public_signals: &[String],
        request_key: &str,
        spend_key: &str,
        intent_id: &str,
    ) -> Result<RelaySubmission, RelayError> {
        let url = self.endpoint("/relay/submit")?;
        let body = serde_json::json!({
            "action": action.as_str(),
            // The EVM chain id, not an indexer's internal network row.
            "networkId": chain_id,
            "maxInputs": max_inputs,
            "proof": { "a": proof.a, "b": proof.b, "c": proof.c },
            "publicSignals": public_signals,
            "requestKey": request_key,
            "spendKey": spend_key,
            "intentId": intent_id,
        });
        let response = self
            .http
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|error| RelayError::Transport(error.to_string()))?;
        if response.status() == reqwest::StatusCode::CONFLICT {
            // The relayer answers a conflict with the submission already holding the spend.
            return Self::decode(response).await;
        }
        Self::decode(response).await
    }

    /// One submission's current state.
    pub async fn status(&self, request_id: &str) -> Result<RelaySubmission, RelayError> {
        let url = self.endpoint(&format!("/relay/submission/{request_id}/status"))?;
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|error| RelayError::Transport(error.to_string()))?;
        Self::decode(response).await
    }

    /// The submission carrying `intent_id`, if the relayer ever received it.
    ///
    /// The recovery path for a lost `POST` response: the intent id is ours and journalled before
    /// submitting, so this answers "did my proof reach the relayer" without knowing its
    /// `requestId`. A `404` means it never arrived.
    pub async fn by_intent(&self, intent_id: &str, chain_id: u64) -> Result<Option<RelaySubmission>, RelayError> {
        let url = self.endpoint(&format!("/relay/intent/{intent_id}/status?networkId={chain_id}"))?;
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|error| RelayError::Transport(error.to_string()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Self::decode(response).await.map(Some)
    }

    /// Polls until the submission is on chain, fails, or `deadline` passes.
    pub async fn await_inclusion(
        &self,
        submission: RelaySubmission,
        deadline: Duration,
    ) -> Result<RelaySubmission, RelayError> {
        let mut current = submission;
        if current.status.is_terminal() {
            return Self::terminal(current);
        }
        let started = std::time::Instant::now();
        while started.elapsed() < deadline {
            tokio::time::sleep(POLL_INTERVAL).await;
            current = self.status(&current.request_id).await?;
            if current.status.is_terminal() {
                return Self::terminal(current);
            }
        }
        Err(RelayError::Timeout {
            request_id: current.request_id,
            status: current.status,
        })
    }

    fn terminal(submission: RelaySubmission) -> Result<RelaySubmission, RelayError> {
        if submission.status.is_on_chain() {
            Ok(submission)
        } else {
            Err(RelayError::Failed(
                submission
                    .error
                    .unwrap_or_else(|| format!("status {:?}", submission.status)),
            ))
        }
    }

    /// Reads a response, separating the relayer's own refusals from transport faults.
    ///
    /// The distinction decides whether a retry is worth anything: a `4xx` is a verdict on this
    /// exact payload, while anything else may be transient.
    async fn decode<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T, RelayError> {
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|error| RelayError::Transport(format!("reading the relayer's response: {error}")))?;
        if status.is_client_error() {
            return Err(RelayError::Rejected(Self::describe(status, &body)));
        }
        if !status.is_success() {
            return Err(RelayError::Transport(Self::describe(status, &body)));
        }
        serde_json::from_str(&body)
            .map_err(|error| RelayError::Transport(format!("could not read the relayer's response: {error}: {body}")))
    }

    /// The relayer's error envelope is `{error, message, details?}`; anything else is quoted raw.
    fn describe(status: reqwest::StatusCode, body: &str) -> String {
        #[derive(Deserialize)]
        struct Envelope {
            message: Option<String>,
            error: Option<String>,
        }
        let described = serde_json::from_str::<Envelope>(body)
            .ok()
            .and_then(|envelope| envelope.message.or(envelope.error))
            .unwrap_or_else(|| body.chars().take(200).collect());
        format!("HTTP {status}: {described}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paymaster(units: &str, price: &str, buffer_bps: u64) -> PaymasterInfo {
        PaymasterInfo {
            operator: PaymasterOperator {
                spend_public_key: "0x01".to_owned(),
                view_public_key: "0x02".to_owned(),
                bjj_public_key: "0x03".to_owned(),
            },
            accepted_vault_token_ids: None,
            submit_aggregation_gas_units: units.to_owned(),
            gas_price_wei: price.to_owned(),
            client_buffer_bps: buffer_bps,
            relayer_tolerance_bps: 500,
        }
    }

    #[test]
    fn the_fee_note_covers_the_quote_plus_the_buffer() -> anyhow::Result<()> {
        // The relayer's own defaults: 675 000 gas units at 1 gwei, with 15% client headroom.
        let quote = paymaster("675000", "1000000000", 1500).required_fee()?;
        assert_eq!(quote, 675_000u128 * 1_000_000_000 * 11_500 / 10_000);
        Ok(())
    }

    #[test]
    fn a_zero_buffer_is_exactly_the_quote() -> anyhow::Result<()> {
        assert_eq!(paymaster("100", "7", 0).required_fee()?, 700);
        Ok(())
    }

    #[test]
    fn an_unparseable_quote_is_refused_rather_than_defaulted() {
        // Silently substituting a default here would under-price the fee note and get the
        // aggregation refused after a full proof.
        assert!(paymaster("not-a-number", "7", 0).required_fee().is_err());
        assert!(paymaster("100", "", 0).required_fee().is_err());
    }

    #[test]
    fn only_on_chain_statuses_count_as_success() {
        assert!(RelayStatus::Included.is_on_chain());
        assert!(RelayStatus::Finalized.is_on_chain());
        // `submitted` means the relayer sent it, not that it landed — waiting on it as if it had
        // would report a deposit that may still fail.
        assert!(!RelayStatus::Submitted.is_on_chain());
        assert!(!RelayStatus::Queued.is_on_chain());
        assert!(!RelayStatus::Reorged.is_on_chain());
        assert!(!RelayStatus::Failed.is_on_chain());
    }

    #[test]
    fn a_reorg_is_not_terminal_because_the_relayer_retries_it() {
        assert!(RelayStatus::Failed.is_terminal());
        assert!(RelayStatus::Included.is_terminal());
        assert!(!RelayStatus::Reorged.is_terminal());
        assert!(!RelayStatus::Submitting.is_terminal());
    }

    #[test]
    fn a_failed_submission_surfaces_the_relayers_reason() {
        let error = RelayClient::terminal(RelaySubmission {
            request_id: "r1".to_owned(),
            status: RelayStatus::Failed,
            transaction_hash: None,
            error: Some("insufficient operator note".to_owned()),
        })
        .expect_err("a failed submission is not a success");
        assert!(error.to_string().contains("insufficient operator note"), "{error}");
    }

    #[test]
    fn an_included_submission_is_returned_as_is() -> anyhow::Result<()> {
        let submission = RelayClient::terminal(RelaySubmission {
            request_id: "r1".to_owned(),
            status: RelayStatus::Included,
            transaction_hash: Some("0xabc".to_owned()),
            error: None,
        })?;
        assert_eq!(submission.transaction_hash.as_deref(), Some("0xabc"));
        Ok(())
    }

    #[test]
    fn statuses_parse_from_the_relayers_spelling() -> anyhow::Result<()> {
        let submission: RelaySubmission = serde_json::from_str(
            r#"{"requestId":"abc","status":"included","transactionHash":"0xdeadbeef"}"#,
        )?;
        assert_eq!(submission.status, RelayStatus::Included);
        assert_eq!(submission.request_id, "abc");
        Ok(())
    }

    #[test]
    fn a_queued_response_carries_no_transaction_yet() -> anyhow::Result<()> {
        let submission: RelaySubmission = serde_json::from_str(r#"{"requestId":"abc","status":"queued"}"#)?;
        assert_eq!(submission.status, RelayStatus::Queued);
        assert!(submission.transaction_hash.is_none());
        Ok(())
    }

    #[test]
    fn a_paymaster_response_parses_from_the_documented_shape() -> anyhow::Result<()> {
        let info: PaymasterInfo = serde_json::from_str(
            r#"{"operator":{"S":"0x1","V":"0x2","babyJubjubPublicKey":"0x3"},
                "acceptedVaultTokenIds":["3"],"submitAggregationGasUnits":"675000",
                "gasPriceWei":"1000000000","clientBufferBps":1500,"relayerToleranceBps":500}"#,
        )?;
        assert_eq!(info.accepted_vault_token_ids.as_deref(), Some(["3".to_owned()].as_slice()));
        assert_eq!(info.operator.bjj_public_key, "0x3");
        Ok(())
    }

    #[test]
    fn an_error_envelope_is_summarised_not_dumped() {
        let described = RelayClient::describe(
            reqwest::StatusCode::BAD_REQUEST,
            r#"{"error":"BadRequest","message":"spendKey does not match the submitted nullifiers"}"#,
        );
        assert!(described.contains("400"), "{described}");
        assert!(described.contains("spendKey does not match"), "{described}");
    }

    #[test]
    fn an_unreadable_error_body_is_still_reported() {
        let described = RelayClient::describe(reqwest::StatusCode::BAD_GATEWAY, "<html>gateway</html>");
        assert!(described.contains("502"), "{described}");
        assert!(described.contains("gateway"), "{described}");
    }
}
