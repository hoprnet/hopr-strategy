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
use hopr_api::types::primitive::prelude::U256;
use serde::{Deserialize, Serialize};

use crate::errors::StrategyError;

/// How often to ask whether a queued submission has landed.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// What a submission is doing, as the relayer reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    pub operator: CurvyPublicKeys,
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

/// The public half of a Curvy stealth identity as the gateway spells it: the `S`/`V` meta keys
/// and the BabyJubJub owner key, each an `"x.y"` decimal point. The relayer's operator and the
/// protocol's fee collector are both published in this shape.
#[derive(Clone, Debug, Deserialize)]
pub struct CurvyPublicKeys {
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
        let price: u128 = self.gas_price_wei.parse().map_err(|error| {
            StrategyError::other(anyhow::anyhow!("relayer quoted an unparseable gas price: {error}"))
        })?;
        let base = units
            .checked_mul(price)
            .ok_or_else(|| StrategyError::other(anyhow::anyhow!("the relayer's gas quote overflows")))?;
        let buffered = base
            .checked_mul(10_000u128.saturating_add(self.client_buffer_bps as u128))
            .map(|scaled| scaled / 10_000)
            .ok_or_else(|| StrategyError::other(anyhow::anyhow!("the relayer's buffered gas quote overflows")))?;
        Ok(buffered)
    }

    /// The fee note's value in the vault token it is paid in: [`Self::required_fee`], which is
    /// native gas, converted at the two USD prices the way the relayer's `gasCostInToken` does
    /// (`ceil(native_wei * native_usd * 10^token_decimals / (10^native_decimals * token_usd))`),
    /// so the note clears the gate's threshold by the client buffer rather than by luck.
    ///
    /// Carries [`FEE_NOTE_HEADROOM_BPS`] on top of the operator's own buffer. The gate re-reads
    /// the gas price and the prices when the proof arrives, tolerating only 5% of drift, while
    /// the quote is minutes old by then: on Gnosis the gas price is single-digit wei and moves by
    /// tens of percent between the two. The note is worth a fraction of a cent, and its excess
    /// is the operator's, so erring far high is the cheap side of a re-proof.
    pub fn required_fee_in_token(
        &self,
        native: &TokenValuation,
        token: &TokenValuation,
    ) -> Result<u128, StrategyError> {
        let native_wei = self.required_fee()?;
        let converted = convert_token_amount(native_wei, native, token)?;
        converted
            .checked_mul(10_000u128 + FEE_NOTE_HEADROOM_BPS as u128)
            .map(|scaled| scaled.div_ceil(10_000))
            .ok_or_else(|| StrategyError::other(anyhow::anyhow!("the fee note headroom overflows")))
    }
}

/// A currency of a network as `GET /networks` lists it, reduced to what pricing a fee note needs.
#[derive(Clone, Debug, Deserialize)]
pub struct NetworkCurrency {
    pub symbol: String,
    /// USD price as a decimal string; `None` until the price refresher has seen the currency.
    pub price: Option<String>,
    pub decimals: u32,
    /// The vault token id, for the currencies the vault registers.
    #[serde(rename = "vaultTokenId")]
    pub vault_token_id: Option<String>,
    #[serde(rename = "nativeCurrency")]
    pub native_currency: bool,
}

/// A network as `GET /networks` lists it.
#[derive(Clone, Debug, Deserialize)]
pub struct NetworkInfo {
    pub slug: String,
    #[serde(rename = "chainId")]
    pub chain_id: String,
    pub currencies: Vec<NetworkCurrency>,
}

/// The gateway's `{data, error}` envelope around the network list.
#[derive(Deserialize)]
struct NetworksEnvelope {
    data: Option<Vec<NetworkInfo>>,
    error: Option<serde_json::Value>,
}

impl NetworksEnvelope {
    fn into_network(self, chain_id: u64) -> Result<NetworkInfo, RelayError> {
        let networks = self.data.ok_or_else(|| {
            RelayError::Transport(format!(
                "the gateway published no networks: {}",
                self.error
                    .map(|error| error.to_string())
                    .unwrap_or_else(|| "no error given".to_owned())
            ))
        })?;
        let wanted = chain_id.to_string();
        networks
            .into_iter()
            .find(|network| network.chain_id == wanted)
            .ok_or_else(|| RelayError::Rejected(format!("the gateway lists no network with chain id {chain_id}")))
    }
}

/// Headroom a relayer fee note carries over the converted quote, in basis points: doubled. See
/// [`PaymasterInfo::required_fee_in_token`].
pub const FEE_NOTE_HEADROOM_BPS: u64 = 10_000;

/// Decimal places the relayer scales USD prices to before integer arithmetic (`PRICE_DECIMALS`).
pub const PRICE_DECIMALS: u32 = 8;

/// A USD valuation the way the relayer's gas conversion carries it: the price scaled by
/// `10^PRICE_DECIMALS`, and the token's own decimals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenValuation {
    pub usd: U256,
    pub decimals: u32,
}

impl TokenValuation {
    pub fn of(currency: &NetworkCurrency) -> Result<Self, StrategyError> {
        let price = currency.price.as_deref().ok_or_else(|| {
            StrategyError::other(anyhow::anyhow!(
                "the gateway has no USD price for {} yet",
                currency.symbol
            ))
        })?;
        Ok(Self {
            usd: parse_usd_price(price)?,
            decimals: currency.decimals,
        })
    }
}

/// The native currency's and the fee token's valuations on `network`, for a fee note in
/// vault token `vault_token_id`.
pub fn fee_note_valuations(
    network: &NetworkInfo,
    vault_token_id: u64,
) -> Result<(TokenValuation, TokenValuation), StrategyError> {
    let native = network
        .currencies
        .iter()
        .find(|currency| currency.native_currency)
        .ok_or_else(|| {
            StrategyError::other(anyhow::anyhow!(
                "the gateway lists no native currency for {}",
                network.slug
            ))
        })?;
    let wanted = vault_token_id.to_string();
    let token = network
        .currencies
        .iter()
        .find(|currency| currency.vault_token_id.as_deref() == Some(wanted.as_str()))
        .ok_or_else(|| {
            StrategyError::other(anyhow::anyhow!(
                "the gateway lists no currency with vault token id {vault_token_id} on {}",
                network.slug
            ))
        })?;
    Ok((TokenValuation::of(native)?, TokenValuation::of(token)?))
}

/// `parseUsdPrice`: a decimal USD price string scaled to [`PRICE_DECIMALS`] places, extra
/// places truncated, the way the relayer parses the same string.
pub fn parse_usd_price(price: &str) -> Result<U256, StrategyError> {
    let trimmed = price.trim();
    let (whole, fraction) = trimmed.split_once('.').unwrap_or((trimmed, ""));
    let digits = |part: &str| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit());
    if !digits(whole) || !(fraction.is_empty() || digits(fraction)) {
        return Err(StrategyError::other(anyhow::anyhow!("malformed USD price {price:?}")));
    }
    let mut fraction = fraction.to_owned();
    fraction.truncate(PRICE_DECIMALS as usize);
    while fraction.len() < PRICE_DECIMALS as usize {
        fraction.push('0');
    }
    let parse = |part: &str| {
        U256::from_dec_str(part)
            .map_err(|error| StrategyError::other(anyhow::anyhow!("malformed USD price {price:?}: {error}")))
    };
    let scaled = parse(whole)? * U256::exp10(PRICE_DECIMALS as usize) + parse(&fraction)?;
    if scaled.is_zero() {
        return Err(StrategyError::other(anyhow::anyhow!(
            "non-positive USD price {price:?}"
        )));
    }
    Ok(scaled)
}

/// `convertTokenAmount`: `amount` of `from` in units of `to`, rounded up.
pub fn convert_token_amount(amount: u128, from: &TokenValuation, to: &TokenValuation) -> Result<u128, StrategyError> {
    if from.usd.is_zero() || to.usd.is_zero() {
        return Err(StrategyError::other(anyhow::anyhow!("token prices must be positive")));
    }
    let numerator = U256::from(amount) * from.usd * U256::exp10(to.decimals as usize);
    let denominator = U256::exp10(from.decimals as usize) * to.usd;
    let converted = (numerator + denominator - U256::one()) / denominator;
    u128::try_from(converted)
        .map_err(|_| StrategyError::other(anyhow::anyhow!("the converted fee note amount overflows u128")))
}

/// What the gateway publishes about the protocol as a whole at `GET /protocol`.
#[derive(Clone, Debug, Deserialize)]
pub struct ProtocolInfo {
    /// The protocol fee collector: one identity shared by every aggregator, the owner of each
    /// aggregator's `feeNotePublicKey`. `None` when the deployment names no collector, in which
    /// case only fee-free aggregations can be built.
    #[serde(rename = "feeCollector")]
    pub fee_collector: Option<CurvyPublicKeys>,
}

/// The gateway's `{data, error}` envelope around [`ProtocolInfo`].
#[derive(Deserialize)]
struct ProtocolEnvelope {
    data: Option<ProtocolInfo>,
    error: Option<serde_json::Value>,
}

impl ProtocolEnvelope {
    fn into_info(self) -> Result<ProtocolInfo, RelayError> {
        self.data.ok_or_else(|| {
            RelayError::Transport(format!(
                "the gateway published no protocol data: {}",
                self.error
                    .map(|error| error.to_string())
                    .unwrap_or_else(|| "no error given".to_owned())
            ))
        })
    }
}

/// Errors the relayer reports that a caller must distinguish.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    /// A previously assigned request id is no longer tracked; its proof may still land.
    #[error("the Curvy relayer no longer knows request {0}")]
    MissingRequest(String),
    #[error("the Curvy relayer denied access: {0}")]
    AccessDenied(String),
    #[error("the Curvy relayer rate limited the request: {0}")]
    RateLimited(String),
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
    Timeout {
        request_id: String,
        status: RelayStatus,
        transaction_hash: Option<String>,
        progressed: bool,
    },
}

impl RelayError {
    /// These errors permit replacement of a journalled aggregation over the same inputs.
    /// Neither one proves that an earlier copy of the proof cannot still land.
    pub fn permits_replacement(&self) -> bool {
        matches!(self, Self::MissingRequest(_) | Self::Rejected(_))
    }
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
        self.base_url.join(path).map_err(|error| {
            RelayError::Transport(format!("{path} is not a valid path under the relayer URL: {error}"))
        })
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

    /// The protocol-global facts: the fee collector an aggregation's protocol fee note is sealed
    /// to.
    pub async fn protocol(&self) -> Result<ProtocolInfo, RelayError> {
        let url = self.endpoint("/protocol")?;
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|error| RelayError::Transport(error.to_string()))?;
        Self::decode::<ProtocolEnvelope>(response).await?.into_info()
    }

    /// The network `chain_id` as the gateway describes it: its currencies with the USD prices
    /// the relayer converts gas into a fee-note amount with.
    pub async fn network(&self, chain_id: u64) -> Result<NetworkInfo, RelayError> {
        let url = self.endpoint("/networks")?;
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|error| RelayError::Transport(error.to_string()))?;
        Self::decode::<NetworksEnvelope>(response).await?.into_network(chain_id)
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
            return response
                .json::<RelaySubmission>()
                .await
                .map_err(|error| RelayError::Transport(format!("invalid relayer conflict response: {error}")));
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
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RelayError::MissingRequest(request_id.to_owned()));
        }
        Self::decode(response).await
    }

    /// The submission carrying `intent_id`, if the relayer ever received it.
    ///
    /// The recovery path for a lost `POST` response: the intent id is ours and journalled before
    /// submitting, so this answers "did my proof reach the relayer" without knowing its
    /// `requestId`. A `404` means it is not tracked, including requests the relayer forgot.
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
        let mut progressed = false;
        while started.elapsed() < deadline {
            tokio::time::sleep(POLL_INTERVAL).await;
            let mut next = self.status(&current.request_id).await?;
            progressed |= next.status != current.status
                || next
                    .transaction_hash
                    .as_ref()
                    .is_some_and(|hash| Some(hash) != current.transaction_hash.as_ref());
            next.transaction_hash = next.transaction_hash.or(current.transaction_hash);
            current = next;
            if current.status.is_terminal() {
                return Self::terminal(current);
            }
        }
        Err(RelayError::Timeout {
            request_id: current.request_id,
            status: current.status,
            transaction_hash: current.transaction_hash,
            progressed,
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
    /// Authentication and rate limits are not verdicts on the proof. Return them to the caller
    /// without triggering proof replacement; transport faults likewise leave the proof intact.
    async fn decode<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T, RelayError> {
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|error| RelayError::Transport(format!("reading the relayer's response: {error}")))?;
        if matches!(status.as_u16(), 401 | 403) {
            return Err(RelayError::AccessDenied(Self::describe(status, &body)));
        }
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(RelayError::RateLimited(Self::describe(status, &body)));
        }
        if status == reqwest::StatusCode::REQUEST_TIMEOUT {
            return Err(RelayError::Transport(Self::describe(status, &body)));
        }
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
            operator: CurvyPublicKeys {
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

    /// `GET /protocol` on Curvy staging, 2026-09-13, with the Gnosis aggregator's fee key.
    const STAGING_PROTOCOL: &str = r#"{"data":{"feeCollector":{"S":"98196467739045737361624042364526845165893723256538881225564237194894305749964.85819546747324778252702861357825104568382762224457080263515028979058114370157","V":"21579150582945393796432405977169743203548565927228117293904839000735742388195.2199873391156304912266865805931783414728595814770346143973990126650821750981","babyJubjubPublicKey":"6696655508272513187635510409223451359447854228192370110374659020120287021020.14667705991255323606553352965901746640607929945787383727539340760340072797708"},"proving":{}},"error":null}"#;

    #[test]
    fn the_fee_collector_is_read_out_of_the_protocol_envelope() -> anyhow::Result<()> {
        let info = serde_json::from_str::<ProtocolEnvelope>(STAGING_PROTOCOL)?.into_info()?;
        let collector = info.fee_collector.expect("staging names a fee collector");
        assert!(
            collector
                .bjj_public_key
                .starts_with("6696655508272513187635510409223451359447854228192370110374659020120287021020.")
        );
        assert!(
            collector
                .spend_public_key
                .starts_with("98196467739045737361624042364526845165893723256538881225564237194894305749964.")
        );
        assert!(
            collector
                .view_public_key
                .starts_with("21579150582945393796432405977169743203548565927228117293904839000735742388195.")
        );
        Ok(())
    }

    #[test]
    fn a_deployment_without_a_fee_collector_is_not_an_error() -> anyhow::Result<()> {
        let info =
            serde_json::from_str::<ProtocolEnvelope>(r#"{"data":{"feeCollector":null},"error":null}"#)?.into_info()?;
        assert!(info.fee_collector.is_none());
        Ok(())
    }

    #[test]
    fn a_protocol_error_envelope_is_reported_with_its_message() -> anyhow::Result<()> {
        let error = serde_json::from_str::<ProtocolEnvelope>(r#"{"data":null,"error":"protocol not configured"}"#)?
            .into_info()
            .expect_err("no data is an error");
        assert!(error.to_string().contains("protocol not configured"), "{error}");
        Ok(())
    }

    /// `GET /networks` on Curvy staging, 2026-09-13, reduced to the Gnosis entry.
    const STAGING_NETWORKS: &str = r#"{"data":[{"slug":"gnosis","chainId":"100","currencies":[{"id":39,"symbol":"XDAI","price":"1","decimals":18,"vaultTokenId":"1","nativeCurrency":true},{"id":40,"symbol":"WXHOPR","price":"0.011918","decimals":18,"vaultTokenId":"2","nativeCurrency":false},{"id":6,"symbol":"USDC","price":"0.9998271138189069","decimals":6,"vaultTokenId":null,"nativeCurrency":false}]}],"error":null}"#;

    #[test]
    fn usd_prices_are_scaled_to_eight_places_and_truncated() -> anyhow::Result<()> {
        assert_eq!(parse_usd_price("1")?, U256::from(100_000_000u64));
        assert_eq!(parse_usd_price("0.011918")?, U256::from(1_191_800u64));
        assert_eq!(parse_usd_price("0.9998271138189069")?, U256::from(99_982_711u64));
        assert!(parse_usd_price("0").is_err());
        assert!(parse_usd_price("1e3").is_err());
        Ok(())
    }

    #[test]
    fn the_fee_note_is_priced_in_the_vault_token_like_the_relayer_prices_it() -> anyhow::Result<()> {
        // 675 000 gas at 1 gwei is 6.75e14 wei of a $1 native; in a $0.50 six-decimal token
        // that is 6.75e14 * 1e8 * 1e6 / (1e18 * 0.5e8) = 1350 units.
        let native = TokenValuation {
            usd: parse_usd_price("1")?,
            decimals: 18,
        };
        let cheap = TokenValuation {
            usd: parse_usd_price("0.5")?,
            decimals: 6,
        };
        // ... and the note carries FEE_NOTE_HEADROOM_BPS on top: 2700.
        assert_eq!(
            paymaster("675000", "1000000000", 0).required_fee_in_token(&native, &cheap)?,
            2700
        );
        // Rounded up: one unit short would be refused by the gate.
        let odd = TokenValuation {
            usd: parse_usd_price("0.3")?,
            decimals: 6,
        };
        assert_eq!(paymaster("1", "1", 0).required_fee_in_token(&native, &odd)?, 2);
        // Staging's Gnosis numbers: the wxHOPR note is about 84x the native gas cost, doubled.
        let network = serde_json::from_str::<NetworksEnvelope>(STAGING_NETWORKS)?.into_network(100)?;
        let (native, wxhopr) = fee_note_valuations(&network, 2)?;
        assert_eq!(
            paymaster("675000", "1000000000", 0).required_fee_in_token(&native, &wxhopr)?,
            2 * 56637019634166807
        );
        Ok(())
    }

    #[test]
    fn fee_note_valuations_need_a_priced_native_and_token_currency() -> anyhow::Result<()> {
        let network = serde_json::from_str::<NetworksEnvelope>(STAGING_NETWORKS)?.into_network(100)?;
        assert!(fee_note_valuations(&network, 7).is_err(), "no such vault token");
        assert!(
            serde_json::from_str::<NetworksEnvelope>(STAGING_NETWORKS)?
                .into_network(1)
                .is_err()
        );
        let mut unpriced = network.clone();
        unpriced.currencies[1].price = None;
        assert!(
            fee_note_valuations(&unpriced, 2).is_err(),
            "an unpriced token cannot be converted"
        );
        Ok(())
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
        let submission: RelaySubmission =
            serde_json::from_str(r#"{"requestId":"abc","status":"included","transactionHash":"0xdeadbeef"}"#)?;
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
        assert_eq!(
            info.accepted_vault_token_ids.as_deref(),
            Some(["3".to_owned()].as_slice())
        );
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

/// Local HTTP fixtures exercise the actual reqwest boundary without external services.
#[cfg(test)]
pub(super) mod http_tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    pub struct Server {
        pub url: Url,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl Server {
        pub async fn new(
            handler: impl Fn(&str, serde_json::Value) -> Option<(u16, serde_json::Value)> + Send + 'static,
        ) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/", listener.local_addr().unwrap()).parse().unwrap();
            let task = tokio::spawn(async move {
                loop {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut input = Vec::new();
                    let (head_end, length) = loop {
                        let mut buffer = [0; 4096];
                        let n = socket.read(&mut buffer).await.unwrap();
                        if n == 0 {
                            break (input.len(), 0);
                        }
                        input.extend_from_slice(&buffer[..n]);
                        if let Some(end) = input.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&input[..end]);
                            let length = head
                                .lines()
                                .find_map(|line| {
                                    let (name, value) = line.split_once(':')?;
                                    name.eq_ignore_ascii_case("content-length")
                                        .then(|| value.trim().parse::<usize>().unwrap())
                                })
                                .unwrap_or(0);
                            break (end + 4, length);
                        }
                    };
                    while input.len() < head_end + length {
                        let mut buffer = [0; 4096];
                        let n = socket.read(&mut buffer).await.unwrap();
                        if n == 0 {
                            break;
                        }
                        input.extend_from_slice(&buffer[..n]);
                    }
                    let head = String::from_utf8_lossy(&input[..head_end]);
                    let path = head.split_whitespace().nth(1).unwrap_or("");
                    let body = serde_json::from_slice(&input[head_end..]).unwrap_or(serde_json::Value::Null);
                    if let Some((status, response)) = handler(path, body) {
                        let body = response.to_string();
                        let response = format!(
                            "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: \
                             {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    }
                }
            });
            Self { url, task }
        }
    }

    pub fn proof() -> curvy_abi::curvy_types::Groth16Proof {
        serde_json::from_value(serde_json::json!({"a":["1","2"],"b":[["3","4"],["5","6"]],"c":["7","8"]})).unwrap()
    }

    #[tokio::test]
    async fn status_errors_separate_lost_requests_from_access_and_transient_failures() -> anyhow::Result<()> {
        for code in [400, 401, 403, 404, 408, 410, 429, 503] {
            let server = Server::new(move |_, _| Some((code, serde_json::json!({"error":"test"})))).await;
            let client = RelayClient::new(server.url.clone(), Duration::from_secs(2))?;
            let error = client.status("saved-request").await.unwrap_err();
            assert_eq!(error.permits_replacement(), matches!(code, 400 | 404 | 410));
            match code {
                401 | 403 => assert!(matches!(error, RelayError::AccessDenied(_))),
                404 => {
                    assert!(matches!(error, RelayError::MissingRequest(_)));
                    assert!(client.by_intent("saved-intent", 100).await?.is_none());
                }
                429 => assert!(matches!(error, RelayError::RateLimited(_))),
                408 | 503 => assert!(matches!(error, RelayError::Transport(_))),
                _ => assert!(matches!(error, RelayError::Rejected(_))),
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn inclusion_timeout_reports_progress_and_preserves_transaction_hash() -> anyhow::Result<()> {
        let server = Server::new(|_, _| {
            Some((
                200,
                serde_json::json!({
                    "requestId":"saved", "status":"submitted"
                }),
            ))
        })
        .await;
        let client = RelayClient::new(server.url.clone(), Duration::from_secs(2))?;
        let error = client
            .await_inclusion(
                RelaySubmission {
                    request_id: "saved".into(),
                    status: RelayStatus::Submitting,
                    transaction_hash: Some("0xabc".into()),
                    error: None,
                },
                Duration::from_millis(1),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, RelayError::Timeout {
            status: RelayStatus::Submitted,
            transaction_hash: Some(ref hash),
            progressed: true,
            ..
        } if hash == "0xabc"));
        Ok(())
    }

    #[tokio::test]
    async fn conflicts_resume_existing_submissions() -> anyhow::Result<()> {
        for status in ["included", "queued"] {
            let server = Server::new(move |path, _| {
                Some(if path == "/relay/submit" {
                    (409, serde_json::json!({"requestId":"existing","status":status}))
                } else {
                    assert_eq!(path, "/relay/submission/existing/status");
                    (200, serde_json::json!({"requestId":"existing","status":"included"}))
                })
            })
            .await;
            let client = RelayClient::new(server.url.clone(), Duration::from_secs(2))?;
            let existing = client
                .submit(
                    curvy_abi::RelayAction::Aggregation,
                    100,
                    2,
                    &proof(),
                    &[],
                    "request",
                    "spend",
                    "intent",
                )
                .await?;
            assert_eq!(existing.request_id, "existing");
            assert!(
                client
                    .await_inclusion(existing, Duration::from_secs(5))
                    .await?
                    .status
                    .is_on_chain()
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn malformed_conflicts_remain_uncertain_and_other_client_errors_reject() -> anyhow::Result<()> {
        for code in [409, 400] {
            let server = Server::new(move |_, _| Some((code, serde_json::json!({"error":"bad request"})))).await;
            let client = RelayClient::new(server.url.clone(), Duration::from_secs(2))?;
            let error = client
                .submit(
                    curvy_abi::RelayAction::Aggregation,
                    100,
                    2,
                    &proof(),
                    &[],
                    "request",
                    "spend",
                    "intent",
                )
                .await
                .unwrap_err();
            if code == 409 {
                assert!(matches!(error, RelayError::Transport(_)));
            } else {
                assert!(matches!(error, RelayError::Rejected(_)));
            }
        }
        Ok(())
    }
}
