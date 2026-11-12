//! Client for Curvy's off-chain relayer: the node hands over a proof and the relayer puts it on
//! chain, paying gas and appearing as the sender.
//!
//! The node is then not a transaction sender at all for the two operations that would otherwise
//! link it to its deposits. What it still signs is the shield, which the relayer does not accept —
//! and, on a self-submitting deployment, its own note commitments.
//!
//! ### The shape of a submission
//!
//! `POST /relay/submit` takes the proof, the circuit family version it was made for, its calldata
//! words, and two derived keys. The words travel
//! in the `publicSignals` field: they are what the circuits exposed as public signals before the
//! calldata binding, and the relayer recomputes the proof's commitment to them. It answers immediately
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
//! its live gas quote — [`RelayClient::paymaster_quote`] is what prices it. A withdrawal carries none:
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
    ///
    /// ```
    /// # use hopr_strategy::pix::pools::curvy::relayer::{CurvyPublicKeys, PaymasterInfo};
    /// let quote = PaymasterInfo {
    ///     operator: CurvyPublicKeys {
    ///         spend_public_key: "1.2".into(),
    ///         view_public_key: "3.4".into(),
    ///         bjj_public_key: "5.6".into(),
    ///     },
    ///     accepted_vault_token_ids: None,
    ///     submit_aggregation_gas_units: "100000".into(),
    ///     gas_price_wei: "2".into(),
    ///     client_buffer_bps: 1_000,
    ///     relayer_tolerance_bps: 500,
    /// };
    /// // 100 000 gas at 2 wei, plus the operator's 10% client buffer.
    /// assert_eq!(quote.required_fee()?, 220_000);
    /// # Ok::<(), hopr_strategy::errors::StrategyError>(())
    /// ```
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
    /// the gas price and the prices when the proof arrives, tolerating only 5% of drift. That
    /// would be harmless if the quote were one number that drifted; on Gnosis it is not. The
    /// paymaster's `gasPriceWei` alternates between two modes roughly seven times apart — base
    /// fee alone (~15–25 wei) and base fee plus the chain's median tip (~113–125 wei) — and
    /// flips between them on consecutive requests, so the gate draws its own value from the
    /// same distribution the quote came from. A note sized to the quote plus a few percent is
    /// therefore rejected whenever the client drew the low mode and the gate the high one, which
    /// is about one first submission in four. The headroom covers the widest spread measured
    /// with a margin of about 1.3x — enough, but not several times over (see
    /// [`FEE_NOTE_HEADROOM_BPS`]); the note is worth a fraction of a cent, and its excess is the
    /// operator's, so erring far high is the cheap side of a re-proof.
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

    /// The lowest fee note the gate accepts if the proof arrives at `live_gas_price_wei`.
    ///
    /// The gate re-reads the gas price when the proof arrives and applies its own
    /// `relayer_tolerance_bps` downward. A note below this floor is refused outright, so this is
    /// what [`Self::required_fee_in_token`] has to clear — including the gas-price mode the
    /// quote did not land on.
    ///
    /// A model, not an oracle: the conversion rounds up here while the gate's own rounding is
    /// unknown, so this can over-estimate the threshold by less than one token unit. Against a
    /// note carrying nine times the quote that is irrelevant, but a caller should not treat a
    /// one-unit shortfall as a real rejection.
    ///
    /// It is also what the note has to clear, not what sizes it: production prices the note from
    /// [`FEE_NOTE_HEADROOM_BPS`] alone and never compares the two, which is why the constant has
    /// to be justified against the measured spread rather than against this function.
    pub fn gate_floor_in_token(
        &self,
        live_gas_price_wei: u128,
        native: &TokenValuation,
        token: &TokenValuation,
    ) -> Result<u128, StrategyError> {
        let units: u128 = self.submit_aggregation_gas_units.parse().map_err(|error| {
            StrategyError::other(anyhow::anyhow!("relayer quoted an unparseable gas unit count: {error}"))
        })?;
        let gas = units
            .checked_mul(live_gas_price_wei)
            .ok_or_else(|| StrategyError::other(anyhow::anyhow!("the live gas cost overflows")))?;
        let converted = convert_token_amount(gas, native, token)?;
        let allowed = 10_000u128.saturating_sub(self.relayer_tolerance_bps.min(10_000) as u128);
        converted
            .checked_mul(allowed)
            .map(|scaled| scaled / 10_000)
            .ok_or_else(|| StrategyError::other(anyhow::anyhow!("the gate floor overflows")))
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

/// Headroom a relayer fee note carries over the converted quote, in basis points.
///
/// The quote is drawn from the paymaster's gas-price view, which on Gnosis alternates between
/// two modes about seven times apart on consecutive requests (see
/// [`PaymasterInfo::required_fee_in_token`]); the gate then draws its own value from the same
/// distribution. The gate accepts a note down to `1 - tolerance` of its live gas cost, so a note
/// worth `m` times the quoted gas cost covers a live price up to `m / (1 - tolerance)` times the
/// quote. The widest spread measured is 8.33x (125 against 15 wei), which needs `m` of at least
/// `8.33 × 0.95 = 7.92`; the blocks of the four rejected submissions ranged 3.75x to 6.50x.
/// Doubling gave `m = 1.15 × 2 = 2.3` and covered only 2.42x, which is why roughly one first
/// submission in four was refused. 800% over the client buffer gives `m = 1.15 × 9 = 10.35`,
/// covering 10.89x after the gate's 5% allowance — a margin of about 1.3x over the worst case
/// (`10.89 / 8.33`), not a generous one.
pub const FEE_NOTE_HEADROOM_BPS: u64 = 80_000;

/// How many paymaster quotes to draw, keeping the highest, when pricing a fee note.
///
/// The quote is not a signed price, so the only defence against drawing the low gas-price mode
/// is redundancy: the high mode comes up about half the time, so four *independent* draws miss
/// it with probability `2^-4`. Independence is not something the client controls — a gateway
/// that answers identical requests from one cached or coalesced upstream read hands every draw
/// the same mode — so the draws ask caches not to answer them and start
/// [`FEE_QUOTE_DRAW_SPACING`] apart rather than at the same instant. They still overlap, so the
/// call costs one round trip plus the spacing, and the worst case is one request timeout plus
/// the spacing rather than one timeout per draw.
pub const FEE_QUOTE_SAMPLES: usize = 4;

/// How long after the previous paymaster draw the next one starts.
///
/// Identical requests sent at the same instant are the ones a gateway is most likely to merge
/// into one upstream read, which would make the draws one sample repeated. Spaced out, each draw
/// reaches the gateway on its own whenever the upstream read takes less than this, at a cost of
/// `(FEE_QUOTE_SAMPLES - 1)` times this much added latency — under a second against a deposit
/// budget of a minute.
pub const FEE_QUOTE_DRAW_SPACING: Duration = Duration::from_millis(200);

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
///
/// ```
/// # use hopr_strategy::pix::pools::curvy::relayer::parse_usd_price;
/// # use hopr_api::types::primitive::prelude::U256;
/// assert_eq!(parse_usd_price("0.05")?, U256::from(5_000_000_u64));
/// // Places beyond the eighth are truncated, not rounded.
/// assert_eq!(parse_usd_price("1.234567899")?, U256::from(123_456_789_u64));
/// assert!(parse_usd_price("0").is_err());
/// # Ok::<(), hopr_strategy::errors::StrategyError>(())
/// ```
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
///
/// ```
/// # use hopr_strategy::pix::pools::curvy::relayer::{TokenValuation, convert_token_amount, parse_usd_price};
/// let xdai = TokenValuation {
///     usd: parse_usd_price("1")?,
///     decimals: 18,
/// };
/// let wxhopr = TokenValuation {
///     usd: parse_usd_price("0.05")?,
///     decimals: 18,
/// };
/// // One xDai buys twenty wxHOPR.
/// assert_eq!(
///     convert_token_amount(10_u128.pow(18), &xdai, &wxhopr)?,
///     20 * 10_u128.pow(18)
/// );
/// // A fraction of a base unit rounds up, so a fee note never falls short of the gate.
/// let pricier = TokenValuation {
///     usd: parse_usd_price("3")?,
///     decimals: 18,
/// };
/// assert_eq!(convert_token_amount(1, &xdai, &pricier)?, 1);
/// # Ok::<(), hopr_strategy::errors::StrategyError>(())
/// ```
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

    /// How much the error says about the cause, low first, for picking which of several
    /// concurrent failures to report.
    ///
    /// A refusal (`Rejected`) or a denied credential is a verdict on the request and retrying
    /// changes nothing; a transport fault only says that one attempt did not get through. When
    /// several draws fail for different reasons, the verdict is the informative one — reporting a
    /// transport fault instead would have the caller retry an access failure as though it were
    /// transient.
    fn severity(&self) -> u8 {
        match self {
            Self::AccessDenied(_) | Self::Rejected(_) => 0,
            Self::RateLimited(_) => 1,
            Self::MissingRequest(_) => 2,
            Self::Failed(_) => 3,
            Self::Transport(_) => 4,
            Self::Timeout { .. } => 5,
        }
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
    ///
    /// This is a single draw of a gas price that flips between two modes, so it is the wrong
    /// thing to size a fee note from: use [`Self::paymaster_quote`] for that. The request asks
    /// caches not to answer it, so repeated calls each reach the paymaster.
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # use hopr_strategy::pix::pools::curvy::relayer::RelayClient;
    /// # async fn example() -> anyhow::Result<()> {
    /// let relay = RelayClient::new("https://api.curvy.box".parse()?, Duration::from_secs(10))?;
    /// match relay.paymaster(100).await? {
    ///     Some(quote) => println!("fee note of {} wei", quote.required_fee()?),
    ///     None => println!("this deployment takes aggregations without a fee note"),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn paymaster(&self, chain_id: u64) -> Result<Option<PaymasterInfo>, RelayError> {
        let url = self.endpoint(&format!("/relay/paymaster?chainId={chain_id}"))?;
        let response = self
            .http
            .get(url)
            .header(reqwest::header::CACHE_CONTROL, "no-cache")
            .header(reqwest::header::PRAGMA, "no-cache")
            .send()
            .await
            .map_err(|error| RelayError::Transport(error.to_string()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Self::decode(response).await.map(Some)
    }

    /// The paymaster terms to price a fee note from: [`Self::paymaster`], drawn
    /// [`FEE_QUOTE_SAMPLES`] times, keeping the quote with the highest required fee.
    ///
    /// The endpoint is not a signed quote — the gate re-prices when the proof arrives — and on
    /// Gnosis its gas price alternates between two modes about seven times apart on consecutive
    /// requests. One draw therefore lands low about half the time, and the note built from it is
    /// under the gate's floor whenever the gate then draws high: the first submission is refused
    /// with `operator note does not cover the gas cost`. Taking the highest of several draws
    /// makes that a `2^-FEE_QUOTE_SAMPLES` event rather than a coin flip, as far as the draws are
    /// independent (see [`FEE_QUOTE_SAMPLES`]).
    ///
    /// A draw that fails does not fail the call: any draw that returns a quote prices the note,
    /// and a warning names the draws that did not. A deployment without a paymaster (`404`) is
    /// reported as `Ok(None)` only when *every* draw says so. A stray `404` from a gateway edge
    /// next to a real quote is not taken as one: an aggregation built without the fee note is
    /// refused by a paymaster deployment after it has been proven. When no draw returns a quote
    /// and the others failed, the failure is reported instead, so the caller retries.
    ///
    /// The draws overlap, each starting [`FEE_QUOTE_DRAW_SPACING`] after the previous one, so the
    /// call costs one round trip plus the spacing however many are taken — which matters because
    /// a hung gateway would otherwise burn the deposit's whole tracking budget before the retry
    /// loop even saw an error.
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # use hopr_strategy::pix::pools::curvy::relayer::RelayClient;
    /// # async fn example() -> anyhow::Result<()> {
    /// let relay = RelayClient::new("https://api.curvy.box".parse()?, Duration::from_secs(10))?;
    /// match relay.paymaster_quote(100).await? {
    ///     Some(quote) => println!("fee note of {} wei", quote.required_fee()?),
    ///     None => println!("this deployment takes aggregations without a fee note"),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn paymaster_quote(&self, chain_id: u64) -> Result<Option<PaymasterInfo>, RelayError> {
        let draws = futures::future::join_all((0..FEE_QUOTE_SAMPLES).map(|draw| async move {
            // Staggered rather than simultaneous: identical requests sent at the same instant
            // are the likeliest to be answered from one upstream read.
            tokio::time::sleep(FEE_QUOTE_DRAW_SPACING * draw as u32).await;
            self.paymaster(chain_id).await
        }))
        .await;
        let mut best: Option<PaymasterInfo> = None;
        // Draws that answered `404`. Only a unanimous `404` means the deployment runs no
        // paymaster.
        let mut without_paymaster = 0_usize;
        // Every failed draw, kept so the reported error is the most informative one rather than
        // whichever happened to run last.
        let mut errors: Vec<RelayError> = Vec::new();
        for draw in draws {
            match draw {
                Ok(None) => without_paymaster += 1,
                Ok(Some(info)) => {
                    let higher = match &best {
                        None => true,
                        // A quote we cannot parse must not win by default; `required_fee`
                        // reports it, and a replacement quote may well be readable.
                        Some(current) => match (info.required_fee(), current.required_fee()) {
                            (Ok(candidate), Ok(incumbent)) => candidate > incumbent,
                            (Ok(_), Err(_)) => true,
                            (Err(_), _) => false,
                        },
                    };
                    if higher {
                        best = Some(info);
                    }
                }
                Err(error) => errors.push(error),
            }
        }
        if let Some(info) = best {
            if !errors.is_empty() || without_paymaster > 0 {
                // Not a failure — the note is priced from a real quote — but it is priced from
                // fewer draws than intended, so the chance that it missed the high gas-price mode
                // is higher, and the gateway is degrading. Worth seeing in production.
                tracing::warn!(
                    failed_draws = errors.len(),
                    without_paymaster,
                    samples = FEE_QUOTE_SAMPLES,
                    gas_price_wei = %info.gas_price_wei,
                    first_error = %errors.first().map(ToString::to_string).unwrap_or_default(),
                    "some paymaster quote draws failed; priced the fee note from those that succeeded"
                );
            }
            return Ok(Some(info));
        }
        if errors.is_empty() {
            // Every draw answered `404`: the deployment runs no paymaster.
            return Ok(None);
        }
        // Some draws may have said `404`, but the others failed rather than agreeing, so there
        // is no telling a deployment without a paymaster from a gateway having a bad moment.
        // Retrying is the safe side; building the aggregation without a fee note is not.
        let error = errors
            .into_iter()
            .min_by_key(RelayError::severity)
            .unwrap_or_else(|| RelayError::Transport("the paymaster quote was not drawn".to_owned()));
        Err(error)
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
    ///
    /// ```no_run
    /// # use hopr_strategy::pix::pools::curvy::relayer::{RelayClient, RelayError};
    /// # async fn relay(client: &RelayClient, request: &curvy_sdk::PixWithdrawalRequest) -> Result<(), RelayError> {
    /// let submission = client
    ///     .submit(
    ///         curvy_abi::RelayAction::Withdrawal,
    ///         100, // EVM chain id: Gnosis
    ///         request.max_inputs,
    ///         request.circuit, // the circuit family version the proof was made for
    ///         &request.proof,
    ///         &request.public_signals,
    ///         &request.request_key,
    ///         &request.spend_key,
    ///         "6f1c2a7e-0b9d-4e53-9a41-2d8c5b7f3e10", // the journalled intent id
    ///     )
    ///     .await?;
    /// # let _ = submission;
    /// # Ok(())
    /// # }
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub async fn submit(
        &self,
        action: curvy_abi::RelayAction,
        chain_id: u64,
        max_inputs: usize,
        circuit: curvy_abi::curvy_types::CircuitRef,
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
            "circuitFamily": circuit.family.as_str(),
            "circuitVersion": circuit.version,
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
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # use hopr_strategy::pix::pools::curvy::relayer::RelayClient;
    /// # async fn example() -> anyhow::Result<()> {
    /// let relay = RelayClient::new("https://api.curvy.box".parse()?, Duration::from_secs(10))?;
    /// let submitted = relay.status("request-id-from-submit").await?;
    /// let landed = relay.await_inclusion(submitted, Duration::from_secs(120)).await?;
    /// assert!(landed.status.is_on_chain());
    /// # Ok(())
    /// # }
    /// ```
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
        // ... and the note carries FEE_NOTE_HEADROOM_BPS on top: 1350 * 9.
        assert_eq!(
            paymaster("675000", "1000000000", 0).required_fee_in_token(&native, &cheap)?,
            12_150
        );
        // Rounded up: one unit short would be refused by the gate.
        let odd = TokenValuation {
            usd: parse_usd_price("0.3")?,
            decimals: 6,
        };
        assert_eq!(paymaster("1", "1", 0).required_fee_in_token(&native, &odd)?, 9);
        // Staging's Gnosis numbers: the wxHOPR note is about 84x the native gas cost, times the
        // headroom.
        let network = serde_json::from_str::<NetworksEnvelope>(STAGING_NETWORKS)?.into_network(100)?;
        let (native, wxhopr) = fee_note_valuations(&network, 2)?;
        let staging_quote = 56637019634166807_u128;
        assert_eq!(
            paymaster("675000", "1000000000", 0).required_fee_in_token(&native, &wxhopr)?,
            9 * staging_quote
        );
        Ok(())
    }

    /// The note covers the gas-price mode the quote missed, which is what the old doubling was
    /// short of on Gnosis: `1.15 × (1 + headroom)` against a mode ratio of up to 8.33x (125
    /// against 15 wei).
    #[test]
    fn the_fee_note_covers_the_other_gas_price_mode() -> anyhow::Result<()> {
        let network = serde_json::from_str::<NetworksEnvelope>(STAGING_NETWORKS)?.into_network(100)?;
        let (native, wxhopr) = fee_note_valuations(&network, 2)?;
        // The lowest quote the prod paymaster was observed to serve, and the highest the chain
        // was paying at the same moment.
        for (quote, live) in [(15_u128, 125_u128), (16, 118), (19, 114), (21, 120), (32, 131)] {
            let info = paymaster("675000", &quote.to_string(), 1_500);
            let note = info.required_fee_in_token(&native, &wxhopr)?;
            let floor = info.gate_floor_in_token(live, &native, &wxhopr)?;
            assert!(
                note >= floor,
                "a quote of {quote} wei cannot pay a gate that reads {live} wei: note {note} < floor {floor}"
            );
        }
        // And the coverage is a property of the constants, not of the token: the note is
        // 1.15 * (1 + headroom) the quoted gas cost. Held in hundredths so the truncation does
        // not hide the 10.35x behind a 10.
        let cover_hundredths = 11_500_u128 * (10_000 + FEE_NOTE_HEADROOM_BPS as u128) / 10_000 / 100;
        assert!(
            cover_hundredths >= 1_000,
            "covers {}.{:02}x the quoted gas cost",
            cover_hundredths / 100,
            cover_hundredths % 100
        );
        assert_eq!(cover_hundredths, 1_035, "1.15 x 9");
        Ok(())
    }

    /// The gate's own 5% allowance counts against us, so the covered ratio is the note over
    /// `(1 - tolerance)`.
    #[test]
    fn the_gate_floor_applies_its_tolerance_downward() -> anyhow::Result<()> {
        let native = TokenValuation {
            usd: parse_usd_price("1")?,
            decimals: 18,
        };
        let token = TokenValuation {
            usd: parse_usd_price("1")?,
            decimals: 18,
        };
        let info = paymaster("1000", "1", 0);
        // 1000 gas at 1 wei, less the 500 bps the relayer tolerates: 950.
        assert_eq!(info.gate_floor_in_token(1, &native, &token)?, 950);
        assert_eq!(info.gate_floor_in_token(0, &native, &token)?, 0);
        assert_eq!(
            paymaster("1000", "1", 0).required_fee_in_token(&native, &token)?,
            9_000,
            "the note is the quote times the headroom, with no client buffer"
        );
        Ok(())
    }

    #[test]
    fn the_covered_ratio_is_above_the_measured_gas_price_spread() -> anyhow::Result<()> {
        // Measured on the prod paymaster 2026-11-12: modes at 15-26 and 113-125 wei, a ratio of
        // 125/15 = 8.33. The gate accepts a note down to 95% of its live cost, so a note priced
        // at 15 wei must be worth at least 125 * 0.95 / 15 = 7.92x the quoted gas cost.
        let (quoted_wei, live_wei, tolerance_bps) = (15_u128, 125_u128, 500_u128);
        // In basis points of the quoted gas cost.
        let note_over_quote = |buffer_bps: u64, headroom_bps: u64| {
            (10_000 + buffer_bps) as u128 * (10_000 + headroom_bps) as u128 / 10_000
        };
        // `note >= floor`, with both sides in basis points of one wei of gas and no division.
        let clears = |note_bps: u128| note_bps * quoted_wei >= live_wei * (10_000 - tolerance_bps);
        assert_eq!(note_over_quote(1_500, FEE_NOTE_HEADROOM_BPS), 103_500, "1.15 x 9");
        assert!(clears(note_over_quote(1_500, FEE_NOTE_HEADROOM_BPS)));
        // The margin is the covered ratio over the measured one: 10.35 / 0.95 = 10.89x against
        // 8.33x, about 1.3x. Held in hundredths of the measured ratio.
        let margin_hundredths =
            note_over_quote(1_500, FEE_NOTE_HEADROOM_BPS) * quoted_wei * 100 / (live_wei * (10_000 - tolerance_bps));
        assert_eq!(margin_hundredths, 130, "about 1.3x over the widest spread measured");
        // The doubling this replaced did not: 2.3 / 0.95 = 2.42 < 8.33, so it only covered the
        // spread if the gate happened to draw a mode at most 2.42x the one that priced the note.
        assert!(!clears(note_over_quote(1_500, 10_000)));
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
    use std::sync::Arc;

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

    /// One request as the fixture read it.
    pub struct Request {
        pub path: String,
        /// The request line and headers, as sent.
        pub head: String,
        pub body: serde_json::Value,
    }

    impl Request {
        /// The value of header `name`, matched case-insensitively.
        pub fn header(&self, name: &str) -> Option<&str> {
            self.head.lines().skip(1).find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
            })
        }
    }

    async fn read_request(socket: &mut tokio::net::TcpStream) -> Request {
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
        let head = String::from_utf8_lossy(&input[..head_end]).into_owned();
        let path = head.split_whitespace().nth(1).unwrap_or("").to_owned();
        let body = serde_json::from_slice(&input[head_end..]).unwrap_or(serde_json::Value::Null);
        Request { path, head, body }
    }

    async fn respond(socket: &mut tokio::net::TcpStream, status: u16, response: serde_json::Value) {
        let body = response.to_string();
        let response = format!(
            "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: \
             close\r\n\r\n{body}",
            body.len()
        );
        let _ = socket.write_all(response.as_bytes()).await;
    }

    impl Server {
        /// Answers one connection at a time, in the order they were accepted.
        pub async fn new(
            handler: impl Fn(&str, serde_json::Value) -> Option<(u16, serde_json::Value)> + Send + 'static,
        ) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/", listener.local_addr().unwrap()).parse().unwrap();
            let task = tokio::spawn(async move {
                loop {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let request = read_request(&mut socket).await;
                    if let Some((status, response)) = handler(&request.path, request.body) {
                        respond(&mut socket, status, response).await;
                    }
                }
            });
            Self { url, task }
        }

        /// Answers every connection on its own task, so `handler` can hold one response back
        /// until other requests have arrived. Dropping the server cancels the requests still
        /// being held.
        pub async fn concurrent<F, Fut>(handler: F) -> Self
        where
            F: Fn(Request) -> Fut + Send + Sync + 'static,
            Fut: std::future::Future<Output = Option<(u16, serde_json::Value)>> + Send + 'static,
        {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/", listener.local_addr().unwrap()).parse().unwrap();
            let handler = Arc::new(handler);
            let task = tokio::spawn(async move {
                // Owned by the accept loop, so aborting it on drop aborts every connection too.
                let mut connections = tokio::task::JoinSet::new();
                loop {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let handler = handler.clone();
                    connections.spawn(async move {
                        let request = read_request(&mut socket).await;
                        if let Some((status, response)) = handler(request).await {
                            respond(&mut socket, status, response).await;
                        }
                    });
                }
            });
            Self { url, task }
        }
    }

    /// The paymaster's body as the prod gateway serves it, parameterised by the gas price.
    pub fn paymaster_body(gas_price_wei: &str) -> serde_json::Value {
        serde_json::json!({
            "operator":{"S":"1.2","V":"3.4","babyJubjubPublicKey":"5.6"},
            "acceptedVaultTokenIds":null,
            "submitAggregationGasUnits":"675000",
            "gasPriceWei":gas_price_wei,
            "clientBufferBps":1500,
            "relayerToleranceBps":500,
        })
    }

    /// The quote comes from one random draw of the paymaster's two-mode gas price, so a single
    /// draw is the low mode half the time and the note built from it falls under the gate's
    /// floor. Sampling must keep the highest of the draws instead.
    #[tokio::test]
    async fn the_fee_quote_keeps_the_highest_of_several_draws() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        // One high draw among three low ones, in whatever order the concurrent draws land: only
        // keeping the highest prices the note at 118. A single draw would be 16 three times in
        // four.
        let draws = Arc::new(AtomicUsize::new(0));
        let server = Server::new({
            let draws = draws.clone();
            move |path, _| {
                assert_eq!(path, "/relay/paymaster?chainId=100");
                let draw = draws.fetch_add(1, Ordering::SeqCst);
                let price = if draw + 1 == FEE_QUOTE_SAMPLES { "118" } else { "16" };
                Some((200, paymaster_body(price)))
            }
        })
        .await;
        let client = RelayClient::new(server.url.clone(), Duration::from_secs(2))?;
        let info = client.paymaster_quote(100).await?.expect("a paymaster is served");
        assert_eq!(info.gas_price_wei, "118", "the highest draw prices the note");
        assert_eq!(draws.load(Ordering::SeqCst), FEE_QUOTE_SAMPLES);
        Ok(())
    }

    /// The draws overlap, so a hung gateway costs one request timeout rather than one per draw.
    /// Sequential draws would spend `FEE_QUOTE_SAMPLES` × 30 s of a 60 s deposit budget before
    /// the retry loop saw any error at all.
    ///
    /// Checked without a clock: the server holds every answer until all `FEE_QUOTE_SAMPLES`
    /// draws have arrived, and only the first draw to arrive is quoted high. Overlapping draws
    /// are all answered, so the high quote wins. Draws one after another never get there: each
    /// waits on an answer that only a later draw can release, so all but the last time out, and
    /// the quote comes back low (or not at all). A slow runner can delay the answers but cannot
    /// change which ones arrive.
    #[tokio::test]
    async fn the_fee_quote_draws_run_concurrently() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let all_arrived = Arc::new(tokio::sync::Barrier::new(FEE_QUOTE_SAMPLES));
        let arrivals = Arc::new(AtomicUsize::new(0));
        let server = Server::concurrent({
            let arrivals = arrivals.clone();
            move |_| {
                let all_arrived = all_arrived.clone();
                let arrival = arrivals.fetch_add(1, Ordering::SeqCst);
                async move {
                    all_arrived.wait().await;
                    let price = if arrival == 0 { "118" } else { "16" };
                    Some((200, paymaster_body(price)))
                }
            }
        })
        .await;
        let client = RelayClient::new(server.url.clone(), Duration::from_secs(5))?;
        let info = client.paymaster_quote(100).await?.expect("a paymaster is served");
        assert_eq!(
            info.gas_price_wei, "118",
            "the first draw was answered, so every draw was in flight at once"
        );
        assert_eq!(arrivals.load(Ordering::SeqCst), FEE_QUOTE_SAMPLES);
        Ok(())
    }

    /// The draws are spaced out rather than fired at the same instant, and each asks caches not
    /// to answer it, so a gateway that merges or caches identical requests cannot hand every
    /// draw one upstream read. The spacing is checked as a lower bound only — a sleep never ends
    /// early, so no runner is too slow for it.
    #[tokio::test]
    async fn the_fee_quote_draws_are_spaced_out_and_bypass_caches() -> anyhow::Result<()> {
        let headers = Arc::new(std::sync::Mutex::new(Vec::new()));
        let server = Server::concurrent({
            let headers = headers.clone();
            move |request: Request| {
                headers.lock().unwrap().push((
                    request.header("cache-control").map(str::to_owned),
                    request.header("pragma").map(str::to_owned),
                ));
                async { Some((200, paymaster_body("118"))) }
            }
        })
        .await;
        let client = RelayClient::new(server.url.clone(), Duration::from_secs(5))?;
        let started = std::time::Instant::now();
        client.paymaster_quote(100).await?.expect("a paymaster is served");
        let elapsed = started.elapsed();
        let spread = FEE_QUOTE_DRAW_SPACING * (FEE_QUOTE_SAMPLES as u32 - 1);
        assert!(
            elapsed >= spread,
            "took {elapsed:?}; the last draw cannot start before {spread:?}"
        );
        let headers = headers.lock().unwrap().clone();
        assert_eq!(headers.len(), FEE_QUOTE_SAMPLES);
        for (cache_control, pragma) in headers {
            assert_eq!(cache_control.as_deref(), Some("no-cache"));
            assert_eq!(pragma.as_deref(), Some("no-cache"));
        }
        Ok(())
    }

    /// A draw that fails does not lose the ones that succeeded: the quote is what the note is
    /// built from, and a transport blip on one of four GETs is not a reason to re-prove.
    #[tokio::test]
    async fn a_failed_draw_does_not_discard_the_quote() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let draws = Arc::new(AtomicUsize::new(0));
        let server = Server::new({
            let draws = draws.clone();
            move |_, _| {
                let draw = draws.fetch_add(1, Ordering::SeqCst);
                Some(match draw {
                    0 => (200, paymaster_body("17")),
                    1 => (503, serde_json::json!({"error":"quote unavailable"})),
                    2 => (200, paymaster_body("19")),
                    _ => (200, paymaster_body("18")),
                })
            }
        })
        .await;
        let client = RelayClient::new(server.url.clone(), Duration::from_secs(2))?;
        let info = client.paymaster_quote(100).await?.expect("a paymaster is served");
        assert_eq!(info.gas_price_wei, "19", "the highest readable draw wins");
        Ok(())
    }

    /// With no paymaster (`404`) the answer is `Ok(None)`, not an error: a deployment without one
    /// accepts aggregations with no fee note, and that is not a failure to retry.
    #[tokio::test]
    async fn a_deployment_without_a_paymaster_prices_no_note() -> anyhow::Result<()> {
        let server = Server::new(|_, _| Some((404, serde_json::Value::Null))).await;
        let client = RelayClient::new(server.url.clone(), Duration::from_secs(2))?;
        assert!(client.paymaster_quote(100).await?.is_none());
        Ok(())
    }

    /// One `404` among real quotes is a gateway edge misrouting a draw, not a deployment without
    /// a paymaster. Taking it at its word would build the aggregation without a fee note, which
    /// the paymaster's gate refuses only after the proof has been paid for.
    #[tokio::test]
    async fn a_stray_404_does_not_drop_the_fee_note() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let draws = Arc::new(AtomicUsize::new(0));
        let server = Server::new({
            let draws = draws.clone();
            move |_, _| {
                let draw = draws.fetch_add(1, Ordering::SeqCst);
                Some(match draw {
                    0 => (404, serde_json::Value::Null),
                    1 => (200, paymaster_body("118")),
                    _ => (200, paymaster_body("16")),
                })
            }
        })
        .await;
        let client = RelayClient::new(server.url.clone(), Duration::from_secs(2))?;
        let info = client
            .paymaster_quote(100)
            .await?
            .expect("the other draws quoted a paymaster");
        assert_eq!(info.gas_price_wei, "118");
        assert_eq!(draws.load(Ordering::SeqCst), FEE_QUOTE_SAMPLES);
        Ok(())
    }

    /// A `404` next to failed draws proves nothing either way, so the failure is reported and
    /// retried rather than read as "no paymaster".
    #[tokio::test]
    async fn a_404_among_failed_draws_is_reported_as_the_failure() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let draws = Arc::new(AtomicUsize::new(0));
        let server = Server::new({
            let draws = draws.clone();
            move |_, _| {
                let draw = draws.fetch_add(1, Ordering::SeqCst);
                Some(match draw {
                    0 => (404, serde_json::Value::Null),
                    _ => (503, serde_json::json!({"error":"quote unavailable"})),
                })
            }
        })
        .await;
        let client = RelayClient::new(server.url.clone(), Duration::from_secs(2))?;
        let error = client
            .paymaster_quote(100)
            .await
            .expect_err("a lone 404 is not a verdict");
        assert!(matches!(error, RelayError::Transport(_)), "{error}");
        Ok(())
    }

    /// A verdict is reported over a transport fault when the draws disagree, so the caller does
    /// not retry an access failure as though it were transient. Requesting the lowest-severity
    /// error would report the 503, whose class retries inside the deposit budget instead of
    /// failing the allocation outright.
    #[tokio::test]
    async fn a_verdict_outranks_a_transport_fault_in_the_reported_error() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let draws = Arc::new(AtomicUsize::new(0));
        let server = Server::new({
            let draws = draws.clone();
            move |_, _| {
                let draw = draws.fetch_add(1, Ordering::SeqCst);
                Some(match draw {
                    0 => (401, serde_json::json!({"error":"denied"})),
                    _ => (503, serde_json::json!({"error":"quote unavailable"})),
                })
            }
        })
        .await;
        let client = RelayClient::new(server.url.clone(), Duration::from_secs(2))?;
        let error = client.paymaster_quote(100).await.expect_err("no draw succeeded");
        assert!(matches!(error, RelayError::AccessDenied(_)), "{error}");
        Ok(())
    }

    /// Every draw failing is still an error of the same class as the old single call, so the
    /// caller's retry handling is unchanged.
    #[tokio::test]
    async fn every_draw_failing_reports_the_relayer_error() -> anyhow::Result<()> {
        let server = Server::new(|_, _| Some((503, serde_json::json!({"error":"quote unavailable"})))).await;
        let client = RelayClient::new(server.url.clone(), Duration::from_secs(2))?;
        let error = client.paymaster_quote(100).await.expect_err("no draw succeeded");
        assert!(matches!(error, RelayError::Transport(_)), "{error}");
        assert!(error.to_string().contains("503"), "{error}");
        Ok(())
    }

    pub fn proof() -> curvy_abi::curvy_types::Groth16Proof {
        serde_json::from_value(serde_json::json!({"a":["1","2"],"b":[["3","4"],["5","6"]],"c":["7","8"]})).unwrap()
    }

    pub const PIX_1: curvy_abi::curvy_types::CircuitRef = curvy_abi::curvy_types::CircuitRef {
        family: curvy_abi::curvy_types::CircuitFamily::Pix,
        version: 1,
    };

    #[tokio::test]
    async fn submissions_name_their_circuit_version() -> anyhow::Result<()> {
        let server = Server::new(|path, body| {
            assert_eq!(path, "/relay/submit");
            assert_eq!(body["circuitFamily"], "pix");
            assert_eq!(body["circuitVersion"], 1);
            Some((200, serde_json::json!({"requestId":"queued", "status":"queued"})))
        })
        .await;
        let client = RelayClient::new(server.url.clone(), Duration::from_secs(2))?;
        let submission = client
            .submit(
                curvy_abi::RelayAction::Withdrawal,
                100,
                10,
                PIX_1,
                &proof(),
                &[],
                "request",
                "spend",
                "intent",
            )
            .await?;
        assert_eq!(submission.request_id, "queued");
        Ok(())
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
                    PIX_1,
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
                    PIX_1,
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
