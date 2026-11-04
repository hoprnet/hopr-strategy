use hopr_api::types::primitive::errors::GeneralError;
use thiserror::Error;

/// Enumerates all errors in this crate.
#[derive(Debug, Error)]
pub enum StrategyError {
    #[error("criteria to trigger the strategy were not satisfied")]
    CriteriaNotSatisfied,

    #[error("strategy could not perform action because action of the same type is on-going")]
    InProgress,

    /// Returned by every strategy builder — instead of panicking — when the
    /// configuration violates its declared constraints.
    ///
    /// ```
    /// # use hopr_strategy::errors::StrategyError;
    /// let err = StrategyError::InvalidConfiguration("sizing_mode: out of range".into());
    /// assert_eq!(
    ///     err.to_string(),
    ///     "invalid strategy configuration: sizing_mode: out of range"
    /// );
    /// ```
    #[error("invalid strategy configuration: {0}")]
    InvalidConfiguration(String),

    #[error("non-specific strategy error: {0}")]
    Other(anyhow::Error),

    #[error("HOPR error: {0}")]
    HoprError(anyhow::Error),

    #[error("lower-level error: {0}")]
    GeneralError(#[from] GeneralError),
}

impl StrategyError {
    pub fn other<E: Into<anyhow::Error>>(e: E) -> Self {
        StrategyError::Other(e.into())
    }

    /// Validate a strategy configuration, mapping a constraint violation to
    /// [`Self::InvalidConfiguration`]. Every builder runs this; config loaders can
    /// call it to fail early with the same error.
    ///
    /// ```
    /// # use hopr_strategy::errors::StrategyError;
    /// use validator::Validate;
    ///
    /// #[derive(Validate)]
    /// struct Cfg {
    ///     #[validate(range(min = 1, max = 3))]
    ///     hops: u32,
    /// }
    ///
    /// assert!(StrategyError::validate_config(&Cfg { hops: 3 }).is_ok());
    /// assert!(StrategyError::validate_config(&Cfg { hops: 0 }).is_err());
    /// ```
    pub fn validate_config<C: validator::Validate>(cfg: &C) -> Result<()> {
        cfg.validate()
            .map_err(|e| StrategyError::InvalidConfiguration(e.to_string()))
    }

    /// Whether a failed deposit carrying this error provably moved no funds.
    ///
    /// The PIX strategy reserves each deposit against
    /// [`max_spend_per_window`](crate::pix::strategy::PixStrategyConfig::max_spend_per_window)
    /// before it settles, and hands the reservation back only when the pool says the failure
    /// cannot have spent anything. That distinction matters because a pool retries internally and
    /// re-reads the destination balance precisely because a transfer reported as failed may still
    /// have landed — so an ambiguous outcome must stay counted, and this answers `false` for
    /// anything but a refusal that provably precedes settlement.
    ///
    /// The concrete cases:
    ///
    /// - [`Self::GeneralError`] `InvalidInput` — a payload the pool refused before submitting.
    ///   The other `GeneralError` variants carry no such guarantee and stay counted.
    /// - [`Self::Other`] wrapping an error a pool classifies as fund-free; see `pix::pools`. This
    ///   is how a pool says so for an error whose class it can only decide itself, such as the
    ///   plain pool's retrying affordability gate.
    ///
    /// [`Self::CriteriaNotSatisfied`] is deliberately **not** here. It is a plain "the criteria
    /// were not met", and the pools raise it in both directions: the plain pool from its
    /// pre-transfer gate, the Curvy pool for "no committed funding note", which `allocate_all`
    /// can report for a later chunk *after* an earlier one was submitted.
    ///
    /// ```
    /// # use hopr_strategy::errors::StrategyError;
    /// use hopr_api::types::primitive::prelude::GeneralError;
    ///
    /// // A malformed payload is refused before anything is submitted.
    /// assert!(StrategyError::GeneralError(GeneralError::InvalidInput).moved_no_funds());
    /// // Ambiguous, so it stays counted by default.
    /// assert!(!StrategyError::GeneralError(GeneralError::NonSpecificError("boom".into())).moved_no_funds());
    /// assert!(!StrategyError::CriteriaNotSatisfied.moved_no_funds());
    /// assert!(!StrategyError::other(anyhow::anyhow!("boom")).moved_no_funds());
    /// ```
    pub fn moved_no_funds(&self) -> bool {
        match self {
            Self::GeneralError(GeneralError::InvalidInput) => true,
            // A pool that classifies its own errors puts them behind `Other`; ask it.
            #[cfg(feature = "strategy-pix")]
            Self::Other(error) => crate::pix::pools::error_moved_no_funds(error),
            _ => false,
        }
    }
}

pub type Result<T> = std::result::Result<T, StrategyError>;
