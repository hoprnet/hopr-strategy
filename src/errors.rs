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
    /// - [`Self::GeneralError`] — a payload or input refused before anything was submitted.
    /// - [`Self::Other`] wrapping an error a pool classifies as fund-free; see `pix::pools`.
    ///
    /// [`Self::CriteriaNotSatisfied`] is deliberately **not** here. The two bundled pools mean
    /// different things by it: the plain pool raises it only before submitting, but the Curvy
    /// pool raises it for "no committed funding note", which `allocate_all` can report for a later
    /// chunk *after* an earlier chunk's aggregation was submitted. A pool that knows its own
    /// `CriteriaNotSatisfied` is pre-submission says so through
    /// [`Self::moved_no_funds_by_pool`].
    ///
    /// ```
    /// # use hopr_strategy::errors::StrategyError;
    /// use hopr_api::types::primitive::prelude::GeneralError;
    ///
    /// // A malformed payload is refused before anything is submitted.
    /// assert!(StrategyError::GeneralError(GeneralError::InvalidInput).moved_no_funds());
    /// // Ambiguous, so it stays counted by default.
    /// assert!(!StrategyError::CriteriaNotSatisfied.moved_no_funds());
    /// assert!(!StrategyError::other(anyhow::anyhow!("boom")).moved_no_funds());
    /// ```
    pub fn moved_no_funds(&self) -> bool {
        match self {
            Self::GeneralError(_) => true,
            // A pool that classifies its own errors puts them behind `Other`; ask it.
            Self::Other(error) => crate::pix::pools::error_moved_no_funds(error),
            _ => false,
        }
    }

    /// [`Self::moved_no_funds`], additionally accepting a `CriteriaNotSatisfied` the calling pool
    /// has established is pre-submission.
    ///
    /// Used by the plain pool only: its `CriteriaNotSatisfied` is raised by `deposit_once`'s
    /// affordability gate, before any transfer is built.
    pub fn moved_no_funds_pre_satisfied(&self) -> bool {
        matches!(self, Self::CriteriaNotSatisfied) || self.moved_no_funds()
    }
}

pub type Result<T> = std::result::Result<T, StrategyError>;
