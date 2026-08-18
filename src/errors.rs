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
}

pub type Result<T> = std::result::Result<T, StrategyError>;
