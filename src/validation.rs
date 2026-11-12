//! Validators shared by the strategies' configurations.

use hopr_api::types::primitive::prelude::HoprBalance;
use validator::ValidationError;

/// A balance that must move something: zero would make the setting a no-op, which is almost
/// certainly a misconfiguration rather than an intent.
pub(crate) fn validate_positive_balance(balance: &HoprBalance) -> Result<(), ValidationError> {
    if balance.is_zero() {
        return Err(ValidationError::new("must be greater than zero"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_balance_is_refused_and_any_other_is_not() {
        assert!(validate_positive_balance(&HoprBalance::zero()).is_err());
        assert!(validate_positive_balance(&HoprBalance::new_base(1)).is_ok());
    }
}
