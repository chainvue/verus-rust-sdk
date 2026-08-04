//! Money, in a type that will not silently become something else.
//!
//! Every amount in this crate is satoshis — 1e-8 of a coin — and every one used
//! to be a bare `u64`. That is enough to build a transaction and not enough to
//! stop a caller handing whole coins to a function expecting satoshis, or a fee
//! to a parameter expecting a value. Both compile, both sign, and the mistake
//! surfaces as money that went somewhere unintended.
//!
//! [`Amount`] is a wrapper with no arithmetic operators. Addition and
//! subtraction exist only in checked form, so a sum that overflows or a
//! difference that would go negative is a `None` the caller has to handle rather
//! than a wrap-around that produces a plausible, wrong transaction. Wrapping in
//! release mode is the specific failure this prevents: Rust only panics on
//! overflow in debug builds, and a wallet ships in release.
//!
//! # Converting
//!
//! [`Amount::from_coins_str`] parses a decimal string exactly — no floats
//! anywhere. `0.1 + 0.2` in binary floating point is not `0.3`, and money that
//! is off by one satoshi is money that fails a conservation check at best and
//! is lost at worst.

use core::fmt;

use crate::error::TxError;

/// Satoshis: 1e-8 of a coin.
///
/// Deliberately has no `Add`, `Sub` or `Mul` — see the module docs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Amount(u64);

/// Satoshis in one coin.
pub const SATS_PER_COIN: u64 = 100_000_000;

impl Amount {
    /// Nothing.
    pub const ZERO: Amount = Amount(0);

    /// From a raw satoshi count.
    pub const fn from_sat(satoshis: u64) -> Self {
        Amount(satoshis)
    }

    /// The raw satoshi count, for the wire format and for arithmetic this type
    /// deliberately does not offer.
    pub const fn to_sat(self) -> u64 {
        self.0
    }

    /// Whether this is zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Sum, or `None` on overflow.
    #[must_use]
    pub fn checked_add(self, other: Amount) -> Option<Amount> {
        self.0.checked_add(other.0).map(Amount)
    }

    /// Difference, or `None` if it would go negative.
    ///
    /// Money cannot be negative, so an underflow here is always a bug in the
    /// caller's accounting rather than a value to represent.
    #[must_use]
    pub fn checked_sub(self, other: Amount) -> Option<Amount> {
        self.0.checked_sub(other.0).map(Amount)
    }

    /// Multiply by a count — a per-item fee, a referral payout repeated.
    #[must_use]
    pub fn checked_mul(self, factor: u64) -> Option<Amount> {
        self.0.checked_mul(factor).map(Amount)
    }

    /// Sum a sequence, or `None` on overflow.
    pub fn checked_sum(amounts: impl IntoIterator<Item = Amount>) -> Option<Amount> {
        amounts
            .into_iter()
            .try_fold(Amount::ZERO, Amount::checked_add)
    }

    /// Parse a decimal coin string — `"1.5"`, `"0.00000001"`, `"100"` — exactly.
    ///
    /// No floating point is involved at any point. Rejects more than eight
    /// decimal places rather than rounding, because silently discarding a
    /// satoshi is how a conservation check fails much later, somewhere else.
    pub fn from_coins_str(text: &str) -> Result<Self, TxError> {
        let invalid = || TxError::InvalidAmount(text.to_string());
        let text = text.trim();
        if text.is_empty() || text.starts_with('-') || text.starts_with('+') {
            return Err(invalid());
        }
        let (whole, fraction) = match text.split_once('.') {
            Some((whole, fraction)) => (whole, fraction),
            None => (text, ""),
        };
        if whole.is_empty() && fraction.is_empty() {
            return Err(invalid());
        }
        if !whole.chars().all(|c| c.is_ascii_digit())
            || !fraction.chars().all(|c| c.is_ascii_digit())
            || fraction.len() > 8
        {
            return Err(invalid());
        }
        let whole: u64 = if whole.is_empty() {
            0
        } else {
            whole.parse().map_err(|_| invalid())?
        };
        // Right-pad to eight places: "1.5" is 50_000_000 satoshis, not 5.
        let mut fraction_sats: u64 = if fraction.is_empty() {
            0
        } else {
            fraction.parse().map_err(|_| invalid())?
        };
        for _ in fraction.len()..8 {
            fraction_sats = fraction_sats.checked_mul(10).ok_or_else(invalid)?;
        }
        whole
            .checked_mul(SATS_PER_COIN)
            .and_then(|sats| sats.checked_add(fraction_sats))
            .map(Amount)
            .ok_or_else(invalid)
    }

    /// The decimal coin string, with no trailing zeros beyond the point.
    pub fn to_coins_string(self) -> String {
        let whole = self.0 / SATS_PER_COIN;
        let fraction = self.0 % SATS_PER_COIN;
        if fraction == 0 {
            return whole.to_string();
        }
        let fraction = format!("{fraction:08}");
        format!("{whole}.{}", fraction.trim_end_matches('0'))
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_coins_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decimal_coins_exactly() {
        for (text, sats) in [
            ("0", 0u64),
            ("1", 100_000_000),
            ("1.5", 150_000_000),
            ("0.00000001", 1),
            ("100", 10_000_000_000),
            ("0.1", 10_000_000),
            (".5", 50_000_000),
            ("1500.00000000", 150_000_000_000),
        ] {
            assert_eq!(
                Amount::from_coins_str(text).unwrap().to_sat(),
                sats,
                "{text}"
            );
        }
    }

    /// The float trap this exists to avoid: 0.1 + 0.2 is not 0.3 in binary
    /// floating point, and (0.1_f64 * 1e8) does not round to 10_000_000 on
    /// every value. Exact decimal parsing has no such cases.
    #[test]
    fn a_tenth_of_a_coin_is_exactly_ten_million_satoshis() {
        assert_eq!(Amount::from_coins_str("0.1").unwrap().to_sat(), 10_000_000);
        assert_eq!(Amount::from_coins_str("0.2").unwrap().to_sat(), 20_000_000);
        let sum = Amount::from_coins_str("0.1")
            .unwrap()
            .checked_add(Amount::from_coins_str("0.2").unwrap())
            .unwrap();
        assert_eq!(sum, Amount::from_coins_str("0.3").unwrap());
    }

    /// Rounding away a satoshi is how a conservation check fails later,
    /// somewhere else. Refuse instead.
    #[test]
    fn refuses_more_precision_than_a_satoshi() {
        assert!(Amount::from_coins_str("0.000000001").is_err());
    }

    #[test]
    fn refuses_things_that_are_not_amounts() {
        for text in ["", "-1", "+1", "1.2.3", "abc", "1e8", " ", "1 000"] {
            assert!(Amount::from_coins_str(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn round_trips_through_the_decimal_string() {
        for sats in [0u64, 1, 12_345_678, 100_000_000, 150_000_000_000, u64::MAX] {
            let amount = Amount::from_sat(sats);
            assert_eq!(
                Amount::from_coins_str(&amount.to_coins_string()).unwrap(),
                amount,
                "{sats}"
            );
        }
    }

    /// Release builds do not panic on overflow, they wrap — which would turn a
    /// huge total into a small one and produce a transaction that looks funded.
    #[test]
    fn overflow_is_none_rather_than_a_wrap() {
        assert_eq!(
            Amount::from_sat(u64::MAX).checked_add(Amount::from_sat(1)),
            None
        );
        assert_eq!(Amount::from_sat(u64::MAX).checked_mul(2), None);
    }

    /// Money cannot be negative; an underflow is an accounting bug.
    #[test]
    fn underflow_is_none() {
        assert_eq!(Amount::ZERO.checked_sub(Amount::from_sat(1)), None);
    }

    #[test]
    fn sums_a_sequence_and_reports_overflow() {
        let amounts = [
            Amount::from_sat(1),
            Amount::from_sat(2),
            Amount::from_sat(3),
        ];
        assert_eq!(Amount::checked_sum(amounts), Some(Amount::from_sat(6)));
        assert_eq!(
            Amount::checked_sum([Amount::from_sat(u64::MAX), Amount::from_sat(1)]),
            None
        );
    }

    #[test]
    fn displays_as_coins() {
        assert_eq!(Amount::from_sat(150_000_000).to_string(), "1.5");
        assert_eq!(Amount::from_sat(1).to_string(), "0.00000001");
        assert_eq!(Amount::from_sat(0).to_string(), "0");
    }
}
