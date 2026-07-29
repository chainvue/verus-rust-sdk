//! Reading money out of JSON without going through a float.
//!
//! A daemon reports amounts two different ways, and mixing them up is a
//! fund-losing bug rather than a formatting one:
//!
//! ```text
//! getcurrency.idregistrationfees   100.0          COINS
//! getaddressutxos[].satoshis       10000000000    SATOSHIS
//! ```
//!
//! So there are two types here and no conversion between them. A single
//! "amount" type covering both is exactly the confusion `Amount` was introduced
//! to prevent.
//!
//! # No floats, ever
//!
//! `100.0` cannot be read as `f64` and multiplied by `1e8` — that is the float
//! path this workspace bans, and it is wrong for values a daemon can legally
//! report. Instead the original token text is kept with `serde_json`'s
//! `RawValue` and handed to [`Amount::from_coins_str`], which is exact.
//!
//! `RawValue` is used rather than `arbitrary_precision` deliberately: the latter
//! is a **global, non-additive** feature that changes `Number` semantics for
//! every crate in a consumer's build and breaks `#[serde(flatten)]` in unrelated
//! code. `raw_value` adds a type and changes nothing else.

use serde_json::value::RawValue;
use verus_tx::Amount;

use crate::error::RpcError;

/// An amount the daemon reported in **coins** — `100.0`.
pub(crate) fn coins(raw: &RawValue, field: &'static str) -> Result<Amount, RpcError> {
    let text = raw.get().trim();
    // Some fields are quoted and some are bare, depending on the method.
    let text = text.strip_prefix('"').unwrap_or(text);
    let text = text.strip_suffix('"').unwrap_or(text);

    // Exponent form would need expanding, and expanding it is guessing about a
    // value that is money. Refuse instead.
    if text.contains(['e', 'E']) {
        return Err(RpcError::LossyNumber {
            field,
            value: text.to_string(),
        });
    }

    Amount::from_coins_str(text).map_err(|_| RpcError::LossyNumber {
        field,
        value: text.to_string(),
    })
}

/// An amount the daemon reported in **satoshis** — `10000000000`.
pub(crate) fn satoshis(raw: &RawValue, field: &'static str) -> Result<Amount, RpcError> {
    let text = raw.get().trim();
    let text = text.strip_prefix('"').unwrap_or(text);
    let text = text.strip_suffix('"').unwrap_or(text);

    // A fractional satoshi is not a rounding question: the field is misread.
    text.parse::<u64>()
        .map(Amount::from_sat)
        .map_err(|_| RpcError::LossyNumber {
            field,
            value: text.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(text: &str) -> Box<RawValue> {
        RawValue::from_string(text.to_string()).expect("raw")
    }

    /// The literal a daemon actually sends for a 100-coin registration fee.
    #[test]
    fn reads_the_registration_fee_the_daemon_reports() {
        assert_eq!(
            coins(&raw("100.0"), "idregistrationfees").unwrap(),
            Amount::from_sat(100_00000000)
        );
    }

    /// The whole reason this module exists: the coin figure and the satoshi
    /// figure for the same fee are different numbers, and reading one as the
    /// other funds a transaction wrongly by a factor of 1e8.
    #[test]
    fn coins_and_satoshis_are_not_interchangeable() {
        let as_coins = coins(&raw("100.0"), "fee").unwrap();
        let as_sats = satoshis(&raw("100"), "fee").unwrap();
        assert_ne!(as_coins, as_sats);
        assert_eq!(as_coins.to_sat(), 100_00000000);
        assert_eq!(as_sats.to_sat(), 100);
    }

    /// Values that a float round-trip would corrupt.
    #[test]
    fn awkward_decimals_stay_exact() {
        for (text, sats) in [
            ("0.1", 10_000_000u64),
            ("0.00000001", 1),
            ("1234.56789012", 123_456_789_012),
            ("0.3", 30_000_000),
        ] {
            assert_eq!(coins(&raw(text), "x").unwrap().to_sat(), sats, "{text}");
        }
    }

    /// Expanding an exponent is guessing about money. Refuse.
    #[test]
    fn exponent_form_is_refused_rather_than_expanded() {
        assert!(matches!(
            coins(&raw("1e-8"), "fee"),
            Err(RpcError::LossyNumber { .. })
        ));
    }

    #[test]
    fn a_fractional_satoshi_is_refused() {
        assert!(matches!(
            satoshis(&raw("100.5"), "satoshis"),
            Err(RpcError::LossyNumber { .. })
        ));
    }

    #[test]
    fn quoted_and_bare_both_read() {
        assert_eq!(coins(&raw(r#""1.5""#), "x").unwrap().to_sat(), 150_000_000);
        assert_eq!(satoshis(&raw(r#""42""#), "x").unwrap().to_sat(), 42);
    }

    #[test]
    fn a_negative_amount_is_refused() {
        assert!(coins(&raw("-1.0"), "x").is_err());
        assert!(satoshis(&raw("-1"), "x").is_err());
    }
}
