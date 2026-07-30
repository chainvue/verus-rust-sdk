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

/// A ceiling on a **native** amount — a balance or a fee denominated in the
/// chain's own currency.
///
/// Verus's emission is asymptotic to roughly 83.5 million VRSC, so anything
/// near that is a plausible native balance. This sits two orders of magnitude
/// above it, which still catches the concrete failure it exists for: a node
/// answering `"balance": 18446744073709551615` (`u64::MAX` satoshis, ~184.4
/// billion coins), which parsed without a bound and handed a wallet UI a
/// fabricated ten-figure balance.
const MAX_NATIVE_SATS: u64 = 1_000_000_000 * verus_tx::SATS_PER_COIN;

/// A ceiling on an amount of **some other currency**.
///
/// Deliberately far looser than [`MAX_NATIVE_SATS`], and the difference is
/// load-bearing. A token's supply is whatever its issuer defined; supplies in
/// the billions of units are ordinary and consensus-legal, up to the ~92
/// billion coins the chain itself can represent, and this crate cannot look up
/// issuance before deciding whether to believe a number.
/// Bounding these fields at the native ceiling would make one address holding
/// a large-supply token fail its *entire* balance reply, and would make
/// `estimateconversion` refuse an answer the daemon gave happily.
///
/// So the bound here is what the chain itself can represent — `i64::MAX`
/// satoshis. That is not a plausibility check; it is a refusal to accept a
/// number no honest daemon could have meant, which is all this crate is in a
/// position to judge.
const MAX_CURRENCY_SATS: u64 = i64::MAX as u64;

/// Refuse an amount above `ceiling`, naming the field it came from.
fn bounded(amount: Amount, field: &'static str, ceiling: u64) -> Result<Amount, RpcError> {
    if amount.to_sat() > ceiling {
        return Err(RpcError::OutOfRange(format!(
            "{field}: {amount} coins exceeds the {}-coin ceiling this crate will believe",
            ceiling / verus_tx::SATS_PER_COIN
        )));
    }
    Ok(amount)
}

/// An amount of the chain's own currency, reported in **coins** — `100.0`.
///
/// Bounded by [`MAX_NATIVE_SATS`]. For an amount of some *other* currency use
/// [`currency_coins`], whose ceiling is far looser and deliberately so.
pub(crate) fn coins(raw: &RawValue, field: &'static str) -> Result<Amount, RpcError> {
    coins_bounded(raw, field, MAX_NATIVE_SATS)
}

/// An amount of an arbitrary currency, reported in **coins**.
///
/// Bounded by [`MAX_CURRENCY_SATS`], because a token's supply is its issuer's
/// choice and this crate cannot look it up. See that constant.
pub(crate) fn currency_coins(raw: &RawValue, field: &'static str) -> Result<Amount, RpcError> {
    coins_bounded(raw, field, MAX_CURRENCY_SATS)
}

fn coins_bounded(raw: &RawValue, field: &'static str, ceiling: u64) -> Result<Amount, RpcError> {
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

    let amount = Amount::from_coins_str(text).map_err(|_| RpcError::LossyNumber {
        field,
        value: text.to_string(),
    })?;
    bounded(amount, field, ceiling)
}

/// An amount of the chain's own currency, reported in **satoshis**.
pub(crate) fn satoshis(raw: &RawValue, field: &'static str) -> Result<Amount, RpcError> {
    let text = raw.get().trim();
    let text = text.strip_prefix('"').unwrap_or(text);
    let text = text.strip_suffix('"').unwrap_or(text);

    // A fractional satoshi is not a rounding question: the field is misread.
    let amount = text
        .parse::<u64>()
        .map(Amount::from_sat)
        .map_err(|_| RpcError::LossyNumber {
            field,
            value: text.to_string(),
        })?;
    bounded(amount, field, MAX_NATIVE_SATS)
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

    /// The concrete failure `MAX_NATIVE_SATS` exists for: `u64::MAX` satoshis
    /// parses cleanly as a number — nothing about it is malformed — but it is
    /// roughly 184.4 billion coins, more than two orders of magnitude past
    /// Verus's own asymptotic supply. Without a ceiling this becomes a wallet
    /// UI displaying a fabricated ten-figure balance.
    #[test]
    fn an_absurdly_large_satoshi_figure_is_refused() {
        match satoshis(&raw(&u64::MAX.to_string()), "balance") {
            Err(RpcError::OutOfRange(message)) => assert!(message.contains("balance")),
            other => panic!("expected OutOfRange, got {other:?}"),
        }
    }

    /// Same bound, reached through the coins reader instead of the satoshi
    /// one — both units funnel through the same ceiling.
    #[test]
    fn an_absurdly_large_coin_figure_is_refused() {
        assert!(matches!(
            coins(&raw("2000000000.0"), "idregistrationfees"),
            Err(RpcError::OutOfRange(_))
        ));
    }

    /// The ceiling has real headroom: an amount comfortably above Verus's own
    /// current supply, but still under the bound, must keep reading.
    #[test]
    fn a_large_but_plausible_amount_still_reads() {
        assert_eq!(
            coins(&raw("500000000.0"), "x").unwrap().to_sat(),
            500_000_000 * verus_tx::SATS_PER_COIN
        );
    }

    /// The two ceilings are not interchangeable, and the difference is the
    /// point: a ten-billion-unit token balance is ordinary and must read,
    /// while the same figure claimed as a NATIVE balance is not credible.
    ///
    /// Bounding per-currency fields at the native ceiling made one address
    /// holding a large-supply token fail its entire balance reply.
    #[test]
    fn a_large_token_balance_reads_where_the_same_native_figure_is_refused() {
        let ten_billion = "10000000000.0";
        assert!(
            currency_coins(&raw(ten_billion), "currencybalance").is_ok(),
            "a large-supply token balance must be readable"
        );
        assert!(
            coins(&raw(ten_billion), "balance").is_err(),
            "the same figure as a native balance is not credible"
        );
    }

    /// Neither ceiling accepts what no honest daemon could mean.
    #[test]
    fn both_ceilings_refuse_an_impossible_amount() {
        // u64::MAX satoshis — the concrete fabricated-balance case.
        assert!(satoshis(&raw("18446744073709551615"), "balance").is_err());
        // Above what the chain itself can represent, in either denomination.
        assert!(currency_coins(&raw("100000000000.0"), "currencybalance").is_err());
    }
}
