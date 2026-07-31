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
use crate::types::SignedAmount;

/// The largest decimal exponent this will expand.
///
/// Not a plausibility bound — a purely mechanical one. `1e2000000000` parses as
/// an `i32` exponent perfectly well and would then ask for a two-gigabyte string
/// of zeros before anything got the chance to refuse it. A satoshi is `1e-8` and
/// the chain's whole representable range tops out around `9.2e10`, so nothing
/// legitimate comes close to this.
const MAX_EXPONENT: i32 = 100;

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
///
/// **Exponent form is refused here**, and the line between this and
/// [`currency_coins`] is drawn where the *daemon* draws it, not where it felt
/// natural to draw it.
///
/// The first attempt split on intent — "a registration fee arriving as `1e2`
/// means something changed upstream, so refuse it" — and that reasoning is
/// sound for these fields. But it is a property of the **serializer**, not of
/// the field. The figures left here are chain policy, formatted exactly, and
/// cannot come out in exponent form. Everything read through
/// [`currency_coins`] comes off the double formatter, which emits `1e-8` for
/// one satoshi whenever the value is small enough — a fact rather than a
/// hypothetical: `estimateconversion` answers `"reservein":1e-8` and
/// `"netinputamount":1e-8` in the same reply as the figure this crate reads.
///
/// Guarding a double-formatted field strictly is therefore not caution, it is
/// an outage waiting for a small number. Anyone can send an address a
/// hundred-millionth of any token — dust, costing nothing — and
/// `getaddressbalance` then answers `1e-8` for it and fails *permanently* for
/// that wallet. Fail-closed, so not a fund loss, but a balance that never loads
/// again and that its owner cannot clear.
pub(crate) fn coins(raw: &RawValue, field: &'static str) -> Result<Amount, RpcError> {
    coins_bounded(raw, field, MAX_NATIVE_SATS)
}

/// An amount of an arbitrary currency, reported in **coins**.
///
/// Bounded by [`MAX_CURRENCY_SATS`], because a token's supply is its issuer's
/// choice and this crate cannot look it up. See that constant.
///
/// **Exponent form is accepted**, because every field that reaches this comes
/// off the daemon's double formatter — see [`expand_exponent`] for why that is
/// the line that matters and [`coins`] for the fields on the other side of it.
pub(crate) fn currency_coins(raw: &RawValue, field: &'static str) -> Result<Amount, RpcError> {
    let text = unquote(raw.get());
    match expand_exponent(text) {
        Some(plain) => {
            let expanded = RawValue::from_string(plain).map_err(|_| RpcError::LossyNumber {
                field,
                value: text.to_string(),
            })?;
            coins_bounded(&expanded, field, MAX_CURRENCY_SATS)
        }
        None => coins_bounded(raw, field, MAX_CURRENCY_SATS),
    }
}

fn coins_bounded(raw: &RawValue, field: &'static str, ceiling: u64) -> Result<Amount, RpcError> {
    // Some fields are quoted and some are bare, depending on the method.
    let text = unquote(raw.get());

    // Exponent form is refused *here*. See `coins` for which fields that is,
    // and why the line falls where it does.
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
    let text = unquote(raw.get());

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

/// Rewrite a decimal in exponent form as a plain decimal, **exactly**.
///
/// `"1e-8"` becomes `"0.00000001"`; `"3.9e-7"` becomes `"0.00000039"`. Returns
/// `None` for anything that is not exponent form, or whose exponent is beyond
/// [`MAX_EXPONENT`].
///
/// # Why this exists, given [`coins_bounded`] refuses exponents
///
/// That refusal was written for the fields it guards, and it is right there: an
/// `idregistrationfees` arriving as `1e2` means something changed and guessing
/// is not the answer. But it is not a statement about exponents being
/// *unreadable*. `getoffers`, `estimatefee` and `listcurrencies` emit `1e-8`,
/// `1e-6` and `3.9e-7` **routinely**, for ordinary values — `1e-8` is one
/// satoshi — and a reader that refuses them cannot read those methods at all.
///
/// The distinction that makes this safe is that shifting a decimal point in a
/// decimal string is a *lossless textual transform*, not a numeric conversion.
/// Nothing here parses a float, and nothing rounds. What comes out still goes
/// through [`Amount::from_coins_str`], so a sub-satoshi value like `1e-9` is
/// refused exactly as `0.000000001` would be — the expansion widens what can be
/// *spelled*, never what can be represented.
fn expand_exponent(text: &str) -> Option<String> {
    let (mantissa, exponent) = text.split_once(['e', 'E'])?;

    // `parse` accepts a leading `+`, which JSON permits in an exponent.
    let exponent: i32 = exponent.parse().ok()?;
    // `unsigned_abs`, not `abs`. `i32::MIN` has no positive counterpart, so
    // `abs()` panics in a debug build and — worse — **wraps back to `i32::MIN`**
    // in a release one, which is negative and therefore sails past this guard.
    // `1e-2147483648` is a legal JSON number token, so that path is reachable
    // from any money field: 15 bytes on the wire asking for a 2.1-billion-byte
    // string of zeros.
    if exponent.unsigned_abs() > MAX_EXPONENT.unsigned_abs() {
        return None;
    }

    // A leading `+` on the *mantissa* is refused, matching `coins_bounded`,
    // which would reject `+100` as well. JSON has no such number, so this is
    // only reachable through a quoted field, and reading it here while the
    // plain path refuses it would make the two spellings disagree.
    let (negative, mantissa) = match mantissa.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, mantissa),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if whole.is_empty() && fraction.is_empty() {
        return None;
    }
    if !whole
        .bytes()
        .chain(fraction.bytes())
        .all(|b| b.is_ascii_digit())
    {
        return None;
    }

    // Every digit, decimal point removed, and where the point now belongs.
    // `checked_add`, because a mantissa long enough to be near `i32::MAX` would
    // otherwise wrap the position and silently place the point somewhere else.
    let digits = format!("{whole}{fraction}");
    let point = i32::try_from(whole.len()).ok()?.checked_add(exponent)?;

    let shifted = if point <= 0 {
        let leading_zeros = usize::try_from(-point).ok()?;
        format!("0.{}{digits}", "0".repeat(leading_zeros))
    } else {
        let point = usize::try_from(point).ok()?;
        match point.checked_sub(digits.len()) {
            Some(trailing_zeros) => format!("{digits}{}", "0".repeat(trailing_zeros)),
            None => {
                let (left, right) = digits.split_at(point);
                format!("{left}.{right}")
            }
        }
    };

    Some(if negative {
        format!("-{shifted}")
    } else {
        shifted
    })
}

/// A **signed** amount in satoshis — what `getaddressdeltas` reports.
///
/// A delta is negative when the output is being spent, and that sign is the
/// whole point of the method: dropping it turns a payment out into a payment in.
pub(crate) fn signed_satoshis(
    raw: &RawValue,
    field: &'static str,
) -> Result<SignedAmount, RpcError> {
    let text = unquote(raw.get());
    let sats = text.parse::<i64>().map_err(|_| RpcError::LossyNumber {
        field,
        value: text.to_string(),
    })?;
    bounded_signed(SignedAmount::from_sat(sats), field, MAX_NATIVE_SATS)
}

/// A **signed** amount of an arbitrary currency in coins, exponent form
/// accepted.
///
/// `getaddressdeltas` reports `currencyvalues` this way: `-1.0` for the side
/// being spent, and `1e-8` is an ordinary one-satoshi entry.
pub(crate) fn signed_currency_coins(
    raw: &RawValue,
    field: &'static str,
) -> Result<SignedAmount, RpcError> {
    let text = unquote(raw.get());
    let (negative, magnitude) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let magnitude =
        RawValue::from_string(magnitude.to_string()).map_err(|_| RpcError::LossyNumber {
            field,
            value: text.to_string(),
        })?;
    let amount = currency_coins(&magnitude, field)?;

    let sats = i64::try_from(amount.to_sat())
        .map_err(|_| RpcError::OutOfRange(format!("{field}: {amount} coins does not fit")))?;
    Ok(SignedAmount::from_sat(if negative { -sats } else { sats }))
}

/// Refuse a signed amount whose **magnitude** is above `ceiling`.
fn bounded_signed(
    amount: SignedAmount,
    field: &'static str,
    ceiling: u64,
) -> Result<SignedAmount, RpcError> {
    if amount.magnitude().to_sat() > ceiling {
        return Err(RpcError::OutOfRange(format!(
            "{field}: {amount} coins exceeds the {}-coin ceiling this crate will believe",
            ceiling / verus_tx::SATS_PER_COIN
        )));
    }
    Ok(amount)
}

/// Strip the quotes off a field the daemon happened to quote.
///
/// For **numbers** that arrive quoted. Never for a string: this does no JSON
/// decoding, so an escape survives verbatim — use `serde_json::from_str` there.
pub(crate) fn unquote(text: &str) -> &str {
    let text = text.trim();
    let text = text.strip_prefix('"').unwrap_or(text);
    text.strip_suffix('"').unwrap_or(text)
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

    /// The literals that made this necessary, taken from live replies:
    /// `estimatefee` answers `1e-6`, `getoffers` prices legs at `1e-8`, and
    /// `listcurrencies` reports conversion fees as `2.5e-6`.
    #[test]
    fn the_exponent_forms_a_daemon_actually_sends_expand_exactly() {
        for (sent, expanded, sats) in [
            ("1e-8", "0.00000001", 1u64),
            ("1e-6", "0.000001", 100),
            ("2.5e-6", "0.0000025", 250),
            ("3.9e-7", "0.00000039", 39),
            ("1e2", "100", 100 * verus_tx::SATS_PER_COIN),
            ("1.5E+2", "150", 150 * verus_tx::SATS_PER_COIN),
        ] {
            assert_eq!(expand_exponent(sent).as_deref(), Some(expanded), "{sent}");
            assert_eq!(
                currency_coins(&raw(sent), "x").unwrap().to_sat(),
                sats,
                "{sent}"
            );
        }
    }

    /// The expansion widens what can be *spelled*, never what can be
    /// represented. A sub-satoshi value is refused in exponent form exactly as
    /// it is when written out.
    #[test]
    fn an_exponent_cannot_smuggle_in_a_sub_satoshi_amount() {
        assert_eq!(expand_exponent("1e-9").as_deref(), Some("0.000000001"));
        assert!(currency_coins(&raw("1e-9"), "x").is_err());
        assert!(currency_coins(&raw("0.000000001"), "x").is_err());
    }

    /// A plain decimal must reach the identical result by either reader, or the
    /// exponent path has become a second, divergent way to read money.
    #[test]
    fn plain_decimals_read_the_same_through_either_reader() {
        for text in ["0.1", "0.00000001", "1234.56789012", "100.0", "0"] {
            assert_eq!(expand_exponent(text), None, "{text} is not exponent form");
            assert_eq!(
                currency_coins(&raw(text), "x").unwrap(),
                Amount::from_coins_str(text).unwrap(),
                "{text}"
            );
        }
    }

    /// `1e2000000000` parses as an exponent perfectly well and would then ask
    /// for a two-gigabyte string of zeros. Refused before anything is built.
    ///
    /// `1e-2147483648` is the one that matters, and it is the reason the guard
    /// uses `unsigned_abs` rather than `abs`. `i32::MIN` has no positive
    /// counterpart: `abs()` panics in a debug build and **wraps back to
    /// `i32::MIN`** in a release one, where it is negative and so passes a
    /// `> MAX_EXPONENT` test unchallenged. Fifteen bytes on the wire then ask
    /// for a 2.1-gigabyte allocation. It is a legal JSON number token, so it
    /// reaches here from any money field a daemon fills.
    #[test]
    fn an_absurd_exponent_is_refused_rather_than_expanded() {
        for absurd in [
            "1e2000000000",
            "1e-2000000000",
            "1e-2147483648",
            "1e2147483647",
        ] {
            assert_eq!(expand_exponent(absurd), None, "{absurd}");
            assert!(currency_coins(&raw(absurd), "x").is_err(), "{absurd}");
        }
    }

    /// The boundary itself, so the guard cannot quietly drift to `>=`.
    #[test]
    fn the_exponent_bound_is_inclusive() {
        assert!(expand_exponent(&format!("1e-{MAX_EXPONENT}")).is_some());
        assert_eq!(expand_exponent(&format!("1e-{}", MAX_EXPONENT + 1)), None);
    }

    /// A full-precision double artifact — `3.0000000000000001e-06` — expands to
    /// more decimals than a satoshi has and is refused rather than rounded.
    /// Chosen behaviour: a value that cannot be represented exactly should fail
    /// loudly, not silently become `0.000003`.
    #[test]
    fn a_value_below_satoshi_precision_is_refused_not_rounded() {
        assert_eq!(
            expand_exponent("3.0000000000000001e-06").as_deref(),
            Some("0.0000030000000000000001")
        );
        assert!(currency_coins(&raw("3.0000000000000001e-06"), "x").is_err());

        // Even when the extra digits are all zeros and the value *is* exact.
        assert_eq!(
            expand_exponent("1.000000000e0").as_deref(),
            Some("1.000000000")
        );
        assert!(currency_coins(&raw("1.000000000e0"), "x").is_err());
    }

    /// A leading `+` is refused in either spelling, so the two cannot disagree.
    /// Only reachable through a quoted field — JSON has no such number.
    #[test]
    fn a_leading_plus_is_refused_the_same_way_in_both_spellings() {
        assert_eq!(expand_exponent("+1e2"), None);
        assert!(currency_coins(&raw(r#""+1e2""#), "x").is_err());
        assert!(currency_coins(&raw(r#""+100""#), "x").is_err());
    }

    /// The line between the two readers, asserted from both sides.
    ///
    /// It is drawn by **serializer**, not by field sentiment. The policy
    /// figures `coins` guards are formatted exactly by the daemon and cannot
    /// arrive in exponent form, so refusing one there still means something
    /// changed upstream. Every field `currency_coins` reads comes off the
    /// double formatter, which emits `1e-8` for a single satoshi as a matter of
    /// course.
    ///
    /// An earlier version of this change had `currency_coins` refusing too.
    /// That is the griefable case: `currencybalance` is read through it, so
    /// sending an address one hundred-millionth of any token — dust, free —
    /// would have made `getaddressbalance` fail permanently for that wallet.
    #[test]
    fn the_two_readers_split_on_which_formatter_produced_the_field() {
        assert!(matches!(
            coins(&raw("1e-8"), "idregistrationfees"),
            Err(RpcError::LossyNumber { .. })
        ));
        assert_eq!(
            currency_coins(&raw("1e-8"), "currencybalance")
                .expect("a dust token balance must not break the reply")
                .to_sat(),
            1
        );
    }

    /// The sign is the entire content of a spend row. Losing it turns money
    /// leaving an address into money arriving at it.
    #[test]
    fn a_delta_keeps_its_direction() {
        let out = signed_satoshis(&raw("-100000000"), "satoshis").unwrap();
        assert!(out.is_negative());
        assert_eq!(out.to_sat(), -100_000_000);
        assert_eq!(out.magnitude().to_sat(), 100_000_000);
        assert_eq!(out.to_coins_string(), "-1");

        let inflow = signed_satoshis(&raw("100000000"), "satoshis").unwrap();
        assert!(inflow.is_positive());
        assert_ne!(inflow, out);
    }

    /// A token leg is reported in coins and signed, and `-1.0` is the literal
    /// the live index returns for the spend side.
    #[test]
    fn a_signed_currency_value_reads_in_coins() {
        assert_eq!(
            signed_currency_coins(&raw("-1.0"), "currencyvalues")
                .unwrap()
                .to_sat(),
            -100_000_000
        );
        assert_eq!(
            signed_currency_coins(&raw("0.0999"), "currencyvalues")
                .unwrap()
                .to_sat(),
            9_990_000
        );
        // Exponent form, signed, one satoshi out.
        assert_eq!(
            signed_currency_coins(&raw("-1e-8"), "currencyvalues")
                .unwrap()
                .to_sat(),
            -1
        );
    }

    /// A magnitude past what the chain can represent is refused in either
    /// direction — the ceiling is on size, not on sign.
    #[test]
    fn a_signed_amount_is_bounded_in_both_directions() {
        assert!(signed_satoshis(&raw("-18446744073709551615"), "satoshis").is_err());
        assert!(signed_satoshis(&raw("18446744073709551615"), "satoshis").is_err());
        assert!(signed_currency_coins(&raw("-100000000000.0"), "currencyvalues").is_err());
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
