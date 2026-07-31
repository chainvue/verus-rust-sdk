//! Coins and satoshis, converted exactly.
//!
//! A chain amount is an integer number of satoshis. A human types coins. In
//! JavaScript the usual bridge between them is `Math.round(coins * 1e8)`, and
//! it is worth being exact about where that fails, because the common telling
//! is wrong: for ordinary amounts it is *fine*. `1.1 * 1e8` really is
//! `110000000.0000000149`, but rounding recovers the satoshi.
//!
//! It fails on **magnitude**. A float64 carries 53 bits of mantissa, so no
//! satoshi count above `2^53` survives it: `90071992.54740993` coins scales to
//! `9007199254740994`, one satoshi more than the truth, and reading
//! `9007199254740993` back into a `number` gives `…992`. Ninety million coins
//! is not a hypothetical on a chain whose supply cap is 83.5 million, and a
//! currency's own supply can be anything its issuer chose.
//!
//! So the conversion happens here, on decimal strings, with no float anywhere
//! in it — and amounts leave this API as strings for the same reason.

use wasm_bindgen::prelude::*;

use crate::dto;
use crate::error::{WasmError, WasmResult};
use crate::types::JsText;

/// Coins to satoshis. Host-testable core of [`parse_coins`].
pub(crate) fn coins_to_sats(coins: &str) -> WasmResult<String> {
    // `Amount::from_coins_str` trims, and `dto::sats` explicitly refuses
    // whitespace. Two entry points for money should not disagree about what a
    // valid amount looks like, so the stricter rule wins here too.
    if coins.trim() != coins {
        return Err(WasmError::new(
            "InvalidAmount",
            format!("{coins:?} has leading or trailing whitespace"),
        ));
    }
    Ok(dto::sats_string(
        verus_tx::Amount::from_coins_str(coins).map_err(WasmError::from)?,
    ))
}

/// Satoshis to coins. Host-testable core of [`format_coins`].
pub(crate) fn sats_to_coins(satoshis: &str) -> WasmResult<String> {
    Ok(dto::sats(satoshis)?.to_coins_string())
}

/// Convert a decimal amount of coins to satoshis.
///
/// Both sides are strings: the input because `0.1` is not exactly
/// representable as a float64, the output because a satoshi count can exceed
/// what a JavaScript `number` holds without loss. Pass the result to a
/// `bigint` if you want arithmetic.
///
/// ```js
/// parseCoins("1.1")        // "110000000"
/// parseCoins("0.00000001") // "1"
/// parseCoins("1.123456789") // throws: more precision than a satoshi has
/// ```
#[wasm_bindgen(js_name = parseCoins)]
pub fn parse_coins(coins: JsText) -> Result<String, WasmError> {
    coins_to_sats(&dto::text("coins", coins.as_ref())?)
}

/// Convert satoshis to a decimal amount of coins.
///
/// The inverse of [`parse_coins`], and exact in the same way: eight decimal
/// places, no rounding, no float.
///
/// ```js
/// formatCoins("110000000") // "1.1"
/// formatCoins("1")         // "0.00000001"
/// ```
#[wasm_bindgen(js_name = formatCoins)]
pub fn format_coins(satoshis: JsText) -> Result<String, WasmError> {
    sats_to_coins(&dto::text("satoshis", satoshis.as_ref())?)
}

/// Satoshis in one coin, as a string, so a caller can assert against it.
#[wasm_bindgen(js_name = satsPerCoin)]
pub fn sats_per_coin() -> String {
    verus_tx::SATS_PER_COIN.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values a float bridge gets wrong. Each of these is a real rounding
    /// failure of `Math.round(coins * 1e8)` in JavaScript, and each must come
    /// out exact here.
    #[test]
    fn the_amounts_a_float_would_round_are_exact() {
        for (coins, satoshis) in [
            ("1.1", "110000000"),
            ("0.1", "10000000"),
            ("0.00000001", "1"),
            ("4.35", "435000000"),
            ("92233720368.54775807", "9223372036854775807"),
        ] {
            assert_eq!(coins_to_sats(coins).unwrap(), satoshis, "coins {coins}");
            assert_eq!(sats_to_coins(satoshis).unwrap(), coins, "sats {satoshis}");
        }
    }

    #[test]
    fn more_precision_than_a_satoshi_has_is_refused() {
        assert!(coins_to_sats("1.123456789").is_err());
    }

    #[test]
    fn a_coin_amount_is_not_a_satoshi_amount() {
        // The commonest mix-up: passing coins where satoshis belong. It has to
        // fail rather than silently mean 1 satoshi.
        assert!(sats_to_coins("1.0").is_err());
    }

    /// The two money entry points must agree about whitespace — one used to
    /// trim where the other refused.
    #[test]
    fn neither_money_reader_accepts_whitespace() {
        assert!(coins_to_sats(" 1.1").is_err());
        assert!(coins_to_sats("1.1 ").is_err());
        assert!(sats_to_coins(" 110000000").is_err());
    }

    #[test]
    fn one_coin_is_the_constant_everything_else_scales_by() {
        assert_eq!(sats_per_coin(), "100000000");
        assert_eq!(coins_to_sats("1").unwrap(), sats_per_coin());
    }
}
