//! The shapes JavaScript passes in and gets back, and how they become Rust.
//!
//! Three rules hold across every type here, and they are the whole reason this
//! module exists rather than deriving `Serialize` on the SDK's own types.
//!
//! **Money is a decimal string, never a `number`.** JavaScript's `number` is a
//! float64: it cannot hold every satoshi value a 64-bit chain can express, and
//! it rounds silently rather than failing. The workspace bans float money paths
//! end to end for that reason, and the boundary to JavaScript is precisely
//! where the ban would otherwise be lost. A string-typed field turns
//! `satoshis: 1e8` into a thrown error instead of a rounded amount — and a JS
//! `bigint` converts with `.toString()`, which is the intended path.
//!
//! **Hashes and scripts are hex strings**, spelled the way the daemon's JSON
//! spells them: a txid in display (reversed) order, a script as raw hex.
//!
//! **Unknown fields are refused** — see [`from_js`], which is where that is
//! actually enforced, and why `serde`'s own `deny_unknown_fields` is not
//! enough.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use verus_keys::Address;
use verus_tx::{Amount, CurrencyId, Expiry, Txid, Utxo};
use wasm_bindgen::JsValue;

use crate::error::{WasmError, WasmResult};

/// Read a request object, refusing any field the type does not declare.
///
/// # Why this is not `deny_unknown_fields`
///
/// The request types carry `#[serde(deny_unknown_fields)]`, and against
/// `serde_json` it does what it says. Against `serde-wasm-bindgen` it does
/// **nothing**: that deserializer reads a struct by asking the JavaScript
/// object for the names it wants, so a key nobody asked for is never visited
/// and never reported. The attribute is silently inert.
///
/// That mattered. `expiryHieght: tip + 20` — one transposition — deserialized
/// as a request with no expiry at all, and produced a perfectly valid,
/// perfectly signed transaction that can be mined at any height for the rest
/// of the chain's life. Every field this could happen to is optional by
/// definition (a mistyped *required* field is caught as a missing one), and
/// the optional fields are exactly the ones that choose between materially
/// different transactions: whether it expires, and what it pays the miner.
///
/// So the keys are enumerated and checked here, before deserializing. `fields`
/// is the type's own field list; [`crate::types`]-style tests pin each one
/// against what the type actually serializes, so it cannot drift.
pub fn from_js<T: DeserializeOwned>(value: JsValue, fields: &[&str]) -> WasmResult<T> {
    // A non-object is left to serde, which reports the type mismatch better
    // than a key enumeration could — and `Object::keys` on `null` throws.
    if value.is_object() {
        use wasm_bindgen::JsCast;
        for key in js_sys::Object::keys(value.unchecked_ref::<js_sys::Object>()).iter() {
            let name = key.as_string().unwrap_or_default();
            if !fields.contains(&name.as_str()) {
                return Err(WasmError::new(
                    "UnknownField",
                    format!(
                        "unknown field {name:?}; expected one of {}",
                        fields.join(", ")
                    ),
                ));
            }
        }
    }
    serde_wasm_bindgen::from_value(value).map_err(WasmError::from)
}

/// Read a decimal integer number of satoshis.
///
/// Rejects a leading `+`, a decimal point, whitespace and an empty string: this
/// is satoshis, and anything that looks like coins should go through
/// [`crate::money::parse_coins`] where the scaling is explicit.
pub fn sats(text: &str) -> WasmResult<Amount> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(WasmError::new(
            "InvalidAmount",
            format!("{text:?} is not a decimal number of satoshis"),
        ));
    }
    let value = text.parse::<u64>().map_err(|_| {
        WasmError::new(
            "InvalidAmount",
            format!("{text:?} does not fit in 64 bits of satoshis"),
        )
    })?;
    Ok(Amount::from_sat(value))
}

/// Render satoshis the way every DTO field here spells them.
pub fn sats_string(amount: Amount) -> String {
    amount.to_sat().to_string()
}

/// Decode a hex string of exactly `N` bytes.
pub fn fixed_hex<const N: usize>(field: &str, text: &str) -> WasmResult<[u8; N]> {
    let bytes = hex::decode(text)?;
    <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| {
        WasmError::new(
            "InvalidHex",
            format!("{field} must be {N} bytes of hex, got {} ", text.len() / 2),
        )
    })
}

/// Decode a hex string of any length.
pub fn bytes_hex(text: &str) -> WasmResult<Vec<u8>> {
    Ok(hex::decode(text)?)
}

/// Parse any Verus base58 address — `R…`, `i…` or a script hash.
pub fn address(text: &str) -> WasmResult<Address> {
    text.parse::<Address>().map_err(WasmError::from)
}

/// Parse an address that must be a spendable `R…`.
pub fn pubkey_hash_address(field: &str, text: &str) -> WasmResult<Address> {
    let parsed = address(text)?;
    if parsed.kind() != verus_keys::AddressKind::PubKeyHash {
        return Err(WasmError::new(
            "UnsupportedRecipient",
            format!("{field} must be an R-address; {text} is not"),
        ));
    }
    Ok(parsed)
}

/// Parse an `i…` identity address into the 20 bytes that name it.
pub fn identity_id(field: &str, text: &str) -> WasmResult<[u8; 20]> {
    let parsed = address(text)?;
    if parsed.kind() != verus_keys::AddressKind::Identity {
        return Err(WasmError::new(
            "NotAnIdentity",
            format!("{field} must be an i-address; {text} is not"),
        ));
    }
    Ok(parsed.hash())
}

/// Parse a currency, which is named by its i-address.
pub fn currency(field: &str, text: &str) -> WasmResult<CurrencyId> {
    Ok(CurrencyId::from_bytes(identity_id(field, text)?))
}

/// Render 20 bytes as the i-address that names an identity or a currency.
pub fn identity_address(id: [u8; 20]) -> String {
    Address::new(verus_keys::AddressKind::Identity, id).to_string()
}

/// An unspent output, as a wallet holds it.
///
/// `txid` is display order — the same string `getaddressutxos` prints, which is
/// the reverse of the bytes in the transaction. Getting this backwards produces
/// a transaction that spends nothing and is rejected, so the field is named for
/// what a caller sees rather than for what goes on the wire.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JsUtxo {
    /// The transaction that created it, in display order.
    pub txid: String,
    /// Index of the output within that transaction.
    pub vout: u32,
    /// What it is worth, in satoshis, as a decimal string.
    pub satoshis: String,
    /// The scriptPubKey it pays to, as hex.
    ///
    /// Renamed explicitly rather than left to `rename_all`, which would spell
    /// it `scriptPubkey` — one capital away from the name every daemon, every
    /// wallet and every doc in this repo uses. With `deny_unknown_fields` that
    /// mismatch is a thrown error rather than a silently ignored field, but it
    /// would still be an error for no reason.
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: String,
}

impl JsUtxo {
    /// Convert to the SDK's own type.
    pub fn to_utxo(&self) -> WasmResult<Utxo> {
        Ok(Utxo {
            txid: Txid::from_display_hex(&self.txid)?,
            vout: self.vout,
            satoshis: sats(&self.satoshis)?,
            script_pubkey: bytes_hex(&self.script_pubkey)?,
        })
    }
}

/// Convert a whole list, reporting which entry failed.
pub fn utxos(list: &[JsUtxo]) -> WasmResult<Vec<Utxo>> {
    list.iter()
        .enumerate()
        .map(|(index, utxo)| {
            utxo.to_utxo().map_err(|error| {
                WasmError::new(error.code(), format!("utxos[{index}]: {}", error.message()))
            })
        })
        .collect()
}

/// Where value is going.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JsRecipient {
    /// The address being paid.
    pub address: String,
    /// How much, in satoshis, as a decimal string.
    pub satoshis: String,
}

/// When a transaction stops being minable.
///
/// `null` means never, and has to be written: an expiring transaction that
/// falls out of the mempool is recoverable, while `Never` is a transaction that
/// can be mined at any height for the rest of the chain's life. The SDK makes
/// the same distinction non-defaultable for the same reason.
pub fn expiry(height: Option<u32>) -> WasmResult<Expiry> {
    let expiry = match height {
        None => Expiry::Never,
        Some(height) => Expiry::from_height(height),
    };
    expiry.check()?;
    Ok(expiry)
}

/// A signed transaction, ready to broadcast.
///
/// `fee` and `change` are reported rather than left implicit because they are
/// the two numbers a caller cannot recover from the hex without also holding
/// every prevout — and the fee is the one an accidental unit slip destroys.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsSignedTransaction {
    /// The raw transaction, hex — what `sendrawtransaction` takes.
    pub hex: String,
    /// Its txid in display order, known before it is broadcast.
    pub txid: String,
    /// The miner fee paid, in satoshis, including any dust folded into it.
    pub fee: String,
    /// Change returned, in satoshis; `"0"` if it would have been dust.
    pub change: String,
    /// The outpoints spent, in input order.
    pub inputs_used: Vec<JsOutpoint>,
}

/// One outpoint: which output of which transaction.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JsOutpoint {
    /// The transaction, in display order.
    pub txid: String,
    /// The output index.
    pub vout: u32,
}

impl From<verus_tx::SignedTransaction> for JsSignedTransaction {
    fn from(signed: verus_tx::SignedTransaction) -> Self {
        Self {
            hex: signed.hex,
            txid: signed.txid,
            fee: sats_string(signed.fee),
            change: sats_string(signed.change),
            inputs_used: signed
                .inputs_used
                .into_iter()
                .map(|(txid, vout)| JsOutpoint {
                    txid: txid.to_display_hex(),
                    vout,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn satoshis_are_decimal_strings() {
        assert_eq!(sats("100000000").unwrap(), Amount::from_sat(100_000_000));
        assert_eq!(sats("0").unwrap(), Amount::ZERO);
    }

    /// The whole point of the string-typed money fields: the ways JavaScript
    /// would otherwise smuggle a float in must each fail loudly.
    #[test]
    fn anything_that_is_not_an_integer_of_satoshis_is_refused() {
        for bad in ["", "1.5", "1e8", " 100", "100 ", "+100", "-100", "0x64"] {
            let error = sats(bad).expect_err("{bad:?} must be refused");
            assert_eq!(error.code(), "InvalidAmount", "{bad:?} -> {error}");
        }
    }

    #[test]
    fn a_satoshi_count_beyond_64_bits_is_refused() {
        let error = sats("99999999999999999999999").expect_err("must not wrap");
        assert!(error.message().contains("64 bits"), "{error}");
    }

    #[test]
    fn an_i_address_is_not_accepted_where_an_r_address_is_required() {
        let identity = identity_address([0x11; 20]);
        let error = pubkey_hash_address("changeAddress", &identity).expect_err("i is not R");
        assert_eq!(error.code(), "UnsupportedRecipient");
    }

    #[test]
    fn an_r_address_is_not_accepted_where_an_identity_is_required() {
        let key = verus_keys::PrivateKey::from_bytes(&[0x22; 32], true).unwrap();
        let error =
            identity_id("parent", &key.address().to_string()).expect_err("R is not an identity");
        assert_eq!(error.code(), "NotAnIdentity");
    }

    #[test]
    fn a_utxo_round_trips_through_its_dto() {
        let js = JsUtxo {
            txid: "11".repeat(32),
            vout: 3,
            satoshis: "250000000".into(),
            script_pubkey: hex::encode(
                verus_keys::PrivateKey::from_bytes(&[0x33; 32], true)
                    .unwrap()
                    .address()
                    .p2pkh_script_pubkey()
                    .unwrap(),
            ),
        };
        let utxo = js.to_utxo().unwrap();
        assert_eq!(utxo.vout, 3);
        assert_eq!(utxo.satoshis, Amount::from_sat(250_000_000));
        assert_eq!(utxo.txid.to_display_hex(), js.txid);
    }

    /// A bad entry must name its index — a wallet passing forty outputs needs
    /// to know which one, and "invalid hex" alone does not say.
    #[test]
    fn a_bad_utxo_names_its_index() {
        let good = JsUtxo {
            txid: "11".repeat(32),
            vout: 0,
            satoshis: "1".into(),
            script_pubkey: "76a914".to_string() + &"22".repeat(20) + "88ac",
        };
        let mut bad = good.clone();
        bad.satoshis = "1.0".into();
        let error = utxos(&[good, bad]).expect_err("the second entry is bad");
        assert!(error.message().starts_with("utxos[1]:"), "{error}");
    }

    #[test]
    fn an_expiry_beyond_the_height_threshold_is_refused() {
        assert!(expiry(Some(500_000_001)).is_err());
        assert_eq!(expiry(None).unwrap(), Expiry::Never);
    }
}
