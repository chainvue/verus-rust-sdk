//! Reading what an output is, before deciding whether to spend it.
//!
//! A wallet cannot treat every output as native value. A CryptoCondition
//! output can carry tokens, hold an identity, or use an eval code this SDK does
//! not decode — and an output whose value cannot be accounted for must be
//! *refused*, never quietly read as "native only". That reclassification is a
//! fund-loss bug: it builds a transaction that destroys the token value it did
//! not see.
//!
//! So this binding never guesses. An eval code it does not understand comes
//! back as `unsupportedCryptoCondition`, and it is the caller's job to leave
//! that output alone.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use verus_tx::{decode_output_script, OutputKind};

use crate::dto::{self, JsUtxo};
use crate::error::{WasmError, WasmResult};
use crate::types::{DecodedOutputValue, JsText, TokenBalancesValue, UtxoListValue};

/// What an output turned out to be.
///
/// Exactly one of the optional fields is set, selected by `kind`. A caller that
/// switches on `kind` and has no branch for `unsupportedCryptoCondition` is a
/// caller that will one day spend an output it could not read.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodedOutput {
    /// One of `pubKeyHash`, `reserveOutput`, `identityPayment`,
    /// `identityPrimary`, `unsupportedCryptoCondition`.
    pub kind: String,
    /// For `pubKeyHash`: the `R…` address paid. For `identityPayment` and
    /// `identityPrimary`: the `i…` address of the identity. For
    /// `reserveOutput`: the destination, as an `R…` address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// For `reserveOutput`: the token value carried, which is *in addition* to
    /// the output's native value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens: Option<Vec<TokenAmount>>,
    /// For `identityPrimary`: the identity's name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// For `identityPrimary`: the addresses that control it, and the number of
    /// them a spend needs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_addresses: Option<Vec<String>>,
    /// For `identityPrimary`: `minimumsignatures`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_signatures: Option<u32>,
    /// For `unsupportedCryptoCondition`: the eval code found. The output may
    /// carry value this SDK cannot see — do not spend it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eval_code: Option<u8>,
}

/// How much of which token.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenAmount {
    /// The currency, as its `i…` address.
    pub currency: String,
    /// The amount in its smallest unit, as a decimal string.
    pub amount: String,
}

/// Decode a scriptPubKey. Host-testable core of [`decode_output`].
pub(crate) fn decode(script_hex: &str) -> WasmResult<DecodedOutput> {
    let script = dto::bytes_hex(script_hex)?;
    let blank = DecodedOutput {
        kind: String::new(),
        address: None,
        tokens: None,
        name: None,
        primary_addresses: None,
        minimum_signatures: None,
        eval_code: None,
    };
    Ok(match decode_output_script(&script)? {
        OutputKind::PubKeyHash { hash } => DecodedOutput {
            kind: "pubKeyHash".into(),
            address: Some(
                verus_keys::Address::new(verus_keys::AddressKind::PubKeyHash, hash).to_string(),
            ),
            ..blank
        },
        OutputKind::ReserveOutput {
            destination,
            tokens,
        } => DecodedOutput {
            kind: "reserveOutput".into(),
            address: Some(
                verus_keys::Address::new(verus_keys::AddressKind::PubKeyHash, destination)
                    .to_string(),
            ),
            tokens: Some(
                tokens
                    .into_iter()
                    .map(|(currency, amount)| TokenAmount {
                        currency: dto::identity_address(currency.to_bytes()),
                        amount: amount.to_string(),
                    })
                    .collect(),
            ),
            ..blank
        },
        OutputKind::IdentityPayment { identity } => DecodedOutput {
            kind: "identityPayment".into(),
            address: Some(dto::identity_address(identity)),
            ..blank
        },
        OutputKind::IdentityPrimary { identity } => DecodedOutput {
            kind: "identityPrimary".into(),
            address: Some(dto::identity_address(verus_tx::identity_id(
                &identity.name,
                Some(identity.parent),
            ))),
            name: Some(identity.name.clone()),
            primary_addresses: Some(
                identity
                    .primary_addresses
                    .iter()
                    .map(destination_address)
                    .collect(),
            ),
            minimum_signatures: Some(identity.min_sigs),
            ..blank
        },
        OutputKind::PubKey { hash, .. } => DecodedOutput {
            kind: "pubKey".into(),
            // Native value only. A proof-of-work coinbase pays this shape, and
            // the address shown is the one that controls the key.
            address: Some(
                verus_keys::Address::new(verus_keys::AddressKind::PubKeyHash, hash).to_string(),
            ),
            ..blank
        },
        OutputKind::UnsupportedCryptoCondition { eval_code } => DecodedOutput {
            kind: "unsupportedCryptoCondition".into(),
            eval_code: Some(eval_code),
            ..blank
        },
        // `OutputKind` is non-exhaustive: this crate can learn to read a new
        // shape between releases. Reported as unknown rather than guessed at,
        // and with no address, so a caller switching on `kind` treats it the
        // way it treats anything else it does not recognise — by leaving the
        // output alone.
        _ => DecodedOutput {
            kind: "unknown".into(),
            ..blank
        },
    })
}

/// Render a destination the way a wallet displays it.
///
/// A raw public key has no address of its own, so it is reported as the address
/// of its hash — which is the address that controls it, and what the daemon
/// shows.
fn destination_address(destination: &verus_tx::Destination) -> String {
    use verus_keys::{Address, AddressKind};
    match destination {
        verus_tx::Destination::PubKeyHash(hash) => {
            Address::new(AddressKind::PubKeyHash, *hash).to_string()
        }
        verus_tx::Destination::ScriptHash(hash) => {
            Address::new(AddressKind::ScriptHash, *hash).to_string()
        }
        verus_tx::Destination::Identity(id) => dto::identity_address(*id),
        verus_tx::Destination::PubKey(bytes) => {
            Address::new(AddressKind::PubKeyHash, verus_keys::hash160(bytes)).to_string()
        }
    }
}

/// Decode a scriptPubKey — what an output is, and what it carries.
///
/// ```js
/// const output = decodeOutput(utxo.scriptPubKey);
/// if (output.kind !== "pubKeyHash") return;   // leave the rest alone
/// ```
///
/// Throws rather than guessing when a CryptoCondition script cannot be
/// unpacked at all: a smart output that fails to decode is not a native one.
#[wasm_bindgen(js_name = decodeOutput)]
pub fn decode_output(script_hex: JsText) -> Result<DecodedOutputValue, WasmError> {
    let script_hex = dto::text("scriptHex", script_hex.as_ref())?;
    Ok(crate::to_js(&decode(&script_hex)?)?.unchecked_into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> verus_keys::PrivateKey {
        verus_keys::PrivateKey::from_bytes(&[0x11; 32], true).unwrap()
    }

    #[test]
    fn a_plain_output_decodes_to_the_address_it_pays() {
        let script = hex::encode(key().address().p2pkh_script_pubkey().unwrap());
        let output = decode(&script).unwrap();
        assert_eq!(output.kind, "pubKeyHash");
        assert_eq!(output.address.unwrap(), key().address().to_string());
        assert!(output.tokens.is_none());
    }

    #[test]
    fn an_identity_payment_reports_the_identity_it_holds_for() {
        let script = hex::encode(verus_tx::identity_payment_script([0x33; 20]).unwrap());
        let output = decode(&script).unwrap();
        assert_eq!(output.kind, "identityPayment");
        assert_eq!(output.address.unwrap(), dto::identity_address([0x33; 20]));
    }

    /// The refusal that matters: an eval code this SDK cannot read must be
    /// reported as unreadable, never as a plain native output.
    #[test]
    fn an_unknown_eval_code_is_reported_not_reclassified() {
        let script = hex::encode(
            verus_tx::cc::cc_script(
                &verus_tx::cc::OptCcParams::one_of_one(
                    0x7f,
                    verus_tx::Destination::PubKeyHash([0x44; 20]),
                ),
                &verus_tx::cc::OptCcParams::one_of_one(
                    0x7f,
                    verus_tx::Destination::PubKeyHash([0x44; 20]),
                ),
            )
            .unwrap(),
        );
        let output = decode(&script).unwrap();
        assert_eq!(output.kind, "unsupportedCryptoCondition");
        assert_eq!(output.eval_code, Some(0x7f));
        assert!(
            output.address.is_none(),
            "an unreadable output must not look payable"
        );
    }

    /// A malformed CryptoCondition throws rather than falling back to native.
    #[test]
    fn a_broken_smart_script_throws_rather_than_reading_as_native() {
        // A CryptoCondition prefix with nothing decodable after it.
        assert!(decode("4c0f").is_err());
    }

    #[test]
    fn a_non_hex_script_is_refused() {
        let error = decode("zzzz").expect_err("not hex");
        assert_eq!(error.code(), "InvalidHex");
    }
}

/// The total of each currency a set of outputs carries.
///
/// The loop every wallet would otherwise write for itself, with the two traps
/// it would otherwise hit. A reserve output carries native satoshis **as well
/// as** its token payload, so `satoshis` is not the token amount and must not
/// be added to one. And an output whose eval code this SDK cannot decode may
/// carry currency it cannot see, so this **throws** rather than returning a
/// total that quietly omits it — a balance that is wrong downward tells a user
/// they hold nothing when they hold something.
///
/// Amounts come back as decimal strings in the currency's smallest unit, the
/// same convention as everywhere else here. Native value is not included: it
/// has no currency id, and folding the two together is how double-counting
/// starts.
///
/// Pass each outpoint at most once — this sums what it is given and cannot
/// tell a second output from the same one listed twice, which matters when a
/// caller concatenates paged RPC results.
///
/// ```js
/// const utxos = await rpc("getaddressutxos", [{ addresses: [key.address()] }]);
/// for (const { currency, amount } of tokenBalances(utxos.map(toUtxo))) {
///   console.log(currency, formatCoins(amount));
/// }
/// ```
#[wasm_bindgen(js_name = tokenBalances)]
pub fn token_balances(utxos: UtxoListValue) -> Result<TokenBalancesValue, WasmError> {
    let list: Vec<JsUtxo> = dto::from_js_list(utxos.into(), &JsUtxo::SHAPE)?;
    let held = verus_tx::token_balances(&dto::utxos(&list)?)?;
    let reported: Vec<TokenAmount> = held
        .into_iter()
        .map(|(currency, amount)| TokenAmount {
            currency: dto::identity_address(currency.to_bytes()),
            amount: dto::sats_string(amount),
        })
        .collect();
    Ok(crate::to_js(&reported)?.unchecked_into())
}
