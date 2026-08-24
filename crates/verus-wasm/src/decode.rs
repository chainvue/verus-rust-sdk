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

use crate::dto;
use crate::error::{WasmError, WasmResult};
use crate::types::{DecodedOutputValue, JsText, TokenBalancesValue, UtxoListValue};

/// What an output turned out to be.
///
/// A tagged union: `kind` names the shape, and each shape carries exactly the
/// fields it has — no more, and none of them optional. That is the whole point
/// of the type. The flat struct this replaced had fifteen optional fields of
/// which one group was ever populated, so `output.fees` type-checked on a plain
/// payment and came back `undefined`; here it does not exist until `kind` has
/// been narrowed to `reserveTransfer`.
///
/// A caller that switches on `kind` and has no branch for
/// `unsupportedCryptoCondition` is a caller that will one day spend an output
/// it could not read.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum DecodedOutput {
    /// A plain payment. Native value only.
    PubKeyHash {
        /// The `R…` address paid.
        address: String,
    },
    /// A payment to a bare public key — the shape a proof-of-work coinbase
    /// pays. Native value only.
    PubKey {
        /// The address controlling that key, which is what a daemon shows.
        address: String,
    },
    /// An output carrying token value.
    ReserveOutput {
        /// The destination. May be an `i…` address: tokens held by a VerusID
        /// are an ordinary shape, spendable only by that identity's authority.
        address: String,
        /// The token value carried, which is *in addition* to the output's
        /// native value.
        tokens: Vec<TokenAmount>,
    },
    /// Native value held for an identity.
    IdentityPayment {
        /// The `i…` address of the identity.
        address: String,
    },
    /// The identity object itself.
    IdentityPrimary {
        /// The `i…` address of the identity.
        address: String,
        /// The identity's name.
        name: String,
        /// The addresses that control it.
        primary_addresses: Vec<String>,
        /// How many of them a spend needs — `minimumsignatures`.
        minimum_signatures: u32,
    },
    /// A name commitment, the first half of registering an identity.
    IdentityCommitment {
        /// The destination.
        address: String,
        /// The 32-byte commitment as hex, in the order the script holds it.
        ///
        /// The daemon prints this reversed, the way it prints every hash.
        /// Reverse it before comparing with `registernamecommitment` output.
        commitment: String,
        /// Empty for every ordinary commitment; the advanced form carries
        /// currency alongside the hash, and that is read rather than assumed
        /// away.
        tokens: Vec<TokenAmount>,
    },
    /// Reserves backing a currency.
    ReserveDeposit {
        /// The destination.
        address: String,
        /// The currency whose reserves the output holds.
        controlling_currency: String,
        /// As written, the chain's own currency included — `tokenBalances`
        /// removes that part, this reports the payload.
        tokens: Vec<TokenAmount>,
    },
    /// Value in flight: a conversion, a burn, or a cross-chain send.
    ReserveTransfer {
        /// The protocol's transfer address, not a recipient — see `recipient`.
        address: String,
        /// The token value carried.
        tokens: Vec<TokenAmount>,
        /// The raw flag word.
        flags: u64,
        /// The currency the fee is paid in.
        fee_currency: String,
        /// The fee, as a decimal string.
        fees: String,
        /// The currency written in the destination slot.
        destination_currency: String,
        /// Who the value is ultimately for.
        ///
        /// Not `address`, which is the same for every transfer on the chain —
        /// the real recipient travels inside the payload.
        recipient: String,
    },
    /// An eval code this SDK does not decode. Do not spend it.
    UnsupportedCryptoCondition {
        /// The eval code found.
        eval_code: u8,
        /// Whether an output with that eval code is *able* to hold a token.
        ///
        /// `false` is a proof of absence, taken from the chain's own
        /// `CScript::ReserveOutValue`, not a guess — so a balance can count
        /// the output as zero instead of refusing to answer. The commonest
        /// case by far is a proof-of-stake coinbase's stakeguard output (eval
        /// code 1), which every staking address holds.
        ///
        /// The output is still unspendable by this SDK either way.
        may_carry_currency: bool,
    },
    /// A shape this build does not know. Carries no address, so a caller
    /// switching on `kind` treats it the way it treats anything else it does
    /// not recognise — by leaving the output alone.
    Unknown,
}

/// Token amounts, rendered the way every other field here renders them.
fn amounts(tokens: Vec<(verus_tx::CurrencyId, u64)>) -> Vec<TokenAmount> {
    tokens
        .into_iter()
        .map(|(currency, amount)| TokenAmount {
            currency: dto::identity_address(currency.to_bytes()),
            amount: amount.to_string(),
        })
        .collect()
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
    Ok(match decode_output_script(&script)? {
        OutputKind::PubKeyHash { hash } => DecodedOutput::PubKeyHash {
            address: verus_keys::Address::new(verus_keys::AddressKind::PubKeyHash, hash)
                .to_string(),
        },
        OutputKind::ReserveOutput {
            destination,
            tokens,
        } => DecodedOutput::ReserveOutput {
            // Whatever kind of destination it pays. Tokens held by a VerusID
            // are an ordinary shape, and rendering that identity's hash as an
            // `R…` address would name an address nobody controls.
            address: destination_address(&destination),
            tokens: amounts(tokens),
        },
        OutputKind::IdentityPayment { identity } => DecodedOutput::IdentityPayment {
            address: dto::identity_address(identity),
        },
        OutputKind::IdentityPrimary { identity } => DecodedOutput::IdentityPrimary {
            address: dto::identity_address(verus_tx::identity_id(
                &identity.name,
                Some(identity.parent),
            )),
            name: identity.name.clone(),
            primary_addresses: identity
                .primary_addresses
                .iter()
                .map(destination_address)
                .collect(),
            minimum_signatures: identity.min_sigs,
        },
        // Native value only. A proof-of-work coinbase pays this shape, and the
        // address shown is the one that controls the key.
        OutputKind::PubKey { hash, .. } => DecodedOutput::PubKey {
            address: verus_keys::Address::new(verus_keys::AddressKind::PubKeyHash, hash)
                .to_string(),
        },
        OutputKind::IdentityCommitment {
            destination,
            commitment,
            tokens,
        } => DecodedOutput::IdentityCommitment {
            address: destination_address(&destination),
            commitment: hex::encode(commitment),
            tokens: amounts(tokens),
        },
        OutputKind::ReserveDeposit {
            destination,
            controlling_currency,
            tokens,
        } => DecodedOutput::ReserveDeposit {
            address: destination_address(&destination),
            controlling_currency: dto::identity_address(controlling_currency.to_bytes()),
            tokens: amounts(tokens),
        },
        OutputKind::ReserveTransfer {
            destination,
            transfer,
        } => DecodedOutput::ReserveTransfer {
            address: destination_address(&destination),
            tokens: amounts(transfer.tokens.clone()),
            flags: transfer.flags,
            fee_currency: dto::identity_address(transfer.fee_currency.to_bytes()),
            fees: transfer.fees.to_string(),
            destination_currency: dto::identity_address(transfer.destination_currency.to_bytes()),
            recipient: destination_address(&transfer.destination.recipient),
        },
        OutputKind::UnsupportedCryptoCondition {
            eval_code,
            may_carry_currency,
        } => DecodedOutput::UnsupportedCryptoCondition {
            eval_code,
            may_carry_currency,
        },
        // `OutputKind` is non-exhaustive: this crate can learn to read a new
        // shape between releases. Reported as unknown rather than guessed at.
        _ => DecodedOutput::Unknown,
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

    /// The JSON a caller actually receives.
    fn json(script: &str) -> serde_json::Value {
        serde_json::to_value(decode(script).expect("decodes")).expect("serializes")
    }

    #[test]
    fn a_plain_output_decodes_to_the_address_it_pays() {
        let script = hex::encode(key().address().p2pkh_script_pubkey().unwrap());
        assert!(matches!(
            decode(&script).unwrap(),
            DecodedOutput::PubKeyHash { address } if address == key().address().to_string()
        ));
    }

    #[test]
    fn an_identity_payment_reports_the_identity_it_holds_for() {
        let script = hex::encode(verus_tx::identity_payment_script([0x33; 20]).unwrap());
        assert!(matches!(
            decode(&script).unwrap(),
            DecodedOutput::IdentityPayment { address }
                if address == dto::identity_address([0x33; 20])
        ));
    }

    fn unreadable_script() -> String {
        let params = verus_tx::cc::OptCcParams::one_of_one(
            0x7f,
            verus_tx::Destination::PubKeyHash([0x44; 20]),
        );
        hex::encode(verus_tx::cc::cc_script(&params, &params).unwrap())
    }

    /// The refusal that matters: an eval code this SDK cannot read must be
    /// reported as unreadable, never as a plain native output.
    #[test]
    fn an_unknown_eval_code_is_reported_not_reclassified() {
        assert!(matches!(
            decode(&unreadable_script()).unwrap(),
            DecodedOutput::UnsupportedCryptoCondition {
                eval_code: 0x7f,
                ..
            }
        ));
    }

    /// The union is a *wire* union, not only a Rust one: `kind` is the tag, and
    /// a variant serializes exactly its own fields.
    ///
    /// This is the check that makes the flat-struct-to-enum change type-level
    /// rather than behavioural — a caller reading the JSON must not be able to
    /// tell the two apart. It also pins the property the TypeScript union
    /// claims: a field belonging to another shape is *absent*, never `null`,
    /// so `"address" in output` is a sound narrowing in JavaScript too.
    #[test]
    fn a_variant_serializes_as_kind_plus_exactly_its_own_fields() {
        let script = hex::encode(key().address().p2pkh_script_pubkey().unwrap());
        assert_eq!(
            json(&script),
            serde_json::json!({
                "kind": "pubKeyHash",
                "address": key().address().to_string(),
            })
        );

        assert_eq!(
            json(&unreadable_script()),
            serde_json::json!({
                "kind": "unsupportedCryptoCondition",
                "evalCode": 0x7f,
                // Unreadable, so it must not look payable.
                "mayCarryCurrency": false,
            })
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
/// `nativeCurrency` is the chain's own currency id — `iJhCez…` on VRSCTEST.
/// Pass `null` if you do not know it. It is needed only for reserve deposits
/// and transfers, which name the chain's own currency in their payload *as
/// well as* carrying it as satoshis; without it those two throw rather than
/// report the same money twice. Nothing an ordinary address holds is affected.
///
/// ```js
/// const utxos = await rpc("getaddressutxos", [{ addresses: [key.address()] }]);
/// for (const { currency, amount } of tokenBalances(utxos.map(toUtxo))) {
///   console.log(currency, formatCoins(amount));
/// }
/// ```
#[wasm_bindgen(js_name = tokenBalances)]
pub fn token_balances(
    utxos: UtxoListValue,
    native_currency: crate::types::JsOptionalText,
) -> Result<TokenBalancesValue, WasmError> {
    let list = dto::utxo_list_from_js(utxos.into())?;
    let native = dto::optional_text("nativeCurrency", &native_currency)?
        .map(|text| dto::currency("nativeCurrency", &text))
        .transpose()?;
    let held = verus_tx::token_balances(&dto::utxos(&list)?, native)?;
    let reported: Vec<TokenAmount> = held
        .into_iter()
        .map(|(currency, amount)| TokenAmount {
            currency: dto::identity_address(currency.to_bytes()),
            amount: dto::sats_string(amount),
        })
        .collect();
    Ok(crate::to_js(&reported)?.unchecked_into())
}
