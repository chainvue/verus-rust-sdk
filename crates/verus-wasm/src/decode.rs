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
use verus_wire::{hash::txid_display, TxV4};

use crate::dto;
use crate::error::{WasmError, WasmResult};
use crate::types::{
    DecodedOutputValue, DecodedTransactionValue, JsText, TokenBalancesValue, UtxoListValue,
};

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
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
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
        /// Where the value comes back to if the conversion does not happen.
        ///
        /// `None` for a burn and a mint, which carry a plain destination
        /// because neither has anything to refund. A wallet checking what it
        /// signed has to be able to see this: a preconversion into a launch
        /// that misses its minimum refunds EVERY contribution, so the refund
        /// address is an ordinary outcome rather than a rare one, and one that
        /// was changed is value going somewhere nobody asked for.
        refund: Option<String>,
        /// The reserve currency actually being bought, when the transfer routes
        /// through a basket.
        ///
        /// Present only for a reserve-to-reserve conversion, where
        /// `destinationCurrency` is the basket routed THROUGH and this is the
        /// far side. Without it those two conversions are indistinguishable
        /// from the outside — same source, same via, different destination —
        /// and a wallet cannot verify where its money ends up.
        second_reserve: Option<String>,
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
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
            // The FIRST auxiliary is the refund; the templates this SDK builds
            // write exactly one, and a burn or a mint writes none.
            refund: transfer
                .destination
                .auxiliary
                .first()
                .map(destination_address),
            second_reserve: transfer
                .second_reserve
                .map(|currency| dto::identity_address(currency.to_bytes())),
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

/// One transparent input of a decoded transaction.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodedInput {
    /// The outpoint's transaction, in the display order a daemon prints.
    pub txid: String,
    /// Which output of it is spent.
    pub vout: u32,
    /// `nSequence`, as written.
    pub sequence: u32,
}

/// One transparent output of a decoded transaction.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodedTxOut {
    /// The native value, in satoshis, as a decimal string.
    ///
    /// A string for the reason every amount here is one, and it is not
    /// theoretical on this field: an output's value is a `u64` and the
    /// chain's supply already exceeds what a float64 holds exactly.
    pub satoshis: String,
    /// The scriptPubKey, as hex.
    ///
    /// Renamed explicitly rather than left to `rename_all`, which spells it
    /// `scriptPubkey` — one capital away from the name every daemon, every
    /// wallet and this crate's own `Utxo` use. `dto::JsUtxo` carries the same
    /// rename for the same reason. On a response there is no
    /// `deny_unknown_fields` to turn the mismatch into an error, so it
    /// surfaces as `undefined` at a call site whose types said otherwise,
    /// which is how it was found.
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: String,
    /// What that script turned out to be — the same union
    /// [`decode_output`] returns, so a token amount is readable without a
    /// second call and without the caller re-deriving which outputs have one.
    pub output: DecodedOutput,
}

/// A transaction, read back from its own bytes.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodedTransaction {
    /// The txid of **these** bytes, in display order.
    ///
    /// Computed here, not carried alongside: that is what makes it evidence
    /// about the bytes rather than a claim about them.
    pub txid: String,
    /// `nExpiryHeight` — the height after which the chain will not mine this
    /// transaction. `0` means it never expires.
    pub expiry_height: u32,
    /// `nLockTime`, as written.
    pub lock_time: u32,
    /// Whether any shielded component is present.
    ///
    /// A caller that accounts for value by summing transparent outputs is only
    /// correct when this is `false`; when it is `true`, `valueBalance` moved
    /// value the transparent side does not show.
    pub shielded: bool,
    /// `valueBalance` in satoshis, as a decimal string. Signed: negative when
    /// value enters the shielded pool.
    pub value_balance: String,
    /// What is spent.
    pub inputs: Vec<DecodedInput>,
    /// What is paid.
    pub outputs: Vec<DecodedTxOut>,
}

/// Decode a serialized transaction. Host-testable core of
/// [`decode_transaction`].
pub(crate) fn decode_tx(tx_hex: &str) -> WasmResult<DecodedTransaction> {
    let bytes = dto::bytes_hex(tx_hex)?;
    let tx = TxV4::deserialize(&bytes)?;

    let outputs = tx
        .outputs
        .iter()
        .enumerate()
        .map(|(index, out)| {
            let script_pubkey = hex::encode(&out.script_pubkey);
            let output = decode(&script_pubkey).map_err(|error| {
                WasmError::new(
                    error.code(),
                    format!("outputs[{index}]: {}", error.message()),
                )
            })?;
            Ok(DecodedTxOut {
                satoshis: out.value.to_string(),
                script_pubkey,
                output,
            })
        })
        .collect::<WasmResult<Vec<_>>>()?;

    Ok(DecodedTransaction {
        txid: txid_display(&tx.txid()?),
        expiry_height: tx.expiry_height,
        lock_time: tx.lock_time,
        shielded: tx.is_shielded(),
        value_balance: tx.value_balance.to_string(),
        inputs: tx
            .inputs
            .iter()
            .map(|input| DecodedInput {
                txid: txid_display(&input.txid_internal),
                vout: input.vout,
                sequence: input.sequence,
            })
            .collect(),
        outputs,
    })
}

/// Read a signed transaction back from its own bytes.
///
/// # What this is for
///
/// A wallet shows a user an amount, a recipient and a fee, and then signs. The
/// only way to establish that the bytes it is about to broadcast say the same
/// thing as the screen the user approved is to **read the bytes**. Trusting the
/// builder that produced them proves nothing: a builder that got it wrong is
/// exactly the case the check exists for.
///
/// ```js
/// const signed  = key.send(request);
/// const decoded = decodeTransaction(signed.hex);
///
/// if (decoded.txid !== signed.txid) throw new Error("not the hash of these bytes");
/// if (decoded.expiryHeight !== tip + 20) throw new Error("wrong expiry");
/// for (const input of decoded.inputs) assertWasOffered(input.txid, input.vout);
/// ```
///
/// Every output is decoded through the same union [`decode_output`] returns, so
/// a reserve output's token payload — which lives in the script, not in
/// `satoshis` — is checkable without a second pass.
///
/// # It parses hostile input
///
/// The bytes may have come from anywhere: a counterparty's half-signed offer, a
/// node, a file. `verus-wire`'s decoder checks every length against what
/// remains, allocates nothing on a declared count, and **refuses trailing
/// bytes** rather than stopping early — two byte strings that differ must not
/// decode to the same transaction, or a signature covers something other than
/// what was presented.
///
/// Throws on bytes that are not a Verus v4 (Sapling) transaction, and on an
/// output whose CryptoCondition cannot be unpacked at all. An eval code this
/// SDK simply does not know is *not* an error — it comes back as
/// `unsupportedCryptoCondition`, and leaving that output alone is the caller's
/// job.
#[wasm_bindgen(js_name = decodeTransaction)]
pub fn decode_transaction(tx_hex: JsText) -> Result<DecodedTransactionValue, WasmError> {
    let tx_hex = dto::text("txHex", tx_hex.as_ref())?;
    Ok(crate::to_js(&decode_tx(&tx_hex)?)?.unchecked_into())
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

    // ── decodeTransaction ────────────────────────────────────────────────────

    /// A signed transaction from the builder, to read back.
    fn built() -> crate::dto::JsSignedTransaction {
        let script = hex::encode(key().address().p2pkh_script_pubkey().unwrap());
        crate::send::build_send(
            &key(),
            &crate::send::SendRequest {
                utxos: vec![crate::dto::JsUtxo {
                    txid: "ab".repeat(32),
                    vout: 3,
                    satoshis: "1000000000".into(),
                    script_pubkey: script,
                }],
                recipients: vec![crate::dto::JsRecipient {
                    address: "RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX".into(),
                    satoshis: "150000000".into(),
                }],
                change_address: key().address().to_string(),
                expiry_height: Some(1_170_000),
                fee_per_kb: None,
            },
        )
        .expect("builds")
    }

    /// The point of the whole binding: the txid a builder reports must be the
    /// hash of the bytes it handed over. If this can be asserted, a wallet can
    /// stop taking the builder's word for what it is about to broadcast.
    #[test]
    fn the_decoded_txid_is_the_hash_of_the_bytes_not_a_repeated_claim() {
        let signed = built();
        assert_eq!(decode_tx(&signed.hex).unwrap().txid, signed.txid);
    }

    /// Changing one byte must change the txid. Without this the test above
    /// passes for a decoder that simply echoes something back.
    #[test]
    fn a_single_altered_byte_gives_a_different_txid() {
        let signed = built();
        let mut altered: Vec<char> = signed.hex.chars().collect();
        // The last output's value, well clear of any length prefix.
        let at = altered.len() - 40;
        altered[at] = if altered[at] == 'a' { 'b' } else { 'a' };
        let altered: String = altered.into_iter().collect();

        assert_ne!(altered, signed.hex);
        // A mutation landing inside a length prefix is refused outright, which
        // is the stronger answer rather than a weaker one; anything that still
        // parses has to hash differently.
        if let Ok(decoded) = decode_tx(&altered) {
            assert_ne!(decoded.txid, signed.txid);
        }
    }

    /// Outpoints have to come back the way a daemon prints them, or a caller
    /// comparing against `getaddressutxos` compares reversed hex and finds
    /// nothing.
    #[test]
    fn inputs_report_the_outpoint_in_display_order() {
        let decoded = decode_tx(&built().hex).unwrap();
        assert_eq!(decoded.inputs.len(), 1);
        assert_eq!(decoded.inputs[0].txid, "ab".repeat(32));
        assert_eq!(decoded.inputs[0].vout, 3);
    }

    /// Expiry is the field a wallet cannot otherwise see. It is why this
    /// binding exists at all rather than a caller reading the tail by offset.
    #[test]
    fn the_expiry_height_is_read_from_the_bytes() {
        assert_eq!(decode_tx(&built().hex).unwrap().expiry_height, 1_170_000);
    }

    /// Value has to be conserved across the decode, per the amounts the builder
    /// itself reported — the check a wallet runs before showing a fee.
    #[test]
    fn the_outputs_account_for_the_input_less_the_fee() {
        let signed = built();
        let decoded = decode_tx(&signed.hex).unwrap();

        let paid: u64 = decoded
            .outputs
            .iter()
            .map(|out| out.satoshis.parse::<u64>().unwrap())
            .sum();
        let fee: u64 = signed.fee.parse().unwrap();
        assert_eq!(paid + fee, 1_000_000_000);
    }

    /// Each output carries its own decoded shape, so a token payload is
    /// readable without a second call.
    #[test]
    fn every_output_carries_what_its_script_decoded_to() {
        let decoded = decode_tx(&built().hex).unwrap();
        assert_eq!(decoded.outputs.len(), 2);
        // The payment, then change back to this key.
        assert!(matches!(
            &decoded.outputs[0].output,
            DecodedOutput::PubKeyHash { address }
                if address == "RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX"
        ));
        assert!(matches!(
            &decoded.outputs[1].output,
            DecodedOutput::PubKeyHash { address } if *address == key().address().to_string()
        ));
        // The script comes back as written, so a caller can decode it again.
        for out in &decoded.outputs {
            assert_eq!(decode(&out.script_pubkey).unwrap(), out.output);
        }
        assert_eq!(decoded.value_balance, "0");
    }

    /// A transparent wallet transaction must not claim shielded value.
    #[test]
    fn a_transparent_transaction_reports_no_shielded_part() {
        let decoded = decode_tx(&built().hex).unwrap();
        assert!(!decoded.shielded);
    }

    /// Trailing bytes are refused rather than ignored. A decoder that stops
    /// early lets two different byte strings decode to the same transaction,
    /// which is a way to be paid for something other than what was signed.
    /// The field names a caller actually receives, pinned against the names
    /// `types.d.ts` declares.
    ///
    /// The registry-driven drift guards in `types` cover REQUEST DTOs — the
    /// ones `dto::from_js` reads — because that is the list they iterate. A
    /// response DTO is declared in `types.d.ts` by hand and serialized by
    /// `serde`, and nothing was comparing the two. `scriptPubKey` shipped as
    /// `scriptPubkey` behind a declaration that said otherwise, and the only
    /// symptom was `undefined` at a call site whose types promised a string.
    #[test]
    fn a_decoded_transaction_serializes_the_names_its_interface_declares() {
        let signed = built();
        let json = serde_json::to_value(decode_tx(&signed.hex).unwrap()).unwrap();

        let object = json.as_object().expect("an object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "expiryHeight",
                "inputs",
                "lockTime",
                "outputs",
                "shielded",
                "txid",
                "valueBalance",
            ]
        );

        let mut input: Vec<&str> = object["inputs"][0]
            .as_object()
            .expect("an input")
            .keys()
            .map(String::as_str)
            .collect();
        input.sort_unstable();
        assert_eq!(input, ["sequence", "txid", "vout"]);

        let out = object["outputs"][0].as_object().expect("an output");
        let mut names: Vec<&str> = out.keys().map(String::as_str).collect();
        names.sort_unstable();
        // `scriptPubKey`, with the capital K a daemon writes.
        assert_eq!(names, ["output", "satoshis", "scriptPubKey"]);
    }

    #[test]
    fn trailing_bytes_are_refused_not_ignored() {
        let signed = built();
        decode_tx(&format!("{}00", signed.hex)).expect_err("trailing byte");
    }

    #[test]
    fn bytes_that_are_not_a_transaction_are_refused() {
        decode_tx("00").expect_err("truncated");
        assert_eq!(decode_tx("zz").expect_err("not hex").code(), "InvalidHex");
    }

    /// The index has to appear, or a caller with many outputs cannot tell which
    /// one it could not read.
    #[test]
    fn an_undecodable_output_names_its_index() {
        let signed = built();
        let mut tx = TxV4::deserialize(&hex::decode(&signed.hex).unwrap()).unwrap();
        // A CryptoCondition prefix with nothing decodable after it.
        tx.outputs[1].script_pubkey = hex::decode("4c0f").unwrap();
        let broken = hex::encode(tx.serialize().unwrap());

        let error = decode_tx(&broken).expect_err("output 1 is unreadable");
        assert!(error.message().contains("outputs[1]"), "{error}");
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
