//! Sending value: native coins, and tokens.
//!
//! Both bindings take the same shape — the UTXOs a wallet found, where the
//! value goes, where change returns, and when the transaction expires — and
//! give back signed hex plus the txid it will have. Nothing here talks to a
//! node: a signer that cannot reach the network is a signer that cannot leak to
//! one.
//!
//! **Finding the UTXOs is the caller's** — which is a real cost, because
//! `getaddressutxos` does not say which outputs are immature coinbases and
//! spending one is a rejection that names nothing.
//! [`Key::plan_send`](crate::flows) does that lookup with the SDK's own rules
//! and is the better default; this stays for a wallet that already tracks its
//! own outputs, or is signing for a chain view it gathered elsewhere.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use verus_keys::PrivateKey;
use verus_tx::{
    build_token_send, build_transparent_send, Recipient, SendParams, TokenRecipient,
    TokenSendParams,
};

use crate::dto::{self, JsRecipient, JsSignedTransaction, JsUtxo, Shape};
use crate::error::{WasmError, WasmResult};
use crate::keys::Key;
use crate::types::{SendRequestValue, SignedTransactionValue, TokenSendRequestValue};

/// What to build for a native send.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SendRequest {
    /// UTXOs available to spend. Every one must be plain P2PKH paying this key.
    pub utxos: Vec<JsUtxo>,
    /// Where the value is going. An `R…` or an `i…` address; paying a VerusID
    /// costs more in fee, because it is a CryptoCondition output.
    pub recipients: Vec<JsRecipient>,
    /// Where change returns. Must be an `R…` address.
    pub change_address: String,
    /// The height past which this transaction can no longer be mined. Omit it
    /// (or pass `null`) for a transaction that never expires — see
    /// [`crate::dto::expiry`] on why that is written rather than defaulted.
    #[serde(default)]
    pub expiry_height: Option<u32>,
    /// Fee rate in satoshis per kilobyte, as a decimal string. Omit for the
    /// SDK's default.
    #[serde(default)]
    pub fee_per_kb: Option<String>,
}

impl SendRequest {
    /// The keys a `SendRequest` object may carry, and the shape of the nested
    /// ones. Pinned against what the type serializes by a test in
    /// [`crate::types`].
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[
            ("utxos", Some(&JsUtxo::SHAPE)),
            ("recipients", Some(&JsRecipient::SHAPE)),
            ("changeAddress", None),
            ("expiryHeight", None),
            ("feePerKb", None),
        ],
    };
}

/// What to build for a token send.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TokenSendRequest {
    /// UTXOs available: token-bearing reserve outputs, and native P2PKH to pay
    /// the miner fee with.
    pub utxos: Vec<JsUtxo>,
    /// Where the tokens are going.
    pub recipients: Vec<JsTokenRecipient>,
    /// Where both token and native change return. Must be an `R…` address.
    pub change_address: String,
    /// The height past which this transaction can no longer be mined.
    #[serde(default)]
    pub expiry_height: Option<u32>,
    /// Fee rate in satoshis per kilobyte, as a decimal string.
    #[serde(default)]
    pub fee_per_kb: Option<String>,
}

impl TokenSendRequest {
    /// The keys a `TokenSendRequest` object may carry, and the shape of the
    /// nested ones.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[
            ("utxos", Some(&JsUtxo::SHAPE)),
            ("recipients", Some(&JsTokenRecipient::SHAPE)),
            ("changeAddress", None),
            ("expiryHeight", None),
            ("feePerKb", None),
        ],
    };
}

/// One token payment.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JsTokenRecipient {
    /// The `R…` address being paid.
    pub address: String,
    /// Which token, named by its `i…` currency address.
    pub currency: String,
    /// How much, in the token's smallest unit, as a decimal string.
    pub amount: String,
}

impl JsTokenRecipient {
    /// The keys a token recipient object may carry.
    pub const SHAPE: Shape = Shape {
        fields: &[("address", None), ("currency", None), ("amount", None)],
    };
}

/// The fee rate, or the SDK's default when none was given.
pub(crate) fn fee_per_kb(supplied: &Option<String>) -> WasmResult<u64> {
    fee_per_kb_from(supplied)
}

/// The shared body, so the request path and `estimateFee` cap identically.
fn fee_per_kb_from(supplied: &Option<String>) -> WasmResult<u64> {
    match supplied {
        None => Ok(verus_tx::fee::DEFAULT_FEE_PER_KB),
        Some(text) => {
            let rate = dto::sats(text)?.to_sat();
            // The fee estimate multiplies this by the transaction size, and a
            // release wasm build has overflow checks off — so an absurd rate
            // wrapped `u64` and came out as the MINIMUM fee, which is the
            // wrong direction to be silent in. One coin per kilobyte is orders
            // of magnitude above any real rate and leaves the product nowhere
            // near 2^64.
            if rate > MAX_FEE_PER_KB {
                return Err(WasmError::new(
                    "FeeRateTooLarge",
                    format!(
                        "feePerKb {rate} exceeds the {MAX_FEE_PER_KB} satoshi/kB ceiling; \
                         that is {} coins per kilobyte and is almost certainly a unit mistake",
                        verus_tx::Amount::from_sat(rate).to_coins_string()
                    ),
                ));
            }
            Ok(rate)
        }
    }
}

/// The largest fee rate this binding will accept: one coin per kilobyte.
///
/// Not a consensus rule — a sanity bound, so that caller-controlled arithmetic
/// crossing the boundary cannot overflow and land on the minimum fee.
pub(crate) const MAX_FEE_PER_KB: u64 = verus_tx::SATS_PER_COIN;

/// What a transparent transaction of this shape will cost in miner fee.
///
/// # Why a wallet needs this before it builds anything
///
/// [`Key::send`] reports the fee it charged, which is the honest number — but
/// it reports it *after* signing, and by then a key has been derived and an
/// amount has been committed to. A wallet has questions it must answer earlier:
/// whether a balance can cover an amount at all, what a "send everything" leaves
/// once the transaction has been paid for, and which coins to select. Each is a
/// prediction, and each is wrong in a way that costs the user if it disagrees
/// with what the builder will actually charge.
///
/// So this is the same function the builder itself uses, exposed rather than
/// re-implemented. A wallet that estimates with its own copy of the arithmetic
/// has two fee models, and the day they disagree is the day it shows one number
/// and signs another.
///
/// ```js
/// // Can this balance cover 1.5 coins, once the fee is paid?
/// const fee = estimateFee(1, 2, null, false);
/// if (balance < parseCoins("1.5") + BigInt(fee)) refuse();
/// ```
///
/// `numOutputs` should include the change output, whether or not one is
/// emitted: selection budgets for it either way, so an estimate that leaves it
/// out is an estimate the builder can exceed.
///
/// `hasSmartOutputs` sizes outputs as CryptoCondition scripts rather than
/// P2PKH. It follows the **currency**, not the address type: a native send to a
/// VerusID is still sized as P2PKH, and a token send is not, whatever it pays.
///
/// `feePerKb` is a decimal string, or `null` for the SDK's own rate.
///
/// # This is an estimate of a rate-based model
///
/// It is `ceil(size × feePerKb / 1000)`, floored at the minimum fee, over a
/// size estimated from input and output counts. That is what this SDK charges.
/// It is **not** what the daemon's relay minimum computes, which is priced by
/// output count and has no size term at all — the two agree on ordinary shapes
/// because the floor hides the difference, and diverge on shapes with many
/// outputs.
#[wasm_bindgen(js_name = estimateFee)]
pub fn estimate_fee(
    num_inputs: u32,
    num_outputs: u32,
    fee_per_kb: crate::types::JsOptionalText,
    has_smart_outputs: bool,
) -> Result<String, WasmError> {
    estimate_fee_core(
        num_inputs,
        num_outputs,
        dto::optional_text("feePerKb", &fee_per_kb)?,
        has_smart_outputs,
    )
}

/// Host-testable core of [`estimate_fee`].
pub(crate) fn estimate_fee_core(
    num_inputs: u32,
    num_outputs: u32,
    fee_per_kb: Option<String>,
    has_smart_outputs: bool,
) -> WasmResult<String> {
    let rate = fee_per_kb_from(&fee_per_kb)?;
    let fee = verus_tx::estimate_fee(
        u64::from(num_inputs),
        u64::from(num_outputs),
        rate,
        has_smart_outputs,
    )?;
    Ok(fee.to_string())
}

/// The SDK's own fee rate, as a decimal string, so a caller can assert against
/// it rather than hard-coding a copy that later drifts.
#[wasm_bindgen(js_name = defaultFeePerKb)]
pub fn default_fee_per_kb() -> String {
    verus_tx::fee::DEFAULT_FEE_PER_KB.to_string()
}

/// The value below which an output is dust and is folded into the fee instead
/// of being written.
///
/// A wallet that predicts its own change needs this: change at or below it does
/// not become an output, so a balance check that expects one is wrong by
/// exactly this much.
#[wasm_bindgen(js_name = dustThreshold)]
pub fn dust_threshold() -> String {
    verus_tx::fee::DUST_THRESHOLD.to_string()
}

/// Build and sign a native send. Host-testable core of [`send`].
pub(crate) fn build_send(
    key: &PrivateKey,
    request: &SendRequest,
) -> WasmResult<JsSignedTransaction> {
    let utxos = dto::utxos(&request.utxos)?;
    let recipients = request
        .recipients
        .iter()
        .enumerate()
        .map(|(index, recipient)| {
            Ok(Recipient {
                address: dto::address(&recipient.address).map_err(|error| {
                    WasmError::new(
                        error.code(),
                        format!("recipients[{index}]: {}", error.message()),
                    )
                })?,
                satoshis: dto::sats(&recipient.satoshis).map_err(|error| {
                    WasmError::new(
                        error.code(),
                        format!("recipients[{index}]: {}", error.message()),
                    )
                })?,
            })
        })
        .collect::<WasmResult<Vec<_>>>()?;
    let params = SendParams::new(
        &utxos,
        &recipients,
        dto::pubkey_hash_address("changeAddress", &request.change_address)?,
        dto::expiry(request.expiry_height)?,
    )
    .with_fee_per_kb(fee_per_kb(&request.fee_per_kb)?);
    Ok(build_transparent_send(key, &params)?.into())
}

/// Build and sign a token send. Host-testable core of [`send_token`].
pub(crate) fn build_token(
    key: &PrivateKey,
    request: &TokenSendRequest,
) -> WasmResult<JsSignedTransaction> {
    let utxos = dto::utxos(&request.utxos)?;
    let recipients = request
        .recipients
        .iter()
        .enumerate()
        .map(|(index, recipient)| {
            let label = |error: WasmError| {
                WasmError::new(
                    error.code(),
                    format!("recipients[{index}]: {}", error.message()),
                )
            };
            Ok(TokenRecipient {
                address: dto::pubkey_hash_address("address", &recipient.address).map_err(label)?,
                currency: dto::currency("currency", &recipient.currency).map_err(label)?,
                amount: dto::sats(&recipient.amount).map_err(label)?,
            })
        })
        .collect::<WasmResult<Vec<_>>>()?;
    let params = TokenSendParams::new(
        &utxos,
        &recipients,
        dto::pubkey_hash_address("changeAddress", &request.change_address)?,
        dto::expiry(request.expiry_height)?,
    )
    .with_fee_per_kb(fee_per_kb(&request.fee_per_kb)?);
    Ok(build_token_send(key, &params)?.into())
}

#[wasm_bindgen]
impl Key {
    /// Build and sign a native send.
    ///
    /// ```js
    /// const signed = key.send({
    ///   utxos: [{ txid, vout: 0, satoshis: "1000000000", scriptPubKey }],
    ///   recipients: [{ address: "RQr2…", satoshis: parseCoins("1.5") }],
    ///   changeAddress: key.address(),
    ///   expiryHeight: tip + 20,
    /// });
    /// await rpc("sendrawtransaction", [signed.hex]);
    /// ```
    ///
    /// Coin selection and signing are both deterministic, so the same inputs
    /// always produce the same bytes — a wallet can re-derive and compare
    /// rather than having to store what it sent.
    pub fn send(&self, request: SendRequestValue) -> Result<SignedTransactionValue, WasmError> {
        let request: SendRequest = dto::from_js(request.into())?;
        Ok(crate::to_js(&build_send(self.private(), &request)?)?.unchecked_into())
    }

    /// Build and sign a token send.
    ///
    /// Needs both kinds of funding: reserve outputs carrying the token, and
    /// native P2PKH outputs to pay the miner in. Token change and native change
    /// both return to `changeAddress`.
    #[wasm_bindgen(js_name = sendToken)]
    pub fn send_token(
        &self,
        request: TokenSendRequestValue,
    ) -> Result<SignedTransactionValue, WasmError> {
        let request: TokenSendRequest = dto::from_js(request.into())?;
        Ok(crate::to_js(&build_token(self.private(), &request)?)?.unchecked_into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";

    fn key() -> PrivateKey {
        PrivateKey::from_wif(WIF).unwrap()
    }

    fn funding(satoshis: &str) -> JsUtxo {
        JsUtxo {
            txid: "aa".repeat(32),
            vout: 0,
            satoshis: satoshis.into(),
            script_pubkey: hex::encode(key().address().p2pkh_script_pubkey().unwrap()),
        }
    }

    fn request() -> SendRequest {
        SendRequest {
            utxos: vec![funding("1000000000")],
            recipients: vec![JsRecipient {
                address: "RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX".into(),
                satoshis: "150000000".into(),
            }],
            change_address: key().address().to_string(),
            expiry_height: Some(1_170_000),
            fee_per_kb: None,
        }
    }

    /// The binding must produce the same bytes as calling the builder directly.
    /// If it did not, every vector this repo has proven on chain would say
    /// nothing about what a JavaScript caller gets.
    #[test]
    fn the_binding_produces_exactly_what_the_builder_does() {
        let request = request();
        let through_binding = build_send(&key(), &request).unwrap();

        let utxos = dto::utxos(&request.utxos).unwrap();
        let recipients = vec![Recipient {
            address: request.recipients[0].address.parse().unwrap(),
            satoshis: verus_tx::Amount::from_sat(150_000_000),
        }];
        let direct = build_transparent_send(
            &key(),
            &SendParams::new(
                &utxos,
                &recipients,
                key().address(),
                verus_tx::Expiry::from_height(1_170_000),
            ),
        )
        .unwrap();

        assert_eq!(through_binding.hex, direct.hex);
        assert_eq!(through_binding.txid, direct.txid);
        assert_eq!(through_binding.fee, direct.fee.to_sat().to_string());
    }

    /// A caller who omits the fee rate gets the SDK's default, not zero.
    #[test]
    fn an_omitted_fee_rate_is_the_default_not_zero() {
        assert_eq!(
            fee_per_kb(&None).unwrap(),
            verus_tx::fee::DEFAULT_FEE_PER_KB
        );
        assert!(build_send(&key(), &request()).unwrap().fee != "0");
    }

    /// The reported fee and change have to be the real ones: a wallet shows
    /// them to a user before broadcasting, and they are not recoverable from
    /// the hex alone.
    #[test]
    fn the_reported_fee_and_change_account_for_the_input() {
        let signed = build_send(&key(), &request()).unwrap();
        let fee: u64 = signed.fee.parse().unwrap();
        let change: u64 = signed.change.parse().unwrap();
        assert_eq!(150_000_000 + fee + change, 1_000_000_000);
        assert_eq!(signed.inputs_used.len(), 1);
        assert_eq!(signed.inputs_used[0].vout, 0);
    }

    /// The whole point of exposing the estimator: it has to agree with what the
    /// builder charges for the shape it describes. A wallet that predicts with
    /// one model and signs with another shows a user one number and spends
    /// another.
    #[test]
    fn the_estimate_is_what_the_builder_actually_charges() {
        let signed = build_send(&key(), &request()).unwrap();
        // One input, and the payment plus change.
        let predicted = estimate_fee_core(1, 2, None, false).unwrap();
        assert_eq!(signed.fee, predicted);
    }

    /// An omitted rate must be the SDK's own, and the accessor must report the
    /// same one — a caller asserting against a hard-coded copy is how the two
    /// drift.
    #[test]
    fn the_reported_default_rate_is_the_rate_that_is_used() {
        assert_eq!(default_fee_per_kb(), "10000");
        assert_eq!(fee_per_kb(&None).unwrap().to_string(), default_fee_per_kb());
        assert_eq!(
            estimate_fee_core(1, 2, None, false).unwrap(),
            estimate_fee_core(1, 2, Some(default_fee_per_kb()), false).unwrap()
        );
    }

    /// A CryptoCondition output is sized larger, so a token shape must not
    /// estimate the same as a plain one once the floor is cleared.
    #[test]
    fn a_smart_output_is_not_sized_as_a_plain_one() {
        let plain = estimate_fee_core(2, 3, None, false).unwrap();
        let smart = estimate_fee_core(2, 3, None, true).unwrap();
        assert_ne!(plain, smart);
        assert!(smart.parse::<u64>().unwrap() > plain.parse::<u64>().unwrap());
    }

    /// The floor is what hides the model on ordinary shapes, and a caller
    /// relying on the estimate needs it to be the floor the builder uses.
    #[test]
    fn a_small_transaction_pays_the_minimum_not_less() {
        assert_eq!(estimate_fee_core(1, 1, None, false).unwrap(), "10000");
    }

    /// A rate above the ceiling is refused rather than wrapping to the minimum.
    #[test]
    fn an_absurd_rate_is_refused_by_the_estimator_too() {
        let error = estimate_fee_core(1, 2, Some("100000001".into()), false)
            .expect_err("one coin per kilobyte is the ceiling");
        assert_eq!(error.code(), "FeeRateTooLarge", "{error}");
    }

    #[test]
    fn a_shortfall_is_reported_as_insufficient_funds() {
        let mut request = request();
        request.utxos = vec![funding("1000")];
        let error = build_send(&key(), &request).expect_err("1000 satoshis is not enough");
        assert_eq!(error.code(), "InsufficientFunds", "{error}");
    }

    /// The index has to appear, or a wallet with many recipients cannot tell
    /// which one it typed wrong.
    #[test]
    fn a_bad_recipient_names_its_index() {
        let mut request = request();
        request.recipients.push(JsRecipient {
            address: "not an address".into(),
            satoshis: "1".into(),
        });
        let error = build_send(&key(), &request).expect_err("the second recipient is bad");
        assert!(error.message().contains("recipients[1]"), "{error}");
    }

    #[test]
    fn change_must_go_somewhere_spendable() {
        let mut request = request();
        request.change_address = dto::identity_address([0x44; 20]);
        let error = build_send(&key(), &request).expect_err("an identity is not P2PKH");
        assert_eq!(error.code(), "UnsupportedRecipient", "{error}");
    }

    /// Paying a VerusID is an ordinary recipient, not an error — it is a
    /// CryptoCondition output, and the builder sizes the fee accordingly.
    #[test]
    fn a_verusid_recipient_is_accepted() {
        let mut request = request();
        request.recipients[0].address = dto::identity_address([0x55; 20]);
        let signed = build_send(&key(), &request).expect("paying an identity is supported");
        assert!(!signed.hex.is_empty());
    }
}
