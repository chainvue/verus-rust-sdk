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
fn fee_per_kb(supplied: &Option<String>) -> WasmResult<u64> {
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
const MAX_FEE_PER_KB: u64 = verus_tx::SATS_PER_COIN;

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
        let request: SendRequest = dto::from_js(request.into(), &SendRequest::SHAPE)?;
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
        let request: TokenSendRequest = dto::from_js(request.into(), &TokenSendRequest::SHAPE)?;
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
