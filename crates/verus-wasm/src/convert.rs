//! Converting one currency into another, from data the caller already has.
//!
//! The direct counterpart to [`Key::plan_convert`](crate::flows), the same way
//! [`send`](crate::send) is the counterpart to `planSend`. The flow asks a node
//! which coins are spendable and what the transaction should expire at; this
//! takes both as arguments and talks to nothing.
//!
//! Use the flow unless the application already tracks its own outputs. Use this
//! when it does — a wallet with its own UTXO view, or a signer working from a
//! chain view gathered somewhere else — because routing that through the flow
//! would mean re-fetching what is already known and accepting the node's
//! answer over the application's own.
//!
//! # A conversion is a request at an unknown price
//!
//! The transaction says what goes in and where the result should land. It says
//! **nothing about what comes out**. The chain performs the conversion when it
//! *imports* the output — a block later at best — at whatever the reserve
//! ratios are then, and there is no slippage bound anywhere in the protocol.
//!
//! `planConvert` has a `minExpected` that refuses before signing if the node's
//! own estimate has already fallen below it. This binding does not, and cannot:
//! it asks no node, so it has no estimate to compare against. An application
//! using it that wants that check must make it itself, before calling.
//!
//! **A wallet showing a user a number must show it as an estimate.**

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use verus_keys::PrivateKey;
use verus_tx::{build_conversion, build_conversion_transaction, ConversionParams};

use crate::dto::{self, JsSignedTransaction, JsUtxo, Shape};
use crate::error::{WasmError, WasmResult};
use crate::keys::Key;
use crate::types::{ConvertRequestValue, SignedTransactionValue};

/// What to convert, into what, and out of which coins.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConvertRequest {
    /// P2PKH UTXOs funding the native side.
    ///
    /// That is the amount **plus** the fee when the source is the chain's own
    /// currency, and the fee alone when it is a token — plus the miner fee
    /// either way.
    pub utxos: Vec<JsUtxo>,
    /// Outputs carrying the source currency, when it is a token.
    ///
    /// Leave empty when converting the chain's own currency. Every one is spent
    /// whole and the surplus returns as token change, so a token input left out
    /// is a token burned.
    #[serde(default)]
    pub token_funding: Vec<JsUtxo>,
    /// The currency being spent, as an `i…` address.
    pub from: String,
    /// How much of it, in its smallest unit, as a decimal string.
    pub amount: String,
    /// Which kind of conversion. One of `"intoFractional"`, `"intoReserve"`,
    /// `"reserveToReserve"`, `"preconvert"`.
    ///
    /// Minting and burning are deliberately not reachable from here, for the
    /// same reason they are not reachable from `planConvert`: a burn cannot be
    /// undone and a mint needs a controlling identity's authority, and neither
    /// should be one mistyped string away.
    pub kind: String,
    /// The currency being bought — the fractional, the reserve, or the target.
    pub into: String,
    /// The fractional to route through. **Only** for `"reserveToReserve"`, and
    /// refused for every other kind rather than ignored.
    #[serde(default)]
    pub via: Option<String>,
    /// Where the converted value should land.
    pub recipient: String,
    /// Where a refund goes if the conversion does not happen.
    ///
    /// Defaults to this key's own address, which is what the daemon does and
    /// what converting for yourself wants. It is separate from `recipient`
    /// because the two differ when you convert **on somebody else's behalf**,
    /// and naming the recipient twice then sends them your money back as well
    /// as your conversion.
    ///
    /// For a preconvert this is not a corner case: a launch that misses its
    /// minimum refunds every contribution, so the refund path is the ordinary
    /// outcome rather than a rare one.
    #[serde(default)]
    pub refund: Option<String>,
    /// The chain's own currency, as an `i…` address.
    ///
    /// Required, and not defaulted: it is what decides whether the conversion
    /// is funded from `utxos` or from `tokenFunding`, and guessing it wrong
    /// builds a transaction whose value does not conserve. The flow bindings
    /// read it from the node; a binding that asks no node has to be told.
    pub chain_currency: String,
    /// The currency the conversion fee is paid in. Defaults to `chainCurrency`.
    #[serde(default)]
    pub fee_currency: Option<String>,
    /// The conversion fee, in `feeCurrency`'s smallest unit, as a decimal
    /// string.
    ///
    /// **Chain policy, not a constant.** Read it from `estimateconversion`
    /// rather than hard-coding one: the daemon charged 0.0002001 for a
    /// conversion and 0.0002 for a burn on VRSCTEST, and neither figure is
    /// guaranteed to hold on another chain or after a parameter change.
    pub fee: String,
    /// Where change returns. Must be an `R…` address.
    pub change_address: String,
    /// The height after which the transaction stops being minable.
    #[serde(default)]
    pub expiry_height: Option<u32>,
    /// Miner fee rate in satoshis per kilobyte. Defaults to the SDK's rate.
    #[serde(default)]
    pub fee_per_kb: Option<String>,
}

impl ConvertRequest {
    /// The keys a `ConvertRequest` object may carry.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[
            ("utxos", Some(&JsUtxo::SHAPE)),
            ("tokenFunding", Some(&JsUtxo::SHAPE)),
            ("from", None),
            ("amount", None),
            ("kind", None),
            ("into", None),
            ("via", None),
            ("recipient", None),
            ("refund", None),
            ("chainCurrency", None),
            ("feeCurrency", None),
            ("fee", None),
            ("changeAddress", None),
            ("expiryHeight", None),
            ("feePerKb", None),
        ],
    };
}

/// Build and sign a conversion. Host-testable core of [`Key::convert`].
pub(crate) fn build_convert(
    key: &PrivateKey,
    request: &ConvertRequest,
) -> WasmResult<JsSignedTransaction> {
    let chain_currency = dto::currency("chainCurrency", &request.chain_currency)?;
    let fee_currency = match &request.fee_currency {
        Some(text) => dto::currency("feeCurrency", text)?,
        None => chain_currency,
    };
    // The signer's own address, which is what a conversion for yourself refunds
    // to and what the daemon's own templates carry.
    let refund = match &request.refund {
        Some(text) => dto::address(text)?,
        None => key.address(),
    };

    let transfer = build_conversion(
        dto::currency("from", &request.from)?,
        dto::sats(&request.amount)?,
        crate::flows::conversion_kind_of(&request.kind, &request.into, &request.via)?,
        dto::address(&request.recipient)?,
        refund,
        fee_currency,
        dto::sats(&request.fee)?,
    )?;

    let utxos = dto::utxos(&request.utxos)?;
    let token_funding = dto::utxos_named("tokenFunding", &request.token_funding)?;

    let params = ConversionParams::new(
        &transfer,
        &utxos,
        chain_currency,
        dto::pubkey_hash_address("changeAddress", &request.change_address)?,
        dto::expiry(request.expiry_height)?,
    )
    .with_token_funding(&token_funding)
    .with_fee_per_kb(crate::send::fee_per_kb(&request.fee_per_kb)?);

    Ok(build_conversion_transaction(key, &params)?.into())
}

#[wasm_bindgen]
impl Key {
    /// Build and sign a conversion.
    ///
    /// ```js
    /// const signed = key.convert({
    ///   utxos,
    ///   from: VRSCTEST, amount: parseCoins("1"),
    ///   kind: "intoReserve", into: VETH,
    ///   recipient: key.address(),
    ///   chainCurrency: VRSCTEST,
    ///   fee: "20000",                 // from `estimateconversion`, not a constant
    ///   changeAddress: key.address(),
    ///   expiryHeight: tip + 20,
    /// });
    /// ```
    ///
    /// Converting a **token** needs both kinds of funding: `tokenFunding` for
    /// the source currency, and `utxos` for the fee and the miner fee. Token
    /// change and native change both return to `changeAddress`.
    ///
    /// Read the module documentation before wiring this to a button: the price
    /// is not decided here, and there is no slippage bound in the protocol.
    ///
    /// Nothing is broadcast.
    pub fn convert(
        &self,
        request: ConvertRequestValue,
    ) -> Result<SignedTransactionValue, WasmError> {
        let request: ConvertRequest = dto::from_js(request.into())?;
        Ok(crate::to_js(&build_convert(self.private(), &request)?)?.unchecked_into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";
    const VRSCTEST: &str = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";
    const BRIDGE: &str = "iQihXUcQt8G9TSh58YoM5NRwC1nAyoazFR";
    const VETH: &str = "i9nwxtKuVYX4MSbeULLiK2ttVi6rUEhh4X";
    /// Somebody else. Belongs to a different key — `RQr2cUkF…`, which the
    /// `send` fixtures use as a recipient, is this WIF's OWN address, and a
    /// "pay a stranger" test written with it proves nothing.
    const STRANGER: &str = "RYJ1Jbofs42vuRygtXb1GqTFnoYzbEGsk4";

    fn key() -> PrivateKey {
        PrivateKey::from_wif(WIF).unwrap()
    }

    fn currency(id: &str) -> verus_tx::CurrencyId {
        verus_tx::CurrencyId::from_bytes(id.parse::<verus_keys::Address>().unwrap().hash())
    }

    fn funding(satoshis: &str) -> JsUtxo {
        JsUtxo {
            txid: "aa".repeat(32),
            vout: 0,
            satoshis: satoshis.into(),
            script_pubkey: hex::encode(key().address().p2pkh_script_pubkey().unwrap()),
        }
    }

    fn request() -> ConvertRequest {
        ConvertRequest {
            utxos: vec![funding("1000000000")],
            token_funding: vec![],
            from: VRSCTEST.into(),
            amount: "100000000".into(),
            kind: "intoFractional".into(),
            into: BRIDGE.into(),
            via: None,
            recipient: key().address().to_string(),
            refund: None,
            chain_currency: VRSCTEST.into(),
            fee_currency: None,
            fee: "20000".into(),
            change_address: key().address().to_string(),
            expiry_height: Some(1_170_000),
            fee_per_kb: None,
        }
    }

    /// The binding must produce the same bytes as calling the builder directly,
    /// or every vector this repo has proven on chain says nothing about what a
    /// JavaScript caller gets.
    #[test]
    fn the_binding_produces_exactly_what_the_builder_does() {
        let request = request();
        let through_binding = build_convert(&key(), &request).unwrap();

        let transfer = build_conversion(
            currency(VRSCTEST),
            verus_tx::Amount::from_sat(100_000_000),
            verus_tx::convert::ConversionKind::IntoFractional {
                fractional: currency(BRIDGE),
            },
            key().address(),
            key().address(),
            currency(VRSCTEST),
            verus_tx::Amount::from_sat(20_000),
        )
        .unwrap();
        let utxos = dto::utxos(&request.utxos).unwrap();
        let direct = build_conversion_transaction(
            &key(),
            &ConversionParams::new(
                &transfer,
                &utxos,
                currency(VRSCTEST),
                key().address(),
                verus_tx::Expiry::from_height(1_170_000),
            ),
        )
        .unwrap();

        assert_eq!(through_binding.hex, direct.hex);
        assert_eq!(through_binding.txid, direct.txid);
    }

    /// The transaction has to say what it was asked to say. Decoding it back is
    /// the only way to check that, which is why `decodeTransaction` exists.
    #[test]
    fn the_signed_bytes_carry_the_conversion_that_was_requested() {
        let signed = build_convert(&key(), &request()).unwrap();
        let decoded = crate::decode::decode_tx(&signed.hex).unwrap();

        assert_eq!(decoded.txid, signed.txid);
        assert_eq!(decoded.expiry_height, 1_170_000);

        let transfer = decoded
            .outputs
            .iter()
            .find_map(|out| match &out.output {
                crate::decode::DecodedOutput::ReserveTransfer {
                    recipient,
                    destination_currency,
                    fees,
                    ..
                } => Some((
                    recipient.clone(),
                    destination_currency.clone(),
                    fees.clone(),
                )),
                _ => None,
            })
            .expect("a conversion carries a reserve transfer");

        assert_eq!(transfer.0, key().address().to_string());
        assert_eq!(transfer.1, BRIDGE, "the fractional being bought");
        assert_eq!(transfer.2, "20000", "the fee that was asked for");
    }

    /// A native conversion's output must carry amount PLUS fee. Getting this
    /// backwards builds a transaction whose value does not conserve — or one
    /// that quietly hands the difference to a miner.
    #[test]
    fn a_native_conversion_carries_the_amount_and_the_fee() {
        let signed = build_convert(&key(), &request()).unwrap();
        let decoded = crate::decode::decode_tx(&signed.hex).unwrap();
        let carried: u64 = decoded
            .outputs
            .iter()
            .find(|out| {
                matches!(
                    out.output,
                    crate::decode::DecodedOutput::ReserveTransfer { .. }
                )
            })
            .map(|out| out.satoshis.parse().unwrap())
            .expect("a reserve transfer output");
        assert_eq!(carried, 100_000_000 + 20_000);
    }

    /// `via` alongside a kind that does not route is a combination the shape
    /// permits and the meaning does not. Refused by name, because a caller who
    /// set it believed it did something.
    #[test]
    fn a_route_on_a_kind_that_does_not_route_is_refused() {
        let mut request = request();
        request.via = Some(BRIDGE.into());
        let error = build_convert(&key(), &request).expect_err("intoFractional does not route");
        assert!(error.message().contains("via"), "{error}");
    }

    #[test]
    fn a_routed_conversion_without_a_route_is_refused() {
        let mut request = request();
        request.kind = "reserveToReserve".into();
        request.into = VETH.into();
        let error = build_convert(&key(), &request).expect_err("no via");
        assert_eq!(error.code(), "InvalidArgument", "{error}");
    }

    /// A burn and a mint are not reachable by changing a string.
    #[test]
    fn a_burn_is_not_reachable_from_here() {
        let mut request = request();
        request.kind = "burn".into();
        let error = build_convert(&key(), &request).expect_err("burn is a separate operation");
        assert!(error.message().contains("planBurn"), "{error}");
    }

    /// Converting a currency into itself is refused before the fee is spent.
    #[test]
    fn a_currency_cannot_be_converted_into_itself() {
        let mut request = request();
        request.into = VRSCTEST.into();
        build_convert(&key(), &request).expect_err("into itself");
    }

    #[test]
    fn a_shortfall_is_reported_as_insufficient_funds() {
        let mut request = request();
        request.utxos = vec![funding("1000")];
        let error = build_convert(&key(), &request).expect_err("1000 satoshis is not enough");
        assert_eq!(error.code(), "InsufficientFunds", "{error}");
    }

    /// The refund defaults to the signer, not to the recipient. Naming the
    /// recipient twice sends them your money back as well as your conversion.
    #[test]
    fn the_refund_defaults_to_the_signer_not_the_recipient() {
        let mut request = request();
        request.recipient = STRANGER.into();

        let with_default = build_convert(&key(), &request).unwrap();
        request.refund = Some(key().address().to_string());
        let spelled_out = build_convert(&key(), &request).unwrap();
        assert_eq!(with_default.hex, spelled_out.hex);

        request.refund = Some(STRANGER.into());
        let to_the_stranger = build_convert(&key(), &request).unwrap();
        assert_ne!(
            with_default.hex, to_the_stranger.hex,
            "a refund address that is not the signer must change the bytes"
        );
    }
}
