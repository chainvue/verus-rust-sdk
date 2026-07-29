//! Byte-for-byte agreement with the TypeScript SDK on a token transfer.
//!
//! Same oracle as the native vectors, exercising the parts a native send never
//! touches: two-phase selection, CryptoCondition output construction, token
//! change, and the smart-output fee sizing that pushes the fee above the floor.

use serde_json::Value;
use verus_keys::{Address, PrivateKey};
use verus_tx::Expiry;
use verus_tx::{build_token_send, Amount, CurrencyId, TokenRecipient, TokenSendParams, Txid, Utxo};

fn vector(name: &str) -> Value {
    let path = format!(
        "{}/../../fixtures/transparent/vectors.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read_to_string(&path).expect("read vectors");
    let parsed: Value = serde_json::from_str(&raw).expect("valid JSON");
    parsed["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .find(|v| v["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("vector `{name}` not found"))
        .clone()
}

/// The currency id behind an `i` address.
fn currency_of(address: &str) -> CurrencyId {
    address.parse::<Address>().expect("valid i-address").hash()
}

#[test]
fn reproduces_the_typescript_token_transfer() {
    let v = vector("token_transfer_with_token_and_native_change");
    let key = PrivateKey::from_wif(v["wif"].as_str().expect("wif")).expect("valid WIF");

    let utxos: Vec<Utxo> = v["utxos"]
        .as_array()
        .expect("utxos")
        .iter()
        .map(|u| Utxo {
            txid: Txid::from_display_hex(u["txid"].as_str().expect("txid")).expect("txid"),
            vout: u32::try_from(u["vout"].as_u64().expect("vout")).expect("fits"),
            satoshis: Amount::from_sat(u["satoshis"].as_u64().expect("satoshis")),
            script_pubkey: hex::decode(u["script_pubkey"].as_str().expect("script")).expect("hex"),
        })
        .collect();

    let recipients: Vec<TokenRecipient> = v["outputs"]
        .as_array()
        .expect("outputs")
        .iter()
        .map(|o| TokenRecipient {
            address: o["address"]
                .as_str()
                .expect("address")
                .parse()
                .expect("addr"),
            currency: currency_of(o["currency"].as_str().expect("currency")),
            amount: Amount::from_sat(o["satoshis"].as_u64().expect("amount")),
        })
        .collect();

    let params = TokenSendParams::new(
        &utxos,
        &recipients,
        v["change_address"]
            .as_str()
            .expect("change")
            .parse()
            .expect("addr"),
        Expiry::from_height(
            u32::try_from(v["expiry_height"].as_u64().expect("expiry")).expect("fits"),
        ),
    );

    let signed = build_token_send(&key, &params).expect("build");

    assert_eq!(
        signed.hex,
        v["expected_signed_hex"].as_str().expect("hex"),
        "token transaction bytes differ from the TypeScript SDK's"
    );
    assert_eq!(signed.txid, v["expected_txid"].as_str().expect("txid"));
    assert_eq!(
        signed.fee.to_sat(),
        v["expected_fee"].as_u64().expect("fee")
    );
    assert_eq!(
        signed.change.to_sat(),
        v["expected_change"].as_u64().expect("change")
    );
    assert_eq!(
        signed.inputs_used.len() as u64,
        v["expected_inputs_used"].as_u64().expect("inputs")
    );
}

/// The fee must come from the smart-output sizing, not the floor — otherwise the
/// test above could pass for the wrong reason on a differently-shaped vector.
#[test]
fn the_token_fee_is_size_derived_not_the_floor() {
    let v = vector("token_transfer_with_token_and_native_change");
    assert_eq!(v["expected_fee"].as_u64(), Some(10_200));
}
