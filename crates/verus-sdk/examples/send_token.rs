//! Send a token (reserve currency) from a JSON spec on stdin.
//!
//! ```sh
//! cargo run -p verus-sdk --example send_token < spec.json
//! ```
//!
//! ```json
//! {
//!   "wif": "Uw…",
//!   "utxos": [
//!     { "txid": "…", "vout": 0, "satoshis": 0, "script_pubkey": "1a0403…75" },
//!     { "txid": "…", "vout": 1, "satoshis": 139999969600, "script_pubkey": "76a914…88ac" }
//!   ],
//!   "recipients": [
//!     { "address": "R…", "currency": "i7UCaJkKRFXBCK4S1AMrkfKTnPwdLc7dV7", "amount": 10000000000 }
//!   ],
//!   "change_address": "R…",
//!   "expiry_height": 0
//! }
//! ```
//!
//! `amount` is in the token's smallest unit — 1e8 per whole coin, like the
//! native one. Pass **both** the token-bearing outputs and enough plain P2PKH
//! value: a token output carries no native value, so it cannot pay its own fee.
//!
//! # Why token change is not optional
//!
//! A reserve output holds its token value in the CryptoCondition payload, not in
//! the output's satoshis. Spend one and every token in it leaves the transaction
//! — so anything not sent to a recipient must be returned as an explicit token
//! change output, or it is destroyed. The builder emits that change itself and
//! refuses to produce a transaction where token value in does not equal token
//! value out; this example prints both sides so the arithmetic is visible before
//! anyone broadcasts.

use std::io::Read;

use serde_json::{json, Value};
use verus_keys::{Address, PrivateKey};
use verus_sdk::verus_tx::{
    build_token_send, decode_output_script, Amount, Expiry, OutputKind, TokenRecipient,
    TokenSendParams, Txid, Utxo,
};

type Error = Box<dyn std::error::Error>;

fn main() -> Result<(), Error> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let spec: Value = serde_json::from_str(&input)?;

    let key = PrivateKey::from_wif(spec["wif"].as_str().ok_or("spec.wif")?)?;
    let change_address: Address = spec["change_address"]
        .as_str()
        .ok_or("spec.change_address")?
        .parse()?;
    // 0 in a spec means Expiry::Never, which is what these examples have always
    // sent; a wallet should set a real height.
    let expiry = Expiry::from_height(u32::try_from(
        spec["expiry_height"].as_u64().ok_or("spec.expiry_height")?,
    )?);

    let utxos = spec["utxos"]
        .as_array()
        .ok_or("spec.utxos")?
        .iter()
        .map(read_utxo)
        .collect::<Result<Vec<_>, Error>>()?;

    let recipients = spec["recipients"]
        .as_array()
        .ok_or("spec.recipients")?
        .iter()
        .map(|r| -> Result<TokenRecipient, Error> {
            let currency: Address = r["currency"]
                .as_str()
                .ok_or("recipient.currency")?
                .parse()?;
            Ok(TokenRecipient {
                address: r["address"].as_str().ok_or("recipient.address")?.parse()?,
                currency: currency.hash(),
                amount: Amount::from_sat(r["amount"].as_u64().ok_or("recipient.amount")?),
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;

    // What the inputs actually carry, read from the scripts rather than from the
    // spec — the spec says what to send, the chain says what is there.
    let mut available: Vec<(String, u64)> = Vec::new();
    for utxo in &utxos {
        if let OutputKind::ReserveOutput { tokens, .. } = decode_output_script(&utxo.script_pubkey)?
        {
            for (currency, amount) in tokens {
                let currency = hex::encode(currency);
                match available.iter_mut().find(|(id, _)| *id == currency) {
                    Some(entry) => entry.1 += amount,
                    None => available.push((currency, amount)),
                }
            }
        }
    }

    let params =
        TokenSendParams::new(&utxos, &recipients, change_address, expiry).with_fee_per_kb(10_000);
    let signed = build_token_send(&key, &params)?;

    println!(
        "{:#}",
        json!({
            "txid": signed.txid,
            "hex": signed.hex,
            "fee": signed.fee.to_sat(),
            "native_change": signed.change.to_sat(),
            "inputs_used": signed.inputs_used.len(),
            "tokens_in": available.iter()
                .map(|(id, amount)| json!({ "currency": id, "amount": amount }))
                .collect::<Vec<_>>(),
            "tokens_sent": recipients.iter()
                .map(|r| json!({ "currency": hex::encode(r.currency), "amount": r.amount.to_sat() }))
                .collect::<Vec<_>>(),
        })
    );
    Ok(())
}

fn read_utxo(value: &Value) -> Result<Utxo, Error> {
    Ok(Utxo {
        txid: Txid::from_display_hex(value["txid"].as_str().ok_or("utxo.txid")?)?,
        vout: u32::try_from(value["vout"].as_u64().ok_or("utxo.vout")?)?,
        satoshis: Amount::from_sat(value["satoshis"].as_u64().ok_or("utxo.satoshis")?),
        script_pubkey: hex::decode(
            value["script_pubkey"]
                .as_str()
                .ok_or("utxo.script_pubkey")?,
        )?,
    })
}
