//! Build and sign a transparent send from a JSON spec on stdin.
//!
//!   cargo run -p verus-sdk --example send < spec.json
//!
//! ```json
//! {
//!   "wif": "Uu…",
//!   "change_address": "R…",
//!   "expiry_height": 0,
//!   "utxos":  [{ "txid": "…", "vout": 0, "satoshis": 100000000, "script_pubkey": "76a914…88ac" }],
//!   "outputs": [{ "address": "R…", "satoshis": 50000000 }]
//! }
//! ```
//!
//! Prints the signed transaction as JSON. It does not broadcast — this SDK never
//! opens a socket; hand the hex to a node yourself.
//!
//! The spec is read from stdin rather than argv so a WIF never lands in the
//! process table or the shell history.

use std::io::Read;

use serde_json::{json, Value};
use verus_sdk::verus_keys::{Address, PrivateKey};
use verus_sdk::verus_tx::{build_transparent_send, Recipient, SendParams, Txid, Utxo};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let spec: Value = serde_json::from_str(&input)?;

    let key = PrivateKey::from_wif(spec["wif"].as_str().ok_or("spec.wif")?)?;

    let utxos: Vec<Utxo> = spec["utxos"]
        .as_array()
        .ok_or("spec.utxos")?
        .iter()
        .map(|u| -> Result<Utxo, Box<dyn std::error::Error>> {
            Ok(Utxo {
                txid: Txid::from_display_hex(u["txid"].as_str().ok_or("utxo.txid")?)?,
                vout: u32::try_from(u["vout"].as_u64().ok_or("utxo.vout")?)?,
                satoshis: u["satoshis"].as_u64().ok_or("utxo.satoshis")?,
                script_pubkey: hex::decode(
                    u["script_pubkey"].as_str().ok_or("utxo.script_pubkey")?,
                )?,
            })
        })
        .collect::<Result<_, _>>()?;

    let outputs: Vec<Recipient> = spec["outputs"]
        .as_array()
        .ok_or("spec.outputs")?
        .iter()
        .map(|o| -> Result<Recipient, Box<dyn std::error::Error>> {
            Ok(Recipient {
                address: o["address"].as_str().ok_or("output.address")?.parse()?,
                satoshis: o["satoshis"].as_u64().ok_or("output.satoshis")?,
            })
        })
        .collect::<Result<_, _>>()?;

    let change_address: Address = spec["change_address"]
        .as_str()
        .ok_or("spec.change_address")?
        .parse()?;
    let expiry_height = u32::try_from(spec["expiry_height"].as_u64().unwrap_or(0))?;

    let params = SendParams::new(&utxos, &outputs, change_address, expiry_height);
    let signed = build_transparent_send(&key, &params)?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "txid": signed.txid,
            "fee": signed.fee,
            "change": signed.change,
            "inputs_used": signed.inputs_used.len(),
            "hex": signed.hex,
        }))?
    );
    Ok(())
}
