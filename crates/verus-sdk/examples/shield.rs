//! Build and sign a t→z shield from a JSON spec on stdin.
//!
//! ```sh
//! cargo run --release -p verus-sdk --features prover,multicore --example shield < spec.json
//! ```
//!
//! ```json
//! {
//!   "wif": "Uu…",
//!   "params_dir": "/path/to/ZcashParams",
//!   "expiry_height": 0,
//!   "fee": 30000,
//!   "utxos":   [{ "txid": "…", "vout": 0, "satoshis": 100000000, "script_pubkey": "76a914…88ac" }],
//!   "shielded": [{ "address": "zs1…", "satoshis": 99970000, "memo": "optional" }],
//!   "change_address": "R…"
//! }
//! ```
//!
//! Prints the signed transaction as JSON. It does not broadcast — this SDK never
//! opens a socket; hand the hex to a node yourself.
//!
//! The spec is read from stdin rather than argv so a WIF never lands in the
//! process table or the shell history.
//!
//! # The two halves
//!
//! `verus-sapling` proves the shielded bundle and applies the binding signature
//! over the ZIP-243 *shielded* sighash, which has no transparent-input section.
//! `verus-tx` then signs the transparent inputs. Neither invalidates the other,
//! which is what lets one transaction be signed by two crates in sequence.

use std::io::Read;

use serde_json::{json, Value};
use verus_sdk::verus_keys::{Address, PrivateKey};
use verus_sdk::verus_sapling::build::{build_shield, ShieldSpec, ShieldedOutput, MEMO_SIZE};
use verus_sdk::verus_sapling::params::SaplingParams;
use verus_sdk::verus_sapling::zaddr;
use verus_sdk::verus_sapling::VERUS_ZIP212;
use verus_sdk::verus_tx::{sign_p2pkh_inputs, Txid, Utxo};
use verus_sdk::verus_wire::consensus::VERUS_BRANCH_ID;
use verus_sdk::verus_wire::hash::txid_display;
use verus_sdk::verus_wire::{TxIn, TxOut};

type Error = Box<dyn std::error::Error>;

fn main() -> Result<(), Error> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let spec: Value = serde_json::from_str(&input)?;

    let key = PrivateKey::from_wif(spec["wif"].as_str().ok_or("spec.wif")?)?;
    let fee = spec["fee"].as_u64().ok_or("spec.fee")?;
    let expiry_height = u32::try_from(spec["expiry_height"].as_u64().ok_or("spec.expiry_height")?)?;

    let utxos: Vec<Utxo> = spec["utxos"]
        .as_array()
        .ok_or("spec.utxos")?
        .iter()
        .map(|u| -> Result<Utxo, Error> {
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

    let shielded: Vec<ShieldedOutput> = spec["shielded"]
        .as_array()
        .ok_or("spec.shielded")?
        .iter()
        .map(|o| -> Result<ShieldedOutput, Error> {
            let mut memo = [0u8; MEMO_SIZE];
            if let Some(text) = o["memo"].as_str() {
                let bytes = text.as_bytes();
                if bytes.len() > MEMO_SIZE {
                    return Err(
                        format!("memo is {} bytes, limit is {MEMO_SIZE}", bytes.len()).into(),
                    );
                }
                memo[..bytes.len()].copy_from_slice(bytes);
            }
            Ok(ShieldedOutput {
                recipient: zaddr::decode(o["address"].as_str().ok_or("shielded.address")?)?,
                value: o["satoshis"].as_u64().ok_or("shielded.satoshis")?,
                memo,
            })
        })
        .collect::<Result<_, _>>()?;

    // Conservation, in exact integers, before anything is proven or signed:
    // inputs = shielded + transparent change + fee. The daemon accepts an
    // overshoot and hands the difference to a miner, so this is caught here.
    let inputs_total: u64 = utxos.iter().map(|u| u.satoshis).sum();
    let shielded_total: u64 = shielded.iter().map(|o| o.value).sum();
    let spent = shielded_total
        .checked_add(fee)
        .ok_or("shielded outputs plus fee overflow")?;
    let change = inputs_total.checked_sub(spent).ok_or_else(|| {
        format!("inputs {inputs_total} do not cover outputs {shielded_total} + fee {fee}")
    })?;

    let mut transparent_outputs = Vec::new();
    if change > 0 {
        let address: Address = spec["change_address"]
            .as_str()
            .ok_or("spec.change_address is required when there is change")?
            .parse()?;
        transparent_outputs.push(TxOut {
            value: change,
            script_pubkey: address.p2pkh_script_pubkey()?,
        });
    }

    let dir = spec["params_dir"].as_str().ok_or("spec.params_dir")?;
    eprintln!("loading Sapling parameters from {dir} …");
    let params = SaplingParams::from_files(
        format!("{dir}/sapling-spend.params"),
        format!("{dir}/sapling-output.params"),
    )?;

    eprintln!("proving …");
    let mut tx = build_shield(
        &params,
        &ShieldSpec {
            transparent_inputs: &utxos
                .iter()
                .map(|u| TxIn::unsigned(u.txid.to_internal(), u.vout, 0xffff_ffff))
                .collect::<Vec<_>>(),
            transparent_outputs: &transparent_outputs,
            shielded_outputs: &shielded,
            lock_time: 0,
            expiry_height,
            branch_id: VERUS_BRANCH_ID,
            zip212: VERUS_ZIP212,
        },
    )?;

    // The shielded side is signed. Now the transparent inputs.
    sign_p2pkh_inputs(&mut tx, &key, &utxos)?;

    let raw = tx.serialize()?;
    println!(
        "{:#}",
        json!({
            "txid": txid_display(&tx.txid()?),
            "hex": hex::encode(&raw),
            "size": raw.len(),
            "fee": fee,
            "shielded": shielded_total,
            "transparent_change": change,
            "value_balance": tx.value_balance,
            "shielded_outputs": tx.shielded_outputs.len(),
        })
    );
    Ok(())
}
