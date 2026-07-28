//! Spend a shielded note — z→z, z→t, or both — from a JSON spec on stdin.
//!
//! ```sh
//! cargo run --release -p verus-sdk --features prover,multicore --example spend_note < spec.json
//! ```
//!
//! ```json
//! {
//!   "extsk_hex": "…169 bytes…",
//!   "params_dir": "/path/to/ZcashParams",
//!   "expiry_height": 0,
//!   "fee": 30000,
//!   "tree_hex": "…the frontier BEFORE the note's block…",
//!   "block_cmus": ["…every Sapling cmu in the note's block, in order…"],
//!   "my_cmu_index": 0,
//!   "note_output": { "cv": "…", "cmu": "…", "ephemeralKey": "…",
//!                    "encCiphertext": "…", "outCiphertext": "…", "proof": "…" },
//!   "transparent": [{ "address": "R…", "satoshis": 9000000 }],
//!   "shielded":    [{ "address": "zs…", "satoshis": 0, "memo": "optional" }]
//! }
//! ```
//!
//! Prints the signed transaction as JSON. There are no transparent *inputs* in a
//! shielded spend, so this comes out complete — nothing further to sign.
//!
//! # Getting `tree_hex`, which is the hard part
//!
//! The witness proving your note is in the commitment tree needs the tree's
//! frontier as it stood **immediately before the note's block**. That is the one
//! input a signing host cannot derive for itself, and it cannot be recovered
//! later: a frontier only moves forward, so a tree from a later height tells you
//! nothing about an earlier one.
//!
//! * From a node: `z_gettreestate <height-1>`, field
//!   `sapling.commitments.finalState`.
//! * From a light-wallet server: lightwalletd `GetTreeState`.
//! * Ahead of time: `getsaplingtree` returns the tip, so capturing it *before*
//!   broadcasting the transaction that creates the note gives you exactly this,
//!   plus whatever commitments land in between.
//!
//! Check it: `TreeStateBefore::root()` must equal the `finalsaplingroot` in that
//! block's header (byte-reversed — the header displays it like a txid).
//!
//! A frontier that parses cleanly but is from the wrong height is the failure
//! mode to watch for. Everything downstream succeeds — the note decrypts, the
//! witness builds, the proof is generated, the transaction serializes — and the
//! daemon then rejects it with:
//!
//! ```text
//! 18: bad-txns-shielded-requirements-not-met
//! ```
//!
//! which is the anchor check: the root your witness produced is not one this
//! chain has ever had. Confirmed against a VRSCTEST node on 2026-07-28 by
//! deliberately passing the tip frontier for a note mined 24 blocks earlier.
//!
//! `block_cmus` is every Sapling output commitment in the note's own block, in
//! order — not only yours. `my_cmu_index` is where yours sits in that list.

use std::io::Read;

use serde_json::{json, Value};
use verus_sdk::verus_keys::Address;
use verus_sdk::verus_sapling::build::{
    build_shielded_spend, NoteToSpend, ShieldedOutput, SpendSpec, MEMO_SIZE,
};
use verus_sdk::verus_sapling::params::SaplingParams;
use verus_sdk::verus_sapling::scan::{FullOutput, TreeStateBefore};
use verus_sdk::verus_sapling::{zaddr, VERUS_ZIP212};
use verus_sdk::verus_wire::consensus::VERUS_BRANCH_ID;
use verus_sdk::verus_wire::hash::txid_display;
use verus_sdk::verus_wire::TxOut;

type Error = Box<dyn std::error::Error>;

fn main() -> Result<(), Error> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let spec: Value = serde_json::from_str(&input)?;

    let extsk = hex::decode(spec["extsk_hex"].as_str().ok_or("spec.extsk_hex")?)?;
    let fee = spec["fee"].as_u64().ok_or("spec.fee")?;
    let expiry_height = u32::try_from(spec["expiry_height"].as_u64().ok_or("spec.expiry_height")?)?;

    let tree = TreeStateBefore::from_hex(spec["tree_hex"].as_str().ok_or("spec.tree_hex")?)?;
    eprintln!(
        "frontier: {} commitments, root {}",
        tree.size()?,
        hex::encode(tree.root()?)
    );

    let block_cmus: Vec<[u8; 32]> = spec["block_cmus"]
        .as_array()
        .ok_or("spec.block_cmus")?
        .iter()
        .map(|c| reversed32(c.as_str().ok_or("block_cmus[]")?))
        .collect::<Result<_, Error>>()?;
    let my_cmu_index = usize::try_from(spec["my_cmu_index"].as_u64().ok_or("spec.my_cmu_index")?)?;

    let out = &spec["note_output"];
    let output = FullOutput {
        cv: reversed32(out["cv"].as_str().ok_or("note_output.cv")?)?,
        cmu: reversed32(out["cmu"].as_str().ok_or("note_output.cmu")?)?,
        epk: reversed32(
            out["ephemeralKey"]
                .as_str()
                .ok_or("note_output.ephemeralKey")?,
        )?,
        enc: hex::decode(out["encCiphertext"].as_str().ok_or("encCiphertext")?)?,
        ct: hex::decode(out["outCiphertext"].as_str().ok_or("outCiphertext")?)?,
        proof: hex::decode(out["proof"].as_str().ok_or("proof")?)?,
    };
    if block_cmus.get(my_cmu_index) != Some(&output.cmu) {
        return Err(format!(
            "block_cmus[{my_cmu_index}] is not the note's own commitment — \
             the witness would be built for the wrong leaf"
        )
        .into());
    }

    let shielded: Vec<ShieldedOutput> = spec["shielded"]
        .as_array()
        .map(|outs| {
            outs.iter()
                .map(|o| -> Result<ShieldedOutput, Error> {
                    let mut memo = [0u8; MEMO_SIZE];
                    if let Some(text) = o["memo"].as_str() {
                        let bytes = text.as_bytes();
                        if bytes.len() > MEMO_SIZE {
                            return Err(format!("memo is {} bytes", bytes.len()).into());
                        }
                        memo[..bytes.len()].copy_from_slice(bytes);
                    }
                    Ok(ShieldedOutput {
                        recipient: zaddr::decode(o["address"].as_str().ok_or("shielded.address")?)?,
                        value: o["satoshis"].as_u64().ok_or("shielded.satoshis")?,
                        memo,
                    })
                })
                .collect::<Result<Vec<_>, Error>>()
        })
        .transpose()?
        .unwrap_or_default();

    let transparent: Vec<TxOut> = spec["transparent"]
        .as_array()
        .map(|outs| {
            outs.iter()
                .map(|o| -> Result<TxOut, Error> {
                    let address: Address = o["address"]
                        .as_str()
                        .ok_or("transparent.address")?
                        .parse()?;
                    Ok(TxOut {
                        value: o["satoshis"].as_u64().ok_or("transparent.satoshis")?,
                        script_pubkey: address.p2pkh_script_pubkey()?,
                    })
                })
                .collect::<Result<Vec<_>, Error>>()
        })
        .transpose()?
        .unwrap_or_default();

    let dir = spec["params_dir"].as_str().ok_or("spec.params_dir")?;
    eprintln!("loading Sapling parameters from {dir} …");
    let params = SaplingParams::from_files(
        format!("{dir}/sapling-spend.params"),
        format!("{dir}/sapling-output.params"),
    )?;

    eprintln!("proving …");
    // Value conservation against the decrypted note is enforced inside
    // `build_shielded_spend` — an overshoot here is a valid transaction that
    // hands the difference to a miner, so it is refused rather than broadcast.
    let tx = build_shielded_spend(
        &params,
        &SpendSpec {
            note: NoteToSpend {
                extsk_bytes: &extsk,
                output: &output,
                tree_before_block: &tree,
                block_cmus: &block_cmus,
                my_cmu_index,
            },
            shielded_outputs: &shielded,
            transparent_outputs: &transparent,
            fee,
            expiry_height,
            branch_id: VERUS_BRANCH_ID,
            zip212: VERUS_ZIP212,
        },
    )?;

    let raw = tx.serialize()?;
    println!(
        "{:#}",
        json!({
            "txid": txid_display(&tx.txid()?),
            "hex": hex::encode(&raw),
            "size": raw.len(),
            "fee": fee,
            "value_balance": tx.value_balance,
            "shielded_spends": tx.shielded_spends.len(),
            "shielded_outputs": tx.shielded_outputs.len(),
            "transparent_outputs": tx.outputs.len(),
        })
    );
    Ok(())
}

/// Read a 32-byte field the daemon printed in display (reversed) order.
///
/// `decoderawtransaction` reverses `cv`, `cmu` and `ephemeralKey` exactly as it
/// reverses txids, while ciphertexts and proofs come out raw.
fn reversed32(hex_str: &str) -> Result<[u8; 32], Error> {
    let mut bytes: [u8; 32] = hex::decode(hex_str)?
        .try_into()
        .map_err(|_| "expected 32 bytes")?;
    bytes.reverse();
    Ok(bytes)
}
