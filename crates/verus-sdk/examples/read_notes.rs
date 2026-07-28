//! Find and decrypt your own notes in a transaction, from a viewing key.
//!
//! ```sh
//! cargo run -p verus-sdk --features shielded --example read_notes < spec.json
//! ```
//!
//! ```json
//! {
//!   "dfvk_hex": "…128 bytes…",
//!   "shielded_outputs": [
//!     { "cv": "…", "cmu": "…", "ephemeralKey": "…", "encCiphertext": "…",
//!       "outCiphertext": "…", "proof": "…" }
//!   ]
//! }
//! ```
//!
//! The field names match a Verus daemon's `decoderawtransaction` output, so you
//! can pipe `.vShieldedOutput` straight in — but nothing here talks to a node.
//! A light wallet gets the same fields from lightwalletd.
//!
//! A viewing key is enough: this recovers the value, the recipient and the memo
//! without ever touching a spending key. Outputs that are not yours simply do
//! not decrypt, which is the whole mechanism — there is no flag on an output
//! saying who it belongs to.
//!
//! That is also why `output_index` is reported rather than assumed. The Sapling
//! builder shuffles outputs, so even your own transaction will not reliably put
//! your note first — trial decryption is the only way to know which one is
//! yours, and a spend needs that index to build the right witness.

use std::io::Read;

use serde_json::{json, Value};
use verus_sdk::verus_sapling::scan::{read_note, FullOutput};
use verus_sdk::verus_sapling::zaddr;
use verus_sdk::verus_sapling::VERUS_ZIP212;

type Error = Box<dyn std::error::Error>;

fn main() -> Result<(), Error> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let spec: Value = serde_json::from_str(&input)?;

    let dfvk_bytes = hex::decode(spec["dfvk_hex"].as_str().ok_or("spec.dfvk_hex")?)?;
    let dfvk = sapling_dfvk(&dfvk_bytes)?;

    let mut found = Vec::new();
    for (index, out) in spec["shielded_outputs"]
        .as_array()
        .ok_or("spec.shielded_outputs")?
        .iter()
        .enumerate()
    {
        let output = FullOutput {
            cv: array32(out, "cv")?,
            cmu: array32(out, "cmu")?,
            epk: array32(out, "ephemeralKey")?,
            enc: hex::decode(out["encCiphertext"].as_str().ok_or("encCiphertext")?)?,
            ct: hex::decode(out["outCiphertext"].as_str().ok_or("outCiphertext")?)?,
            proof: hex::decode(out["proof"].as_str().ok_or("proof")?)?,
        };
        if let Some(note) = read_note(&dfvk, &output, VERUS_ZIP212)? {
            // ZIP-302 memos are zero-padded to 512 bytes; trim before display.
            let end = note.memo.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
            found.push(json!({
                "output_index": index,
                "satoshis": note.value,
                "address": zaddr::encode(&note.recipient)?,
                "memo": String::from_utf8_lossy(&note.memo[..end]),
            }));
        }
    }

    println!("{:#}", json!({ "notes": found }));
    Ok(())
}

fn sapling_dfvk(
    bytes: &[u8],
) -> Result<verus_sdk::verus_sapling::scan::DiversifiableFullViewingKey, Error> {
    let bytes: [u8; 128] = bytes
        .try_into()
        .map_err(|_| format!("a DFVK is 128 bytes, got {}", bytes.len()))?;
    verus_sdk::verus_sapling::scan::dfvk_from_bytes(&bytes).map_err(Into::into)
}

/// Read one of the 32-byte fields, undoing the daemon's display order.
///
/// `decoderawtransaction` prints `cv`, `cmu` and `ephemeralKey` **byte
/// reversed**, the same convention it uses for txids — while `encCiphertext`,
/// `outCiphertext` and `proof` are raw. Feeding the displayed order straight in
/// fails as "bad note commitment" if you are lucky, and silently fails to
/// decrypt if you are not.
fn array32(value: &Value, field: &str) -> Result<[u8; 32], Error> {
    let bytes = hex::decode(value[field].as_str().ok_or(field.to_string())?)?;
    let mut array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{field} is not 32 bytes"))?;
    array.reverse();
    Ok(array)
}
