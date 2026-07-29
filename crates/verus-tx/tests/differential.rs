//! Byte-for-byte agreement with the TypeScript SDK.
//!
//! **This is milestone 1's gate.** Each vector in `fixtures/transparent/` was
//! produced by `@chainvue/verus-sdk` — daemon-proven, and deterministic on this
//! path because RFC6979 signing involves no randomness. Reproducing its exact
//! bytes means the fee heuristic, coin selection, change and dust rules,
//! assembly order, sighash and signature all agree with an implementation the
//! Verus network accepts.
//!
//! A mismatch is never "close enough": a fee that differs by one satoshi is a
//! different change output, which is a different transaction.

use std::collections::BTreeMap;

use serde_json::Value;
use verus_keys::{Address, PrivateKey};
use verus_tx::{build_transparent_send, Amount, Recipient, SendParams, Txid, Utxo};

fn load_vectors() -> Vec<Value> {
    let path = format!(
        "{}/../../fixtures/transparent/vectors.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let parsed: Value = serde_json::from_str(&raw).expect("vectors are valid JSON");
    parsed["vectors"]
        .as_array()
        .expect("vectors is an array")
        .iter()
        // Native sends only. Token vectors exercise `build_token_send`, which is
        // a different builder with its own differential test; feeding one here
        // would (correctly) be refused for its CryptoCondition funding script.
        .filter(|v| {
            v["outputs"]
                .as_array()
                .is_some_and(|outs| outs.iter().all(|o| o["currency"].is_null()))
        })
        .cloned()
        .collect()
}

fn u64_at(value: &Value, key: &str) -> u64 {
    value[key]
        .as_u64()
        .unwrap_or_else(|| panic!("field `{key}` is not a u64"))
}

#[test]
fn reproduces_every_typescript_vector_byte_for_byte() {
    let vectors = load_vectors();
    // A filter that silently matched nothing would make this test vacuous.
    assert!(
        vectors.len() >= 6,
        "expected at least 6 native vectors, found {}",
        vectors.len()
    );

    // Collected so a failure reports every divergence at once rather than
    // stopping at the first — when bytes drift, the pattern across cases is what
    // tells you which rule moved.
    let mut failures: BTreeMap<String, String> = BTreeMap::new();

    for vector in &vectors {
        let name = vector["name"].as_str().expect("name").to_string();
        let key = PrivateKey::from_wif(vector["wif"].as_str().expect("wif")).expect("valid WIF");

        let utxos: Vec<Utxo> = vector["utxos"]
            .as_array()
            .expect("utxos")
            .iter()
            .map(|u| Utxo {
                txid: Txid::from_display_hex(u["txid"].as_str().expect("txid")).expect("txid"),
                vout: u32::try_from(u64_at(u, "vout")).expect("vout fits u32"),
                satoshis: Amount::from_sat(u64_at(u, "satoshis")),
                script_pubkey: hex::decode(u["script_pubkey"].as_str().expect("script"))
                    .expect("script is hex"),
            })
            .collect();

        let recipients: Vec<Recipient> = vector["outputs"]
            .as_array()
            .expect("outputs")
            .iter()
            .map(|o| Recipient {
                address: o["address"]
                    .as_str()
                    .expect("address")
                    .parse()
                    .expect("addr"),
                satoshis: Amount::from_sat(u64_at(o, "satoshis")),
            })
            .collect();

        let change_address: Address = vector["change_address"]
            .as_str()
            .expect("change_address")
            .parse()
            .expect("valid change address");

        let params = SendParams::new(
            &utxos,
            &recipients,
            change_address,
            u32::try_from(u64_at(vector, "expiry_height")).expect("expiry fits u32"),
        );

        match build_transparent_send(&key, &params) {
            Err(e) => {
                failures.insert(name, format!("build failed: {e}"));
            }
            Ok(signed) => {
                let expected_hex = vector["expected_signed_hex"].as_str().expect("hex");
                if signed.hex != expected_hex {
                    failures.insert(
                        name.clone(),
                        format!(
                            "hex differs\n   ours: {}\n  theirs: {}",
                            signed.hex, expected_hex
                        ),
                    );
                    continue;
                }
                let expected_txid = vector["expected_txid"].as_str().expect("txid");
                let expected_fee = u64_at(vector, "expected_fee");
                let expected_change = u64_at(vector, "expected_change");
                let expected_inputs = u64_at(vector, "expected_inputs_used");

                if signed.txid != expected_txid {
                    failures.insert(
                        name.clone(),
                        format!("txid {} != {}", signed.txid, expected_txid),
                    );
                } else if signed.fee.to_sat() != expected_fee {
                    failures.insert(
                        name.clone(),
                        format!("fee {} != {}", signed.fee.to_sat(), expected_fee),
                    );
                } else if signed.change.to_sat() != expected_change {
                    failures.insert(
                        name.clone(),
                        format!("change {} != {}", signed.change.to_sat(), expected_change),
                    );
                } else if signed.inputs_used.len() as u64 != expected_inputs {
                    failures.insert(
                        name,
                        format!(
                            "inputs used {} != {}",
                            signed.inputs_used.len(),
                            expected_inputs
                        ),
                    );
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "diverged from the TypeScript SDK on {} of {} vectors:\n{}",
        failures.len(),
        vectors.len(),
        failures
            .iter()
            .map(|(name, detail)| format!("  {name}: {detail}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Guards against the suite silently passing because the fixtures went missing
/// or were emptied — a green run over zero vectors proves nothing.
#[test]
fn the_vector_set_covers_the_branches_it_claims_to() {
    let vectors = load_vectors();
    let names: Vec<&str> = vectors
        .iter()
        .map(|v| v["name"].as_str().expect("name"))
        .collect();

    for required in [
        "single_utxo_single_output",
        "multi_utxo_selection",
        "multi_output",
        "descending_selection_order",
        "above_the_2_32_satoshi_blind_spot",
        "nonzero_expiry_height",
    ] {
        assert!(names.contains(&required), "missing vector: {required}");
    }

    // At least one vector must genuinely need more than one input, or the
    // accumulation loop is untested.
    assert!(
        vectors
            .iter()
            .any(|v| v["expected_inputs_used"].as_u64() == Some(2)),
        "no vector exercises multi-input selection"
    );
}
