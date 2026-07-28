//! Reconstruct a [`TxV4`] from a `decoderawtransaction` JSON decode.
//!
//! **Byte order is the whole difficulty here.** `decoderawtransaction` DISPLAYS
//! 32-byte fields byte-reversed — transparent txids, and the shielded `cv`,
//! `anchor`, `nullifier`, `rk`, `cmu`, `ephemeralKey`. Ciphertexts, proofs and
//! signatures are raw. This module reverses exactly the reversed ones, so the
//! reconstructed transaction matches what the daemon actually hashed and signed.

use serde_json::Value;
use verus_wire::{TxIn, TxOut, TxV4};

/// Load `fixtures/daemon/<name>.json` and `<name>.hex`.
///
/// `CARGO_MANIFEST_DIR` is per-package, so this resolves from `crates/verus-wire/`.
pub fn load_fixture(name: &str) -> (Value, String) {
    let base = format!(
        "{}/../../fixtures/daemon/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = std::fs::read_to_string(format!("{base}.json"))
        .unwrap_or_else(|e| panic!("read {base}.json: {e}"));
    let hex = std::fs::read_to_string(format!("{base}.hex"))
        .unwrap_or_else(|e| panic!("read {base}.hex: {e}"));
    (
        serde_json::from_str(&json).expect("fixture is valid JSON"),
        hex.trim().to_string(),
    )
}

fn bytes(value: &Value, key: &str) -> Vec<u8> {
    hex::decode(
        value[key]
            .as_str()
            .unwrap_or_else(|| panic!("field `{key}`")),
    )
    .unwrap_or_else(|e| panic!("field `{key}` is not hex: {e}"))
}

fn array32(value: &Value, key: &str) -> [u8; 32] {
    let raw = bytes(value, key);
    let mut out = [0u8; 32];
    assert_eq!(raw.len(), 32, "field `{key}` is not 32 bytes");
    out.copy_from_slice(&raw);
    out
}

/// A displayed 32-byte field, reversed back into wire order.
fn array32_reversed(value: &Value, key: &str) -> [u8; 32] {
    let mut out = array32(value, key);
    out.reverse();
    out
}

fn array64(value: &Value, key: &str) -> [u8; 64] {
    let raw = bytes(value, key);
    let mut out = [0u8; 64];
    assert_eq!(raw.len(), 64, "field `{key}` is not 64 bytes");
    out.copy_from_slice(&raw);
    out
}

fn u32_at(value: &Value, key: &str) -> u32 {
    u32::try_from(
        value[key]
            .as_u64()
            .unwrap_or_else(|| panic!("field `{key}`")),
    )
    .unwrap_or_else(|_| panic!("field `{key}` exceeds u32"))
}

/// Satoshis from a decoded coin amount.
///
/// The daemon prints `value` as a JSON float. Fixtures carry exact 8-decimal
/// values so this round-trips, but the float stops here: it must never reach a
/// library crate, where money is integers only.
#[allow(
    clippy::cast_possible_truncation,
    reason = "fixture amounts are far below 2^53; this is test-only parsing of daemon JSON"
)]
fn coins_to_sats(coins: f64) -> i64 {
    (coins * 1e8).round() as i64
}

/// A shielded spend, in wire order.
pub struct Spend {
    cv: [u8; 32],
    anchor: [u8; 32],
    nullifier: [u8; 32],
    rk: [u8; 32],
    proof: Vec<u8>,
    auth_sig: [u8; 64],
}

impl Spend {
    /// The form hashed into the sighash: no spend-auth signature (320 bytes).
    pub fn sighash_description(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.cv);
        out.extend_from_slice(&self.anchor);
        out.extend_from_slice(&self.nullifier);
        out.extend_from_slice(&self.rk);
        out.extend_from_slice(&self.proof);
        out
    }

    /// The form serialized into the transaction: with the signature (384 bytes).
    pub fn wire_description(&self) -> Vec<u8> {
        let mut out = self.sighash_description();
        out.extend_from_slice(&self.auth_sig);
        out
    }
}

/// A decoded daemon transaction plus the pieces the sighash needs.
pub struct Decoded {
    /// The transaction, with shielded spends in their *wire* form.
    pub tx: TxV4,
    /// Spends, kept separately because the sighash needs a different encoding.
    pub spends: Vec<Spend>,
}

impl Decoded {
    /// The transaction with spends re-encoded for hashing rather than serializing.
    pub fn for_sighash(&self) -> TxV4 {
        let mut tx = self.tx.clone();
        tx.shielded_spends = self.spends.iter().map(Spend::sighash_description).collect();
        tx
    }
}

/// Parse a `decoderawtransaction` decode into a transaction we can serialize.
pub fn decode(decoded: &Value) -> Decoded {
    let inputs = decoded["vin"]
        .as_array()
        .map(|vin| {
            vin.iter()
                .map(|input| {
                    let mut txid = array32(input, "txid");
                    txid.reverse(); // display order → wire order
                    TxIn {
                        txid_internal: txid,
                        vout: u32_at(input, "vout"),
                        sequence: u32_at(input, "sequence"),
                        script_sig: bytes(&input["scriptSig"], "hex"),
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let outputs = decoded["vout"]
        .as_array()
        .map(|vout| {
            vout.iter()
                .map(|output| TxOut {
                    value: u64::try_from(coins_to_sats(
                        output["value"].as_f64().expect("vout.value"),
                    ))
                    .expect("output value is non-negative"),
                    script_pubkey: bytes(&output["scriptPubKey"], "hex"),
                })
                .collect()
        })
        .unwrap_or_default();

    let spends: Vec<Spend> = decoded["vShieldedSpend"]
        .as_array()
        .map(|spends| {
            spends
                .iter()
                .map(|spend| Spend {
                    cv: array32_reversed(spend, "cv"),
                    anchor: array32_reversed(spend, "anchor"),
                    nullifier: array32_reversed(spend, "nullifier"),
                    rk: array32_reversed(spend, "rk"),
                    proof: bytes(spend, "proof"),
                    auth_sig: array64(spend, "spendAuthSig"),
                })
                .collect()
        })
        .unwrap_or_default();

    let shielded_outputs = decoded["vShieldedOutput"]
        .as_array()
        .map(|outs| {
            outs.iter()
                .map(|out| {
                    let mut description = Vec::with_capacity(948);
                    description.extend_from_slice(&array32_reversed(out, "cv"));
                    description.extend_from_slice(&array32_reversed(out, "cmu"));
                    description.extend_from_slice(&array32_reversed(out, "ephemeralKey"));
                    description.extend_from_slice(&bytes(out, "encCiphertext"));
                    description.extend_from_slice(&bytes(out, "outCiphertext"));
                    description.extend_from_slice(&bytes(out, "proof"));
                    description
                })
                .collect()
        })
        .unwrap_or_default();

    let binding_sig = decoded
        .get("bindingSig")
        .and_then(Value::as_str)
        .map(|_| array64(decoded, "bindingSig"));

    Decoded {
        tx: TxV4 {
            inputs,
            outputs,
            lock_time: decoded
                .get("locktime")
                .and_then(Value::as_u64)
                .map_or(0, |v| u32::try_from(v).expect("locktime exceeds u32")),
            expiry_height: u32_at(decoded, "expiryheight"),
            value_balance: coins_to_sats(decoded["valueBalance"].as_f64().expect("valueBalance")),
            shielded_spends: spends.iter().map(Spend::wire_description).collect(),
            shielded_outputs,
            binding_sig,
        },
        spends,
    }
}
