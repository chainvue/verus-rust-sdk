//! Agreement with a live Verus daemon.
//!
//! The differential vectors prove we match the TypeScript SDK. This proves the
//! bytes are what the *network* thinks they are: a real daemon parses each
//! transaction and computes the same transaction id, output count and expiry.
//!
//! **Opt-in, because it needs the network:**
//!
//! ```sh
//! VERUS_LIVE_DECODE=1 cargo test -p verus-tx --test live_daemon -- --nocapture
//! ```
//!
//! `decoderawtransaction` only parses; it neither validates that the inputs
//! exist nor broadcasts anything. The vectors deliberately spend invented
//! outpoints, which is fine for a decode and would be rejected by a real
//! broadcast — proving a transaction *spends* correctly requires funded UTXOs
//! and is a separate, manual exercise.
//!
//! `curl` is used rather than an HTTP crate: a library that never opens a socket
//! should not carry an HTTP client as a dependency just so one optional test can
//! reach the internet.

use std::process::Command;

use serde_json::Value;

const ENDPOINT: &str = "https://api.verustest.net";

fn vectors() -> Vec<Value> {
    let path = format!(
        "{}/../../fixtures/transparent/vectors.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let parsed: Value = serde_json::from_str(&raw).expect("valid JSON");
    parsed["vectors"].as_array().expect("vectors").clone()
}

fn decode_via_daemon(hex: &str) -> Value {
    let request = serde_json::json!({
        "jsonrpc": "1.0",
        "id": "verus-rust-sdk",
        "method": "decoderawtransaction",
        "params": [hex],
    })
    .to_string();

    let output = Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "30",
            "-H",
            "Content-Type: application/json",
            "--data-binary",
            &request,
            ENDPOINT,
        ])
        .output()
        .expect("curl is available");
    assert!(output.status.success(), "curl failed: {:?}", output.status);

    let response: Value =
        serde_json::from_slice(&output.stdout).expect("daemon returned valid JSON");
    assert!(
        response["error"].is_null(),
        "daemon error: {}",
        response["error"]
    );
    response["result"].clone()
}

#[test]
fn the_daemon_computes_the_same_txid_for_every_vector() {
    if std::env::var("VERUS_LIVE_DECODE").is_err() {
        eprintln!("skipping: set VERUS_LIVE_DECODE=1 to run against {ENDPOINT}");
        return;
    }

    for vector in vectors() {
        let name = vector["name"].as_str().expect("name");
        let decoded = decode_via_daemon(vector["expected_signed_hex"].as_str().expect("hex"));

        assert_eq!(
            decoded["txid"].as_str(),
            vector["expected_txid"].as_str(),
            "{name}: the daemon computed a different transaction id"
        );
        assert_eq!(decoded["version"].as_u64(), Some(4), "{name}: not v4");
        assert_eq!(
            decoded["expiryheight"].as_u64(),
            vector["expiry_height"].as_u64(),
            "{name}: expiry height was not carried"
        );

        // Outputs = recipients, plus change when it was above dust.
        let recipients = vector["outputs"].as_array().expect("outputs").len();
        let change = vector["expected_change"].as_u64().expect("change");
        let expected_outputs = recipients + usize::from(change > 0);
        assert_eq!(
            decoded["vout"].as_array().map(Vec::len),
            Some(expected_outputs),
            "{name}: output count differs"
        );

        eprintln!("{name}: daemon agrees (txid {})", decoded["txid"]);
    }
}
