//! Agreement with a live Verus daemon.
//!
//! The differential vectors prove we match the TypeScript SDK. This proves the
//! bytes are what the *network* thinks they are: a real daemon parses each
//! transaction and computes the same transaction id, output count and expiry.
//!
//! It also serves a second purpose that a fixture cannot — **schema drift**. The
//! recorded replies in `fixtures/rpc/` are frozen at the day they were captured,
//! so a daemon upgrade that renames a field passes every offline test and fails
//! in a consumer's wallet. Running these against the live endpoint on a schedule
//! is how that gets noticed.
//!
//! **Opt-in, in two separate steps, because they carry different risk:**
//!
//! ```sh
//! # Read-only. Decodes and queries; changes nothing anywhere.
//! VERUS_LIVE_RPC=1 cargo test -p verus-rpc --test live_daemon -- --nocapture
//! ```
//!
//! There is deliberately no broadcast here. `decoderawtransaction` only parses:
//! it neither checks that the inputs exist nor relays anything. The vectors
//! spend invented outpoints, which is fine for a decode and would be rejected by
//! a real broadcast.
//!
//! This test lives in `verus-rpc` rather than `verus-tx` because this is the
//! crate that is *allowed* to open a socket. It previously shelled out to
//! `curl`, for exactly that reason; here it uses the real client, so the
//! transport is under test alongside the bytes.

use serde_json::Value;
use verus_rpc::{ChainReader, HttpTransport, RpcClient};

const ENDPOINT: &str = "https://api.verustest.net";

/// Whether the caller asked for network access.
///
/// Accepts the older `VERUS_LIVE_DECODE` too, so anyone with it in their shell
/// history is not silently skipped.
fn live() -> bool {
    std::env::var("VERUS_LIVE_RPC").is_ok() || std::env::var("VERUS_LIVE_DECODE").is_ok()
}

fn client() -> RpcClient<HttpTransport> {
    RpcClient::new(HttpTransport::new(ENDPOINT).expect("https endpoint"))
}

fn vectors() -> Vec<Value> {
    let path = format!(
        "{}/../../fixtures/transparent/vectors.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let parsed: Value = serde_json::from_str(&raw).expect("valid JSON");
    parsed["vectors"].as_array().expect("vectors").clone()
}

#[test]
fn the_daemon_computes_the_same_txid_for_every_vector() {
    if !live() {
        eprintln!("skipping: set VERUS_LIVE_RPC=1 to run against {ENDPOINT}");
        return;
    }
    let client = client();

    for vector in vectors() {
        let name = vector["name"].as_str().expect("name");
        let decoded = client
            .decode_raw_transaction(vector["expected_signed_hex"].as_str().expect("hex"))
            .unwrap_or_else(|e| panic!("{name}: {e}"));

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

        // The txid is a hash over every output, so the assertion above already
        // pins the output set exactly. What is worth checking separately is
        // that the daemon sees at least the recipients — a readable failure if
        // a vector and its hex ever drift apart.
        //
        // Recomputing the exact count from the vector is deliberately not done:
        // a token transfer carries *token* change as well as native change, so
        // "recipients + 1" is wrong for it, and encoding that arithmetic here
        // duplicates the builder's logic in the one place that should be
        // checking it from outside.
        let recipients = vector["outputs"].as_array().expect("outputs").len();
        let vouts = decoded["vout"].as_array().map(Vec::len).unwrap_or(0);
        assert!(
            vouts >= recipients,
            "{name}: {vouts} outputs for {recipients} recipients"
        );

        eprintln!("{name}: daemon agrees (txid {})", decoded["txid"]);
    }
}

/// Every recorded fixture still parses when it comes off the live wire.
///
/// This is the drift check. A frozen fixture proves the parser handled the
/// bytes of 2026-07-29; only the live endpoint proves it handles today's.
#[test]
fn every_typed_read_still_parses_from_the_live_endpoint() {
    if !live() {
        eprintln!("skipping: set VERUS_LIVE_RPC=1 to run against {ENDPOINT}");
        return;
    }
    let client = client();

    let info = client.chain_info().expect("getinfo");
    assert_eq!(info.name, "VRSCTEST");
    eprintln!("chain: {} at {}", info.name, info.blocks);

    let tip = client.block_count().expect("getblockcount");
    assert!(tip > 1_000_000);
    let hash = client.block_hash(tip).expect("getblockhash");
    eprintln!("tip: {tip} {hash}");

    // The money field this whole crate is shaped around. If a daemon upgrade
    // changes how it is reported, this is where it surfaces.
    let policy = client.currency("VRSCTEST").expect("getcurrency");
    eprintln!(
        "registration fee: {} ({} referral levels)",
        policy.id_registration_fee.to_coins_string(),
        policy.id_referral_levels
    );
    assert!(policy.id_registration_fee.to_sat() > 0);

    // An identity this SDK registered, read back through the typed path.
    let identity = client.identity("rustsdk@").expect("getidentity");
    assert_eq!(identity.fully_qualified_name, "rustsdk.VRSCTEST@");
    assert!(!identity.is_revoked());

    let address = "RJUgxvDnDLsRGCXNKDK56Rxngzh6m25J6F";
    let utxos = client.address_utxos(&[address]).expect("getaddressutxos");
    let balance = client
        .address_balance(&[address])
        .expect("getaddressbalance");
    eprintln!(
        "{} utxos, balance {}",
        utxos.len(),
        balance.balance.to_coins_string()
    );

    // The two reads must agree about the same coins: every UTXO summed is the
    // balance. A mismatch means one of the two money paths is misreading.
    let summed: u64 = utxos.iter().map(|u| u.utxo.satoshis.to_sat()).sum();
    assert_eq!(summed, balance.balance.to_sat());
}

/// What a public endpoint actually serves, and the trap in finding out.
///
/// **`-32601` from this endpoint does not mean the method is missing.** The
/// allowlist in front of it is *arity-sensitive*: `getblock` with one parameter
/// is served, and `getblock` with a verbosity argument is refused as "Method not
/// found". Probing with the wrong argument count is how a method gets recorded
/// as unavailable when it is not — which is exactly what happened here.
///
/// The corrected picture:
///
/// * `getblock(height|hash)` — **served**, with the block's `tx` list and
///   `finalsaplingroot`. Add a verbosity argument and it is refused.
/// * `getrawtransaction(txid, 1)` — served, including `vShieldedOutput`.
/// * `z_gettreestate` — genuinely absent at any arity.
/// * `getsaplingtree` — answers, but only for the chain tip; it ignores the
///   height argument.
///
/// So a block's Sapling commitments **are** enumerable here, via `getblock` then
/// `getrawtransaction` per transaction. What is not directly available is the
/// frontier *before* a historical block: `z_gettreestate` is gone and
/// `getsaplingtree` only knows the tip. That has to be folded up from the
/// commitments themselves, which is the job lightwalletd exists to do cheaply.
/// The blocker for shielded is therefore cost, not capability.
#[test]
fn the_endpoints_allowlist_is_arity_sensitive() {
    if !live() {
        eprintln!("skipping: set VERUS_LIVE_RPC=1 to run against {ENDPOINT}");
        return;
    }

    // The same method, two argument counts, two different answers.
    let one_arg = probe("getblock", "[1166308]");
    assert!(
        one_arg["result"]["finalsaplingroot"].is_string(),
        "getblock with one argument should be served: {one_arg}"
    );
    assert!(
        one_arg["result"]["tx"]
            .as_array()
            .is_some_and(|tx| !tx.is_empty()),
        "getblock should list the block's transactions"
    );

    let two_args = probe("getblock", "[1166308,1]");
    assert_eq!(
        two_args["error"]["code"].as_i64(),
        Some(-32601),
        "getblock with a verbosity argument should be refused: {two_args}"
    );
    eprintln!("getblock: served with 1 argument, -32601 with 2");

    // Genuinely absent, at any arity.
    for params in [
        "[1166307]",
        r#"["0000000236aeff3b95da1f1a6ca0def3edfff2a5a2cc1b5ee0923b1842c77dc6"]"#,
    ] {
        let answer = probe("z_gettreestate", params);
        assert_eq!(
            answer["error"]["code"].as_i64(),
            Some(-32601),
            "z_gettreestate is now available: {answer}"
        );
    }
    eprintln!("z_gettreestate: absent at every arity");

    // Answers, but only ever about the tip — the limit that is easy to miss,
    // because the call succeeds.
    let tree = probe("getsaplingtree", "[1166308]");
    let height = tree["result"][0]["height"].as_u64().expect("a tree");
    eprintln!("getsaplingtree(1166308) answered for height {height}");
    assert!(
        height > 1_166_308,
        "getsaplingtree now honours a historical height — a frontier is directly reachable"
    );
}

/// A block's Sapling commitments are reachable here, contrary to the earlier
/// finding. This walks the path a witness builder would take.
#[test]
fn a_blocks_sapling_commitments_can_be_enumerated() {
    if !live() {
        eprintln!("skipping: set VERUS_LIVE_RPC=1 to run against {ENDPOINT}");
        return;
    }
    let client = client();

    // The block one of this session's shielded notes was mined in.
    let block = probe("getblock", "[1166308]");
    let txids: Vec<String> = block["result"]["tx"]
        .as_array()
        .expect("tx list")
        .iter()
        .map(|t| t.as_str().expect("txid").to_string())
        .collect();

    let mut commitments = Vec::new();
    for txid in &txids {
        let tx = client.raw_transaction(txid).expect("getrawtransaction");
        for output in tx["vShieldedOutput"].as_array().unwrap_or(&Vec::new()) {
            commitments.push(output["cmu"].as_str().expect("cmu").to_string());
        }
    }

    eprintln!(
        "block 1166308: {} transactions, {} sapling commitments",
        txids.len(),
        commitments.len()
    );
    assert!(
        !commitments.is_empty(),
        "this block is known to contain shielded outputs"
    );
    // The header commits to the tree after this block, which is what a witness
    // built from these commitments must reproduce.
    assert!(block["result"]["finalsaplingroot"].is_string());
}

/// Ask the endpoint directly, for methods the typed client has no variant for.
///
/// Returns the whole envelope rather than a result, because for these probes the
/// error *is* the finding.
fn probe(method: &str, params: &str) -> Value {
    let body = format!(r#"{{"jsonrpc":"1.0","id":"probe","method":"{method}","params":{params}}}"#);
    let response = std::process::Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "30",
            "-H",
            "content-type: application/json",
            "--data-binary",
            &body,
            ENDPOINT,
        ])
        .output()
        .expect("curl is available");
    serde_json::from_slice(&response.stdout).expect("the endpoint returned JSON")
}
