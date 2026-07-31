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

/// **What an output holds, checked against the daemon's own reader.**
///
/// Two claims in `verus_tx::decode` rest on the chain's behaviour rather than
/// on anything this workspace can prove to itself, and both were originally
/// settled by reading `CScript::ReserveOutValue` in VerusCoin's
/// `src/script/script.cpp`. Reading source is evidence; asking the daemon is
/// proof, and `decodescript` gives it for free — it parses a script and reports
/// the currency it finds, with no transaction, no inputs and no broadcast.
///
/// 1. A reserve output paying an **identity** holds exactly the currency its
///    payload says, and the daemon names the `i` address. The decoder used to
///    refuse this shape outright, which made a VerusID's holdings uncountable.
/// 2. A **stakeguard** output — eval code 1, what a proof-of-stake coinbase
///    pays — holds no currency at all. That is what lets `token_balances`
///    count it as zero instead of refusing a staker a balance, and it is the
///    claim with the most riding on it: counting a currency-bearing output as
///    zero would under-report someone's money.
#[test]
fn the_daemon_agrees_about_what_each_output_shape_holds() {
    if !live() {
        eprintln!("skipping: set VERUS_LIVE_RPC=1 to run against {ENDPOINT}");
        return;
    }

    // shylock@ on VRSCTEST, and an identity that exists there.
    let currency = verus_tx::CurrencyId::from_bytes(
        "iQihXUcQt8G9TSh58YoM5NRwC1nAyoazFR"
            .parse::<verus_keys::Address>()
            .expect("i-address")
            .hash(),
    );
    let identity = "i6api8faWPZjATwXGSuXZvsv5AtXN689KH";
    let script = verus_tx::cc::reserve_output_script_to(
        verus_tx::Destination::Identity(
            identity.parse::<verus_keys::Address>().expect("id").hash(),
        ),
        currency,
        40_000_000,
    )
    .expect("reserve script");

    let decoded = probe("decodescript", &format!("[\"{}\"]", hex::encode(&script)));
    let result = &decoded["result"];
    assert_eq!(
        result["addresses"][0].as_str(),
        Some(identity),
        "the daemon must see the identity as the destination: {decoded}"
    );
    assert_eq!(
        result["reserveoutput"]["currencyvalues"]["iQihXUcQt8G9TSh58YoM5NRwC1nAyoazFR"].as_f64(),
        Some(0.4),
        "the daemon must read the same token value out of it: {decoded}"
    );

    // And this crate must read it the same way.
    assert!(matches!(
        verus_tx::decode_output_script(&script),
        Ok(verus_tx::OutputKind::ReserveOutput { .. })
    ));

    // Block 1170103 on VRSCTEST, coinbase vout 0 — a real proof-of-stake
    // coinbase's stakeguard output.
    let stakeguard = "3d04030001021504d72c764548836ae9e1784b54afed2c1f1061bd532103166b7813a4855\
                      a88e9ef7340a692ef3c2decedfdc2c7563ec79537e89667d935cc4c8704030101011504d7\
                      2c764548836ae9e1784b54afed2c1f1061bd5343010000a659dcb60845f0ea2f48a9a5513\
                      cd90ab986fd670d8644f52fcc153478260efdd114a32487649aababf8c747cb6733b6c69d\
                      a63362cd6f226fead87401000000270403010101210316 6b7813a4855a88e9ef7340a692\
                      ef3c2decedfdc2c7563ec79537e89667d93575"
        .replace(' ', "");
    let decoded = probe("decodescript", &format!("[\"{stakeguard}\"]"));
    let result = &decoded["result"];
    assert!(
        result["stakeguard"].is_string(),
        "this is meant to be a stakeguard output: {decoded}"
    );
    // The absence is the whole point: no `reserveoutput`, no `reserve_balance`.
    // If a daemon upgrade ever starts reporting currency here, `token_balances`
    // is under-counting a staker and this must fail.
    assert!(
        result["reserveoutput"].is_null() && result["reserve_balance"].is_null(),
        "a stakeguard output is supposed to hold no currency: {decoded}"
    );
    assert!(!verus_tx::may_carry_currency(1));
}

/// **Multi-currency outputs and name commitments, against the daemon's reader.**
///
/// The scripts are real and their expected contents are not written down here
/// — they are read back out of the same node. That is the difference between
/// a fixture, which is frozen at the day it was captured, and an oracle: if a
/// daemon upgrade changes what these bytes mean, this fails.
///
/// The multi-currency one matters most. Misreading a `CCurrencyValueMap` does
/// not throw — the amount is a fixed eight-byte `int64` and the currency ids
/// are opaque, so reading it as a VARINT would report a plausible balance in
/// currencies that do not exist.
#[test]
fn the_daemon_agrees_about_multi_currency_outputs_and_commitments() {
    if !live() {
        eprintln!("skipping: set VERUS_LIVE_RPC=1 to run against {ENDPOINT}");
        return;
    }
    let client = client();

    for (txid, vout) in [
        // Nine currencies in one output.
        (
            "9d0859212eb5dd5bbcd5d8a171e8e0080e16d5629ed84bd596573aae9b086443",
            10usize,
        ),
        // An ordinary name commitment.
        (
            "3a6f6a02f2fb74dc16a5e9d49cb02966100a72656acd30d9c28d5eae554edaca",
            0,
        ),
    ] {
        let transaction = client.raw_transaction(txid).expect("getrawtransaction");
        let output = &transaction["vout"][vout];
        let script = hex::decode(
            output["scriptPubKey"]["hex"]
                .as_str()
                .expect("a script in hex"),
        )
        .expect("hex");

        // Whatever the daemon says this output holds, keyed by i-address and
        // in coins. Both shapes report it, under different keys.
        let reported = output["scriptPubKey"]["reserveoutput"]["currencyvalues"]
            .as_object()
            .or_else(|| output["scriptPubKey"]["commitmenthash"]["currencyvalues"].as_object())
            .unwrap_or_else(|| panic!("{txid}:{vout} reports no currency values"));

        let decoded = verus_tx::decode_output_script(&script).expect("decodes");
        let tokens = match &decoded {
            verus_tx::OutputKind::ReserveOutput { tokens, .. }
            | verus_tx::OutputKind::IdentityCommitment { tokens, .. } => tokens.clone(),
            other => panic!("{txid}:{vout} decoded as {other:?}"),
        };

        assert_eq!(
            tokens.len(),
            reported.len(),
            "{txid}:{vout}: {} currencies read, {} reported\n{decoded:?}",
            tokens.len(),
            reported.len()
        );
        for (currency, amount) in &tokens {
            let id =
                verus_keys::Address::new(verus_keys::AddressKind::Identity, currency.to_bytes())
                    .to_string();
            let theirs = reported
                .get(&id)
                .and_then(serde_json::Value::as_f64)
                .unwrap_or_else(|| panic!("{txid}:{vout}: the daemon reports nothing for {id}"));
            // Coins, so the comparison is against the figure a person sees.
            // The daemon's JSON is a float; one satoshi of tolerance is the
            // honest allowance for that, not for our own arithmetic.
            #[allow(clippy::cast_precision_loss)] // -- compared with a tolerance
            let ours = *amount as f64 / 100_000_000.0;
            assert!(
                (ours - theirs).abs() < 1e-8,
                "{txid}:{vout}: {id} read as {ours} and reported as {theirs}"
            );
        }
        eprintln!(
            "{txid}:{vout}: daemon agrees on {} currencies",
            tokens.len()
        );
    }

    // The sentinel that decides whether a commitment carries currency at all,
    // against the node that issues it.
    let issued = probe(
        "getvdxfid",
        "[\"vrsc::system.identity.advancedcommitmenthash\"]",
    );
    assert_eq!(
        issued["result"]["vdxfid"].as_str(),
        Some(
            verus_keys::Address::new(
                verus_keys::AddressKind::Identity,
                verus_tx::ADVANCED_COMMITMENT_KEY
            )
            .to_string()
            .as_str()
        ),
        "the advanced commitment key is not the one this node issues: {issued}"
    );
}

/// **Reserve transfers and deposits, against the daemon's own reader.**
///
/// These two are the ones where a decoding mistake does not throw. Their
/// payloads are a chain of fields with a variable-length destination in the
/// middle, so a misread does not fail where it happens — it fails several
/// fields later on a "currency id" that is really the tail of an address, and
/// produces a plausible answer about a currency nobody has ever held.
///
/// So rather than pin a fixture, this scans recent blocks for whatever real
/// examples exist and checks every field of each against the daemon's own
/// `reservetransfer` / `reservedeposit` object. Scanning rather than naming a
/// txid also means it keeps working: these outputs are common on VRSCTEST and
/// a pinned one would eventually be spent out of easy reach.
#[test]
fn the_daemon_agrees_about_reserve_transfers_and_deposits() {
    if !live() {
        eprintln!("skipping: set VERUS_LIVE_RPC=1 to run against {ENDPOINT}");
        return;
    }
    let client = client();
    let tip = client.block_count().expect("getblockcount");

    let mut transfers = 0;
    let mut deposits = 0;
    // How far back to look for fresh material.
    //
    // This was twelve, on the evidence that the first probe found one of each
    // in the first two blocks. That did not hold: on 2026-07-31 neither the
    // last twelve blocks of VRSCTEST nor the last **250** carried either kind.
    // The test failed on a quiet chain rather than on a defect — in a
    // *scheduled* job, where a false alarm is expensive because it trains you
    // to ignore the real one.
    //
    // So scanning cannot be the only source. It is kept, because fresh data is
    // what catches schema drift and a pinned vector never will; but when the
    // chain has been quiet it falls back to two transactions that are known to
    // carry one of each. Spent outputs still read fine through
    // `getrawtransaction`, so pinning them is stable in a way that pinning an
    // *unspent* outpoint would not be.
    //
    // What is deliberately NOT done is softening the assertion below. A scan
    // that finds nothing must fail rather than pass vacuously; the fix is to
    // give it something real to check, not to accept an empty result.
    const SCAN_BLOCKS: u32 = 60;
    const PINNED: [&str; 2] = [
        // A reserve transfer, block 1170450.
        "18273a8f0722753c3103d7fd253c32985ee5047b97aea85f271d822a0a974bf3",
        // A reserve deposit, block 1170449.
        "1b6817f2b573afefbed5d3eb7c10576765a4a9eb86ea256baffcb2aebb3633dc",
    ];

    let mut candidates: Vec<String> = Vec::new();
    for height in (tip.saturating_sub(SCAN_BLOCKS)..=tip).rev() {
        let block = probe("getblock", &format!("[{height}]"));
        if let Some(txids) = block["result"]["tx"].as_array() {
            candidates.extend(txids.iter().filter_map(|t| t.as_str().map(str::to_string)));
        }
    }
    let scanned = candidates.len();
    candidates.extend(PINNED.iter().map(|t| (*t).to_string()));

    {
        for txid in &candidates {
            let txid = txid.as_str();
            let transaction = client.raw_transaction(txid).expect("getrawtransaction");
            for output in transaction["vout"].as_array().unwrap_or(&Vec::new()) {
                let script_json = &output["scriptPubKey"];
                let reported = if script_json["reservetransfer"].is_object() {
                    transfers += 1;
                    &script_json["reservetransfer"]
                } else if script_json["reservedeposit"].is_object() {
                    deposits += 1;
                    &script_json["reservedeposit"]
                } else {
                    continue;
                };

                let script = hex::decode(script_json["hex"].as_str().expect("hex")).expect("hex");
                let decoded = verus_tx::decode_output_script(&script)
                    .unwrap_or_else(|e| panic!("{txid}:{} did not decode: {e}", output["n"]));
                let where_ = format!("{txid}:{}", output["n"]);

                // Whatever it is, the currency map has to match.
                let tokens = match &decoded {
                    verus_tx::OutputKind::ReserveTransfer { transfer, .. } => {
                        assert_eq!(
                            transfer.flags,
                            reported["flags"].as_u64().expect("flags"),
                            "{where_}: flags"
                        );
                        assert_eq!(
                            transfer.fee_currency,
                            currency_of(reported["feecurrencyid"].as_str().expect("fee currency")),
                            "{where_}: fee currency"
                        );
                        transfer.tokens.clone()
                    }
                    verus_tx::OutputKind::ReserveDeposit {
                        controlling_currency,
                        tokens,
                        ..
                    } => {
                        assert_eq!(
                            *controlling_currency,
                            currency_of(
                                reported["controllingcurrencyid"]
                                    .as_str()
                                    .expect("controlling currency")
                            ),
                            "{where_}: controlling currency"
                        );
                        tokens.clone()
                    }
                    other => panic!("{where_} decoded as {other:?}"),
                };

                let values = reported["currencyvalues"]
                    .as_object()
                    .unwrap_or_else(|| panic!("{where_}: no currencyvalues"));
                assert_eq!(tokens.len(), values.len(), "{where_}: currency count");
                for (currency, amount) in &tokens {
                    let id = verus_keys::Address::new(
                        verus_keys::AddressKind::Identity,
                        currency.to_bytes(),
                    )
                    .to_string();
                    let theirs = values
                        .get(&id)
                        .and_then(serde_json::Value::as_f64)
                        .unwrap_or_else(|| panic!("{where_}: nothing reported for {id}"));
                    #[allow(clippy::cast_precision_loss)] // -- compared with a tolerance
                    let ours = *amount as f64 / 100_000_000.0;
                    assert!(
                        (ours - theirs).abs() < 1e-8,
                        "{where_}: {id} read as {ours}, reported as {theirs}"
                    );
                }
                eprintln!("{where_}: daemon agrees");
            }
            if transfers > 0 && deposits > 0 {
                break;
            }
        }
    }
    eprintln!("  {scanned} transactions scanned from the last {SCAN_BLOCKS} blocks");

    // A scan that found nothing would pass while proving nothing.
    assert!(
        transfers > 0 && deposits > 0,
        "found {transfers} transfers and {deposits} deposits across {} scanned and pinned \
         transactions; this test proves nothing unless it sees at least one of each",
        candidates.len()
    );
}

fn currency_of(address: &str) -> verus_tx::CurrencyId {
    verus_tx::CurrencyId::from_bytes(
        address
            .parse::<verus_keys::Address>()
            .expect("i-address")
            .hash(),
    )
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

/// The daemon's own reading of a token-demand order.
///
/// This composition — a maker demanding a token, a taker paying it from a
/// reserve input with a CryptoCondition fulfillment and taking the surplus back
/// as change — is the one entry in `PROVEN.md` with no oracle behind it: the
/// TypeScript SDK has no offers, so there are no bytes to be identical to, and
/// the settled order at `92fc291c` had native legs only.
///
/// A settlement needs two funded keys and is gated separately in
/// `verus-flows`. This is what can be had *without* funds, and it is not
/// nothing: `decoderawtransaction` parses without checking that the inputs
/// exist, so the whole transaction can be built from invented outpoints and the
/// daemon still has to agree about what every output holds. If our reserve
/// encoding were wrong, the currency ids or the amounts below would not match.
///
/// What it does NOT prove: that the signatures verify, or that the network
/// accepts it. Those need the settlement.
#[test]
fn the_daemon_reads_a_token_demand_the_way_we_built_it() {
    if !live() {
        eprintln!("skipping: set VERUS_LIVE_RPC=1 to run against {ENDPOINT}");
        return;
    }
    use std::str::FromStr;
    use verus_tx::offer::{
        make_offer, offer_funding_script, take_offer, OfferParams, TakeParams, Wanted,
    };
    use verus_tx::{Amount, CurrencyId, Expiry, Txid, Utxo};

    // `sdkcuralpha` on VRSCTEST — a currency that really exists, so the daemon
    // resolves it by name and a wrong id would show up as a different one
    // rather than as a blob it echoes back.
    const SDKCURALPHA: &str = "i7UCaJkKRFXBCK4S1AMrkfKTnPwdLc7dV7";
    let currency =
        CurrencyId::from_bytes(verus_keys::Address::from_str(SDKCURALPHA).unwrap().hash());

    let maker = verus_keys::PrivateKey::from_bytes(&[0x21; 32], true).unwrap();
    let taker = verus_keys::PrivateKey::from_bytes(&[0x22; 32], true).unwrap();

    let offered = Amount::from_sat(1_00000000);
    let wanted = Amount::from_sat(2_00000000);
    let held = Amount::from_sat(3_00000000);

    let funding = Utxo {
        txid: Txid::from_internal([0x71; 32]),
        vout: 0,
        satoshis: offered,
        script_pubkey: offer_funding_script(maker.address().hash()).unwrap(),
    };
    let offer = make_offer(
        &maker,
        &OfferParams::new(
            &funding,
            Wanted::Token {
                currency,
                amount: wanted,
                recipient: maker.address().hash(),
            },
            Expiry::AtHeight(1_200_000),
        ),
    )
    .expect("make a token offer");

    let utxos = [
        // The token, as a reserve output the taker controls.
        Utxo {
            txid: Txid::from_internal([0x72; 32]),
            vout: 1,
            satoshis: Amount::ZERO,
            script_pubkey: verus_tx::cc::reserve_output_script(
                taker.address().hash(),
                currency,
                held.to_sat(),
            )
            .unwrap(),
        },
        // Native, to pay the miner fee.
        Utxo {
            txid: Txid::from_internal([0x73; 32]),
            vout: 0,
            satoshis: Amount::from_sat(1_00000000),
            script_pubkey: taker.address().p2pkh_script_pubkey().unwrap(),
        },
    ];
    let raw = take_offer(
        &taker,
        &TakeParams::new(
            &offer.hex,
            &utxos,
            taker.address().hash(),
            taker.address(),
            offered,
            10_000,
        ),
    )
    .expect("take the token offer");

    let decoded = probe(
        "decoderawtransaction",
        &format!("[\"{}\"]", hex::encode(&raw)),
    );
    let result = &decoded["result"];
    assert!(
        !result.is_null(),
        "the daemon refused to parse our token demand: {decoded}"
    );

    // Every currency amount the daemon sees, per output.
    let seen: Vec<Option<f64>> = result["vout"]
        .as_array()
        .expect("vout")
        .iter()
        .map(|out| {
            out["scriptPubKey"]["reserveoutput"]["currencyvalues"][SDKCURALPHA]
                .as_f64()
                .or_else(|| out["scriptPubKey"]["currencyvalues"][SDKCURALPHA].as_f64())
        })
        .collect();
    eprintln!("  daemon sees per-output {SDKCURALPHA}: {seen:?}");

    // Output 0 is the maker's demand and must carry exactly what was asked. It
    // is the output their signature commits to, so a mismatch here is not a
    // rounding detail — it is the trade being for the wrong amount.
    assert_eq!(
        seen[0],
        Some(2.0),
        "the daemon must see the demanded amount in output 0: {result}"
    );

    // Tokens in must equal tokens out. The surplus rides in a change output,
    // and anything unaccounted for is burned.
    let total: f64 = seen.iter().flatten().sum();
    assert!(
        (total - 3.0).abs() < 1e-8,
        "three tokens went in, so the daemon must see three come out, saw {total}: {result}"
    );

    eprintln!("  daemon agrees: 2 demanded + 1 change, from a 3-token input");
}

/// The address index still reports what `fixtures/rpc/getaddressdeltas.json`
/// froze, and still reports it the same way.
///
/// This is the drift half of the pair. The fixture proves the parser handles
/// the bytes; only a live run notices a daemon that renames `currencyvalues`,
/// stops signing `satoshis`, or starts quoting either — none of which the
/// frozen copy could ever fail on.
///
/// Pinned against a settled transaction rather than "whatever is recent", so it
/// cannot go quiet the way the earlier reserve-transfer scan did when the last
/// N blocks happened to hold nothing of interest.
#[test]
fn the_address_index_still_reports_signed_movements() {
    if !live() {
        eprintln!("skipping: set VERUS_LIVE_RPC=1 to run against {ENDPOINT}");
        return;
    }

    const TAKER: &str = "RGRTws8PJQC5oBqftKMCAaBD1Vj5MHKKSz";
    const TOKEN: &str = "i7UCaJkKRFXBCK4S1AMrkfKTnPwdLc7dV7";

    let deltas = client()
        .address_deltas(&[TAKER], Some((1_170_740, 1_170_760)))
        .expect("getaddressdeltas");
    assert_eq!(deltas.len(), 7, "the settled swap and its funding");

    // A spend is negative. If the daemon ever reports magnitudes instead, a
    // wallet built on this shows every payment out as a payment in.
    let spends: Vec<_> = deltas.iter().filter(|d| d.spending).collect();
    assert!(!spends.is_empty(), "the swap spends outputs");
    assert!(
        spends.iter().any(|d| d.satoshis.is_negative()),
        "a native spend must carry its sign"
    );

    // The token side of the settlement: 5 in, 5 spent, 4 back as change.
    let token: i64 = deltas
        .iter()
        .filter_map(|d| d.currency_values.get(TOKEN))
        .map(|v| v.to_sat())
        .sum();
    assert_eq!(token, 400_000_000, "4 sdkcuralpha left after paying 1");

    eprintln!("{} deltas, token nets to {token} sats", deltas.len());
}
