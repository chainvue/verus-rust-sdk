//! Parsing bodies the live network actually produced.
//!
//! The fixtures under `fixtures/rpc/` are verbatim captures from
//! `api.verustest.net`, committed for the same reason `fixtures/daemon/` is: a
//! mock written from documentation tests my reading of the docs, not the wire.
//! Two of the bugs this crate is shaped around — a money field arriving as a
//! JSON float, and an error reply omitting `result` rather than nulling it —
//! are invisible unless the bytes are real.

use std::cell::RefCell;

use verus_rpc::{Broadcaster, ChainReader, RequestBody, RpcClient, RpcError, Transport};

/// Answers from a recorded body, and records what was asked.
///
/// Also the proof that [`Transport`] is a usable extension point: everything
/// here is reachable by an outside implementor, and composing a request is not.
struct Recorded {
    body: String,
    asked: RefCell<Vec<String>>,
}

impl Recorded {
    fn new(fixture: &str) -> Self {
        let path = format!(
            "{}/../../fixtures/rpc/{fixture}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        Recorded {
            body: std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}")),
            asked: RefCell::new(Vec::new()),
        }
    }
}

impl Transport for Recorded {
    fn post(&self, body: &RequestBody) -> Result<String, RpcError> {
        self.asked.borrow_mut().push(body.as_str().to_string());
        Ok(self.body.clone())
    }
}

fn client(fixture: &str) -> RpcClient<Recorded> {
    RpcClient::new(Recorded::new(fixture))
}

#[test]
fn reads_chain_info() {
    let info = client("getinfo").chain_info().unwrap();
    assert_eq!(info.name, "VRSCTEST");
    assert_eq!(info.chain_id, "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq");
    assert_eq!(info.blocks, 1_167_555);
    assert_eq!(info.longest_chain, 1_167_555);
    assert_eq!(info.version, "1.2.17");
}

/// The fixture this crate exists for.
///
/// `idregistrationfees` is `100.0` in the captured body — coins, as a JSON
/// float — while every builder takes satoshis. Reading it as a number and
/// multiplying by 1e8 is the float path the workspace bans; this asserts the
/// exact result instead.
#[test]
fn reads_the_registration_fee_from_a_float_literal_without_a_float() {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/rpc/getcurrency_vrsctest.json"
    ))
    .unwrap();
    assert!(
        raw.contains(r#""idregistrationfees":100.0"#),
        "the fixture no longer carries the float literal, so this test proves nothing"
    );

    let policy = client("getcurrency_vrsctest").currency("VRSCTEST").unwrap();
    assert_eq!(policy.name, "VRSCTEST");
    assert_eq!(policy.id_registration_fee.to_sat(), 100_00000000);
    assert_eq!(policy.id_referral_levels, 3);
    assert_eq!(policy.id_import_fee.to_sat(), 2_000_000);
    assert_eq!(policy.proof_protocol, 1);
}

/// The fee and the referral split, straight from the node's own policy — the
/// numbers a caller should see before spending a name commitment.
#[test]
fn the_registration_split_follows_the_currencys_own_policy() {
    let policy = client("getcurrency_vrsctest").currency("VRSCTEST").unwrap();

    let (outlay, referral) = verus_rpc::registration_cost(&policy, false);
    assert_eq!(referral.to_sat(), 0);
    assert_eq!(outlay.to_sat(), 100_00000000);

    // 3 levels: the registrant pays fee * (levels + 1) / (levels + 2).
    let (outlay, referral) = verus_rpc::registration_cost(&policy, true);
    assert_eq!(referral.to_sat(), 100_00000000 / 5);
    assert_eq!(outlay.to_sat(), 100_00000000 / 5 * 4);
}

#[test]
fn reads_unspent_outputs() {
    let utxos = client("getaddressutxos_funded")
        .address_utxos(&["RJUgxvDnDLsRGCXNKDK56Rxngzh6m25J6F"])
        .unwrap();
    assert_eq!(utxos.len(), 6);

    let first = &utxos[0];
    assert_eq!(first.utxo.vout, 1);
    assert_eq!(first.utxo.satoshis.to_sat(), 8_830_000);
    assert_eq!(first.height, 1_166_385);
    assert!(first.is_spendable);
    // Display order, as a user would paste it.
    assert_eq!(
        first.utxo.txid.to_display_hex(),
        "5e19de6d3f77b5e1f49ec92db23027d5f026db92004b026465a61bff8ab13d7e"
    );
    assert!(first.utxo.script_pubkey.starts_with(&[0x76, 0xa9, 0x14]));
}

/// An address with nothing is an ordinary answer, not an error. A client that
/// treats `[]` as a failure makes "you have no funds" indistinguishable from
/// "the node is broken".
#[test]
fn an_address_with_nothing_is_an_empty_list_not_an_error() {
    let utxos = client("getaddressutxos_empty")
        .address_utxos(&["RHFuSSCAdBCbWt7wxSJeEXphH8W9XNQYs1"])
        .unwrap();
    assert!(utxos.is_empty());
}

/// The clearest illustration of why [`verus_rpc`] has two money readers: this
/// one reply carries the **same** native balance twice — `112006615800` as
/// satoshis, and `1120.066158` as coins under the chain's own currency id.
/// Reading either field with the other's units is wrong by 1e8.
#[test]
fn a_balance_reports_the_same_money_in_two_units_and_both_read_exactly() {
    let balance = client("getaddressbalance")
        .address_balance(&["RJUgxvDnDLsRGCXNKDK56Rxngzh6m25J6F"])
        .unwrap();

    assert_eq!(balance.balance.to_sat(), 112_006_615_800);
    assert_eq!(balance.received.to_sat(), 2_186_125_143_800);

    // The native currency, reported in coins, must land on the same satoshis.
    let native = &balance.currency_balance["iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq"];
    assert_eq!(*native, balance.balance);

    // And the tokens this session minted, also in coins.
    assert_eq!(
        balance.currency_balance["i7UCaJkKRFXBCK4S1AMrkfKTnPwdLc7dV7"].to_sat(),
        150_00000000
    );
}

/// A node could answer with an output belonging to an address nobody asked
/// about. The sighash commits to the script, so the worst case is a rejected
/// transaction rather than a misdirected one — but failing here names the cause
/// instead of leaving a `-26` to be interpreted.
#[test]
fn an_output_for_an_address_we_did_not_ask_about_is_refused() {
    let wrong = client("getaddressutxos_funded").address_utxos(&["RSomeOtherAddress"]);
    match wrong {
        Err(RpcError::Unexpected(message)) => assert!(message.contains("not asked about")),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn reads_an_identity_and_the_output_holding_it() {
    let record = client("getidentity_rustsdk").identity("rustsdk@").unwrap();
    assert_eq!(record.fully_qualified_name, "rustsdk.VRSCTEST@");
    assert_eq!(
        record.identity_address,
        "iPYbC4ExJ7dRBZnpxq2LGXGgkWDQNQR48g"
    );
    assert_eq!(record.block_height, 1_166_566);
    assert!(!record.is_revoked());
    // The whole object stays reachable: an update has to rebuild every field,
    // and dropping the ones this crate does not model would silently clear them.
    assert!(record.identity.get("contentmap").is_some());
    assert_eq!(record.identity["minimumsignatures"], 1);
}

/// `-5` on `getidentity` means "no such identity", which is a *fact about the
/// chain*, not a failure. `confirmations` relies on the same code meaning "never
/// seen it", so the mapping has to be exact.
#[test]
fn an_unknown_identity_is_a_node_error_with_its_code_intact() {
    match client("err_notfound").identity("nosuchname@") {
        Err(RpcError::Node { code, message }) => {
            assert_eq!(code, -5);
            assert_eq!(message, "Identity not found");
        }
        other => panic!("expected -5, got {other:?}"),
    }
    // And the same code, on a transaction, is an answer rather than an error.
    assert_eq!(
        client("err_notfound")
            .confirmations("00".repeat(32).as_str())
            .unwrap(),
        None
    );
}

/// The reply to a broadcast the node would not decode. Surfacing the daemon's
/// own message verbatim matters: `-22` and `-26` need completely different
/// responses from a wallet.
#[test]
fn a_rejected_broadcast_keeps_the_daemons_own_message() {
    match client("err_baddecode").send_raw_transaction("not hex") {
        Err(RpcError::Node { code, message }) => {
            assert_eq!(code, -22);
            assert_eq!(message, "TX decode failed");
        }
        other => panic!("expected -22, got {other:?}"),
    }
}

/// A long help text, returned as an error message, must not be truncated or
/// swallowed — it is usually the only clue about which parameter was wrong.
#[test]
fn a_long_error_message_survives_intact() {
    match client("err_badparam").currency("") {
        Err(RpcError::Node { code, message }) => {
            assert_eq!(code, -1);
            assert!(message.len() > 200, "message was {} bytes", message.len());
            assert!(message.contains("getcurrency"));
        }
        other => panic!("expected -1, got {other:?}"),
    }
}

/// The failure that defines what this SDK can do on public infrastructure.
///
/// `getblock`, `z_gettreestate` and `getsaplingtree` all answer this way on
/// `api.verustest.net`, which is exactly why shielded flows cannot be served
/// there. It needs its own variant because the remedy — use another endpoint —
/// is nothing like the remedy for a node that said no.
#[test]
fn a_missing_method_is_distinguishable_from_a_refusal() {
    match client("err_methodmissing").raw_transaction("00".repeat(32).as_str()) {
        Err(RpcError::MethodUnavailable { method }) => assert_eq!(method, "getrawtransaction"),
        other => panic!("expected MethodUnavailable, got {other:?}"),
    }
    // And it must not be mistaken for "the node has never seen this
    // transaction", which would report a real outage as a missing payment.
    assert!(client("err_methodmissing")
        .confirmations("00".repeat(32).as_str())
        .is_err());
}

/// Every request this crate emits is one of the typed methods, addressed to a
/// node as JSON-RPC. Pinning the framing keeps a daemon-side parser change
/// visible.
#[test]
fn requests_name_their_method_and_nothing_else() {
    let client = client("getinfo");
    let _ = client.chain_info();
    let _ = client.block_count();

    let asked = client.transport().asked.borrow();
    assert_eq!(asked.len(), 2);
    assert!(asked[0].contains(r#""method":"getinfo""#));
    assert!(asked[1].contains(r#""method":"getblockcount""#));
    for body in asked.iter() {
        assert!(body.contains(r#""jsonrpc":"1.0""#));
    }
}
