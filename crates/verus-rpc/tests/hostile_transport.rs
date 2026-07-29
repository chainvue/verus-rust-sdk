//! What a node says is untrusted input.
//!
//! A public endpoint is somebody else's process. It can be overloaded, half
//! upgraded, behind a proxy that answers with HTML, or simply lying. Every reply
//! below must produce an `Err` and none may panic — a panic in a wallet is a
//! crash in the middle of a payment, at the exact moment the user most needs an
//! error message.
//!
//! Same posture as `crates/verus-tx/tests/decoder_robustness.rs`, applied to the
//! one surface in this workspace that reads bytes it did not produce.

use verus_rpc::{Broadcaster, ChainReader, RequestBody, RpcClient, RpcError, Transport};

/// Answers every request with the same fixed text.
struct Canned(&'static str);

impl Transport for Canned {
    fn post(&self, _body: &RequestBody) -> Result<String, RpcError> {
        Ok(self.0.to_string())
    }
}

/// Fails before a reply ever arrives.
struct Broken;

impl Transport for Broken {
    fn post(&self, _body: &RequestBody) -> Result<String, RpcError> {
        Err(RpcError::Transport("connection reset".into()))
    }
}

fn client(reply: &'static str) -> RpcClient<Canned> {
    RpcClient::new(Canned(reply))
}

/// Every reply a node could plausibly return that is not a good one.
const HOSTILE: &[(&str, &str)] = &[
    ("empty body", ""),
    ("whitespace", "   \n  "),
    ("truncated json", r#"{"result":{"blocks":"#),
    (
        "html from a proxy",
        "<html><body>502 Bad Gateway</body></html>",
    ),
    ("a bare string", "\"hello\""),
    ("a bare number", "42"),
    ("json null", "null"),
    ("an array at the top level", "[1,2,3]"),
    ("no result and no error", r#"{"id":"x"}"#),
    ("result null", r#"{"result":null,"error":null,"id":"x"}"#),
    ("error without a code", r#"{"error":{"message":"nope"}}"#),
    ("error without a message", r#"{"error":{"code":-5}}"#),
    ("error as a string", r#"{"error":"nope"}"#),
    (
        "both result and error",
        r#"{"result":{"blocks":1},"error":{"code":-5,"message":"no"}}"#,
    ),
    (
        "result of the wrong type",
        r#"{"result":"not an object","id":"x"}"#,
    ),
    ("nested nulls", r#"{"result":{"name":null,"blocks":null}}"#),
    ("truncated mid-object", "{\"result\":{\"a\":"),
];

/// The headline property: nothing here may panic, and nothing may be `Ok`.
#[test]
fn no_hostile_reply_is_accepted_and_none_panics() {
    for (label, reply) in HOSTILE {
        let client = RpcClient::new(Canned(reply));
        assert!(
            client.chain_info().is_err(),
            "chain_info accepted {label}: {reply}"
        );
        assert!(
            client.address_utxos(&["R…"]).is_err(),
            "address_utxos accepted {label}: {reply}"
        );
        assert!(
            client.currency("VRSCTEST").is_err(),
            "currency accepted {label}: {reply}"
        );
        assert!(
            client.identity("x@").is_err(),
            "identity accepted {label}: {reply}"
        );
        assert!(
            client.address_balance(&["R…"]).is_err(),
            "address_balance accepted {label}: {reply}"
        );
        assert!(
            client.send_raw_transaction("00").is_err(),
            "send_raw_transaction accepted {label}: {reply}"
        );
    }
}

/// `{"result":null}` is the shape a client that models the envelope as
/// `struct { result: T, error: Option<E> }` silently mishandles: `result` is
/// present, so it looks like a success, and `T` is then built from nothing.
#[test]
fn a_null_result_is_not_a_successful_answer() {
    match client(r#"{"result":null,"error":null,"id":"x"}"#).chain_info() {
        Err(RpcError::Unexpected(message)) => assert!(message.contains("null result")),
        other => panic!("expected Unexpected, got {other:?}"),
    }
}

/// If a node sends both, the error wins. Treating the result as authoritative
/// would let a node hand back a plausible object alongside its own admission
/// that the call failed.
#[test]
fn an_error_beside_a_result_still_fails() {
    let reply = r#"{"result":{"name":"VRSCTEST","chainid":"i","blocks":1,"longestchain":1,"VRSCversion":"1"},"error":{"code":-8,"message":"bad param"}}"#;
    match client(reply).chain_info() {
        Err(RpcError::Node { code, .. }) => assert_eq!(code, -8),
        other => panic!("the result must not win over the error, got {other:?}"),
    }
}

/// A missing field is a daemon-version difference, not a broken connection, and
/// the two need different responses from an operator.
#[test]
fn a_missing_field_reads_as_a_shape_problem_not_a_transport_one() {
    // Valid JSON-RPC, valid JSON, just missing `blocks`.
    let reply =
        r#"{"result":{"name":"VRSCTEST","chainid":"i","longestchain":1,"VRSCversion":"1"}}"#;
    match client(reply).chain_info() {
        Err(RpcError::Unexpected(message)) => assert!(message.contains("getinfo")),
        other => panic!("expected Unexpected, got {other:?}"),
    }
}

/// Money that cannot be read exactly is refused rather than rounded. A value
/// off by one satoshi fails a conservation check somewhere else, much later,
/// with no trace of where it came from.
#[test]
fn an_unreadable_money_field_is_refused_rather_than_rounded() {
    for value in ["1e2", "\"abc\"", "null", "true", "-5.0", "{}"] {
        let reply = format!(
            r#"{{"result":{{"currencyid":"i","name":"X","idregistrationfees":{value},"idreferrallevels":0,"idimportfees":0.0}}}}"#
        );
        let client = RpcClient::new(Canned(Box::leak(reply.into_boxed_str())));
        assert!(
            client.currency("X").is_err(),
            "accepted an unreadable fee: {value}"
        );
    }
}

/// A satoshi field with a fraction in it means the field was misread, not that
/// it should be rounded — and a UTXO's value goes straight into a sighash.
#[test]
fn a_fractional_satoshi_in_a_utxo_is_refused() {
    let reply = r#"{"result":[{"address":"R","txid":"00000000000000000000000000000000000000000000000000000000000000ff","outputIndex":0,"script":"76a914","satoshis":1.5,"height":1,"isspendable":1}]}"#;
    match client(reply).address_utxos(&["R"]) {
        Err(RpcError::LossyNumber { field, .. }) => assert_eq!(field, "satoshis"),
        other => panic!("expected LossyNumber, got {other:?}"),
    }
}

/// A txid or script that is not hex must fail where it is read, naming the
/// field — not later, as an opaque rejection from the daemon.
#[test]
fn unparseable_bytes_fail_at_the_field_that_holds_them() {
    for (field, reply) in [
        (
            "txid",
            r#"{"result":[{"address":"R","txid":"zz","outputIndex":0,"script":"76","satoshis":1,"height":1,"isspendable":1}]}"#,
        ),
        (
            "script",
            r#"{"result":[{"address":"R","txid":"00000000000000000000000000000000000000000000000000000000000000ff","outputIndex":0,"script":"zz","satoshis":1,"height":1,"isspendable":1}]}"#,
        ),
    ] {
        match client(reply).address_utxos(&["R"]) {
            Err(RpcError::OutOfRange(message)) => assert!(
                message.contains(field),
                "error did not name {field}: {message}"
            ),
            other => panic!("expected OutOfRange for {field}, got {other:?}"),
        }
    }
}

/// A transport that never delivers must surface as a transport failure and
/// nothing else. On a broadcast this distinction is the whole game: the
/// transaction may well have been accepted, so the caller has to re-read rather
/// than resend.
#[test]
fn a_transport_failure_stays_a_transport_failure() {
    let client = RpcClient::new(Broken);
    assert!(matches!(client.chain_info(), Err(RpcError::Transport(_))));
    assert!(matches!(
        client.send_raw_transaction("00"),
        Err(RpcError::Transport(_))
    ));
    // Not silently reported as "the node has never seen it", which would read
    // as a lost payment rather than an unreachable node.
    assert!(client.confirmations("00".repeat(32).as_str()).is_err());
}

/// A broadcast hands back the txid the caller will poll on. A node that answers
/// with something that is not a txid must fail here — otherwise the caller
/// spends the next twenty minutes asking about a transaction that cannot exist,
/// and reports it as unconfirmed rather than as a broken node.
#[test]
fn a_broadcast_that_returns_something_other_than_a_txid_is_refused() {
    for reply in [
        r#"{"result":"not an object","id":"x"}"#,
        r#"{"result":"","id":"x"}"#,
        r#"{"result":"zzzz","id":"x"}"#,
        // Right length, not hex.
        r#"{"result":"gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"}"#,
        // Hex, wrong length.
        r#"{"result":"abcd"}"#,
    ] {
        match client(reply).send_raw_transaction("00") {
            Err(RpcError::Unexpected(message)) => {
                assert!(message.contains("32-byte hash"), "{message}")
            }
            other => panic!("accepted {reply} as a txid: {other:?}"),
        }
    }

    // And a real txid still passes.
    let good = r#"{"result":"5e19de6d3f77b5e1f49ec92db23027d5f026db92004b026465a61bff8ab13d7e"}"#;
    assert!(client(good).send_raw_transaction("00").is_ok());
}

/// The same reasoning for block hashes: reorg detection compares them, and
/// comparing garbage to garbage silently never detects anything.
#[test]
fn a_block_hash_that_is_not_a_hash_is_refused() {
    assert!(client(r#"{"result":"tip"}"#).best_block_hash().is_err());
    assert!(client(r#"{"result":"tip"}"#).block_hash(1).is_err());
}

/// A reply far larger than any real one must not be accepted quietly. The
/// ceiling lives in `HttpTransport`, so what is checked here is that the parser
/// above it does not fall over on a big body either.
#[test]
fn an_enormous_reply_fails_without_panicking() {
    let huge = format!(r#"{{"result":"{}"}}"#, "a".repeat(4 * 1024 * 1024));
    let client = RpcClient::new(Canned(Box::leak(huge.into_boxed_str())));
    assert!(client.chain_info().is_err());
}

/// Deeply nested JSON must not blow the stack. `serde_json` bounds recursion by
/// default; this asserts that rather than assuming it.
#[test]
fn deep_nesting_is_refused_rather_than_overflowing_the_stack() {
    let deep = format!(
        r#"{{"result":{}1{}}}"#,
        "[".repeat(2_000),
        "]".repeat(2_000)
    );
    let client = RpcClient::new(Canned(Box::leak(deep.into_boxed_str())));
    assert!(client.chain_info().is_err());
}
