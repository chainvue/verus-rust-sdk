//! `estimate_conversion` must send the amount it is given exactly, never
//! through a float.
//!
//! Before this fix, the amount string was parsed into a bare
//! `serde_json::Value` and handed to `json!` — but without the
//! `arbitrary_precision` feature, `serde_json::Number` stores anything with a
//! decimal point as `f64`. `100000000.00000001` therefore lost its last
//! satoshi the moment it became a `Value`, before it was ever reserialized
//! onto the wire. See `crates/verus-rpc/src/json.rs` for the exact-decimal
//! path this now reuses, the same way every *incoming* money field in this
//! crate is read.

use std::cell::RefCell;

use verus_rpc::{ChainReader, RequestBody, RpcClient, RpcError, Transport};

/// Records every request body it is given and always answers with a
/// trivially valid `estimateconversion` reply — these tests care about what
/// was sent, not what came back.
struct Recording {
    asked: RefCell<Vec<String>>,
}

impl Transport for Recording {
    fn post(&self, body: &RequestBody) -> Result<String, RpcError> {
        self.asked.borrow_mut().push(body.as_str().to_string());
        Ok(r#"{"result":{"estimatedcurrencyout":1.0}}"#.to_string())
    }
}

fn client() -> RpcClient<Recording> {
    RpcClient::new(Recording {
        asked: RefCell::new(Vec::new()),
    })
}

/// The concrete failure the audit reported: parsed and reserialized through
/// `f64`, `100000000.00000001` comes back as `100000000.0`. The exact digits
/// must reach the wire instead.
#[test]
fn a_satoshi_at_the_edge_of_f64_precision_survives_to_the_wire() {
    let client = client();
    client
        .estimate_conversion("VRSC", "BTC", "100000000.00000001", None)
        .expect("a valid, exact amount must be accepted");

    let asked = client.transport().asked.borrow();
    assert_eq!(asked.len(), 1);
    assert!(
        asked[0].contains("100000000.00000001"),
        "the exact amount did not reach the wire: {}",
        asked[0]
    );
    // Not even alongside the rounded figure: the float path must not have
    // run at all.
    assert!(!asked[0].contains("100000000.0,"));
}

/// Every value the audit found passing through unvalidated — negative,
/// exponent form, and non-numeric text in both a quoted and bare form — must
/// now be refused before anything reaches the transport.
#[test]
fn hostile_amounts_are_refused_and_never_reach_the_wire() {
    for amount in [
        "-5",
        "1e30",
        "\"abc\"",
        "abc",
        "{\"a\":1}",
        "NaN",
        "Infinity",
    ] {
        let client = client();
        assert!(
            client
                .estimate_conversion("VRSC", "BTC", amount, None)
                .is_err(),
            "{amount:?} should have been refused"
        );
        assert!(
            client.transport().asked.borrow().is_empty(),
            "{amount:?} should not have reached the wire"
        );
    }
}

/// More than eight decimal places is not a rounding question — satoshis are
/// the smallest unit this workspace represents — so it is refused outright
/// rather than silently rounded the way the float path used to.
#[test]
fn sub_satoshi_precision_is_refused_rather_than_rounded() {
    let client = client();
    assert!(client
        .estimate_conversion("VRSC", "BTC", "1234.567890123456789", None)
        .is_err());
    assert!(client.transport().asked.borrow().is_empty());
}

/// The MAX_MONEY-style ceiling from `crates/verus-rpc/src/json.rs` applies
/// here too: an absurd amount must be refused before it is sent, not just
/// when reading one back from a reply.
#[test]
fn an_amount_above_the_max_money_ceiling_is_refused() {
    let client = client();
    assert!(client
        .estimate_conversion("VRSC", "BTC", "99999999999.0", None)
        .is_err());
    assert!(client.transport().asked.borrow().is_empty());
}

/// …but the amount is denominated in the SOURCE currency, not the chain's
/// own, so it gets the per-currency ceiling and not the native one.
///
/// Two billion units of a large-supply token is an ordinary thing to price.
/// Bounding the request at the native ceiling refused it while the daemon
/// would have answered — the same over-refusal the two ceilings exist to
/// separate, fixed on the reply side first and missed here.
#[test]
fn a_large_token_amount_still_reaches_the_request() {
    let client = client();
    let _ = client.estimate_conversion("LARGETOKEN", "VRSC", "2000000000.0", None);
    let asked = client.transport().asked.borrow();
    let request = asked.first().expect("the request was sent");
    // Emitted without the trailing `.0` — `Amount::to_coins_string` writes
    // the shortest exact decimal, which is what the daemon reads back.
    assert!(
        request.contains(r#""amount":2000000000"#),
        "a large token amount never reached the wire: {request}"
    );
}

/// A sanity check that the exact-amount path did not break the ordinary
/// fields alongside it: `currency`, `convertto` and an optional `via` must
/// still reach the request the way they did before.
#[test]
fn the_other_fields_and_the_optional_via_still_reach_the_request() {
    let with_via = client();
    with_via
        .estimate_conversion("VRSC", "BTC", "1.5", Some("BRIDGE.vETH"))
        .unwrap();
    let asked = with_via.transport().asked.borrow();
    assert!(asked[0].contains(r#""method":"estimateconversion""#));
    assert!(asked[0].contains(r#""currency":"VRSC""#));
    assert!(asked[0].contains(r#""convertto":"BTC""#));
    assert!(asked[0].contains(r#""via":"BRIDGE.vETH""#));
    drop(asked);

    let no_via = client();
    no_via
        .estimate_conversion("VRSC", "BTC", "1.5", None)
        .unwrap();
    assert!(!no_via.transport().asked.borrow()[0].contains("via"));
}
