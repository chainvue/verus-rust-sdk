//! `-32601` is evidence about a call, not about a node.
//!
//! A public endpoint is usually a filtering proxy, and the filter can be
//! sensitive to the number of arguments rather than the method name. The crate
//! docs have said so since the availability table this client was designed
//! against listed `getblock` as absent, which it is not.
//!
//! Measured against `api.verustest.net` on 2026-08-03, `getrawmempool` is the
//! same shape and the other way round:
//!
//! ```text
//! getrawmempool []      -> {"result":[]}
//! getrawmempool [false] -> {"error":{"code":-32601,"message":"Method not found"}}
//! ```
//!
//! So a client that asks once and believes the answer will record a node that
//! serves the mempool as one that does not. These tests pin that the client
//! asks again.

use std::cell::RefCell;

use verus_rpc::{ChainReader, RequestBody, RpcClient, RpcError, Transport};

/// Txid-shaped constants: the client checks these are 32-byte hashes, so a
/// stand-in like `"ab"` is now correctly refused and would make these tests
/// about the wrong thing.
const A_TXID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B_TXID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const C_TXID: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

/// Answers `-32601` until it sees a body it likes, and records everything.
struct Filter {
    /// A body must contain this to be answered.
    accepts: Option<&'static str>,
    reply: &'static str,
    sent: RefCell<Vec<String>>,
}

impl Filter {
    fn new(accepts: Option<&'static str>, reply: &'static str) -> Self {
        Self {
            accepts,
            reply,
            sent: RefCell::new(Vec::new()),
        }
    }

    fn bodies(&self) -> Vec<String> {
        self.sent.borrow().clone()
    }
}

impl Transport for Filter {
    fn post(&self, body: &RequestBody) -> Result<String, RpcError> {
        let text = body.as_str().to_string();
        self.sent.borrow_mut().push(text.clone());
        match self.accepts {
            Some(wanted) if text.contains(wanted) => Ok(self.reply.to_string()),
            Some(_) | None => {
                Ok(r#"{"error":{"code":-32601,"message":"Method not found"}}"#.to_string())
            }
        }
    }
}

/// The preferred arity works, and nothing else is sent.
///
/// The re-probe must not cost a request when the first form is served, which is
/// the overwhelmingly common case.
#[test]
fn a_method_that_answers_first_time_is_asked_once() {
    let client = RpcClient::new(Filter::new(
        Some("getrawmempool"),
        r#"{"result":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]}"#,
    ));
    assert_eq!(client.mempool().expect("served"), vec![A_TXID, B_TXID]);
    assert_eq!(client.transport().bodies().len(), 1);
}

/// The failure this exists for: the node serves the method, at the other arity.
#[test]
fn a_method_refused_at_one_arity_is_tried_at_another() {
    // Only a body carrying the `false` argument is answered — the mirror image
    // of what `api.verustest.net` does, which is the point: the client cannot
    // know which way round a given proxy is.
    let client = RpcClient::new(Filter::new(
        Some("false"),
        r#"{"result":["cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"]}"#,
    ));
    assert_eq!(
        client.mempool().expect("served at the second arity"),
        vec![C_TXID]
    );

    let sent = client.transport().bodies();
    assert_eq!(sent.len(), 2, "it should have asked twice: {sent:?}");
    // Preferred form first, and it is the argument-free one.
    assert!(sent[0].contains(r#""params":[]"#), "{}", sent[0]);
    assert!(sent[1].contains("false"), "{}", sent[1]);
}

/// Refused everywhere is the only thing that may be reported as unavailable.
#[test]
fn refused_at_every_arity_is_finally_unavailable() {
    let client = RpcClient::new(Filter::new(None, ""));
    match client.mempool() {
        Err(RpcError::MethodUnavailable { method }) => assert_eq!(method, "getrawmempool"),
        other => panic!("expected MethodUnavailable, got {other:?}"),
    }
    assert_eq!(
        client.transport().bodies().len(),
        2,
        "every arity has to be tried before concluding absence"
    );
}

/// `getblock` gets the same treatment, and the working call is unchanged.
///
/// This is the method the crate docs name: the public endpoint serves it with
/// one argument and answers `-32601` for the same method with a verbosity
/// argument. So the one-argument form must still be what goes out first, and
/// the fallback must only fire after a refusal.
#[test]
fn getblock_still_leads_with_the_arity_the_public_endpoint_serves() {
    let client = RpcClient::new(Filter::new(Some("getblock"), r#"{"result":{"height":7}}"#));
    client.block("1173695").expect("served");

    let sent = client.transport().bodies();
    assert_eq!(sent.len(), 1);
    // A height goes as a number, not a quoted string, and alone.
    assert!(sent[0].contains(r#""params":[1173695]"#), "{}", sent[0]);
}

/// And a node that wants the verbosity argument is now reachable.
#[test]
fn getblock_falls_back_to_the_verbose_arity() {
    let client = RpcClient::new(Filter::new(Some("1173695,1"), r#"{"result":{"height":7}}"#));
    client.block("1173695").expect("served at the second arity");

    let sent = client.transport().bodies();
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert!(sent[1].contains(r#""params":[1173695,1]"#), "{}", sent[1]);
}

/// A hash is still sent as a string at both arities.
#[test]
fn a_hash_stays_a_string_through_the_fallback() {
    let hash = "0000000000000000000000000000000000000000000000000000000000000abc";
    let client = RpcClient::new(Filter::new(None, ""));
    let _ = client.block(hash);

    for body in client.transport().bodies() {
        assert!(body.contains(&format!(r#""{hash}""#)), "{body}");
    }
}

/// Anything that is not `-32601` stops immediately.
///
/// A node error is an answer. Re-asking at another arity would turn one
/// failure into two requests and could turn a transient error into a different
/// one, which is worse than reporting what the node said.
#[test]
fn a_node_error_is_not_re_probed() {
    struct Erroring(RefCell<usize>);
    impl Transport for Erroring {
        fn post(&self, _body: &RequestBody) -> Result<String, RpcError> {
            *self.0.borrow_mut() += 1;
            Ok(r#"{"error":{"code":-8,"message":"Block height out of range"}}"#.to_string())
        }
    }

    let client = RpcClient::new(Erroring(RefCell::new(0)));
    match client.mempool() {
        Err(RpcError::Node { code, .. }) => assert_eq!(code, -8),
        other => panic!("expected the node's own error, got {other:?}"),
    }
    assert_eq!(*client.transport().0.borrow(), 1);
}

/// And neither is a transport failure.
#[test]
fn a_transport_failure_is_not_re_probed() {
    struct Dead(RefCell<usize>);
    impl Transport for Dead {
        fn post(&self, _body: &RequestBody) -> Result<String, RpcError> {
            *self.0.borrow_mut() += 1;
            Err(RpcError::Transport("connection refused".into()))
        }
    }

    let client = RpcClient::new(Dead(RefCell::new(0)));
    assert!(matches!(client.mempool(), Err(RpcError::Transport(_))));
    assert_eq!(*client.transport().0.borrow(), 1);
}

/// Ids are validated and normalised, like every other hash this client hands
/// back.
///
/// The method exists so a wallet can ask "is my broadcast alive?", which is a
/// `contains` against a txid from `send_raw_transaction` or computed locally —
/// and both of those are lowercase. A node answering in uppercase would
/// otherwise report a mempool that matches nothing.
#[test]
fn mempool_ids_are_lowercased_and_checked() {
    let upper = "AB".repeat(32);
    let client = RpcClient::new(Filter::new(
        Some("getrawmempool"),
        r#"{"result":["ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"]}"#,
    ));
    assert_eq!(
        client.mempool().expect("served"),
        vec![upper.to_lowercase()]
    );

    // Not a hash at all.
    let client = RpcClient::new(Filter::new(Some("getrawmempool"), r#"{"result":["nope"]}"#));
    assert!(matches!(client.mempool(), Err(RpcError::Unexpected(_))));
}

/// A node contradicting itself about a set is refused, not silently deduped.
#[test]
fn a_repeated_mempool_id_is_refused() {
    let one = "ab".repeat(32);
    let client = RpcClient::new(Filter::new(
        Some("getrawmempool"),
        r#"{"result":["abababababababababababababababababababababababababababababababab","abababababababababababababababababababababababababababababababab"]}"#,
    ));
    match client.mempool() {
        Err(RpcError::Unexpected(message)) => assert!(message.contains(&one), "{message}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// An empty mempool is an answer, not a refusal.
#[test]
fn an_empty_mempool_is_a_real_answer() {
    let client = RpcClient::new(Filter::new(Some("getrawmempool"), r#"{"result":[]}"#));
    assert!(client.mempool().expect("served").is_empty());
    // Asked once: an empty result must not look like something to re-probe.
    assert_eq!(client.transport().bodies().len(), 1);
}

// ------------------------------------------------- probing under the cassette

/// Under a [`Cassette`] a probing call must stop at the first unanswered
/// request, not ask the second arity in the same round.
///
/// This is the interaction the design is least obviously right about. A driver
/// posts everything a round records, so a probing call that recorded both
/// arities on a fresh cache would send a request the operation had not yet
/// decided it needed — and on the overwhelmingly common path, where the first
/// arity is served, that request is pure waste and pure extra exposure.
#[test]
fn a_fresh_cassette_records_only_the_preferred_arity() {
    let client = RpcClient::new(verus_rpc::Cassette::new());
    assert!(matches!(client.mempool(), Err(RpcError::AnswerNeeded)));

    let outstanding = client.into_transport().outstanding();
    assert_eq!(outstanding.len(), 1, "{outstanding:?}");
    assert!(
        outstanding[0].contains(r#""params":[]"#),
        "{}",
        outstanding[0]
    );
}

/// And when the answer to the preferred arity turns out to be `-32601`, the
/// next round asks the second one and the round after that succeeds.
///
/// The cache only grows, so each round must get further. Here that means: a
/// refusal is a real answer, cached like any other, and re-running reaches past
/// it rather than asking the same question again forever.
#[test]
fn a_refusal_cached_from_one_round_advances_the_next() {
    let mut cassette = verus_rpc::Cassette::new();

    // Round 1: the preferred arity is recorded.
    let client = RpcClient::new(cassette);
    assert!(matches!(client.mempool(), Err(RpcError::AnswerNeeded)));
    cassette = client.into_transport();
    let first = cassette.outstanding().remove(0);

    // The driver fetches it and the node says "method not found".
    cassette.answer(
        first.clone(),
        r#"{"error":{"code":-32601,"message":"Method not found"}}"#,
    );
    cassette.forget_misses();

    // Round 2: the cached refusal is consumed and the *other* arity is asked.
    let client = RpcClient::new(cassette);
    assert!(matches!(client.mempool(), Err(RpcError::AnswerNeeded)));
    cassette = client.into_transport();
    let outstanding = cassette.outstanding();
    assert_eq!(outstanding.len(), 1, "{outstanding:?}");
    assert!(outstanding[0].contains("false"), "{}", outstanding[0]);
    assert_ne!(outstanding[0], first, "it must ask a different question");

    // Round 3: answered, and the operation completes.
    cassette.answer(
        outstanding[0].clone(),
        r#"{"result":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]}"#,
    );
    cassette.forget_misses();
    let client = RpcClient::new(cassette);
    assert_eq!(
        client.mempool().expect("both arities are known now"),
        // Lowercased on the way out, like every other hash this client returns.
        vec![A_TXID]
    );
}
