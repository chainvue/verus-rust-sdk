//! Real flows, run with no I/O.
//!
//! [`verus_flows::drive`] claims that an operation written as straight-line
//! code against a `ChainReader` can be run by a caller that does its own
//! fetching, without the operation being rewritten. These tests are that claim
//! applied to flows that exist, using replies the live network actually
//! produced.
//!
//! What each one pins:
//!
//! * the **rounds** — how many times a browser would have to go to the network,
//!   which is the number that matters there and is invisible to every other
//!   test;
//! * the **requests per round**, so a carelessly placed read that turns one
//!   round into two is caught;
//! * that the result is **identical** to what the flow produces when every
//!   answer is available at once.

use std::collections::HashMap;

use verus_flows::drive::{advance, Answers, Step};
use verus_flows::FlowError;
use verus_rpc::{RequestBody, RpcError, Transport};

/// A recorded reply for every request these tests can make.
///
/// Keyed by method name rather than by whole body: a fixture is captured for a
/// method, and pinning the exact arguments is the job of the assertions below,
/// not of the lookup.
fn replies() -> HashMap<&'static str, String> {
    fn fixture(name: &str) -> String {
        let path = format!(
            "{}/../../fixtures/rpc/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    HashMap::from([
        ("getinfo", fixture("getinfo")),
        ("getaddressdeltas", fixture("getaddressdeltas")),
    ])
}

/// The method name inside a JSON-RPC body, for looking a fixture up.
fn method_of(body: &str) -> String {
    let marker = r#""method":""#;
    let start = body.find(marker).expect("a body names its method") + marker.len();
    let rest = &body[start..];
    rest[..rest.find('"').expect("a closing quote")].to_string()
}

/// A transport that answers from the fixtures, and counts.
///
/// Stands in for the network in the one-pass comparison — the thing a native
/// caller passes, against which the driven result must match exactly.
struct Recorded {
    replies: HashMap<&'static str, String>,
    calls: std::cell::RefCell<usize>,
}

impl Transport for Recorded {
    fn post(&self, body: &RequestBody) -> Result<String, RpcError> {
        *self.calls.borrow_mut() += 1;
        let method = method_of(body.as_str());
        self.replies
            .get(method.as_str())
            .cloned()
            .ok_or_else(|| RpcError::Unexpected(format!("no fixture for {method}")))
    }
}

/// Drive an operation the way a browser would, returning the value and the
/// bodies asked for in each round.
fn drive_it<T, F>(mut operation: F) -> (T, Vec<Vec<String>>)
where
    F: FnMut(&verus_rpc::RpcClient<verus_rpc::Cassette>) -> Result<T, FlowError>,
{
    let replies = replies();
    let mut answers = Answers::new();
    let mut rounds = Vec::new();

    loop {
        match advance(&mut answers, &mut operation).expect("driving must not fail") {
            Step::Ready(value) => return (value, rounds),
            Step::Ask(bodies) => {
                assert!(!bodies.is_empty(), "a round that asks for nothing loops");
                for body in &bodies {
                    let method = method_of(body);
                    let reply = replies
                        .get(method.as_str())
                        .unwrap_or_else(|| panic!("no fixture for {method}"));
                    answers.record(body.clone(), reply.clone());
                }
                rounds.push(bodies);
            }
        }
    }
}

const TAKER: &str = "RGRTws8PJQC5oBqftKMCAaBD1Vj5MHKKSz";

/// `history` reads the chain's own currency and the address deltas, and neither
/// needs the other — so a browser goes to the network **once**, not twice.
///
/// This is the number the whole exercise is about. Nothing else in the test
/// suite would notice if a change made it two.
#[test]
fn history_resolves_in_a_single_round() {
    let (entries, rounds) = drive_it(|client| {
        verus_flows::history::history(client, &[TAKER], Some((1_170_740, 1_170_760)))
    });

    assert_eq!(rounds.len(), 1, "one round: {rounds:#?}");
    assert_eq!(rounds[0].len(), 2, "both reads go out together");

    let methods: Vec<String> = rounds[0].iter().map(|b| method_of(b)).collect();
    assert!(methods.contains(&"getinfo".to_string()));
    assert!(methods.contains(&"getaddressdeltas".to_string()));

    // And it actually computed something: the settled token swap.
    assert!(!entries.is_empty());
}

/// The driven result must be the same as the one-pass result, or the mechanism
/// is not transparent and every flow would need re-proving.
#[test]
fn driving_produces_exactly_what_a_direct_reader_produces() {
    let direct = verus_rpc::RpcClient::new(Recorded {
        replies: replies(),
        calls: std::cell::RefCell::new(0),
    });
    let straight_through =
        verus_flows::history::history(&direct, &[TAKER], Some((1_170_740, 1_170_760)))
            .expect("the ordinary path");

    let (driven, _) = drive_it(|client| {
        verus_flows::history::history(client, &[TAKER], Some((1_170_740, 1_170_760)))
    });

    assert_eq!(driven, straight_through);
}

/// Two things at once, and both are properties of the mechanism rather than of
/// any flow.
///
/// **A `?` on a read is a round boundary.** `native_currency` is unwrapped
/// before `history` runs, so the operation stops there on the first round —
/// two rounds, not one. That is the cost model to design against: rounds are
/// the number of read points executed *in sequence*, not the depth of the
/// dependency graph. It is why `history` and `spendable` issue their
/// independent reads before unwrapping any of them.
///
/// **An answered request is never asked again.** `chain_info` is reached twice
/// in the second round — once directly, once inside `history` — and appears in
/// no round's asks after the first. That is what makes re-running converge
/// instead of looping, and it only holds because a request body is a stable
/// key.
#[test]
fn an_unwrapped_read_costs_a_round_and_an_answer_is_never_re_asked() {
    let (_, rounds) = drive_it(|client| {
        let _ = verus_flows::balances::native_currency(client)?;
        verus_flows::history::history(client, &[TAKER], Some((1_170_740, 1_170_760)))
    });

    assert_eq!(rounds.len(), 2, "the `?` splits it: {rounds:#?}");
    assert_eq!(
        rounds[0].iter().map(|b| method_of(b)).collect::<Vec<_>>(),
        ["getinfo"]
    );
    assert_eq!(
        rounds[1].iter().map(|b| method_of(b)).collect::<Vec<_>>(),
        ["getaddressdeltas"],
        "the second round must not re-ask what the first answered"
    );
}

/// The hazard the driver introduces, and the fix, on the flow where it would
/// have cost real money.
///
/// `prepare_registration` checks whether a name is already taken before
/// spending a commitment fee. It used to do that with `reader.identity(..).is_ok()`,
/// which reads "anything but success means the name is free" — and against this
/// driver a request that has simply not been answered *yet* is also not `ok`.
/// The first round would have concluded the name was free and gone on to build
/// a registration for a name somebody else owns.
///
/// So the flow must keep asking rather than deciding. Only the daemon's `-5`
/// counts as "no such identity".
#[test]
fn registration_keeps_asking_rather_than_assuming_a_name_is_free() {
    use verus_flows::identity::RegistrationOptions;
    use verus_keys::PrivateKey;

    let key = PrivateKey::from_bytes(&[0x7c; 32], true).expect("a valid scalar");
    let replies = replies();
    let mut answers = Answers::new();

    // Round one: the flow reads the chain before anything else.
    let step = advance(&mut answers, |client| {
        verus_flows::prepare_registration(
            client,
            &key,
            "someonesname",
            &RegistrationOptions::default(),
        )
    })
    .expect("a miss is not a failure");
    let bodies = match step {
        Step::Ask(bodies) => bodies,
        Step::Ready(_) => panic!("it cannot be ready knowing nothing"),
    };
    assert_eq!(
        bodies.iter().map(|b| method_of(b)).collect::<Vec<_>>(),
        ["getinfo"]
    );
    for body in &bodies {
        answers.record(body.clone(), replies[method_of(body).as_str()].clone());
    }

    // Round two is the one that matters. With the chain known but the identity
    // not, the flow must *ask* about the name — not conclude anything from the
    // fact that it has no answer.
    let step = advance(&mut answers, |client| {
        verus_flows::prepare_registration(
            client,
            &key,
            "someonesname",
            &RegistrationOptions::default(),
        )
    })
    .expect("still not a failure");
    let bodies = match step {
        Step::Ask(bodies) => bodies,
        Step::Ready(_) => panic!("a registration was built without ever checking the name"),
    };
    assert!(
        bodies.iter().any(|b| method_of(b) == "getidentity"),
        "the name check must be asked, not assumed: {bodies:#?}"
    );
}

/// The subtlest property in the whole mechanism: a **node error, cached**, is
/// an answer that lets the next round proceed.
///
/// The name check reads `-5` as "no such identity" and anything else as a
/// failure. So the driver has to store the daemon's *error* envelope as the
/// answer to that request, and the following round has to get it from the cache
/// and carry on past it. If either half were wrong the flow would ask the same
/// question forever and die at the round cap.
///
/// Nothing else covers this: the equivalence test only ever caches successes.
#[test]
fn a_cached_node_error_is_an_answer_and_the_next_round_proceeds() {
    use verus_flows::identity::RegistrationOptions;
    use verus_keys::PrivateKey;

    let key = PrivateKey::from_bytes(&[0x7c; 32], true).expect("a valid scalar");
    let replies = replies();
    let mut answers = Answers::new();

    let plan = |client: &verus_rpc::RpcClient<verus_rpc::Cassette>| {
        verus_flows::prepare_registration(client, &key, "freename", &RegistrationOptions::default())
    };

    // Round one: the chain.
    let Step::Ask(bodies) = advance(&mut answers, plan).expect("round one") else {
        panic!("it cannot be ready knowing nothing");
    };
    for body in &bodies {
        answers.record(body.clone(), replies[method_of(body).as_str()].clone());
    }

    // Round two asks about the name. Answer it the way a daemon answers for a
    // name nobody has taken.
    let Step::Ask(bodies) = advance(&mut answers, plan).expect("round two") else {
        panic!("the name must be checked");
    };
    let name_check = bodies
        .iter()
        .find(|b| method_of(b) == "getidentity")
        .expect("the name check");
    answers.record(
        name_check.clone(),
        r#"{"error":{"code":-5,"message":"Identity not found"}}"#,
    );
    for body in bodies.iter().filter(|b| method_of(b) != "getidentity") {
        if let Some(reply) = replies.get(method_of(body).as_str()) {
            answers.record(body.clone(), reply.clone());
        }
    }

    // Round three must get *past* the name check rather than asking again.
    let step = advance(&mut answers, plan).expect("round three");
    let asked_again = match &step {
        Step::Ask(bodies) => bodies.iter().any(|b| method_of(b) == "getidentity"),
        Step::Ready(_) => false,
    };
    assert!(
        !asked_again,
        "a cached `-5` is an answer; asking again means it was not treated as one: {step:?}"
    );
}
