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
use verus_tx::Identity;

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
        // Not a captured reply: `getblockcount` returns a bare integer, and it
        // has to agree with the capture above or every output would look
        // immature. `getinfo` reports 1167555 for the same capture.
        ("getblockcount", r#"{"result":1167555}"#.to_string()),
        // An empty mempool. `funding::spendable` reads it to withhold coins an
        // unconfirmed transaction already spends; with nothing pending, every
        // captured output stays spendable and these fixtures keep meaning what
        // they meant. It is issued in the same round as the two reads above,
        // which is what the round-count assertions below check.
        ("getaddressmempool", r#"{"result":[]}"#.to_string()),
    ])
}

/// The same set, plus one spendable output belonging to `address`.
///
/// The captured `getaddressutxos` reply cannot be used here: the client checks
/// that every output it is handed belongs to an address that was asked about —
/// a node that slips in someone else's output is refused — and no private key
/// for the captured address exists outside the wallet that made it. So the
/// output is synthesised for a key these tests do own. Only the ownership
/// changes; the height, value and script shape are the capture's.
fn replies_for(address: &verus_keys::Address) -> HashMap<&'static str, String> {
    let mut replies = replies();
    replies.insert(
        "getaddressutxos",
        format!(
            r#"{{"result":[{{"address":"{address}","blocktime":1785262420,"height":1166385,"isspendable":1,"outputIndex":1,"satoshis":8830000,"script":"76a914{}88ac","txid":"5e19de6d3f77b5e1f49ec92db23027d5f026db92004b026465a61bff8ab13d7e"}}]}}"#,
            hex::encode(address.hash())
        ),
    );
    replies
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
fn drive_it<T, F>(operation: F) -> (T, Vec<Vec<String>>)
where
    F: FnMut(&verus_rpc::RpcClient<verus_rpc::Cassette>) -> Result<T, FlowError>,
{
    drive_with(replies(), operation)
}

/// As [`drive_it`], against a particular set of replies.
fn drive_with<T, F>(replies: HashMap<&'static str, String>, operation: F) -> (T, Vec<Vec<String>>)
where
    F: FnMut(&verus_rpc::RpcClient<verus_rpc::Cassette>) -> Result<T, FlowError>,
{
    drive_dispatching(
        |body| {
            let method = method_of(body);
            replies
                .get(method.as_str())
                .unwrap_or_else(|| panic!("no fixture for {method}"))
                .clone()
        },
        operation,
    )
}

/// As [`drive_with`], but choosing the reply from the **whole body** rather
/// than from the method name.
///
/// Needed as soon as one flow asks the same method about two different
/// addresses: the client refuses an output belonging to an address it did not
/// ask about, so a single shared `getaddressutxos` fixture carrying both would
/// be rejected for each of them.
fn drive_dispatching<T, F, R>(reply_to: R, mut operation: F) -> (T, Vec<Vec<String>>)
where
    F: FnMut(&verus_rpc::RpcClient<verus_rpc::Cassette>) -> Result<T, FlowError>,
    R: Fn(&str) -> String,
{
    let mut answers = Answers::new();
    let mut rounds = Vec::new();

    loop {
        match advance(&mut answers, &mut operation).expect("driving must not fail") {
            Step::Ready(value) => return (value, rounds),
            Step::Ask(bodies) => {
                assert!(!bodies.is_empty(), "a round that asks for nothing loops");
                for body in &bodies {
                    answers
                        .record(body.clone(), reply_to(body))
                        .expect("a fixture fits");
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

    // The range has to reach the wire. The fixture is pre-trimmed to the
    // queried heights, so a regression that dropped `range` entirely would
    // still produce the right entries here and pass every other assertion —
    // and would then ask a public node for an address's whole history.
    let deltas = rounds[0]
        .iter()
        .find(|b| method_of(b) == "getaddressdeltas")
        .expect("the deltas request");
    assert!(deltas.contains("1170740"), "start height: {deltas}");
    assert!(deltas.contains("1170760"), "end height: {deltas}");

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
        answers
            .record(body.clone(), replies[method_of(body).as_str()].clone())
            .expect("a fixture fits");
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

/// A key for the driven payment tests. Nothing has ever been sent to it; the
/// recorded transport answers by method, so which address is asked about does
/// not change the reply.
fn spender() -> verus_keys::PrivateKey {
    verus_keys::PrivateKey::from_bytes(&[0x7c; 32], true).expect("a valid scalar")
}

const PAYEE: &str = "RJUgxvDnDLsRGCXNKDK56Rxngzh6m25J6F";

/// A **write** flow, driven — which is the half of the mechanism that was
/// missing until the broadcast was split out.
///
/// `prepare_send` reads the tip and the outputs, and neither needs the other,
/// so a browser goes to the network once. The outputs in the fixture are all
/// older than [`COINBASE_MATURITY`](verus_flows::funding::COINBASE_MATURITY),
/// so no maturity probe follows and there is no second round.
#[test]
fn preparing_a_payment_resolves_in_a_single_round() {
    let key = spender();
    let (_unsent, rounds) = drive_with(replies_for(&key.address()), |client| {
        verus_flows::prepare_send(
            client,
            &key,
            PAYEE,
            verus_flows::Amount::from_sat(1_000_000),
        )
    });

    assert_eq!(rounds.len(), 1, "one round: {rounds:#?}");
    let mut methods: Vec<String> = rounds[0].iter().map(|b| method_of(b)).collect();
    methods.sort();
    assert_eq!(
        methods,
        ["getaddressmempool", "getaddressutxos", "getblockcount"]
    );
}

/// The bytes a browser would sign must be the bytes a native caller signs.
///
/// Equivalence was proven for a read flow when the driver landed; this is the
/// claim that matters commercially, because these bytes move money.
#[test]
fn a_driven_payment_signs_exactly_what_a_direct_reader_signs() {
    let key = spender();
    let amount = verus_flows::Amount::from_sat(1_000_000);

    let replies = replies_for(&key.address());
    let direct = verus_rpc::RpcClient::new(Recorded {
        replies: replies.clone(),
        calls: std::cell::RefCell::new(0),
    });
    let straight_through =
        verus_flows::prepare_send(&direct, &key, PAYEE, amount).expect("the ordinary path");

    let (driven, _) = drive_with(replies, |client| {
        verus_flows::prepare_send(client, &key, PAYEE, amount)
    });

    assert_eq!(driven.hex, straight_through.hex);
    assert_eq!(driven.txid, straight_through.txid);
    assert_eq!(driven, straight_through);
}

/// Driving the **unsplit** flow by mistake is refused, loudly, rather than
/// silently sending the transaction once per round.
///
/// `RpcClient<Cassette>` implements `Broadcaster` like any other client — the
/// type system cannot stop `send(client, client, ..)` being written. If a
/// broadcast were merely *recorded* as one more outstanding request, a driver
/// would dutifully go and fetch it, and fetching `sendrawtransaction` means
/// sending the money. So the cassette refuses writes outright, with an error
/// that is deliberately not [`RpcError::AnswerNeeded`].
///
/// This is why the `prepare_…` half exists at all, expressed as a test rather
/// than as a comment.
#[test]
fn driving_a_flow_that_broadcasts_is_refused_rather_than_recorded() {
    let key = spender();
    let replies = replies_for(&key.address());
    let mut answers = Answers::new();

    let operation = |client: &verus_rpc::RpcClient<verus_rpc::Cassette>| {
        verus_flows::send(
            client,
            client,
            &key,
            PAYEE,
            verus_flows::Amount::from_sat(1_000_000),
        )
    };

    // Answer the reads. Once they are all known the flow reaches the broadcast,
    // which must be where it stops.
    let mut refusal = None;
    for _ in 0..4 {
        match advance(&mut answers, operation) {
            Ok(Step::Ask(bodies)) => {
                for body in &bodies {
                    answers
                        .record(body.clone(), replies[method_of(body).as_str()].clone())
                        .expect("a fixture fits");
                }
            }
            Ok(Step::Ready(sent)) => panic!("a driven flow must not broadcast: {}", sent.txid),
            Err(error) => {
                refusal = Some(error);
                break;
            }
        }
    }

    match refusal {
        Some(FlowError::Rpc(RpcError::WriteThroughCassette)) => {}
        other => panic!("expected the write to be refused, got {other:?}"),
    }
}

/// An identity whose sole primary address is `signer`, rendered the way
/// `getidentity` renders one, holding `multimap` in its content multimap.
///
/// The name and parent are the fixture's, so `identityaddress` below is the
/// real derivation for them rather than a made-up `i` address — which matters,
/// because `prepare_publish` refuses an identity whose decoded id does not
/// match the one the node reported.
fn identity_of(signer: &verus_keys::Address, multimap: Vec<([u8; 20], Vec<Vec<u8>>)>) -> Identity {
    Identity {
        version: 3,
        flags: 0,
        primary_addresses: vec![verus_tx::Destination::PubKeyHash(signer.hash())],
        min_sigs: 1,
        parent: PARENT,
        name: "rustsdk".into(),
        content_multimap: multimap,
        content_map: Vec::new(),
        revocation_authority: [0x33; 20],
        recovery_authority: [0x44; 20],
        private_addresses: Vec::new(),
        system_id: PARENT,
        unlock_after: 0,
    }
}

/// VRSCTEST's own currency id, as the fixtures report it.
const PARENT: [u8; 20] = [
    0xf0, 0x76, 0xdd, 0xdd, 0x21, 0x0d, 0x11, 0xb6, 0x67, 0xef, 0x1b, 0xdc, 0x54, 0x24, 0x8f, 0xf3,
    0x84, 0x63, 0xd8, 0x66,
];

/// `getidentity`, for an identity whose id is derived rather than invented.
fn identity_reply(identity: &Identity, outpoint: &verus_tx::Txid) -> String {
    let id = verus_tx::identity_id(&identity.name, Some(identity.parent));
    let address = verus_keys::Address::new(verus_keys::AddressKind::Identity, id);
    let primary: Vec<String> = identity
        .primary_addresses
        .iter()
        .map(|d| match d {
            verus_tx::Destination::PubKeyHash(h) => {
                verus_keys::Address::new(verus_keys::AddressKind::PubKeyHash, *h).to_string()
            }
            other => panic!("unexpected primary address {other:?}"),
        })
        .collect();
    serde_json::json!({"result": {
        "blockheight": 1_166_566,
        "fullyqualifiedname": "rustsdk.VRSCTEST@",
        "status": "active",
        "txid": outpoint.to_display_hex(),
        "vout": 0,
        "identity": {
            "identityaddress": address.to_string(),
            "minimumsignatures": identity.min_sigs,
            "name": identity.name,
            "primaryaddresses": primary,
            "version": identity.version,
        },
    }})
    .to_string()
}

/// The `i` address of an identity, which is also its currency id when it is
/// tokenised.
fn identity_address(identity: &Identity) -> verus_keys::Address {
    verus_keys::Address::new(
        verus_keys::AddressKind::Identity,
        verus_tx::identity_id(&identity.name, Some(identity.parent)),
    )
}

/// `getcurrency`, for a currency whose `proofprotocol` decides whether it can
/// be minted at all.
fn currency_reply(address: &verus_keys::Address, proof_protocol: u32) -> String {
    serde_json::json!({"result": {
        "currencyid": address.to_string(),
        "name": "rustsdk",
        "fullyqualifiedname": "rustsdk.VRSCTEST@",
        "parent": "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq",
        "systemid": "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq",
        "startblock": 1_166_000,
        "endblock": 0,
        "options": 32,
        "proofprotocol": proof_protocol,
    }})
    .to_string()
}

/// A mint is paid for by the identity it spends from, so the outputs it reads
/// are the identity's own pay-to-identity ones — and the four reads it needs
/// (the chain, the identity, the identity's outputs, the definition) need
/// nothing from each other.
///
/// Also the only coverage `mint` has anywhere: it was rearranged more than any
/// other flow in this split and had none.
#[test]
fn preparing_a_mint_resolves_in_a_single_round() {
    let key = spender();
    let identity = identity_of(&key.address(), Vec::new());
    let address = identity_address(&identity);
    let script = verus_tx::identity_payment_script(address.hash()).expect("payment script");

    let mut replies = replies();
    replies.insert(
        "getidentity",
        identity_reply(&identity, &verus_tx::Txid::from_internal([0x22; 32])),
    );
    replies.insert(
        "getcurrency",
        currency_reply(&address, verus_tx::CENTRALIZED_PROOF_PROTOCOL),
    );
    replies.insert(
        "getaddressutxos",
        format!(
            r#"{{"result":[{{"address":"{address}","blocktime":1785262420,"height":1166385,"isspendable":1,"outputIndex":0,"satoshis":500000000,"script":"{}","txid":"5e19de6d3f77b5e1f49ec92db23027d5f026db92004b026465a61bff8ab13d7e"}}]}}"#,
            hex::encode(&script)
        ),
    );

    let currency = address.to_string();
    let (_unsent, rounds) = drive_with(replies, |client| {
        verus_flows::prepare_mint(
            client,
            &key,
            &currency,
            verus_flows::Amount::from_sat(100_000_000),
            PAYEE,
            verus_flows::Amount::from_sat(20_010),
        )
    });

    assert_eq!(rounds.len(), 1, "one round: {rounds:#?}");
    let mut methods: Vec<String> = rounds[0].iter().map(|b| method_of(b)).collect();
    methods.sort();
    assert_eq!(
        methods,
        [
            "getaddressmempool",
            "getaddressutxos",
            "getblockcount",
            "getcurrency",
            "getidentity",
            "getinfo"
        ],
        "all six reads must go out together"
    );
}

/// A currency that is not centralized cannot be minted, and saying so costs
/// nothing here.
///
/// Consensus refuses this too, but only after the fee is spent, and with a
/// message naming neither the field nor the value. The currency cannot then be
/// fixed: the definition is immutable and the defining identity has spent its
/// one-time ability to define a currency, so the name is gone as well.
#[test]
fn minting_a_currency_that_is_not_centralized_is_refused_by_name() {
    let key = spender();
    let identity = identity_of(&key.address(), Vec::new());
    let address = identity_address(&identity);
    let script = verus_tx::identity_payment_script(address.hash()).expect("payment script");

    let mut replies = replies();
    replies.insert(
        "getidentity",
        identity_reply(&identity, &verus_tx::Txid::from_internal([0x22; 32])),
    );
    // The only difference from the passing case above.
    replies.insert("getcurrency", currency_reply(&address, 1));
    replies.insert(
        "getaddressutxos",
        format!(
            r#"{{"result":[{{"address":"{address}","blocktime":1785262420,"height":1166385,"isspendable":1,"outputIndex":0,"satoshis":500000000,"script":"{}","txid":"5e19de6d3f77b5e1f49ec92db23027d5f026db92004b026465a61bff8ab13d7e"}}]}}"#,
            hex::encode(&script)
        ),
    );

    let currency = address.to_string();
    let operation = |client: &verus_rpc::RpcClient<verus_rpc::Cassette>| {
        verus_flows::prepare_mint(
            client,
            &key,
            &currency,
            verus_flows::Amount::from_sat(100_000_000),
            PAYEE,
            verus_flows::Amount::from_sat(20_010),
        )
    };

    let mut answers = Answers::new();
    let error = loop {
        match advance(&mut answers, operation) {
            Ok(Step::Ready(_)) => panic!("a proofprotocol 1 currency must not mint"),
            Ok(Step::Ask(bodies)) => {
                for body in &bodies {
                    let method = method_of(body);
                    let reply = replies.get(method.as_str()).expect("a fixture");
                    answers
                        .record(body.clone(), reply.clone())
                        .expect("it fits");
                }
            }
            Err(e) => break e.to_string(),
        }
    };

    // The field and the value it found, not just "cannot mint" — the point is
    // that the caller learns which knob is wrong.
    assert!(error.contains("proofprotocol 1"), "{error}");
    assert!(
        error.contains(&format!(
            "proofprotocol {}",
            verus_tx::CENTRALIZED_PROOF_PROTOCOL
        )),
        "the refusal must name what would work: {error}"
    );
}

/// Maturity probes go out **together**, so a wallet with several young outputs
/// costs one extra round rather than one per output.
///
/// `funding::probe_coinbase_heights` collects every probe before unwrapping any
/// of them, precisely so this holds. Nothing else notices if a `?` is
/// reintroduced inside that loop: the answers are the same, the transaction is
/// the same, and only the number of network round trips changes — from two to
/// one-per-young-output, silently.
#[test]
fn maturity_probes_for_several_young_outputs_share_one_round() {
    let key = spender();
    let address = key.address();
    let script = format!("76a914{}88ac", hex::encode(address.hash()));

    // Two outputs, both inside the 100-block maturity window, with different
    // transactions — so two distinct probes are needed.
    let mut replies = replies();
    replies.insert(
        "getaddressutxos",
        format!(
            r#"{{"result":[
                {{"address":"{address}","blocktime":1785262420,"height":1167550,"isspendable":1,
                  "outputIndex":0,"satoshis":500000000,"script":"{script}",
                  "txid":"{}"}},
                {{"address":"{address}","blocktime":1785262420,"height":1167551,"isspendable":1,
                  "outputIndex":0,"satoshis":500000000,"script":"{script}",
                  "txid":"{}"}}
            ]}}"#,
            "aa".repeat(32),
            "bb".repeat(32),
        ),
    );
    // Neither is actually a coinbase, so both stay spendable and the plan
    // completes — the point here is the shape of the asking, not the outcome.
    replies.insert(
        "getrawtransaction",
        r#"{"result":{"vin":[{"txid":"cc","vout":0}]}}"#.to_string(),
    );

    let (_unsent, rounds) = drive_with(replies, |client| {
        verus_flows::prepare_send(
            client,
            &key,
            PAYEE,
            verus_flows::Amount::from_sat(1_000_000),
        )
    });

    assert_eq!(
        rounds.len(),
        2,
        "the tip and outputs, then the probes: {rounds:#?}"
    );
    let probes: Vec<String> = rounds[1].iter().map(|b| method_of(b)).collect();
    assert_eq!(
        probes,
        ["getrawtransaction", "getrawtransaction"],
        "both probes must be asked in the same round"
    );
    // And they must be different questions, or the test would pass with one
    // probe issued twice.
    assert_ne!(rounds[1][0], rounds[1][1]);
}

/// Publishing has one **irreducible** round boundary and one that was avoidable.
///
/// The transaction holding the identity cannot be asked for until the identity
/// has named its outpoint — that is a real dependency and no reordering helps.
/// The funding lookup is not: it reads an address the caller supplied, so it
/// belongs in the first round with `getidentity`. Two rounds, not three.
#[test]
fn preparing_a_publish_costs_the_one_round_it_cannot_avoid() {
    let key = spender();
    let theirs = [0xaa; 20];
    let identity = identity_of(&key.address(), vec![(theirs, vec![b"not mine".to_vec()])]);
    let outpoint = verus_tx::Txid::from_internal([0x22; 32]);

    let script = verus_tx::cc::identity_primary_script(
        verus_tx::identity_id(&identity.name, Some(identity.parent)),
        identity.to_bytes().expect("identity encodes"),
        identity.revocation_authority,
        identity.recovery_authority,
        identity.has_tokenized_control(),
    )
    .expect("identity script");

    let mut replies = replies_for(&key.address());
    replies.insert("getidentity", identity_reply(&identity, &outpoint));
    replies.insert(
        "getrawtransaction",
        serde_json::json!({"result": {"vout": [
            {"valueSat": 0, "scriptPubKey": {"hex": hex::encode(&script)}}
        ]}})
        .to_string(),
    );

    let funding_address = key.address().to_string();
    let (unsent, rounds) = drive_with(replies, |client| {
        verus_flows::prepare_publish(
            client,
            &[&key],
            "rustsdk.VRSCTEST@",
            &funding_address,
            [0xbb; 20],
            vec![b"mine".to_vec()],
        )
    });

    assert_eq!(rounds.len(), 2, "two rounds: {rounds:#?}");
    let mut first: Vec<String> = rounds[0].iter().map(|b| method_of(b)).collect();
    first.sort();
    assert_eq!(
        first,
        [
            "getaddressmempool",
            "getaddressutxos",
            "getblockcount",
            "getidentity"
        ],
        "the funding lookup does not wait on the identity"
    );
    assert_eq!(
        rounds[1].iter().map(|b| method_of(b)).collect::<Vec<_>>(),
        ["getrawtransaction"],
        "and the transaction cannot be asked for before the outpoint is known"
    );

    // The erase invariant, on the bytes a browser would send: an update
    // republishes the identity in full, so another application's key has to
    // survive being driven exactly as it survives the one-pass path.
    let raw = hex::decode(&unsent.hex).expect("hex");
    let republished = verus_wire::TxV4::deserialize(&raw)
        .expect("parse")
        .outputs
        .iter()
        .find_map(
            |out| match verus_tx::decode_output_script(&out.script_pubkey) {
                Ok(verus_tx::OutputKind::IdentityPrimary { identity }) => Some(*identity),
                _ => None,
            },
        )
        .expect("the update carries an identity output");
    assert_eq!(
        republished
            .content_multimap
            .iter()
            .find(|(k, _)| *k == theirs)
            .expect("another application's key must survive")
            .1,
        vec![b"not mine".to_vec()]
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
        answers
            .record(body.clone(), replies[method_of(body).as_str()].clone())
            .expect("a fixture fits");
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
    answers
        .record(
            name_check.clone(),
            r#"{"error":{"code":-5,"message":"Identity not found"}}"#,
        )
        .expect("a small reply");
    for body in bodies.iter().filter(|b| method_of(b) != "getidentity") {
        if let Some(reply) = replies.get(method_of(body).as_str()) {
            answers
                .record(body.clone(), reply.clone())
                .expect("a fixture fits");
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

/// Moving a token a VerusID holds reads the identity, then two independent
/// things: the identity's token outputs and the fee payer's coins.
///
/// The second pair is the point. Neither needs the other's answer, so they
/// belong in one round — and they were in two until this test was written,
/// because the first was unwrapped with `?` before the second was issued. That
/// is a whole extra network round trip for a browser and is invisible to every
/// other test of this flow: the bytes it signs are identical either way.
#[test]
fn moving_a_token_from_an_identity_reads_the_two_funding_sources_together() {
    let key = spender();
    let fee_from = key.address();
    let identity = identity_of(&fee_from, Vec::new());
    let identity_at = identity_address(&identity);
    let currency = verus_tx::CurrencyId::from_bytes(PARENT);

    // A reserve output the identity holds, carrying the token and no native
    // value — which is why the fee has to come from the key's own coins, and
    // therefore why there are two funding reads to batch at all.
    let token_script = verus_tx::cc::reserve_output_script_to(
        verus_tx::Destination::Identity(identity_at.hash()),
        currency,
        500_000_000,
    )
    .expect("a reserve output script");

    let utxo_reply = |address: &str, index: u32, satoshis: u64, script: &str| {
        format!(
            r#"{{"result":[{{"address":"{address}","blocktime":1785262420,"height":1166385,"isspendable":1,"outputIndex":{index},"satoshis":{satoshis},"script":"{script}","txid":"5e19de6d3f77b5e1f49ec92db23027d5f026db92004b026465a61bff8ab13d7e"}}]}}"#
        )
    };

    let identity_utxos = utxo_reply(&identity_at.to_string(), 0, 0, &hex::encode(&token_script));
    let fee_utxos = utxo_reply(
        &fee_from.to_string(),
        1,
        8_830_000,
        &format!("76a914{}88ac", hex::encode(fee_from.hash())),
    );
    let getidentity = identity_reply(&identity, &verus_tx::Txid::from_internal([0x55; 32]));
    let identity_text = identity_at.to_string();

    let (_unsent, rounds) = drive_dispatching(
        |body| match method_of(body).as_str() {
            "getidentity" => getidentity.clone(),
            "getblockcount" => r#"{"result":1167555}"#.to_string(),
            "getaddressmempool" => r#"{"result":[]}"#.to_string(),
            // The dispatch that `drive_with` cannot do: same method, two
            // addresses, and each answer must name only the address it was
            // asked about.
            "getaddressutxos" if body.contains(&identity_text) => identity_utxos.clone(),
            "getaddressutxos" => fee_utxos.clone(),
            other => panic!("no fixture for {other}"),
        },
        |client| {
            verus_flows::prepare_send_token_from_identity(
                client,
                &[&key],
                &key,
                &identity_text,
                currency,
                PAYEE,
                verus_flows::Amount::from_sat(100_000_000),
            )
        },
    );

    assert_eq!(
        rounds.len(),
        2,
        "the identity must be read before its address is known, and everything \
         else goes out together: {rounds:#?}"
    );

    // Both funding reads in the second round, against the two different
    // addresses. This is the assertion that fails if either `?` moves back.
    let second: Vec<String> = rounds[1].iter().map(|b| method_of(b)).collect();
    assert_eq!(
        second.iter().filter(|m| *m == "getaddressutxos").count(),
        2,
        "the identity's tokens and the fee payer's coins are asked for in one \
         round: {:#?}",
        rounds[1]
    );
    assert!(
        rounds[1].iter().any(|b| b.contains(&identity_text))
            && rounds[1].iter().any(|b| b.contains(&fee_from.to_string())),
        "both addresses are in the same round: {:#?}",
        rounds[1]
    );
}
