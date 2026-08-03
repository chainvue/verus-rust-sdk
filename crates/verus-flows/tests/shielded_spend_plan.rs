//! A real spend plan, replayed from the data the chain actually served.
//!
//! On 2026-08-03 this SDK shielded 0.55 VRSCTEST into two notes, spent both of
//! them into a z→z payment through `flows::shielded`, and then spent the change
//! note back out to a transparent address:
//!
//! ```text
//! shield  98d5a67ef07e528c4811c7a4a7ee8dc1c71f6cc552f48c473f214dc5c90e0db2  block 1173691
//! z→z     2e2b04df1161e220f6a3dfd80abb821e15723f42fea05dec2dc451da5bcd27f5  block 1173695
//! z→t     2db1cc11c74dc72b9e4e174659404ac58c16599a8442cf9e93e6a23c2c06ae3d  block 1173696
//! ```
//!
//! What is replayed here is the plan behind that last one: the lightwalletd
//! responses are committed verbatim, and the anchor they produce is checked
//! against the `finalsaplingroot` a Verus daemon reports for the same block.
//!
//! That is the point of the test. Every input to the anchor comes from the
//! light server, so a plan agreeing with itself proves nothing — the
//! `flows::shielded` module docs say as much. The root below came from a
//! different machine over a different protocol, and consensus fixed it.

use verus_flows::testing::ScriptedReader;
use verus_flows::{plan_spend, FlowError};
use verus_light::{HttpResponse, LightClient, LightError, LightTransport};
use verus_sapling::scan::DetectedNote;

/// Block the change note was created in, and the height it was witnessed to.
const ANCHOR: u64 = 1_173_695;

/// `getblock 1173695`, field `finalsaplingroot`, exactly as the daemon renders
/// it — reversed, the way a header displays a txid.
const ROOT: &str = "0735f7fca9e7af70ffd77f1ef4ba92783c22a711d6249b3df6f7f0d37d7a1ddb";

/// The same value in the order a witness produces it. Written out rather than
/// computed so that reversing in both the test and the code under test cannot
/// cancel out into a check that always passes.
const ANCHOR_BYTES: &str = "db1d7a7dd3f0f7f63d9b24d611a7223c7892baf41e7fd7ff70afe7a9fcf73507";

/// The z→z transaction's change output, as the scan found it.
///
/// `tx_index` 1 is that transaction's position in block 1173695;
/// `output_index` 1 is the change, the payment to the other account having
/// landed at 0. Neither is guessable — the Sapling builder shuffles a bundle's
/// outputs, which is the whole reason detection reports the index instead of
/// assuming it.
fn the_change_note() -> DetectedNote {
    DetectedNote {
        height: ANCHOR,
        tx_index: 1,
        output_index: 1,
        position: 3184,
        value: 4_970_000,
        recipient: verus_sapling::zaddr::decode(
            "zs12fkm5rmsv8k3yf7et8vjx4le77wy6t6s43t7u4rqsxfvheg9742xrvrvx0f3cp49qtdjkz4x2ag",
        )
        .expect("a payment address"),
        nullifier: hex_32("d4ee6b478c95b36f72c73fe8b9bc1e0271a795bb9a2a6c9abd3d2e0a75901a60"),
    }
}

fn hex_32(text: &str) -> [u8; 32] {
    hex::decode(text)
        .expect("hex")
        .try_into()
        .expect("32 bytes")
}

/// The light server's tip at the time the fixtures were captured.
const TIP: u64 = 1_173_724;

/// Serves the responses this plan drew, keyed by method.
///
/// The plan asks for `GetBlockRange` twice with the same range — once to
/// witness, once to fetch the full output description — so one fixture answers
/// both. Anything else is a panic rather than an empty body: a plan that
/// quietly asked for something new would otherwise pass here and fail live.
struct Server;

impl LightTransport for Server {
    fn call(&self, path: &str, _request: &[u8]) -> Result<HttpResponse, LightError> {
        let base = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/lightwalletd/");
        let name = if path.ends_with("GetLatestBlock") {
            "spend_latestblock.bin"
        } else if path.ends_with("GetTreeState") {
            "spend_treestate_before.bin"
        } else if path.ends_with("GetBlockRange") {
            "spend_block.bin"
        } else if path.ends_with("GetTransaction") {
            "spend_transaction.bin"
        } else {
            panic!("the plan asked for {path}, which this replay does not cover")
        };
        Ok(HttpResponse {
            status: None,
            body: std::fs::read(format!("{base}{name}")).expect("fixture is committed"),
        })
    }
}

fn node() -> ScriptedReader {
    ScriptedReader::new(1_173_700).with_final_sapling_root(ANCHOR, ROOT)
}

/// The whole plan, against the chain's own root.
#[test]
fn the_plan_reaches_the_anchor_the_chain_committed_to() {
    let plan = plan_spend(
        &LightClient::new(Server),
        &node(),
        &[the_change_note()],
        4_970_000,
        Some(ANCHOR),
    )
    .expect("the plan the live spend used");

    assert_eq!(hex::encode(plan.anchor), ANCHOR_BYTES);
    assert_eq!(plan.anchor_height, ANCHOR);
    // The tip is recorded separately from the anchor, because a caller pinning
    // a deeper anchor must not get an expiry behind the chain.
    assert_eq!(plan.tip, TIP);
    assert!(plan.tip > plan.anchor_height);
    assert_eq!(plan.notes.len(), 1);
    assert_eq!(plan.total_in, 4_970_000);
    // 0.0494 out and 0.0003 to the miner is the whole note, so the live spend
    // carried no change output at all.
    assert_eq!(plan.change, 0);
}

/// Change is what the notes are worth beyond the spend, and it has to come back
/// — shielded value cannot be split at the input.
#[test]
fn anything_the_spend_does_not_use_becomes_change() {
    let plan = plan_spend(
        &LightClient::new(Server),
        &node(),
        &[the_change_note()],
        1_000_000,
        Some(ANCHOR),
    )
    .expect("a plan");
    assert_eq!(plan.change, 4_970_000 - 1_000_000);
}

/// The anchor check is wired into the plan, not merely available beside it.
///
/// A node reporting a different root must stop the plan, because everything
/// after this point costs a Groth16 proof — and the daemon's rejection, thirty
/// seconds later, names nothing but `bad-txns-shielded-requirements-not-met`.
#[test]
fn a_node_that_reports_a_different_root_stops_the_plan() {
    let lying = ScriptedReader::new(1_173_700).with_final_sapling_root(ANCHOR, &"11".repeat(32));
    match plan_spend(
        &LightClient::new(Server),
        &lying,
        &[the_change_note()],
        4_970_000,
        Some(ANCHOR),
    ) {
        Err(FlowError::Shielded(message)) => {
            assert!(message.contains(ANCHOR_BYTES), "{message}");
        }
        other => panic!("expected the anchor check to refuse, got {other:?}"),
    }
}

/// A note cannot be witnessed before the block that created it.
#[test]
fn an_anchor_below_the_note_is_refused() {
    match plan_spend(
        &LightClient::new(Server),
        &node(),
        &[the_change_note()],
        4_970_000,
        Some(ANCHOR - 1),
    ) {
        Err(FlowError::Shielded(message)) => {
            assert!(message.contains("earlier"), "{message}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// More than the notes hold is `InsufficientFunds`, before any fetching.
///
/// Driven through a transport that panics on **every** call, so the ordering in
/// the name is pinned rather than merely true today. Against the ordinary
/// fixture server this test would pass just as happily if the funds check moved
/// after the round trips.
#[test]
fn a_spend_beyond_the_notes_is_refused_before_the_light_server_is_touched() {
    struct NeverServes;
    impl LightTransport for NeverServes {
        fn call(&self, path: &str, _request: &[u8]) -> Result<HttpResponse, LightError> {
            panic!("the light server was asked for {path} before the funds were checked")
        }
    }

    match plan_spend(
        &LightClient::new(NeverServes),
        &node(),
        &[the_change_note()],
        4_970_001,
        Some(ANCHOR),
    ) {
        Err(FlowError::InsufficientFunds {
            needed, available, ..
        }) => {
            assert_eq!(needed.to_sat(), 4_970_001);
            assert_eq!(available.to_sat(), 4_970_000);
        }
        other => panic!("expected InsufficientFunds, got {other:?}"),
    }
}

/// And one satoshi less is affordable, so the boundary above is the real one
/// rather than a refusal that would have fired anywhere.
#[test]
fn exactly_what_the_notes_hold_is_affordable() {
    let plan = plan_spend(
        &LightClient::new(Server),
        &node(),
        &[the_change_note()],
        4_970_000,
        Some(ANCHOR),
    )
    .expect("the note covers itself exactly");
    assert_eq!(plan.change, 0);
}
