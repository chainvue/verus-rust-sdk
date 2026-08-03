//! What the anchor check must catch, and what it must not wave through.
//!
//! An anchor is computed entirely from data one light server supplies: the
//! frontier, the commitments, the tree sizes. Every continuity check in
//! `flows::shielded` compares those values against each other, so a server that
//! lies consistently passes all of them — its own module docs say so.
//!
//! `check_anchor` is the one comparison against something that server does not
//! control: the `finalsaplingroot` a Verus daemon reports for that block, which
//! consensus fixed. Everything here is about that comparison being real, since
//! the cost of it being decorative is a Groth16 proof and a daemon rejection
//! saying `bad-txns-shielded-requirements-not-met`.

use verus_flows::check_anchor;
use verus_flows::testing::ScriptedReader;
use verus_flows::FlowError;

/// The real `finalsaplingroot` of VRSCTEST block 1167987 — the block that
/// created the note `shielded_note_lifecycle` follows — exactly as
/// `getblock 1167987` renders it.
const ROOT_1167987: &str = "2da8970e222a0edde38d196989561e4f3c0c307a978594ac33ca7f267b88ce3c";

/// The same value as the witness produces it: header display order reversed.
fn anchor_of(root_display: &str) -> [u8; 32] {
    let mut bytes = hex::decode(root_display).expect("hex");
    bytes.reverse();
    bytes.try_into().expect("32 bytes")
}

#[test]
fn an_anchor_the_chain_committed_to_is_accepted() {
    let reader = ScriptedReader::new(1_167_990).with_final_sapling_root(1_167_987, ROOT_1167987);
    check_anchor(&reader, 1_167_987, anchor_of(ROOT_1167987)).expect("the chain's own root");
}

/// The failure this whole check exists for.
///
/// A frontier from the wrong height fails *nowhere* else — the note decrypts,
/// the witness builds, the proof generates, the transaction serializes. Only
/// the daemon objects, ~30 seconds later.
#[test]
fn an_anchor_the_chain_never_had_is_refused_before_proving() {
    let reader = ScriptedReader::new(1_167_990).with_final_sapling_root(1_167_987, ROOT_1167987);
    match check_anchor(&reader, 1_167_987, [0xab; 32]) {
        Err(FlowError::Shielded(message)) => {
            // Both roots are named, because "the anchor is wrong" without them
            // is not something a wallet author can act on.
            assert!(message.contains(&"ab".repeat(32)), "{message}");
            assert!(
                message.contains(&hex::encode(anchor_of(ROOT_1167987))),
                "{message}"
            );
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// Byte order is the trap here: a header renders the root reversed, like a
/// txid. Comparing without reversing is a check that always fails, which is
/// safe but useless — and comparing the *wrong* way round on both sides would
/// be a check that always passes.
#[test]
fn the_header_ordering_is_not_the_witness_ordering() {
    let reader = ScriptedReader::new(1_167_990).with_final_sapling_root(1_167_987, ROOT_1167987);
    let raw: [u8; 32] = hex::decode(ROOT_1167987)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    // The un-reversed header bytes are NOT the anchor.
    assert!(check_anchor(&reader, 1_167_987, raw).is_err());
    // And the two really are different values, so the assertion above is not
    // vacuous on a palindromic root.
    assert_ne!(raw, anchor_of(ROOT_1167987));
}

/// The height is passed through to the node rather than ignored.
///
/// Without this the check would compare against whatever block the double felt
/// like serving, and would pass for a witness anchored anywhere.
#[test]
fn the_anchor_is_checked_against_the_height_it_came_from() {
    let reader = ScriptedReader::new(1_167_990)
        .with_final_sapling_root(1_167_987, ROOT_1167987)
        .with_final_sapling_root(1_167_988, &"11".repeat(32));

    check_anchor(&reader, 1_167_987, anchor_of(ROOT_1167987)).expect("its own height");
    // The very same anchor, checked one block later, must not pass.
    assert!(check_anchor(&reader, 1_167_988, anchor_of(ROOT_1167987)).is_err());
}

/// A node that cannot answer must not read as agreement.
#[test]
fn an_unreachable_block_is_an_error_not_a_pass() {
    let reader = ScriptedReader::new(1_167_990).with_final_sapling_root(1_167_987, ROOT_1167987);
    match check_anchor(&reader, 9_999_999, anchor_of(ROOT_1167987)) {
        Err(FlowError::Rpc(_)) => {}
        other => panic!("expected the node's own error, got {other:?}"),
    }
}

/// A node that omits the field must not read as agreement either.
#[test]
fn a_block_without_the_field_is_refused() {
    let reader = ScriptedReader::new(1_167_990).without_sapling_roots();
    match check_anchor(&reader, 1_167_987, anchor_of(ROOT_1167987)) {
        Err(FlowError::Shielded(message)) => {
            // The *missing-field* message, not the mismatch one. An earlier
            // version of this test used a double that always supplied a root,
            // so it asserted the mismatch branch under this name and left the
            // branch it is named for entirely uncovered.
            assert!(message.contains("carries no finalsaplingroot"), "{message}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// And the all-zero root a node might report for a pre-Sapling block is a
/// mismatch, which is a different message and a different reason.
#[test]
fn an_all_zero_root_is_a_mismatch_not_an_absence() {
    let reader = ScriptedReader::new(1_167_990);
    match check_anchor(&reader, 1_167_987, anchor_of(ROOT_1167987)) {
        Err(FlowError::Shielded(message)) => assert!(message.contains("committed to"), "{message}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A root that is not 32 bytes is refused with a message that says so, rather
/// than panicking on the conversion.
#[test]
fn a_short_root_is_refused_not_panicked_on() {
    let reader = ScriptedReader::new(1_167_990).with_final_sapling_root(1_167_987, "deadbeef");
    match check_anchor(&reader, 1_167_987, anchor_of(ROOT_1167987)) {
        Err(FlowError::Shielded(message)) => {
            assert!(message.contains("4 bytes, not 32"), "{message}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// And one that is not hex at all.
#[test]
fn a_root_that_is_not_hex_is_refused() {
    let reader =
        ScriptedReader::new(1_167_990).with_final_sapling_root(1_167_987, &"zz".repeat(32));
    assert!(matches!(
        check_anchor(&reader, 1_167_987, anchor_of(ROOT_1167987)),
        Err(FlowError::Shielded(_))
    ));
}

/// The scripted chain can serve a mempool, so a wallet can test its own
/// "is my payment still pending?" logic against it.
///
/// Here because `with_mempool` is new public test surface and would otherwise
/// be used by nothing — a double nobody drives is a double nobody knows works.
#[test]
fn the_scripted_chain_can_report_pending_transactions() {
    use verus_flows::ChainReader;

    let txid = "ab".repeat(32);
    let reader = ScriptedReader::new(1_167_990).with_mempool(&[&txid]);
    assert_eq!(reader.mempool().expect("scripted"), vec![txid]);

    // And an unscripted chain has an empty mempool rather than an error:
    // nothing pending is an answer.
    assert!(ScriptedReader::new(1_167_990)
        .mempool()
        .expect("scripted")
        .is_empty());
}
