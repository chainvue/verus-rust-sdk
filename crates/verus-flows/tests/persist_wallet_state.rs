//! A wallet has to survive a restart.
//!
//! Two things it holds cannot be recovered from the chain if it forgets them.
//!
//! **What a scan found.** Nothing on chain says which outputs are yours — that
//! is the point of a shielded pool — so a wallet that keeps only a balance
//! rescans from its birthday every launch. And notes have to be stored *with*
//! the nullifiers observed alongside them: a note is spendable exactly when its
//! nullifier has not been seen, so storing the two apart loses money in the
//! dangerous direction, reporting a balance that includes coins already gone.
//!
//! **Bytes that are proved but not sent.** A shielded spend costs tens of
//! seconds of Groth16. A crash between the proof and the broadcast should cost
//! a restart, not another proof.
//!
//! These use the real note from the on-chain z→t in `PROVEN.md`, so the values
//! being round-tripped are ones the chain actually held.

#![cfg(feature = "serde")]

use verus_flows::{ScanResult, Unsent};
use verus_sapling::scan::DetectedNote;

/// The change note the live z→t spent — block 1173695, position 3184.
fn the_real_note() -> DetectedNote {
    DetectedNote {
        height: 1_173_695,
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

fn a_scan() -> ScanResult {
    ScanResult {
        notes: vec![the_real_note()],
        nullifiers: vec![verus_flows::SeenNullifier {
            height: 1_173_694,
            nullifier: hex_32(&"11".repeat(32)),
        }],
        from: 1_173_691,
        to: 1_173_695,
        tip_hash: hex_32(&"22".repeat(32)),
        checkpoints: vec![verus_flows::Checkpoint {
            height: 1_173_695,
            hash: hex_32(&"22".repeat(32)),
        }],
    }
}

/// Every field survives, including the 43-byte address serde cannot derive.
#[test]
fn a_scan_result_round_trips_field_for_field() {
    let before = a_scan();
    let json = serde_json::to_string(&before).expect("serialize");
    let after: ScanResult = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(after.from, before.from);
    assert_eq!(after.to, before.to);
    assert_eq!(after.tip_hash, before.tip_hash);
    assert_eq!(after.nullifiers, before.nullifiers);
    assert_eq!(after.notes.len(), 1);

    // Compared field by field rather than by `==` on the struct: a derived
    // `PartialEq` would let a field silently dropped from the serialization
    // pass if its default happened to match.
    let (a, b) = (&after.notes[0], &before.notes[0]);
    assert_eq!(a.height, b.height);
    assert_eq!(a.tx_index, b.tx_index);
    assert_eq!(a.output_index, b.output_index);
    assert_eq!(a.position, b.position);
    assert_eq!(a.value, b.value);
    assert_eq!(a.recipient, b.recipient);
    assert_eq!(a.nullifier, b.nullifier);
}

/// The property the whole thing is for: what was spendable before the restart
/// is spendable after it, and what was spent stays spent.
///
/// This is the join that goes wrong when notes and nullifiers are stored
/// separately — and it goes wrong in the direction that reports money the
/// wallet cannot spend.
#[test]
fn spendability_survives_a_restart() {
    let before = a_scan();
    assert_eq!(before.unspent(&[]).len(), 1);
    assert_eq!(before.balance(&[]), 4_970_000);

    let after: ScanResult =
        serde_json::from_str(&serde_json::to_string(&before).expect("serialize"))
            .expect("deserialize");
    assert_eq!(after.unspent(&[]).len(), 1);
    assert_eq!(after.balance(&[]), 4_970_000);

    // And once the note's own nullifier is known — from this scan or an
    // earlier one — it is worth nothing, on both sides of the restart.
    let spent = [the_real_note().nullifier];
    assert!(before.unspent(&spent).is_empty());
    assert!(after.unspent(&spent).is_empty());
    assert_eq!(after.balance(&spent), 0);
}

/// A scan that saw the note being spent reports it as gone after a restart too.
///
/// Distinct from the test above: there the nullifier is supplied by the caller
/// from an earlier chunk; here it is inside the persisted result, which is the
/// field that would be silently lost if only `notes` were stored.
#[test]
fn a_nullifier_inside_the_persisted_scan_still_counts() {
    let mut scan = a_scan();
    scan.nullifiers.push(verus_flows::SeenNullifier {
        height: 1_173_695,
        nullifier: the_real_note().nullifier,
    });
    assert!(scan.unspent(&[]).is_empty());

    let after: ScanResult = serde_json::from_str(&serde_json::to_string(&scan).expect("serialize"))
        .expect("deserialize");
    assert!(
        after.unspent(&[]).is_empty(),
        "the observed nullifier did not survive, so a spent note came back to life"
    );
}

/// Proved bytes survive a crash before the broadcast.
///
/// The alternative is paying for the Groth16 proof twice — and, for a caller
/// that rebuilt rather than reloaded, signing *different* bytes against the
/// same notes.
#[test]
fn unsent_bytes_round_trip() {
    let unsent = Unsent {
        hex: "0400008085202f89".repeat(4),
        txid: "2db1cc11c74dc72b9e4e174659404ac58c16599a8442cf9e93e6a23c2c06ae3d".into(),
        outcome: 42u32,
    };
    let json = serde_json::to_string(&unsent).expect("serialize");
    let after: Unsent<u32> = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(after, unsent);
    // The bytes are the whole point: a wallet reloading these must broadcast
    // exactly what it proved, not something rebuilt from the same inputs.
    assert_eq!(after.hex, unsent.hex);
}

/// The wire format, pinned exactly.
///
/// Every other test here is serialize-then-deserialize with the same code on
/// both sides, which is symmetric by construction — so a *consistent* mistake
/// passes them all. Rename `tip_hash` to `tipHash` and they stay green while
/// every store already written stops loading. Swap `from` and `to` and they
/// stay green while old stores load silently with the two reversed, and the
/// next scan starts from the wrong height.
///
/// This is the only test that would notice, because it is the only one that
/// reads the keys. It is also the store's compatibility contract: changing it
/// is changing a file format someone already has on disk — which is precisely
/// what happened when nullifiers gained a height and `checkpoints` appeared,
/// and this test is how that was made visible rather than silent.
#[test]
fn the_stored_shape_is_exactly_this() {
    // The address is spelled as the decode of the committed `zs…` string rather
    // than as a literal blob, so this pins the *schema* — the key names, their
    // order, and that bytes are hex — without pretending to independently
    // derive bytes it would only be copying from the code under test.
    let recipient = hex::encode(the_real_note().recipient);
    let expected = format!(
        concat!(
            r#"{{"notes":[{{"height":1173695,"tx_index":1,"output_index":1,"position":3184,"#,
            r#""value":4970000,"recipient":"{recipient}","#,
            r#""nullifier":"d4ee6b478c95b36f72c73fe8b9bc1e0271a795bb9a2a6c9abd3d2e0a75901a60"}}],"#,
            r#""nullifiers":[{{"height":1173694,"#,
            r#""nullifier":"1111111111111111111111111111111111111111111111111111111111111111"}}],"#,
            r#""from":1173691,"to":1173695,"#,
            r#""tip_hash":"2222222222222222222222222222222222222222222222222222222222222222","#,
            r#""checkpoints":[{{"height":1173695,"#,
            r#""hash":"2222222222222222222222222222222222222222222222222222222222222222"}}]}}"#,
        ),
        recipient = recipient,
    );
    assert_eq!(
        serde_json::to_string(&a_scan()).expect("serialize"),
        expected
    );
    // And the address really is 43 bytes of hex, so the line above is not
    // pinning an empty string into place.
    assert_eq!(recipient.len(), 86);
}

/// Heights and values above 2^32 survive.
///
/// Every real fixture here fits in a `u32` — height 1 173 695, value 4 970 000
/// — so a codec that quietly routed a `u64` through a narrower type, or through
/// an `f64`, would round-trip all of them exactly and pass every other test.
/// Money is integers in this workspace, and this is where a store would break
/// it.
#[test]
fn large_values_are_not_truncated() {
    let mut scan = a_scan();
    scan.notes[0].value = u64::MAX;
    scan.notes[0].position = (1u64 << 53) + 1;
    scan.notes[0].height = (1u64 << 40) + 7;
    scan.to = u64::MAX - 1;

    let after: ScanResult = serde_json::from_str(&serde_json::to_string(&scan).expect("serialize"))
        .expect("deserialize");
    assert_eq!(after.notes[0].value, u64::MAX);
    assert_eq!(after.notes[0].position, (1u64 << 53) + 1);
    assert_eq!(after.notes[0].height, (1u64 << 40) + 7);
    assert_eq!(after.to, u64::MAX - 1);
}

/// It loads from a reader, not only from a `&str`.
///
/// A wallet writes with `to_writer` and reads with `from_reader`. An earlier
/// version of the byte codec deserialized through `&str`, which only works for
/// formats that hand out a string borrowed from the input buffer — so that loop
/// wrote a store it could not read back, and every round-trip test here passed
/// anyway because they all used `from_str`.
#[test]
fn a_store_written_to_a_writer_reads_back_from_a_reader() {
    let mut file = Vec::new();
    serde_json::to_writer(&mut file, &a_scan()).expect("write");
    let after: ScanResult =
        serde_json::from_reader(std::io::Cursor::new(file)).expect("read it back");
    assert_eq!(after.notes[0].recipient, the_real_note().recipient);
    assert_eq!(after.tip_hash, a_scan().tip_hash);
}

/// The address helper refuses a corrupted store rather than loading a note that
/// claims to be paid somewhere it is not.
#[test]
fn a_corrupted_address_is_refused_on_load() {
    let json = serde_json::to_string(&a_scan()).expect("serialize");
    let truncated = json.replace(
        &hex::encode(the_real_note().recipient),
        &hex::encode(&the_real_note().recipient[..40]),
    );
    assert!(
        serde_json::from_str::<ScanResult>(&truncated).is_err(),
        "a 40-byte address should not load as a payment address"
    );
}
