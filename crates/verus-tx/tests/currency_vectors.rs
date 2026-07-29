//! What the committed currency-definition vectors pin down.
//!
//! `verus-tx` cannot yet build a currency launch — see
//! `fixtures/daemon/currency_definitions.json` for how far the encoding has been
//! mapped and what is still unknown. These tests guard the facts that *are*
//! established, so the fixtures cannot rot silently and the next person to pick
//! this up starts from something checked rather than something remembered.

use std::collections::BTreeSet;

fn fixture() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/daemon/currency_definitions.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("fixture")).expect("json")
}

fn hex_bytes(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

/// Read a script push, returning its contents.
fn read_push(bytes: &[u8], at: usize) -> (Vec<u8>, usize) {
    let op = bytes[at];
    let (length, next) = match op {
        n if n < 0x4c => (usize::from(n), at + 1),
        0x4c => (usize::from(bytes[at + 1]), at + 2),
        0x4d => (
            usize::from(u16::from_le_bytes([bytes[at + 1], bytes[at + 2]])),
            at + 3,
        ),
        other => panic!("unexpected push opcode {other:#x}"),
    };
    (bytes[next..next + length].to_vec(), next + length)
}

/// The `CCurrencyDefinition` payload out of a definition output script.
fn payload(script_hex: &str) -> Vec<u8> {
    let script = hex_bytes(script_hex);
    let (_master, at) = read_push(&script, 0);
    assert_eq!(script[at], 0xcc, "expected OP_CHECKCRYPTOCONDITION");
    let (params, at) = read_push(&script, at + 1);
    assert_eq!(script[at], 0x75, "expected OP_DROP");

    let (header, j) = read_push(&params, 0);
    assert_eq!(header.len(), 4);
    // version, eval, m, n.
    assert_eq!(header[0], 3, "OptCCParams version");
    assert_eq!(header[1], 2, "EVAL_CURRENCY_DEFINITION");
    let (_destination, j) = read_push(&params, j);
    let (payload, _) = read_push(&params, j);
    payload
}

/// Every permutation the user asked for is actually present.
#[test]
fn the_matrix_covers_every_non_pbaas_permutation() {
    let fixture = fixture();
    let vectors = fixture["vectors"].as_object().expect("vectors");

    let options: BTreeSet<u64> = vectors
        .values()
        .filter_map(|v| v["definition"]["options"].as_u64())
        .collect();
    // TOKEN alone, and with FRACTIONAL, IDRESTRICTED, IDSTAKING, IDREFERRALS
    // and IDREFERRALSREQUIRED.
    for expected in [32, 33, 34, 36, 40, 56] {
        assert!(
            options.contains(&expected),
            "no vector with options {expected}"
        );
    }
    // And nothing PBaaS, which was explicitly out of scope.
    for present in &options {
        assert_eq!(present & 0x100, 0, "options {present} is a PBaaS chain");
    }

    let protocols: BTreeSet<u64> = vectors
        .values()
        .filter_map(|v| v["definition"]["proofprotocol"].as_u64())
        .collect();
    assert!(protocols.contains(&1), "no proofprotocol 1 vector");
    assert!(protocols.contains(&2), "no centralized (mintable) vector");
}

/// The output frame, which is the part that is settled.
#[test]
fn every_definition_uses_eval_two_and_a_public_key_destination() {
    let fixture = fixture();
    for (name, vector) in fixture["vectors"].as_object().expect("vectors") {
        let script_hex = vector["definition_script"].as_str().expect("script");
        // `payload` asserts the eval code; this asserts the destination shape,
        // which is unusual: a 33-byte public key rather than a 20-byte hash.
        let script = hex_bytes(script_hex);
        let (master, _) = read_push(&script, 0);
        let (_header, j) = read_push(&master, 0);
        let (destination, _) = read_push(&master, j);
        assert_eq!(
            destination.len(),
            33,
            "{name}: destination is not a compressed public key"
        );
        assert!(payload(script_hex).len() > 100, "{name}: payload too short");
    }
}

/// The fields that have been mapped, checked against what the daemon reported
/// for the same vector. If the layout drifts, this is what notices.
#[test]
fn the_mapped_header_fields_decode_correctly() {
    let fixture = fixture();
    for (name, vector) in fixture["vectors"].as_object().expect("vectors") {
        let definition = &vector["definition"];
        let payload = payload(vector["definition_script"].as_str().expect("script"));

        let version = u32::from_le_bytes(payload[0..4].try_into().unwrap());
        assert_eq!(
            u64::from(version),
            definition["version"].as_u64().expect("version"),
            "{name}: version"
        );

        let options = u32::from_le_bytes(payload[4..8].try_into().unwrap());
        assert_eq!(
            u64::from(options),
            definition["options"].as_u64().expect("options"),
            "{name}: options"
        );

        // parent(20), then the name as a length-prefixed string.
        let name_length = usize::from(payload[28]);
        let decoded = std::str::from_utf8(&payload[29..29 + name_length]).expect("utf8");
        assert_eq!(
            decoded,
            definition["name"].as_str().expect("name"),
            "{name}: name"
        );

        // systemid, launchsystemid, then the two protocol words.
        let at = 29 + name_length + 40;
        let notarization = u32::from_le_bytes(payload[at..at + 4].try_into().unwrap());
        let proof = u32::from_le_bytes(payload[at + 4..at + 8].try_into().unwrap());
        assert_eq!(
            u64::from(notarization),
            definition["notarizationprotocol"].as_u64().expect("np"),
            "{name}: notarizationprotocol"
        );
        assert_eq!(
            u64::from(proof),
            definition["proofprotocol"].as_u64().expect("pp"),
            "{name}: proofprotocol"
        );
    }
}

/// The fixture must keep saying what is *not* known, or the next person will
/// assume the mapping is complete.
#[test]
fn the_fixture_still_records_what_is_unmapped() {
    let fixture = fixture();
    let note = fixture["_payload_layout_so_far"]["_incomplete"]
        .as_str()
        .expect("the incompleteness note was removed");
    assert!(note.contains("NOT yet mapped"));
    assert!(
        fixture["_structure"]["launch_transaction_outputs"]
            .as_array()
            .expect("outputs")
            .len()
            == 7,
        "a launch is seven outputs; the note about that changed"
    );
}
