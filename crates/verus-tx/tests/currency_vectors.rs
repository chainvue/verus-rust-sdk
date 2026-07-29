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

/// Weights are little-endian, and that is the one fact worth a test of its own.
///
/// Every other amount in this codebase is the Satoshi VARINT — reserve
/// transfers, and the fee fields inside this very object. A currency definition
/// mixes both forms, so reading one as the other is a silent money bug rather
/// than a parse failure. Settled with asymmetric weights so the two encodings
/// could not be confused for one another.
#[test]
fn weights_are_little_endian_not_varint() {
    let fixture = fixture();
    let vector = &fixture["vectors"]["fractional_asym_weights"];
    let payload = hex::encode(payload(
        vector["definition_script"].as_str().expect("script"),
    ));

    // 0.25 and 0.75 in satoshis, four bytes little-endian.
    assert!(
        payload.contains("40787d01"),
        "0.25 is not LE32 in the payload"
    );
    assert!(
        payload.contains("c0687804"),
        "0.75 is not LE32 in the payload"
    );
    // The eight-byte forms are absent, which is what rules out LE64.
    assert!(!payload.contains("40787d0100000000"));
    assert!(!payload.contains("c068780400000000"));

    // And the VARINT encodings of the same amounts appear nowhere.
    assert!(!payload.contains("8af4ef40"), "0.25 appears as a VARINT");
    assert!(!payload.contains("a2e0d040"), "0.75 appears as a VARINT");

    // The initial supply, by contrast, is eight bytes: 1234.5678.
    assert!(
        payload.contains("e0f698be1c000000"),
        "initialsupply is not LE64"
    );
}

/// A three-reserve definition proves the list shape: a count, then that many
/// fixed-width elements.
#[test]
fn reserve_lists_are_a_count_then_fixed_width_elements() {
    let fixture = fixture();
    let vector = &fixture["vectors"]["fractional_three"];
    let payload = hex::encode(payload(
        vector["definition_script"].as_str().expect("script"),
    ));
    // 0.2, 0.3, 0.5 back to back, four bytes each.
    assert!(
        payload.contains("002d310180c3c90180f0fa02"),
        "three weights are not three contiguous LE32 values"
    );
    assert_eq!(
        vector["definition"]["options"].as_u64(),
        Some(33),
        "the three-reserve vector is not fractional"
    );
}

/// Read a Satoshi VARINT.
fn varint(bytes: &[u8], at: &mut usize) -> u64 {
    let mut value = 0u64;
    loop {
        let byte = bytes[*at];
        *at += 1;
        value = (value << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 != 0 {
            value += 1;
        } else {
            return value;
        }
    }
}

/// The non-fractional layout, parsed end to end.
///
/// This is the state of the reverse engineering: a token definition can be read
/// completely and every field agrees with what the daemon reported. A fractional
/// one cannot — see the incompleteness note the fixture carries.
#[test]
fn every_token_definition_parses_completely() {
    let fixture = fixture();
    let mut parsed = 0;
    for (name, vector) in fixture["vectors"].as_object().expect("vectors") {
        let options = vector["definition"]["options"].as_u64().expect("options");
        if options & 0x1 != 0 {
            continue; // fractional; not mapped yet
        }
        // Preallocations are (identity, amount) pairs — see the test below —
        // but WHERE they sit is not settled: inserting them misaligns this
        // parser well before the amount lists, so they are not simply appended
        // after them. Excluded rather than parsed on a guess.
        if !vector["spec"]["preallocations"].is_null() {
            continue;
        }
        let b = payload(vector["definition_script"].as_str().expect("script"));
        let definition = &vector["definition"];
        let mut at = 0usize;

        let read_u32 = |b: &[u8], at: &mut usize| {
            let v = u32::from_le_bytes(b[*at..*at + 4].try_into().unwrap());
            *at += 4;
            u64::from(v)
        };

        assert_eq!(
            read_u32(&b, &mut at),
            definition["version"].as_u64().unwrap(),
            "{name}: version"
        );
        assert_eq!(read_u32(&b, &mut at), options, "{name}: options");
        at += 20; // parent
        let length = usize::from(b[at]);
        at += 1;
        assert_eq!(
            std::str::from_utf8(&b[at..at + length]).unwrap(),
            definition["name"].as_str().unwrap(),
            "{name}: name"
        );
        at += length + 40; // systemid, launchsystemid
        assert_eq!(
            read_u32(&b, &mut at),
            definition["notarizationprotocol"].as_u64().unwrap(),
            "{name}: notarizationprotocol"
        );
        assert_eq!(
            read_u32(&b, &mut at),
            definition["proofprotocol"].as_u64().unwrap(),
            "{name}: proofprotocol"
        );
        at += 22; // unmapped, all zero in every vector here

        assert_eq!(
            varint(&b, &mut at),
            definition["startblock"].as_u64().unwrap_or(0),
            "{name}: startblock"
        );
        assert_eq!(
            varint(&b, &mut at),
            definition["endblock"].as_u64().unwrap_or(0),
            "{name}: endblock"
        );
        at += 16; // initialsupply and one more 8-byte field

        // currencies, weights, then the three amount lists.
        for width in [20usize, 4, 8, 8, 8] {
            let count = usize::from(b[at]);
            at += 1 + count * width;
        }
        // Preallocations: a count, then that many (20-byte identity, 8-byte
        // amount) pairs. Found because the preallocation vectors ran the parser
        // off the end of what had been read as ten opaque zero bytes — one
        // preallocation lengthens the payload by exactly 28.
        at += 10; // preallocations count plus nine still-unmapped zero bytes

        // The three fee fields close the payload out exactly.
        let registration = varint(&b, &mut at);
        let levels = varint(&b, &mut at);
        let import = varint(&b, &mut at);
        assert_eq!(
            levels,
            definition["idreferrallevels"].as_u64().unwrap_or(0),
            "{name}: idreferrallevels"
        );
        assert!(registration > 0, "{name}: registration fee is zero");
        assert_eq!(import, 2_000_000, "{name}: idimportfees is not 0.02");
        assert_eq!(
            at,
            b.len(),
            "{name}: parser did not consume the payload exactly"
        );
        parsed += 1;
    }
    assert!(
        parsed >= 9,
        "only {parsed} token vectors parsed; there are nine without preallocations"
    );
}

/// A preallocation is an identity and an amount, and it lives where ten bytes
/// previously looked like padding.
#[test]
fn preallocations_are_identity_and_amount_pairs() {
    let fixture = fixture();
    let one = payload(
        fixture["vectors"]["token_preallocation"]["definition_script"]
            .as_str()
            .expect("script"),
    );
    let two = payload(
        fixture["vectors"]["token_two_preallocations"]["definition_script"]
            .as_str()
            .expect("script"),
    );
    let none = payload(
        fixture["vectors"]["token_simple"]["definition_script"]
            .as_str()
            .expect("script"),
    );

    // 20 bytes of identity plus 8 of amount, and the count byte was already
    // there — so one preallocation costs exactly 28 more bytes. Where in the
    // payload they sit is NOT settled: adding one misaligns a parser that
    // otherwise reads a token definition exactly, so they are not appended
    // after the amount lists as first assumed.
    assert_eq!(
        one.len() - none.len(),
        28,
        "one preallocation is not 28 bytes"
    );
    assert_eq!(two.len() - one.len(), 28, "the second is not another 28");

    // 10.0, little-endian, is in there.
    assert!(
        hex::encode(&one).contains(&hex::encode(1_000_000_000u64.to_le_bytes())),
        "the preallocated amount is not an 8-byte little-endian value"
    );
}

/// The three amount lists, in the order they appear.
///
/// Identified by giving each a distinct value in one definition, so no two can
/// be confused: 1.0 is the minimum, 2.0 the maximum, 3.0 the contribution.
#[test]
fn the_three_amount_lists_are_min_max_then_contributions() {
    let fixture = fixture();
    let payload = hex::encode(payload(
        fixture["vectors"]["fractional_all_three"]["definition_script"]
            .as_str()
            .expect("script"),
    ));
    let one = hex::encode(100_000_000u64.to_le_bytes());
    let two = hex::encode(200_000_000u64.to_le_bytes());
    let three = hex::encode(300_000_000u64.to_le_bytes());

    let min = payload.find(&one).expect("minpreconversion");
    let max = payload.find(&two).expect("maxpreconversion");
    let contributions = payload.find(&three).expect("initialcontributions");
    assert!(min < max, "the maximum came before the minimum");
    assert!(max < contributions, "contributions came before the maximum");
    // One count byte plus one eight-byte element between each.
    assert_eq!(max - min, 18, "lists are not nine bytes apart");
    assert_eq!(contributions - max, 18);
}

/// A definition uses three different amount encodings, chosen per field.
///
/// This is the trap that makes the object worth testing at all: VARINT for some
/// fields, four-byte little-endian for others, eight-byte for the rest. Picking
/// one for the whole object produces wrong money without failing to parse.
#[test]
fn amounts_use_three_different_encodings() {
    let fixture = fixture();
    let carveout = hex::encode(payload(
        fixture["vectors"]["fractional_carveout"]["definition_script"]
            .as_str()
            .expect("script"),
    ));
    let discount = hex::encode(payload(
        fixture["vectors"]["fractional_discount"]["definition_script"]
            .as_str()
            .expect("script"),
    ));
    let plain = payload(
        fixture["vectors"]["fractional_one_reserve"]["definition_script"]
            .as_str()
            .expect("script"),
    );

    // prelaunchcarveout 0.1 is four-byte little-endian.
    assert!(
        carveout.contains(&hex::encode(10_000_000u32.to_le_bytes())),
        "prelaunchcarveout is not LE32"
    );
    assert!(
        !carveout.contains(&hex::encode(10_000_000u64.to_le_bytes())),
        "prelaunchcarveout looks like LE64"
    );

    // prelaunchdiscount 0.05 is a VARINT: 81b09540, which lengthens the payload
    // by exactly three bytes over the zero case. A fixed-width field could not.
    assert!(
        discount.contains("81b09540"),
        "prelaunchdiscount is not the VARINT 81b09540"
    );
    assert_eq!(
        discount.len() / 2 - plain.len(),
        3,
        "prelaunchdiscount is not variable width"
    );

    // And weights, in the same object, are LE32 while initialsupply is LE64 —
    // covered by their own tests above.
}

/// The fixture must keep saying what is *not* known, or the next person will
/// assume the mapping is complete.
#[test]
fn the_fixture_still_records_what_is_unmapped() {
    let fixture = fixture();
    let note = fixture["_payload_layout_so_far"]["_incomplete"]
        .as_str()
        .expect("the incompleteness note was removed");
    assert!(
        note.contains("STILL NOT"),
        "the note stopped saying what is unmapped: {note}"
    );
    assert!(
        note.contains("NOT sufficient to encode"),
        "the note stopped saying the layout cannot be encoded from yet"
    );
    assert!(
        fixture["_structure"]["launch_transaction_outputs"]
            .as_array()
            .expect("outputs")
            .len()
            == 7,
        "a launch is seven outputs; the note about that changed"
    );
}
