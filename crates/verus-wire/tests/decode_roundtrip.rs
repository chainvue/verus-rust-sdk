//! Every transaction this workspace has ever produced must survive a decode.
//!
//! The decoder's job is to be the exact inverse of the serializer. The strongest
//! available evidence is the corpus already committed here: ten golden VerusID
//! transactions and the TypeScript differential vectors, all of which a daemon
//! has accepted or agreed with. If any one of them fails to round-trip
//! byte-for-byte, the decoder is wrong about something real rather than about a
//! case invented for a test.

use verus_wire::TxV4;

fn hex_bytes(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

/// Pull every transaction hex out of the committed fixtures and goldens.
fn corpus() -> Vec<(String, String)> {
    let mut found = Vec::new();

    let vectors = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/transparent/vectors.json"
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(vectors).expect("vectors")).expect("json");
    for vector in parsed["vectors"].as_array().expect("vectors") {
        found.push((
            format!("vector:{}", vector["name"].as_str().unwrap_or("?")),
            vector["expected_signed_hex"]
                .as_str()
                .expect("hex")
                .to_string(),
        ));
    }

    // The golden identity transactions live as string constants in the test
    // file; scraping them keeps this in step without duplicating 2 kB literals.
    let goldens = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../verus-tx/tests/identity_lifecycle.rs"
    );
    let source = std::fs::read_to_string(goldens).expect("identity_lifecycle.rs");
    for line in source.lines() {
        let Some(rest) = line.split_once("const GOLDEN_") else {
            continue;
        };
        let name = rest.1.split(':').next().unwrap_or("?").trim().to_string();
        if let Some(start) = line.find("\"0400") {
            let hex = &line[start + 1..];
            if let Some(end) = hex.find('"') {
                found.push((format!("golden:{name}"), hex[..end].to_string()));
            }
        }
    }

    assert!(
        found.len() >= 16,
        "expected the whole corpus, found {}",
        found.len()
    );
    found
}

/// The headline property: decode then re-serialize must give back the exact
/// bytes. Anything dropped, reordered or normalised shows up here.
#[test]
fn every_committed_transaction_round_trips_byte_for_byte() {
    for (name, hex) in corpus() {
        let bytes = hex_bytes(&hex);
        let decoded = TxV4::deserialize(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        let reserialized = decoded
            .serialize()
            .unwrap_or_else(|e| panic!("{name}: re-serialize: {e}"));
        assert_eq!(reserialized, bytes, "{name}: round trip changed the bytes");
    }
}

/// And the transaction id must survive, which is the property anything
/// downstream actually depends on.
#[test]
fn the_transaction_id_survives_a_round_trip() {
    for (name, hex) in corpus() {
        let bytes = hex_bytes(&hex);
        let decoded = TxV4::deserialize(&bytes).expect(&name);
        let before = verus_wire::hash::sha256d(&bytes);
        let after = decoded.txid().unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(after, before, "{name}: txid changed");
    }
}

/// Truncating a valid transaction anywhere must fail, and must never panic.
///
/// This is the property that matters for taking an offer: the bytes come from a
/// counterparty, and a decoder that panics is a wallet that crashes on a
/// malformed message someone else chose.
#[test]
fn every_truncation_is_refused_without_panicking() {
    for (name, hex) in corpus() {
        let bytes = hex_bytes(&hex);
        for cut in 0..bytes.len() {
            assert!(
                TxV4::deserialize(&bytes[..cut]).is_err(),
                "{name}: accepted a transaction truncated to {cut} bytes"
            );
        }
    }
}

/// Trailing bytes are refused. Accepting them would let two different byte
/// strings decode to the same transaction.
#[test]
fn trailing_bytes_are_refused() {
    for (name, hex) in corpus().into_iter().take(3) {
        let mut bytes = hex_bytes(&hex);
        bytes.push(0);
        assert!(
            TxV4::deserialize(&bytes).is_err(),
            "{name}: accepted a trailing byte"
        );
    }
}

/// Flipping any single byte either fails to decode or changes the transaction.
/// What must never happen is decoding to something that re-serializes as the
/// *original* bytes — that would mean the decoder ignores part of its input.
#[test]
fn no_byte_is_ignored() {
    let (name, hex) = corpus().into_iter().next().expect("a transaction");
    let bytes = hex_bytes(&hex);
    for index in 0..bytes.len() {
        let mut mutated = bytes.clone();
        mutated[index] ^= 0xff;
        if let Ok(decoded) = TxV4::deserialize(&mutated) {
            let out = decoded.serialize().expect("serialize");
            assert_ne!(
                out, bytes,
                "{name}: byte {index} was ignored by the decoder"
            );
        }
    }
}

/// Arbitrary rubbish must be refused rather than panic.
#[test]
fn hostile_input_is_refused_without_panicking() {
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        vec![0xff; 8],
        // A valid header claiming an enormous number of inputs.
        {
            let mut v = hex_bytes("0400008085202f89");
            v.push(0xff);
            v.extend_from_slice(&u64::MAX.to_le_bytes());
            v
        },
        // A valid header with a script length far beyond the buffer.
        {
            let mut v = hex_bytes("0400008085202f8901");
            v.extend_from_slice(&[0u8; 32]);
            v.extend_from_slice(&0u32.to_le_bytes());
            v.push(0xfe);
            v.extend_from_slice(&u32::MAX.to_le_bytes());
            v
        },
        // Wrong version group.
        hex_bytes("04000080ffffffff00000000000000000000000000"),
        // A v3 header.
        hex_bytes("03000080703a770000000000"),
    ];
    for (index, case) in cases.iter().enumerate() {
        assert!(
            TxV4::deserialize(case).is_err(),
            "case {index} was accepted: {case:02x?}"
        );
    }
}

/// A non-canonical compact size re-serializes to different bytes, so accepting
/// it would break the round-trip guarantee the rest of this file rests on.
#[test]
fn non_canonical_lengths_are_refused() {
    // One input, but the count written in the three-byte form.
    let mut bytes = hex_bytes("0400008085202f89");
    bytes.push(0xfd);
    bytes.extend_from_slice(&1u16.to_le_bytes());
    assert!(TxV4::deserialize(&bytes).is_err());
}
