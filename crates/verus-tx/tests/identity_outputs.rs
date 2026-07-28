//! Pay-to-identity outputs, checked against the chain's own bytes.
//!
//! The vectors in `fixtures/daemon/identity_outputs.json` are live VRSCTEST
//! UTXOs — scripts a Verus daemon produced when paying a VerusID. They pin the
//! encoding independently of any implementation, which matters here because the
//! destination format is easy to get subtly wrong: an identity carries a leading
//! type byte and a key hash does not, so a bare 20-byte push produces a script
//! that pays a transparent address nobody controls.

use serde_json::Value;
use verus_keys::Address;
use verus_tx::{decode_output_script, identity_payment_script, OutputKind};

fn vectors() -> Vec<Value> {
    let path = format!(
        "{}/../../fixtures/daemon/identity_outputs.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let parsed: Value = serde_json::from_str(&raw).expect("valid JSON");
    let vectors = parsed["vectors"].as_array().expect("vectors").clone();
    assert!(
        vectors.len() >= 3,
        "expected several identities; got {}",
        vectors.len()
    );
    vectors
}

/// The encoder must reproduce what the chain emitted, byte for byte.
#[test]
fn reproduces_every_on_chain_identity_payment() {
    for vector in vectors() {
        let name = vector["name"].as_str().expect("name");
        let address: Address = vector["identity_address"]
            .as_str()
            .expect("identity_address")
            .parse()
            .expect("i-address parses");
        let built = identity_payment_script(address.hash()).expect("build");
        assert_eq!(
            hex::encode(built),
            vector["script"].as_str().expect("script"),
            "{name}: our pay-to-identity script differs from the chain's"
        );
    }
}

/// …and the decoder must read it back to the same identity.
#[test]
fn decodes_every_on_chain_identity_payment() {
    for vector in vectors() {
        let name = vector["name"].as_str().expect("name");
        let script = hex::decode(vector["script"].as_str().expect("script")).expect("hex");
        let address: Address = vector["identity_address"]
            .as_str()
            .expect("identity_address")
            .parse()
            .expect("i-address parses");
        match decode_output_script(&script).expect("decode") {
            OutputKind::IdentityPayment { identity } => {
                assert_eq!(identity, address.hash(), "{name}: wrong identity");
            }
            other => panic!("{name}: expected an identity payment, got {other:?}"),
        }
    }
}

/// The mistake this encoding invites: dropping the destination's type byte.
///
/// A bare 20-byte push is a KEY hash, so the resulting script pays a transparent
/// address that merely shares the identity's hash — spendable by nobody. It must
/// not accidentally equal the real thing.
#[test]
fn an_untagged_destination_is_a_different_script() {
    let vector = vectors().into_iter().next().expect("a vector");
    let real = hex::decode(vector["script"].as_str().expect("script")).expect("hex");
    let address: Address = vector["identity_address"]
        .as_str()
        .expect("identity_address")
        .parse()
        .expect("parses");

    // The same script with the identity written as a plain key hash.
    let mut untagged = real.clone();
    let position = untagged
        .windows(21)
        .position(|w| w[0] == 0x04 && w[1..] == address.hash())
        .expect("tagged destination present");
    untagged.remove(position); // drop the 0x04 tag
    untagged[position - 1] = 20; // and fix the push length
    assert_ne!(untagged, real);

    // It must not decode as an identity payment either.
    assert!(!matches!(
        decode_output_script(&untagged),
        Ok(OutputKind::IdentityPayment { .. })
    ));
}

/// An identity payment carries NO eval code, so recognising it depends entirely
/// on decoding the destination kind. Classifying by eval code alone would call
/// this an ordinary output and lose the fact that only the identity can spend it.
#[test]
fn identity_payments_are_not_confused_with_ordinary_outputs() {
    let vector = vectors().into_iter().next().expect("a vector");
    let script = hex::decode(vector["script"].as_str().expect("script")).expect("hex");
    assert!(matches!(
        decode_output_script(&script),
        Ok(OutputKind::IdentityPayment { .. })
    ));
    // A P2PKH output of the same hash is a completely different thing.
    let address: Address = vector["identity_address"]
        .as_str()
        .expect("identity_address")
        .parse()
        .expect("parses");
    let mut p2pkh = vec![0x76, 0xa9, 0x14];
    p2pkh.extend_from_slice(&address.hash());
    p2pkh.extend_from_slice(&[0x88, 0xac]);
    assert!(matches!(
        decode_output_script(&p2pkh),
        Ok(OutputKind::PubKeyHash { .. })
    ));
}
