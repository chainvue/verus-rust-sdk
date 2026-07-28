//! Decoding VerusIDs, checked field by field against a daemon's `getidentity`.
//!
//! Each vector in `fixtures/daemon/identities.json` pairs the raw
//! `EVAL_IDENTITY_PRIMARY` output taken from a live VRSCTEST UTXO with what the
//! daemon reports for that same identity. The daemon is the oracle: agreeing
//! with it on the authority fields is the claim, since those decide who can
//! sign for, revoke and recover the identity.
//!
//! One subtlety in how those pairs were built, which cost a wrong test first
//! time: an identity output indexed under an address does not necessarily
//! DESCRIBE that identity. A parent's address also indexes its children's
//! outputs, so the fixtures resolve each output to the identity named by its own
//! destination before asking the daemon about it.

use serde_json::Value;
use verus_keys::{Address, AddressKind};
use verus_tx::{decode_output_script, Destination, OutputKind};

fn vectors() -> Vec<Value> {
    let path = format!(
        "{}/../../fixtures/daemon/identities.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let parsed: Value = serde_json::from_str(&raw).expect("valid JSON");
    let vectors = parsed["vectors"].as_array().expect("vectors").clone();
    assert!(
        vectors.len() >= 16,
        "expected a broad sample of identities, got {}",
        vectors.len()
    );
    vectors
}

fn hash_of(address: &str) -> [u8; 20] {
    address
        .parse::<Address>()
        .unwrap_or_else(|e| panic!("{address}: {e}"))
        .hash()
}

#[test]
fn every_field_agrees_with_the_daemon() {
    for vector in vectors() {
        let label = vector["name"].as_str().expect("name");
        let script = hex::decode(vector["script"].as_str().expect("script")).expect("hex");
        let oracle = &vector["getidentity"];

        let identity = match decode_output_script(&script).expect("decode") {
            OutputKind::IdentityPrimary { identity } => identity,
            other => panic!("{label}: expected an identity output, got {other:?}"),
        };

        assert_eq!(
            identity.name,
            oracle["name"].as_str().expect("name"),
            "{label}: name"
        );
        assert_eq!(
            u64::from(identity.version),
            oracle["version"].as_u64().expect("version"),
            "{label}: version"
        );
        assert_eq!(
            u64::from(identity.flags),
            oracle["flags"].as_u64().expect("flags"),
            "{label}: flags"
        );
        assert_eq!(
            u64::from(identity.min_sigs),
            oracle["minimumsignatures"].as_u64().expect("minsigs"),
            "{label}: minimumsignatures"
        );
        assert_eq!(
            identity.parent,
            hash_of(oracle["parent"].as_str().expect("parent")),
            "{label}: parent"
        );
        assert_eq!(
            identity.revocation_authority,
            hash_of(oracle["revocationauthority"].as_str().expect("revocation")),
            "{label}: revocationauthority"
        );
        assert_eq!(
            identity.recovery_authority,
            hash_of(oracle["recoveryauthority"].as_str().expect("recovery")),
            "{label}: recoveryauthority"
        );
        assert_eq!(
            identity.system_id,
            hash_of(oracle["systemid"].as_str().expect("systemid")),
            "{label}: systemid"
        );

        // The authority itself: which keys may sign, in order.
        let expected: Vec<[u8; 20]> = oracle["primaryaddresses"]
            .as_array()
            .expect("primaryaddresses")
            .iter()
            .map(|a| hash_of(a.as_str().expect("address")))
            .collect();
        let decoded: Vec<[u8; 20]> = identity
            .primary_addresses
            .iter()
            .map(|d| match d {
                Destination::PubKeyHash(hash) => *hash,
                other => panic!("{label}: unexpected primary address kind {other:?}"),
            })
            .collect();
        assert_eq!(decoded, expected, "{label}: primaryaddresses");

        eprintln!(
            "{label}: version {} flags {} {}-of-{} — agrees with the daemon",
            identity.version,
            identity.flags,
            identity.min_sigs,
            identity.primary_addresses.len()
        );
    }
}

/// The identity's own address is the hash of its output's destination, and must
/// match what the daemon calls `identityaddress`.
#[test]
fn the_output_pays_the_identity_it_describes() {
    for vector in vectors() {
        let label = vector["name"].as_str().expect("name");
        let expected = vector["identity_address"].as_str().expect("address");
        let address: Address = expected.parse().expect("i-address");
        assert_eq!(address.kind(), AddressKind::Identity, "{label}");
        assert_eq!(
            address.hash(),
            hash_of(
                vector["getidentity"]["identityaddress"]
                    .as_str()
                    .expect("identityaddress")
            ),
            "{label}: identity address"
        );
    }
}

/// Truncation must be an error, never a short read that yields a plausible
/// identity with the wrong authority — which is the dangerous failure here,
/// since `primary_addresses` and `min_sigs` decide who can sign.
#[test]
fn a_truncated_identity_is_refused() {
    let vector = vectors().into_iter().next().expect("a vector");
    let script = hex::decode(vector["script"].as_str().expect("script")).expect("hex");
    let mut refused = 0;
    for cut in 1..script.len() {
        if decode_output_script(&script[..cut]).is_err() {
            refused += 1;
        }
    }
    assert_eq!(
        refused,
        script.len() - 1,
        "every truncation of a real identity output must be refused"
    );
}

/// Flipping the declared version must not silently reinterpret the bytes.
#[test]
fn an_unknown_identity_version_is_refused() {
    let vector = vectors().into_iter().next().expect("a vector");
    let script = hex::decode(vector["script"].as_str().expect("script")).expect("hex");
    let identity = match decode_output_script(&script).expect("decode") {
        OutputKind::IdentityPrimary { identity } => identity,
        other => panic!("expected an identity, got {other:?}"),
    };
    // Find the serialized version word and raise it past what we decode.
    let version = identity.version.to_le_bytes();
    let position = script
        .windows(4)
        .position(|w| w == version)
        .expect("version word present");
    let mut broken = script.clone();
    broken[position] = 99;
    assert!(decode_output_script(&broken).is_err());
}

/// The round trip that an identity update depends on.
///
/// An update restates the whole identity, so it is built by decoding the current
/// one, changing a field, and re-encoding. If encode∘decode is not the identity
/// function, an update silently rewrites parts of the object nobody touched —
/// including who may sign for it. Re-encoding the entire on-chain SCRIPT, not
/// just the payload, also covers the master condition and the revoke/recover
/// conditions that make revocation possible.
#[test]
fn every_on_chain_identity_output_re_encodes_byte_for_byte() {
    for vector in vectors() {
        let label = vector["name"].as_str().expect("name");
        let original = vector["script"].as_str().expect("script");
        let script = hex::decode(original).expect("hex");

        let identity = match decode_output_script(&script).expect("decode") {
            OutputKind::IdentityPrimary { identity } => identity,
            other => panic!("{label}: expected an identity output, got {other:?}"),
        };

        let rebuilt = verus_tx::identity_primary_script(
            hash_of(vector["identity_address"].as_str().expect("address")),
            identity.to_bytes().expect("encode"),
            identity.revocation_authority,
            identity.recovery_authority,
        )
        .expect("build");

        assert_eq!(
            hex::encode(rebuilt),
            original,
            "{label}: re-encoded output differs from the chain's"
        );
    }
}

/// Encoding must be sensitive to the fields that carry authority — a serializer
/// that quietly dropped `min_sigs` or reordered primary addresses would still
/// pass a round trip on identities that happen to be 1-of-1.
#[test]
fn changing_the_authority_changes_the_bytes() {
    let vector = vectors().into_iter().next().expect("a vector");
    let script = hex::decode(vector["script"].as_str().expect("script")).expect("hex");
    let identity = match decode_output_script(&script).expect("decode") {
        OutputKind::IdentityPrimary { identity } => identity,
        other => panic!("expected an identity, got {other:?}"),
    };
    let baseline = identity.to_bytes().expect("encode");

    let mut more_signatures = (*identity).clone();
    more_signatures.min_sigs += 1;
    assert_ne!(more_signatures.to_bytes().expect("encode"), baseline);

    let mut other_revocation = (*identity).clone();
    other_revocation.revocation_authority = [0x42; 20];
    assert_ne!(other_revocation.to_bytes().expect("encode"), baseline);

    let mut extra_signer = (*identity).clone();
    extra_signer
        .primary_addresses
        .push(verus_tx::Destination::PubKeyHash([0x7; 20]));
    assert_ne!(extra_signer.to_bytes().expect("encode"), baseline);
}
