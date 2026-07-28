//! Byte-level agreement with a real Verus daemon.
//!
//! These are the tests that make this crate trustworthy. Each fixture is a
//! transaction the network actually accepted, so reproducing it byte for byte
//! proves the serializer against consensus rather than against our own opinion
//! of consensus.

mod common;

use common::{decode, load_fixture};
use verus_wire::consensus::{SIGHASH_ALL, VERUS_BRANCH_ID};
use verus_wire::hash::txid_display;

const FLOWS: [&str; 3] = ["t2z", "z2z", "z2t"];

#[test]
fn serializes_every_daemon_transaction_byte_for_byte() {
    for flow in FLOWS {
        let (json, expected_hex) = load_fixture(flow);
        let decoded = decode(&json);
        let serialized = decoded.tx.serialize().expect("serialize");
        assert_eq!(
            hex::encode(&serialized),
            expected_hex,
            "{flow}: serialized bytes differ from the daemon's"
        );
    }
}

#[test]
fn reproduces_every_daemon_txid() {
    for flow in FLOWS {
        let (json, _) = load_fixture(flow);
        let decoded = decode(&json);
        assert_eq!(
            txid_display(&decoded.tx.txid().expect("txid")),
            json["txid"].as_str().expect("fixture txid"),
            "{flow}: txid differs from the daemon's"
        );
    }
}

/// The shielded sighash, pinned against **externally confirmed** constants.
///
/// These are not self-generated: they are the values `@chainvue/verus-sapling`
/// confirmed cryptographically, by checking that each fixture's Sapling binding
/// signature — produced by the daemon — verifies under them. Reproducing them
/// here proves this port is byte-identical to the implementation the network
/// already accepted, which no amount of self-consistent testing could show.
#[test]
fn shielded_sighashes_match_the_cryptographically_confirmed_values() {
    let expected = [
        (
            "t2z",
            "080034d33ac637cf354a218818f799c74ab8c3900a39f48b5d4bfbdb7cde7f3c",
        ),
        (
            "z2z",
            "52843b719955d380c8d08e56a59526d533a14397e79b615f829a374aafd472d0",
        ),
        (
            "z2t",
            "82dabe7bf06f7d064ccb8791b14376018ae87a7a8f7eaa90bd65fcb49c864cc7",
        ),
    ];
    for (flow, want) in expected {
        let (json, _) = load_fixture(flow);
        let sighash = decode(&json).tx.shielded_sighash(VERUS_BRANCH_ID);
        assert_eq!(
            hex::encode(sighash),
            want,
            "{flow}: shielded sighash drifted"
        );
    }
}

/// The shielded sighash must NOT include a transparent-input section — that is
/// the one structural difference between the two preimages. `t2z` has a
/// transparent input, so if the sections were ever merged, its value would
/// change and the constant above would break; this states the invariant
/// directly rather than leaving it implicit.
#[test]
fn shielded_sighash_ignores_scriptsigs() {
    let (json, _) = load_fixture("t2z");
    let decoded = decode(&json);
    let baseline = decoded.tx.shielded_sighash(VERUS_BRANCH_ID);

    let mut mutated = decoded.tx.clone();
    mutated.inputs[0].script_sig = vec![0xff; 42];
    assert_eq!(
        mutated.shielded_sighash(VERUS_BRANCH_ID),
        baseline,
        "the shielded sighash must not commit to scriptSigs"
    );
}

/// **The decisive test.**
///
/// `t2z` input 0 is a P2PKH spend the *daemon itself* signed and the network
/// accepted. We recompute the transparent sighash from our own serializer and
/// verify the daemon's DER signature against it, using the pubkey from its
/// scriptSig. If our preimage were wrong in any byte — field order, the value
/// commitment, the branch id, the scriptCode encoding — the signature would not
/// verify.
///
/// No network, no proving parameters, no private key.
#[test]
fn transparent_sighash_verifies_the_daemons_own_signature() {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::ecdsa::{DerSignature, VerifyingKey};
    use ripemd::Ripemd160;
    use sha2::{Digest, Sha256};

    let (json, _) = load_fixture("t2z");
    let decoded = decode(&json);

    // scriptSig = PUSH(DER signature || hashtype) PUSH(compressed pubkey)
    let script_sig = &decoded.tx.inputs[0].script_sig;
    let sig_len = usize::from(script_sig[0]);
    let der = &script_sig[1..sig_len]; // trailing byte is the hashtype
    let hash_type = u32::from(script_sig[sig_len]);
    let pubkey_len = usize::from(script_sig[1 + sig_len]);
    let pubkey = &script_sig[2 + sig_len..2 + sig_len + pubkey_len];

    assert_eq!(
        hash_type, SIGHASH_ALL,
        "fixture input signed with SIGHASH_ALL"
    );
    assert_eq!(pubkey_len, 33, "compressed pubkey");

    // The scriptCode for P2PKH is the prevout's script, which we rebuild from
    // the pubkey: OP_DUP OP_HASH160 <20-byte hash160> OP_EQUALVERIFY OP_CHECKSIG
    let hash160 = Ripemd160::digest(Sha256::digest(pubkey));
    let mut script_code = vec![0x76, 0xa9, 0x14];
    script_code.extend_from_slice(&hash160);
    script_code.extend_from_slice(&[0x88, 0xac]);

    // The value being spent, from the fixture's own record of the prevout.
    let value: u64 = json["vin"][0]["valueSat"]
        .as_u64()
        .expect("fixture records the spent value");

    let sighash = decoded
        .tx
        .transparent_sighash(VERUS_BRANCH_ID, 0, &script_code, value, SIGHASH_ALL)
        .expect("sighash");

    let verifying_key = VerifyingKey::from_sec1_bytes(pubkey).expect("valid pubkey");
    let signature = DerSignature::try_from(der).expect("valid DER signature");
    verifying_key
        .verify_prehash(&sighash, &signature)
        .expect("the daemon's signature must verify against our sighash");
}

/// A sighash that verified for the wrong reason would be worse than useless, so
/// prove the check above can fail: the same signature must NOT verify against a
/// sighash computed with a different branch id.
#[test]
fn the_daemon_signature_check_is_not_vacuous() {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::ecdsa::{DerSignature, VerifyingKey};
    use ripemd::Ripemd160;
    use sha2::{Digest, Sha256};

    let (json, _) = load_fixture("t2z");
    let decoded = decode(&json);
    let script_sig = &decoded.tx.inputs[0].script_sig;
    let sig_len = usize::from(script_sig[0]);
    let der = &script_sig[1..sig_len];
    let pubkey = &script_sig[2 + sig_len..];

    let hash160 = Ripemd160::digest(Sha256::digest(pubkey));
    let mut script_code = vec![0x76, 0xa9, 0x14];
    script_code.extend_from_slice(&hash160);
    script_code.extend_from_slice(&[0x88, 0xac]);
    let value = json["vin"][0]["valueSat"].as_u64().expect("valueSat");

    let wrong = decoded
        .tx
        .transparent_sighash(0x76b8_07bb, 0, &script_code, value, SIGHASH_ALL)
        .expect("sighash");

    let verifying_key = VerifyingKey::from_sec1_bytes(pubkey).expect("valid pubkey");
    let signature = DerSignature::try_from(der).expect("valid DER");
    assert!(
        verifying_key.verify_prehash(&wrong, &signature).is_err(),
        "signature verified under the wrong branch id — the check proves nothing"
    );
}
