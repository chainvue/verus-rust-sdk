//! Signature-level agreement with the TypeScript SDK.
//!
//! `@chainvue/verus-sdk` is daemon-proven and its signing is deterministic
//! (RFC6979, no randomness), so its output is a byte-exact oracle. This test
//! takes one of its golden signed transactions, recomputes the sighash with
//! `verus-wire`, signs it with `verus-keys`, and requires the resulting DER
//! signature to be **identical**.
//!
//! If it matches, then RFC6979 nonce derivation, low-S normalization, DER
//! encoding, key derivation from WIF and the sighash preimage all agree with an
//! implementation the Verus network already accepts — before any transaction
//! builder exists to get wrong.

use verus_keys::{Address, PrivateKey};
use verus_wire::consensus::{SIGHASH_ALL, VERUS_BRANCH_ID};
use verus_wire::{TxIn, TxOut, TxV4};

/// From `verus-sdk/test/fixtures/index.ts`.
const TEST_WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";
const TEST_ADDRESS: &str = "RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX";
const TEST_ADDRESS_B: &str = "RPsQDnaxXgrLjcVBh3SpvCpTabWxAdMdzu";

/// `sendCurrency (native transfer, native change)` from
/// `verus-sdk/test/__snapshots__/golden.test.ts.snap`.
///
/// Inputs: one 1.0 VRSC UTXO (`aa…aa:0`) paying `TEST_ADDRESS`; one 0.5 VRSC
/// output to `TEST_ADDRESS_B`; change back to `TEST_ADDRESS`; `expiryHeight` 0.
const GOLDEN_SIGNED_TX: &str = "0400008085202f8901aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000006b483045022100c16ce93bb2b1f240f16dea645ccafb48f535c1d64c97b01b2b48dcefa894863902202974624a51172e062d6cf7ce60ccabc6a20e977c57d1de34fb7cb0cafb3712020121026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57beaffffffff0280f0fa02000000001976a914a00a0a30a020a4f4708ee28aeb62f14eefc304d988ac70c9fa02000000001976a914aabfb6281561808fe200ab7e186f0e3e0e82b38188ac00000000000000000000000000000000000000";

/// The DER signature plus its `SIGHASH_ALL` byte, lifted from that scriptSig.
const GOLDEN_DER_WITH_HASHTYPE: &str = "3045022100c16ce93bb2b1f240f16dea645ccafb48f535c1d64c97b01b2b48dcefa894863902202974624a51172e062d6cf7ce60ccabc6a20e977c57d1de34fb7cb0cafb37120201";
const GOLDEN_PUBKEY: &str = "026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57bea";

const FUNDING_SATS: u64 = 100_000_000;
const SEND_SATS: u64 = 50_000_000;
/// 1.0 in, 0.5 out, 0.0001 fee — the TypeScript SDK's minimum.
const CHANGE_SATS: u64 = 49_990_000;

/// The transaction, unsigned, exactly as the TypeScript SDK assembles it.
fn unsigned_tx() -> (TxV4, Vec<u8>) {
    let funding_script = TEST_ADDRESS
        .parse::<Address>()
        .unwrap()
        .p2pkh_script_pubkey()
        .unwrap();
    let recipient_script = TEST_ADDRESS_B
        .parse::<Address>()
        .unwrap()
        .p2pkh_script_pubkey()
        .unwrap();

    let tx = TxV4 {
        inputs: vec![TxIn::unsigned([0xaa; 32], 0, 0xffff_ffff)],
        outputs: vec![
            TxOut {
                value: SEND_SATS,
                script_pubkey: recipient_script,
            },
            TxOut {
                value: CHANGE_SATS,
                script_pubkey: funding_script.clone(),
            },
        ],
        ..TxV4::default()
    };
    (tx, funding_script)
}

#[test]
fn reproduces_the_typescript_sdk_signature_byte_for_byte() {
    let (tx, funding_script) = unsigned_tx();
    let key = PrivateKey::from_wif(TEST_WIF).unwrap();

    let sighash = tx
        .transparent_sighash(
            VERUS_BRANCH_ID,
            0,
            &funding_script,
            FUNDING_SATS,
            SIGHASH_ALL,
        )
        .unwrap();

    let signature = key.sign_prehash_der(&sighash, 1).unwrap();
    assert_eq!(
        hex::encode(&signature),
        GOLDEN_DER_WITH_HASHTYPE,
        "signature differs from the TypeScript SDK's"
    );
}

#[test]
fn derives_the_same_public_key() {
    let key = PrivateKey::from_wif(TEST_WIF).unwrap();
    assert_eq!(hex::encode(key.public_key().to_bytes()), GOLDEN_PUBKEY);
    assert_eq!(key.address().to_string(), TEST_ADDRESS);
}

/// Assembling the scriptSig and serializing must reproduce the *whole* golden
/// transaction — not just the signature. This is the milestone-1 target reached
/// early, with the fee and change values supplied by hand; Phase 3 adds the coin
/// selection that computes them.
#[test]
fn reproduces_the_whole_golden_transaction() {
    let (mut tx, funding_script) = unsigned_tx();
    let key = PrivateKey::from_wif(TEST_WIF).unwrap();

    let sighash = tx
        .transparent_sighash(
            VERUS_BRANCH_ID,
            0,
            &funding_script,
            FUNDING_SATS,
            SIGHASH_ALL,
        )
        .unwrap();
    let signature = key.sign_prehash_der(&sighash, 1).unwrap();
    let pubkey = key.public_key().to_bytes();

    // scriptSig = PUSH(signature || hashtype) PUSH(pubkey)
    let mut script_sig = Vec::with_capacity(1 + signature.len() + 1 + pubkey.len());
    script_sig.push(u8::try_from(signature.len()).unwrap());
    script_sig.extend_from_slice(&signature);
    script_sig.push(u8::try_from(pubkey.len()).unwrap());
    script_sig.extend_from_slice(&pubkey);
    tx.inputs[0].script_sig = script_sig;

    assert_eq!(hex::encode(tx.serialize().unwrap()), GOLDEN_SIGNED_TX);
}

/// The value commitment is real: signing the same transaction while claiming a
/// different input amount must produce a different signature. Otherwise an
/// attacker could rewrite fees.
#[test]
fn a_different_input_value_produces_a_different_signature() {
    let (tx, funding_script) = unsigned_tx();
    let key = PrivateKey::from_wif(TEST_WIF).unwrap();

    let honest = tx
        .transparent_sighash(
            VERUS_BRANCH_ID,
            0,
            &funding_script,
            FUNDING_SATS,
            SIGHASH_ALL,
        )
        .unwrap();
    let lying = tx
        .transparent_sighash(
            VERUS_BRANCH_ID,
            0,
            &funding_script,
            FUNDING_SATS + 1,
            SIGHASH_ALL,
        )
        .unwrap();

    assert_ne!(
        key.sign_prehash_der(&honest, 1).unwrap(),
        key.sign_prehash_der(&lying, 1).unwrap()
    );
}
