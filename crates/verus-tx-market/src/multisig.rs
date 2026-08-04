//! Transparent m-of-n multisig, as pay-to-script-hash.
//!
//! Distinct from the multisig this crate already had. A **VerusID** with
//! `minimumsignatures > 1` is multisig at the identity layer: the authority
//! lives in a chain object and can be rotated or recovered. This is multisig at
//! the *script* layer — an ordinary output locked to a redeem script, with no
//! identity behind it and no way to change the signers after the fact.
//!
//! ```text
//! redeem script   OP_m PUSH(pubkey)… OP_n OP_CHECKMULTISIG
//! scriptPubKey    OP_HASH160 PUSH(hash160(redeem)) OP_EQUAL
//! scriptSig       OP_0 PUSH(sig)… PUSH(redeem script)
//! ```
//!
//! # Two things that will bite
//!
//! **The pubkey order is part of the address.** Reordering the same keys gives a
//! different redeem script, a different hash, and a different address that the
//! other party's wallet will not recognise. [`redeem_script`] preserves the
//! order given and does not sort — sorting would silently produce an address the
//! caller did not agree to. (BIP-67 defines a *sorted* convention; Verus does
//! not apply it automatically, so if both sides want it they must sort before
//! calling.)
//!
//! **`OP_CHECKMULTISIG` pops one extra item**, a consensus bug old enough to be
//! permanent. The scriptSig therefore starts with `OP_0`, and signatures must
//! appear in the **same relative order as their pubkeys** in the redeem script —
//! the verifier walks both lists once and never backtracks. Signatures in the
//! wrong order fail with every key present and correct, which is a confusing way
//! to lose an afternoon. [`multisig_script_sig`] orders them for you.

use verus_keys::{Address, AddressKind, PublicKey};
use verus_tx_primitives::TxError;

/// `OP_0`, the extra item `OP_CHECKMULTISIG` consumes.
const OP_0: u8 = 0x00;
/// `OP_1` — small integers are `OP_1` through `OP_16`, encoded as `0x50 + n`.
const OP_1: u8 = 0x51;
const OP_HASH160: u8 = 0xa9;
const OP_EQUAL: u8 = 0x87;
const OP_CHECKMULTISIG: u8 = 0xae;

/// The most signers `OP_CHECKMULTISIG` accepts.
pub const MAX_MULTISIG_KEYS: usize = 16;

/// Build an `m`-of-`n` redeem script.
///
/// The order of `pubkeys` is preserved and is part of the resulting address —
/// see the module docs.
pub fn redeem_script(required: usize, pubkeys: &[PublicKey]) -> Result<Vec<u8>, TxError> {
    if pubkeys.is_empty() {
        return Err(TxError::InvalidMultisig(
            "a multisig needs at least one key".into(),
        ));
    }
    if pubkeys.len() > MAX_MULTISIG_KEYS {
        return Err(TxError::InvalidMultisig(format!(
            "{} keys is more than the {MAX_MULTISIG_KEYS} OP_CHECKMULTISIG accepts",
            pubkeys.len()
        )));
    }
    if required == 0 {
        return Err(TxError::InvalidMultisig(
            "a 0-of-n multisig would be spendable by anyone".into(),
        ));
    }
    if required > pubkeys.len() {
        return Err(TxError::InvalidMultisig(format!(
            "{required}-of-{} can never be satisfied",
            pubkeys.len()
        )));
    }

    let mut script = vec![small_int(required)?];
    for pubkey in pubkeys {
        let bytes = pubkey.to_bytes();
        // Push opcodes below 0x4c are the length itself; a SEC1 key is 33 or 65
        // bytes, so this is always the short form.
        script
            .push(u8::try_from(bytes.len()).map_err(|_| {
                TxError::InvalidMultisig("a public key is too long to push".into())
            })?);
        script.extend_from_slice(&bytes);
    }
    script.push(small_int(pubkeys.len())?);
    script.push(OP_CHECKMULTISIG);
    Ok(script)
}

/// The P2SH address a redeem script locks to.
pub fn address(redeem_script: &[u8]) -> Address {
    Address::new(AddressKind::ScriptHash, script_hash(redeem_script))
}

/// `HASH160` of a redeem script — the 20 bytes the output commits to.
///
/// `hash160` is RIPEMD160(SHA256(x)) and applies both itself; hashing the script
/// beforehand would produce an address nothing pays to.
pub fn script_hash(redeem_script: &[u8]) -> [u8; 20] {
    verus_keys::hash160(redeem_script)
}

/// The `scriptPubKey` that pays a redeem script.
pub fn p2sh_script_pubkey(redeem_script: &[u8]) -> Vec<u8> {
    let mut script = vec![OP_HASH160, 20];
    script.extend_from_slice(&script_hash(redeem_script));
    script.push(OP_EQUAL);
    script
}

/// A signature gathered for a multisig input, with the key that made it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultisigSignature {
    /// Whose signature this is. Used to place it in pubkey order.
    pub pubkey: PublicKey,
    /// DER signature with the hash type byte already appended.
    pub signature: Vec<u8>,
}

/// Assemble the `scriptSig` that spends a P2SH multisig output.
///
/// Signatures are reordered to match `pubkeys`, because `OP_CHECKMULTISIG`
/// walks both lists once without backtracking — out-of-order signatures fail
/// even when every one is valid.
///
/// # Errors
///
/// Refuses when a signature's key is not in the redeem script, when two
/// signatures come from the same key, or when there are not exactly `required`
/// of them. Too many is as broken as too few: `OP_CHECKMULTISIG` fails if the
/// count does not match.
pub fn multisig_script_sig(
    required: usize,
    pubkeys: &[PublicKey],
    signatures: &[MultisigSignature],
    redeem_script: &[u8],
) -> Result<Vec<u8>, TxError> {
    let mut ordered: Vec<&MultisigSignature> = Vec::new();
    for pubkey in pubkeys {
        let mut matching = signatures.iter().filter(|s| s.pubkey == *pubkey);
        if let Some(found) = matching.next() {
            if matching.next().is_some() {
                return Err(TxError::InvalidMultisig(
                    "the same key signed twice; it still counts once".into(),
                ));
            }
            ordered.push(found);
        }
    }
    if ordered.len() != signatures.len() {
        return Err(TxError::InvalidMultisig(
            "a signature came from a key that is not in the redeem script".into(),
        ));
    }
    if ordered.len() != required {
        return Err(TxError::InvalidMultisig(format!(
            "{}-of-{} needs exactly {required} signatures, got {}",
            required,
            pubkeys.len(),
            ordered.len()
        )));
    }

    // The extra item OP_CHECKMULTISIG pops and discards.
    let mut script = vec![OP_0];
    for signature in ordered {
        push(&mut script, &signature.signature)?;
    }
    push(&mut script, redeem_script)?;
    Ok(script)
}

/// Push bytes with the smallest encoding, as a scriptSig requires.
fn push(script: &mut Vec<u8>, data: &[u8]) -> Result<(), TxError> {
    match data.len() {
        0 => script.push(OP_0),
        length if length < 0x4c => {
            script.push(u8::try_from(length).expect("the guard bounds this below 0x4c"));
        }
        length if length <= 0xff => {
            script.push(0x4c);
            script.push(u8::try_from(length).expect("the guard bounds this to 0xff"));
        }
        length if length <= 0xffff => {
            script.push(0x4d);
            script.extend_from_slice(
                &u16::try_from(length)
                    .expect("the guard bounds this to 0xffff")
                    .to_le_bytes(),
            );
        }
        length => {
            return Err(TxError::InvalidMultisig(format!(
                "{length} bytes is too large to push into a scriptSig"
            )))
        }
    }
    script.extend_from_slice(data);
    Ok(())
}

/// `OP_1`..`OP_16` for 1..16.
fn small_int(n: usize) -> Result<u8, TxError> {
    if n == 0 || n > MAX_MULTISIG_KEYS {
        return Err(TxError::InvalidMultisig(format!(
            "{n} is not encodable as a small integer opcode"
        )));
    }
    Ok(OP_1 + u8::try_from(n - 1).expect("refused above unless 1 <= n <= MAX_MULTISIG_KEYS"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two public keys the daemon's `createmultisig` was given.
    const KEY_A: &str = "03f5f2dfc9426c95d1c477b324be4ea45f81a370a20be63ca7d8148aadb2db3f64";
    const KEY_B: &str = "026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57bea";

    fn key(hex_text: &str) -> PublicKey {
        PublicKey::from_bytes(&hex::decode(hex_text).expect("hex")).expect("key")
    }

    /// `createmultisig 2 [A, B]` on VRSCTEST returned exactly these bytes and
    /// this address. Reproducing both is what says the encoding is right.
    #[test]
    fn a_two_of_two_matches_the_daemon() {
        let script = redeem_script(2, &[key(KEY_A), key(KEY_B)]).unwrap();
        assert_eq!(
            hex::encode(&script),
            "522103f5f2dfc9426c95d1c477b324be4ea45f81a370a20be63ca7d8148aadb2db3f64\
             21026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57bea52ae"
                .replace(['\n', ' '], "")
        );
        assert_eq!(
            address(&script).to_string(),
            "bH3d6M9q6soGwcgzFxpNagYFvwLqaBnFkk"
        );
    }

    /// `createmultisig 1 [A, B]` — only the leading opcode differs, which is
    /// what pins that `m` and `n` are not transposed.
    #[test]
    fn a_one_of_two_matches_the_daemon() {
        let script = redeem_script(1, &[key(KEY_A), key(KEY_B)]).unwrap();
        assert_eq!(
            hex::encode(&script),
            "512103f5f2dfc9426c95d1c477b324be4ea45f81a370a20be63ca7d8148aadb2db3f64\
             21026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57bea52ae"
                .replace(['\n', ' '], "")
        );
        assert_eq!(
            address(&script).to_string(),
            "bQWDFzNpHMA9ogYjuMVEnTJGxmHpP3RfL5"
        );
    }

    /// The order of the keys is part of the address. A wallet that sorts them
    /// "helpfully" hands its counterparty a different address.
    #[test]
    fn reordering_the_keys_changes_the_address() {
        let forwards = redeem_script(2, &[key(KEY_A), key(KEY_B)]).unwrap();
        let backwards = redeem_script(2, &[key(KEY_B), key(KEY_A)]).unwrap();
        assert_ne!(forwards, backwards);
        assert_ne!(
            address(&forwards).to_string(),
            address(&backwards).to_string()
        );
    }

    /// The output script commits to the hash, not the script.
    #[test]
    fn the_output_script_is_hash160_of_the_redeem_script() {
        let script = redeem_script(2, &[key(KEY_A), key(KEY_B)]).unwrap();
        let spk = p2sh_script_pubkey(&script);
        assert_eq!(spk[0], OP_HASH160);
        assert_eq!(spk[1], 20);
        assert_eq!(spk[22], OP_EQUAL);
        assert_eq!(spk.len(), 23);
        assert_eq!(&spk[2..22], &script_hash(&script));
        assert_eq!(script_hash(&script), address(&script).hash());
    }

    fn signature(pubkey: PublicKey, byte: u8) -> MultisigSignature {
        MultisigSignature {
            pubkey,
            signature: vec![byte; 71],
        }
    }

    /// The scriptSig leads with OP_0 — the item OP_CHECKMULTISIG pops and
    /// throws away. Without it every multisig spend fails.
    #[test]
    fn the_script_sig_leads_with_the_dummy_op_0() {
        let keys = [key(KEY_A), key(KEY_B)];
        let script = redeem_script(2, &keys).unwrap();
        let sigs = [signature(keys[0], 0xaa), signature(keys[1], 0xbb)];
        let script_sig = multisig_script_sig(2, &keys, &sigs, &script).unwrap();
        assert_eq!(script_sig[0], OP_0);
    }

    /// Signatures are placed in pubkey order regardless of the order they were
    /// gathered in. Out of order they fail with every key valid, which is the
    /// worst kind of bug to debug.
    #[test]
    fn signatures_are_reordered_to_match_the_redeem_script() {
        let keys = [key(KEY_A), key(KEY_B)];
        let script = redeem_script(2, &keys).unwrap();

        let in_order = [signature(keys[0], 0xaa), signature(keys[1], 0xbb)];
        let jumbled = [signature(keys[1], 0xbb), signature(keys[0], 0xaa)];

        assert_eq!(
            multisig_script_sig(2, &keys, &in_order, &script).unwrap(),
            multisig_script_sig(2, &keys, &jumbled, &script).unwrap(),
            "the gathering order leaked into the scriptSig"
        );
    }

    /// Exactly `m` signatures. Too many fails on chain just as surely as too
    /// few, so it is caught here.
    #[test]
    fn the_signature_count_must_be_exact() {
        let keys = [key(KEY_A), key(KEY_B)];
        let script = redeem_script(1, &keys).unwrap();
        let both = [signature(keys[0], 0xaa), signature(keys[1], 0xbb)];
        assert!(multisig_script_sig(1, &keys, &both, &script).is_err());
        assert!(multisig_script_sig(1, &keys, &both[..1], &script).is_ok());
        assert!(multisig_script_sig(2, &keys, &both[..1], &script).is_err());
    }

    /// A signature from a key that is not in the script would be silently
    /// dropped by the reordering, leaving a scriptSig short of signatures.
    #[test]
    fn a_signature_from_an_unknown_key_is_refused() {
        let keys = [key(KEY_A)];
        let script = redeem_script(1, &keys).unwrap();
        let stranger = [signature(key(KEY_B), 0xcc)];
        assert!(multisig_script_sig(1, &keys, &stranger, &script).is_err());
    }

    /// One key signing twice must not satisfy a 2-of-2.
    #[test]
    fn one_key_cannot_sign_twice() {
        let keys = [key(KEY_A), key(KEY_B)];
        let script = redeem_script(2, &keys).unwrap();
        let doubled = [signature(keys[0], 0xaa), signature(keys[0], 0xdd)];
        assert!(multisig_script_sig(2, &keys, &doubled, &script).is_err());
    }

    /// Thresholds that can never be satisfied, or that anyone satisfies.
    #[test]
    fn nonsensical_thresholds_are_refused() {
        let keys = [key(KEY_A), key(KEY_B)];
        assert!(redeem_script(0, &keys).is_err());
        assert!(redeem_script(3, &keys).is_err());
        assert!(redeem_script(1, &[]).is_err());
        assert!(redeem_script(1, &vec![key(KEY_A); 17]).is_err());
        assert!(redeem_script(16, &vec![key(KEY_A); 16]).is_ok());
    }
}
