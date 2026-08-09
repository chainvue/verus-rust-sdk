//! Seed-phrase derivation, compatible with Verus Mobile and Verus Desktop.
//!
//! Verus wallets are **not** hierarchical-deterministic on the transparent side.
//! A recovery phrase maps to exactly one key: no account, no chain, no index, no
//! BIP-32 anywhere. The convention comes from Agama/Iguana and lives in
//! `agama-wallet-lib`'s `seedToWif`, shared by Verus Mobile and Verus Desktop:
//!
//! ```text
//! bytes = sha256(utf8(phrase))
//! bytes[0]  &= 248
//! bytes[31] &= 127
//! bytes[31] |= 64        // the "iguana" clamp
//! key = compressed secp256k1 key from bytes
//! ```
//!
//! Verus Mobile applies the clamp from every call site, in both of its
//! derivation versions, so it is unconditional here rather than an option: an
//! unclamped key is one no Verus wallet would ever show a user.
//!
//! # Security
//!
//! This is a single unsalted SHA-256 over the phrase text — no PBKDF2, no salt,
//! no stretching. All of the security is the entropy of the phrase itself, and a
//! guessable phrase is cheap to brute-force offline. That is the ecosystem's
//! format, not a choice this crate makes; it exists so keys users already hold
//! keep working. Do not invent a passphrase — import one a Verus wallet
//! generated, or generate a fresh key from the platform CSPRNG instead.
//!
//! The same phrase drives a *completely different* shielded key (BIP-39 →
//! ZIP-32); the two share nothing. That half starts at
//! [`crate::bip39::mnemonic_to_seed`].
//!
//! # There is no checksum on this path
//!
//! Any text is a valid phrase here, so a mistyped word derives a perfectly
//! good key for a wallet that has never held anything — and nothing below can
//! tell you that happened. [`crate::bip39::validate_mnemonic`] can, for the
//! phrases that are BIP-39 mnemonics; call it first when you are restoring
//! rather than importing. It is deliberately not called from here, because
//! free text is a legitimate Verus phrase and refusing it would strand funds.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::base58::decode_check;
use crate::error::KeyError;
use crate::key::PrivateKey;

/// Derive the private key a Verus Mobile / Verus Desktop seed phrase maps to.
///
/// The phrase is hashed verbatim — no trimming, no case folding, no Unicode
/// normalization, no BIP-39 validation — exactly as the wallets do it.
/// Whitespace is significant.
///
/// Two deliberate deviations from the wallets, both fail-closed:
/// an empty phrase and a WIF passed as a phrase are refused, because hashing
/// either would derive a valid-looking address the user does not control.
pub fn private_key_from_seed_phrase(phrase: &str) -> Result<PrivateKey, KeyError> {
    if phrase.trim().is_empty() {
        return Err(KeyError::EmptySeedPhrase);
    }
    if decode_check(phrase).is_ok() {
        return Err(KeyError::SeedPhraseIsWif);
    }

    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&Sha256::digest(phrase.as_bytes()));
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;

    // The clamp guarantees a usable scalar, deterministically: capping the top
    // byte at 0xF8 (`&= 248`) keeps every clamped buffer below the curve order
    // n (whose top byte is 0xFF), and flooring the low byte at 0x40 (`|= 64`)
    // keeps it non-zero. The result always lands in [0x40, 0xF8FF..FF7F] — a
    // bound that holds for every input, not just almost all of them. That
    // bound is real but incidental and far weaker than "below 2^253"; it is
    // not why the clamp is applied here (see the module docs above for that).
    // Because the range is guaranteed on this path, the `InvalidPrivateKey`
    // rejection in `PrivateKey::from_bytes` below is unreachable — unlike a
    // uniform random 32-byte draw, where it guards a real ~2^-127 case.
    PrivateKey::from_bytes(&bytes, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer vectors from the TypeScript SDK, where the derivation was
    /// confirmed against a live Verus Mobile wallet: a phrase generated in the
    /// app derives the address the app displays.
    const VECTORS: [(&str, &str); 3] = [
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "RFHG6jCuPmTZknnwPwjMWv67HRarPCtEFh",
        ),
        (
            "sample verus seed phrase for testing only do not use",
            "RQi75WyyN6naucDBwfKD7TfwpCUPLJSa6v",
        ),
        ("a", "R9ZMKPDhaiiqiGT7KKD4wXmR9a78ih3qn8"),
    ];

    #[test]
    fn matches_the_wallet_derived_addresses() {
        for (phrase, expected) in VECTORS {
            let key = private_key_from_seed_phrase(phrase).unwrap();
            assert_eq!(key.address().to_string(), expected, "phrase: {phrase}");
        }
    }

    #[test]
    fn applies_the_iguana_clamp() {
        for (phrase, _) in VECTORS {
            let key = private_key_from_seed_phrase(phrase).unwrap();
            let bytes = key.to_bytes();
            assert_eq!(bytes[0] & 0b0000_0111, 0);
            assert_eq!(bytes[31] & 0b1000_0000, 0);
            assert_eq!(bytes[31] & 0b0100_0000, 0b0100_0000);
        }
    }

    #[test]
    fn hashes_the_phrase_verbatim() {
        // Whitespace and case are significant; the wallets do not normalize.
        let base = private_key_from_seed_phrase("my seed phrase").unwrap();
        for variant in [" my seed phrase", "My seed phrase", "my  seed phrase"] {
            assert_ne!(
                private_key_from_seed_phrase(variant).unwrap().address(),
                base.address(),
                "variant {variant:?} collided"
            );
        }
    }

    #[test]
    fn refuses_a_wif_passed_as_a_phrase() {
        // Hashing a WIF would derive a different key and strand the funds.
        let wif = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";
        assert_eq!(
            private_key_from_seed_phrase(wif).unwrap_err(),
            KeyError::SeedPhraseIsWif
        );
    }

    #[test]
    fn refuses_an_empty_phrase() {
        for empty in ["", "   "] {
            assert_eq!(
                private_key_from_seed_phrase(empty).unwrap_err(),
                KeyError::EmptySeedPhrase
            );
        }
    }
}
