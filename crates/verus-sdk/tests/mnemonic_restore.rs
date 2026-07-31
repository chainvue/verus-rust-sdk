//! One recovery phrase, both halves of the wallet.
//!
//! Until now the shielded half was unreachable from Rust: `derive_account`
//! takes a 64-byte BIP-39 seed, and nothing in the workspace could produce one
//! from a phrase — `keygen_shielded`'s header says so outright, "turning a
//! phrase into a seed is the wallet's job". This is the composition that closes
//! it, exercised the way a restore actually runs.
//!
//! Verus derives the two keys by *unrelated* schedules from the same words —
//! `sha256(phrase)` plus the Iguana clamp for the `R…` address, BIP-39 →
//! ZIP-32 for the `zs…` one. Getting that wrong in either direction is the
//! failure this file is here to catch.

#![cfg(feature = "shielded")]

use verus_sdk::verus_keys::bip39::{mnemonic_to_seed, validate_mnemonic, MnemonicError};
use verus_sdk::verus_keys::private_key_from_seed_phrase;
use verus_sdk::verus_sapling::derive::{derive_account, COIN_TYPE_MAINNET};
use verus_sdk::verus_sapling::zaddr;

/// The BIP-39 vector phrase. Public, worthless, and the one every wallet
/// implementation tests with.
const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// A restore reaches both addresses from the one phrase.
///
/// The z-address is **not** a value this code produced and then pinned. It is
/// what `@chainvue/verus-sapling` derives from the same phrase — a separate
/// implementation, in TypeScript, doing PBKDF2 through WebCrypto rather than
/// RustCrypto and ZIP-32 through its own wasm build. Two independent paths
/// agreeing on the address is what makes this a differential rather than a
/// tautology, and it is the same package whose own docs record the hole this
/// work closes: *"it does not validate the BIP-39 checksum … a typo'd phrase
/// derives a valid but empty wallet"*.
///
/// Cross-checked 2026-07-31 with `deriveSaplingAccount({ mnemonic })`.
#[test]
fn one_phrase_reaches_both_the_transparent_and_the_shielded_address() {
    let transparent = private_key_from_seed_phrase(PHRASE).expect("transparent key");
    assert_eq!(
        transparent.address().to_string(),
        // The same value `verus_keys::seed` pins, reached from the facade.
        "RFHG6jCuPmTZknnwPwjMWv67HRarPCtEFh",
    );

    let seed = mnemonic_to_seed(PHRASE, "").expect("bip39 seed");
    let account = derive_account(&*seed, COIN_TYPE_MAINNET, 0).expect("zip32 account");
    let address = zaddr::encode(&account.address).expect("zs address");
    assert_eq!(
        address, "zs188wzupg00tqs3y5reyjc758c6vhl8qm2kg4k43mcp533ytrdkwpy8xjdk3zqtek0ng0cv7f0nta",
        "phrase -> BIP-39 seed -> m/32'/133'/0' -> default address changed",
    );
}

/// The two halves disagree about what a phrase is, and that is not a bug.
///
/// A Verus wallet derives a spendable transparent key from any text at all, so
/// free text must keep working there. It has no BIP-39 seed, so the shielded
/// half of that wallet does not exist — and a caller has to be able to learn
/// that without losing the transparent key it does have.
#[test]
fn free_text_still_has_a_transparent_key_but_no_shielded_one() {
    let phrase = "sample verus seed phrase for testing only do not use";

    assert_eq!(
        private_key_from_seed_phrase(phrase)
            .expect("transparent key")
            .address()
            .to_string(),
        "RQi75WyyN6naucDBwfKD7TfwpCUPLJSa6v",
    );
    assert_eq!(validate_mnemonic(phrase), Err(MnemonicError::WordCount(10)));
    assert_eq!(
        mnemonic_to_seed(phrase, ""),
        Err(MnemonicError::WordCount(10))
    );
}

/// A mistyped word must not reach ZIP-32 at all.
///
/// Without the checksum this derives a perfectly valid z-address holding
/// nothing, which is indistinguishable from a wallet that was never funded.
#[test]
fn a_mistyped_phrase_is_refused_before_any_key_is_derived() {
    let mistyped = PHRASE.replace("about", "abandon");
    assert_eq!(
        mnemonic_to_seed(&mistyped, ""),
        Err(MnemonicError::Checksum)
    );

    // And the address it *would* have produced is a real one — which is
    // exactly why the checksum has to be consulted rather than trusted to
    // surface later as an error.
    let transparent = private_key_from_seed_phrase(&mistyped).expect("still derives");
    assert_ne!(
        transparent.address().to_string(),
        "RFHG6jCuPmTZknnwPwjMWv67HRarPCtEFh",
    );
}
