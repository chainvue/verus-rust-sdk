//! A facade that hands out a struct must hand out the values its fields take.
//!
//! [`currency::CurrencyDefinition`] has a public `options: u32`, and the bits
//! that belong in it are consensus constants — not something a caller can
//! reasonably rederive. Until 2026-08-06 they were reachable only at
//! `verus_sdk::verus_tx::currency_definition::option::TOKEN`, which is reaching
//! around the facade into the crate it exists to front.
//!
//! `CurrencyDefinition::token()` sets `TOKEN` itself, so the simple case never
//! noticed. A fractional basket, an NFT, or referral-paying sub-identity
//! registration all need the constant by name.
//!
//! This is mostly a compile-time assertion: if the re-export goes away, this
//! file stops building. The value checks are here so it is not vacuous — they
//! pin the bits against `CCurrencyDefinition::ECurrencyOptions`.

#![cfg(feature = "transparent")]

use verus_sdk::currency::{option, CurrencyDefinition, CurrencyId};

#[test]
fn the_option_bits_are_reachable_through_the_facade() {
    assert_eq!(option::FRACTIONAL, 0x1);
    assert_eq!(option::ID_REFERRALS, 0x8);
    assert_eq!(option::TOKEN, 0x20);
    assert_eq!(option::NFT_TOKEN, 0x800);
}

/// And they compose with what the facade already handed out.
///
/// The case the constants exist for: `token()` covers a plain token, and
/// anything past that is the caller setting bits.
#[test]
fn a_definition_can_be_given_options_without_naming_verus_tx() {
    let mut definition =
        CurrencyDefinition::token(CurrencyId::from_bytes([0x2b; 20]), "basket", 900_000);
    definition.options |= option::FRACTIONAL | option::ID_REFERRALS;

    assert!(
        definition.is_fractional(),
        "the bit the facade just handed out is the one the struct reads"
    );
    assert_eq!(
        definition.options & option::TOKEN,
        option::TOKEN,
        "and setting more bits does not clear the one token() set"
    );
}
