//! base58check, WIF and address parsing against arbitrary input.
//!
//! These eat text a user pastes — from a QR code, an email, a website. The
//! decoder is the last thing between a typo (or a hostile string) and a
//! transaction paying somewhere unintended.
//!
//! Bytes are interpreted as UTF-8 and non-UTF-8 input is dropped rather than
//! lossily converted: `from_utf8_lossy` would substitute U+FFFD and fuzz a
//! string no user could ever have typed, which wastes the corpus on inputs
//! that cannot occur.
//!
//! The assertions are round-trips. A WIF that parses must re-encode to the
//! same WIF, and an address that parses must re-encode to the same address —
//! otherwise two different strings name one key or one address, and "check the
//! address matches" stops being a check a human can perform.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verus_keys::{fuzzing, Address, PrivateKey};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // The raw codec: version byte plus payload, or an error. Never a panic.
    if let Ok((version, payload)) = fuzzing::decode_check(text) {
        let reencoded = fuzzing::encode_check(version, &payload);
        assert_eq!(
            reencoded, text,
            "base58check decoded a string that does not re-encode to itself"
        );
    }

    // A WIF carries key material. Two spellings of one key would mean a wallet
    // could import the same secret twice and not notice.
    if let Ok(key) = PrivateKey::from_wif(text) {
        assert_eq!(
            key.to_wif().as_str(),
            text,
            "a WIF that parsed did not re-encode to itself"
        );
    }

    // An address is what a human compares before sending money.
    if let Ok(address) = text.parse::<Address>() {
        assert_eq!(
            address.to_string(),
            text,
            "an address that parsed did not re-encode to itself"
        );
    }
});
