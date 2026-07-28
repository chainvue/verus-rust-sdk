//! Sapling payment addresses in their `zs…` bech32 form.
//!
//! A Sapling address is 43 raw bytes — an 11-byte diversifier followed by a
//! 32-byte `pk_d` — and everything inside this crate works on those bytes. This
//! module is the boundary where they meet the string a user pastes.
//!
//! # One HRP, both networks
//!
//! Verus emits `zs` on **mainnet and testnet alike**. That is not an oversight
//! here: the transparent side has the same property (mainnet and testnet share
//! every version byte), so on Verus an address never tells you which network it
//! belongs to. Sending to the wrong one produces a transaction the other chain's
//! daemon will happily reject, but nothing in the address will warn you first.
//!
//! Sapling addresses are bech32, **not** bech32m — the checksum constant
//! differs, and an encoder that picks the wrong one produces an address every
//! wallet rejects.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32, Hrp};

use crate::error::SaplingError;

/// The human-readable part Verus uses for Sapling addresses, on both networks.
pub const HRP: &str = "zs";

/// A raw Sapling payment address: 11-byte diversifier || 32-byte `pk_d`.
pub const ADDRESS_LEN: usize = 43;

/// Encode a raw 43-byte payment address as `zs…`.
pub fn encode(address: &[u8; ADDRESS_LEN]) -> Result<String, SaplingError> {
    let hrp = Hrp::parse(HRP).map_err(|e| SaplingError::Address(e.to_string()))?;
    bech32::encode::<Bech32>(hrp, address).map_err(|e| SaplingError::Address(e.to_string()))
}

/// Decode a `zs…` address to its raw 43 bytes.
///
/// Rejects any other human-readable part rather than decoding it: a `zt`, a
/// `ztestsapling` or a Zcash `zs`-lookalike is not a Verus Sapling address, and
/// silently accepting one would send funds somewhere unspendable.
pub fn decode(address: &str) -> Result<[u8; ADDRESS_LEN], SaplingError> {
    // `bech32::decode` accepts EITHER checksum. Naming the variant is what makes
    // this reject a bech32m string, which Verus never emits.
    let checked = CheckedHrpstring::new::<Bech32>(address)
        .map_err(|e| SaplingError::Address(e.to_string()))?;
    if checked.hrp().as_str() != HRP {
        return Err(SaplingError::Address(format!(
            "expected a `{HRP}` address, got `{}`",
            checked.hrp()
        )));
    }
    let data: Vec<u8> = checked.byte_iter().collect();
    data.as_slice().try_into().map_err(|_| {
        SaplingError::Address(format!(
            "a Sapling address is {ADDRESS_LEN} bytes, got {}",
            data.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real VRSCTEST address from a Verus Mobile wallet, confirmed against the
    /// app on 2026-07-28. It is also the mainnet-path key that wallet derives —
    /// see [`crate::derive`] — which is exactly why the HRP carries no network.
    const MOBILE_TESTNET: &str =
        "zs18pytujp8qu73a3fu6g9chl7mfumrr0htyqsh60r3ed4capagqwm8tx2l8f9c5g7w87q4566uph3";

    #[test]
    fn round_trips_a_real_wallet_address() {
        let raw = decode(MOBILE_TESTNET).expect("decode");
        assert_eq!(encode(&raw).expect("encode"), MOBILE_TESTNET);
    }

    #[test]
    fn a_decoded_address_is_diversifier_then_pk_d() {
        let raw = decode(MOBILE_TESTNET).expect("decode");
        assert_eq!(raw.len(), 43);
        // The 32 bytes after the diversifier must be a valid jubjub point, which
        // is what makes this a spendable address rather than 43 arbitrary bytes.
        assert!(sapling_crypto::PaymentAddress::from_bytes(&raw).is_some());
    }

    #[test]
    fn refuses_a_foreign_human_readable_part() {
        // Zcash testnet's Sapling HRP. Valid bech32, wrong chain.
        let raw = decode(MOBILE_TESTNET).unwrap();
        let hrp = Hrp::parse("ztestsapling").unwrap();
        let foreign = bech32::encode::<Bech32>(hrp, &raw).unwrap();
        assert!(matches!(decode(&foreign), Err(SaplingError::Address(_))));
    }

    #[test]
    fn refuses_a_corrupted_checksum() {
        let mut broken = MOBILE_TESTNET.to_string();
        broken.pop();
        broken.push('q');
        assert!(matches!(decode(&broken), Err(SaplingError::Address(_))));
    }

    #[test]
    fn refuses_bech32m() {
        // Sapling is bech32; bech32m differs only in the checksum constant, so
        // this is the exact mistake an encoder makes silently.
        let raw = decode(MOBILE_TESTNET).unwrap();
        let hrp = Hrp::parse(HRP).unwrap();
        let m = bech32::encode::<bech32::Bech32m>(hrp, &raw).unwrap();
        assert_ne!(m, MOBILE_TESTNET);
        assert!(matches!(decode(&m), Err(SaplingError::Address(_))));
    }
}
