//! Verus addresses.
//!
//! Two kinds share the base58check encoding and differ only in a version byte:
//! `R` addresses (`0x3c`) pay to a public key hash, `i` addresses (`0x66`)
//! identify a VerusID.
//!
//! **Mainnet and testnet use the same version bytes.** An address cannot tell
//! you which network it belongs to — only the chain it is used on can. Anything
//! claiming to validate "a testnet address" is theatre.

use core::fmt;
use core::str::FromStr;

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::base58::{decode_check, encode_check};
use crate::error::KeyError;

/// Version byte of an `R` (pay-to-public-key-hash) address.
pub const PUBKEY_HASH_VERSION: u8 = 0x3c;
/// Version byte of an `i` (VerusID) address.
pub const IDENTITY_VERSION: u8 = 0x66;
/// Version byte of a script-hash address.
pub const SCRIPT_HASH_VERSION: u8 = 0x55;

/// RIPEMD160(SHA256(data)) — the 20-byte hash behind every Verus address.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let ripemd = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripemd);
    out
}

/// What an address points at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressKind {
    /// `R…` — a public key hash.
    PubKeyHash,
    /// `i…` — a VerusID.
    Identity,
    /// A script hash.
    ScriptHash,
}

impl AddressKind {
    /// The base58check version byte for this kind.
    pub fn version(self) -> u8 {
        match self {
            Self::PubKeyHash => PUBKEY_HASH_VERSION,
            Self::Identity => IDENTITY_VERSION,
            Self::ScriptHash => SCRIPT_HASH_VERSION,
        }
    }

    /// The kind for a version byte, if it is one Verus uses.
    pub fn from_version(version: u8) -> Result<Self, KeyError> {
        match version {
            PUBKEY_HASH_VERSION => Ok(Self::PubKeyHash),
            IDENTITY_VERSION => Ok(Self::Identity),
            SCRIPT_HASH_VERSION => Ok(Self::ScriptHash),
            other => Err(KeyError::UnknownAddressVersion(other)),
        }
    }
}

/// A Verus address: a kind plus the 20-byte hash it carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    kind: AddressKind,
    hash: [u8; 20],
}

impl Address {
    /// Build an address from a kind and its 20-byte hash.
    pub fn new(kind: AddressKind, hash: [u8; 20]) -> Self {
        Self { kind, hash }
    }

    /// What this address points at.
    pub fn kind(&self) -> AddressKind {
        self.kind
    }

    /// The 20-byte hash.
    pub fn hash(&self) -> [u8; 20] {
        self.hash
    }

    /// The P2PKH scriptPubKey paying to this address:
    /// `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG`.
    ///
    /// Only meaningful for [`AddressKind::PubKeyHash`]; paying a VerusID uses a
    /// CryptoCondition output, which this crate does not build.
    pub fn p2pkh_script_pubkey(&self) -> Result<Vec<u8>, KeyError> {
        if self.kind != AddressKind::PubKeyHash {
            return Err(KeyError::UnknownAddressVersion(self.kind.version()));
        }
        let mut script = Vec::with_capacity(25);
        script.extend_from_slice(&[0x76, 0xa9, 0x14]); // OP_DUP OP_HASH160 PUSH20
        script.extend_from_slice(&self.hash);
        script.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG
        Ok(script)
    }

    /// Read the address a P2PKH scriptPubKey pays to, if it is one.
    pub fn from_p2pkh_script_pubkey(script: &[u8]) -> Option<Self> {
        if script.len() != 25
            || script[0..3] != [0x76, 0xa9, 0x14]
            || script[23..25] != [0x88, 0xac]
        {
            return None;
        }
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&script[3..23]);
        Some(Self::new(AddressKind::PubKeyHash, hash))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode_check(self.kind.version(), &self.hash))
    }
}

impl FromStr for Address {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (version, payload) = decode_check(s)?;
        if payload.len() != 20 {
            return Err(KeyError::AddressLength(payload.len() + 1));
        }
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&payload);
        Ok(Self::new(AddressKind::from_version(version)?, hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // From the TypeScript SDK's fixtures, where they are exercised against a
    // live daemon.
    const TEST_ADDRESS: &str = "RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX";
    const TEST_ADDRESS_HASH160: &str = "aabfb6281561808fe200ab7e186f0e3e0e82b381";

    #[test]
    fn parses_a_real_r_address_to_its_known_hash() {
        let address: Address = TEST_ADDRESS.parse().unwrap();
        assert_eq!(address.kind(), AddressKind::PubKeyHash);
        assert_eq!(hex::encode(address.hash()), TEST_ADDRESS_HASH160);
        assert_eq!(address.to_string(), TEST_ADDRESS);
    }

    #[test]
    fn builds_the_script_the_golden_transaction_pays_to() {
        let address: Address = TEST_ADDRESS.parse().unwrap();
        assert_eq!(
            hex::encode(address.p2pkh_script_pubkey().unwrap()),
            format!("76a914{TEST_ADDRESS_HASH160}88ac")
        );
    }

    #[test]
    fn script_round_trips_back_to_the_address() {
        let address: Address = TEST_ADDRESS.parse().unwrap();
        let script = address.p2pkh_script_pubkey().unwrap();
        assert_eq!(Address::from_p2pkh_script_pubkey(&script), Some(address));
    }

    #[test]
    fn rejects_a_bitcoin_address() {
        // Version 0x00: decodes cleanly, so it reaches the version check.
        let bitcoin = encode_check(0x00, &[0x11; 20]);
        assert!(matches!(
            bitcoin.parse::<Address>(),
            Err(KeyError::UnknownAddressVersion(0x00))
        ));
    }

    #[test]
    fn identity_addresses_start_with_i_and_are_not_payable_as_p2pkh() {
        let identity = Address::new(AddressKind::Identity, [0x22; 20]);
        assert!(identity.to_string().starts_with('i'));
        assert!(identity.p2pkh_script_pubkey().is_err());
    }
}
