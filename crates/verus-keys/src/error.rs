//! Errors from key, address and signature handling.

use thiserror::Error;

/// Something the key layer refuses to do.
#[derive(Debug, Error, PartialEq, Eq)]
/// `#[non_exhaustive]`: this enum gains a variant whenever the crate learns to
/// refuse something new, which happens routinely. A downstream `match` carries
/// a wildcard arm once rather than breaking on every such discovery.
#[non_exhaustive]
pub enum KeyError {
    /// The string is not valid base58check (bad characters, or a bad checksum).
    ///
    /// The checksum is the only guard against a mistyped address, so a failure
    /// here is a refusal rather than a best-effort decode.
    #[error("invalid base58check: {0}")]
    Base58(String),

    /// A WIF whose version byte is not Verus's `0xbc`.
    ///
    /// Bitcoin's `0x80` is the usual culprit. Accepting it would derive a key
    /// for a different network that fails only later, at signing.
    #[error("wrong WIF version byte {found:#04x}, expected {expected:#04x}")]
    WrongWifVersion {
        /// The byte that was present.
        found: u8,
        /// The byte Verus requires.
        expected: u8,
    },

    /// A WIF payload of the wrong length (33 uncompressed, 34 compressed).
    #[error("WIF payload is {0} bytes, expected 33 or 34")]
    WifLength(usize),

    /// A 34-byte WIF whose trailing compression flag is not `0x01`.
    #[error("invalid WIF compression flag {0:#04x}, expected 0x01")]
    WifCompressionFlag(u8),

    /// An address whose version byte is neither `R` (`0x3c`) nor `i` (`0x66`).
    #[error("unknown address version byte {0:#04x}")]
    UnknownAddressVersion(u8),

    /// An address payload that is not a version byte plus a 20-byte hash.
    #[error("address payload is {0} bytes, expected 21")]
    AddressLength(usize),

    /// Scalar bytes that are not a valid secp256k1 private key — zero, or at or
    /// above the curve order.
    #[error("not a valid secp256k1 private key")]
    InvalidPrivateKey,

    /// Bytes that are not a valid secp256k1 public key.
    #[error("not a valid secp256k1 public key")]
    InvalidPublicKey,

    /// A seed phrase that is empty or only whitespace.
    ///
    /// The wallets hash it happily; we refuse, because an empty seed is an unset
    /// configuration value and its address is a constant anyone can watch.
    #[error("seed phrase is empty")]
    EmptySeedPhrase,

    /// A signature that is not the 65-byte recoverable form, or whose header
    /// byte is outside `27..=34`.
    ///
    /// Recovery would otherwise "succeed" and return an unrelated public key,
    /// which fails later as a mismatched address and reads like the wrong signer
    /// rather than a malformed signature.
    #[error("not a valid recoverable signature")]
    InvalidSignature,

    /// A WIF passed where a seed phrase was expected.
    ///
    /// Hashing it would silently derive a *different* key, stranding funds.
    #[error("input is a WIF private key, not a seed phrase")]
    SeedPhraseIsWif,
}
