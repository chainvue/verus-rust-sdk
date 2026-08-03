//! Verus keys, addresses and signatures.
//!
//! WIF decoding, base58check, `R`/`i` addresses, P2PKH scripts, and ECDSA over a
//! precomputed sighash.
//!
//! ```
//! use verus_keys::PrivateKey;
//!
//! let key = PrivateKey::from_wif("UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc")?;
//! assert_eq!(key.address().to_string(), "RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX");
//!
//! // Signing takes a hash computed elsewhere (a sighash from `verus-wire`).
//! let der = key.sign_prehash_der(&[0x42; 32], 1)?;
//! # Ok::<(), verus_keys::KeyError>(())
//! ```
//!
//! # Properties that are load-bearing
//!
//! **Deterministic signing.** RFC6979 with low-S normalization, matching what
//! the TypeScript SDK produces through `@noble/curves`. No RNG on this path:
//! nothing to seed badly, no nonce to reuse, and byte-for-byte differential
//! testing becomes possible.
//!
//! **Key material zeroizes.** Private scalars and their encodings wipe on drop,
//! and `Debug` for [`PrivateKey`] is deliberately opaque so a key cannot reach a
//! log by accident. This shortens exposure; it does not defend against a host
//! that can read your memory.
//!
//! **No network.** Nothing here opens a socket.
//!
//! # Networks
//!
//! Verus mainnet and testnet share every version byte — `pubKeyHash 0x3c`,
//! `scriptHash 0x55`, `wif 0xbc`, `verusID 0x66`. An address cannot tell you
//! which network it belongs to, and any API claiming to check that would be
//! theatre.

#![doc(html_no_source)]

pub mod address;
mod base58;
pub mod bip39;
mod error;
mod key;
mod seed;

pub use address::{hash160, Address, AddressKind};
pub use bip39::{mnemonic_from_entropy, mnemonic_to_seed, validate_mnemonic, MnemonicError};
pub use error::KeyError;
pub use key::{PrivateKey, PublicKey, WIF_VERSION};
pub use seed::private_key_from_seed_phrase;
