//! Verus keys, addresses and signatures.
//!
//! WIF decoding, base58check, `R`/`i` address encoding, P2PKH scripts, and
//! ECDSA over a precomputed sighash.
//!
//! Two properties are load-bearing and deliberate:
//!
//! * **Deterministic signing.** RFC6979 with low-S normalization, matching what
//!   the TypeScript SDK produces through `@noble/curves`. No RNG is involved on
//!   this path, which is what makes byte-for-byte differential testing possible.
//! * **Key material is zeroized.** Decoded private keys wipe on drop.
//!
//! Note that Verus mainnet and testnet share every address version byte
//! (`pubKeyHash 0x3c`, `scriptHash 0x55`, `wif 0xbc`, `verusID 0x66`) — an
//! address cannot tell you which network it belongs to.

#![doc(html_no_source)]

// Phase 2 lands WIF/address/ECDSA here.
