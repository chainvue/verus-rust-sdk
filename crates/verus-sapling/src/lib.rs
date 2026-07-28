//! Verus shielded (Sapling) transactions.
//!
//! Verus shielded is **stock Zcash Sapling**: unmodified circuit, byte-identical
//! MPC parameters, consensus branch id `0x76b809bb`, version group id
//! `0x892f2085`, transaction v4. The only Verus-specific value in the whole path
//! is that branch id, injected into the sighash — which is why this crate is
//! built on `sapling-crypto` rather than reimplementing anything.
//!
//! # What is here
//!
//! * [`scan`] — find your own notes by trial-decrypting compact blocks, with no
//!   full node and no `z_listunspent`. Needs only a viewing key.
//! * [`mod@derive`] — ZIP-32 shielded key derivation, `m/32'/coin'/account'`.
//!
//! # Features
//!
//! Scanning and derivation are the light half: milliseconds, no zk-SNARK prover,
//! no proving parameters. Enabling `prover` adds Groth16 proving, which pulls in
//! bellman and expects ~50 MB of Sapling parameters at runtime — a wallet that
//! only needs to see its balance should not pay for that.
//!
//! # Provenance
//!
//! Ported from `@chainvue/verus-sapling`, where all three shielded flows (t→z,
//! z→z, z→t) were built, broadcast and accepted by a Verus testnet daemon. This
//! is that proven implementation rebased onto [`verus_wire`], not a rewrite.

#![doc(html_no_source)]

pub mod derive;
mod error;
pub mod scan;

pub use error::SaplingError;
