//! Offline Verus SDK — build and sign transactions without a node.
//!
//! This crate is the facade: it re-exports a coherent API over `verus-wire`,
//! `verus-keys`, `verus-tx` and (behind the `shielded` feature) `verus-sapling`.
//! It builds and signs bytes; broadcasting is the consumer's job.
//!
//! ```text
//! default = transparent    send VRSC and tokens; no prover, no parameters
//! shielded                + find your notes and derive ZIP-32 keys
//! prover                  + BUILD t→z / z→z / z→t; needs the Sapling parameters
//! multicore               native-only speedup for the prover
//! ```
//!
//! `shielded` on its own deliberately cannot build a shielded transaction — it
//! is the light half a balance-only wallet wants, with no bellman in the
//! dependency graph. Ask for `prover` when you need to spend.

#![doc(html_no_source)]

pub use verus_keys;
pub use verus_wire;

#[cfg(feature = "transparent")]
pub use verus_tx;

#[cfg(feature = "shielded")]
pub use verus_sapling;
