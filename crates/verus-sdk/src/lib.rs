//! Offline Verus SDK — build and sign transactions without a node.
//!
//! This crate is the facade: it re-exports a coherent API over `verus-wire`,
//! `verus-keys`, `verus-tx` and (behind the `shielded` feature) `verus-sapling`.
//! It builds and signs bytes; broadcasting is the consumer's job.
//!
//! ```text
//! default features = transparent      send VRSC, no prover, no parameters
//! shielded                            + t→z / z→z / z→t, needs Sapling params
//! ```

#![doc(html_no_source)]

pub use verus_keys;
pub use verus_wire;

#[cfg(feature = "transparent")]
pub use verus_tx;

#[cfg(feature = "shielded")]
pub use verus_sapling;
