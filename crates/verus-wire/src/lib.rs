//! Verus consensus wire format.
//!
//! The bytes a Verus daemon accepts: v4 (Sapling) transaction serialization and
//! the ZIP-243 sighashes, with the Verus consensus branch id injected. This is
//! the shared leaf of the workspace — it holds no keys, performs no signing, and
//! knows nothing about Sapling proving or coin selection.
//!
//! ```
//! use verus_wire::{consensus::VERUS_BRANCH_ID, TxIn, TxOut, TxV4};
//!
//! let tx = TxV4 {
//!     inputs: vec![TxIn::unsigned([0x11; 32], 0, 0xffff_ffff)],
//!     outputs: vec![TxOut { value: 50_000_000, script_pubkey: vec![0x76, 0xa9] }],
//!     expiry_height: 0,
//!     ..TxV4::default()
//! };
//!
//! // What a transparent input signs over, given its prevout script and value.
//! let sighash = tx.transparent_sighash(VERUS_BRANCH_ID, 0, &[0x76, 0xa9], 100_000_000, 1)?;
//! assert_eq!(sighash.len(), 32);
//! # Ok::<(), verus_wire::WireError>(())
//! ```
//!
//! # Correctness
//!
//! The serializer is ported from `@chainvue/verus-sapling`, whose output is
//! locked by real transactions a Verus daemon produced and accepted. Those same
//! transactions are committed here (`fixtures/daemon/`) and the test suite
//! reproduces them byte for byte — including a check that recomputes the
//! transparent sighash for a daemon-signed input and verifies the daemon's own
//! signature against it.
//!
//! # Byte order
//!
//! Txids and the shielded 32-byte fields are stored in **internal** (wire) order
//! here. RPC displays them reversed. [`hash::txid_display`] converts.

#![doc(html_no_source)]

pub mod compact;
pub mod consensus;
mod error;
pub mod hash;
mod tx;

pub use error::WireError;
pub use tx::{TxIn, TxOut, TxV4};
