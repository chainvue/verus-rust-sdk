//! Verus shielded (Sapling) transactions.
//!
//! Verus shielded is *stock Zcash Sapling* — unmodified circuit, byte-identical
//! MPC parameters, consensus branch id `0x76b809bb`, version group id
//! `0x892f2085`, tx v4. The only Verus-specific value in the entire path is that
//! branch id, injected into the sighash.
//!
//! Phase 4 ports the daemon-proven implementation from `verus-sapling`'s crate
//! (t→z, z→z and z→t all accepted on vrsctest) rather than rewriting it.

#![doc(html_no_source)]
