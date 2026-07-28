//! Verus consensus wire format.
//!
//! The bytes a Verus daemon accepts: v4 (Sapling) transaction serialization and
//! the ZIP-243 sighashes, with the Verus consensus branch id injected. This
//! crate is the shared leaf of the workspace — it holds no keys, performs no
//! signing, and knows nothing about Sapling proving or coin selection.
//!
//! Ported from the daemon-proven serializer in `verus-sapling`, whose output is
//! locked by real transactions the daemon produced and accepted (see
//! `fixtures/`).

#![doc(html_no_source)]

// Phase 1 lands the ported serializer and sighashes here.
