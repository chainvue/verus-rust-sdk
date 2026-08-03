//! Trading value, and signing for it with more than one key.
//!
//! [`offer`] builds the on-chain offer: an output funded so that it can only
//! be spent by a transaction that also pays the offerer what they asked for.
//! [`partial`] carries a transaction between signers while it is incomplete.
//! [`multisig`] is m-of-n at the *script* layer — an ordinary P2SH output with
//! no identity behind it.
//!
//! # `SIGHASH_SINGLE | SIGHASH_ANYONECANPAY` is what makes an offer work
//!
//! The offerer signs one input and one output — theirs — and commits to
//! nothing else. Anyone may then add their own inputs and outputs and complete
//! the transaction, and the offerer's signature still verifies. That is the
//! whole mechanism, and it is also why an offer cannot be cancelled by
//! withdrawing the signature: it is cancelled by spending the funding output.
//!
//! # Script multisig is not identity multisig
//!
//! A VerusID with `minimumsignatures > 1` is multisig whose authority lives in
//! a chain object and can be rotated or recovered — that is in
//! `verus-tx-identity`. [`multisig`] here is the other kind: the signer set is
//! baked into the redeem script and cannot be changed afterwards. Their
//! failure modes are opposite, so they are deliberately not one API.

#![doc(html_no_source)]

pub mod multisig;
pub mod offer;
pub mod partial;

pub use partial::{InputKind, PartialTransaction};
