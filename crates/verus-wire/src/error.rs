//! Errors from wire-format operations.

use thiserror::Error;

/// Something the wire layer refuses to do.
///
/// Every variant is a refusal, never a guess: producing a plausible-but-wrong
/// transaction is worse than returning an error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    /// A shielded transaction was serialized without its binding signature.
    ///
    /// Writing zeros here would produce a transaction the network rejects, so
    /// this refuses instead.
    #[error("transaction has shielded parts but no binding signature")]
    MissingBindingSignature,

    /// The requested input index does not exist.
    #[error("input index {index} out of range ({len} inputs)")]
    InputIndexOutOfRange {
        /// The index that was asked for.
        index: usize,
        /// How many inputs the transaction actually has.
        len: usize,
    },

    /// A sighash type other than `SIGHASH_ALL` was requested.
    ///
    /// `SIGHASH_SINGLE` and `ANYONECANPAY` zero out parts of the preimage and
    /// are only needed by marketplace offers, which this crate does not build
    /// yet. Supporting them silently — by ignoring the flags — would sign a
    /// commitment the caller did not ask for.
    #[error("unsupported sighash type {0:#x}; only SIGHASH_ALL (0x1) is implemented")]
    UnsupportedSighashType(u32),
}
