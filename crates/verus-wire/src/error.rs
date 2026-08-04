//! Errors from wire-format operations.

use thiserror::Error;

/// Something the wire layer refuses to do.
///
/// Every variant is a refusal, never a guess: producing a plausible-but-wrong
/// transaction is worse than returning an error.
#[derive(Debug, Error, PartialEq, Eq)]
/// `#[non_exhaustive]`: this enum gains a variant whenever the crate learns to
/// refuse something new, which happens routinely. A downstream `match` carries
/// a wildcard arm once rather than breaking on every such discovery.
#[non_exhaustive]
pub enum WireError {
    /// A shielded transaction was serialized without its binding signature.
    ///
    /// Writing zeros here would produce a transaction the network rejects, so
    /// this refuses instead.
    #[error("transaction has shielded parts but no binding signature")]
    MissingBindingSignature,

    /// A shielded spend was serialized without its spend-auth signature.
    ///
    /// Same reasoning as the binding signature: an unsigned spend is not a
    /// transaction the network will take, and zeros would only hide that.
    #[error("shielded spend {0} has no spend-auth signature")]
    MissingSpendAuthSignature(usize),

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
    /// `SIGHASH_ALL`, `SIGHASH_NONE`, `SIGHASH_SINGLE` and the `ANYONECANPAY`
    /// modifier are implemented; anything else is refused. Treating an unknown
    /// hash type as one of those — by ignoring the bits that differ — would sign
    /// a commitment the caller did not ask for.
    #[error("unsupported sighash type {0:#x}")]
    UnsupportedSighashType(u32),

    /// `SIGHASH_SINGLE` signed for an input with no output at the same index.
    ///
    /// ZIP-243 hashes an all-zero `hashOutputs` in that case, producing a
    /// signature that commits to nothing about where the money goes. Refused
    /// rather than produced.
    #[error("SIGHASH_SINGLE on input {index} but the transaction has {outputs} outputs")]
    SighashSingleWithoutOutput {
        /// The input being signed.
        index: usize,
        /// How many outputs exist.
        outputs: usize,
    },

    /// The bytes ended in the middle of a field.
    #[error("transaction ended mid-field")]
    TruncatedTransaction,

    /// Bytes remained after a complete transaction.
    ///
    /// Refused rather than ignored: a decoder that stops early lets two
    /// different byte strings parse to the same transaction, which is a way to
    /// be paid for something other than what was signed.
    #[error("{0} bytes remained after the transaction")]
    TrailingBytes(usize),

    /// A compact size encoded in more bytes than it needed.
    ///
    /// Re-serializing it produces different bytes and a different transaction
    /// id, so it is refused rather than quietly normalised.
    #[error("non-canonical compact size")]
    NonCanonicalCompactSize,

    /// A transaction header this crate does not parse.
    #[error("unsupported transaction version header {0:#010x}")]
    UnsupportedTransactionVersion(u32),

    /// A version group id that is not Sapling's.
    #[error("unsupported version group id {0:#010x}")]
    UnsupportedVersionGroup(u32),

    /// JoinSplits, which Verus does not use and this crate does not parse.
    #[error("{0} JoinSplits; Verus transactions have none")]
    JoinSplitsUnsupported(u64),
}
