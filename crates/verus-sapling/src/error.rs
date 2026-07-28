//! Errors from shielded operations.

use thiserror::Error;
use verus_wire::WireError;

/// Something the shielded layer refuses to do, or could not do.
#[derive(Debug, Error)]
pub enum SaplingError {
    /// A key blob that is not a valid extended spending key (169 bytes) or
    /// diversifiable full viewing key (128 bytes).
    #[error("invalid shielded key: {0}")]
    InvalidKey(String),

    /// A `zs…` address that could not be decoded, or a raw address that could
    /// not be encoded.
    #[error("invalid Sapling address: {0}")]
    Address(String),

    /// A payment address that is not 43 bytes of valid diversifier and pk_d.
    #[error("invalid Sapling payment address")]
    InvalidPaymentAddress,

    /// A commitment-tree state that could not be parsed.
    #[error("invalid commitment tree state: {0}")]
    InvalidTreeState(String),

    /// A note that could not be decrypted with the supplied key — usually
    /// because it is not ours, which is not an error at the call sites that
    /// expect it.
    #[error("note could not be decrypted with this key")]
    NoteNotDecryptable,

    /// A witness could not be built for a note, so it cannot be spent.
    #[error("cannot build a Merkle witness for the note: {0}")]
    Witness(String),

    /// ZIP-32 derivation was asked for something out of range.
    #[error("invalid ZIP-32 derivation: {0}")]
    Derivation(String),

    /// A seed outside ZIP-32's accepted length (32 to 252 bytes).
    #[error("ZIP-32 seed must be 32 to 252 bytes, got {0}")]
    SeedLength(usize),

    /// The Sapling prover failed.
    #[error("proving failed: {0}")]
    Proving(String),

    /// The Groth16 proving parameters could not be read.
    #[error("cannot load Sapling parameters: {0}")]
    Params(String),

    /// A t→z build with nothing to shield — the shielded output is the point.
    #[error("a shield requires at least one shielded output")]
    NoShieldedOutput,

    /// The note being spent does not equal what the transaction pays out. The
    /// daemon accepts an overshoot and hands the difference to a miner, so this
    /// is caught here or not at all.
    #[error("value conservation failed: note {note} != outputs {outputs} + fee {fee}")]
    Conservation {
        /// Value of the note being spent, in zatoshi.
        note: u64,
        /// Sum of every output, in zatoshi.
        outputs: u64,
        /// The declared miner fee, in zatoshi.
        fee: u64,
    },

    /// Summing output values overflowed — refused rather than wrapped.
    #[error("output values overflow")]
    ValueOverflow,

    /// Wire encoding failed.
    #[error(transparent)]
    Wire(#[from] WireError),
}
