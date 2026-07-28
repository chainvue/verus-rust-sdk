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

    /// Wire encoding failed.
    #[error(transparent)]
    Wire(#[from] WireError),
}
