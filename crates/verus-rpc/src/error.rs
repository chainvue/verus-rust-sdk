//! What can go wrong talking to a node.

use thiserror::Error;

/// A failure reaching, or understanding, a Verus daemon.
#[derive(Debug, Error)]
pub enum RpcError {
    /// The transport could not deliver the request or read the reply.
    #[error("transport: {0}")]
    Transport(String),

    /// The node answered, and the answer was an error.
    ///
    /// Carries the daemon's own code and message: `-5` for an unknown
    /// identity, `-26` for a rejected transaction, and so on.
    #[error("node returned error {code}: {message}")]
    Node {
        /// The daemon's error code.
        code: i64,
        /// The daemon's message, verbatim.
        message: String,
    },

    /// The reply was not JSON, or not the JSON-RPC shape.
    #[error("malformed reply: {0}")]
    Malformed(String),

    /// The reply parsed but a field this crate needs was missing or the wrong
    /// type. Kept distinct from [`RpcError::Malformed`] because it usually means
    /// a daemon version difference rather than a broken connection.
    #[error("unexpected reply shape: {0}")]
    Unexpected(String),

    /// A value the daemon reported could not be represented — an amount that
    /// does not fit, a hash of the wrong length.
    #[error("value out of range: {0}")]
    OutOfRange(String),
}
