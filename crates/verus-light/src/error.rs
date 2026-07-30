//! Errors from talking to a lightwalletd server.

use thiserror::Error;

/// Anything that can go wrong between asking a light server a question and
/// having a typed answer.
#[derive(Debug, Error)]
/// `#[non_exhaustive]`: a new way for a light server to answer badly is a
/// discovery, not a breaking change.
#[non_exhaustive]
pub enum LightError {
    /// The transport could not complete the request at all.
    #[error("transport failed: {0}")]
    Transport(String),

    /// The server answered, but with a non-zero gRPC status.
    ///
    /// `code` is a [gRPC status code]; 5 is `NOT_FOUND`, 2 is `UNKNOWN` (which
    /// is what lightwalletd returns for "block requested is newer than latest
    /// block"), 13 is `INTERNAL`.
    ///
    /// [gRPC status code]: https://grpc.io/docs/guides/status-codes/
    #[error("server returned gRPC status {code}: {message}")]
    Status {
        /// The numeric gRPC status code.
        code: i32,
        /// The server's `grpc-message`, verbatim.
        message: String,
    },

    /// The response did not decode as grpc-web framing.
    #[error("malformed grpc-web response: {0}")]
    Framing(String),

    /// The response body was framed correctly but was not a valid protobuf
    /// message, or a field held something the type cannot represent.
    #[error("malformed protobuf: {0}")]
    Protobuf(String),

    /// A unary call returned other than exactly one message.
    #[error("expected one message in the response, got {0}")]
    NotUnary(usize),

    /// The caller asked for something this crate refuses to do.
    #[error("{0}")]
    Refused(String),
}
