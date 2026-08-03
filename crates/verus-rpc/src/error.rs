//! What can go wrong talking to a node.

use thiserror::Error;

/// A failure reaching, or understanding, a Verus daemon.
#[derive(Debug, Error)]
/// `#[non_exhaustive]`: a new way for a node to answer badly is a discovery,
/// not a breaking change.
#[non_exhaustive]
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

    /// The node answered `-32601`, "method not found".
    ///
    /// Distinct from [`RpcError::Node`] because the remedy differs: this means
    /// try another endpoint or your own node, and on public infrastructure it is
    /// the commonest failure.
    ///
    /// **It does not always mean the method is absent.** A filtering proxy can
    /// allowlist a method *at a particular arity* and answer `-32601` for any
    /// other — `api.verustest.net` serves `getblock` with one argument and
    /// refuses it with two. So this can also mean "not with those arguments",
    /// and a method recorded as unavailable is worth re-probing with a different
    /// argument count before believing it.
    ///
    /// `z_gettreestate` is genuinely absent there, at every arity.
    #[error("{method} was refused as method-not-found (the node may not have it, or may not accept it with these arguments)")]
    MethodUnavailable {
        /// The method that was refused.
        method: &'static str,
    },

    /// A money field could not be read exactly.
    ///
    /// Reading it approximately is not an option: the workspace has no float
    /// path for money, and a value off by one satoshi fails a conservation
    /// check somewhere else, later.
    #[error("{field} could not be read exactly: {value:?}")]
    LossyNumber {
        /// Which field.
        field: &'static str,
        /// What the daemon actually sent.
        value: String,
    },

    /// A plaintext URL for a host that is not loopback.
    #[error("{0} is plaintext: every address you query would be readable in transit")]
    InsecureUrl(String),

    /// A reply larger than the configured ceiling.
    #[error("reply exceeded the {cap}-byte ceiling")]
    ResponseTooLarge {
        /// The configured ceiling.
        cap: usize,
    },

    /// A value the daemon reported could not be represented — an amount that
    /// does not fit, a hash of the wrong length.
    #[error("value out of range: {0}")]
    OutOfRange(String),

    /// Not a failure: a request has not been answered **yet**.
    ///
    /// Only [`Cassette`](crate::Cassette) produces this, and only as the way an
    /// operation says what it still needs to know. A driver catches it, fetches
    /// what was recorded, and runs the operation again against a fuller cache.
    ///
    /// It exists because a flow that needs an answer it does not have simply
    /// has to stop, and stopping is spelled `Err` in Rust. That is the whole
    /// mechanism — no state machine, no async colouring, and no second copy of
    /// any flow.
    ///
    /// **Seeing this as a caller means the driver has a bug**, not that there
    /// is a condition to handle: either an operation was given a `Cassette`
    /// with nobody driving it, or it was still asking questions when the round
    /// budget ran out.
    #[error("an answer is needed before this can continue — a driver should have caught this")]
    AnswerNeeded,

    /// An operation tried to **broadcast** through a
    /// [`Cassette`](crate::Cassette).
    ///
    /// Refused rather than recorded, and that distinction is the point. A
    /// cassette exists to let an operation be re-run; a broadcast that was
    /// merely *recorded* would look to a driver like one more request to go and
    /// fetch, and fetching it means sending the transaction — once per round,
    /// with different bytes each time if anything about the operation varies.
    ///
    /// So this is not [`RpcError::AnswerNeeded`] and must never be treated as
    /// it: there is no answer to go and get.
    #[error(
        "a broadcast cannot be made through a cassette — an operation being re-run must only read"
    )]
    WriteThroughCassette,

    /// Two nodes gave different answers to a question where being lied to costs
    /// money.
    ///
    /// Produced only by [`SecondSourced`](crate::SecondSourced), and only for
    /// the questions it corroborates. Nothing has been spent when this is
    /// returned — that is the entire point, because the failure it guards
    /// against (a wrong `idregistrationfees`) is otherwise discovered *after* a
    /// name commitment has been paid for.
    ///
    /// It says nothing about which node is right. Two nodes disagreeing means
    /// at least one is wrong, and deciding which is the application's call —
    /// ask a third, prefer your own node, or stop and tell the user.
    #[error("{question}: sources disagree — {primary} vs {secondary}")]
    SourcesDisagree {
        /// The question that was asked, as a method and its argument.
        question: String,
        /// What the primary answered.
        primary: String,
        /// What the second source answered.
        secondary: String,
    },
}
