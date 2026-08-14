//! Running an operation that does no I/O of its own.
//!
//! Every operation in this crate is written as straight-line code against a
//! [`ChainReader`](verus_rpc::ChainReader). That reads well and it is how the
//! flows are tested — but it needs a reader that answers *now*, and a browser
//! has no synchronous network to answer from.
//!
//! This module is how the same code runs in both places. It does not rewrite
//! the operations, duplicate them in async, or move any of them to JavaScript;
//! it changes what they are handed.
//!
//! # The two callers
//!
//! **Blocking native code needs nothing from this module.** It passes an
//! `RpcClient<HttpTransport>` as it always did; every request is answered as it
//! is made, so the operation finishes in one pass and no round machinery
//! engages. There is deliberately no blocking driver here, because there is
//! nothing for one to do.
//!
//! Native code that cannot block — a wallet with a UI thread — is the other
//! caller, and it uses [`advance`] exactly as a browser does. See
//! `verus-sdk/examples/drive_async.rs`.
//!
//! [`advance`] is for the other case. It performs **no I/O at all**: it runs
//! the operation against what is already known and returns either the finished
//! value or the requests still outstanding. A browser calls it in a loop, doing
//! the fetching itself between calls.
//!
//! ```no_run
//! # use verus_flows::drive::{advance, Step, Answers};
//! # use verus_flows::FlowError;
//! # fn post(_body: &str) -> Result<String, FlowError> { unimplemented!() }
//! # fn example() -> Result<(), FlowError> {
//! let mut answers = Answers::new();
//! let entries = loop {
//!     match advance(&mut answers, |client| verus_flows::history::history(client, &["R…"], None))? {
//!         Step::Ready(value) => break value,
//!         Step::Ask(bodies) => {
//!             for body in bodies {
//!                 let reply = post(&body)?;
//!                 answers.record(body, reply);
//!             }
//!         }
//!     }
//! };
//! # let _ = entries;
//! # Ok(())
//! # }
//! ```
//!
//! # Read-only, and the compiler says so
//!
//! An operation driven this way **runs more than once** — once per round, each
//! time from the beginning, against a cache that has grown. That is fine for
//! reading and catastrophic for writing: re-running a broadcast would broadcast
//! twice, and a failed broadcast is already ambiguous enough that this crate
//! forbids retrying one (see [`broadcast`](mod@crate::broadcast)).
//!
//! So a driven operation reads and hands back finished bytes; the caller
//! broadcasts, once, outside the loop. Nothing here can enforce that at
//! runtime — but the operations that take no
//! [`Broadcaster`](verus_rpc::Broadcaster) cannot broadcast, and that is a
//! signature rather than a promise.
//!
//! # What a round costs, and how to spend fewer
//!
//! A round ends when an operation asks for something it cannot answer. It
//! resumes from the start, gets its earlier questions from the cache for free,
//! and stops at the next genuinely new one.
//!
//! **A round is therefore one `?` on an unanswered read — not one level of the
//! dependency graph.** Two reads that need nothing from each other still cost
//! two rounds if the first is unwrapped before the second is issued, because
//! `?` returns and the second never runs. This was measured, not assumed:
//! `history` makes two independent reads and took two rounds until they were
//! reordered.
//!
//! The idiom that fixes it is small and local — issue, then unwrap:
//!
//! ```ignore
//! let tip = reader.block_count();          // no `?`
//! let found = reader.address_utxos(&[a]);  // no `?`
//! let (tip, found) = (tip?, found?);       // both already asked for
//! ```
//!
//! It costs nothing on a blocking client **when the reads succeed**, which is
//! the case that matters — and it halves the latency on a browser. On the
//! failure path it does cost something: the second request is now issued even
//! though the first already failed, so a dead node is two timeouts rather than
//! one. Worth knowing, not worth the round trip. The same shape applies to a loop: collect the results, then unwrap
//! them, or every iteration is its own network round trip. [`funding`](mod@crate::funding)
//! does exactly that for its coinbase probes.
//!
//! Where reads genuinely do depend on one another, no reordering helps and the
//! rounds are real: an identity's outpoint cannot be asked for before the
//! identity, and a referral chain is walked one registration at a time.
//!
//! # Randomness inside an operation is survivable; randomness in a *request* is not
//!
//! Re-execution rests on a request body being a stable cache key, so the
//! obvious worry is an operation that is not deterministic. There is one:
//! [`prepare_registration`](crate::prepare_registration) draws a fresh salt on
//! every call, and therefore a different one on every round.
//!
//! It is harmless, and it is worth saying why rather than leaving someone to
//! re-derive it. No request that operation makes mentions the salt — it reads
//! chain policy, a name and an address — so every round asks the same questions
//! and the cache converges. The salt of the round that finally returns is the
//! salt in the `Pending` that comes back, alongside the commitment built from
//! it. Nothing inconsistent escapes.
//!
//! What would break this is randomness that reaches a request body, because
//! then each round would ask a question the last one did not and the operation
//! would run to [`MAX_ROUNDS`] without converging. That is the thing not to
//! add. (Broadcasting under re-execution is a separate matter, and not
//! possible: see below.)

use verus_rpc::{Cassette, RpcClient, RpcError};

use crate::error::FlowError;

/// How many times an operation may be resumed before this gives up.
///
/// A generous ceiling over the deepest flow in the crate. It is a backstop
/// against an operation that asks for something new every round and never
/// converges — a bug, and one that would otherwise present as a browser tab
/// fetching forever.
pub const MAX_ROUNDS: usize = 16;

/// The largest reply [`Answers::record`] will take, matching the ceiling
/// `HttpTransport` applies natively.
///
/// A driver fetches for itself, so nothing else bounds what it can hand back.
/// Natively an oversized body is a caught error; in a browser, copying one into
/// WebAssembly linear memory can abort the instance outright — and an aborted
/// instance takes every imported key with it, for the life of the page. So the
/// bound belongs on this side of the boundary too.
pub const MAX_REPLY_BYTES: usize = 8 * 1024 * 1024;

/// What an operation still needs, or what it produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step<T> {
    /// Complete JSON-RPC bodies to POST, then hand back through
    /// [`Answers::record`].
    ///
    /// They are independent of one another: an operation that needed one
    /// answer to form the next question would have stopped at the first. So
    /// they can be fetched concurrently, and on a browser they should be.
    Ask(Vec<String>),
    /// The operation finished.
    Ready(T),
}

/// What is known so far, carried between rounds.
///
/// One of these belongs to one operation's planning and is discarded
/// afterwards. That is deliberate rather than wasteful: every round sees the
/// same tip, the same UTXO set and the same identity, so a plan cannot be built
/// half from one view of the chain and half from another.
///
/// **Reuse is refused, not merely discouraged.** Once [`advance`] returns
/// [`Step::Ready`], this handle is spent: a second operation driven against it
/// would plan against the first operation's frozen tip and UTXO set, however
/// long ago that was — quietly, because a cached answer is indistinguishable
/// from a fresh one. The concrete cost is a payment built from coins a
/// still-unconfirmed transaction already spends. [`advance`] returns
/// [`FlowError::AnswersSpent`] instead of obliging.
#[derive(Debug, Default)]
pub struct Answers {
    cassette: Cassette,
    rounds: usize,
    /// Set once an operation driven with this handle reaches
    /// [`Step::Ready`]. From then on [`advance`] refuses rather than
    /// replanning against the view left behind.
    finished: bool,
}

impl Answers {
    /// Nothing known yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the reply to one of the bodies from [`Step::Ask`].
    ///
    /// The body is the key and must be passed back unchanged.
    ///
    /// # Errors
    ///
    /// [`FlowError::NotReady`] if the reply is larger than
    /// [`MAX_REPLY_BYTES`]. A driver does its own fetching, so the ceiling
    /// [`HttpTransport`](verus_rpc::RpcError) applies natively is not in the
    /// path — and a browser copying an unbounded body into WebAssembly linear
    /// memory does not get an error, it gets a dead module, taking any imported
    /// keys with it.
    pub fn record(
        &mut self,
        body: impl Into<String>,
        reply: impl Into<String>,
    ) -> Result<(), FlowError> {
        let reply = reply.into();
        if reply.len() > MAX_REPLY_BYTES {
            return Err(FlowError::NotReady(format!(
                "a reply of {} bytes exceeds the {MAX_REPLY_BYTES}-byte ceiling",
                reply.len()
            )));
        }
        self.cassette.answer(body, reply);
        Ok(())
    }

    /// How many rounds have run.
    #[must_use]
    pub fn rounds(&self) -> usize {
        self.rounds
    }

    /// How many answers are held.
    #[must_use]
    pub fn known(&self) -> usize {
        self.cassette.known()
    }
}

/// Run one round of `operation` against what is known. **Performs no I/O.**
///
/// Returns [`Step::Ready`] when the operation completed, or [`Step::Ask`] with
/// the bodies it still needs. Any other failure is the operation's own and is
/// returned as-is.
///
/// # Errors
///
/// [`FlowError::AnswersSpent`] if this `Answers` already carried an earlier
/// operation to [`Step::Ready`]. See the type's docs for why reuse is refused
/// rather than merely discouraged — start the next operation from
/// [`Answers::new`].
///
/// [`FlowError::Stalled`] if the operation is still asking after
/// [`MAX_ROUNDS`], or if it stopped for want of an answer without recording
/// what it wanted. Both mean it is not converging; neither is a slow network.
pub fn advance<T, F>(answers: &mut Answers, operation: F) -> Result<Step<T>, FlowError>
where
    F: FnOnce(&RpcClient<Cassette>) -> Result<T, FlowError>,
{
    // Checked before the round cap: a finished handle is refused regardless of
    // how many rounds it has left, and the message should say why rather than
    // report a coincidental cap.
    if answers.finished {
        return Err(FlowError::AnswersSpent);
    }
    if answers.rounds >= MAX_ROUNDS {
        return Err(FlowError::Stalled(format!(
            "still asking for more after {MAX_ROUNDS} rounds"
        )));
    }
    answers.rounds += 1;

    let mut cassette = std::mem::take(&mut answers.cassette);
    cassette.forget_misses();

    let client = RpcClient::new(cassette);
    let outcome = operation(&client);
    let cassette = client.into_transport();

    let step = match outcome {
        Ok(value) => Step::Ready(value),
        // Not a failure — the operation stopped because it needs to know
        // something. Anything it asked for and could not get is in the record.
        Err(FlowError::Rpc(RpcError::AnswerNeeded)) => {
            let outstanding = cassette.outstanding();
            // An empty list would send a caller round the loop with nothing to
            // fetch and nothing to record — the browser tab spinning forever
            // that `MAX_ROUNDS` is supposed to prevent. A `debug_assert` here
            // would hold in tests and vanish in the build that matters.
            if outstanding.is_empty() {
                answers.cassette = cassette;
                return Err(FlowError::Stalled(
                    "an operation stopped for want of an answer without recording what it wanted"
                        .into(),
                ));
            }
            Step::Ask(outstanding)
        }
        Err(other) => {
            answers.cassette = cassette;
            return Err(other);
        }
    };

    // Marked here rather than only where the caller stops driving: the field
    // has to be true the instant `Ready` exists, or a second call slipped in
    // before the caller notices would still see a live handle.
    if matches!(step, Step::Ready(_)) {
        answers.finished = true;
    }

    answers.cassette = cassette;
    Ok(step)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape of a driven run: the operation stops, says what it needs, and
    /// gets further on the next round.
    #[test]
    fn an_operation_asks_then_finishes() {
        let mut answers = Answers::new();

        let step = advance(&mut answers, |client| {
            Ok(verus_rpc::ChainReader::block_count(client)?)
        })
        .expect("a miss is not a failure");

        let bodies = match step {
            Step::Ask(bodies) => bodies,
            Step::Ready(value) => panic!("nothing was known, yet it answered {value}"),
        };
        assert_eq!(bodies.len(), 1);
        assert!(bodies[0].contains(r#""method":"getblockcount""#));

        answers
            .record(bodies[0].clone(), r#"{"result":1171000}"#)
            .expect("a small reply");

        let step = advance(&mut answers, |client| {
            Ok(verus_rpc::ChainReader::block_count(client)?)
        })
        .expect("the answer is known now");
        assert_eq!(step, Step::Ready(1_171_000));
        assert_eq!(answers.rounds(), 2);
    }

    /// The ceiling a driver has to enforce because nothing else can.
    ///
    /// `HttpTransport` caps what it reads; a driver fetches for itself, so a
    /// hostile endpoint's reply arrives here unmeasured. Natively that is a
    /// large allocation; in a browser it is a dead module.
    #[test]
    fn an_oversized_reply_is_refused() {
        let mut answers = Answers::new();
        let huge = "x".repeat(MAX_REPLY_BYTES + 1);
        let refused = answers.record("body", huge);
        assert!(
            matches!(refused, Err(FlowError::NotReady(_))),
            "{refused:?}"
        );

        // And the boundary itself is allowed, so the cap is not off by one.
        assert!(answers.record("body", "x".repeat(MAX_REPLY_BYTES)).is_ok());
    }

    /// A real failure must not be mistaken for "needs an answer" and retried
    /// forever.
    #[test]
    fn a_genuine_error_is_returned_rather_than_retried() {
        let mut answers = Answers::new();
        let outcome: Result<Step<u32>, FlowError> =
            advance(&mut answers, |_| Err(FlowError::Content("no".into())));
        assert!(matches!(outcome, Err(FlowError::Content(_))));
    }

    /// An operation that never converges would otherwise present as a browser
    /// tab fetching forever. The cap turns that into a loud failure.
    #[test]
    fn a_non_converging_operation_gives_up() {
        let mut answers = Answers::new();

        // Never record the answer, so every round asks again and gets nowhere.
        for round in 0..MAX_ROUNDS {
            let step = advance(&mut answers, |client| {
                Ok(verus_rpc::ChainReader::block_count(client)?)
            })
            .unwrap_or_else(|e| panic!("round {round} should still be allowed: {e}"));
            assert!(matches!(step, Step::Ask(_)));
        }

        let past_the_cap: Result<Step<u32>, FlowError> = advance(&mut answers, |client| {
            Ok(verus_rpc::ChainReader::block_count(client)?)
        });
        assert!(matches!(past_the_cap, Err(FlowError::Stalled(_))));
    }

    /// The defect this module exists to close: a finished handle must not be
    /// handed to a second operation.
    ///
    /// Without this, a second operation's first round asks exactly the
    /// questions the first operation already answered — the tip and the UTXO
    /// set are keyed only by address, not by which payment they fund — so it
    /// would resolve straight to `Ready` against a view that may be hours
    /// old, no differently answered than a fresh one.
    #[test]
    fn a_second_operation_on_a_finished_handle_is_refused() {
        let mut answers = Answers::new();

        let step = advance(&mut answers, |client| {
            Ok(verus_rpc::ChainReader::block_count(client)?)
        })
        .expect("a miss is not a failure");
        let bodies = match step {
            Step::Ask(bodies) => bodies,
            Step::Ready(value) => panic!("nothing was known, yet it answered {value}"),
        };
        answers
            .record(bodies[0].clone(), r#"{"result":1171000}"#)
            .expect("a small reply");

        let first = advance(&mut answers, |client| {
            Ok(verus_rpc::ChainReader::block_count(client)?)
        })
        .expect("the answer is known now");
        assert_eq!(first, Step::Ready(1_171_000));

        // A second, distinct operation against the same handle — the shape a
        // caller reusing `Answers` across two payments would hit. It must be
        // refused rather than resolved against the first operation's cache.
        let second: Result<Step<u32>, FlowError> = advance(&mut answers, |client| {
            Ok(verus_rpc::ChainReader::block_count(client)? + 1)
        });
        // Its own variant, not `NotReady`: `NotReady` means the chain does not
        // yet support a step and a retry can succeed, which sends a caller
        // into a loop that never can.
        assert!(
            matches!(second, Err(FlowError::AnswersSpent)),
            "a finished handle must refuse a second operation: {second:?}"
        );
    }

    /// The poison must not be over-eager: it fires on `Ready`, not on a round
    /// that merely asked.
    ///
    /// The same operation is routinely driven more than once — that is what
    /// rounds are — and a caller whose fetch failed mid-flight re-drives it
    /// with the answers it did get. Refusing there would break the ordinary
    /// path, so the handle stays live until an operation actually completes.
    #[test]
    fn the_same_operation_can_be_re_driven_before_it_is_ready() {
        let mut answers = Answers::new();

        let step = advance(&mut answers, |client| {
            Ok(verus_rpc::ChainReader::block_count(client)?)
        })
        .expect("a miss is not a failure");
        assert!(matches!(step, Step::Ask(_)));

        // Nothing recorded — the caller's fetch failed. The very same
        // operation goes round again and must still be allowed.
        let again = advance(&mut answers, |client| {
            Ok(verus_rpc::ChainReader::block_count(client)?)
        })
        .expect("an unfinished handle must still drive its own operation");
        let bodies = match again {
            Step::Ask(bodies) => bodies,
            Step::Ready(value) => panic!("nothing was known, yet it answered {value}"),
        };

        answers
            .record(bodies[0].clone(), r#"{"result":1171000}"#)
            .expect("a small reply");

        let done = advance(&mut answers, |client| {
            Ok(verus_rpc::ChainReader::block_count(client)?)
        })
        .expect("the answer is known now");
        assert_eq!(done, Step::Ready(1_171_000));
        assert_eq!(answers.rounds(), 3);
    }
}
