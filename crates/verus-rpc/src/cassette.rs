//! A transport that answers from what it has been told, and remembers what it
//! could not answer.
//!
//! This is the whole of the sans-io mechanism. It exists so the flows in
//! `verus-flows` can run somewhere with no synchronous network — a browser —
//! without being rewritten, duplicated in async, or reimplemented in
//! JavaScript.
//!
//! # How an operation runs without doing any I/O
//!
//! Give an operation an [`RpcClient`](crate::RpcClient) over a `Cassette` and
//! run it. Every request it makes either hits the cache and returns, or misses,
//! gets recorded, and stops the operation with
//! [`RpcError::AnswerNeeded`]. A driver then fetches what was recorded, puts
//! the replies in, and runs the operation **again**.
//!
//! ```text
//! run  →  Err(AnswerNeeded), recorded: [getblockcount, getaddressutxos]
//! fetch those two, answer them
//! run  →  Err(AnswerNeeded), recorded: [getrawtransaction …]   (it got further)
//! fetch that, answer it
//! run  →  Ok(signed bytes)
//! ```
//!
//! Each round gets further than the last, because the cache only grows.
//!
//! # Why re-running is sound, and where it is not
//!
//! Two properties make it work, and both are facts about this crate rather than
//! hopes:
//!
//! * **A request body is a stable key.** [`crate::envelope`] builds every body
//!   with a constant id, so the same call always produces the same bytes. Two
//!   runs of the same operation ask the same questions in the same words.
//! * **Nothing that varies between rounds reaches a request.** This is the
//!   honest form of "the operations are pure", which they are not:
//!   `prepare_registration` draws a fresh commitment salt on every run. That is
//!   harmless because the salt reaches no request body — see below — but the
//!   property the mechanism actually needs is this narrower one.
//!
//! The place it is *not* sound is anything that changes the world. Re-running a
//! broadcast would broadcast twice, and a failed broadcast is already ambiguous
//! enough that this crate forbids retrying one. So an operation driven this way
//! must **read only** and hand back finished bytes — the broadcast belongs to
//! the driver, outside the loop, exactly once.
//!
//! That is refused here rather than left to a signature. An earlier version of
//! this note claimed the type system enforced it, and it does not:
//! [`RpcClient`](crate::RpcClient) implements
//! [`Broadcaster`](crate::Broadcaster) for *every* transport, so an
//! `RpcClient<Cassette>` is a perfectly good broadcaster and driving a
//! broadcasting flow compiles. Worse, a broadcast recorded as an ordinary miss
//! looks to a driver like one more thing to go and fetch — and fetching it
//! means sending the transaction, once per round.
//!
//! So a write is refused at the transport with
//! [`RpcError::WriteThroughCassette`], which is deliberately **not**
//! [`RpcError::AnswerNeeded`]: there is nothing to go and get.
//!
//! # Nothing that varies per round may reach a request
//!
//! The purity this rests on is narrower than "the operations are pure".
//! `prepare_registration` draws a fresh commitment salt on every run, so two
//! rounds of it are not identical — that is harmless only because the salt
//! reaches no request body, and the transaction it eventually appears in is
//! built once, on the last round. A round-varying value that *did* reach a body
//! would produce a new key every round, never converge, and — before writes
//! were refused above — have broadcast something different each time.
//!
//! A driven caller that wants the stronger property should use
//! `prepare_registration_with_salt` and hold the salt itself, which it must do
//! anyway: the salt cannot be recovered from the chain.
//!
//! The other hazard is a flow that treats a failed request as an answer. One
//! did — a registration checked `reader.identity(name).is_ok()` to decide a
//! name was free, and an unanswered request is also not `ok`. Distinguish "the
//! node said no" from "not asked yet"; [`RpcError::AnswerNeeded`] is how.
//!
//! # It is not a cache in the ordinary sense
//!
//! A `Cassette` never expires anything and never fetches anything. It holds the
//! answers for **one** operation's planning, which is a feature: every round
//! sees the same tip, the same UTXO set and the same identity, so a plan cannot
//! be built half from one view of the chain and half from another.

use std::cell::RefCell;
use std::collections::BTreeMap;

use crate::error::RpcError;
use crate::transport::{RequestBody, Transport};

/// Answers already known, and a record of what was asked for and missing.
///
/// See the module docs for how this is driven.
#[derive(Debug, Default)]
pub struct Cassette {
    answers: BTreeMap<String, String>,
    missing: RefCell<Vec<String>>,
}

impl Cassette {
    /// A cassette that knows nothing. Every request will miss.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the reply to one request body.
    ///
    /// The body must be exactly what was handed out by
    /// [`Cassette::outstanding`] — it is the key, byte for byte.
    pub fn answer(&mut self, body: impl Into<String>, reply: impl Into<String>) {
        self.answers.insert(body.into(), reply.into());
    }

    /// The request bodies that were asked for and not known, in the order they
    /// were first asked, each once.
    ///
    /// These are complete JSON-RPC bodies: POST one verbatim and give the
    /// response text back through [`Cassette::answer`]. A caller never composes
    /// a request, which is the same property [`RequestBody`] exists to protect.
    ///
    /// They are all independent of each other **within a round** — an operation
    /// that needed one to ask the next would have stopped at the first — so
    /// they can be fetched concurrently.
    #[must_use]
    pub fn outstanding(&self) -> Vec<String> {
        self.missing.borrow().clone()
    }

    /// Whether anything went unanswered since [`Cassette::forget_misses`].
    #[must_use]
    pub fn missed(&self) -> bool {
        !self.missing.borrow().is_empty()
    }

    /// Clear the record of misses, keeping the answers.
    ///
    /// A driver calls this between rounds. The answers are what makes progress;
    /// the misses are only the current round's shopping list.
    pub fn forget_misses(&mut self) {
        self.missing.borrow_mut().clear();
    }

    /// How many answers are held.
    #[must_use]
    pub fn known(&self) -> usize {
        self.answers.len()
    }
}

impl Transport for Cassette {
    fn post(&self, body: &RequestBody) -> Result<String, RpcError> {
        // Before anything is looked up or recorded. A write has no answer to
        // fetch, and recording one would invite a driver to send it.
        if body.writes() {
            return Err(RpcError::WriteThroughCassette);
        }
        if let Some(reply) = self.answers.get(body.as_str()) {
            return Ok(reply.clone());
        }
        // Recorded once. An operation re-run against a growing cache asks its
        // earlier questions again and gets them from the cache, so anything
        // reaching here is genuinely new — but a single round can still ask the
        // same unknown twice through two code paths, and asking the network
        // for it twice would be waste.
        let mut missing = self.missing.borrow_mut();
        let body = body.as_str();
        if !missing.iter().any(|seen| seen == body) {
            missing.push(body.to_string());
        }
        Err(RpcError::AnswerNeeded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChainReader, RpcClient};

    /// The body `getblockcount` produces, which the tests use as a known key.
    fn ask_block_count(cassette: Cassette) -> (Cassette, Vec<String>) {
        let client = RpcClient::new(cassette);
        let _ = client.block_count();
        let outstanding = client.transport().outstanding();
        (client.into_transport(), outstanding)
    }

    #[test]
    fn an_unknown_request_is_recorded_rather_than_failing() {
        let (_, outstanding) = ask_block_count(Cassette::new());
        assert_eq!(outstanding.len(), 1);
        assert!(outstanding[0].contains(r#""method":"getblockcount""#));
        assert!(outstanding[0].contains(r#""jsonrpc":"1.0""#));
    }

    /// The property the whole design rests on: the same call produces the same
    /// bytes every time, so a body can be its own cache key. If
    /// `envelope::request` ever gained a counter or a random id, re-running an
    /// operation would ask the same question in different words and never
    /// converge.
    #[test]
    fn the_same_request_produces_the_same_key_every_time() {
        let (_, first) = ask_block_count(Cassette::new());
        let (_, second) = ask_block_count(Cassette::new());
        assert_eq!(first, second);
    }

    #[test]
    fn an_answered_request_stops_being_outstanding() {
        let (mut cassette, outstanding) = ask_block_count(Cassette::new());
        cassette.answer(outstanding[0].clone(), r#"{"result":1170000}"#);
        cassette.forget_misses();

        let client = RpcClient::new(cassette);
        assert_eq!(client.block_count().unwrap(), 1_170_000);
        assert!(!client.transport().missed());
    }

    /// One round can reach the same unknown by two paths. Asking the network
    /// for it twice would be waste, and a driver that deduplicated afterwards
    /// would be doing this crate's job.
    #[test]
    fn the_same_miss_is_recorded_once() {
        let client = RpcClient::new(Cassette::new());
        let _ = client.block_count();
        let _ = client.block_count();
        assert_eq!(client.transport().outstanding().len(), 1);
    }

    /// A broadcast is refused outright, and with an error that cannot be
    /// mistaken for "go and fetch this".
    ///
    /// `RpcClient` is a `Broadcaster` over every transport, this one included,
    /// so nothing in the types stops a broadcasting flow from being driven.
    /// This is what stops it instead — and it matters most for an operation
    /// whose bytes differ between rounds, where a driver treating the recorded
    /// body as a miss would send a *different* transaction each time.
    #[test]
    fn a_broadcast_is_refused_and_never_recorded() {
        use crate::Broadcaster;

        let client = RpcClient::new(Cassette::new());
        let outcome = client.send_raw_transaction("00");

        assert!(matches!(outcome, Err(RpcError::WriteThroughCassette)));
        assert!(
            !client.transport().missed(),
            "a write must not be recorded as something to go and fetch"
        );
    }

    /// A miss must not be mistaken for the node answering. Anything that reads
    /// a failure as information — "no such identity, so the name is free" —
    /// would act on an answer that does not exist yet.
    #[test]
    fn a_miss_is_distinguishable_from_a_node_error() {
        let client = RpcClient::new(Cassette::new());
        assert!(matches!(client.block_count(), Err(RpcError::AnswerNeeded)));
    }
}
