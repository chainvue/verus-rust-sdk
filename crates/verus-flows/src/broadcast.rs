//! Handing over finished bytes, and the one failure that must not be retried.
//!
//! # Why there is no retry here
//!
//! A transport failure on `sendrawtransaction` is **ambiguous**. The request may
//! never have arrived; it may have arrived, been accepted, and been relayed to
//! the whole network before the connection dropped. From inside this process the
//! two are indistinguishable.
//!
//! A retry loop resolves that ambiguity by guessing. If the first attempt landed
//! then the second is a duplicate broadcast — usually harmless, because the
//! transaction is identical and a node rejects it as already known, but "usually"
//! is doing a lot of work in a sentence about money. Worse, an automatic retry
//! buries the event: the caller never learns the outcome was ever in doubt.
//!
//! So an ambiguous failure surfaces as [`FlowError::BroadcastUncertain`],
//! carrying the txid and the signed bytes. Resolving it takes one read:
//!
//! ```no_run
//! # use verus_flows::FlowError;
//! # use verus_rpc::{ChainReader, Broadcaster};
//! # fn example(reader: &impl ChainReader, broadcaster: &impl Broadcaster, e: FlowError)
//! #     -> Result<(), Box<dyn std::error::Error>> {
//! if let FlowError::BroadcastUncertain { txid, hex, .. } = e {
//!     match reader.confirmations(&txid)? {
//!         // The node has it. Nothing to do.
//!         Some(_) => {}
//!         // It never arrived. Sending the same bytes again is safe.
//!         None => { broadcaster.send_raw_transaction(&hex)?; }
//!     }
//! }
//! # Ok(()) }
//! ```
//!
//! A rejection is different and is *not* ambiguous: the node understood the
//! transaction and refused it. That comes back as the daemon's own error, and
//! resending unchanged will fail identically.

use verus_rpc::{Broadcaster, RpcError};

use crate::error::FlowError;

/// Signed bytes that have not been sent, and what sending them will mean.
///
/// Every operation here that writes to the chain is split in two: a
/// `prepare_…` half that only **reads** and returns one of these, and a thin
/// wrapper that hands it to a node. The split is not a stylistic preference.
///
/// # Why the halves are separate types and not a flag
///
/// An operation driven by [`drive`](mod@crate::drive) runs **again from the
/// beginning on every round** — that is the whole mechanism by which a browser
/// gets synchronous-looking flows without an async duplicate of each one. Reads
/// are answered from a cache and cost nothing the second time. A broadcast has
/// no such property: running it twice sends twice, and with anything
/// non-deterministic in the operation it sends *different bytes* twice.
///
/// So the re-runnable half takes no [`Broadcaster`] and therefore cannot
/// broadcast — a signature, not a promise — and the send happens once, outside
/// the loop, through [`Unsent::broadcast`].
///
/// # The fields
///
/// `hex` and `txid` are the bytes and their locally computed id. Where
/// `outcome` also carries them (as [`Sent`](crate::Sent) does) they are the
/// same values: the id is computed from the bytes, and
/// [`broadcast`] refuses a node that answers about a different transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unsent<T> {
    /// The signed transaction, hex-encoded, ready to submit.
    pub hex: String,
    /// The transaction id computed locally from `hex`.
    pub txid: String,
    /// What the operation will have done once these bytes are accepted.
    pub outcome: T,
}

impl<T> Unsent<T> {
    /// Submit the bytes, once, and yield what the operation set out to do.
    ///
    /// **The outcome is consumed on failure.** For most flows that costs
    /// nothing — the whole operation can simply be built again from the chain.
    /// It is not true of
    /// [`Pending`](crate::Pending): the salt inside it cannot be recovered from
    /// anywhere, so a caller sending a name commitment should persist or clone
    /// the `Unsent` first. `Unsent<T>` is [`Clone`] whenever `T` is.
    ///
    /// # Errors
    ///
    /// Whatever [`broadcast`] reports — in particular
    /// [`FlowError::BroadcastUncertain`], which carries `hex` and `txid` back
    /// so the outcome can be resolved with a single read rather than a resend.
    pub fn broadcast(self, broadcaster: &impl Broadcaster) -> Result<T, FlowError> {
        broadcast(broadcaster, &self.hex, &self.txid)?;
        Ok(self.outcome)
    }
}

/// Submit signed bytes, distinguishing a refusal from an unknown outcome.
///
/// `local_txid` is the id computed while building. It is compared against what
/// the node reports: a mismatch means the node is talking about a different
/// transaction, and continuing would hand the caller a txid that tracks
/// something else.
pub fn broadcast(
    broadcaster: &impl Broadcaster,
    hex: &str,
    local_txid: &str,
) -> Result<String, FlowError> {
    match broadcaster.send_raw_transaction(hex) {
        Ok(txid) => {
            if txid != local_txid {
                return Err(FlowError::NotReady(format!(
                    "node reported txid {txid} for a transaction we computed as {local_txid}"
                )));
            }
            Ok(txid)
        }
        // The node answered. It understood the transaction and said no, so the
        // outcome is known and resending unchanged will not help.
        Err(error @ RpcError::Node { .. }) => Err(FlowError::Rpc(error)),
        // Nothing was sent and nothing could have been: both of these come from
        // a cassette, which has no node behind it at all.
        //
        // Calling either "uncertain" would be worse than merely imprecise. The
        // documented way to resolve an uncertain broadcast is to check for the
        // transaction and, finding it absent, **send it** — so a caller who
        // drove an unsplit flow by mistake would follow the recovery path
        // straight into the broadcast the cassette exists to prevent.
        //
        // `AnswerNeeded` is not reachable here today, because a cassette
        // refuses a write before it ever looks the request up. It is matched
        // anyway: the catch-all below is the dangerous classification, and a
        // future write method that slipped past `RequestBody::writes` would
        // land in it silently.
        Err(error @ (RpcError::WriteThroughCassette | RpcError::AnswerNeeded)) => {
            Err(FlowError::Rpc(error))
        }
        // `-32601` is the node **answering**: it will not serve
        // `sendrawtransaction`, usually because it is a filtering proxy. The
        // transaction was not relayed and the outcome is not in doubt — so it
        // is not uncertainty, it is "find a node that will take this".
        Err(error @ RpcError::MethodUnavailable { .. }) => Err(FlowError::Rpc(error)),
        // Everything else — a dropped connection, a timeout, a proxy's HTML —
        // leaves the outcome genuinely unknown.
        Err(error) => Err(FlowError::BroadcastUncertain {
            txid: local_txid.to_string(),
            hex: hex.to_string(),
            reason: error.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::ScriptedReader;

    const TXID: &str = "abababababababababababababababababababababababababababababababab";
    /// The real txid of the bytes `00ff` — SHA256d, printed in reverse. The
    /// scripted node computes this the way a daemon would, so the agreement
    /// check below is exercised rather than assumed.
    const TXID_OF_00FF: &str = "23888744a048bba7861ac543035224b8852673795c7e5e27e10167c4e76be163";

    #[test]
    fn a_successful_broadcast_returns_the_txid() {
        let node = ScriptedReader::new(1_000);
        assert_eq!(
            broadcast(&node, "00ff", TXID_OF_00FF).unwrap(),
            TXID_OF_00FF
        );
        assert_eq!(node.broadcasts(), vec!["00ff".to_string()]);
    }

    /// A refusal is a known outcome. It must not be dressed up as uncertainty,
    /// or a caller will poll for a transaction that was never accepted.
    #[test]
    fn a_rejection_is_reported_as_a_rejection() {
        let node = ScriptedReader::new(1_000).failing_broadcast(RpcError::Node {
            code: -26,
            message: "16: bad-txns-inputs-missingorspent".into(),
        });
        match broadcast(&node, "00ff", TXID) {
            Err(FlowError::Rpc(RpcError::Node { code, .. })) => assert_eq!(code, -26),
            other => panic!("expected a node error, got {other:?}"),
        }
    }

    /// The case the module exists for: the node may have it, and the caller has
    /// to be given enough to find out rather than a silent retry.
    #[test]
    fn a_transport_failure_is_uncertain_and_carries_what_a_resend_needs() {
        let node = ScriptedReader::new(1_000)
            .failing_broadcast(RpcError::Transport("connection reset".into()));
        match broadcast(&node, "00ff", TXID) {
            Err(FlowError::BroadcastUncertain { txid, hex, reason }) => {
                assert_eq!(txid, TXID);
                assert_eq!(hex, "00ff");
                assert!(reason.contains("connection reset"));
            }
            other => panic!("expected BroadcastUncertain, got {other:?}"),
        }
        // And nothing was resent behind the caller's back.
        assert!(node.broadcasts().is_empty());
    }

    /// A cassette's refusal must not be dressed up as uncertainty.
    ///
    /// The recovery path for [`FlowError::BroadcastUncertain`] is documented as
    /// "check, and if it is not there, send it". Reporting a refusal that way
    /// would walk a caller into performing the very broadcast the cassette
    /// refused — and this is reachable, because `RpcClient<Cassette>` is a
    /// `Broadcaster` like any other client.
    #[test]
    fn a_cassette_refusing_a_write_is_certain_not_uncertain() {
        let node = ScriptedReader::new(1_000).failing_broadcast(RpcError::WriteThroughCassette);
        match broadcast(&node, "00ff", TXID) {
            Err(FlowError::Rpc(RpcError::WriteThroughCassette)) => {}
            other => panic!("a refusal is a known outcome, got {other:?}"),
        }
    }

    /// The same, for the other error only a cassette produces. Unreachable
    /// today; pinned so that it stays a certainty if it ever becomes reachable.
    #[test]
    fn an_unanswered_request_is_certain_too() {
        let node = ScriptedReader::new(1_000).failing_broadcast(RpcError::AnswerNeeded);
        match broadcast(&node, "00ff", TXID) {
            Err(FlowError::Rpc(RpcError::AnswerNeeded)) => {}
            other => panic!("nothing was sent, so nothing is uncertain: {other:?}"),
        }
    }

    /// A node that refuses to serve `sendrawtransaction` has **answered**.
    ///
    /// Public Verus infrastructure is full of filtering proxies, so this is a
    /// common reply — and the remedy is another endpoint, not the check-and-
    /// resend dance an uncertain outcome calls for. Nothing was relayed.
    #[test]
    fn a_node_that_will_not_relay_is_a_known_outcome() {
        let node = ScriptedReader::new(1_000).failing_broadcast(RpcError::MethodUnavailable {
            method: "sendrawtransaction",
        });
        match broadcast(&node, "00ff", TXID) {
            Err(FlowError::Rpc(RpcError::MethodUnavailable { .. })) => {}
            other => panic!("nothing was sent, so nothing is uncertain: {other:?}"),
        }
    }

    /// If the node names a different transaction, the txid handed back would
    /// track the wrong thing for the rest of the operation.
    #[test]
    fn a_txid_the_node_disagrees_about_is_refused() {
        let node = ScriptedReader::new(1_000);
        match broadcast(&node, "00ff", &"cd".repeat(32)) {
            Err(FlowError::NotReady(message)) => assert!(message.contains("node reported")),
            other => panic!("expected a mismatch to be caught, got {other:?}"),
        }
    }
}
