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
