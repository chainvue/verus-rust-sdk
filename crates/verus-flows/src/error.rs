//! What can go wrong in an operation that spans a network and a signer.

use thiserror::Error;
use verus_tx::Amount;

/// A failure somewhere in lookup, build, sign or broadcast.
#[derive(Debug, Error)]
pub enum FlowError {
    /// The node could not be reached, or its answer could not be used.
    #[error(transparent)]
    Rpc(#[from] verus_rpc::RpcError),

    /// The transaction could not be built or signed.
    #[error(transparent)]
    Tx(#[from] verus_tx::TxError),

    /// An address could not be parsed.
    #[error(transparent)]
    Key(#[from] verus_keys::KeyError),

    /// There is not enough spendable value at the funding address.
    ///
    /// `available` counts only what can actually be spent *now*: an immature
    /// coinbase is excluded, so this can fire while a balance lookup shows
    /// plenty. That difference is the point — the alternative is a transaction
    /// that builds, signs and is rejected.
    #[error(
        "need {needed} but only {available} is spendable at {address} ({utxos} usable outputs)"
    )]
    InsufficientFunds {
        /// What the operation costs, fee included where it is known.
        needed: Amount,
        /// What is spendable at this moment.
        available: Amount,
        /// The address that was funded from.
        address: String,
        /// How many outputs were usable.
        utxos: usize,
    },

    /// The broadcast may or may not have happened.
    ///
    /// A transport failure on `sendrawtransaction` is **ambiguous**: the node
    /// may have accepted and relayed the transaction before the connection
    /// broke. Resending blindly risks a second broadcast of something already
    /// propagating, so this hands back everything needed to find out and decide.
    ///
    /// Re-read with [`verus_rpc::ChainReader::confirmations`]. If the node has
    /// never seen it, broadcasting `hex` again is safe.
    #[error("broadcast outcome unknown for {txid}: {reason} — check before resending")]
    BroadcastUncertain {
        /// The transaction id, computed locally before sending.
        txid: String,
        /// The signed bytes, so a resend needs no rebuild.
        hex: String,
        /// What went wrong.
        reason: String,
    },

    /// The chain moved under a pending operation.
    ///
    /// Anything built against the old state has to be re-checked: an output it
    /// meant to spend may no longer exist.
    #[error("the chain reorganised: {0}")]
    Reorged(String),

    /// An identity the operation needs is not on chain.
    #[error("no identity named {0}")]
    NoSuchIdentity(String),

    /// The name is already registered.
    ///
    /// Checked before a commitment is paid for, since discovering it afterwards
    /// costs the commitment fee.
    #[error("{0} is already registered")]
    NameTaken(String),

    /// A step was attempted against state that does not support it.
    #[error("{0}")]
    NotReady(String),
}
