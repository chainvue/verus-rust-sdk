//! What can go wrong in an operation that spans a network and a signer.

use thiserror::Error;
use verus_tx::Amount;

/// A failure somewhere in lookup, build, sign or broadcast.
#[derive(Debug, Error)]
/// `#[non_exhaustive]` for the same reason [`verus_tx::TxError`] is: a new
/// refusal is a normal outcome of learning what a node or the chain rejects.
#[non_exhaustive]
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

    /// An offer could not be read, or does not describe what it claims.
    #[error("offer: {0}")]
    Offer(String),

    /// Data published on an identity could not be read, or the identity an
    /// update was about to be written to is not the one that was asked for.
    #[error("identity content: {0}")]
    Content(String),

    /// A shielded lookup could not be trusted to position or witness a note.
    ///
    /// Almost every case here is a *continuity* failure — a reorg under a scan,
    /// a chunk that does not chain to the last, a tree size that disagrees with
    /// the frontier. None of them would fail loudly on their own: they shift
    /// note positions, and a note witnessed at the wrong position produces a
    /// proof the daemon rejects only after ~20 seconds of proving.
    #[cfg(feature = "shielded")]
    #[error("shielded lookup failed: {0}")]
    Shielded(String),

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

    /// A node-reported fee too large to trust by default.
    ///
    /// H4: `operation`'s fee is BURNED — no output exists to recover it from —
    /// and by default it is read straight from whatever the node answers
    /// (`idregistrationfees` / `currencyregistrationfee`), which is exactly the
    /// value a hostile or misconfigured node controls outright.
    /// `verus_tx::fee::MAX_DECLARED_BURN` alone does not catch this: it exists
    /// to catch a typo in a fee the *caller* already decided on, not to doubt a
    /// number nobody here chose. A node reporting 999 against a real 100-coin
    /// registration fee sails through it with three orders of magnitude to
    /// spare, and exact conservation would certify the resulting transaction
    /// as happily as a correct one.
    #[error(
        "{operation} fee of {reported} exceeds the {ceiling} sanity bar for a fee read from the \
         node; if this is genuinely the current chain policy, pin it explicitly instead of \
         trusting the node's answer"
    )]
    ImplausibleNodeFee {
        /// What the fee was for — `"identity registration"` or `"currency
        /// launch"`.
        operation: &'static str,
        /// What the node reported.
        reported: Amount,
        /// The bar it exceeded — see `verus_tx::fee::MAX_TRUSTED_NODE_FEE`.
        ceiling: Amount,
    },

    /// The node reported more referral levels than this crate will act on.
    ///
    /// Refused at *prepare*, before the commitment is broadcast. The same
    /// value would otherwise be refused deep in the fee split at step two —
    /// after the commitment fee has been spent, which is precisely the
    /// fail-after-paying shape the two-step flow exists to prevent.
    #[error(
        "the node reports {reported} referral levels for this currency, above the \
         {ceiling} this crate will act on; nothing has been broadcast"
    )]
    ImplausibleReferralLevels {
        /// What the node reported.
        reported: u32,
        /// The bar it exceeded — `verus_tx::register::MAX_REFERRAL_LEVELS`.
        ceiling: u32,
    },

    /// A referral was requested for a currency that pays none.
    ///
    /// Also refused at prepare. Left to step two it surfaces as
    /// `ReferralChainTooLong`, which describes the arithmetic rather than the
    /// cause and arrives after the commitment is spent.
    #[error("this currency pays no referrals, so {referrer} cannot be credited")]
    CurrencyPaysNoReferrals {
        /// The referrer that was asked for.
        referrer: String,
    },
}
