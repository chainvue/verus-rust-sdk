//! Operations a wallet can call, composed from lookup, the offline builders and
//! broadcast.
//!
//! The rest of this workspace is deliberately unhelpful: `verus-tx` will sign
//! anything you hand it and knows nothing about where coins come from, and
//! `verus-rpc` will answer questions and relay bytes but never builds either.
//! This crate is the join — `send(&reader, &broadcaster, &key, to, amount)` and
//! the identity lifecycle, with UTXO lookup, fee policy, expiry and change
//! handled.
//!
//! # The key never leaves this process
//!
//! Every transaction is built and signed locally. The node is asked questions
//! and given finished bytes. There is no `sendcurrency`, no `registeridentity`,
//! and nothing that would require a daemon to hold or be told a private key —
//! see [the `verus-rpc` docs](verus_rpc) for how that is enforced rather than
//! merely intended.
//!
//! # What is here
//!
//! * [`send()`] and [`send_token()`] — pay someone.
//! * [`login`] — sign in with a VerusID, verified against the identity as it
//!   stood when the signature was made.
//! * [`identity`] — the VerusID lifecycle. Registration is two transactions with
//!   a wait in between, and its API is shaped around the fact that the salt
//!   joining them cannot be recovered from the chain.
//! * [`funding`] — which coins can actually be spent right now, which is not the
//!   same as which coins exist.
//! * [`broadcast`](mod@broadcast) — and the one failure that must never be retried
//!   automatically.
//!
//! # What is not here
//!
//! **Shielded.** Not for want of builders — `verus-sapling` does t→z, z→z, z→t
//! and multi-note spends, all proven on chain. Building a note witness needs
//! every Sapling commitment in the note's block *and* the tree frontier before
//! it. The commitments are reachable through a public node (`getblock`, then
//! `getrawtransaction` per transaction); the historical frontier is not, since
//! `z_gettreestate` is absent and `getsaplingtree` only ever answers for the
//! tip. Folding one up from genesis is possible and slow, which is the problem
//! lightwalletd exists to solve. So shielded flows wait for that client rather
//! than for more builder work.
//!
//! # A node is untrusted infrastructure
//!
//! Restating what [`verus_rpc`] says, because these functions act on the
//! answers:
//!
//! * A node that **hides UTXOs** makes a payment fail, not misdirect.
//! * A node that **misreports a value or script** produces a transaction that is
//!   rejected — the sighash commits to both.
//! * A node that **misreports chain policy** is the one with teeth. A wrong
//!   `idregistrationfees` is discovered *after* a name commitment has been
//!   spent, so [`identity::Pending`] records the fee it read and
//!   [`identity::RegistrationOptions::pin_fee`] lets a caller override it.
//! * A node **sees every address you ask about**. Nothing here changes that.

#![doc(html_no_source)]

pub mod broadcast;
pub mod error;
pub mod funding;
pub mod identity;
pub mod login;
pub mod send;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use broadcast::broadcast;
pub use error::FlowError;
pub use funding::{spendable, Funding};
pub use identity::{
    prepare_registration, prepare_registration_with_salt, AwaitingCommitment, CommitmentStatus,
    Pending, ReadyToRegister, Registered, RegistrationOptions, WaitPolicy,
};
pub use login::{sign_login, verify_login, LoggedIn, LoginPolicy, LoginRequest};
pub use send::{prepare_send, send, send_token, Sent};

// The whole stack, so a consumer takes one dependency rather than three.
#[cfg(feature = "http")]
pub use verus_rpc::HttpTransport;
pub use verus_rpc::{Broadcaster, ChainReader, RpcClient, RpcError};
pub use verus_tx::{Amount, CurrencyId, Expiry, TxError};
