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
//! * [`convert`](mod@convert) — turn one currency into another, or burn one.
//! * [`login`] — sign in with a VerusID, verified against the identity as it
//!   stood when the signature was made.
//! * [`identity`] — the VerusID lifecycle. Registration is two transactions with
//!   a wait in between, and its API is shaped around the fact that the salt
//!   joining them cannot be recovered from the chain.
//! * [`funding`] — which coins can actually be spent right now, which is not the
//!   same as which coins exist.
//! * [`history`](mod@history) — what already happened, which a UTXO set cannot
//!   tell you: an output that arrived and was spent is simply gone from it.
//! * [`vdxf`](mod@vdxf) — keeping application data on a VerusID, and the care an
//!   update needs given that it republishes the identity in full.
//! * [`broadcast`](mod@broadcast) — and the one failure that must never be retried
//!   automatically.
//!
//! # Shielded, behind a feature
//!
//! [`shielded`](mod@shielded) finds, values and witnesses Sapling notes through
//! a lightwalletd server. It is off by default because it pulls the Sapling
//! stack, which is a far heavier tree than the transparent path needs.
//!
//! The blocker was never the builders — `verus-sapling` has done t→z, z→z, z→t
//! and multi-note spends, proven on chain, since PR #9. It was the data: a
//! witness needs every commitment added before its note, a commitment tree
//! cannot be walked backwards, and public Verus RPC will not serve
//! `z_gettreestate`. `verus-light` closes that, and this module joins the two.
//!
//! Spending is behind a second feature, `prover`, because building the
//! transaction costs Groth16 and ~50 MB of Sapling parameters that a
//! balance-only wallet has no use for. With it,
//! [`shielded::spend`](fn@shielded::spend) is the whole path: select notes,
//! witness them to a shared anchor, **check that anchor against the block
//! header's `finalsaplingroot`**, prove, and hand over the bytes. That check is
//! the reason the spend path takes a [`ChainReader`] as well as a light client
//! — every input to a witness comes from the light server, so agreeing with
//! itself proves nothing.
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

pub mod balances;
pub mod broadcast;
pub mod convert;
pub mod drive;
pub mod error;
pub mod funding;
pub mod history;
pub mod identity;
pub mod launch;
pub mod login;
pub mod offer;
pub mod send;
pub mod vdxf;

#[cfg(feature = "shielded")]
pub mod shielded;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use balances::{currency_names, native_currency};
pub use broadcast::{broadcast, Unsent};
pub use convert::{
    burn, convert, estimate, mint, plan_conversion, prepare_burn, prepare_conversion, prepare_mint,
    ConversionPlan,
};
pub use error::FlowError;
pub use funding::{identity_held, spendable, Funding};
pub use history::{history, HistoryEntry};
pub use identity::{
    prepare_registration, prepare_registration_with_salt, AwaitingCommitment, CommitmentStatus,
    Pending, ReadyToRegister, Registered, RegistrationOptions, WaitPolicy,
};
pub use launch::{launch_currency, prepare_launch, Launched};
pub use login::{sign_login, verify_login, LoggedIn, LoginPolicy, LoginRequest};
pub use offer::{browse, inspect, prepare_take, take, Demand, Listing, OfferTerms, Taken, Taking};
pub use send::{
    prepare_send, prepare_send_from_identity, prepare_send_token, send, send_from_identity,
    send_token, Sent,
};
pub use vdxf::{
    key_address, prepare_publish, publish, read, read_all, read_history, Namespace, Published,
};

#[cfg(feature = "shielded")]
pub use shielded::{
    check_anchor, full_output, plan_spend, scan, select_notes, witness_note, ScanResult, SpendPlan,
    WitnessedNote,
};

#[cfg(feature = "prover")]
pub use shielded::{
    prepare_spend, prove_spend, spend, ShieldedRecipient, ShieldedSpent, SpendRequest,
    TransparentRecipient,
};

// The whole stack, so a consumer takes one dependency rather than three.
#[cfg(feature = "http")]
pub use verus_rpc::HttpTransport;
pub use verus_rpc::{Broadcaster, ChainReader, RpcClient, RpcError};
pub use verus_tx::{token_balances, Amount, CurrencyId, Expiry, TokenBalances, TxError};
