//! Reading chain state and broadcasting signed bytes — and nothing else.
//!
//! The rest of this workspace never opens a socket. This crate is where the
//! network lives, kept separate so that a hardware signer, an air-gapped host or
//! a wasm build can depend on the builders without pulling in an HTTP stack.
//!
//! # What this client will not do
//!
//! A Verus daemon exposes two very different kinds of method. There are the ones
//! that answer questions about the chain, and there are the ones that **make the
//! node act as a wallet** — `sendcurrency`, `z_sendmany`, `registeridentity`,
//! `signrawtransaction`, `dumpprivkey`. The second kind requires the node to
//! hold, or be handed, a private key.
//!
//! None of those exist here, and there is deliberately **no generic
//! `call(method, params)`**. The only reachable methods are the typed ones
//! below: questions, plus [`RpcClient::send_raw_transaction`] for bytes that
//! were already signed locally. A caller cannot reach a wallet method through
//! this type, so "the node never sees a key" is a property of the API rather
//! than a convention someone drifts away from later.
//!
//! Adding a method means adding a typed one, which is a diff a reviewer can see.
//!
//! # A node is untrusted infrastructure
//!
//! Everything here is somebody else's answer to a question. What that somebody
//! can and cannot do:
//!
//! * **Cannot** take funds. Signing happens in `verus-tx` and `verus-sapling`,
//!   from keys that never leave the caller.
//! * **Can** omit UTXOs, and you simply fail to spend. Only asking a second node
//!   detects it.
//! * **Can** misreport a value or script — but the sighash commits to both, so
//!   the transaction is rejected rather than misdirected.
//! * **Can** misreport chain policy, and this one has teeth: a wrong
//!   `idregistrationfees` is discovered *after* a name commitment has been
//!   spent. Cross-check it against a second source before a registration.
//! * **Can** misreport a Sapling frontier, costing a proof. Compare the anchor
//!   against the block header's `finalsaplingroot` first — `verus-sapling`
//!   exposes that check without the prover for exactly this reason.
//! * **Sees every address you ask about.** That is the real price of a public
//!   node, and no amount of care in this crate changes it.
//!
//! # `-32601` does not reliably mean "missing"
//!
//! A public endpoint is usually a filtering proxy, and the filter can be
//! sensitive to the *number of arguments*, not just the method name.
//! `api.verustest.net` serves `getblock` with one argument and answers
//! `-32601` — "method not found" — for the same method with a verbosity
//! argument.
//!
//! So [`RpcError::MethodUnavailable`] means "refused as not-found", which is
//! weaker than "this node cannot do that". Before recording a method as
//! unavailable, re-probe it at a different arity; an availability table built
//! from careless probes will be wrong. That is not hypothetical — the table this
//! crate was designed against had `getblock` listed as absent, and it is not.

#![doc(html_no_source)]

mod cassette;
mod client;
mod envelope;
mod error;
mod json;
mod method;
mod transport;
mod types;

pub use cassette::Cassette;
pub use client::{content_multimap, registration_cost, Broadcaster, ChainReader, RpcClient};
pub use error::RpcError;
pub use method::{callable_methods, CallableMethod};
#[cfg(feature = "http")]
pub use transport::HttpTransport;
pub use transport::{RequestBody, Transport};
pub use types::{
    spendable_at, AddressBalance, AddressDelta, AddressUtxo, ChainInfo, ContentValue,
    ConversionEstimate, CurrencyConverter, CurrencyPolicy, CurrencySummary, IdentityContent,
    IdentityRecord, OfferListing, OfferSide, SignedAmount, COINBASE_MATURITY,
};
