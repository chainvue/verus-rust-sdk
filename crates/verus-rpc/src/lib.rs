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
//!   spent. Cross-check it against a second source before a registration —
//!   [`SecondSourced`] is that check, and returns
//!   [`RpcError::SourcesDisagree`] before anything is paid for.
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
//! It is not one method's quirk, and it does not point one way. Measured
//! against the same endpoint on 2026-08-03:
//!
//! ```text
//! getblock      [1166308]    -> served        getrawmempool []       -> served
//! getblock      [1166308,1]  -> -32601        getrawmempool [false]  -> -32601
//! ```
//!
//! One method wants an argument, the other refuses one, and a client that
//! guessed either rule would be wrong about the other.
//!
//! So this crate does not guess. A method with a second argument list that asks
//! the *same question* is tried both ways before anything is concluded, and
//! [`RpcError::MethodUnavailable`] therefore means **"refused at every arity
//! this crate knows how to ask"** rather than "refused once". The preferred
//! form still goes first and a served call still costs exactly one request; the
//! second is sent only after a refusal.
//!
//! Anything that is not `-32601` stops there. A node error is an answer, and
//! re-asking would turn one failure into two requests.
//!
//! "Same question" is the load-bearing word. `getblock <h>` and
//! `getblock <h> 1` qualify — verbosity 1 is the daemon's default, and the two
//! were measured byte-identical against a VRSCTEST daemon on 2026-08-03.
//! `getblock <h> 0` does not: it answers with the block as hex. Listing an
//! arity that asks something else would hand a caller a shape it does not
//! parse, and only on the nodes where the preferred arity happens to be
//! filtered — the hardest possible place to notice it.
//!
//! That is not hypothetical — the availability table this crate was designed
//! against had `getblock` listed as absent, and it is not.

#![doc(html_no_source)]

mod cassette;
mod client;
mod envelope;
mod error;
mod json;
mod method;
pub mod second_source;
mod transport;
mod types;

pub use cassette::Cassette;
pub use client::{content_multimap, registration_cost, Broadcaster, ChainReader, RpcClient};
pub use error::RpcError;
pub use method::{callable_methods, CallableMethod};
pub use second_source::SecondSourced;
#[cfg(feature = "http")]
pub use transport::HttpTransport;
pub use transport::{RequestBody, Transport};
pub use types::{
    spendable_at, AddressBalance, AddressDelta, AddressUtxo, ChainInfo, ContentValue,
    ConversionEstimate, CurrencyConverter, CurrencyPolicy, CurrencySummary, IdentityAtAddress,
    IdentityContent, IdentityRecord, MempoolDelta, OfferListing, OfferSide, SignedAmount,
    COINBASE_MATURITY,
};
