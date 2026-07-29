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

#![doc(html_no_source)]

mod client;
mod error;
mod transport;
mod types;

pub use client::RpcClient;
pub use error::RpcError;
pub use transport::Transport;
#[cfg(feature = "http")]
pub use transport::HttpTransport;
pub use types::{AddressUtxo, ChainInfo, CurrencyPolicy, IdentityRecord, TreeState};
