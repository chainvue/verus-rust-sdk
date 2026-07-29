//! Read Sapling chain data from a lightwalletd server.
//!
//! `verus-sapling` can detect notes, build witnesses, prove and sign spends —
//! all of it offline, all of it proven on chain. What it cannot do is *find* the
//! data those operations consume. A note's witness depends on every commitment
//! added to the tree before it, and a commitment tree cannot be walked
//! backwards, so a signer must be told the frontier by something that watched
//! the chain. Public Verus RPC will not serve `z_gettreestate`, and
//! reconstructing a frontier from raw blocks means fetching every transaction in
//! every block since Sapling activation.
//!
//! That gap is what lightwalletd exists to close, and this crate is the client
//! for it.
//!
//! ```text
//! tree_state(h - 1)   ─┐
//! block_range(h, tip) ─┴─→ verus_sapling::scan / witness / build → signed bytes
//! ```
//!
//! # What it does not do
//!
//! No keys, ever. `CompactTxStreamer` has no method that could carry one, and
//! [`callable_methods`] enumerates the entire surface this crate can emit —
//! six methods, exactly one of which ([`LightClient::send_transaction`]) hands
//! the network anything.
//!
//! Trial decryption happens in `verus-sapling`, on your machine, over compact
//! outputs this crate fetched. The server learns which block ranges you asked
//! for and nothing about which notes were yours.
//!
//! # Transport
//!
//! grpc-web over HTTP/1.1, not native gRPC — no HTTP/2 stack, no async runtime,
//! and the same framing a browser is obliged to use, so one transport serves
//! both a server-side caller and a wasm build. See [`transport`] for the cost of
//! that choice.
//!
//! # Example
//!
//! ```no_run
//! use verus_light::{GrpcWebTransport, LightClient};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let client = LightClient::new(GrpcWebTransport::new("http://127.0.0.1:8080")?);
//!
//! let info = client.server_info()?;
//! assert_eq!(info.consensus_branch_id, "76b809bb");
//!
//! let tip = client.latest_block()?;
//! let frontier = client.tree_state(tip.height - 1)?;
//! let blocks = client.block_range(tip.height, tip.height)?;
//!
//! println!("{} commitments in block {}", blocks[0].commitments().len(), tip.height);
//! # Ok(())
//! # }
//! ```

#![doc(html_no_source)]

mod client;
mod error;
pub mod grpc;
mod messages;
mod method;
pub mod transport;

mod proto;

pub use client::{LightClient, MAX_BLOCK_RANGE};
pub use error::LightError;
pub use grpc::GrpcStatus;
pub use messages::{
    BlockId, CompactBlock, CompactSaplingOutput, CompactTx, RawTransaction, SendResponse,
    ServerInfo, TreeState, COMPACT_NOTE_SIZE,
};
pub use method::{callable_methods, CallableMethod};
pub use transport::{HttpResponse, LightTransport};

#[cfg(feature = "grpc-web")]
pub use transport::GrpcWebTransport;
