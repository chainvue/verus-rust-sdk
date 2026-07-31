//! Verus for JavaScript: build and sign in WebAssembly, on the same bytes the
//! rest of this workspace proved on chain.
//!
//! This crate is a *binding*, not a second implementation. Every transaction it
//! produces comes out of `verus-tx` unchanged, so the txids in
//! [`PROVEN.md`](https://github.com/chainvue/verus-rust-sdk/blob/main/PROVEN.md)
//! — sends, the whole VerusID lifecycle, tokens, conversions, offers, currency
//! launches — are evidence about what a browser gets, not merely about what a
//! Rust caller gets. A test in [`send`] pins that by comparing the binding's
//! output against the builder's, byte for byte.
//!
//! # What it does, and what it deliberately does not
//!
//! It builds and signs. It does not fetch, and it does not broadcast.
//!
//! That is not an omission waiting to be filled. `verus-rpc` and `verus-flows`
//! are built on a **synchronous** transport, and a browser has no synchronous
//! `fetch` — binding them would mean either an async duplicate of every flow or
//! a blocking call the main thread cannot make. Meanwhile the thing they would
//! wrap, JSON-RPC over HTTP, is a few lines of JavaScript an application
//! already knows how to write, with its own retries, its own auth and its own
//! node choice. So the split is: **JavaScript asks the questions, WebAssembly
//! holds the key and makes the bytes.**
//!
//! ```js
//! import init, { Key, parseCoins } from "@chainvue/verus-wasm";
//! await init();
//!
//! const key   = Key.fromWif(wif);
//! const utxos = await rpc("getaddressutxos", [{ addresses: [key.address()] }]);
//! const tip   = await rpc("getblockcount", []);
//!
//! const signed = key.send({
//!   utxos: utxos.map(u => ({
//!     txid: u.txid, vout: u.outputIndex,
//!     satoshis: String(u.satoshis), scriptPubKey: u.script,
//!   })),
//!   recipients: [{ address: to, satoshis: parseCoins("1.5") }],
//!   changeAddress: key.address(),
//!   expiryHeight: tip + 20,
//! });
//!
//! await rpc("sendrawtransaction", [signed.hex]);
//! key.free();
//! ```
//!
//! # Conventions across the whole API
//!
//! * **Money is a decimal string, never a `number`.** JavaScript's `number` is
//!   a float64 and rounds silently; a satoshi count can exceed what it holds
//!   exactly. Passing `satoshis: 1e8` throws. Convert with [`money::parse_coins`]
//!   and [`money::format_coins`], or hand a `bigint` its `.toString()`.
//! * **Hashes and scripts are hex strings**, spelled the way the daemon's JSON
//!   spells them — a txid in display order, a script as raw hex.
//! * **Errors are thrown `Error`s whose `.name` is the failure**, so
//!   `catch (e) { if (e.name === "InsufficientFunds") … }` works. See [`error`].
//!   Passing a `number` where a string belongs throws too, rather than
//!   trapping the module — which a release `wasm-bindgen` build does not do on
//!   its own.
//! * **Unknown fields are refused**, so a mistyped optional field fails instead
//!   of being ignored — and the optional fields here choose between materially
//!   different transactions. This is enforced by rebuilding each request
//!   object rather than by `serde`, which cannot see the difference; see
//!   [`dto::from_js`] for what that costs and why the cheaper version was
//!   unsound.
//! * **Requests must be plain objects.** A class instance or an object with a
//!   custom prototype is refused, and a polluted `Object.prototype` is refused
//!   rather than silently read. Ordinary framework proxies — Vue's
//!   `reactive()`, MobX — work unchanged.
//!
//! # Trust
//!
//! The key stays in the module's memory and is used through method calls; see
//! [`keys`] for what that does and does not buy. It is not a defence against a
//! compromised page: anything that can run script in the same realm can call
//! the same methods and read the same memory.

#![doc(html_no_source)]

use serde::Serialize;
use wasm_bindgen::prelude::*;

pub mod decode;
pub mod dto;
pub mod error;
pub mod keys;
pub mod login;
pub mod mnemonic;
pub mod money;
pub mod send;
pub mod types;
pub mod vdxf;

pub use error::WasmError;
pub use keys::Key;

/// Serialize a response for JavaScript.
///
/// `json_compatible` matters: without it `serde-wasm-bindgen` renders a struct
/// as a `Map`, which JavaScript cannot destructure, `JSON.stringify` renders as
/// `{}`, and no `.field` access reaches. Every value returned by this crate
/// goes through here so the shape is a plain object, once.
pub(crate) fn to_js<T: Serialize>(value: &T) -> Result<JsValue, WasmError> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(WasmError::from)
}

/// The version of this crate, so an application can report what it bundled.
#[wasm_bindgen(js_name = version)]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
