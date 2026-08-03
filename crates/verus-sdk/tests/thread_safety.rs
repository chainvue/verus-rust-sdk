//! The types a wallet holds across threads must actually be safe to.
//!
//! Everything here is already `Send + Sync` — the assertions below compile
//! today and nothing needed changing to make them. That is the point: the
//! property held by accident of what the types are made of, and nothing in the
//! workspace stated it, so an `Rc` in a cache, a `RefCell` in a client, or a
//! raw pointer in an FFI shim would compile cleanly here and break in a
//! consumer's wallet — at the point where a `PrivateKey` crosses into a worker
//! thread, or an `RpcClient` is shared by a UI task and a sync task.
//!
//! These are compile-time assertions. There is nothing to run; if this file
//! builds, the guarantee holds.
//!
//! # Why `Answers` is only `Send`
//!
//! [`network::Answers`] carries a `Cassette`, whose miss log is a `RefCell`.
//! `RefCell<T>` is `Send` when `T` is, and never `Sync`, so `Answers` can be
//! **moved**
//! between threads and cannot be **shared** by two at once. That is the right
//! shape rather than a limitation: one `Answers` belongs to one operation's
//! planning, and two threads driving the same operation against the same cache
//! would be racing over which round they are in. Asserting `Send` alone says so
//! deliberately, instead of leaving the next person to discover it from a
//! compiler error.

#![cfg(feature = "network")]

use verus_sdk::money::Amount;
use verus_sdk::network::{
    Answers, ChainInfo, FlowError, Funding, HttpTransport, RpcClient, RpcError, Step,
};
use verus_sdk::verus_keys::{Address, PrivateKey};
use verus_sdk::verus_tx::{SignedTransaction, Utxo};

/// Compiles only for a `T` that is both.
const fn assert_send_sync<T: Send + Sync>() {}

/// Compiles only for a `T` that can be moved across a thread boundary.
const fn assert_send<T: Send>() {}

#[test]
fn the_types_a_wallet_holds_can_cross_threads() {
    // Keys and addresses: a signer on a worker thread is the ordinary case, and
    // `PrivateKey` zeroizes on drop — which has to happen on whichever thread
    // finally owns it.
    assert_send_sync::<PrivateKey>();
    assert_send_sync::<Address>();

    // Money and the things it is counted in.
    assert_send_sync::<Amount>();
    assert_send_sync::<Utxo>();
    assert_send_sync::<SignedTransaction>();
    assert_send_sync::<Funding>();

    // The networked client, shared: a wallet with a balance poller and a send
    // action holds one of these behind an `Arc`.
    assert_send_sync::<RpcClient<HttpTransport>>();

    // Moved, not shared — see the module docs.
    assert_send::<Answers>();
}

/// The errors, which are the likeliest of all of these to stop being `Send`.
///
/// One `Box<dyn Error>` field added without `+ Send + Sync` is enough, and it
/// is an easy thing to write. The consequence lands nowhere near the change:
/// every consumer `tokio::spawn` returning `Result<_, FlowError>` stops
/// compiling — which is the exact shape `examples/drive_async.rs` is a template
/// for.
#[test]
fn the_errors_can_cross_threads_too() {
    assert_send_sync::<FlowError>();
    assert_send_sync::<RpcError>();
    assert_send_sync::<ChainInfo>();
    // The value that literally crosses between the flow and the executor.
    assert_send_sync::<Step<Funding>>();
}

/// The shielded surface a light wallet holds, when it is compiled in.
#[cfg(feature = "light")]
#[test]
fn the_light_wallet_types_can_cross_threads() {
    use verus_sdk::light::{DetectedNote, GrpcWebTransport, LightClient};

    // A balance poller and a spend action share one of these.
    assert_send_sync::<LightClient<GrpcWebTransport>>();
    // Persisted wallet state: what a scan found, kept between runs.
    assert_send_sync::<DetectedNote>();
}

/// The helpers accept what they should, and the two bounds are not the same
/// bound.
///
/// Be precise about what this does and does not establish. It shows
/// `assert_send` admits a type that is `Send` and not `Sync`, so the two
/// helpers genuinely differ — an `assert_send` that had quietly acquired a
/// `Sync` bound would fail here. It does **not** show that either helper
/// rejects anything, because a test cannot assert that code fails to compile
/// without a compile-fail harness, and adding one (`trybuild`) for this is not
/// worth a dev-dependency.
///
/// The gap is small. `assert_send_sync<T: Send + Sync>()` is checked by the
/// compiler at every call site above; the only way to make it vacuous is to
/// edit the bound off the helper, which is a visible line in a file whose whole
/// subject is that bound.
#[test]
fn the_two_helpers_are_different_bounds() {
    // `Cell` is `Send` and not `Sync`, so it separates them.
    assert_send::<std::cell::Cell<u8>>();
    assert_send_sync::<u8>();
}
