//! `TxV4::deserialize` against arbitrary bytes.
//!
//! This parser is fed whatever a node, a light server or a peer calls "a
//! transaction". It must return `Err` on anything it does not understand —
//! never panic, never index out of bounds, never allocate a gigabyte because a
//! length prefix said so.
//!
//! The round-trip is the second half, and the more interesting one. A parser
//! can be perfectly panic-free and still be wrong: if it accepts bytes it then
//! re-serializes differently, two encodings map to one transaction — and a
//! txid is a hash of those bytes, so it would stop identifying what was
//! signed. That is malleability, and it is a consensus bug rather than a
//! robustness one.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verus_wire::TxV4;

fuzz_target!(|data: &[u8]| {
    let Ok(tx) = TxV4::deserialize(data) else {
        return;
    };

    // It parsed, so it must re-serialize to exactly what it was given. Any
    // difference means two byte strings decode to the same transaction, and a
    // txid computed over one would not match the other.
    let reserialized = tx
        .serialize()
        .expect("a transaction that parsed must serialize");
    assert_eq!(
        reserialized.as_slice(),
        data,
        "a transaction that parsed did not re-serialize to its own bytes"
    );
});
