//! The hand-written protobuf reader against arbitrary bytes.
//!
//! `verus-light` hand-rolls just enough protobuf for seven messages rather
//! than pulling in `prost` and a `protoc` at build time. That is a reasonable
//! trade, and it means the parser is this repo's own code eating bytes chosen
//! by whatever is on the other end of the socket — a lightwalletd that is
//! buggy, hostile, or not lightwalletd at all.
//!
//! The first byte selects a message so one corpus exercises all six decoders
//! rather than needing six corpora; the rest is the body.
//!
//! Beyond not panicking, the accessors are called on anything that decoded.
//! `TreeState::tree_bytes` and `leaf_count` parse a hex string and a
//! commitment tree *inside* an already-decoded message — a second parser,
//! reached only through the first, which is exactly the kind of place a bound
//! gets forgotten.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verus_light::fuzzing;

fuzz_target!(|data: &[u8]| {
    let Some((selector, body)) = data.split_first() else {
        return;
    };

    match selector % 6 {
        0 => {
            if let Ok(block) = fuzzing::compact_block(body) {
                // Every note a wallet would trial-decrypt.
                let _ = block.commitments();
            }
        }
        1 => {
            if let Ok(state) = fuzzing::tree_state(body) {
                // Both accessors parse further, from fields the server chose.
                let _ = state.tree_bytes();
                let _ = state.leaf_count();
            }
        }
        2 => {
            let _ = fuzzing::raw_transaction(body);
        }
        3 => {
            let _ = fuzzing::server_info(body);
        }
        4 => {
            if let Ok(id) = fuzzing::block_id(body) {
                let _ = id.hash_display();
            }
        }
        _ => {
            let _ = fuzzing::send_response(body);
        }
    }
});
