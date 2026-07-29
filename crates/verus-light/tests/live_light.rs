//! Read-only checks against a real lightwalletd server.
//!
//! Opt-in, because it needs a server this repository does not run:
//!
//! ```sh
//! ssh -N -L 8080:127.0.0.1:8080 vrsc-testnet   # grpcwebproxy in front of lightwalletd
//! VERUS_LIVE_LIGHT=1 cargo test -p verus-light --test live_light -- --nocapture
//! ```
//!
//! Set `VERUS_LIGHT_ENDPOINT` to point somewhere else. Nothing here spends or
//! broadcasts; every call is a question.

use verus_light::{GrpcWebTransport, LightClient};

fn client() -> Option<LightClient<GrpcWebTransport>> {
    if std::env::var("VERUS_LIVE_LIGHT").is_err() {
        eprintln!("skipping: set VERUS_LIVE_LIGHT=1 and tunnel a grpc-web proxy to :8080");
        return None;
    }
    let endpoint = std::env::var("VERUS_LIGHT_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    Some(LightClient::new(
        GrpcWebTransport::new(endpoint).expect("endpoint"),
    ))
}

#[test]
fn the_server_follows_the_chain_this_sdk_signs_for() {
    let Some(client) = client() else { return };
    let info = client.server_info().unwrap();
    eprintln!(
        "  {} on {} — tip {}, synced to {}",
        info.version, info.chain_name, info.block_height, info.estimated_height
    );

    // The branch id goes into every ZIP-243 sighash. If the server's chain and
    // this SDK's constant ever diverge, everything signed here is rejected, and
    // nothing at the signing end would reveal why.
    let expected = format!("{:08x}", verus_wire::consensus::VERUS_BRANCH_ID);
    assert_eq!(info.consensus_branch_id, expected);
}

/// Two different calls must describe the same block the same way.
///
/// This is the byte-order check. `GetLatestBlock` and `GetBlockRange` return the
/// block hash in separate message types, and getting the endianness wrong in one
/// of them is the classic way to produce a wallet that silently never matches
/// anything.
///
/// Note what is deliberately *not* asserted: leading zeros. Verus is hybrid
/// PoW/PoS, and roughly half of consecutive blocks have none — 1167931, 1167932
/// and 1167933 in a row, observed live. A `starts_with("0000")` check is a
/// Bitcoin assumption that fails here about half the time.
#[test]
fn the_tip_is_described_identically_by_two_calls() {
    let Some(client) = client() else { return };
    let tip = client.latest_block().unwrap();
    eprintln!("  tip {} {}", tip.height, tip.hash_display());
    assert!(tip.height > 1_000_000, "testnet is well past this height");
    assert_ne!(tip.hash, [0u8; 32], "a block hash is never zero");

    let block = &client.block_range(tip.height, tip.height).unwrap()[0];
    assert_eq!(
        block.hash, tip.hash,
        "the two calls disagree on the tip hash"
    );
}

/// The check that makes note positioning trustworthy, run against live data
/// rather than a fixture.
///
/// `GetTreeState` returns a serialized Merkle frontier and `GetBlockRange`
/// returns a varint count. Different calls, unrelated encodings, no shared code
/// — so agreement is evidence, and disagreement means a note would be witnessed
/// at the wrong position.
#[test]
fn the_frontier_and_the_block_metadata_agree_live() {
    let Some(client) = client() else { return };
    let tip = client.latest_block().unwrap();

    // Stay a little behind the tip so a block arriving mid-test cannot make the
    // two calls disagree for an uninteresting reason.
    let height = tip.height - 10;

    let state = client.tree_state(height).unwrap();
    assert_eq!(state.height, height);

    let blocks = client.block_range(height, height).unwrap();
    let from_metadata = blocks[0].tree_size.expect("server sends chainMetadata");
    let from_frontier = state.leaf_count().unwrap();

    eprintln!("  height {height}: frontier {from_frontier}, metadata {from_metadata}");
    assert_eq!(from_frontier, from_metadata);
}

#[test]
fn a_block_range_comes_back_contiguous_and_chained() {
    let Some(client) = client() else { return };
    let tip = client.latest_block().unwrap();
    let start = tip.height - 20;

    let blocks = client.block_range(start, start + 9).unwrap();
    assert_eq!(blocks.len(), 10);
    for (offset, block) in blocks.iter().enumerate() {
        assert_eq!(block.height, start + u64::try_from(offset).unwrap());
    }
    for pair in blocks.windows(2) {
        assert_eq!(pair[1].prev_hash, pair[0].hash, "blocks must chain");
    }

    let commitments: usize = blocks.iter().map(|b| b.commitments().len()).sum();
    eprintln!("  {start}..={} — {commitments} commitments", start + 9);
}

/// A range past the tip is the trailers-only error path, live.
#[test]
fn asking_past_the_tip_is_an_error_not_an_empty_range() {
    let Some(client) = client() else { return };
    let tip = client.latest_block().unwrap();
    let err = client
        .block_range(tip.height + 1_000, tip.height + 1_001)
        .unwrap_err();
    eprintln!("  {err}");
    assert!(
        matches!(err, verus_light::LightError::Status { .. }),
        "expected a gRPC status, got {err:?}"
    );
}
