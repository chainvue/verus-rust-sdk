//! Decode response bodies captured verbatim from a real lightwalletd server.
//!
//! These are the tests that can catch a wrong protobuf field number. A
//! round-trip through this crate's own encoder cannot: it would be wrong in both
//! directions and agree with itself.
//!
//! Captured 2026-07-29 from the VRSCTEST server, through `grpcwebproxy`. The
//! bodies are committed under `fixtures/lightwalletd/` exactly as they came off
//! the wire, framing and trailers included.

use verus_light::{HttpResponse, LightClient, LightError, LightTransport};

/// Replays one captured body regardless of what is asked for.
struct Replay(Vec<u8>);

impl LightTransport for Replay {
    fn call(&self, _path: &str, _request: &[u8]) -> Result<HttpResponse, LightError> {
        Ok(HttpResponse {
            status: None,
            body: self.0.clone(),
        })
    }
}

fn fixture(name: &str) -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/lightwalletd/");
    std::fs::read(format!("{path}{name}")).expect("fixture is committed")
}

fn client(name: &str) -> LightClient<Replay> {
    LightClient::new(Replay(fixture(name)))
}

#[test]
fn latest_block_decodes() {
    let tip = client("getlatestblock.bin").latest_block().unwrap();
    assert_eq!(tip.height, 1_167_934);
    // The hash arrives in internal byte order and is reversed for display. This
    // particular block happens to be proof-of-work, so its displayed form has
    // leading zeros — which makes it a usable byte-order check. Do not
    // generalise it: Verus is hybrid PoW/PoS and roughly half of all blocks have
    // no leading zeros at all.
    assert_eq!(
        tip.hash_display(),
        "0000000042d57d7555f7112ec0ecf12fa6ec54828961891d45753168dbb0c48f"
    );
}

#[test]
fn server_info_agrees_with_the_consensus_this_sdk_signs_under() {
    let info = client("getlightdinfo.bin").server_info().unwrap();
    assert_eq!(info.chain_name, "VRSCTEST");
    // Stock Zcash lightwalletd would say "test" here. The fork reports the
    // Verus chain name, which is why nothing in this crate matches on "main"
    // or "test" to decide a network.
    assert_ne!(info.chain_name, "test");

    // `verus_wire::consensus::VERUS_BRANCH_ID` is 0x76b809bb. If the server
    // ever disagrees, every transaction this SDK signs would be rejected, and
    // the cause would be invisible at the signing end.
    assert_eq!(info.consensus_branch_id, "76b809bb");
    assert_eq!(info.sapling_activation_height, 1);
}

#[test]
fn tree_state_decodes() {
    let state = client("gettreestate.bin").tree_state(1_156_848).unwrap();
    assert_eq!(state.network, "VRSCTEST");
    assert_eq!(state.height, 1_156_848);
    assert_eq!(
        state.hash,
        "00000000c1e6b2fd607b496ce238e8c1410d3154fd164639f8d5eaf57a4c9f47"
    );
    // 206 bytes: left, no right, and eleven parent slots.
    assert_eq!(state.tree_bytes().unwrap().len(), 206);
}

#[test]
fn block_range_decodes_including_the_empty_block() {
    let blocks = client("getblockrange.bin")
        .block_range(1_156_847, 1_156_850)
        .unwrap();
    assert_eq!(blocks.len(), 4);

    let heights: Vec<u64> = blocks.iter().map(|b| b.height).collect();
    assert_eq!(heights, vec![1_156_847, 1_156_848, 1_156_849, 1_156_850]);

    // Commitments per block. The two empty ones are the point: a block with no
    // shielded activity is still served, and witness maintenance depends on
    // seeing it rather than skipping a height.
    let counts: Vec<usize> = blocks.iter().map(|b| b.commitments().len()).collect();
    assert_eq!(counts, vec![4, 0, 5, 0]);

    // Blocks chain to each other, which is how a scanner notices a reorg.
    for pair in blocks.windows(2) {
        assert_eq!(pair[1].prev_hash, pair[0].hash);
    }

    // Nullifiers only appear where notes were spent.
    let spends: Vec<usize> = blocks
        .iter()
        .map(|b| b.transactions.iter().map(|t| t.nullifiers.len()).sum())
        .collect();
    assert_eq!(spends, vec![0, 0, 3, 0]);
}

#[test]
fn tree_size_advances_by_exactly_the_commitments_in_each_block() {
    let blocks = client("getblockrange.bin")
        .block_range(1_156_847, 1_156_850)
        .unwrap();

    for pair in blocks.windows(2) {
        let before = pair[0].tree_size.expect("server sends chainMetadata");
        let after = pair[1].tree_size.expect("server sends chainMetadata");
        let added = u64::try_from(pair[1].commitments().len()).unwrap();
        assert_eq!(
            after,
            before + added,
            "tree size {before} → {after} across block {} which added {added}",
            pair[1].height
        );
    }
}

/// The cross-check that makes note positioning trustworthy.
///
/// `GetTreeState` returns a serialized Merkle frontier; `GetBlockRange` returns
/// a plain varint count. Different calls, different encodings, no shared code
/// path — so agreement is real evidence rather than a tautology.
///
/// It matters because this number *is* the absolute position of the next
/// commitment. Off by one and the witness still builds, still proves, still
/// costs a fee, and is rejected as
/// `bad-txns-shielded-requirements-not-met`.
#[test]
fn the_frontier_and_the_block_metadata_agree_on_the_leaf_count() {
    let state = client("gettreestate.bin").tree_state(1_156_848).unwrap();
    let blocks = client("getblockrange.bin")
        .block_range(1_156_847, 1_156_850)
        .unwrap();

    let from_frontier = state.leaf_count().unwrap();
    let from_metadata = blocks
        .iter()
        .find(|b| b.height == state.height)
        .and_then(|b| b.tree_size)
        .expect("the range covers the tree state's height");

    assert_eq!(from_frontier, 3099);
    assert_eq!(from_frontier, from_metadata);
}

#[test]
fn a_unary_call_refuses_a_streamed_body() {
    // GetBlockRange's four messages are not a valid answer to GetTreeState.
    let err = client("getblockrange.bin").tree_state(1).unwrap_err();
    assert!(matches!(err, LightError::NotUnary(4)), "{err:?}");
}
