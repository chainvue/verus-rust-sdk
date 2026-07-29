//! The witness path, end to end, against real captured chain data.
//!
//! No keys and no prover: this is arithmetic over public commitments, so it runs
//! in CI on every push rather than behind a live gate.

use verus_light::{HttpResponse, LightClient, LightError, LightTransport};
use verus_sapling::scan::{witness_anchor, TreeStateBefore};

/// Replays a captured response per gRPC method.
struct Replay(Vec<(&'static str, Vec<u8>)>);

impl LightTransport for Replay {
    fn call(&self, path: &str, _request: &[u8]) -> Result<HttpResponse, LightError> {
        let body = self
            .0
            .iter()
            .find(|(method, _)| path.ends_with(method))
            .map(|(_, body)| body.clone())
            .unwrap_or_else(|| panic!("no canned response for {path}"));
        Ok(HttpResponse { status: None, body })
    }
}

fn fixture(name: &str) -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/lightwalletd/");
    std::fs::read(format!("{path}{name}")).expect("fixture is committed")
}

fn tree_at(name: &str, height: u64) -> TreeStateBefore {
    let client = LightClient::new(Replay(vec![("GetTreeState", fixture(name))]));
    let state = client.tree_state(height).unwrap();
    assert_eq!(state.height, height);
    TreeStateBefore::from_hex(&state.tree).expect("the frontier parses")
}

/// **The whole witness path, proven with public data alone.**
///
/// Take the commitment tree before block 1156849, append exactly the five
/// commitments that block added — as served by `GetBlockRange` — and the
/// resulting Merkle root must equal the tree the server reports *after* that
/// block.
///
/// Three things have to be simultaneously right for this to hold, and each is a
/// way a shielded wallet fails silently:
///
/// * the serialized frontier is parsed correctly (a wrong parse roots to an
///   anchor no node has ever seen),
/// * lightwalletd's `cmu` bytes are in the byte order `Node::from_bytes`
///   expects (reversed, and every root is wrong),
/// * commitments are appended in tree order — block, then transaction, then
///   output.
///
/// None of them fails anywhere earlier. The note decrypts, the witness builds,
/// the Groth16 proof generates after ~20 seconds, and only then does the daemon
/// answer `bad-txns-shielded-requirements-not-met`.
#[test]
fn appending_a_block_reproduces_the_servers_own_tree_root() {
    let before = tree_at("gettreestate.bin", 1_156_848);
    let after = tree_at("gettreestate_after.bin", 1_156_849);

    let client = LightClient::new(Replay(vec![(
        "GetBlockRange",
        fixture("getblockrange.bin"),
    )]));
    let blocks = client.block_range(1_156_847, 1_156_850).unwrap();
    let block = blocks.iter().find(|b| b.height == 1_156_849).unwrap();
    let cmus = block.commitments();
    assert_eq!(cmus.len(), 5);

    // `witness_anchor` appends every commitment in the block, so its anchor is
    // the root at the end of that block regardless of which index is witnessed.
    let rebuilt = witness_anchor(&before, &cmus, 0).expect("witness builds");

    assert_eq!(
        hex::encode(rebuilt),
        hex::encode(after.root().expect("root")),
        "appending block 1156849's commitments to the frontier before it must \
         reproduce the frontier after it"
    );
}

/// The same tree, counted three ways.
///
/// `leaf_count` reads the frontier's filled slots, `TreeStateBefore::size` asks
/// the rebuilt tree, and `chainMetadata` is the server's own varint. This is the
/// number that *is* a note's absolute position, so agreement across three
/// independent routes is worth asserting explicitly.
#[test]
fn three_independent_routes_agree_on_the_tree_size() {
    let client = LightClient::new(Replay(vec![
        ("GetTreeState", fixture("gettreestate.bin")),
        ("GetBlockRange", fixture("getblockrange.bin")),
    ]));

    let state = client.tree_state(1_156_848).unwrap();
    let from_encoding = state.leaf_count().unwrap();
    let from_tree = TreeStateBefore::from_hex(&state.tree)
        .unwrap()
        .size()
        .unwrap();
    let from_metadata = client
        .block_range(1_156_847, 1_156_850)
        .unwrap()
        .iter()
        .find(|b| b.height == 1_156_848)
        .and_then(|b| b.tree_size)
        .unwrap();

    assert_eq!(from_encoding, 3099);
    assert_eq!(from_tree, 3099);
    assert_eq!(from_metadata, 3099);
}

/// Positions are counted from the frontier, so the first output of block 1156849
/// must land exactly where the previous block's tree ended.
#[test]
fn the_first_commitment_of_a_block_takes_the_next_free_position() {
    let before = tree_at("gettreestate.bin", 1_156_848);
    let client = LightClient::new(Replay(vec![(
        "GetBlockRange",
        fixture("getblockrange.bin"),
    )]));
    let blocks = client.block_range(1_156_847, 1_156_850).unwrap();

    let mut position = before.size().unwrap();
    assert_eq!(position, 3099);

    for block in blocks.iter().filter(|b| b.height > 1_156_848) {
        position += u64::try_from(block.commitments().len()).unwrap();
        if let Some(reported) = block.tree_size {
            assert_eq!(
                position, reported,
                "positions drifted from the server's count at block {}",
                block.height
            );
        }
    }
    assert_eq!(position, 3104);
}
