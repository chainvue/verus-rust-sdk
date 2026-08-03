//! What `scan` must refuse.
//!
//! Every failure here shifts note *positions* rather than producing an obvious
//! error, and a note witnessed at the wrong position fails only at the daemon,
//! after the prover has been paid for. So each one is refused explicitly rather
//! than allowed to become a silently wrong balance.

use verus_flows::{scan, FlowError};
use verus_light::{HttpResponse, LightClient, LightError, LightTransport};
use verus_sapling::scan::dfvk_from_extsk;
use verus_sapling::scan::DiversifiableFullViewingKey;

// ---------------------------------------------------------------- test doubles

/// Serves a canned body per gRPC method.
struct Server {
    tree_state: Vec<u8>,
    block_range: Vec<u8>,
}

impl LightTransport for Server {
    fn call(&self, path: &str, _request: &[u8]) -> Result<HttpResponse, LightError> {
        let body = if path.ends_with("GetTreeState") {
            self.tree_state.clone()
        } else if path.ends_with("GetBlockRange") {
            self.block_range.clone()
        } else {
            panic!("unexpected call to {path}")
        };
        Ok(HttpResponse { status: None, body })
    }
}

fn fixture(name: &str) -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/lightwalletd/");
    std::fs::read(format!("{path}{name}")).expect("fixture is committed")
}

// ------------------------------------------------------------ protobuf writing

fn varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = u8::try_from(value & 0x7f).unwrap();
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn varint_field(out: &mut Vec<u8>, field: u32, value: u64) {
    varint(out, u64::from(field) << 3);
    varint(out, value);
}

fn bytes_field(out: &mut Vec<u8>, field: u32, value: &[u8]) {
    varint(out, (u64::from(field) << 3) | 2);
    varint(out, u64::try_from(value.len()).unwrap());
    out.extend_from_slice(value);
}

/// A CompactBlock with no transactions.
fn empty_block(height: u64, hash: [u8; 32], prev: [u8; 32], tree_size: u64) -> Vec<u8> {
    let mut block = Vec::new();
    varint_field(&mut block, 2, height);
    bytes_field(&mut block, 3, &hash);
    bytes_field(&mut block, 4, &prev);
    let mut meta = Vec::new();
    varint_field(&mut meta, 1, tree_size);
    bytes_field(&mut block, 8, &meta);
    block
}

/// Wrap messages into a grpc-web body with a success trailer.
fn body(messages: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for message in messages {
        out.push(0);
        out.extend_from_slice(&u32::try_from(message.len()).unwrap().to_be_bytes());
        out.extend_from_slice(message);
    }
    let trailer = "grpc-status: 0\r\n";
    out.push(0x80);
    out.extend_from_slice(&u32::try_from(trailer.len()).unwrap().to_be_bytes());
    out.extend_from_slice(trailer.as_bytes());
    out
}

/// A viewing key that owns nothing on this chain. Detection must still run over
/// every output, because positions are counted from all of them.
fn stranger() -> DiversifiableFullViewingKey {
    let account = verus_sapling::derive::derive_account(&[7u8; 64], 1, 0).expect("derivation");
    dfvk_from_extsk(&*account.extsk).expect("a viewing key")
}

fn client(tree_state: Vec<u8>, block_range: Vec<u8>) -> LightClient<Server> {
    LightClient::new(Server {
        tree_state,
        block_range,
    })
}

// ------------------------------------------------------------------- the tests

/// A real scan over real data: four blocks, nine outputs, three nullifiers.
#[test]
fn a_scan_over_real_blocks_counts_everything() {
    let client = client(
        fixture("gettreestate_before.bin"),
        fixture("getblockrange.bin"),
    );
    let result = scan(&client, &stranger(), 1_156_847, 1_156_850).unwrap();

    // None of these notes belong to the key, which is the normal case: a wallet
    // trial-decrypts every output on the chain and keeps almost none.
    assert!(result.notes.is_empty());
    assert_eq!(result.balance(&[]), 0);

    // Nullifiers are collected regardless of whose they are — a wallet needs
    // them all to tell whether its own notes are still unspent.
    assert_eq!(result.nullifiers.len(), 3);
    assert_eq!(result.from, 1_156_847);
    assert_eq!(result.to, 1_156_850);
}

/// A block that does not chain to the one before it means the range spans a
/// reorg, and every position after the break is wrong.
///
/// Reported as [`FlowError::Reorged`] rather than `Shielded`. A wallet's
/// response to this is to roll back and rescan, and that is the same response
/// whether the break is inside one scan or between one scan and the next — so
/// it is one variant and one match arm, not two.
#[test]
fn a_broken_chain_is_refused() {
    let first = empty_block(1_156_847, [1u8; 32], [0u8; 32], 3099);
    // Second block's prevHash does not match the first block's hash.
    let second = empty_block(1_156_848, [2u8; 32], [0xaa; 32], 3099);

    let client = client(fixture("gettreestate.bin"), body(&[first, second]));
    let err = scan(&client, &stranger(), 1_156_847, 1_156_848).unwrap_err();
    match err {
        FlowError::Reorged(ref text) => {
            assert!(text.contains("does not follow"), "{text}");
            assert!(text.contains("reorged"), "{text}");
            assert!(text.contains("1156848"), "{text}");
        }
        other => panic!("expected a reorg, got {other:?}"),
    }
}

/// The server's own commitment counter must agree with the outputs it served.
///
/// If it does not, one of the two is wrong and there is no way to tell which —
/// so neither can be used to place a note.
#[test]
fn a_tree_size_that_disagrees_with_the_outputs_is_refused() {
    let first = empty_block(1_156_847, [1u8; 32], [0u8; 32], 3099);
    // Same chain, but the server claims the tree grew across two empty blocks.
    let second = empty_block(1_156_848, [2u8; 32], [1u8; 32], 3111);

    let client = client(fixture("gettreestate.bin"), body(&[first, second]));
    let err = scan(&client, &stranger(), 1_156_847, 1_156_848).unwrap_err();
    match err {
        FlowError::Shielded(ref text) => {
            assert!(text.contains("3099"), "{text}");
            assert!(text.contains("3111"), "{text}");
            assert!(text.contains("cannot be derived"), "{text}");
        }
        other => panic!("expected a shielded error, got {other:?}"),
    }
}

/// Two empty blocks must leave the tree exactly where it was.
#[test]
fn empty_blocks_advance_the_height_and_not_the_tree() {
    let first = empty_block(1_156_847, [1u8; 32], [0u8; 32], 3099);
    let second = empty_block(1_156_848, [2u8; 32], [1u8; 32], 3099);

    let client = client(fixture("gettreestate.bin"), body(&[first, second]));
    let result = scan(&client, &stranger(), 1_156_847, 1_156_848).unwrap();
    assert!(result.notes.is_empty());
    assert!(result.nullifiers.is_empty());
    assert_eq!(result.tip_hash, [2u8; 32]);
}

#[test]
fn a_backwards_or_genesis_range_is_refused() {
    let client = client(fixture("gettreestate.bin"), body(&[]));

    let err = scan(&client, &stranger(), 200, 100).unwrap_err();
    assert!(matches!(err, FlowError::Shielded(_)), "{err:?}");

    // There is no block -1 to take a frontier from.
    let err = scan(&client, &stranger(), 0, 10).unwrap_err();
    match err {
        FlowError::Shielded(ref text) => assert!(text.contains("height 1 or later"), "{text}"),
        other => panic!("expected a shielded error, got {other:?}"),
    }
}

/// A note is not spendable merely because it was paid to you.
#[test]
fn a_note_whose_nullifier_was_seen_is_not_counted() {
    let client = client(
        fixture("gettreestate_before.bin"),
        fixture("getblockrange.bin"),
    );
    let mut result = scan(&client, &stranger(), 1_156_847, 1_156_850).unwrap();

    // Graft a note in, so the spent-filter can be exercised without owning one.
    let nullifier = result.nullifiers[0];
    result.notes.push(verus_sapling::scan::DetectedNote {
        height: 1_156_847,
        tx_index: 0,
        output_index: 0,
        position: 3099,
        value: 100_000_000,
        recipient: [0u8; 43],
        nullifier,
    });

    // Its nullifier is in this very range: already spent, worth nothing.
    assert_eq!(result.unspent(&[]).len(), 0);
    assert_eq!(result.balance(&[]), 0);

    // And a nullifier carried in from an earlier chunk must count too, or a
    // chunked scan reports spent money as spendable.
    result.nullifiers.clear();
    assert_eq!(result.balance(&[]), 100_000_000);
    assert_eq!(result.balance(&[nullifier]), 0);
}
