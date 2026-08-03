//! Proving one scan continues the last one.
//!
//! A wallet's first scan is a one-off. Every scan after it is the tail, every
//! few minutes, for the life of the wallet — so *across* calls is where a
//! wallet actually lives, and until [`scan_after`] existed nothing checked it.
//! [`ScanResult::tip_hash`] was documented "so the next scan can prove it
//! continues the same chain rather than a reorged one" and no function took it.
//!
//! What makes the gap matter is that a reorg does not fail loudly here. It
//! shifts note *positions*, and a note witnessed at the wrong position produces
//! a proof the daemon rejects only after the prover has been paid for.

use verus_flows::{scan, scan_after, FlowError, ScanResult};
use verus_light::{HttpResponse, LightClient, LightError, LightTransport};
use verus_sapling::scan::{dfvk_from_extsk, DiversifiableFullViewingKey};

// ------------------------------------------------------------ test doubles

/// Serves one canned body per gRPC method.
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

fn client(block_range: Vec<u8>) -> LightClient<Server> {
    LightClient::new(Server {
        tree_state: fixture("gettreestate.bin"),
        block_range,
    })
}

// ------------------------------------------------------- protobuf writing

fn varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = u8::try_from(value & 0x7f).expect("7 bits");
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
    varint(out, u64::try_from(value.len()).expect("a length"));
    out.extend_from_slice(value);
}

/// A CompactBlock with no shielded activity, so the tree does not move.
fn empty_block(height: u64, hash: [u8; 32], prev: [u8; 32]) -> Vec<u8> {
    let mut block = Vec::new();
    varint_field(&mut block, 2, height);
    bytes_field(&mut block, 3, &hash);
    bytes_field(&mut block, 4, &prev);
    let mut meta = Vec::new();
    // The fixture frontier holds 3099 commitments and these blocks add none.
    varint_field(&mut meta, 1, 3099);
    bytes_field(&mut block, 8, &meta);
    block
}

fn body(messages: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for message in messages {
        out.push(0);
        out.extend_from_slice(
            &u32::try_from(message.len())
                .expect("a length")
                .to_be_bytes(),
        );
        out.extend_from_slice(message);
    }
    let trailer = "grpc-status: 0\r\n";
    out.push(0x80);
    out.extend_from_slice(
        &u32::try_from(trailer.len())
            .expect("a length")
            .to_be_bytes(),
    );
    out.extend_from_slice(trailer.as_bytes());
    out
}

fn stranger() -> DiversifiableFullViewingKey {
    let account = verus_sapling::derive::derive_account(&[7u8; 64], 1, 0).expect("derivation");
    dfvk_from_extsk(&*account.extsk).expect("a viewing key")
}

/// Blocks 1156847 and 1156848, chained, ending at hash `[2; 32]`.
///
/// Given a note and a nullifier afterwards, deliberately. With an empty result
/// the two things `scan_after` could return for "nothing new" — an empty
/// continuation, or `previous` handed straight back — are indistinguishable,
/// and the second is the dangerous one: a poll loop absorbing it would
/// re-append every note it already had, on every idle tick.
fn first_scan() -> ScanResult {
    let a = empty_block(1_156_847, [1u8; 32], [0u8; 32]);
    let b = empty_block(1_156_848, [2u8; 32], [1u8; 32]);
    let mut result =
        scan(&client(body(&[a, b])), &stranger(), 1_156_847, 1_156_848).expect("a scan");
    assert_eq!(result.tip_hash, [2u8; 32]);
    result.notes.push(a_note(1_156_848, 3099));
    result.nullifiers.push([0x77; 32]);
    result
}

/// A note the wallet already holds. Its contents do not matter here; that it
/// survives — and is not duplicated — does.
fn a_note(height: u64, position: u64) -> verus_sapling::scan::DetectedNote {
    verus_sapling::scan::DetectedNote {
        height,
        tx_index: 0,
        output_index: 0,
        position,
        value: 1_000,
        recipient: [7u8; 43],
        nullifier: [0x99; 32],
    }
}

// -------------------------------------------------------------- the tests

/// The ordinary case: the next chunk chains onto the last one.
#[test]
fn a_scan_that_continues_the_last_one_is_accepted() {
    let previous = first_scan();

    // 1156849's prevHash is the previous scan's tip hash.
    let c = empty_block(1_156_849, [3u8; 32], [2u8; 32]);
    let d = empty_block(1_156_850, [4u8; 32], [3u8; 32]);
    let next = scan_after(&client(body(&[c, d])), &stranger(), &previous, 1_156_850)
        .expect("it continues");

    // It starts where the last one stopped, with no gap and no overlap.
    assert_eq!(next.from, previous.to + 1);
    assert_eq!(next.to, 1_156_850);
    assert_eq!(next.tip_hash, [4u8; 32]);
}

/// The failure the whole thing exists for.
///
/// The server serves a chain whose 1156849 does not descend from the 1156848
/// already scanned. Positions derived from it would be wrong, and wrong
/// positions do not fail until the daemon rejects a paid-for proof.
#[test]
fn a_scan_that_does_not_continue_the_last_one_is_refused() {
    let previous = first_scan();

    // prevHash is some other block, not `[2; 32]`.
    let c = empty_block(1_156_849, [3u8; 32], [0xaa; 32]);
    match scan_after(&client(body(&[c])), &stranger(), &previous, 1_156_849) {
        Err(FlowError::Reorged(text)) => {
            assert!(text.contains("does not follow"), "{text}");
            assert!(text.contains("1156849"), "{text}");
        }
        other => panic!("expected a reorg, got {other:?}"),
    }
}

/// And it is the *first* block of the new range that gets checked.
///
/// Without seeding the previous tip hash, the check only starts at the second
/// block of each call — so a single-block continuation, which is what a wallet
/// polling every few minutes asks for, would never be checked at all.
#[test]
fn a_single_block_continuation_is_still_checked() {
    let previous = first_scan();

    let honest = empty_block(1_156_849, [3u8; 32], [2u8; 32]);
    assert!(scan_after(&client(body(&[honest])), &stranger(), &previous, 1_156_849).is_ok());

    let forked = empty_block(1_156_849, [3u8; 32], [0xbb; 32]);
    assert!(matches!(
        scan_after(&client(body(&[forked])), &stranger(), &previous, 1_156_849),
        Err(FlowError::Reorged(_))
    ));
}

/// Nothing new is not an error.
///
/// A polling wallet asks far more often than blocks arrive, and an error for
/// the common case is a design that gets worked around.
#[test]
fn asking_for_nothing_new_returns_an_empty_continuation() {
    let previous = first_scan();

    let next = scan_after(&client(body(&[])), &stranger(), &previous, previous.to)
        .expect("nothing new is fine");

    // Empty, and NOT `previous` handed back: `previous` holds a note and a
    // nullifier, so returning it wholesale would pass an emptiness check that
    // only looked at a wallet with nothing in it — and a poll loop absorbing
    // that would double its notes every idle tick.
    assert!(next.notes.is_empty(), "it returned the previous notes");
    assert!(next.nullifiers.is_empty());

    // An empty range is spelled as one: it starts one past where the last scan
    // ended. Claiming `from == to == previous.to` would assert that block was
    // scanned by this call and held nothing, which is false — `previous` found
    // a note there.
    assert_eq!(next.from, previous.to + 1);
    assert_eq!(next.to, previous.to);
    assert!(next.to < next.from);
    // It chains, so a poll loop can feed it straight back in.
    assert_eq!(next.tip_hash, previous.tip_hash);

    let c = empty_block(1_156_849, [3u8; 32], [2u8; 32]);
    assert!(
        scan_after(&client(body(&[c])), &stranger(), &next, 1_156_849).is_ok(),
        "the empty result must be usable as the next call's `previous`"
    );

    // And absorbing it changes nothing.
    let mut wallet = previous.clone();
    wallet.absorb(next).expect("an empty continuation absorbs");
    assert_eq!(wallet.notes.len(), previous.notes.len());
    assert_eq!(wallet.nullifiers.len(), previous.nullifiers.len());
    assert_eq!(wallet.to, previous.to);
}

/// The merge, which is the half of this a wallet gets wrong on its own.
///
/// `scan_after` returns only the tail, in the same type that holds the whole
/// wallet. Storing it in place of the old state loses every note; storing the
/// notes but not the nullifiers is worse, because a note spent in the old range
/// comes back as spendable.
#[test]
fn absorbing_a_continuation_keeps_both_halves() {
    let mut wallet = first_scan();
    let before = (wallet.notes.len(), wallet.nullifiers.len());

    let c = empty_block(1_156_849, [3u8; 32], [2u8; 32]);
    let mut tail =
        scan_after(&client(body(&[c])), &stranger(), &wallet, 1_156_849).expect("it continues");
    tail.notes.push(a_note(1_156_849, 3100));
    tail.nullifiers.push([0x88; 32]);

    wallet.absorb(tail).expect("it continues, so it absorbs");

    assert_eq!(wallet.notes.len(), before.0 + 1, "the old notes were lost");
    assert_eq!(
        wallet.nullifiers.len(),
        before.1 + 1,
        "the old nullifiers were lost, so a spent note is spendable again"
    );
    // The range and the tip moved forward.
    assert_eq!(wallet.to, 1_156_849);
    assert_eq!(wallet.tip_hash, [3u8; 32]);
    assert_eq!(wallet.from, 1_156_847);
}

/// A continuation that does not start where this one ended is refused.
///
/// Absorbing it would leave blocks nobody scanned, and every note position
/// after a gap is derived from a count that skipped them.
#[test]
fn absorbing_across_a_gap_is_refused() {
    let mut wallet = first_scan();
    let stale = ScanResult {
        notes: Vec::new(),
        nullifiers: Vec::new(),
        // Two past the end, not one.
        from: wallet.to + 2,
        to: wallet.to + 3,
        tip_hash: [9u8; 32],
    };
    match wallet.absorb(stale) {
        Err(FlowError::Shielded(text)) => assert!(text.contains("gap"), "{text}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    // And nothing moved.
    assert_eq!(wallet.to, 1_156_848);
}

/// A server behind the last scan is refused — but not called a reorg.
///
/// A node still syncing after a restart, or a load-balanced name that rotated
/// to a replica, serves the *same* chain with less of it. Every block already
/// scanned is still on it. Reporting that as `Reorged` would push a wallet into
/// the reorg remedy — discard notes, rescan — for a condition whose correct
/// response is to wait.
#[test]
fn a_server_behind_the_last_scan_is_not_called_a_reorg() {
    let previous = first_scan();
    match scan_after(&client(body(&[])), &stranger(), &previous, previous.to - 1) {
        Err(FlowError::NotReady(text)) => {
            assert!(text.contains("behind"), "{text}");
            assert!(text.contains("1156848"), "{text}");
            assert!(text.contains("1156847"), "{text}");
            // No run of stray whitespace from a broken line continuation.
            assert!(!text.contains("  "), "{text}");
        }
        other => panic!("expected NotReady, not a reorg: {other:?}"),
    }
}

/// The plain `scan` is unchanged: it still starts from nothing.
///
/// If seeding the previous hash had leaked into it, a first scan would compare
/// its opening block against an all-zero hash and refuse every real chain.
#[test]
fn a_first_scan_still_needs_nothing_to_follow() {
    let a = empty_block(1_156_847, [1u8; 32], [0xcd; 32]);
    let b = empty_block(1_156_848, [2u8; 32], [1u8; 32]);
    // The opening block's prevHash is arbitrary and must not be checked.
    assert!(scan(&client(body(&[a, b])), &stranger(), 1_156_847, 1_156_848).is_ok());
}
