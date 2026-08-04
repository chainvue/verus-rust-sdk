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
    result.nullifiers.push(verus_flows::SeenNullifier {
        height: 1_156_848,
        nullifier: [0x77; 32],
    });
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
    tail.nullifiers.push(verus_flows::SeenNullifier {
        height: 1_156_849,
        nullifier: [0x88; 32],
    });

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

    // And the rewind window was *extended*, not replaced. Replacing it would
    // leave a wallet able to roll back only into the blocks it just scanned —
    // so after one poll the recovery depth would be one block, which is no
    // recovery at all. The window still reaches the first block scanned.
    assert_eq!(wallet.earliest_rewind(), Some(1_156_847));
    assert!(
        wallet.rewind_to(1_156_847).is_ok(),
        "absorbing a tail must not throw away the older checkpoints"
    );
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
        checkpoints: Vec::new(),
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

// ------------------------------------------------------ recovering from one

/// A wallet holding four blocks, with a note and a nullifier in each of the
/// last two — the ones a rollback has to reach.
fn wallet_over_four_blocks() -> ScanResult {
    let blocks: Vec<Vec<u8>> = (0..4)
        .map(|i| {
            let height = 1_156_847 + i;
            let hash = [u8::try_from(i + 1).expect("a byte"); 32];
            let prev = if i == 0 {
                [0u8; 32]
            } else {
                [u8::try_from(i).expect("a byte"); 32]
            };
            empty_block(height, hash, prev)
        })
        .collect();

    let mut wallet =
        scan(&client(body(&blocks)), &stranger(), 1_156_847, 1_156_850).expect("a scan");
    // One note and one nullifier in each of the last two blocks.
    for height in [1_156_849, 1_156_850] {
        wallet.notes.push(a_note(height, height));
        wallet.nullifiers.push(verus_flows::SeenNullifier {
            height,
            nullifier: [u8::try_from(height % 251).expect("a byte"); 32],
        });
    }
    wallet
}

/// Rewinding drops exactly what the rolled-back blocks contributed, and leaves
/// the wallet able to prove where it now stands.
#[test]
fn a_rewind_drops_only_what_came_from_the_dropped_blocks() {
    let mut wallet = wallet_over_four_blocks();
    assert_eq!(wallet.notes.len(), 2);
    assert_eq!(wallet.nullifiers.len(), 2);

    wallet.rewind_to(1_156_849).expect("a checkpoint covers it");

    // The block-1156850 note and nullifier are gone; the 1156849 ones stay.
    assert_eq!(wallet.notes.len(), 1);
    assert_eq!(wallet.notes[0].height, 1_156_849);
    assert_eq!(wallet.nullifiers.len(), 1);
    assert_eq!(wallet.nullifiers[0].height, 1_156_849);

    // And the wallet now stands at a block it can prove.
    assert_eq!(wallet.to, 1_156_849);
    assert_eq!(wallet.tip_hash, [3u8; 32]);
}

/// The point of rewinding: the next scan is checked against the rewound state,
/// not merely accepted.
///
/// Without the checkpoint there is no hash to seed the next call with, so a
/// wallet's only option is a plain `scan` — which performs no continuity check
/// at all, and quietly mixes positions from a dead chain with live ones when
/// the rollback was too shallow.
#[test]
fn a_rewound_wallet_still_verifies_what_comes_next() {
    let mut wallet = wallet_over_four_blocks();
    wallet.rewind_to(1_156_849).expect("a checkpoint covers it");

    // A continuation from the live chain is accepted...
    let live = empty_block(1_156_850, [0x50; 32], [3u8; 32]);
    assert!(scan_after(&client(body(&[live])), &stranger(), &wallet, 1_156_850).is_ok());

    // ...and one that does not descend from where the rewind stopped is not.
    let dead = empty_block(1_156_850, [0x50; 32], [0xee; 32]);
    assert!(matches!(
        scan_after(&client(body(&[dead])), &stranger(), &wallet, 1_156_850),
        Err(FlowError::Reorged(_))
    ));
}

/// Rolling back too little fails loudly on the next attempt.
///
/// This is what makes the recovery loop a search rather than a guess: each
/// depth is checkable, so going too shallow is caught instead of succeeding
/// with a mixed state.
#[test]
fn too_shallow_a_rewind_is_caught_rather_than_accepted() {
    let mut wallet = wallet_over_four_blocks();

    // Suppose the fork is actually at 1156848, and the wallet only rolls back
    // to 1156849 — one block short.
    wallet.rewind_to(1_156_849).expect("a checkpoint covers it");
    let forked = empty_block(1_156_850, [0x50; 32], [0xaa; 32]);
    assert!(
        matches!(
            scan_after(&client(body(&[forked])), &stranger(), &wallet, 1_156_850),
            Err(FlowError::Reorged(_))
        ),
        "a too-shallow rewind must not be silently accepted"
    );

    // Going deeper is checkable too, and lands on a chain that does continue.
    wallet
        .rewind_to(1_156_848)
        .expect("still within the window");
    assert_eq!(wallet.tip_hash, [2u8; 32]);
    let real = empty_block(1_156_849, [0xaa; 32], [2u8; 32]);
    assert!(scan_after(&client(body(&[real])), &stranger(), &wallet, 1_156_849).is_ok());
}

/// Past the checkpoint window there is nothing left to verify against, and it
/// says so rather than guessing.
#[test]
fn a_rewind_beyond_the_window_is_refused() {
    let mut wallet = wallet_over_four_blocks();

    match wallet.rewind_to(1_000_000) {
        Err(FlowError::Shielded(text)) => {
            assert!(text.contains("no checkpoint"), "{text}");
            assert!(text.contains("fresh scan"), "{text}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    // Nothing moved.
    assert_eq!(wallet.to, 1_156_850);

    // And the wallet can say how far back it could have gone.
    assert_eq!(wallet.earliest_rewind(), Some(1_156_847));
}

/// Forward is not a rewind.
#[test]
fn rewinding_past_the_tip_is_refused() {
    let mut wallet = wallet_over_four_blocks();
    match wallet.rewind_to(wallet.to + 1) {
        Err(FlowError::Shielded(text)) => assert!(text.contains("only reaches"), "{text}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// Idle polls must not erode the window a rewind depends on.
///
/// `scan_after` with nothing new returns no checkpoints, so absorbing it leaves
/// the wallet's own window alone. If it returned an empty checkpoint list that
/// *replaced* the wallet's, a wallet that polled for an hour would lose the
/// ability to roll back at all.
#[test]
fn idle_polls_do_not_erode_the_rewind_window() {
    let mut wallet = wallet_over_four_blocks();
    let before = wallet.earliest_rewind();

    for _ in 0..5 {
        let nothing = scan_after(&client(body(&[])), &stranger(), &wallet, wallet.to)
            .expect("nothing new is fine");
        wallet.absorb(nothing).expect("it absorbs");
    }

    assert_eq!(wallet.earliest_rewind(), before);
    assert!(wallet.rewind_to(1_156_848).is_ok());
}

// ------------------------------------------------- the bounded window itself

/// A distinct hash per height, so a long synthetic chain still chains.
fn hash_at(height: u64) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[..8].copy_from_slice(&height.to_le_bytes());
    hash
}

/// `count` chained blocks starting at `first`, whose opening block descends
/// from `follows` — so a continuation really continues.
fn chain_from(first: u64, count: u64, follows: [u8; 32]) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| {
            let height = first + i;
            let prev = if i == 0 { follows } else { hash_at(height - 1) };
            empty_block(height, hash_at(height), prev)
        })
        .collect()
}

/// The window keeps the **newest** `REORG_CHECKPOINTS`, not the oldest.
///
/// Nothing else in this file scans more than four blocks, so the trim never
/// ran — and a trim that kept the oldest entries passed every test while making
/// the whole feature useless: `earliest_rewind` would advertise heights near
/// the wallet's birthday, and every realistic rollback (a block or two back
/// from the tip) would be refused, sending a wallet into a full rescan on every
/// reorg, forever.
#[test]
fn a_long_scan_keeps_the_newest_checkpoints() {
    let count = u64::try_from(verus_flows::REORG_CHECKPOINTS).expect("a count") + 50;
    let first = 1_156_847;
    let last = first + count - 1;

    let wallet = scan(
        &client(body(&chain_from(first, count, [0u8; 32]))),
        &stranger(),
        first,
        last,
    )
    .expect("a long scan");

    // Bounded...
    assert_eq!(wallet.checkpoints.len(), verus_flows::REORG_CHECKPOINTS);
    // ...at the recent end, which is the end a rollback needs.
    assert_eq!(
        wallet.earliest_rewind(),
        Some(last - u64::try_from(verus_flows::REORG_CHECKPOINTS).expect("a count") + 1)
    );
    // The invariant the struct docs claim: the last entry is the tip.
    let tip = wallet.checkpoints.last().expect("a window");
    assert_eq!(tip.height, wallet.to);
    assert_eq!(tip.hash, wallet.tip_hash);

    // And a realistic rollback — a block or two — actually works.
    let mut wallet = wallet;
    wallet.rewind_to(last - 2).expect("well inside the window");
    assert_eq!(wallet.to, last - 2);
    assert_eq!(wallet.tip_hash, hash_at(last - 2));
}

/// Absorbing keeps the window bounded too, and still ending at the tip.
#[test]
fn absorbing_past_the_window_stays_bounded_and_recent() {
    let first = 1_156_847;
    let mut wallet = scan(
        &client(body(&chain_from(first, 10, [0u8; 32]))),
        &stranger(),
        first,
        first + 9,
    )
    .expect("a scan");

    let count = u64::try_from(verus_flows::REORG_CHECKPOINTS).expect("a count") + 5;
    let tail = scan_after(
        &client(body(&chain_from(first + 10, count, hash_at(first + 9)))),
        &stranger(),
        &wallet,
        first + 9 + count,
    )
    .expect("it continues");
    wallet.absorb(tail).expect("it absorbs");

    assert_eq!(wallet.checkpoints.len(), verus_flows::REORG_CHECKPOINTS);
    let tip = wallet.checkpoints.last().expect("a window");
    assert_eq!(tip.height, wallet.to);
    assert_eq!(tip.hash, wallet.tip_hash);
    // The oldest blocks fell out of the window, as they must.
    assert!(wallet.earliest_rewind().expect("a window") > first);
}

/// After a rewind the window still ends at the new tip.
///
/// Without this, dropping the checkpoint *at* the height rewound to passes
/// every other test — `tip_hash` is copied out before the retain, so it stays
/// right — and only shows up as a refused second rollback to the same fork.
#[test]
fn a_rewind_leaves_the_window_ending_at_the_new_tip() {
    let mut wallet = wallet_over_four_blocks();
    wallet.rewind_to(1_156_849).expect("a checkpoint covers it");

    let tip = wallet.checkpoints.last().expect("a window");
    assert_eq!(tip.height, wallet.to);
    assert_eq!(tip.hash, wallet.tip_hash);

    // So the same height can be rewound to again — two reorgs forking at the
    // same block is an ordinary thing.
    wallet.rewind_to(1_156_849).expect("still there");
    assert_eq!(wallet.to, 1_156_849);
}

/// Rewinding to where you already are is allowed, and changes nothing.
///
/// The guard is `>`, not `>=`, on purpose: it is a legal no-op, and the error
/// text promises it by only refusing heights *above* `to`.
#[test]
fn rewinding_to_the_current_tip_is_a_no_op() {
    let mut wallet = wallet_over_four_blocks();
    let (notes, nullifiers, to, tip) = (
        wallet.notes.len(),
        wallet.nullifiers.len(),
        wallet.to,
        wallet.tip_hash,
    );

    wallet.rewind_to(to).expect("rewinding to here is allowed");

    assert_eq!(wallet.notes.len(), notes);
    assert_eq!(wallet.nullifiers.len(), nullifiers);
    assert_eq!(wallet.to, to);
    assert_eq!(wallet.tip_hash, tip);
}

/// A continuation whose window does not end at its own tip is refused.
///
/// Every field is public, so a hand-built or hand-edited result can claim a tip
/// its checkpoints do not cover. Absorbing that leaves a window a later
/// `rewind_to` lands on the wrong hash for — which surfaces two calls later as
/// a refused scan, naming nothing useful. Caught at the boundary instead.
#[test]
fn absorbing_a_tail_whose_window_does_not_end_at_its_tip_is_refused() {
    let mut wallet = wallet_over_four_blocks();
    let inconsistent = ScanResult {
        notes: Vec::new(),
        nullifiers: Vec::new(),
        from: wallet.to + 1,
        to: wallet.to + 1,
        tip_hash: [0x5a; 32],
        // Says nothing about the block it claims to have reached.
        checkpoints: Vec::new(),
    };
    match wallet.absorb(inconsistent) {
        Err(FlowError::Shielded(text)) => {
            assert!(text.contains("do not end at its own tip"), "{text}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(wallet.to, 1_156_850, "nothing should have moved");
}
