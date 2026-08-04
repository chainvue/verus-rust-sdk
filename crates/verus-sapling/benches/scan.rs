//! Compact block scanning throughput.
//!
//! This is the number that decides whether a shielded wallet is usable. There
//! is no way to know which outputs are yours without trying to decrypt every
//! one, and **Sapling activates at height 1 on Verus** — there is no activation
//! floor to start from the way there is on Zcash. A wallet without a recorded
//! birthday rescans 1.17 million blocks on VRSCTEST and roughly four times that
//! on mainnet, every restore.
//!
//! So the figure to read here is `not_ours`: outputs per second on the failed
//! trial-decryption path, which is what a scan spends essentially all of its
//! time doing. Divide the chain's total output count by it and you have the
//! restore time a user without a birthday would wait.
//!
//! `ours` is measured alongside because a hit costs more than a miss — it
//! carries on to derive the nullifier and the position — but at realistic hit
//! rates it contributes nothing to the total, and showing both is what makes
//! that claim checkable rather than assumed.

// `criterion_group!` expands to a `pub fn` it does not document, and the
// workspace denies `missing_docs`. Allowed here rather than workspace-wide:
// the lint is doing its job everywhere else.
#![allow(missing_docs)]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use sapling_crypto::note_encryption::{sapling_note_encryption, SaplingDomain, Zip212Enforcement};
use sapling_crypto::value::NoteValue;
use sapling_crypto::{Note, PaymentAddress, Rseed};
use verus_sapling::derive::{derive_account, COIN_TYPE_MAINNET};
use verus_sapling::scan::{detect_notes, dfvk_from_bytes, CompactOutput, TreeStateBefore};

/// Two unrelated accounts from one seed: the scanning key, and a stranger.
fn keys() -> (
    sapling_crypto::zip32::DiversifiableFullViewingKey,
    sapling_crypto::zip32::DiversifiableFullViewingKey,
) {
    let seed = [7u8; 64];
    let mine = derive_account(&seed, COIN_TYPE_MAINNET, 0).expect("account 0");
    let theirs = derive_account(&seed, COIN_TYPE_MAINNET, 1).expect("account 1");
    (
        dfvk_from_bytes(&mine.dfvk).expect("our viewing key"),
        dfvk_from_bytes(&theirs.dfvk).expect("a stranger's viewing key"),
    )
}

/// `count` real, well-formed outputs paying `to`.
///
/// Genuinely encrypted rather than filled with random bytes: a random `cmu`
/// is not a valid curve point and would be rejected before any decryption is
/// attempted, which would measure the error path instead of the scan.
fn outputs(to: &PaymentAddress, count: usize) -> Vec<CompactOutput> {
    (0..count)
        .map(|i| {
            let note = Note::from_parts(
                *to,
                NoteValue::from_raw(100_000 + i as u64),
                Rseed::AfterZip212([u8::try_from(i % 256).unwrap_or(0); 32]),
            );
            let encryptor =
                sapling_note_encryption(None, note.clone(), [0u8; 512], &mut rand::rngs::OsRng);
            let enc = encryptor.encrypt_note_plaintext();
            let mut ciphertext = [0u8; 52];
            ciphertext.copy_from_slice(&enc[..52]);
            CompactOutput {
                height: 1,
                tx_index: 0,
                output_index: i as u64,
                cmu: note.cmu().to_bytes(),
                epk: <SaplingDomain as zcash_note_encryption::Domain>::epk_bytes(encryptor.epk()).0,
                ciphertext,
            }
        })
        .collect()
}

fn empty_tree() -> TreeStateBefore {
    TreeStateBefore {
        left: None,
        right: None,
        parents: Vec::new(),
    }
}

fn scanning(c: &mut Criterion) {
    let (mine, theirs) = keys();
    let my_address = PaymentAddress::from_bytes(&mine.default_address().1.to_bytes())
        .expect("our address round-trips");
    let their_address = PaymentAddress::from_bytes(&theirs.default_address().1.to_bytes())
        .expect("a stranger's address round-trips");

    // The realistic path: nothing in the block belongs to us.
    let mut group = c.benchmark_group("detect_notes/not_ours");
    for count in [100usize, 1000] {
        let outputs = outputs(&their_address, count);
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &outputs,
            |b, outputs| {
                b.iter(|| {
                    let found = detect_notes(&mine, &empty_tree(), outputs, Zip212Enforcement::On)
                        .expect("scan");
                    debug_assert!(found.is_empty(), "a stranger's notes were detected as ours");
                    black_box(found)
                });
            },
        );
    }
    group.finish();

    // Every output is ours: the upper bound, not a realistic block.
    let mut group = c.benchmark_group("detect_notes/ours");
    for count in [100usize, 1000] {
        let outputs = outputs(&my_address, count);
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &outputs,
            |b, outputs| {
                b.iter(|| {
                    let found = detect_notes(&mine, &empty_tree(), outputs, Zip212Enforcement::On)
                        .expect("scan");
                    debug_assert_eq!(found.len(), outputs.len(), "our own notes were missed");
                    black_box(found)
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, scanning);
criterion_main!(benches);
