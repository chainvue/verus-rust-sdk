//! Serialization, parsing and sighash.
//!
//! These three are the innermost loop of everything this SDK does. A wallet
//! parses every transaction in every block it looks at; it serializes and
//! sighashes once per input it signs. Nothing here is optimised, and nothing
//! here should be optimised on the strength of a guess — that is what these
//! numbers are for.
//!
//! # What the shapes mean
//!
//! The input counts are not arbitrary. One input is the common send. Ten is a
//! wallet consolidating small change. A hundred is the shape that hurts:
//! ZIP-243 hashes the whole input set into `hash_prevouts` and `hash_sequence`
//! for *every* input signed, so signing an N-input transaction is O(N²) work
//! over the prevouts. If that ever becomes a problem, it will show up as the
//! 100-input sighash growing faster than 10× the 10-input one — which is
//! exactly what the numbers below let someone check rather than assume.

// `criterion_group!` expands to a `pub fn` it does not document, and the
// workspace denies `missing_docs`. Allowed here rather than workspace-wide:
// the lint is doing its job everywhere else.
#![allow(missing_docs)]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;
use verus_wire::{consensus, TxIn, TxOut, TxV4};

/// A transaction with `inputs` P2PKH-shaped inputs and two outputs.
///
/// Built by hand rather than taken from a fixture so the input count is a
/// parameter. The script contents are not what is being measured — the byte
/// counts are representative and the values are arbitrary.
fn transaction(inputs: usize) -> TxV4 {
    let script_pubkey = vec![
        0x76, 0xa9, 0x14, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
        0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x88, 0xac,
    ];
    TxV4 {
        inputs: (0..inputs)
            .map(|i| TxIn {
                txid_internal: [u8::try_from(i % 256).unwrap_or(0); 32],
                vout: u32::try_from(i).unwrap_or(0),
                sequence: 0xffff_ffff,
                // A signed P2PKH scriptSig: 71-byte DER signature plus a
                // 33-byte compressed pubkey.
                script_sig: vec![0x47; 106],
            })
            .collect(),
        outputs: vec![
            TxOut {
                value: 50_000_000,
                script_pubkey: script_pubkey.clone(),
            },
            TxOut {
                value: 49_990_000,
                script_pubkey: script_pubkey.clone(),
            },
        ],
        lock_time: 0,
        expiry_height: 1_200_000,
        ..TxV4::default()
    }
}

fn serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialize");
    for inputs in [1usize, 10, 100] {
        let tx = transaction(inputs);
        let bytes = tx.serialize().expect("the fixture serializes");
        // Bytes, so the report is a rate and the three sizes are comparable.
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(inputs), &tx, |b, tx| {
            b.iter(|| black_box(tx.serialize().expect("serialize")));
        });
    }
    group.finish();

    let mut group = c.benchmark_group("deserialize");
    for inputs in [1usize, 10, 100] {
        let bytes = transaction(inputs).serialize().expect("serialize");
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(inputs), &bytes, |b, bytes| {
            b.iter(|| black_box(TxV4::deserialize(bytes).expect("deserialize")));
        });
    }
    group.finish();
}

fn sighash(c: &mut Criterion) {
    let branch_id = consensus::VERUS_BRANCH_ID;
    let script_code = vec![
        0x76, 0xa9, 0x14, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
        0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x88, 0xac,
    ];

    // One input's sighash. Multiply by the input count for the cost of
    // signing the whole transaction — that is the O(N²) noted above.
    let mut group = c.benchmark_group("transparent_sighash_one_input");
    for inputs in [1usize, 10, 100] {
        let tx = transaction(inputs);
        group.bench_with_input(BenchmarkId::from_parameter(inputs), &tx, |b, tx| {
            b.iter(|| {
                black_box(
                    tx.transparent_sighash(
                        branch_id,
                        0,
                        &script_code,
                        100_000_000,
                        consensus::SIGHASH_ALL,
                    )
                    .expect("sighash"),
                )
            });
        });
    }
    group.finish();

    // And the whole transaction, which is what a caller actually pays.
    let mut group = c.benchmark_group("transparent_sighash_every_input");
    for inputs in [1usize, 10, 100] {
        let tx = transaction(inputs);
        group.throughput(Throughput::Elements(inputs as u64));
        group.bench_with_input(BenchmarkId::from_parameter(inputs), &tx, |b, tx| {
            b.iter(|| {
                for index in 0..tx.inputs.len() {
                    black_box(
                        tx.transparent_sighash(
                            branch_id,
                            index,
                            &script_code,
                            100_000_000,
                            consensus::SIGHASH_ALL,
                        )
                        .expect("sighash"),
                    );
                }
            });
        });
    }
    group.finish();

    let mut group = c.benchmark_group("shielded_sighash");
    for inputs in [1usize, 10, 100] {
        let tx = transaction(inputs);
        group.bench_with_input(BenchmarkId::from_parameter(inputs), &tx, |b, tx| {
            b.iter(|| black_box(tx.shielded_sighash(branch_id)));
        });
    }
    group.finish();
}

criterion_group!(benches, serialization, sighash);
criterion_main!(benches);
