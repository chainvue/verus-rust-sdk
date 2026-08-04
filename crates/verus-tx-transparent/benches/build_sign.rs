//! Building and signing a transparent send.
//!
//! The whole path a wallet pays for when it spends: coin selection, fee
//! estimation, change placement, assembly, and one ECDSA signature per input.
//!
//! # Why the input count is the parameter
//!
//! Almost all of this is expected to be dominated by signing, which is linear
//! in the input count — one secp256k1 operation each. The parts that are not
//! linear are `select_utxos`, and the ZIP-243 sighash, which rehashes the full
//! prevout set for every input signed and is therefore O(N²).
//!
//! At ten inputs that is invisible. At a hundred — a wallet sweeping dust, or
//! consolidating after a long time receiving — it may not be. These numbers
//! say which, and nothing here should be changed on a hunch about it: the fee
//! and selection logic is a literal transcription whose byte-identity with the
//! TypeScript SDK is the correctness gate, so "faster" is only worth having if
//! it is also byte-identical.

// `criterion_group!` expands to a `pub fn` it does not document, and the
// workspace denies `missing_docs`. Allowed here rather than workspace-wide:
// the lint is doing its job everywhere else.
#![allow(missing_docs)]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;
use verus_keys::{Address, PrivateKey};
use verus_tx_primitives::{Amount, Expiry, Txid, Utxo};
use verus_tx_transparent::{build_transparent_send, Recipient, SendParams};

/// A key from a WIF that already appears in this repo's public fixtures.
///
/// Public, empty, and testnet — see `fixtures/README.md`. Nothing is being
/// spent; only the signing cost is measured.
fn key() -> PrivateKey {
    PrivateKey::from_wif("UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc")
        .expect("the fixture WIF parses")
}

/// `count` UTXOs, each big enough that selection takes all of them.
fn utxos(key: &PrivateKey, count: usize) -> Vec<Utxo> {
    let script_pubkey = key
        .address()
        .p2pkh_script_pubkey()
        .expect("a P2PKH script for the funding address");
    (0..count)
        .map(|i| Utxo {
            txid: Txid::from_display_hex(&format!("{i:064x}")).expect("a synthetic txid"),
            vout: 0,
            satoshis: Amount::from_sat(1_000_000),
            script_pubkey: script_pubkey.clone(),
        })
        .collect()
}

fn build_and_sign(c: &mut Criterion) {
    let key = key();
    let change = key.address();
    let to: Address = "RPsQDnaxXgrLjcVBh3SpvCpTabWxAdMdzu"
        .parse()
        .expect("the recipient address parses");

    let mut group = c.benchmark_group("build_transparent_send");
    for count in [1usize, 10, 100] {
        let utxos = utxos(&key, count);
        // Spend most of it, so every UTXO is selected and there is change.
        let amount = Amount::from_sat(900_000 * count as u64);
        let recipients = [Recipient {
            address: to,
            satoshis: amount,
        }];

        // Per-input, so the three sizes are directly comparable: if this is
        // flat, signing dominates and the O(N²) sighash does not matter yet.
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), &utxos, |b, utxos| {
            b.iter(|| {
                let params = SendParams::new(utxos, &recipients, change, Expiry::Never);
                black_box(build_transparent_send(&key, &params).expect("build and sign"))
            });
        });
    }
    group.finish();
}

criterion_group!(benches, build_and_sign);
criterion_main!(benches);
