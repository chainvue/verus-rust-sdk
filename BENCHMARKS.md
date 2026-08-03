# Baseline

Every performance statement in this repo used to be an assertion nobody could
check, and a regression would have been invisible. These are the numbers.

**Nothing has been optimised.** This is a measurement, deliberately taken
before any tuning, so that a later change has something to be compared
against. Two of the numbers below say an optimisation would be pointless, and
that is worth as much as finding one that would help.

```sh
cargo bench -p verus-wire -p verus-tx-transparent -p verus-sapling
```

Recorded **2026-08-04**, Apple M-series, rustc 1.95.0, `--release`, criterion
0.5, medians of 100 samples. Absolute figures are machine-specific; the
*ratios* between rows are the part that carries over, and the part a
regression would show up in.

## Signing a transparent send

The whole path: selection, fee, change, assembly, one ECDSA signature per
input.

| inputs | total | per input |
|---|---|---|
| 1 | 49.3 µs | 49.3 µs |
| 10 | 474 µs | 47.4 µs |
| 100 | 4.51 ms | 45.1 µs |

Flat, and very slightly *improving* with size as fixed overhead amortises. So
this is linear in the input count and dominated by secp256k1 — a hundred-input
sweep costs 4.5 ms, which is not a number worth attacking.

## Sighash, and the O(N²) that turns out not to matter

ZIP-243 hashes the entire prevout and sequence set into the preimage of
*every* input's sighash, so signing an N-input transaction is O(N²) over the
prevouts. That is a real property of the algorithm, and it is visible here:

| inputs | one input's sighash | all inputs |
|---|---|---|
| 1 | 784 ns | 775 ns |
| 10 | 1.01 µs | 10.0 µs |
| 100 | 3.76 µs | 376 µs |

From 10 to 100 the input count grows 10× and the total grows **37.5×**. The
quadratic term is measurable and not theoretical.

It is also irrelevant. At 100 inputs the whole sighash cost is 376 µs against
4.51 ms for the build — **8%**, with ECDSA taking the rest. Caching
`hash_prevouts` across inputs is the obvious optimisation and it would buy
back a twelfth of the time at a size no wallet reaches, in exchange for
touching the code whose byte-identity with the TypeScript SDK is the
correctness gate. Not worth it. If someone revisits this, the entry cost is
re-proving byte-identity, not writing the cache.

`shielded_sighash` is cheaper than the transparent one at every size (631 ns
to 3.61 µs) because it commits to no script code.

## Serialization

| inputs | serialize | deserialize |
|---|---|---|
| 1 | 173 ns | 123 ns |
| 10 | 351 ns | 379 ns |
| 100 | 1.16 µs | 2.19 µs |

Multiple GiB/s in both directions. Parsing a 100-input transaction takes 2.2
µs, so a wallet could parse every transaction in a full block in well under a
millisecond. Nothing here is a bottleneck for anything.

Deserialization is faster than serialization at one input and slower at a
hundred — allocation, not parsing: `serialize` writes into one growing buffer
while `deserialize` allocates a `Vec` per script.

## Shielded scanning — the number that actually matters

| | outputs/second |
|---|---|
| not ours (trial decryption fails) | **12,590** |
| ours (decrypts, then derives nullifier and position) | 1,667 |

A hit costs **7.5× a miss**, because it carries on past decryption. At any
realistic hit rate that contributes nothing, so 12,590/s is the figure to
plan with.

This is the one number here with a user-visible consequence, and the reason
is Verus-specific: **Sapling activates at height 1**. There is no activation
floor to start a rescan from, the way there is on Zcash. A wallet that has not
recorded a birthday scans from genesis:

* VRSCTEST, ~1.17M blocks — at one shielded output per block, ~93 seconds; at
  ten, ~15 minutes.
* mainnet, roughly 4× that.

Per block that is a rounding error. Over a chain it is the difference between
a wallet that restores and one that appears to hang, and it is why
`crates/verus-sdk/examples/receive_online.rs` treats the birthday as the one
thing that must be persisted *before* an address is shown to anyone.

If any of this is ever worth optimising, it is here — and the lever is not
the trial decryption but avoiding it: birthdays, then persisted scan state.
Both already exist.

## Adding to this

Benches live in `crates/*/benches/`, `harness = false`, criterion from
`[workspace.dependencies]`. Update the table when a number moves, and say
which commit moved it. A baseline nobody refreshes is worse than none,
because it reads as current.
