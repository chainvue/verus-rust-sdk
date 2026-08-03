# Fuzzing

Four targets, one per parser that eats bytes somebody else chose.

| target | entry point | crate |
|---|---|---|
| `tx_deserialize` | `TxV4::deserialize` | `verus-wire` |
| `output_script` | `decode_output_script` | `verus-tx-protocol` |
| `base58` | `decode_check`, `PrivateKey::from_wif`, `Address::from_str` | `verus-keys` |
| `lightwalletd_proto` | the six protobuf message decoders | `verus-light` |

## Running

```sh
cd fuzz
cargo +nightly fuzz run output_script -- -max_total_time=900 -malloc_limit_mb=512
cargo +nightly fuzz run output_script -- -runs=0      # replay the corpus and exit
```

Nightly is not optional — `cargo-fuzz` compiles with `-Zsanitizer=address`.
That is why `fuzz/` is **its own workspace**: the rest of the repo pins 1.95.0
in `rust-toolchain.toml` so the build stays reproducible, and nothing outside
this directory should ever try to compile a libfuzzer target.

`-malloc_limit_mb=512` is worth passing every time. It is the check that
catches the bug class panics do not: a parser that believes a length prefix and
allocates accordingly. No message here needs half a gigabyte.

## Not a substitute for `crates/verus-tx/tests/decoder_robustness.rs`

That test does a deterministic mutation search on stable, in the normal CI job,
on every change. This finds more, but only where it is pointed and only on a
machine with nightly. Keep both — see the note at the top of that file for the
bug that demonstrates why.

## What has actually been run

Recording this because "we fuzz it" means nothing without a number. Runs are on
an M-series Mac, `cargo-fuzz` 0.13.2, one process per target, with
`-rss_limit_mb=2048 -malloc_limit_mb=512`.

**2026-08-03 — 900s per target, corpus seeded from `fixtures/`.**

| target | executions | corpus after | peak RSS | result |
|---|---|---|---|---|
| `tx_deserialize` | 156,412,055 | 197 inputs | 640 MB | clean |
| `lightwalletd_proto` | 127,510,148 | 942 inputs | 1082 MB | clean |
| `base58` | 11,776,740 | 75 inputs | 597 MB | clean |
| `output_script` | 329,861 | — | 241 MB | **crash at 0.3M** |

The `output_script` crash was an integer overflow in
`convert.rs::read_var_slice` — `*offset + length` where `length` is a
`CompactSize` the script author picks. Fixed with `checked_add`; the artifact
is pinned as a regression test in `crates/verus-tx/tests/decoder_robustness.rs`.
Re-run after the fix: clean for 900s.

Note what those numbers say about the seeds. `base58` runs at a fraction of the
others' rate because base58 decoding is genuinely expensive per input, and its
corpus barely grew — 109 seeds down to 75 after minimisation — which suggests
the input space is close to exhausted at this size. `tx_deserialize` and
`lightwalletd_proto` are still finding new coverage at 900s and would repay a
longer soak.

## The `fuzzing` feature

`verus-keys` and `verus-light` each expose a `#[doc(hidden)] pub mod fuzzing`
behind a `fuzzing` feature, off by default and enabled only by this crate's
`Cargo.toml`.

Both exist because the interesting parser is private. `base58` is reachable
only through `Address` and `PrivateKey`, which never hand it anything but a 20-
or 32-byte payload — the raw codec accepts any length, and that is the surface
worth fuzzing. The lightwalletd decoders are reachable only through a
`LightClient`, which needs a transport; a fuzzer wants the parser, not the
HTTP.

Neither is part of the API. If one of these features ever gets enabled by
something other than this directory, that is a mistake.

## When a target crashes

libFuzzer writes the input to `artifacts/<target>/crash-<sha1>`.

```sh
cargo +nightly fuzz run output_script artifacts/output_script/crash-<sha1>
cargo +nightly fuzz tmin output_script artifacts/output_script/crash-<sha1>
```

Fix the bug, then add the artifact bytes to a deterministic test on stable so
the regression is caught without nightly. Verify the new test **fails against
the unfixed code** — a regression test that never failed is a test of nothing.
