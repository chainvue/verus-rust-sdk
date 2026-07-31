# Contributing

## The gate

Run before opening a PR — CI runs the same thing:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo check -p verus-sdk --no-default-features     # feature gates must hold
```

If you touched `crates/verus-wasm`, or anything it depends on, run the browser
half too. `wasm-bindgen` is inert on the host, so the generated glue, the
`JsValue` marshalling and the thrown `Error` are exercised **only** here:

```bash
cargo check -p verus-wasm --target wasm32-unknown-unknown --all-targets
wasm-pack build crates/verus-wasm --target nodejs --out-dir pkg --release
node crates/verus-wasm/tests/node/differential.mjs crates/verus-wasm/pkg
```

The toolchain is pinned to **1.95.0** in `rust-toolchain.toml`. The same version
appears in `.github/workflows/ci.yml` (`dtolnay/rust-toolchain` reads its version
from the workflow, not from the file) — **change one, change the other.**

## Rules that are not style preferences

These exist because breaking them loses money.

**Correctness is proven against the daemon.** New consensus-touching code needs a
test against `fixtures/daemon/` — real transactions the network accepted — or
against the differential vectors in `fixtures/transparent/`. A test that only
checks our own output against our own expectations proves nothing.

**Port literally; do not improve.** The fee heuristic, coin selection and the
dust rule are transcribed from the TypeScript SDK, including its quirks (the
`selected.len() + 1` off-by-one in the initial fee estimate; `>` rather than `>=`
against `MIN_FEE` and the dust threshold). Byte-for-byte agreement is the
correctness gate. If a heuristic is genuinely wrong, fix it on both sides in one
change and regenerate the vectors — never silently diverge.

**Money is integers.** `u64`/`i128`, parsed from decimal strings. No `f64` in the
value path, ever. `(v * 1e8).round()` is acceptable only when parsing a daemon
JSON decode in test code, and must not leak into a library crate.

**Ordering is observable.** Output emission order is consensus-visible. Where the
TypeScript side relies on JavaScript `Map` insertion order, use `IndexMap` or
`Vec<(_, _)>` — never `HashMap`.

**Refuse rather than guess.** If an input combination isn't supported yet, return
a typed error. A fallback that produces a plausible-but-wrong transaction is
worse than a refusal.

**Never `unwrap()` on caller input.** A malformed spec must be an `Err`, not a
panic — this is a library, and a panic in a wallet is a crash in someone's app.
`unsafe` is forbidden workspace-wide.

## Keys and secrets

Never commit key material, even testnet. Test WIFs that already appear in public
fixtures are fine; anything else is not. Private key types must zeroize on drop.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/) — `feat:`, `fix:`,
`docs:`, `build:`, `chore:`, `test:`, `refactor:`.
