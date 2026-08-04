# Examples

Each file here is a complete, runnable operation meant to be **copied as a
starting point** rather than read as a tutorial. They are the SDK's own
acceptance tests for ergonomics: if an operation is awkward here, it is awkward
in a wallet.

**The header of each file is its real documentation** — the exact command, the
input format, and the reasoning behind whatever is non-obvious. This page is the
index: what exists, what it costs you, and how to get going.

```sh
head -45 examples/send_online.rs      # from crates/verus-sdk/
cargo run -p verus-sdk --example      # lists every name
```

---

## Sixty seconds from a clone

```sh
git clone https://github.com/chainvue/verus-rust-sdk && cd verus-rust-sdk

# 1. Decode a real transaction. No key, no coins, no features, no network.
TXID=9ad56bd37604672cbfb18a4f0f2391b449cb30f326cafefe9b13e42712e53bdc
curl -s --data-binary "{\"method\":\"getrawtransaction\",\"params\":[\"$TXID\"]}" \
  https://api.verustest.net | sed 's/.*"result":"\([0-9a-f]*\)".*/\1/' \
  | cargo run -q -p verus-sdk --example decode_tx

# 2. Make a key. Note the address.
cargo run -p verus-sdk --example keygen

# 3. Send that address some VRSCTEST (see "Testnet coins" below), then look at it.
VERUS_ADDRESS=R… cargo run -p verus-sdk --features network --example wallet_balance

# 4. Spend some.
VERUS_WIF=U… cargo run -p verus-sdk --features network --example send_online -- R… 0.1
```

Steps 1–3 cost nothing and cannot spend anything. Step 4 is the first one that
moves money.

---

## What costs what

Read this column first. **`spends`** means the example broadcasts a transaction
that leaves your address permanently poorer, on testnet.

### Free, and entirely offline

No node is contacted. These run on a machine with no network interface.

| Example | Does | Needs |
|---|---|---|
| [`decode_tx`](decode_tx.rs) | Reads a raw transaction (or a bare output script) and says what every output **is** — identity, token, conversion, commitment — and where it cannot tell, whether that output can hold money | nothing |
| [`keygen`](keygen.rs) | A throwaway key: WIF and address | nothing |
| [`keygen_phrase`](keygen_phrase.rs) | A throwaway 24-word BIP-39 phrase and the seed it maps to | nothing |
| [`airgap_sign`](airgap_sign.rs) | The offline half of an air-gapped wallet: read a plan, check what it does, sign it. Deliberately built **without** `network`, so it links no HTTP client at all | `VERUS_WIF` |
| [`send`](send.rs) | Build and sign a transparent send from a JSON spec. Prints hex; broadcasting is yours | JSON on stdin |
| [`send_token`](send_token.rs) | The same for a token (reserve currency) | JSON on stdin |
| [`register_id`](register_id.rs) | Both halves of the VerusID commit/reveal, from JSON | JSON on stdin |
| [`update_id`](update_id.rs) | Republish an identity with one thing changed | JSON on stdin |
| [`revoke_id`](revoke_id.rs) | Revoke or recover an identity | JSON on stdin |
| [`keygen_shielded`](keygen_shielded.rs) | Derive a shielded account from a BIP-39 seed | `--features shielded`, JSON on stdin |
| [`read_notes`](read_notes.rs) | Find and decrypt your own notes in a transaction, from a viewing key | `--features shielded`, JSON on stdin |
| [`shield`](shield.rs) | Build and sign a t→z shield | `--features prover`, Sapling params, JSON on stdin |
| [`spend_note`](spend_note.rs) | Spend a shielded note — z→z, z→t, or both | `--features prover`, Sapling params, JSON on stdin |

### Free, but talks to a node

Read-only. The node is asked questions and never handed anything to broadcast.

| Example | Does | Needs |
|---|---|---|
| [`wallet_balance`](wallet_balance.rs) | Spendable vs immature coinbase vs token-bearing outputs — three numbers a wallet must keep apart | `VERUS_ADDRESS` |
| [`drive_async`](drive_async.rs) | The non-blocking driver: `advance` in an async loop, each round's requests fetched concurrently. Set `VERUS_COMPARE=1` to time concurrent against sequential | `VERUS_ADDRESS` |
| [`airgap_watch plan`](airgap_watch.rs) | Plan a payment from an **address**, with no key in the process. Prints the blob for `airgap_sign` | `VERUS_ADDRESS` |
| [`id_login`](id_login.rs) | Sign a challenge as a VerusID and verify it — both halves, so it doubles as the round-trip check | `VERUS_WIF` |
| [`take_offer_online`](take_offer_online.rs) | Inspect a marketplace offer against what its funding output **actually holds right now**. Free unless `TAKE=1` | offer hex on stdin |
| [`receive_online`](receive_online.rs) | The receiving half of a shielded wallet: account, birthday, scan, incoming payments with memos | `--features light`, a lightwalletd |

### Spends real testnet coins

| Example | Costs | Needs |
|---|---|---|
| [`send_online`](send_online.rs) | the amount + fee | `VERUS_WIF` |
| [`airgap_watch send`](airgap_watch.rs) | the amount + fee | a signed blob |
| [`convert_online`](convert_online.rs) | the amount + fee | `VERUS_WIF` |
| [`make_offer_online`](make_offer_online.rs) | the funding step broadcasts; signing the offer does not | `VERUS_WIF` |
| [`take_offer_online`](take_offer_online.rs) with `TAKE=1` | what the offer demands | `VERUS_WIF` |
| [`register_id_online`](register_id_online.rs) | **100+ VRSCTEST** — a root identity is not cheap | `VERUS_WIF` |
| [`spend_note_online`](spend_note_online.rs) with `VERUS_SPEND_BROADCAST=1` | the amount + fee | `--features light,prover` |

---

## The air-gapped pair

The one flow that spans two programs, so it gets its own note.

```sh
# ── machine A: online, holds no key ───────────────────────────────────
VERUS_ADDRESS=R… cargo run -p verus-sdk --features network \
  --example airgap_watch -- plan <to-address> 0.1
# → prints a blob (163 bytes for a one-input payment)

# ── machine B: offline, holds the key ─────────────────────────────────
cargo run -p verus-sdk --example airgap_sign -- <blob>          # look, then stop
VERUS_WIF=U… cargo run -p verus-sdk --example airgap_sign -- <blob> --sign

# ── machine A again ───────────────────────────────────────────────────
cargo run -p verus-sdk --features network --example airgap_watch -- send <signed blob>
```

Neither half can do the other's job, and neither is prevented by discipline:
`airgap_watch` calls a function with no parameter a private key could go in, and
`airgap_sign` is compiled without `network`, so **no HTTP client exists in its
dependency tree**. Check it yourself:

```sh
cargo tree -p verus-sdk -e normal --prefix none --target all \
  --features transparent | grep -cE '^(ureq|reqwest|hyper|rustls|tokio)'   # → 0
```

`airgap_sign` prints the summary and **stops** unless you pass `--sign`. That is
the point of it: the outputs were chosen by a machine you decided not to trust
with your key, and signing is the irreversible step. The line to read last is
`scope` — under `SIGHASH_ALL` your signature binds the outputs shown; under
anything else it does not, and whoever holds the blob can still redirect the
money.

Proven on chain, block 1176357 — planned by a process with no key, signed by one
with no socket:

```sh
curl -s --data-binary '{"method":"getrawtransaction","params":
  ["570c9e724c724136002e95df22dd67c851594221425654f71575c9fa8bd51f20",1]}' \
  https://api.verustest.net
```

---

## Feature flags

Examples that need a feature declare it, so Cargo tells you rather than failing
to compile. Nothing is enabled by accident: linking an HTTP client or a 50 MB
zk-SNARK prover should be a decision.

| Flag | Buys | Cost |
|---|---|---|
| *(default)* `transparent` | build and sign transparent transactions | — |
| `--features network` | ask a node, compose operations, broadcast | an HTTP client (`ureq`, `rustls`) |
| `--features shielded` | find your notes, derive ZIP-32 keys | the Sapling read stack, no prover |
| `--features prover` | **build** shielded transactions | bellman, and ~50 MB of parameters at runtime |
| `--features light` | scan and witness notes via lightwalletd | implies `network` + `shielded` |
| `--features multicore` | native prover speedup | rayon; not available on wasm32 |

Shielded proving is slow in a debug build. Use `--release`:

```sh
cargo run --release -p verus-sdk --features prover,multicore --example shield < spec.json
```

---

## Environment

| Variable | Used by | Default |
|---|---|---|
| `VERUS_ENDPOINT` | every online example | `https://api.verustest.net` |
| `VERUS_WIF` | everything that signs | — |
| `VERUS_ADDRESS` | `wallet_balance`, `drive_async`, `airgap_watch` | — |
| `VERUS_LIGHT_ENDPOINT` | `receive_online`, `spend_note_online` | `http://127.0.0.1:8080` |
| `VERUS_SEED_HEX`, `VERUS_BIRTHDAY` | `receive_online` | — |
| `VERUS_SHIELDED_EXTSK`, `VERUS_SPEND_TO`, `VERUS_SPEND_SATS`, `VERUS_SPEND_FEE`, `VERUS_SCAN_FROM`, `VERUS_SAPLING_PARAMS` | `spend_note_online` | — |
| `VERUS_SPEND_BROADCAST=1` | `spend_note_online` — **the switch that spends** | unset = build and print only |
| `TAKE=1` | `take_offer_online` — **the switch that spends** | unset = inspect only |
| `VERUS_COMPARE=1` | `drive_async`, times concurrent vs sequential | unset |

A key on a command line lands in your shell history. Prefer a file:

```sh
set -a; . ./.env; set +a          # VERUS_WIF=U… in .env, chmod 600, and .gitignore'd
```

---

## Conventions

**JSON on stdin** for the offline builders. They take a full specification —
UTXOs, recipients, expiry — because an offline builder cannot look anything up,
and that is the honest shape of an air-gapped signer's input. The header of each
file shows the exact schema.

**Nothing generates a key inside the library.** `keygen` and `keygen_phrase`
read `/dev/urandom` in the *example*, not in `verus-keys`. Where entropy comes
from is the most security-critical decision a wallet makes, and a library that
picked for you would move it somewhere nobody reviews.

**No example ever sends a key to a node.** The node is asked questions and
handed finished bytes. `verus-rpc`'s method denylist test fails the build if a
wallet RPC method is ever added.

---

## Testnet coins

Free. Send some from any testnet wallet, or ask in the Verus Discord.

`register_id_online` wants **100+ VRSCTEST** for a root identity. That figure is
chain policy, not the SDK's — `getcurrency VRSCTEST` reports it as
`idregistrationfees` — and it is *burned*, so it shows up as an oversized miner
fee rather than an output. The `register_id` header explains the two ways to
lose it.

## When something fails

- **``error: target `x` in package `verus-sdk` requires the features: `network` ``**
  — add `--features network` to the `cargo run`, before `--example`.
- **`InsufficientFunds` while `wallet_balance` shows more** — an immature
  coinbase needs 100 confirmations. `wallet_balance` reports that figure
  separately, which is why it exists.
- **`BroadcastUncertain`** — the transaction may or may not have been accepted.
  **Do not retry blindly.** Re-read; `send_online` shows the correct handling.
- **A shielded example is very slow** — you are in a debug build. Add
  `--release`.
