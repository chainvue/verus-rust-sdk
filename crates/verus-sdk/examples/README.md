# Examples

Every example below is one command you can paste. The ones that take a JSON
specification have a ready-made one in [`specs/`](./specs/) — filled with real
data from this repository's own fixtures, and
[tested](../tests/example_specs.rs) so they cannot rot.

Run everything from the **repository root**.

Each file's header is the detailed documentation: the input format, and the
reasoning behind whatever is non-obvious.

```sh
head -45 crates/verus-sdk/examples/send_online.rs
cargo run -p verus-sdk --example                  # lists every name
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

# 3. Send that address some VRSCTEST, then look at it.
VERUS_ADDRESS=R… cargo run -p verus-sdk --features network --example wallet_balance

# 4. Spend some.
VERUS_WIF=U… cargo run -p verus-sdk --features network --example send_online -- R… 0.1
```

Steps 1–3 cost nothing and cannot spend anything. Step 4 is the first that
moves money.

---

# Offline — no node, no coins

## `decode_tx` — what is actually in this transaction?

```sh
cargo run -q -p verus-sdk --example decode_tx -- <raw-tx-hex>
```

Reads a raw transaction, or a bare output script if you give it one. Prints
every output by kind — identity, token, conversion, name commitment — and where
it cannot tell, whether that output is *able* to hold currency. On Verus the
satoshi column is the value only for the plain outputs; a token lives in the
payload of a CryptoCondition whose satoshi field is zero.

Against a live testnet transaction:

```sh
TXID=9ad56bd37604672cbfb18a4f0f2391b449cb30f326cafefe9b13e42712e53bdc
curl -s --data-binary "{\"method\":\"getrawtransaction\",\"params\":[\"$TXID\"]}" \
  https://api.verustest.net | sed 's/.*"result":"\([0-9a-f]*\)".*/\1/' \
  | cargo run -q -p verus-sdk --example decode_tx
```

## `keygen` — a throwaway key

```sh
cargo run -q -p verus-sdk --example keygen
```

## `keygen_phrase` — a throwaway 24-word recovery phrase

```sh
cargo run -q -p verus-sdk --example keygen_phrase
```

## `send` — build and sign a transparent payment

```sh
cargo run -q -p verus-sdk --example send < crates/verus-sdk/examples/specs/send.json
```

Prints signed hex; it does not broadcast. The spec is the first vector of
`fixtures/transparent/vectors.json`, so the txid it prints
(`a7e66718…`) is the one checked byte-for-byte against the TypeScript SDK.

## `send_token` — move a reserve currency

```sh
cargo run -q -p verus-sdk --example send_token < crates/verus-sdk/examples/specs/send_token.json
```

Prints tokens in and tokens out, because they must be equal: spend a reserve
output and *every* token in it leaves the transaction, so anything not sent to
a recipient has to come back as explicit token change or it is destroyed.

## `register_id` — claim a VerusID, both halves

```sh
# Step 1 — commit to the name behind a salt. STORE THE SALT.
cargo run -q -p verus-sdk --example register_id < crates/verus-sdk/examples/specs/register_id.step1.json

# Step 2 — reveal it and publish the identity.
cargo run -q -p verus-sdk --example register_id < crates/verus-sdk/examples/specs/register_id.step2.json
```

Step 1 draws a **fresh random salt every run**, and it exists nowhere but in
that output. The checked-in step 2 carries the salt from one recorded step 1,
which is why the two are consistent with each other and not with a step 1 you
just ran. On chain, broadcast step 1, wait for a confirmation, then step 2.

## `update_id` — republish an identity with one thing changed

```sh
cargo run -q -p verus-sdk --example update_id < crates/verus-sdk/examples/specs/update_id.json
```

The spec's `identity_output` is the identity built by `register_id.step2.json`,
which is what makes it runnable: an update must be signed by one of the
identity's own primary addresses, and the builder refuses otherwise
(`NotAPrimaryAddress`). Point it at an identity you do not control and it will
say so rather than produce something a node rejects.

An update republishes the **entire** identity, so this example decodes the
current object out of `identity_output` rather than trusting the spec. Anything
not carried over is silently erased.

## `revoke_id` — revoke or recover

```sh
cargo run -q -p verus-sdk --example revoke_id < crates/verus-sdk/examples/specs/revoke_id.json
```

For recovery, change `"action"` to `"recover"` and add `"primary_addresses"` —
usually the point, since revocation normally means the old keys are gone.

The spec works because the identity it names has its **recovery** authority
pointed elsewhere. Revocation is refused for an identity that is its own
recovery authority — nobody could then recover it — and the builder refuses
first. The revocation authority is not what decides this; an identity can
revoke itself as long as somebody else can recover it.

## `keygen_shielded` — a shielded account from a seed

```sh
cargo run -q -p verus-sdk --features shielded --example keygen_shielded \
  < crates/verus-sdk/examples/specs/keygen_shielded.json
```

Prints the `zs…` address, the viewing key **and the spending key** — redirect
it somewhere with restrictive permissions. The spec's seed is 64 zero bytes:
obviously fake, deliberately.

## `read_notes` — decrypt your own notes with a viewing key

```sh
cargo run -q -p verus-sdk --features shielded --example read_notes \
  < crates/verus-sdk/examples/specs/read_notes.json
```

Real data: the z→z transaction from `PROVEN.md`. It prints the value, the
address and the memo — `sent by verus-rust-sdk` — from a viewing key alone, no
spending key involved. Outputs that are not yours simply do not decrypt, which
is the whole mechanism.

## `shield` — build a t→z, with a real zk-SNARK proof

```sh
export VERUS_SAPLING_PARAMS="$HOME/Library/Application Support/ZcashParams"
cargo run -q --release -p verus-sdk --features prover,multicore --example shield \
  < crates/verus-sdk/examples/specs/shield.json
```

`--release` is not optional advice: proving in a debug build takes minutes. The
~50 MB of Sapling parameters are the ones any Zcash or Verus node downloads;
`VERUS_SAPLING_PARAMS` points at the directory, or put `"params_dir"` in the
spec.

## `spend_note` — spend a shielded note

```sh
cargo run -q --release -p verus-sdk --features prover,multicore --example spend_note < spec.json
```

**The one example with no ready-made spec.** It needs a spending key for a note
that exists on chain, and this repository has the note
(`fixtures/daemon/sapling_tree.json`) but not the key — correctly, since that
key controls real testnet money. Use `spend_note_online` below, which assembles
the same inputs from a scan; the header here documents the schema if you want
to build one by hand.

---

# Online, read-only — a node is asked questions and told nothing

All of these default to `https://api.verustest.net`. Set `VERUS_ENDPOINT` for
another node.

## `wallet_balance` — what an address holds

```sh
VERUS_ADDRESS=RK9izAySZHQAaCEkRmVV4Xtu73uV5sqsZy \
  cargo run -q -p verus-sdk --features network --example wallet_balance
```

Three figures a wallet must keep apart: spendable now, immature coinbase, and
value held in CryptoCondition outputs that the native builders rightly refuse
as funding. The last one is invisible from a satoshi count.

## `drive_async` — the non-blocking driver

```sh
VERUS_ADDRESS=RK9izAySZHQAaCEkRmVV4Xtu73uV5sqsZy \
  cargo run -q -p verus-sdk --features network --example drive_async

# and to see what the concurrency actually buys, per round:
VERUS_COMPARE=1 VERUS_ADDRESS=RK9izAySZHQAaCEkRmVV4Xtu73uV5sqsZy \
  cargo run -q -p verus-sdk --features network --example drive_async
```

`advance` in an async loop, each round's requests fetched together. The flow
itself is the same synchronous function a blocking caller uses — only the
fetching between rounds is async, which is why there is no async duplicate of
every operation.

## `id_login` — sign a challenge as a VerusID and verify it

```sh
VERUS_WIF=U… cargo run -q -p verus-sdk --features network --example id_login -- myname@
```

Both halves in one process, so it doubles as the round-trip check; a server
would run only `verify_login`. The signature commits to a block height, and
verification resolves the identity **as it stood then** — so rotating a key
later does not invalidate old logins.

## `take_offer_online` (inspect) — read an offer against the chain

```sh
cargo run -q -p verus-sdk --features network --example take_offer_online < offer.hex
```

Free. `inspect` reads what the offer's funding outpoint **actually holds right
now**, rather than what the maker's hex claims. Taking it costs money — see
below.

## `receive_online` — the receiving half of a shielded wallet

```sh
# A new account. Record the birthday BEFORE showing anyone the address.
VERUS_SEED_HEX=… cargo run -q -p verus-sdk --features light --example receive_online

# An existing one.
VERUS_SEED_HEX=… VERUS_BIRTHDAY=1173600 \
  cargo run -q -p verus-sdk --features light --example receive_online
```

Needs a lightwalletd behind a grpcwebproxy — `VERUS_LIGHT_ENDPOINT`, default
`http://127.0.0.1:8080`. Sapling activates at height 1 on Verus, so an account
without a recorded birthday rescans the whole chain.

---

# The air-gapped pair

One payment, two machines. The online half holds no key; the offline half
reaches no node.

```sh
# ── machine A: online, no key ────────────────────────────────────────
VERUS_ADDRESS=RK9izAySZHQAaCEkRmVV4Xtu73uV5sqsZy \
  cargo run -q -p verus-sdk --features network --example airgap_watch \
  -- plan RK9izAySZHQAaCEkRmVV4Xtu73uV5sqsZy 0.1
```

The last line printed is the blob — 163 bytes for a one-input payment.

```sh
# ── machine B: offline, holds the key ────────────────────────────────
cargo run -q -p verus-sdk --example airgap_sign -- <blob>            # look, then stop
VERUS_WIF=U… cargo run -q -p verus-sdk --example airgap_sign -- <blob> --sign
```

Without `--sign` it prints the summary and stops. That is the point: the
outputs were chosen by a machine you decided not to trust with your key, and
signing is the irreversible step. The line to read last is `scope` — under
`SIGHASH_ALL` your signature binds the outputs shown; under anything else it
does not, and whoever holds the blob can still redirect the money.

```sh
# ── machine A again — THIS SPENDS ────────────────────────────────────
cargo run -q -p verus-sdk --features network --example airgap_watch -- send <signed blob>
```

Neither half is prevented from doing the other's job by discipline.
`airgap_watch` calls a function with no parameter a private key could go in,
and `airgap_sign` is compiled without `network`, so no HTTP client exists in
its dependency tree:

```sh
cargo tree -p verus-sdk -e normal --prefix none --target all \
  --features transparent | grep -cE '^(ureq|reqwest|hyper|rustls|tokio)'   # → 0
```

Proven on chain, block 1176357 — planned by a process with no key, signed by
one with no socket:

```sh
curl -s --data-binary '{"method":"getrawtransaction","params":
  ["570c9e724c724136002e95df22dd67c851594221425654f71575c9fa8bd51f20",1]}' \
  https://api.verustest.net
```

---

# These spend real testnet coins

## `send_online` — lookup → build → sign → broadcast

```sh
VERUS_WIF=U… cargo run -q -p verus-sdk --features network --example send_online -- R… 0.1
```

The part worth copying is the error handling. A broadcast that fails at the
transport level is **ambiguous** — the node may have relayed it before the
connection died. Retrying blind can double-spend against yourself; the
`BroadcastUncertain` arm re-reads instead.

## `convert_online` — convert one currency into another

```sh
VERUS_WIF=U… cargo run -q -p verus-sdk --features network --example convert_online \
  -- VRSCTEST shylock 0.5
```

Estimates first, then converts with the estimate as a floor. The floor is
checked **before signing and never again**: a conversion executes when the
chain imports the transfer, at whatever the price is then.

## `make_offer_online` — publish a marketplace offer

```sh
VERUS_WIF=U… cargo run -q -p verus-sdk --features network --example make_offer_online -- 1.0 1.2
```

Offers 1.0 VRSCTEST and demands 1.2 back. Two steps: **funding** broadcasts,
**signing the offer** does not — the printed hex *is* the offer, and handing it
to someone is what publishing means. There is no cancel message, which is why
the expiry matters.

## `take_offer_online` (take) — accept one

```sh
VERUS_WIF=U… TAKE=1 cargo run -q -p verus-sdk --features network \
  --example take_offer_online < offer.hex
```

`TAKE=1` is the switch. `take` uses the figure `inspect` read off the chain,
not the one in the offer hex, so a mistyped value cannot hand the difference to
a miner.

## `register_id_online` — a VerusID, resumably

```sh
VERUS_WIF=U… cargo run -q -p verus-sdk --features network --example register_id_online -- myname
```

**100+ VRSCTEST.** Registration is two transactions with a confirmation
between, and the first commits to a salt that exists nowhere but in your
process — so the flow builds step 1, serializes the pending state to disk, and
only then broadcasts. Crash after broadcasting without persisting the salt and
the commitment fee is gone for good.

## `spend_note_online` — a shielded spend, end to end

```sh
export VERUS_SHIELDED_EXTSK=…      # 169-byte extended spending key, hex
export VERUS_SPEND_TO=zs1…         # or an R address, or a VerusID
export VERUS_SPEND_SATS=10000000
export VERUS_SPEND_FEE=30000
export VERUS_SCAN_FROM=1167000
export VERUS_SAPLING_PARAMS="$HOME/Library/Application Support/ZcashParams"

cargo run -q --release -p verus-sdk --features light,prover,multicore \
  --example spend_note_online                       # builds and prints, sends nothing

VERUS_SPEND_BROADCAST=1 cargo run -q --release -p verus-sdk \
  --features light,prover,multicore --example spend_note_online    # THIS SPENDS
```

scan → select → witness → **check the anchor against a second source** → prove
→ broadcast. `VERUS_SPEND_BROADCAST=1` is the switch; without it nothing is
sent.

---

## Feature flags

Nothing is enabled by accident: linking an HTTP client or a 50 MB zk-SNARK
prover should be a decision.

| Flag | Buys | Cost |
|---|---|---|
| *(default)* `transparent` | build and sign transparent transactions | — |
| `network` | ask a node, compose operations, broadcast | an HTTP client (`ureq`, `rustls`) |
| `shielded` | find your notes, derive ZIP-32 keys | the Sapling read stack, no prover |
| `prover` | **build** shielded transactions | bellman, and ~50 MB of parameters at runtime |
| `light` | scan and witness notes via lightwalletd | implies `network` + `shielded` |
| `multicore` | native prover speedup | rayon; unavailable on wasm32 |

## Environment

| Variable | Used by | Default |
|---|---|---|
| `VERUS_ENDPOINT` | every online example | `https://api.verustest.net` |
| `VERUS_WIF` | everything that signs | — |
| `VERUS_ADDRESS` | `wallet_balance`, `drive_async`, `airgap_watch` | — |
| `VERUS_LIGHT_ENDPOINT` | `receive_online`, `spend_note_online` | `http://127.0.0.1:8080` |
| `VERUS_SAPLING_PARAMS` | `shield`, `spend_note`, `spend_note_online` | — |
| `VERUS_SEED_HEX`, `VERUS_BIRTHDAY` | `receive_online` | — |
| `VERUS_SHIELDED_EXTSK`, `VERUS_SPEND_TO`, `VERUS_SPEND_SATS`, `VERUS_SPEND_FEE`, `VERUS_SCAN_FROM` | `spend_note_online` | — |
| `VERUS_SPEND_BROADCAST=1` | `spend_note_online` — **the switch that spends** | unset = build and print |
| `TAKE=1` | `take_offer_online` — **the switch that spends** | unset = inspect only |
| `VERUS_COMPARE=1` | `drive_async`, times concurrent vs sequential | unset |

A key on a command line lands in your shell history. Prefer a file:

```sh
set -a; . ./.env; set +a          # VERUS_WIF=U… in .env, chmod 600, .gitignore'd
```

## Conventions

**JSON on stdin, not argv.** An offline builder cannot look anything up, so it
takes the whole specification — UTXOs, recipients, expiry. On stdin so a WIF
never reaches the process table or your shell history.

**Nothing generates a key inside the library.** `keygen` and `keygen_phrase`
read `/dev/urandom` in the *example*. Where entropy comes from is the most
security-critical decision a wallet makes, and a library that picked for you
would move it somewhere nobody reviews.

**No example ever sends a key to a node.** The node is asked questions and
handed finished bytes; `verus-rpc`'s method denylist test fails the build if a
wallet RPC method is ever added.

## Testnet coins

Free. Send some from any testnet wallet, or ask in the Verus Discord.

`register_id_online` wants **100+ VRSCTEST** for a root identity. That figure
is chain policy, not the SDK's — `getcurrency VRSCTEST` reports it as
`idregistrationfees` — and it is *burned*, so it appears as an oversized miner
fee rather than an output.

## When something fails

- **``error: target `x` in package `verus-sdk` requires the features: `network` ``**
  — add `--features network` to the `cargo run`, before `--example`.
- **`Error: "spec.recipients"`** — the JSON is missing that field. Compare
  against the matching file in [`specs/`](./specs/).
- **`NotAPrimaryAddress`** — the key does not control that identity. Correct
  refusal, not a bug.
- **`InsufficientFunds` while `wallet_balance` shows more** — an immature
  coinbase needs 100 confirmations. `wallet_balance` reports that separately,
  which is why it exists.
- **`BroadcastUncertain`** — the transaction may or may not have been accepted.
  **Do not retry blindly.** Re-read; `send_online` shows the correct handling.
- **A shielded example takes minutes** — you are in a debug build. Add
  `--release`.
