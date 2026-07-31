# verus-rust-sdk

> **Offline-first Verus SDK, in Rust.** Builds and signs bytes — transparent and
> shielded — without a node, a wallet daemon, or a network connection. Behind
> the `network` feature it also looks up, composes and broadcasts whole
> operations through a public node, which never sees a key.

> [!WARNING]
> **Early development. Nothing here is ready for mainnet funds.** The crates are
> unpublished and the API will change without notice. See [Status](#status).

## Why

Verus tooling in JavaScript works but cannot leave Node: it depends on forks of
`@bitgo/utxo-lib` and friends that assume `Buffer` and Node's `crypto`, and that
cannot survive an ordinary consumer install. That rules out native desktop
wallets, and makes browser wallets awkward.

This is the same capability with a different centre of gravity: a Rust core that
compiles anywhere — a native desktop wallet links it directly, a browser
extension reaches it through wasm, and the consensus-critical bytes live in one
auditable place instead of three.

## Quickstart

One dependency line is a working testnet wallet:

```toml
[dependencies]
verus-sdk = { git = "https://github.com/chainvue/verus-rust-sdk", features = ["network"] }
```

```rust,no_run
use verus_sdk::money::Amount;
use verus_sdk::network::{send, spendable, HttpTransport, RpcClient};
use verus_sdk::verus_keys::PrivateKey;

fn main() {
    let key = PrivateKey::from_wif(&std::env::var("VERUS_WIF").unwrap()).unwrap();
    let me = key.address().to_string();

    let node = RpcClient::new(HttpTransport::new("https://api.verustest.net").unwrap());
    let funding = spendable(&node, &me).unwrap();
    println!("{me}: {} VRSCTEST at tip {}", funding.total, funding.tip);

    let sent = send(&node, &node, &key, &me, Amount::from_coins_str("0.1").unwrap()).unwrap();
    println!("txid {}", sent.txid);
}
```

Generate a key with `cargo run -p verus-sdk --example keygen`, send the printed
address some VRSCTEST from any testnet wallet (or ask in the Verus Discord —
testnet coins are free), and the code above runs as-is.
The node is only ever asked questions and handed finished bytes — lookup,
build, sign and broadcast all happen locally, and the key never leaves the
process. Without the `network` and `light` features the same crate is the
offline half alone: builders in, bytes out, no socket anywhere in the
dependency tree.

### App templates

Each online example in [`crates/verus-sdk/examples/`](./crates/verus-sdk/examples/)
is a complete operation meant to be copied as a starting point. The header of
each says whether running it spends testnet coins.

| Example | Shows |
|---|---|
| `wallet_balance` | spendable vs immature vs token-bearing outputs |
| `send_online` | a payment, including the `BroadcastUncertain` re-read that makes retrying safe |
| `register_id_online` | the resumable two-step VerusID registration — salt persisted **before** any coins move |
| `id_login` | sign a challenge as a VerusID and verify it, both halves |
| `convert_online` | estimate, then convert with the estimate as a floor |
| `make_offer_online` | fund and sign a marketplace offer (the hex *is* the offer) |
| `take_offer_online` | inspect an offer against the chain, then take it at the verified terms |

### In a browser

```bash
wasm-pack build crates/verus-wasm --target web --out-dir pkg --release
```

```js
import init, { Key, parseCoins } from "./pkg/verus_wasm.js";
await init();

const key   = Key.fromWif(wif);
const utxos = await rpc("getaddressutxos", [{ addresses: [key.address()] }]);
const tip   = await rpc("getblockcount", []);

const signed = key.send({
  utxos: utxos.map(u => ({
    txid: u.txid, vout: u.outputIndex,
    satoshis: String(u.satoshis), scriptPubKey: u.script,
  })),
  recipients: [{ address: to, satoshis: parseCoins("1.5") }],
  changeAddress: key.address(),
  expiryHeight: tip + 20,
});

await rpc("sendrawtransaction", [signed.hex]);
key.free();
```

`verus-wasm` builds and signs; it does **not** fetch or broadcast. That split is
deliberate. `verus-rpc` is built on a synchronous transport and a browser has no
synchronous `fetch`, so binding the flows would mean an async duplicate of every
one of them — while the thing that would wrap, JSON-RPC over HTTP, is a few
lines of JavaScript with the app's own auth, retries and node choice. So:
**JavaScript asks the questions, WebAssembly holds the key and makes the bytes.**

Two conventions carry through the whole JS API. Money is a **decimal string**,
never a `number` — `satoshis: 1e8` throws, because a float64 cannot hold a
satoshi count above 2^53 and 90 million coins is not a hypothetical on a chain
capped at 83.5 million. And errors are thrown `Error`s whose `.name` is the
cause, so `catch (e) { if (e.name === "InsufficientFunds") … }` works.

Covered: native and token sends, VerusID message signing and verification (log
in with Verus), VDXF key derivation, identity ids, and output decoding. The
package ships hand-written TypeScript declarations, pinned against the Rust
types by a test so they cannot drift.

## Design

**Correctness is proven against the network, not against itself.** Four
independent checks, none of which is self-referential:

1. Real transactions a Verus daemon produced and accepted (`fixtures/daemon/`)
   re-serialize byte for byte — and the daemon's *own* signature on one of them
   verifies against a sighash this crate recomputes.
2. The transparent path is diffed byte for byte against the daemon-proven
   TypeScript SDK, which signs deterministically and so is an exact oracle.
3. A live daemon decodes what we build and computes the same transaction id
   (opt-in: `VERUS_LIVE_DECODE=1`).
4. **The network accepted a transaction this SDK built and signed.** See below.

A green suite that only agrees with itself would prove nothing about consensus.

### Accepted on chain

The firsts are told below; the complete ledger of every proven capability and
its txid is [`PROVEN.md`](./PROVEN.md).

VRSCTEST txid
[`59a1097f1162b8dfd7037b5933d7156700bb0fe4230f14f003ba5f1c087206b3`](https://testex.verus.io/tx/59a1097f1162b8dfd7037b5933d7156700bb0fe4230f14f003ba5f1c087206b3),
mined at height 1 166 191.

The key was generated by `cargo run -p verus-sdk --example keygen`, the address
derived by `verus-keys`, and the spend built and signed by `verus-tx` — coin
selection, the 10 000 satoshi fee, the change output, the ZIP-243 sighash and the
signature. The daemon only held the coins and accepted the result. The txid this
SDK computed before broadcasting is the one the chain recorded, so the
serialization is byte-identical to the daemon's.

#### Paying a VerusID

VRSCTEST txid
[`5e19de6d3f77b5e1f49ec92db23027d5f026db92004b026465a61bff8ab13d7e`](https://testex.verus.io/tx/5e19de6d3f77b5e1f49ec92db23027d5f026db92004b026465a61bff8ab13d7e),
mined at height 1 166 385. The daemon reports that output as type
`cryptocondition` paying `i8jHXEEYEQ7KEoYe6eKXBib8cUBZ6vjWSd` — an identity, not
an address.

Paying a VerusID is not a P2PKH output with a different hash in it. It is a
CryptoCondition with **no eval code**, where the identity is expressed purely by
the destination's *kind*. And destinations are not uniformly encoded: a key hash
and a public key go in bare, identified by length alone, while an identity
carries a leading `0x04` type byte. Writing one as a bare 20-byte hash produces a
script that pays a transparent address which merely shares the identity's hash —
spendable by nobody.

So the encoding was taken from consensus rather than inferred: the tests build
pay-to-identity scripts for three live VRSCTEST identities and require them to
equal the bytes already on chain, and a separate test asserts that dropping the
type byte yields a different script.

#### A shield, end to end

VRSCTEST txid
[`35eccaca9518b2d105bd791c74dc1bd25c3377d2a18a115e5ca67f1d86c9aa79`](https://testex.verus.io/tx/35eccaca9518b2d105bd791c74dc1bd25c3377d2a18a115e5ca67f1d86c9aa79),
mined at height 1 166 308: 0.0996 VRSC moved into the shielded pool.

This one is signed by **two crates in sequence**. `verus-sapling` proved the
Sapling bundle and applied the binding signature over the ZIP-243 shielded
sighash; `verus-tx` then signed the transparent input. That works because the
shielded sighash has no transparent-input section and `scriptSig` bytes never
reach `hashPrevouts`, `hashSequence` or `hashOutputs` — so neither signature
invalidates the other.

Then the loop was closed from the other end: the transaction was fetched back
off the chain and the note recovered from it with a **viewing key alone** —
9 960 000 zatoshi, the right address, memo intact.

```sh
cargo run -p verus-sdk --features shielded --example read_notes < spec.json
```

#### And spending it back out

VRSCTEST txid
[`4c16d1e73c3c9579575ae171169aee01261bdd1f35c488f972fe07c6dc20deba`](https://testex.verus.io/tx/4c16d1e73c3c9579575ae171169aee01261bdd1f35c488f972fe07c6dc20deba),
mined at height 1 166 356: that same note spent back to a transparent address.
The nullifier is published, the 0.0993 VRSC arrived, **t → z → t is closed on
chain with real value.**

The hard part of a shielded spend is not the proof — it is the witness. Proving
a note is in the commitment tree needs the tree's frontier as it stood
immediately *before* the note's block, and that is the one input a signing host
cannot compute for itself. Worse, it cannot generally be recovered afterwards: a
frontier only moves forward, and once further notes are added the earlier state
cascades away for good.

`getsaplingtree` returns only the tip, and this endpoint blocks
`z_gettreestate`. What made this spend possible is that a Sapling frontier keeps
its last two leaves in `left`/`right` — so while a note is still the
second-to-last commitment on the chain, clearing those two recovers exactly the
tree that preceded it. `scan.rs` pins that against real chain data: the
reconstructed witness roots to the `finalsaplingroot` in the block header. It is
a narrow trick, not a general answer; for anything older, capture the frontier
before broadcasting, or ask a node.

Which is why [`witness_anchor`] exists and needs no proving parameters. A
frontier from the wrong height fails *nowhere* else — the note decrypts, the
witness builds, the proof generates, the transaction serializes — and the daemon
then rejects it with `18: bad-txns-shielded-requirements-not-met`. Confirmed the
hard way. Check the anchor first; it costs microseconds instead of a 30-second
proof.

[`witness_anchor`]: crates/verus-sapling/src/scan.rs

#### And a transfer that never surfaces

VRSCTEST txid
[`9478fe9bee08db2dcf49d84288932adde89950a9c01d4f81848d0e361b6b3728`](https://testex.verus.io/tx/9478fe9bee08db2dcf49d84288932adde89950a9c01d4f81848d0e361b6b3728),
mined at height 1 166 368: `vin 0, vout 0`, one shielded spend, two shielded
outputs, `valueBalance` exactly the fee. A second account then scanned that
transaction with only its viewing key and found 9 870 000 zatoshi and a memo
addressed to it. **Nothing about the transfer is visible on the transparent
side.**

This one used the frontier workflow that actually generalises: `getsaplingtree`
captured *before* broadcasting the shield, then checked — nothing else was
shielded in the two blocks in between, and `witness_anchor` matched the block's
`finalsaplingroot` before any proving ran.

One trap on the way. **Your note is not reliably output 0.** The Sapling builder
shuffles a bundle's outputs — concealing which is the real recipient is the
point of the padding output — so the index moves between transactions built the
same way. The first shield here landed at index 0, the second at index 1. Find
it by trial decryption; guessing builds a witness for the wrong leaf, which
proves and serializes happily before failing.

The offline gate re-proves the whole shielded path on every opt-in run,
with no chain and no coins:

```sh
cargo run --release -p verus-sapling --features prover,multicore --example prove_and_verify
```

It shields, spends the very note it created, and checks every proof and
signature with `SaplingVerificationContext` — the verifier a consensus node
runs. Every shielded flow is now also proven on chain; tokens remain
byte-identical to the TypeScript SDK and never broadcast.

**Money is integers.** Satoshis are `u64`/`i128` end to end, parsed from decimal
strings. There is no float in the value path.

**Signing is deterministic.** RFC6979 with low-S normalization — no RNG on the
transparent path. That is a security property *and* what makes byte-for-byte
differential testing possible at all.

**Keys are handled deliberately.** Transparent private key material zeroizes on
drop, with an opaque `Debug` and no `PartialEq`. Shielded key handling is
bounded by the upstream `sapling-crypto` types, which do not zeroize — their
`Debug` is redacted and nothing here serializes them, but spending keys do
linger in memory, and saying otherwise would overclaim.

Outside the `network`/`light` features nothing in the dependency tree can open
a socket — a test pins that. The networked crates ask questions and hand over
finished bytes; they can never ask a node to sign.

## Layout

| Crate | What it does |
|---|---|
| `verus-wire` | v4 transaction serialization and parsing, ZIP-243 sighashes. No keys, no network. |
| `verus-keys` | WIF, base58check, `R`/`i` addresses, P2PKH scripts, ECDSA |
| `verus-tx` | transparent transactions: sends, tokens, VerusIDs, offers, conversions, multisig, currency launch |
| `verus-sapling` | shielded: note scanning, ZIP-32 derivation, and t→z / z→z / z→t building behind `prover` |
| `verus-rpc` | typed read-only JSON-RPC client + broadcast; can never ask a node to sign |
| `verus-flows` | lookup → build → sign → broadcast, composed into operations a wallet calls |
| `verus-light` | Sapling chain data from a lightwalletd server, over grpc-web |
| `verus-sdk` | the facade you actually depend on |
| `verus-wasm` | the browser binding: the same builders, from JavaScript, with the key inside the module |

```toml
[dependencies]
verus-sdk = { git = "https://github.com/chainvue/verus-rust-sdk" }   # offline builders only
verus-sdk = { git = "…", features = ["network"] }                   # + node lookup, flows, broadcast
verus-sdk = { git = "…", features = ["shielded"] }                  # + find notes, derive keys
verus-sdk = { git = "…", features = ["prover"] }                    # + build shielded transactions
verus-sdk = { git = "…", features = ["light"] }                     # + scan/witness notes via lightwalletd
```

The shielded half is priced in two steps, because seeing your notes and spending
them cost very different things. `shielded` is trial decryption and ZIP-32 —
milliseconds, no bellman in the dependency graph. `prover` adds Groth16 and
expects ~50 MB of Sapling parameters at runtime. A balance-only wallet takes the
first and stops. The networked half is priced the same way: without `network`,
nothing in the tree can open a socket — and a test pins that.

## Status

Everything below marked **on chain** was built and signed by this SDK and
accepted by VRSCTEST — every txid is in [`PROVEN.md`](./PROVEN.md).

| | |
|---|---|
| Native and VerusID-addressed sends | ✅ **on chain**, incl. through the public node via `flows` |
| Token send | ✅ byte-identical to the TypeScript SDK; not yet broadcast |
| VerusID lifecycle — commit, register, referred, token-parent sub-ID, update, 2-of-2 multisig, revoke, recover | ✅ **on chain**, all eight |
| VerusID message signing / login | ✅ verified live against the daemon, both directions |
| Shielded — t→z, z→t, z→z, multi-note, via lightwalletd end to end | ✅ **on chain** |
| Marketplace offers — make, inspect against the chain, take | ✅ **on chain** (native legs; token demands byte-verified) |
| Conversions | ✅ **on chain**, exactly the estimate; burns byte-verified |
| Currency launch — fractional basket and centralized token, preconvert | ✅ **on chain** |
| Transparent P2SH multisig, SIGHASH variants, identity timelocks | ✅ byte-verified, not broadcast |
| Mint new supply, spend from a VerusID | ✅ **on chain** — spent-by-identity, per consensus |
| wasm bindings — build and sign from JavaScript | ✅ **byte-identical to the TypeScript SDK**, checked under node in CI |
| PBaaS / cross-chain export | ⬜ needs a second system |

Not published to crates.io yet — the API has not settled, and a crate name is a
promise about stability.

## Related

- [`@chainvue/verus-sdk`](https://www.npmjs.com/package/@chainvue/verus-sdk) — the TypeScript SDK (transparent), daemon-proven, the differential oracle for this repo
- [`@chainvue/verus-sapling`](https://www.npmjs.com/package/@chainvue/verus-sapling) — shielded signing for JavaScript, where the Sapling implementation ported here comes from

## License

Apache-2.0. See [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).
