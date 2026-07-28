# verus-rust-sdk

> **Offline Verus transaction SDK, in Rust.** Builds and signs bytes — transparent
> and shielded — without a node, a wallet daemon, or a network connection.
> Your application broadcasts.

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

## Design

**Correctness is proven against the network, not against itself.** Every layer is
checked with real transactions a Verus daemon produced and accepted
(`fixtures/daemon/`), and the transparent path is additionally diffed byte for
byte against the daemon-proven TypeScript SDK. A green test suite that only
agrees with itself would prove nothing about consensus.

**Money is integers.** Satoshis are `u64`/`i128` end to end, parsed from decimal
strings. There is no float in the value path.

**Signing is deterministic.** RFC6979 with low-S normalization — no RNG on the
transparent path. That is a security property *and* what makes byte-for-byte
differential testing possible at all.

**Keys are handled deliberately.** Private key material zeroizes on drop, and no
crate here ever opens a socket.

## Layout

| Crate | What it does |
|---|---|
| `verus-wire` | v4 transaction serialization, ZIP-243 sighashes. No keys, no network. |
| `verus-keys` | WIF, base58check, `R`/`i` addresses, P2PKH scripts, ECDSA |
| `verus-tx` | transparent transactions: coin selection, fees, change, signing |
| `verus-sapling` | shielded transactions: Groth16 proving, note scanning, ZIP-32 |
| `verus-sdk` | the facade you actually depend on |

```toml
[dependencies]
verus-sdk = { git = "https://github.com/chainvue/verus-rust-sdk" }              # transparent
verus-sdk = { git = "…", features = ["shielded"] }                             # + shielded
```

Shielded is off by default: it pulls in a zk-SNARK prover and needs ~50 MB of
Sapling parameters at runtime. A wallet that only sends VRSC should not pay for
that.

## Status

| | |
|---|---|
| Workspace, CI, fixtures | ✅ |
| `verus-wire` — serializer + sighashes | ✅ proven against daemon transactions |
| `verus-keys` — WIF, addresses, ECDSA | ✅ signature matches the TypeScript SDK |
| `verus-tx` — native VRSC send | ✅ byte-identical on 6 differential vectors |
| `verus-sapling` — port the proven prover | ⬜ |
| Tokens, VerusID, wasm bindings | ⬜ later |

Not published to crates.io yet — the API has not settled, and a crate name is a
promise about stability.

## Related

- [`@chainvue/verus-sdk`](https://www.npmjs.com/package/@chainvue/verus-sdk) — the TypeScript SDK (transparent), daemon-proven, the differential oracle for this repo
- [`@chainvue/verus-sapling`](https://www.npmjs.com/package/@chainvue/verus-sapling) — shielded signing for JavaScript, where the Sapling implementation ported here comes from

## License

Apache-2.0. See [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).
