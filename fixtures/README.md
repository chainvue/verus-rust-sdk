# Fixtures

Test data only. Nothing here is compiled into the library, and nothing in the
build depends on another repository — these are committed bytes.

## `daemon/` — ground truth

Real Verus **v4** transactions captured from a live testnet daemon
(`verusd -chain=vrsctest`, Sapling active, branch id `76b809bb`). Each pair is
`<flow>.hex` (raw serialized transaction) plus `<flow>.json`
(`getrawtransaction <txid> 1`). Copied from `verus-sapling/test/vectors/`, where
they were the byte-layout targets for the Sapling prover.

| File | Flow | vin | vout | Why it matters here |
|---|---|---|---|---|
| `t2z` | transparent → shielded | 1 | 1 | **The transparent oracle.** `vin[0]` is a daemon-signed P2PKH spend: a 106-byte scriptSig (DER signature + hashtype, then the compressed pubkey) over a `190000000000` zatoshi input. That lets the transparent sighash be proven offline — recompute it, then ECDSA-verify the daemon's own signature against it. No network, no keys, no proving parameters. |
| `z2z` | shielded → shielded | 0 | 0 | Fully private; locks the shielded spend/output layout |
| `z2t` | shielded → transparent | 0 | 1 | Mixed; locks `valueBalance` sign handling |

All: `version 4`, `overwintered`, `versiongroupid 892f2085`, `bindingSig`
present, fee 0.0001.

Note the JSON decodes display 32-byte fields (`cv`, `cmu`, `ephemeralKey`,
`anchor`, `nullifier`, `rk`, txids) **byte-reversed** — uint256 display order.
`encCiphertext`, `outCiphertext` and proofs are raw. Reverse the former when
reconstructing wire bytes.

## `transparent/` — differential vectors

Generated from the TypeScript SDK (`@chainvue/verus-sdk`), which is
daemon-proven and deterministic: RFC6979 signing means the same inputs always
produce the same bytes. Each vector carries the inputs plus the expected signed
hex, txid, fee and change, so this crate's output is compared byte for byte
against an implementation already known to work.

Six cases, each covering a branch that can move the bytes:

| Vector | What it pins |
|---|---|
| `single_utxo_single_output` | the baseline; change above dust |
| `multi_utxo_selection` | the accumulation loop and its fee re-estimate |
| `multi_output` | output count feeding the fee, and therefore the change |
| `descending_selection_order` | largest-first ordering regardless of input order |
| `above_the_2_32_satoshi_blind_spot` | values where the JS fork's own fee guard truncates and goes blind |
| `nonzero_expiry_height` | the expiry is committed to by the sighash |

Regenerate with `fixtures/tools/export-vectors.cjs` — only when a rule genuinely
changes on the TypeScript side, and review the byte diff rather than
rubber-stamping it. Nothing is fetched at build or test time.

## `vdxf/` — wallet-layer golden vectors

VerusPay invoices and login-consent requests/responses, generated from
`verus-typescript-primitives` at the revision `chainvue/verus-sdk` pins.

**Read `fixtures/vdxf/README.md` before trusting a number in there, because the
proof is a weaker kind than the two sections above.** `transparent/` is backed by
`daemon/`; nothing stands behind `vdxf/` in the same way, because no daemon RPC
validates an invoice or a login consent request — they are wallet/application-layer
formats that travel in QR codes and deep links and never enter a transaction. The
oracle is the deployed upstream TypeScript implementation that real wallets
interoperate with: an independent implementation, but not daemon-proven.

Twenty vectors: VerusPay invoice v3 and v4 across the flag matrix, plus login
consent request/response, provisioning and credentials. Regenerate with
`fixtures/tools/export-vdxf-vectors.cjs`, which needs a checkout of the pinned
primitives revision and, unlike `export-vectors.cjs`, no build step.
