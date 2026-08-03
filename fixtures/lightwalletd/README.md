# lightwalletd fixtures

Response bodies captured verbatim from a real lightwalletd server on **2026-07-29**,
through `grpcwebproxy`, against **VRSCTEST**. Each `.bin` is the complete HTTP
response body — grpc-web framing and trailer frame included, exactly as it came
off the wire. Nothing here was produced by this SDK.

That distinction is the point. A round-trip through our own encoder proves the
encoder agrees with the decoder, which it would even if both used the wrong
protobuf field number. Only bytes from a real server can catch that.

| file | call | what it pins |
|---|---|---|
| `getlatestblock.bin` | `GetLatestBlock` | `BlockID` shape; hash byte order |
| `getlightdinfo.bin` | `GetLightdInfo` | chain name `VRSCTEST`, consensus branch id `76b809bb` |
| `gettreestate_before.bin` | `GetTreeState(1156846)` | the frontier before the whole range, so a scan of it can be tested |
| `gettreestate.bin` | `GetTreeState(1156848)` | a serialized Sapling frontier: 206 bytes, 3099 leaves |
| `gettreestate_after.bin` | `GetTreeState(1156849)` | the frontier after the 5-output block: 270 bytes, 3104 leaves |
| `getblockrange.bin` | `GetBlockRange(1156847, 1156850)` | four blocks, two of them empty, five nullifiers, `chainMetadata` |

## A real note's whole life

A second set covers one note from creation to spend. On 2026-07-29 this SDK
generated a Sapling key, had 5 VRSCTEST shielded to it from the maintainer's
node, then found, witnessed, proved and spent it — every step through
`verus-light` / `verus-flows` / `verus-sapling`, key never leaving the process.

| file | call | covers |
|---|---|---|
| `note_treestate_before.bin` | `GetTreeState(1167986)` | the frontier that fixes the note's position at 3176 |
| `note_blocks.bin` | `GetBlockRange(1167987, 1167995)` | funding block through spend block |
| `note_blocks_before_spend.bin` | `GetBlockRange(1167987, 1167994)` | the same range stopping one block short |

```text
funded  5af146d0583f535ece8518a1f3b7abaafae0b65155e4d05a90956367ecc91626  block 1167987
spent   8f9e0a6b1073349bd6f25433e617de3bd4826ab4afeae68b293d23d6e68a78c8  block 1167995
```

The last fixture exists so `before_the_spend_the_note_was_spendable` cannot pass
for the wrong reason — without it, the "spent" assertion would hold even if the
nullifier join were broken.

`crates/verus-flows/tests/shielded_note_lifecycle.rs` commits the **viewing key**
for that address. It can find and value the note and can spend nothing; the
spending key was written outside the repository and is not here.

## A spend plan, replayed

A third set covers the plan behind a spend composed through `flows::shielded` on
**2026-08-03**: one note, witnessed to its own block, anchored, and checked
against consensus.

| file | call | covers |
|---|---|---|
| `spend_latestblock.bin` | `GetLatestBlock` | the tip, 1173724 — recorded separately from the anchor so an expiry cannot land behind the chain |
| `spend_treestate_before.bin` | `GetTreeState(1173694)` | the frontier that fixes the note's position at 3184 |
| `spend_block.bin` | `GetBlockRange(1173695, 1173695)` | the note's own block — asked for twice, to witness and to fetch the full output |
| `spend_transaction.bin` | `GetTransaction` | the z→z transaction, whose 948-byte output description is the note |

```text
shield  98d5a67ef07e528c4811c7a4a7ee8dc1c71f6cc552f48c473f214dc5c90e0db2  block 1173691
z→z     2e2b04df1161e220f6a3dfd80abb821e15723f42fea05dec2dc451da5bcd27f5  block 1173695
z→t     2db1cc11c74dc72b9e4e174659404ac58c16599a8442cf9e93e6a23c2c06ae3d  block 1173696
```

What makes this set worth committing is that the anchor it produces has an
**independent** oracle. `crates/verus-flows/tests/shielded_spend_plan.rs`
computes `db1d7a7d…` from these bytes and checks it against the
`finalsaplingroot` a Verus daemon reports for block 1173695 — `0735f7fc…`, the
same 32 bytes in header display order. Every other check in the shielded module
compares one lightwalletd value against another.

The wallet these notes belonged to is empty: the z→t above spent its whole
remaining note, change and all. No key material for it is in this repository.

`compact_formats.proto` and `service.proto` are copied unmodified from the
server's `walletrpc/` directory, MIT-licensed by the Zcash developers. They are
the authority for every field number in `crates/verus-light/src/messages.rs`;
this crate hand-writes its codec rather than generating one, so keeping the
source of truth in the tree matters.

## Why this block range

`1156847..=1156850` was chosen after sweeping the chain for shielded activity,
because it contains all four cases in four blocks:

- **1156847** — 3 transactions, 4 outputs, no spends
- **1156848** — *empty*: no shielded activity at all
- **1156849** — 3 transactions, 5 outputs, 3 nullifiers
- **1156850** — *empty*

The empty blocks are not padding. Witness maintenance requires applying **every**
block in order including the empty ones, and a client that skips them silently
corrupts every witness it holds. A fixture without an empty block cannot catch
that.

## The proof these fixtures make possible

`gettreestate.bin`, `getblockrange.bin` and `gettreestate_after.bin` together
prove the entire witness path with **public data and no keys**: take the frontier
before block 1156849, append exactly the five commitments that block added, and
the resulting Merkle root must equal the frontier reported after it.

Three things have to be right at once for that to hold, and each fails silently
on its own — the frontier parse, the byte order of lightwalletd's `cmu` values,
and appending in block/transaction/output order. None of them surfaces earlier
than the daemon rejecting a finished proof. See
`crates/verus-flows/tests/shielded_scan.rs`.

## The cross-check these two fixtures make possible

`gettreestate.bin` and `getblockrange.bin` both state the size of the commitment
tree at height 1156848, by completely different routes:

- `GetTreeState` serializes a Merkle **frontier**; the leaf count has to be
  derived from which slots are filled — one leaf per level-0 slot, `2^(i+1)` per
  filled parent at level `i`.
- `GetBlockRange` reports `chainMetadata.saplingCommitmentTreeSize` as a plain
  varint.

Both say **3099**. Nothing is shared between the two code paths, so agreement is
real evidence rather than a tautology — and this number *is* the absolute
position the next commitment takes. Off by one and a note's witness still builds,
still proves, still costs a fee, and is rejected as
`bad-txns-shielded-requirements-not-met`.

## Recapturing

Needs a lightwalletd with a grpc-web proxy in front of it. Requests are trivial
to build by hand: a grpc-web frame is a zero byte, a big-endian `u32` length, and
the protobuf message.

```sh
ssh -N -L 8080:127.0.0.1:8080 <host>
printf '\x00\x00\x00\x00\x00' | curl -s --data-binary @- \
  -H 'Content-Type: application/grpc-web+proto' \
  http://127.0.0.1:8080/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock
```

Heights are baked into the assertions, so recapturing at a different height means
updating `crates/verus-light/tests/fixtures.rs` with it.

## Not captured, and why

Errors have **empty bodies**. lightwalletd reports a failure as a trailers-only
response: HTTP 200, no frames at all, and `Grpc-Status` among the HTTP *headers*.
A zero-byte fixture would assert nothing, so that path is covered by
`tests/hostile_server.rs` instead, which can construct the headers a file cannot
carry. It is the single most important case in the suite: a client reading only
trailer frames sees an empty body and reports **zero blocks**, which for
`GetBlockRange` is indistinguishable from "no shielded activity here".
