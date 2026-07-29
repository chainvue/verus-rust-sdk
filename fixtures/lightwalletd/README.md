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
| `gettreestate.bin` | `GetTreeState(1156848)` | a serialized Sapling frontier: 206 bytes, 3099 leaves |
| `getblockrange.bin` | `GetBlockRange(1156847, 1156850)` | four blocks, two of them empty, five nullifiers, `chainMetadata` |

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
