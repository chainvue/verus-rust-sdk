# VDXF golden vectors

VerusPay invoices and login-consent requests/responses, byte for byte, as
`verus-typescript-primitives` produces them.

## What the oracle is — and what it is not

`fixtures/transparent/` earns its authority from `fixtures/daemon/`: a real
daemon signed those bytes, so the expectation can be checked against consensus
offline. **There is nothing equivalent behind this directory, and it would be
dishonest to imply otherwise.**

No daemon RPC validates a `VerusPayInvoice` or a `LoginConsentRequest`. They are
wallet/application-layer formats — they travel in QR codes and `x-callback-url`
deep links, never in a transaction — so no node ever sees one, let alone accepts
or rejects it. The oracle here is therefore **the deployed upstream TypeScript
implementation that real wallets interoperate with**: `VerusCoin/verus-typescript-primitives`
at `4243cd075b4f68df1ce72fd2fd9c9b18ac36767e`, which is the exact revision
`chainvue/verus-sdk` pins. That is one level weaker than daemon-proven.

CONTRIBUTING's "correctness is proven against the daemon" rule is scoped to
*consensus-touching* code, and an invoice is not that — nothing here ever reaches
a validator. The sentence that does apply is the one after it: "a test that only
checks our own output against our own expectations proves nothing." These bytes
are an independent implementation's, not ours, and agreeing with them is exactly
what makes a third-party wallet able to read an invoice this SDK writes.

One further thing worth knowing before trusting a number in here. **Upstream's
own tests contain no hardcoded vectors.** Every VDXF assertion there is a self
round-trip — `_inv.fromBuffer(inv.toBuffer())`, then compare the hex — which
proves the library is self-consistent and says nothing about what the bytes
should be. So there was nothing to copy, and these vectors were *generated*. The
upstream test matrix is reproduced case for case, the inputs are lifted verbatim
so the two can be diffed side by side, and the generator re-asserts every
round-trip upstream asserts (buffer, QR, deeplink, JSON) before writing a vector
down. A vector whose round-trip fails is never emitted.

## Regenerating

```sh
git clone https://github.com/VerusCoin/verus-typescript-primitives.git
cd verus-typescript-primitives
git checkout 4243cd075b4f68df1ce72fd2fd9c9b18ac36767e
yarn install --frozen-lockfile          # ~7s; dist/ is already committed at this pin

PRIMITIVES=$PWD NODE_PATH=$PWD/node_modules \
  node fixtures/tools/export-vdxf-vectors.cjs
```

The generator refuses to run against any other revision unless `ALLOW_UNPINNED=1`
is set, because a vector generated from an unnamed revision is a fixture that
lies about what it pins.

Unlike `fixtures/tools/export-vectors.cjs`, which needs a **built** `verus-sdk`
(`require(dist/bundle.js)`), this one requires the primitives package directly,
so there is no build step to get wrong. `NODE_PATH` is only there so a script
living in a repo with no `node_modules` can resolve `bn.js`.

Output is committed. Nothing is fetched at build or test time. Regenerate only
when a rule genuinely changes upstream, and read the byte diff rather than
rubber-stamping it: a diff here means every invoice this SDK writes has moved.

## What each vector carries

| Field | Meaning |
|---|---|
| `full_hex` | the whole serialized object: 20-byte vdxf key hash, version varint, compactSize data length, data |
| `details_hex` | `VerusPayInvoiceDetails.toBuffer()` alone — the tail of `full_hex` |
| `deeplink_payload_hex` | the bytes base64url-encoded into `deeplink_uri`. For an invoice this is `full_hex` **minus** the leading 20-byte key; for a login request it equals `full_hex` |
| `qr_string` | base64url of `full_hex` |
| `deeplink_uri` | the full `x-callback-url` string |
| `details_sha256` / `challenge_sha256` / `decision_sha256` | sha256 of the corresponding serialization |
| `*_hash_sigv1_h10000`, `*_hash_sigv2_h10000` | `getDetailsHash` / `getChallengeHash` / `getDecisionHash` at block height 10000 |
| `flags_decoded` | the ten booleans the flags word decodes to |
| `result_hex` | `ProvisioningResult.toBuffer()` alone |
| `credentials[]` | each `Credential`'s inputs beside its own hex, as carried in the decision context |

**The argument pair matters.** `getDecisionHash(10000, 1)` and
`getDecisionHash(10000, 2)` are different hashes of the same decision:
signature version 1 puts the Verus data-signature prefix first, version 2 puts
it after `signing_id`. Both are reachable from a wallet, so both are recorded
wherever upstream computes either. `ProvisioningRequest.getChallengeHash()` is a
third shape again — no height, no signature version, just
`sha256(prefix || challenge_sha256)` — so it is spelled `challenge_hash` rather
than `challenge_hash_sigvN_hNNNNN`.

**Ordering is observable.** `acceptedsystems`, `subject`, `provisioning_info`,
`redirect_uris` and `provisioning_txids` all serialize in array order. A
`Context` serializes in `Object.keys` order, i.e. insertion order, so contexts
are recorded as an **ordered array of `{key, value}`** rather than as a JSON
object — a JSON object invites a consumer to read it into a sorted map, and
`serde_json` does exactly that unless its `preserve_order` feature is on. This is
CONTRIBUTING's "where the TypeScript side relies on JavaScript `Map` insertion
order, use `IndexMap` or `Vec<(_, _)>` — never `HashMap`", applied to the fixture
rather than to the reader.

**Money and heights are decimal strings**, taken from `BN.toString(10)`. Nothing
in this file passed through a JavaScript double on its way out.

## The vectors

### VerusPay invoices

The first six cases run against **both v3 and v4**, because the version changes
the encoding rather than the fields: v3 writes its variable-length integers with
`writeVarInt` (7 bits per byte, MSB continuation) and v4 with `writeCompactSize`
(the Bitcoin `0xfd`/`0xfe`/`0xff` form). The same logical invoice is a different
byte string under each — `invoice_v3_basic` is 48 bytes of details and
`invoice_v4_basic` is 52, and the whole 4-byte difference is the amount.

| Vector | What it pins |
|---|---|
| `invoice_v3_basic` / `invoice_v4_basic` | the baseline: a fixed amount to a PKH destination, and the v3-vs-v4 varuint encoding |
| `invoice_v3_any_amount_any_destination` / `…v4…` | `acceptsAnyAmount` (32) and `acceptsAnyDestination` (16) each **suppress a field**: amount and destination are absent from the bytes, not zeroed |
| `invoice_v3_accepts_conversion` / `…v4…` | `acceptsConversion` (2) appends `maxestimatedslippage` after the currency id |
| `invoice_v3_accepts_conversion_expires` / `…v4…` | `expiryheight` is written **before** `maxestimatedslippage` even though `expires` (8) is a higher bit than `acceptsConversion` (2) — field order is not flag order |
| `invoice_v3_two_nonverus_systems_expires` / `…v4…` | `acceptsNonVerusSystems` (4) appends a counted array of 20-byte system hashes, in array order |
| `invoice_v3_signed_two_nonverus_systems_expires` / `…v4…` | the signed path: bit 31 of the version field (`0x80000003` / `0x80000004`) prepends `system_id`, `signing_id` and the signature ahead of the details, and switches `getDetailsHash` from a plain sha256 to the height-and-identity form |
| `invoice_v4_signed_sapling_destination` | **v4 only.** `destinationIsSaplingPaymentAddress` (512) swaps a 22-byte `TransferDestination` (type byte, length byte, 20-byte hash) for a **raw 43-byte** `SaplingPaymentAddress` (11-byte diversifier + 32-byte `pk_d`, no type and no length prefix) in the same field position |
| `invoice_v4_any_amount_any_destination_preconvert` | **v4 only.** `isPreconvert` (256) changes no field, only the meaning of the invoice, and `setFlags` silently drops it on v3 — so this pins that the flag survives a v4 round trip |

### Login consent

| Vector | What it pins |
|---|---|
| `login_consent_request_signed` | the signed request: `system_id`, `signing_id` and an `IDENTITY_AUTH_SIG` signature ahead of a challenge carrying both base58 subjects (serialized as 20-byte hashes) and a utf-8 one, provisioning info, a redirect uri and a context |
| `login_consent_response_signed` | the signed response, whose signature uses a **different** vdxf key than the request's (`LOGIN_CONSENT_RESPONSE_SIG`), and which embeds the whole request it answers |
| `login_consent_response_one_credential` | a `Credential` serialized to hex and carried in the decision context under its own vdxf key |
| `login_consent_response_two_credentials` | two credentials under two keys, the second with an optional `label`: the label branch, and that context keys keep insertion order |
| `provisioning_request_non_ascii_name` | the requested identity name is a single emoji — `name` is a utf-8 **byte** string behind a byte-count prefix, not a character count. Its `signing_address` is an R-address, read back with `R_ADDR_VERSION`, where a login request uses `I_ADDR_VERSION` for `signing_id` |
| `provisioning_response_result_non_ascii_fqn` | a full `ProvisioningResult` with every optional field present, two provisioning txids in order, and `"😊.vrsc"` — a fully qualified name whose first character is four bytes |

## Two traps

- **`Request.toWalletDeeplinkUri()` and `toQrString()` throw** `"Request must be
  signed before it can be used as a deep link"` when `signature` is null. Every
  request vector here therefore carries one. `Response` has neither method at
  all, which is why the response vectors have no `qr_string` or `deeplink_uri`.
- **A `VerusPayInvoice` is signed by a version bit, not by a field.**
  `setSigned()` ORs `0x80000000` into `version`; `getVersionNoFlags()` masks it
  off again for the details. Forgetting the mask reads the version as
  2147483652 and rejects the invoice as unsupported.

## Deliberately out of scope: `isTagged` and x-addresses

Upstream's v4 Sapling-destination test also sets `isTagged` (1024) and attaches a
`CompactXAddressObject.fromAddress("xA91QPpBrHZto92NCU5KEjCqRveS4dAPrf")`. **That
case is omitted here, and `invoice_v4_signed_sapling_destination` is the same
invoice without the tag.**

`X_ADDR_VERSION = 137` exists upstream, but `verus-keys`'s `AddressKind` has only
`PubKeyHash`, `Identity` and `ScriptHash`. The Rust side cannot consume an
x-address vector without first deciding what an x-address is in this SDK's public
API — what kind it becomes, what it means, whether it is constructible — and that
is a public-API decision, not a fixture decision. Generating the vectors first
would quietly settle it. Add them once `AddressKind` has an answer; the generator
has the inputs in upstream's test ready to lift.

## What must survive any regeneration

- **The v3 *and* v4 pair for all six shared cases.** Dropping either collapses
  the one difference the two versions have, and a reader that handles only
  compactSize passes the whole v4 half.
- **Both `sigv1` and `sigv2` hashes.** Recording only the default (version 2)
  leaves the version-1 ordering untested, and it is the one a wallet reaches
  when verifying an older signature.
- **`"😊"` and `"😊.vrsc"` exactly.** Replacing them with ASCII turns the
  byte-count-vs-character-count test green for the wrong reason.
- **`amount: "10000000000"` as a string.** It is 100 coins in satoshis; the
  moment it becomes a JSON float the fixture stops being able to catch the bug
  it exists for.
- **Array and context order.** Re-sorting any of them silently changes what the
  expected bytes mean.
