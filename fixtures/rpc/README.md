# Recorded RPC replies

Verbatim bodies captured from `https://api.verustest.net`, committed so the
parsers are tested against bytes the network actually produced rather than
against a mock written from documentation. Same reasoning as `fixtures/daemon/`.

Regenerate one with:

```sh
curl -s -X POST https://api.verustest.net -H 'content-type: application/json' \
  --data '{"method":"getcurrency","params":["VRSCTEST"],"id":"c"}' \
  > fixtures/rpc/getcurrency_vrsctest.json
```

Three things must survive any regeneration, or the tests they support stop
meaning anything:

- **`getcurrency_vrsctest.json` must keep `"idregistrationfees":100.0`
  literally.** A fee arrives from the daemon in *coins*, as a JSON float, while
  the builders take satoshis. That token is the whole reason `json.rs` exists;
  if a regeneration rewrites it to `100` or `10000000000`, the exactness test
  passes for the wrong reason.
- **`getoffers_mainnet_vrsc.json` must keep an offer side with more than one
  currency and a `1e-8` amount.** Both shapes are absent from VRSCTEST
  entirely, so a reader that assumes one currency per side, or refuses
  exponent form, passes every testnet fixture and fails on the chain with the
  volume. Both files are trimmed by hand to a few representative entries; the
  full replies are 96 KB and 671 KB.
- **The `err_*.json` files must keep their exact shape** — in particular that an
  error reply carries **no `result` key at all**, rather than `result: null`.
  That is what breaks the obvious `struct { result: T, error: Option<E> }`.

| File | What it pins |
|---|---|
| `getinfo.json` | chain name, id, height |
| `getcurrency_vrsctest.json` | the `100.0` coins literal, referral levels, proofprotocol |
| `getaddressutxos_funded.json` | outputs with `satoshis`, `height`, `isspendable` |
| `getaddressutxos_empty.json` | an address with nothing — the empty array |
| `getaddressutxos_second_address.json` | a second funded address |
| `getidentity_rustsdk.json` | an identity and the outpoint holding it |
| `err_notfound.json` | `-5`, unknown identity |
| `err_badparam.json` | `-1`, with a long help-text message |
| `err_baddecode.json` | `-22`, `sendrawtransaction` refusing bad hex |
| `err_methodmissing.json` | `-32601` — "refused", which is not the same as "absent"; see below |
| `getaddressbalance.json` | the same balance in satoshis *and* in coins, in one reply |
| `getoffers_vrsctest.json` | the three bucket shapes, an identity on **either** side, and `tx` alongside `txid` |
| `getoffers_mainnet_vrsc.json` | an offer side naming several currencies, with a `1e-8` leg — shapes VRSCTEST has none of |
| `estimatefee.json` | a fee rate as `1e-6` — the exponent literal the money readers grew an expander for |
| `listcurrencies_vrsctest.json` | the root chain (no `parent`), a fractional basket, a token |
| `getcurrencyconverters_vrsctest.json` | an entry whose definition hides under a key that is its own currency id |
| `getidentitycontent_rustsdk.json` | an identity's `contentmap`, published by this SDK at block 1166566 |
| `getaddressdeltas.json` | signed movements — a spend row, a token leg with `satoshis` of zero, and the settled swap's economics |
| `getaddressmempool.json` | an **unconfirmed** transaction: a spend row naming its prevout, two receives, and an `index` of 0 on both a receive and a spend |
| `getaddressmempool_verbose.json` | the same call with `verbosity: 1`, kept to show what it does *and does not* add |

## `-32601` is not proof a method is missing

The endpoint is a filtering proxy and its allowlist is **arity-sensitive**:

```sh
# Served.
--data '{"method":"getblock","params":[1166308],"id":"c"}'
# Same method, refused as "Method not found".
--data '{"method":"getblock","params":[1166308,1],"id":"c"}'
```

An availability table built by probing with a convenient argument count will be
wrong. This one was: `getblock` was recorded as absent, and it is not — which
means a block's Sapling commitments *are* enumerable through the public node
after all. `z_gettreestate` is genuinely gone at every arity, and
`getsaplingtree` answers only for the tip whatever height it is given.

## What `getaddressmempool`'s `verbosity` actually changes

The daemon's help describes `verbosity: 1` as adding "output information for
spends, including all reserve amounts and destinations", which reads as though
per-currency values were behind it. They are not — compare the two fixtures:
`currencyvalues` and `currencynames` are in the plain reply, so a token transfer
in flight is visible without asking for anything.

What `verbosity: 1` adds is a `sent` object on **spend** rows, naming the other
addresses that spent output paid:

```json
"sent": { "outputs": [ { "addresses": "RJ7gs…", "amounts": { "iJhC…": 4.8998 } } ] }
```

That is information about someone else's outputs. `verus-rpc` does not ask for
it: it is not needed to see that money is moving, it makes every reply larger,
and it puts one more option in a request whose arity the proxy is already picky
about.

Both fixtures are from the same live pending transaction, captured on
2026-08-05 before it was mined. It is not this SDK's transaction — it was
somebody else's, in flight at the right moment, which is why it is the only
shape of this reply that has been seen here at all.
