# Capturing currency-definition vectors

`definecurrency` **does not broadcast**. It returns `{tx, hex}` with no `txid`,
and the mempool stays empty afterwards — so an unlimited number of permutations
costs nothing once one identity is funded. That is what made
`currency_definitions.json` cheap to produce, and it is the thing to know before
assuming each vector costs the 200 VRSCTEST `currencyregistrationfee`.

## What it does need

The identity the currency is named after must **hold the funds itself**:

```
Insufficient funds held by <name> identity.
```

So send the fee to the *identity address*, not to a wallet address, and wait for
a confirmation. 205 VRSCTEST was enough for every case here. Nothing is spent
unless the returned hex is broadcast.

```sh
verus -chain=VRSCTEST definecurrency '{
  "name":"some-identity-with-no-currency",
  "options":32, "proofprotocol":1,
  "idregistrationfees":1.0, "idreferrallevels":0
}'
```

## Options bits (non-PBaaS)

| bit | meaning |
|---|---|
| `0x01` | FRACTIONAL — needs `currencies`, `weights`, `initialsupply` |
| `0x02` | IDRESTRICTED |
| `0x04` | IDSTAKING |
| `0x08` | IDREFERRALS |
| `0x10` | IDREFERRALSREQUIRED |
| `0x20` | TOKEN |
| `0x100` | IS_PBAAS_CHAIN — deliberately **not** covered here |

`proofprotocol` 2 makes the currency mintable by whoever controls the identity.

## Gotchas

- A preallocation target must be written `name@`, not `name`, or it fails with
  *"attempting to pre-allocate currency to a non-existent ID"*.
- The identity must have no active currency already: check `flags & 1`.
- Defining a currency permanently consumes that name for currency use **once
  broadcast**. Nothing here was broadcast.
