// The wasm bindings, driven from JavaScript, against the TypeScript SDK's
// own bytes.
//
// Every other test in this crate runs on the host, where `wasm-bindgen` is
// inert: the DTO conversions are exercised but the *binding* — the generated
// glue, the JsValue marshalling, the thrown Error — is not. Those are exactly
// the parts a Rust test cannot reach, and the parts a JavaScript caller only
// ever touches. So this runs under plain `node`, on a real compiled module.
//
// The oracle is `fixtures/transparent/vectors.json`: transactions built by
// @chainvue/verus-sdk, which is daemon-proven and signs deterministically.
// Matching them byte for byte means a browser calling `key.send(…)` produces
// what a daemon has already accepted — not merely something well-formed.
//
// Run:  node crates/verus-wasm/tests/node/differential.mjs <path-to-pkg>

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import assert from "node:assert/strict";

const here = dirname(fileURLToPath(import.meta.url));
const pkg = process.argv[2] ?? resolve(here, "../../pkg");
const wasm = await import(resolve(pkg, "verus_wasm.js"));
const { Key, parseCoins, formatCoins, satsPerCoin, decodeOutput, verifyMessage,
        signatureBlockHeight, vdxfKey, rootNamespace, identityId } = wasm;

const vectors = JSON.parse(
  readFileSync(resolve(here, "../../../../fixtures/transparent/vectors.json"), "utf8"),
);

let checks = 0;
const ok = (name) => { checks += 1; console.log(`  ok  ${name}`); };

// ---------------------------------------------------------------------------
// The differential: the whole vector file, through the bindings.
// ---------------------------------------------------------------------------

console.log(`\n${vectors.vectors.length} transparent vectors from ${vectors.source}`);

for (const vector of vectors.vectors) {
  const key = Key.fromWif(vector.wif);
  const utxos = vector.utxos.map((u) => ({
    txid: u.txid,
    vout: u.vout,
    satoshis: String(u.satoshis),
    scriptPubKey: u.script_pubkey,
  }));
  // The fixture spells "never expires" as height 0, the way the wire does; the
  // binding spells it as an absent field, so that a caller has to mean it.
  const expiryHeight = vector.expiry_height === 0 ? null : vector.expiry_height;
  const tokenVector = vector.outputs.some((o) => o.currency !== null);

  const signed = tokenVector
    ? key.sendToken({
        utxos,
        recipients: vector.outputs.map((o) => ({
          address: o.address,
          currency: o.currency,
          amount: String(o.satoshis),
        })),
        changeAddress: vector.change_address,
        expiryHeight,
      })
    : key.send({
        utxos,
        recipients: vector.outputs.map((o) => ({
          address: o.address,
          satoshis: String(o.satoshis),
        })),
        changeAddress: vector.change_address,
        expiryHeight,
      });

  assert.equal(signed.hex, vector.expected_signed_hex, `${vector.name}: signed hex`);
  assert.equal(signed.txid, vector.expected_txid, `${vector.name}: txid`);
  assert.equal(signed.fee, String(vector.expected_fee), `${vector.name}: fee`);
  assert.equal(signed.change, String(vector.expected_change), `${vector.name}: change`);
  // The fixture records how MANY inputs the TypeScript SDK selected; the
  // binding reports which ones. Both are checked: the count against the
  // oracle, and the identity of each against the UTXOs that were offered —
  // which is the part the count alone would not catch.
  assert.equal(
    signed.inputsUsed.length,
    vector.expected_inputs_used,
    `${vector.name}: number of inputs selected`,
  );
  for (const input of signed.inputsUsed) {
    assert.ok(
      utxos.some((u) => u.txid === input.txid && u.vout === input.vout),
      `${vector.name}: reported an input that was never offered`,
    );
  }
  ok(`${vector.name} — ${vector.why}`);
  key.free();
}

// ---------------------------------------------------------------------------
// The shape of what comes back. A `Map` would pass every Rust test and be
// unusable from JavaScript, so it is asserted where it matters.
// ---------------------------------------------------------------------------

console.log("\nreturn shapes");
{
  const vector = vectors.vectors[0];
  const key = Key.fromWif(vector.wif);
  const signed = key.send({
    utxos: vector.utxos.map((u) => ({
      txid: u.txid, vout: u.vout,
      satoshis: String(u.satoshis), scriptPubKey: u.script_pubkey,
    })),
    recipients: [{ address: vector.outputs[0].address, satoshis: String(vector.outputs[0].satoshis) }],
    changeAddress: vector.change_address,
  });
  assert.equal(Object.getPrototypeOf(signed), Object.prototype, "a plain object, not a Map");
  assert.deepEqual(
    Object.keys(signed).sort(),
    ["change", "fee", "hex", "inputsUsed", "txid"],
    "destructurable fields",
  );
  assert.equal(JSON.parse(JSON.stringify(signed)).txid, signed.txid, "survives JSON round trip");
  ok("a signed transaction is a plain, destructurable, serializable object");
  key.free();
}

// ---------------------------------------------------------------------------
// Money. The reason every amount in this API is a string.
// ---------------------------------------------------------------------------

console.log("\nmoney");
{
  assert.equal(parseCoins("1.1"), "110000000");
  assert.equal(parseCoins("0.00000001"), "1");
  assert.equal(formatCoins("110000000"), "1.1");
  assert.equal(satsPerCoin(), "100000000");
  ok("coins and satoshis convert exactly");

  // Where the usual JavaScript bridge actually breaks. It is not the rounding
  // of small amounts — `Math.round(coins * 1e8)` gets those right, and saying
  // otherwise would be scaremongering. It is MAGNITUDE: a satoshi count above
  // 2^53 cannot be held by a float64 at all, and 90 million coins is not a
  // hypothetical number on a chain whose supply cap is 83.5 million.
  assert.equal(parseCoins("90071992.54740993"), "9007199254740993");
  assert.equal(Math.round(Number("90071992.54740993") * 1e8), 9007199254740994);
  ok("a large amount survives here and is off by a satoshi through a float");

  // And the same trap on the way back: reading a satoshi count into a `number`
  // silently loses it, which is why every amount leaves this API as a string.
  assert.equal(Number("9007199254740993"), 9007199254740992);
  assert.equal(formatCoins("9007199254740993"), "90071992.54740993");
  ok("a satoshi count is returned as a string because a number would lose it");

  // A bigint is the intended way to do arithmetic and hand a value back.
  const total = BigInt(parseCoins("1.1")) + BigInt(parseCoins("2.2"));
  assert.equal(formatCoins(total.toString()), "3.3");
  ok("a bigint round-trips through the API");
}

console.log("\nrefusals");
{
  const vector = vectors.vectors[0];
  const key = Key.fromWif(vector.wif);
  const base = {
    utxos: vector.utxos.map((u) => ({
      txid: u.txid, vout: u.vout,
      satoshis: String(u.satoshis), scriptPubKey: u.script_pubkey,
    })),
    recipients: [{ address: vector.outputs[0].address, satoshis: "50000000" }],
    changeAddress: vector.change_address,
  };

  // A float amount must throw, not round. This is the single most important
  // refusal in the whole binding.
  assert.throws(
    () => key.send({ ...base, recipients: [{ address: vector.outputs[0].address, satoshis: 5e7 }] }),
    (e) => e instanceof Error,
    "a number amount must be refused",
  );
  ok("a `number` amount is refused rather than rounded");

  // A mistyped OPTIONAL field must fail, not be ignored. This is the one
  // serde's `deny_unknown_fields` does not catch under serde-wasm-bindgen, and
  // it is the dangerous one: `expiryHieght` deserializes as "no expiry", so the
  // transaction is valid, signed, and minable for the rest of the chain's life.
  assert.throws(
    () => key.send({ ...base, expiryHieght: 1170000 }),
    (e) => e.name === "UnknownField" && /expiryHieght/.test(e.message),
    "a transposed optional field must be refused",
  );
  // Proof it is not merely rejecting everything: the correct spelling works,
  // and produces a DIFFERENT transaction from the one with no expiry.
  assert.notEqual(
    key.send({ ...base, expiryHeight: 1170000 }).hex,
    key.send(base).hex,
    "the field the typo targeted really does change the transaction",
  );
  ok("a mistyped optional field is refused, not silently ignored");

  // A typo in a NESTED object is caught a different way — every nested field
  // is required, so a misspelling reads as a missing one. Asserted because the
  // key check above only covers the top level, and the scope of a guarantee
  // should be tested, not assumed.
  assert.throws(
    () => key.send({
      ...base,
      utxos: [{ ...base.utxos[0], scriptPubkey: base.utxos[0].scriptPubKey, scriptPubKey: undefined }],
    }),
    (e) => e instanceof Error,
    "a misspelled required field must be refused",
  );
  ok("a misspelled nested field is caught as a missing required one");

  // The error carries a machine-readable cause.
  try {
    key.send({ ...base, recipients: [{ address: vector.outputs[0].address, satoshis: "99999999999" }] });
    assert.fail("should have thrown");
  } catch (e) {
    assert.ok(e instanceof Error, "a real Error");
    assert.equal(e.name, "InsufficientFunds", `e.name carries the cause, got ${e.name}`);
    assert.match(e.message, /satoshis/);
  }
  ok("a thrown Error names its cause in `.name`");
  key.free();
}

// ---------------------------------------------------------------------------
// Log in with Verus: sign in the browser, verify against the chain's answer.
// ---------------------------------------------------------------------------

console.log("\nlogin");
{
  const VRSCTEST = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";
  const identity = "iL9bcBmaR6YF37UfrPdkAxVwXwAG72xebm";
  const key = Key.fromWif(vectors.vectors[0].wif);
  const request = {
    identity, systemId: VRSCTEST, blockHeight: 1169587, message: "log me in",
  };
  const signature = key.signMessage(request);

  assert.equal(signatureBlockHeight(signature), 1169587);
  const claim = verifyMessage({
    identity, systemId: VRSCTEST, message: "log me in", signature,
    primaryAddresses: [key.address()], minimumSignatures: 1,
  });
  assert.equal(claim.valid, true);
  assert.equal(claim.blockHeight, 1169587);
  assert.deepEqual(claim.signers, [key.address()]);
  ok("a signature made in wasm verifies in wasm");

  const tampered = verifyMessage({
    identity, systemId: VRSCTEST, message: "log me in as someone else", signature,
    primaryAddresses: [key.address()], minimumSignatures: 1,
  });
  assert.equal(tampered.valid, false, "a changed message must not verify");
  ok("a changed message does not verify");
  key.free();
}

// ---------------------------------------------------------------------------
// Offline derivations an app needs before it has a node.
// ---------------------------------------------------------------------------

console.log("\noffline derivation");
{
  const VRSCTEST = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";
  assert.equal(vdxfKey("test", "VRSCTEST", VRSCTEST), "i67adKXncRAtgsmoZpSCRA6iba5U7SPgF4");
  assert.equal(rootNamespace("vrsc"), "i5w5MuNik5NtLcYmNzcvaoixooEebB6MGV");
  assert.equal(identityId("rusttok1168500", VRSCTEST), "iKzX5FyzKzYxtcWKYveYKVfrz2LNXLj4xM");
  ok("VDXF keys and identity ids match the daemon");

  const key = Key.fromWif(vectors.vectors[0].wif);
  const decoded = decodeOutput(key.scriptPubKey());
  assert.equal(decoded.kind, "pubKeyHash");
  assert.equal(decoded.address, key.address());
  ok("an output decodes to the address it pays");
  key.free();
}

// ---------------------------------------------------------------------------
// The key handle.
// ---------------------------------------------------------------------------

console.log("\nkey handling");
{
  const key = Key.fromWif(vectors.vectors[0].wif);
  assert.equal(key.toWif(), vectors.vectors[0].wif, "WIF round trip");
  key.free();
  // After free the handle is dead; using it must throw rather than read freed
  // memory. This is what makes `free()` safe to call on lock.
  assert.throws(() => key.address(), /null pointer|moved|freed/i);
  ok("a freed key cannot be used");

  const entropy = new Uint8Array(32).fill(7);
  const generated = Key.fromEntropy(entropy);
  assert.match(generated.address(), /^R/);
  generated.free();
  assert.throws(() => Key.fromEntropy(new Uint8Array(31)), /32 bytes/);
  ok("a key is made from entropy the caller supplies");
}

console.log(`\n${checks} checks passed under node ${process.version}\n`);
