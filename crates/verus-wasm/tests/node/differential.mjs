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

/** VRSCTEST's own currency id, and an identity this repo registered on it. */
const VRSCTEST = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";
const IDENTITY = "iL9bcBmaR6YF37UfrPdkAxVwXwAG72xebm";
const SIGNED_AT = 1169587;

/** A complete, valid verification request for `key`. */
const verifyBase = (key, message = "log me in") => ({
  identity: IDENTITY,
  systemId: VRSCTEST,
  message,
  signature: key.signMessage({
    identity: IDENTITY, systemId: VRSCTEST, blockHeight: SIGNED_AT, message,
  }),
  primaryAddresses: [key.address()],
  minimumSignatures: 1,
  currentHeight: SIGNED_AT + 5,
  maxAgeBlocks: 60,
});

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
  const utxo = {
    txid: vector.utxos[0].txid, vout: vector.utxos[0].vout,
    satoshis: String(vector.utxos[0].satoshis), scriptPubKey: vector.utxos[0].script_pubkey,
  };
  const base = {
    utxos: [utxo],
    recipients: [{ address: vector.outputs[0].address, satoshis: "50000000" }],
    changeAddress: vector.change_address,
  };
  const tokenBase = {
    utxos: [utxo],
    recipients: [{ address: vector.change_address, currency: VRSCTEST, amount: "1" }],
    changeAddress: vector.change_address,
  };
  const signBase = {
    identity: IDENTITY, systemId: VRSCTEST, blockHeight: 1169587, message: "hello",
  };
  const throws = (name, fn, predicate, why) =>
    assert.throws(fn, predicate ?? ((e) => e instanceof Error), why ?? name);

  // A float amount must throw, not round. The single most important refusal.
  throws("number amount", () => key.send({ ...base, recipients: [{ address: vector.outputs[0].address, satoshis: 5e7 }] }));
  ok("a `number` amount is refused rather than rounded");

  // A number where a string belongs must throw an Error, not trap the module.
  // A release build has no `typeof` guard, so this used to be
  // `RuntimeError: memory access out of bounds` — with no `.name` to branch on
  // and, for parseCoins, on the single likeliest caller mistake there is.
  for (const [name, call] of [
    ["parseCoins(1.1)", () => parseCoins(1.1)],
    ["formatCoins(1)", () => formatCoins(1)],
    ["Key.fromWif(123)", () => Key.fromWif(123)],
    ["Key.fromSeedPhrase(1)", () => Key.fromSeedPhrase(1)],
    ["decodeOutput(123)", () => decodeOutput(123)],
    ["vdxfKey(1,2,3)", () => vdxfKey(1, 2, 3)],
    ["rootNamespace(1)", () => rootNamespace(1)],
    ["identityId(1,null)", () => identityId(1, null)],
    ["signatureBlockHeight(1)", () => signatureBlockHeight(1)],
    ["parseCoins(null)", () => parseCoins(null)],
    ["parseCoins(['1'])", () => parseCoins(["1"])],
  ]) {
    throws(name, call, (e) => e.name === "InvalidArgument", `${name} must throw a named Error`);
  }
  // …and the module is still usable afterwards, not left in a trapped state.
  assert.equal(parseCoins("1.1"), "110000000");
  ok("a non-string argument throws a named Error instead of trapping the module");

  // A mistyped OPTIONAL field must fail on EVERY entry point. `expiryHieght`
  // deserialized as "no expiry": a valid, signed transaction minable for the
  // rest of the chain's life. Only `send` was covered before, and dropping the
  // guard from `sendToken` left every test green.
  throws("send", () => key.send({ ...base, expiryHieght: 1170000 }),
    (e) => e.name === "UnknownField" && /expiryHieght/.test(e.message));
  throws("sendToken", () => key.sendToken({ ...tokenBase, expiryHieght: 1170000 }),
    (e) => e.name === "UnknownField" && /expiryHieght/.test(e.message));
  throws("signMessage", () => key.signMessage({ ...signBase, blockHieght: 1 }),
    (e) => e.name === "UnknownField" && /blockHieght/.test(e.message));
  throws("verifyMessage", () => verifyMessage({ ...verifyBase(key), maxAgeBlock: 60 }),
    (e) => e.name === "UnknownField" && /maxAgeBlock/.test(e.message));
  ok("every entry point refuses a mistyped optional field");

  // Proof it is not merely rejecting everything: the correct spelling works and
  // produces a DIFFERENT transaction from the one with no expiry.
  assert.notEqual(key.send({ ...base, expiryHeight: 1170000 }).hex, key.send(base).hex);
  ok("the field the typo targeted really does change the transaction");

  // A stray key inside a NESTED object. `currency` on a native recipient is
  // what a caller writes when they meant `sendToken`; it used to be dropped,
  // and native coins moved instead.
  throws("nested recipient", () => key.send({
    ...base,
    recipients: [{ ...base.recipients[0], currency: VRSCTEST }],
  }), (e) => e.name === "UnknownField" && /currency/.test(e.message));
  throws("nested utxo", () => key.send({ ...base, utxos: [{ ...utxo, extra: 1 }] }),
    (e) => e.name === "UnknownField");
  ok("a stray key inside a nested object is refused too");

  // The guard must ask the same question the deserializer does. Each of these
  // hid a field from `Object.keys` while `Reflect.get` still returned it, and
  // each one restored the original bug.
  const hidden = { ...base };
  Object.defineProperty(hidden, "expiryHieght", { value: 1170000, enumerable: false });
  throws("non-enumerable", () => key.send(hidden), (e) => e.name === "UnknownField");
  throws("prototype chain", () => key.send(Object.assign(Object.create({ expiryHieght: 1 }), base)),
    (e) => e.name === "InvalidArgument");
  class Request {}
  throws("class instance", () => key.send(Object.assign(new Request(), base)),
    (e) => e.name === "InvalidArgument");
  throws("lying proxy", () => key.send(new Proxy({ ...base, expiryHeight: 1170000 },
    { ownKeys: () => Object.keys(base) })), (e) => e.name === "InvalidArgument");
  ok("a field hidden from key enumeration cannot slip past the guard");

  // The other direction: a polluted prototype must not silently SET a field.
  Object.prototype.expiryHeight = 1170000;
  try {
    throws("prototype pollution", () => key.send({ ...base }), (e) => e.name === "InvalidArgument");
  } finally {
    delete Object.prototype.expiryHeight;
  }
  ok("prototype pollution is refused, not silently applied");

  // A faithful Proxy is what Vue's `reactive()` and MobX hand you, and it must
  // keep working — the guard has to reject liars, not frameworks.
  const reactive = (o) => new Proxy(o, {
    get: (t, k, r) => { const v = Reflect.get(t, k, r); return v && typeof v === "object" ? reactive(v) : v; },
  });
  assert.equal(
    key.send(reactive({ ...base, expiryHeight: 1170000 })).hex,
    key.send({ ...base, expiryHeight: 1170000 }).hex,
    "a faithful proxy must produce identical bytes",
  );
  ok("an ordinary framework proxy still works, byte for byte");

  // `0` is how the WIRE spells "never", and how an uninitialised counter
  // spells itself. The second is far likelier here, so it is refused.
  throws("expiryHeight 0", () => key.send({ ...base, expiryHeight: 0 }),
    (e) => e.name === "InvalidExpiry");
  ok("expiryHeight 0 is refused rather than silently meaning never");

  // An absurd fee rate wrapped u64 in the size×rate estimate and came out as
  // the MINIMUM fee — silent, and in the wrong direction.
  throws("huge feePerKb", () => key.send({ ...base, feePerKb: "9223372036854775808" }),
    (e) => e.name === "FeeRateTooLarge");
  ok("a fee rate that would overflow the estimate is refused");

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
  const key = Key.fromWif(vectors.vectors[0].wif);
  const request = verifyBase(key);

  assert.equal(signatureBlockHeight(request.signature), SIGNED_AT);
  const claim = verifyMessage(request);
  assert.equal(claim.valid, true);
  assert.equal(claim.blockHeight, SIGNED_AT);
  assert.deepEqual(claim.signers, [key.address()]);
  assert.equal(claim.reason, undefined, "a pass carries no reason");
  ok("a signature made in wasm verifies in wasm");

  const tampered = verifyMessage({ ...request, message: "log me in as someone else" });
  assert.equal(tampered.valid, false, "a changed message must not verify");
  assert.equal(tampered.reason, "threshold");
  ok("a changed message does not verify");

  // The attack the height window exists for. The SIGNER picks the height, so a
  // verifier that resolves the identity at whatever height it was handed — and
  // stops — authenticates a key whose owner rotated it away. The signature here
  // is cryptographically fine and the threshold IS met; only the age refuses it.
  const stolen = key;
  const old = {
    ...request,
    signature: stolen.signMessage({
      identity: IDENTITY, systemId: VRSCTEST,
      blockHeight: request.currentHeight - 5000, message: "log me in",
    }),
  };
  const stale = verifyMessage(old);
  assert.equal(stale.valid, false, "a signature 5000 blocks old must not log anyone in");
  assert.equal(stale.reason, "stale");
  assert.deepEqual(stale.signers, [stolen.address()], "the signature itself is sound");
  ok("a signature stamped outside the window is refused, whatever its keys say");

  // And the window is a real dial, not decoration.
  assert.equal(verifyMessage({ ...old, maxAgeBlocks: 10000 }).valid, true);
  ok("widening the window accepts the same signature");

  const ahead = {
    ...request,
    signature: key.signMessage({
      identity: IDENTITY, systemId: VRSCTEST,
      blockHeight: request.currentHeight + 1, message: "log me in",
    }),
  };
  assert.equal(verifyMessage(ahead).valid, false);
  assert.equal(verifyMessage(ahead).reason, "future");
  ok("a signature stamped past the verifier's tip is refused");

  // The bound is not optional: a verifier cannot forget to pass it.
  for (const missing of ["currentHeight", "maxAgeBlocks"]) {
    const partial = { ...request };
    delete partial[missing];
    assert.throws(() => verifyMessage(partial), (e) => e instanceof Error,
      `${missing} must be required`);
  }
  ok("the height bound cannot be omitted");
  key.free();
}

// ---------------------------------------------------------------------------
// Offline derivations an app needs before it has a node.
// ---------------------------------------------------------------------------

console.log("\noffline derivation");
{
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
