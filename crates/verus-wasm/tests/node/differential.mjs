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
const { Key, Answers, planHistory, planVerifyLogin, planSpendable, planContent,
        planContentHistory, planOffers, planOfferTerms, planCommitmentStatus, parseCoins, formatCoins, satsPerCoin, decodeOutput,
        tokenBalances, verifyMessage, signatureBlockHeight, vdxfKey,
        rootNamespace, identityId, validateMnemonic, mnemonicToSeed } = wasm;

const vectors = JSON.parse(
  readFileSync(resolve(here, "../../../../fixtures/transparent/vectors.json"), "utf8"),
);

let checks = 0;
const ok = (name) => { checks += 1; console.log(`  ok  ${name}`); };

/**
 * Every output script in a v4 transaction, hex.
 *
 * Written out rather than pattern-matched on the hex: scanning for a byte run
 * cannot tell the identity body from the CryptoCondition wrapper that repeats
 * parts of it, and that difference is exactly what the erase invariant is
 * about. The layout is fixed — version(4) versionGroupId(4), varint inputs,
 * varint outputs of value(8) + varint script.
 */
function outputScripts(hex) {
  const raw = Buffer.from(hex, "hex");
  let at = 8;
  const varint = () => {
    const first = raw[at];
    at += 1;
    if (first < 0xfd) return first;
    if (first === 0xfd) { const v = raw.readUInt16LE(at); at += 2; return v; }
    if (first === 0xfe) { const v = raw.readUInt32LE(at); at += 4; return v; }
    const v = Number(raw.readBigUInt64LE(at)); at += 8; return v;
  };
  const inputs = varint();
  for (let i = 0; i < inputs; i += 1) {
    at += 36;                          // outpoint
    // NOT `at += varint()`: JavaScript reads the left operand before calling
    // the right, so the varint's own byte advance would be thrown away.
    const scriptSig = varint();
    at += scriptSig;
    at += 4;                           // sequence
  }
  const outputs = varint();
  const scripts = [];
  for (let i = 0; i < outputs; i += 1) {
    at += 8;                           // value
    const len = varint();
    scripts.push(raw.subarray(at, at + len).toString("hex"));
    at += len;
  }
  return scripts;
}

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
  // and native coins moved instead. Covered on BOTH send paths: removing the
  // nested shape from `TokenSendRequest` alone left the whole gate green.
  throws("nested recipient", () => key.send({
    ...base,
    recipients: [{ ...base.recipients[0], currency: VRSCTEST }],
  }), (e) => e.name === "UnknownField" && /currency/.test(e.message));
  throws("nested utxo", () => key.send({ ...base, utxos: [{ ...utxo, extra: 1 }] }),
    (e) => e.name === "UnknownField");
  throws("nested token recipient", () => key.sendToken({
    ...tokenBase,
    recipients: [{ ...tokenBase.recipients[0], satoshis: "1" }],
  }), (e) => e.name === "UnknownField" && /satoshis/.test(e.message));
  throws("nested token utxo", () => key.sendToken({ ...tokenBase, utxos: [{ ...utxo, extra: 1 }] }),
    (e) => e.name === "UnknownField");
  ok("a stray key inside a nested object is refused on both send paths");

  // The error must say WHICH entry, not merely that one was bad.
  try {
    key.send({ ...base, utxos: [utxo, { ...utxo, extra: 1 }] });
    assert.fail("should have thrown");
  } catch (e) {
    assert.match(e.message, /utxos\[1\]\.extra/, `the position must be named, got: ${e.message}`);
  }
  ok("a stray key names its position, not just its name");

  // Depth must not be the caller's to choose. A `utxos` nested a few thousand
  // arrays deep used to overflow the wasm stack — not into a catchable error
  // but into an uncatchable trap that left the stack pointer corrupt, so every
  // later call to ANY export failed the same way and the module was dead for
  // the life of the page. `utxos` is filled from JSON a wallet did not author.
  {
    let deep = base.utxos;
    for (let i = 0; i < 20000; i++) deep = [deep];
    assert.throws(() => key.send({ ...base, utxos: deep }), (e) => e instanceof Error);
    // The assertion that matters is the next one: the module survived.
    assert.equal(parseCoins("1.1"), "110000000", "the module was bricked by a deep input");
    assert.equal(
      key.send({ ...base, expiryHeight: 1170000 }).hex,
      key.send({ ...base, expiryHeight: 1170000 }).hex,
      "signing still works after a deep input",
    );
  }
  ok("a deeply nested input is refused without poisoning the module");

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

  // Token balances, off the same fixture the token differential uses: its
  // UTXOs carry a real reserve output, so this counts something real.
  const tokenVector = vectors.vectors.find((v) => v.outputs.some((o) => o.currency !== null));
  const utxos = tokenVector.utxos.map((u) => ({
    txid: u.txid, vout: u.vout,
    satoshis: String(u.satoshis), scriptPubKey: u.script_pubkey,
  }));
  const held = tokenBalances(utxos, null);
  assert.ok(held.length > 0, "the token fixture must carry a token");
  for (const entry of held) {
    assert.match(entry.currency, /^i/, "a currency is named by its i-address");
    assert.match(entry.amount, /^[0-9]+$/, "an amount is a decimal string");
    // The native satoshis a reserve output also carries are NOT token value.
    assert.notEqual(entry.amount, String(tokenVector.utxos[0].satoshis));
  }
  assert.deepEqual(tokenBalances([], null), [], "no outputs, no balances");
  assert.deepEqual(
    tokenBalances([{ txid: "aa".repeat(32), vout: 0, satoshis: "1", scriptPubKey: key.scriptPubKey() }], null),
    [],
    "a plain output carries no currency",
  );
  ok("token balances are counted from the outputs, native value excluded");

  // An output this SDK cannot decode may carry currency it cannot see, so a
  // balance must not be reported at all rather than reported short.
  const opaque = "4c0f" + "00".repeat(15);
  assert.throws(
    () => tokenBalances([{ txid: "bb".repeat(32), vout: 2, satoshis: "1", scriptPubKey: opaque }], null),
    (e) => e instanceof Error,
    "an unreadable output must not be counted as zero",
  );
  assert.throws(() => tokenBalances({ txid: "aa" }, null), (e) => e.name === "InvalidArgument",
    "a single object is not a list of outputs");
  ok("an output that cannot be read refuses the whole balance");

  // …but "cannot be read" must stay narrow. A proof-of-stake coinbase pays a
  // stakeguard CryptoCondition, and refusing that refused a balance to every
  // staking address. The chain's own `CScript::ReserveOutValue` never reads
  // currency out of eval code 1, so it counts as zero — cross-checked against
  // `decodescript` on api.verustest.net, which reports no reserve for it.
  //
  // Real script: block 1170103 on VRSCTEST, coinbase vout 0.
  const stakeguard =
    "3d04030001021504d72c764548836ae9e1784b54afed2c1f1061bd532103166b7813a4855a88e9ef7340a692ef" +
    "3c2decedfdc2c7563ec79537e89667d935cc4c8704030101011504d72c764548836ae9e1784b54afed2c1f1061" +
    "bd5343010000a659dcb60845f0ea2f48a9a5513cd90ab986fd670d8644f52fcc153478260efdd114a32487649a" +
    "ababf8c747cb6733b6c69da63362cd6f226fead874010000002704030101012103166b7813a4855a88e9ef7340" +
    "a692ef3c2decedfdc2c7563ec79537e89667d93575";
  const staked = decodeOutput(stakeguard);
  assert.equal(staked.kind, "unsupportedCryptoCondition");
  assert.equal(staked.evalCode, 1);
  assert.equal(staked.mayCarryCurrency, false, "a stakeguard output holds no currency");
  assert.deepEqual(
    tokenBalances([{ txid: "cc".repeat(32), vout: 0, satoshis: "600000000", scriptPubKey: stakeguard }], null),
    [],
    "a staker must get a balance, not an exception",
  );
  ok("a proof-of-stake coinbase counts as tokenless instead of refusing the balance");

  // The same script with the eval code changed to 13 (EVAL_CROSSCHAIN_IMPORT),
  // the one remaining code the chain reads currency out of and this SDK does
  // not decode. The refusal has to survive for it, or narrowing the refusal
  // turned into removing it.
  const importing = stakeguard.replace("cc4c870403010101", "cc4c8704030d0101");
  assert.notEqual(importing, stakeguard, "the eval code must actually have changed");
  const bearing = decodeOutput(importing);
  assert.equal(bearing.evalCode, 13);
  assert.equal(bearing.mayCarryCurrency, true);
  assert.throws(
    () => tokenBalances([{ txid: "dd".repeat(32), vout: 0, satoshis: "1", scriptPubKey: importing }], null),
    (e) => e instanceof Error,
    "an eval code that can hold currency still refuses the whole balance",
  );
  ok("an eval code that can hold currency is still refused");

  // Tokens held by a VerusID. `decodescript` on api.verustest.net reports this
  // exact script as paying i6api8faWPZjATwXGSuXZvsv5AtXN689KH and holding 0.4
  // shylock; the decoder used to refuse it and lose an identity's holdings.
  const identityHeld =
    "1b0403000101150422194b8b56f7ce20f0d6bbde491e3ed37f15d5bbcc3504030901011504" +
    "22194b8b56f7ce20f0d6bbde491e3ed37f15d5bb1901e908e3e5c373389fa7ae5d4b22a87f" +
    "fc204a74ff9288b30075";
  const owned = decodeOutput(identityHeld);
  assert.equal(owned.kind, "reserveOutput");
  assert.equal(owned.address, "i6api8faWPZjATwXGSuXZvsv5AtXN689KH",
    "an identity destination must not be rendered as an R address nobody controls");
  assert.deepEqual(owned.tokens, [{ currency: "iQihXUcQt8G9TSh58YoM5NRwC1nAyoazFR", amount: "40000000" }]);
  assert.deepEqual(
    tokenBalances([{ txid: "ee".repeat(32), vout: 1, satoshis: "0", scriptPubKey: identityHeld }], null),
    [{ currency: "iQihXUcQt8G9TSh58YoM5NRwC1nAyoazFR", amount: "40000000" }],
  );
  assert.equal(formatCoins(owned.tokens[0].amount), "0.4", "the daemon reads the same 0.4");
  ok("tokens held by a VerusID are read and counted");

  // Several currencies in one output. Real script: output 10 of
  // 9d0859212eb5dd5bbcd5d8a171e8e0080e16d5629ed84bd596573aae9b086443 on
  // VRSCTEST, which getrawtransaction reports as holding these nine.
  const multivalue =
    "1b040300010115040d70e777403b2fa1e52b09853be00beb8ac88762cc4d200104030901011504" +
    "0d70e777403b2fa1e52b09853be00beb8ac887624d020186fefeff010944a25b3d593e0bb4f0b7" +
    "00b98d3c625c891a61bf00076b7a070700004aa2555d465e133e03c7e084177b21d32373717100" +
    "48c66fefa00a006ac68d215ec4da6375ca23b89f211c810881b83a0048c66fefa00a0074c096ce" +
    "2c9a09f237b0b512cfe3e71579ab03b70048c66fefa00a0084d881e355c1c87dd84baa2e068dc3" +
    "829e140d3c0078562014b10000c0bfd996f3716d9d397db9b1070756b4d8ac9a5a0088e1b24c09" +
    "0100ca1753f4d2f16990d8db6e7972525daf603609640048c66fefa00a00d173589004f1ddb99f" +
    "cd6952f84c148d45407309000814fd1d000000e5548cd120855cfb556307543f86d63d0fec02b5" +
    "00f47cab871a000075";
  const daemonValues = {
    i9jRsqnfMnQmGc3LJnMt9Z6T4CoDkv6Q9o: "77287",
    iAH9uQ4GnREmbpVKd1fU9zrePte3odZGFd: "29917000",
    iDD6uzji8SpCvHs3hgq9Z4tKqr9CKrL73S: "29917000",
    iE7rXeqXV6ec93heNqZ35xcswZ8yzHoQQw: "29917000",
    iFawzbS99RqGs7J2TNxME1TmmayBGuRkA2: "1947000",
    iM3gzspfspD8SqsNpHSaVJA2BZQrbTc7TL: "2917000",
    iMu5sgTiGcaWryiwGwNTWcHxQo589xMXK8: "29917000",
    iNZzqYdmfCPCcVSTBjbPT8Q7rqeFohxATu: "1288",
    iQP7TeWNDNsF7aaaCkQzNyS4jDjdKncNWf: "291700",
  };
  const many = tokenBalances(
    [{ txid: "ff".repeat(32), vout: 10, satoshis: "0", scriptPubKey: multivalue }],
    null,
  );
  assert.deepEqual(
    Object.fromEntries(many.map((t) => [t.currency, formatCoins(t.amount)])),
    daemonValues,
    "nine currencies from one output, in coins, exactly as the daemon reports them",
  );
  ok("a multi-currency output is counted currency by currency");

  // A name commitment. Real script: output 0 of
  // 3a6f6a02f2fb74dc16a5e9d49cb02966100a72656acd30d9c28d5eae554edaca. The
  // daemon reports currencyvalues {} for it — read, not assumed.
  const commitment =
    "1b040300010115040d70e777403b2fa1e52b09853be00beb8ac88762cc3c0403110101150" +
    "40d70e777403b2fa1e52b09853be00beb8ac8876220089ce908e263013785c59404a6b88c" +
    "47e30e52e32dedde094f8c5ade74ebb9ed75";
  const reserved = decodeOutput(commitment);
  assert.equal(reserved.kind, "identityCommitment");
  assert.equal(
    reserved.commitment,
    "089ce908e263013785c59404a6b88c47e30e52e32dedde094f8c5ade74ebb9ed",
    "the daemon prints this reversed; these are the bytes in the script",
  );
  assert.deepEqual(reserved.tokens, []);
  assert.deepEqual(
    tokenBalances([{ txid: "ab".repeat(32), vout: 0, satoshis: "0", scriptPubKey: commitment }], null),
    [],
  );
  ok("a name commitment is read rather than refused");

  // Reserve transfers and deposits. Both name the chain's own currency in their
  // payload AND carry it as satoshis, so counting the payload without knowing
  // which currency is native reports the same money twice. Real scripts: block
  // 1170450 output 1, and block 1170449 output 0.
  const VRSCTEST_CURRENCY = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";
  const transfer =
    "1a040300010114cb8a0f7f651b484a81e2312c3438deb601e27368cc4ca4040308010114cb8a0f7f651b" +
    "484a81e2312c3438deb601e273684c8801a6ef9ea235635e328124ff3429db9f9e91b64e2d81b4e13187" +
    "03a6ef9ea235635e328124ff3429db9f9e91b64e2d809b2a42144fad5a983b2b714651afe2e40a9e0a7d" +
    "498bfdd7011602143d74453766227cfd9c0449e83184ae4912b0d5cb6d4a9a7ef695f4f2a35a49c9f232" +
    "beb5cc9b964ac0bfd996f3716d9d397db9b1070756b4d8ac9a5a75";
  const deposit =
    "2704030001012103b99d7cb946c5b1f8a54cde49b8d7e0a2a15a22639feb798009f82b519526c050cc4c" +
    "5504030b01012103b99d7cb946c5b1f8a54cde49b8d7e0a2a15a22639feb798009f82b519526c0502d01" +
    "a6ef9ea235635e328124ff3429db9f9e91b64e2d81b5fd5f6d4a9a7ef695f4f2a35a49c9f232beb5cc9b" +
    "964a75";

  const moving = decodeOutput(transfer);
  assert.equal(moving.kind, "reserveTransfer");
  assert.equal(moving.flags, 1027, "VALID | CONVERT | RESERVE_TO_RESERVE");
  assert.equal(moving.fees, "20010");
  assert.equal(moving.feeCurrency, VRSCTEST_CURRENCY);
  // `address` is the protocol's transfer address, the same for every transfer
  // on the chain; the real recipient is inside the payload.
  assert.equal(moving.address, "RTqQe58LSj2yr5CrwYFwcsAQ1edQwmrkUU");
  assert.equal(moving.recipient, "RGYV8WX9ykrCUZz9VgPAdaRV1aqGDnhz5j");
  assert.deepEqual(moving.tokens, [{ currency: VRSCTEST_CURRENCY, amount: "5075249" }]);

  const deposited = decodeOutput(deposit);
  assert.equal(deposited.kind, "reserveDeposit");
  assert.equal(deposited.controllingCurrency, "iDSQTXbRNjSfXvQf9q9rHZy51x3CNSypBM");
  assert.deepEqual(deposited.tokens, [{ currency: VRSCTEST_CURRENCY, amount: "5095263" }]);
  ok("reserve transfers and deposits decode field for field");

  for (const [label, script, satoshis] of [["transfer", transfer, "5095259"], ["deposit", deposit, "5095263"]]) {
    // Told which currency is the chain's own, both come to nothing: every
    // satoshi they name is already in the output's value.
    assert.deepEqual(
      tokenBalances([{ txid: "12".repeat(32), vout: 0, satoshis, scriptPubKey: script }], VRSCTEST_CURRENCY),
      [],
      `${label}: its payload is native value, not a token`,
    );
    // Not told, it refuses rather than double-counting.
    assert.throws(
      () => tokenBalances([{ txid: "12".repeat(32), vout: 0, satoshis, scriptPubKey: script }], null),
      (e) => e instanceof Error,
      `${label}: must refuse without the chain's own currency`,
    );
  }
  ok("both count as nothing with the native currency, and refuse without it");
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

console.log("\nrecovery phrases");
{
  const PHRASE =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

  const good = validateMnemonic(PHRASE);
  assert.equal(good.valid, true);
  assert.equal(good.words, 12);
  assert.equal(good.reason, undefined, "a valid phrase carries no reason");
  ok("a real mnemonic validates");

  // The distinction the binding exists for. Free text is NOT an error: a Verus
  // wallet derives a real, spendable transparent key from it, and a UI that
  // shows a warning here would be wrong.
  const free = validateMnemonic("my own words");
  assert.equal(free.valid, false);
  assert.equal(free.reason, "wordCount");
  assert.equal(Key.fromSeedPhrase("my own words").address().startsWith("R"), true);

  // A typo IS worth stopping for, and looks nothing like the above.
  const typo = validateMnemonic(PHRASE.replace("about", "abandon"));
  assert.equal(typo.reason, "checksum");
  ok("free text and a mistyped word are told apart");

  const unknown = validateMnemonic(PHRASE.replace("about", "verus"));
  assert.equal(unknown.reason, "unknownWord");
  assert.equal(unknown.position, 12);
  // The phrase must not travel in the result: it reaches logs and screenshots.
  assert.equal(JSON.stringify(unknown).includes("verus"), false);
  ok("a bad word is reported by position, never by value");

  // The official BIP-39 vector seed with an empty passphrase — what a Verus
  // wallet uses. Bytes rather than hex, so a caller can zero them.
  const seed = mnemonicToSeed(PHRASE, null);
  assert.ok(seed instanceof Uint8Array);
  assert.equal(seed.length, 64);
  assert.equal(
    Buffer.from(seed).toString("hex"),
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1" +
      "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
  );
  // Whitespace must not reach PBKDF2 — a pasted newline would otherwise derive
  // a different, empty wallet.
  assert.deepEqual(mnemonicToSeed(`  ${PHRASE}\n`, ""), seed);
  ok("a mnemonic derives the BIP-39 seed, whitespace notwithstanding");

  // Deriving from words that do not check out is refused rather than done.
  assert.throws(() => mnemonicToSeed(PHRASE.replace("about", "abandon"), null), /checksum/i);
  ok("a seed is not derived from a phrase that fails its checksum");
}

// ---------------------------------------------------------------------------
// Whole flows, driven the way a page would drive them.
//
// No network: a `post` stands in for `fetch` and answers from a small table of
// recorded replies. What is under test is the loop itself — that the module
// asks for what it needs, takes the answers back, converges, and signs the same
// bytes the direct, vector-proven path signs.
// ---------------------------------------------------------------------------

console.log("\nflows, driven with no network");
{
  const TIP = 1167555;
  const EXPIRY_BLOCKS = 20;            // the SDK's default, added to the tip
  const vector = vectors.vectors[0];
  const key = Key.fromWif(vector.wif);
  const address = key.address();
  // The vector's own funding script: this key spends it upstream, so it is
  // this address's P2PKH script without having to derive one here.
  const SCRIPT = vector.utxos[0].script_pubkey;
  const TXID = "5e19de6d3f77b5e1f49ec92db23027d5f026db92004b026465a61bff8ab13d7e";
  const HEIGHT = 1166385;              // old enough that no maturity probe follows
  const SATS = 1000000000;
  const PAYEE = "RPsQDnaxXgrLjcVBh3SpvCpTabWxAdMdzu";

  const replies = {
    getblockcount: JSON.stringify({ result: TIP }),
    getaddressutxos: JSON.stringify({
      result: [{
        address, blocktime: 1785262420, height: HEIGHT, isspendable: 1,
        outputIndex: 1, satoshis: SATS, script: SCRIPT, txid: TXID,
      }],
    }),
    // The live capture, so the chain-id read is answered by what a daemon
    // really sends rather than by a hand-written subset of it.
    getinfo: readFileSync(
      resolve(here, "../../../../fixtures/rpc/getinfo.json"), "utf8"),
    getaddressdeltas: JSON.stringify({
      result: [{
        address, blockindex: 1, blocktime: 1785262420, height: HEIGHT,
        index: 0, satoshis: SATS, txid: TXID,
      }],
    }),
    // An empty mempool. Funding reads it to withhold coins an unconfirmed
    // transaction already spends; with nothing pending, the captured output
    // above stays spendable and this fixture keeps meaning what it meant.
    getaddressmempool: JSON.stringify({ result: [] }),
  };

  let posted = [];
  /** The page's `fetch`, minus the network. */
  const post = (body) => {
    posted.push(body);
    const { method } = JSON.parse(body);
    const reply = replies[method];
    assert.ok(reply, `nothing recorded for ${method}`);
    return reply;
  };

  // -- a payment, planned ---------------------------------------------------
  const answers = new Answers();
  let step;
  let rounds = 0;
  for (;;) {
    step = key.planSend({ to: PAYEE, satoshis: "150000000" }, answers);
    if (step.kind === "ready") break;
    rounds += 1;
    assert.ok(step.ask.length > 0, "an asking round must ask for something");
    for (const body of step.ask) answers.record(body, post(body));
  }

  assert.equal(rounds, 1, "the tip, the outputs and the mempool go out together");
  assert.deepEqual(
    posted.map((body) => JSON.parse(body).method).sort(),
    ["getaddressmempool", "getaddressutxos", "getblockcount"],
  );
  ok("a payment plans in one round trip");

  // The claim everything rests on: driving the flow signs exactly what the
  // direct path signs from the same view of the chain — and the direct path is
  // the one checked against the TypeScript SDK's bytes above.
  const direct = key.send({
    utxos: [{ txid: TXID, vout: 1, satoshis: String(SATS), scriptPubKey: SCRIPT }],
    recipients: [{ address: PAYEE, satoshis: "150000000" }],
    changeAddress: address,
    expiryHeight: TIP + EXPIRY_BLOCKS,
  });
  assert.equal(step.value.hex, direct.hex);
  assert.equal(step.value.txid, direct.txid);
  assert.equal(step.value.fee, direct.fee);
  ok("a planned payment is byte-identical to a directly built one");

  // A plan reads. It cannot ask the page to write, and that is what makes it
  // safe to re-run once per round.
  assert.equal(
    posted.some((body) => JSON.parse(body).method === "sendrawtransaction"),
    false,
  );
  ok("planning never asks the page to broadcast");
  answers.free();

  // -- a body that came back changed ---------------------------------------
  // The strings in `ask` are the cache keys. A page that re-encodes one records
  // an answer to a question nobody asked, so the same round repeats — and the
  // round cap is what turns that from a tab fetching forever into an error.
  {
    const stubborn = new Answers();
    let thrown;
    try {
      for (let i = 0; i < 40; i += 1) {
        const s = key.planSend({ to: PAYEE, satoshis: "150000000" }, stubborn);
        if (s.kind === "ready") break;
        // Same JSON, different bytes.
        for (const body of s.ask) stubborn.record(`${body} `, post(body));
      }
    } catch (e) {
      thrown = e;
    }
    assert.ok(thrown, "a plan that never converges must fail rather than spin");
    assert.equal(thrown.name, "Stalled");
    stubborn.free();
    ok("a mangled request body stalls loudly instead of looping forever");
  }

  // -- history, which needs no key -----------------------------------------
  {
    posted = [];
    const reading = new Answers();
    let entries;
    let readRounds = 0;
    for (;;) {
      const s = planHistory(
        { addresses: [address], startHeight: 1166000, endHeight: TIP },
        reading,
      );
      if (s.kind === "ready") { entries = s.value; break; }
      readRounds += 1;
      for (const body of s.ask) reading.record(body, post(body));
    }

    assert.equal(readRounds, 1, "the chain id and the deltas go out together");
    assert.deepEqual(
      posted.map((body) => JSON.parse(body).method).sort(),
      ["getaddressdeltas", "getinfo"],
    );
    assert.equal(entries.length, 1);
    assert.equal(entries[0].txid, TXID);
    // Money is a string here as everywhere, with the sign carried in it.
    assert.equal(typeof entries[0].netNative, "string");
    assert.equal(entries[0].netNative, String(SATS));
    assert.equal(entries[0].spentSomething, false);
    // A timestamp is the one number here that IS a number, and it has to
    // survive the boundary as one rather than as a BigInt a caller cannot
    // arithmetic on.
    assert.equal(typeof entries[0].blockTime, "number");
    assert.equal(entries[0].blockTime, 1785262420);
    reading.free();
    ok("a history read plans in one round trip and reports string amounts");
  }

  // -- the name a caller branches on ---------------------------------------
  {
    const broke = new Answers();
    let thrown;
    try {
      for (let i = 0; i < 8; i += 1) {
        const s = key.planSend({ to: PAYEE, satoshis: "999999999999" }, broke);
        if (s.kind === "ready") break;
        for (const body of s.ask) broke.record(body, post(body));
      }
    } catch (e) {
      thrown = e;
    }
    assert.ok(thrown, "asking for more than the address holds must fail");
    // Not "InsufficientFunds" wrapped as "Tx": `e.name` has to mean the same
    // thing on the planned path as on the direct one, or a caller's `catch`
    // works on one and silently not on the other.
    assert.equal(thrown.name, "InsufficientFunds");
    broke.free();

    // `FlowError` has three transparent wrappers, and missing any one of them
    // reintroduces the problem for a whole class of failure. A bad payee
    // address arrives as `FlowError::Key`, and must not be named "Key".
    const bad = new Answers();
    let addressError;
    try {
      key.planSend({ to: "not an address", satoshis: "1" }, bad);
    } catch (e) {
      addressError = e;
    }
    assert.ok(addressError, "an unparseable address must be refused");
    assert.notEqual(addressError.name, "Key");
    assert.notEqual(addressError.name, "Tx");
    assert.notEqual(addressError.name, "Rpc");
    bad.free();
    ok("a flow error is named by its own variant, not by its wrapper");
  }

  // -- the reason planSend exists at all ------------------------------------
  //
  // A coinbase output is unspendable for a hundred blocks, and
  // `getaddressutxos` does not say which outputs are coinbases. An application
  // holding the raw list cannot tell, builds a transaction spending one, and is
  // rejected by the daemon with a message that names nothing. The flow asks —
  // and only about outputs young enough for it to matter, which is why this
  // takes a second round where the mature case took one.
  {
    const YOUNG = TIP - 10;            // inside the 100-block maturity window
    const probing = {
      ...replies,
      getaddressutxos: JSON.stringify({
        result: [{
          address, blocktime: 1785262420, height: YOUNG, isspendable: 1,
          outputIndex: 0, satoshis: SATS, script: SCRIPT, txid: TXID,
        }],
      }),
      // The daemon's shape for a coinbase: one input, carrying `coinbase`
      // instead of an outpoint.
      getrawtransaction: JSON.stringify({
        result: { vin: [{ coinbase: "03c1cd11", sequence: 4294967295 }] },
      }),
    };

    posted = [];
    const probe = (body) => {
      posted.push(body);
      const { method } = JSON.parse(body);
      assert.ok(probing[method], `nothing recorded for ${method}`);
      return probing[method];
    };

    const immature = new Answers();
    let thrown;
    try {
      for (let i = 0; i < 8; i += 1) {
        const s = key.planSend({ to: PAYEE, satoshis: "150000000" }, immature);
        if (s.kind === "ready") break;
        for (const body of s.ask) immature.record(body, probe(body));
      }
    } catch (e) {
      thrown = e;
    }

    assert.ok(
      posted.some((body) => JSON.parse(body).method === "getrawtransaction"),
      "a young output must be probed, or its maturity is a guess",
    );
    assert.ok(thrown, "an immature coinbase is not spendable");
    assert.equal(thrown.name, "InsufficientFunds");
    immature.free();
    ok("an immature coinbase is probed for and refused, not silently spent");
  }

  // -- one Answers, one operation ------------------------------------------
  //
  // A cached answer is indistinguishable from a fresh one, so a reused handle
  // plans against a tip that may be hours old. Nothing can detect that from
  // inside; what CAN be shown is that reuse is real caching rather than a
  // coincidence — a second operation on the same handle asks for nothing.
  {
    const shared = new Answers();
    for (;;) {
      const s = key.planSend({ to: PAYEE, satoshis: "150000000" }, shared);
      if (s.kind === "ready") break;
      for (const body of s.ask) shared.record(body, post(body));
    }
    const before = shared.rounds;
    const again = key.planSend({ to: PAYEE, satoshis: "250000000" }, shared);
    assert.equal(again.kind, "ready");
    assert.ok(shared.rounds > before, "rounds accumulate across operations");
    assert.notEqual(again.value.hex, step.value.hex);
    shared.free();
    ok("a reused Answers replans from the cache without asking again");
  }

  // -- a login, signed and verified through the driver ----------------------
  //
  // The whole round trip: the module reads the tip and the identity to stamp a
  // signature, then a verifier reads the identity *as it stood at that height*
  // and decides. Both halves driven, no network.
  {
    const identityKey = Key.fromWif(vector.wif);
    const IDENTITY_ADDRESS = "iL9bcBmaR6YF37UfrPdkAxVwXwAG72xebm";
    const signerAddress = identityKey.address();

    const identityReply = (height) => JSON.stringify({
      result: {
        blockheight: height,
        fullyqualifiedname: "someone.VRSCTEST@",
        status: "active",
        txid: TXID,
        vout: 0,
        identity: {
          identityaddress: IDENTITY_ADDRESS,
          minimumsignatures: 1,
          name: "someone",
          primaryaddresses: [signerAddress],
          version: 3,
        },
      },
    });

    const loginReplies = {
      ...replies,
      getidentity: identityReply(HEIGHT),
    };
    const loginPost = (body) => {
      const { method } = JSON.parse(body);
      assert.ok(loginReplies[method], `nothing recorded for ${method}`);
      return loginReplies[method];
    };

    const drive = (call) => {
      const a = new Answers();
      for (;;) {
        const s = call(a);
        if (s.kind === "ready") { a.free(); return s.value; }
        for (const body of s.ask) a.record(body, loginPost(body));
      }
    };

    const challenge = { audience: "https://example.com", challenge: "9f2c4e7a1b" };
    const signature = drive((a) => identityKey.planLogin("someone.VRSCTEST@", challenge, a));
    assert.equal(typeof signature, "string");
    ok("a login is signed against the chain's own tip");

    const session = drive((a) =>
      planVerifyLogin({ identity: "someone.VRSCTEST@", signature, ...challenge }, a));
    assert.equal(session.identityAddress, IDENTITY_ADDRESS);
    assert.equal(session.signedAt, TIP);
    assert.deepEqual(session.signers, [signerAddress]);
    ok("and verified against the identity as it stood when it was signed");

    // A challenge the verifier did not issue must not verify, or the whole
    // thing is a signature over nothing in particular.
    assert.throws(
      () => drive((a) => planVerifyLogin(
        { identity: "someone.VRSCTEST@", signature, audience: "https://evil.example", challenge: challenge.challenge },
        a)),
      (e) => e.name !== undefined,
    );
    ok("a signature made for one audience does not verify at another");

    identityKey.free();
  }

  // -- what an address can actually spend -----------------------------------
  {
    const funding = (() => {
      const a = new Answers();
      for (;;) {
        const s = planSpendable({ address }, a);
        if (s.kind === "ready") { a.free(); return s.value; }
        for (const body of s.ask) a.record(body, post(body));
      }
    })();

    assert.equal(funding.tip, TIP);
    // Money is a string here as everywhere.
    assert.equal(typeof funding.total, "string");
    assert.equal(funding.total, String(SATS));
    assert.equal(funding.notYetSpendable, "0");
    assert.equal(funding.spentUnconfirmed, "0");
    assert.equal(funding.utxos.length, 1);
    assert.equal(funding.utxos[0].scriptPubKey, SCRIPT);
    ok("spendable coins are reported with the tip they were judged against");

    // The same address, with the one output already spent by something in the
    // mempool. `getaddressutxos` is confirmed-only and still reports it, so
    // without the mempool read a page would rebuild that spend byte for byte —
    // the duplicate, not a conflict a node explains.
    //
    // Reported separately from `notYetSpendable` on purpose: that figure means
    // "wait", and this money is not waiting for anything. A wallet showing this
    // as unavailable rather than pending tells a user their coins vanished.
    const spentReplies = {
      ...replies,
      getaddressmempool: JSON.stringify({
        result: [{
          address, txid: "9f".repeat(32), index: 0, satoshis: -SATS,
          spending: true, prevtxid: TXID, prevout: 1, timestamp: 1785262500,
        }],
      }),
    };
    const pendingFunding = (() => {
      const a = new Answers();
      for (;;) {
        const s = planSpendable({ address }, a);
        if (s.kind === "ready") { a.free(); return s.value; }
        for (const body of s.ask) {
          const { method } = JSON.parse(body);
          a.record(body, spentReplies[method]);
        }
      }
    })();

    assert.deepEqual(pendingFunding.utxos, [], "a coin already spent is withheld");
    assert.equal(pendingFunding.total, "0");
    assert.equal(pendingFunding.notYetSpendable, "0", "it is not waiting for anything");
    assert.equal(pendingFunding.spentUnconfirmed, String(SATS));
    ok("money an unconfirmed transaction already spends is withheld and reported as pending");
  }

  // -- stored data, current versus accumulated ------------------------------
  {
    const KEY = "iGRp1CGkuro3LtGazX8W1PRjVupPVfe8Pv";
    const contentReplies = {
      ...replies,
      // `getidentity` is current state: one value under the key.
      getidentity: JSON.stringify({
        result: {
          blockheight: HEIGHT, fullyqualifiedname: "app.VRSCTEST@", status: "active",
          txid: TXID, vout: 0,
          identity: {
            identityaddress: "iL9bcBmaR6YF37UfrPdkAxVwXwAG72xebm",
            minimumsignatures: 1, name: "app", primaryaddresses: [address], version: 3,
            contentmultimap: { [KEY]: [Buffer.from("now").toString("hex")] },
          },
        },
      }),
      // `getidentitycontent` accumulates: every value ever published.
      getidentitycontent: JSON.stringify({
        result: {
          blockheight: HEIGHT, fullyqualifiedname: "app.VRSCTEST@", status: "active",
          txid: TXID, vout: 0,
          identity: {
            identityaddress: "iL9bcBmaR6YF37UfrPdkAxVwXwAG72xebm",
            minimumsignatures: 1, name: "app", primaryaddresses: [address], version: 3,
            contentmultimap: {
              [KEY]: [
                Buffer.from("before").toString("hex"),
                Buffer.from("now").toString("hex"),
              ],
            },
          },
        },
      }),
    };
    const contentPost = (body) => contentReplies[JSON.parse(body).method];

    const drive = (call) => {
      const a = new Answers();
      for (;;) {
        const s = call(a);
        if (s.kind === "ready") { a.free(); return s.value; }
        for (const body of s.ask) a.record(body, contentPost(body));
      }
    };

    const now = drive((a) => planContent({ identity: "app.VRSCTEST@" }, a));
    const ever = drive((a) => planContentHistory({ identity: "app.VRSCTEST@" }, a));

    assert.equal(now[KEY].length, 1, "planContent is current state");
    assert.equal(Buffer.from(now[KEY][0].hex, "hex").toString(), "now");
    assert.equal(ever[KEY].length, 2, "planContentHistory accumulates");
    ok("stored data reads as current state, with the audit view kept separate");
  }

  // -- a key this identity does not list ------------------------------------
  //
  // Signing with a key the identity no longer lists builds cleanly and then
  // fails script verification at the daemon with a message that names nothing.
  // Caught here instead, by name.
  {
    const strangerReplies = {
      ...replies,
      getidentity: JSON.stringify({
        result: {
          blockheight: HEIGHT, fullyqualifiedname: "holder.VRSCTEST@", status: "active",
          txid: TXID, vout: 0,
          identity: {
            identityaddress: "iL9bcBmaR6YF37UfrPdkAxVwXwAG72xebm",
            minimumsignatures: 1, name: "holder",
            // Deliberately not this key: PAYEE is a different address.
            primaryaddresses: [PAYEE], version: 3,
          },
        },
      }),
    };
    const a = new Answers();
    let thrown;
    try {
      for (let i = 0; i < 6; i += 1) {
        const s = key.planSendFromIdentity(
          { identity: "holder.VRSCTEST@", to: PAYEE, satoshis: "1" }, a);
        if (s.kind === "ready") break;
        for (const body of s.ask) {
          a.record(body, strangerReplies[JSON.parse(body).method] ?? post(body));
        }
      }
    } catch (e) { thrown = e; }
    a.free();
    assert.ok(thrown, "a key the identity does not list must be refused");
    assert.equal(thrown.name, "NotAPrimaryAddress");
    ok("a key the identity does not list is refused by name, not by the daemon");
  }

  // -- a token a VerusID holds, moved from a page ---------------------------
  //
  // The reason `planSendTokenFromIdentity` exists. A non-mintable token's
  // supply is preallocated to its defining identity, so every unit lives in a
  // reserve output paying that identity and never touches a key-held address.
  // Nothing else on this binding can reach it: `planSendToken` is key-signed
  // and refuses an identity-held reserve output by design.
  //
  // The output below is the real one — `aaa@` on VRSCTEST
  // (iQmq5ota52pquV5RJvqynYo8AAro2b5bXn), whose 1,000,000,000 units were
  // stranded until this landed. Real bytes rather than a synthesised script,
  // because the shape is the whole point.
  {
    const HOLDER = "iQmq5ota52pquV5RJvqynYo8AAro2b5bXn";
    const TOKEN = HOLDER;                       // a currency IS its identity
    const TOKEN_OUTPUT =
      "1b04030001011504e9a0725e95d34445accf81b5190485ebf1e64d11cc3a04030901011504e9a0" +
      "725e95d34445accf81b5190485ebf1e64d111e01e9a0725e95d34445accf81b5190485ebf1e64d" +
      "1180b0d0ae84eba6ff0075";

    // Two addresses are asked about — the identity's, for the token, and this
    // key's, for the miner fee — so the reply has to depend on WHICH, not just
    // on the method. The client refuses an output belonging to an address it
    // did not ask about, which is what makes a single shared answer wrong.
    const identityPost = (body) => {
      const { method, params } = JSON.parse(body);
      const asked = params?.[0]?.addresses?.[0];
      if (method === "getaddressutxos") {
        return JSON.stringify({
          result: asked === HOLDER
            ? [{
                address: HOLDER, blocktime: 1785262420, height: HEIGHT, isspendable: 1,
                outputIndex: 0, satoshis: 0, script: TOKEN_OUTPUT, txid: TXID,
              }]
            : [{
                address, blocktime: 1785262420, height: HEIGHT, isspendable: 1,
                outputIndex: 1, satoshis: SATS, script: SCRIPT, txid: TXID,
              }],
        });
      }
      if (method === "getidentity") {
        return JSON.stringify({
          result: {
            blockheight: HEIGHT, fullyqualifiedname: "aaa.VRSCTEST@", status: "active",
            txid: TXID, vout: 0,
            identity: {
              identityaddress: HOLDER, minimumsignatures: 1, name: "aaa",
              primaryaddresses: [address], version: 3, flags: 0, timelock: 0,
            },
          },
        });
      }
      return post(body);
    };

    const a = new Answers();
    let planned;
    for (let i = 0; i < 8; i += 1) {
      const s = key.planSendTokenFromIdentity(
        { identity: "aaa.VRSCTEST@", currency: TOKEN, to: PAYEE, amount: "100000000" },
        a,
      );
      if (s.kind === "ready") { planned = s.value; break; }
      for (const body of s.ask) a.record(body, identityPost(body));
    }
    a.free();

    assert.ok(planned, "the plan must resolve");
    assert.equal(typeof planned.hex, "string");
    assert.ok(planned.hex.length > 0);
    // Money crosses as a string here as everywhere else.
    assert.equal(typeof planned.fee, "string");
    ok("a token a VerusID holds can be moved from a page");

    // The sanitizer guards this request like every other: an undeclared field
    // is refused rather than ignored. `expiryHieght` once produced a validly
    // signed, permanently minable transaction, which is why this is checked
    // per DTO and not once.
    const b = new Answers();
    let thrown;
    try {
      key.planSendTokenFromIdentity(
        { identity: "aaa.VRSCTEST@", currency: TOKEN, to: PAYEE, amount: "1", extra: 1 },
        b,
      );
    } catch (e) { thrown = e; }
    b.free();
    assert.ok(thrown, "an undeclared field must be refused");
    // `UnknownField`, not the `InvalidArgument` a mistyped VALUE raises — the
    // sanitizer distinguishes "this key does not belong here" from "this key's
    // value is the wrong shape", and a caller can act on the difference.
    assert.equal(thrown.name, "UnknownField");
    ok("planSendTokenFromIdentity refuses a field it does not declare");

    // The same supply, converted straight into a basket instead of being moved
    // out first. That is the whole point of planConvertFromIdentity: seeding a
    // basket otherwise takes two transactions, and between them the supply sits
    // at a bare address while the launch window runs down. A basket that
    // reaches its start block with an empty reserve refunds its entire launch,
    // and the name cannot be reused.
    const BASKET = "iRRhsKoiBuMoyANFcQ2NMLJXDgfSHjgffS";
    const c = new Answers();
    let converted;
    for (let i = 0; i < 8; i += 1) {
      const s = key.planConvertFromIdentity(
        {
          identity: "aaa.VRSCTEST@", from: TOKEN, amount: "100000000",
          kind: "preconvert", into: BASKET, recipient: PAYEE, fee: "20000",
        },
        c,
      );
      if (s.kind === "ready") { converted = s.value; break; }
      for (const body of s.ask) c.record(body, identityPost(body));
    }
    c.free();

    assert.ok(converted, "the conversion must resolve");
    assert.equal(typeof converted.hex, "string");
    assert.ok(converted.hex.length > 0);
    assert.equal(typeof converted.fee, "string");
    ok("a token a VerusID holds converts into a basket without leaving the identity");

    // `via` belongs to reserveToReserve alone. Set beside any other kind it is
    // refused rather than ignored — a caller who set it believed it did
    // something, and the shared parser is what keeps this identical to
    // planConvert.
    const d = new Answers();
    let viaThrown;
    try {
      key.planConvertFromIdentity(
        {
          identity: "aaa.VRSCTEST@", from: TOKEN, amount: "1",
          kind: "preconvert", into: BASKET, via: BASKET, recipient: PAYEE, fee: "20000",
        },
        d,
      );
    } catch (e) { viaThrown = e; }
    d.free();
    assert.ok(viaThrown, "via beside a non-routing kind must be refused");
    assert.equal(viaThrown.name, "InvalidArgument");
    ok("planConvertFromIdentity refuses `via` on a kind that does not route");
  }

  // -- a token send needs its token outputs named ---------------------------
  {
    const a = new Answers();
    let thrown;
    try {
      key.planSendToken(
        { currency: VRSCTEST, to: PAYEE, amount: "1", tokenUtxos: [{ txid: TXID, vout: 0, satoshis: 1000000000, scriptPubKey: SCRIPT }] },
        a,
      );
    } catch (e) { thrown = e; }
    a.free();
    // `satoshis` as a number, inside a nested object — the sanitizer has to
    // reach in there too, and money must not cross as a float.
    assert.ok(thrown);
    assert.equal(thrown.name, "InvalidArgument");
    ok("money inside a nested token UTXO is a string like everywhere else");
  }

  // -- storing data on a VerusID, and the invariant it must not break -------
  //
  // An identity update republishes the identity IN FULL: anything not carried
  // over is erased permanently. So this checks the bytes the page would post,
  // not the binding's own report — another application's key must survive.
  //
  // The identity output script is generated from the same builders the Rust
  // tests use; it decodes to an identity whose sole primary address is this
  // key, holding one key that belongs to somebody else.
  {
    const ID_ADDRESS = "iHiamgHF3VdUXq3A6s5Mu61uhJM398MoRb";
    const THEIR_KEY = "iK2vkpGaZXExJAeZWjs47scSHTTBJcvHNb";
    const OUR_KEY = "iGRp1CGkuro3LtGazX8W1PRjVupPVfe8Pv";
    const ID_SCRIPT =
      "47040300010315049c3a5eee28817dbe3012929998e6ba7a04c41fde1504333333333333333333333333333333333333333315044444444444444444444444444444444444444444cc4cf004030e010115049c3a5eee28817dbe3012929998e6ba7a04c41fde4c9b03000000000000000114aabfb6281561808fe200ab7e186f0e3e0e82b38101000000a6ef9ea235635e328124ff3429db9f9e91b64e2d0361707001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01086e6f74206d696e65003333333333333333333333333333333333333333444444444444444444444444444444444444444400a6ef9ea235635e328124ff3429db9f9e91b64e2d000000001b04030f0101150433333333333333333333333333333333333333331b04031001011504444444444444444444444444444444444444444475";

    const pubReplies = {
      ...replies,
      getidentity: JSON.stringify({
        result: {
          blockheight: HEIGHT, fullyqualifiedname: "app.VRSCTEST@", status: "active",
          txid: TXID, vout: 0,
          identity: {
            identityaddress: ID_ADDRESS, minimumsignatures: 1, name: "app",
            primaryaddresses: [address], version: 3,
          },
        },
      }),
      getrawtransaction: JSON.stringify({
        result: { vout: [{ valueSat: 0, scriptPubKey: { hex: ID_SCRIPT } }] },
      }),
    };
    const pubPost = (b) => {
      const reply = pubReplies[JSON.parse(b).method];
      assert.ok(reply, `nothing recorded for ${JSON.parse(b).method}`);
      return reply;
    };

    const a = new Answers();
    let update;
    for (;;) {
      const s = key.planPublish(
        { identity: "app.VRSCTEST@", key: OUR_KEY, values: [Buffer.from("ours").toString("hex")] },
        a,
      );
      if (s.kind === "ready") { update = s.value; break; }
      for (const body of s.ask) a.record(body, pubPost(body));
    }
    a.free();

    assert.equal(update.key, OUR_KEY);
    assert.equal(update.values, 1);
    // Storing data costs a miner fee, and a wallet asking a user to approve
    // the update has to be able to say how much. A string, like all money.
    assert.equal(typeof update.fee, "string");
    assert.ok(BigInt(update.fee) > 0n);
    assert.equal(typeof update.change, "string");
    ok("storing data on a VerusID is planned and signed");

    // The invariant, read out of the transaction the page would actually post
    // — **structurally**, by locating the identity output and decoding it.
    //
    // A first version of this asserted that certain byte runs appeared in the
    // hex. That was unsound: the two authorities appear three times each, once
    // in the identity body and twice in the CryptoCondition wrapper, which the
    // builder fills in separately. Dropping an authority from the body — the
    // copy consensus republishes — would have left the wrapper's copies and the
    // assertion would have stayed green while the invariant it exists for was
    // broken.
    const scripts = outputScripts(update.hex);
    const identityScript = scripts.find((script) => {
      try { return decodeOutput(script).kind === "identityPrimary"; } catch { return false; }
    });
    assert.ok(identityScript, "the update must carry an identity output");

    const identityOutput = decodeOutput(identityScript);
    assert.equal(identityOutput.name, "app");
    assert.equal(identityOutput.minimumSignatures, 1);
    assert.deepEqual(identityOutput.primaryAddresses, [address]);
    assert.equal(identityOutput.address, ID_ADDRESS);

    // `decodeOutput` does not surface the authorities or the content multimap,
    // so those are checked against the identity output's own script — and by
    // COUNT, not presence. Each authority appears three times in it: once in
    // the identity body, which is the copy consensus republishes, and twice in
    // the CryptoCondition wrapper, which the builder fills in separately.
    // Asserting mere presence would survive the body's copy being dropped,
    // which is the erase this whole test exists to catch.
    const occurrences = (needle) => identityScript.split(needle).length - 1;
    assert.equal(occurrences("33".repeat(20)), 3, "revocation authority");
    assert.equal(occurrences("44".repeat(20)), 3, "recovery authority");

    // The other application's key and value live only in the body, so presence
    // is the right assertion for them.
    assert.equal(occurrences("aa".repeat(20)), 1, "another application's key");
    assert.equal(occurrences(Buffer.from("not mine").toString("hex")), 1, "and its value");
    // Counted once, deliberately: an earlier version wrote "mine", whose hex is
    // a substring of "not mine"'s, so the expected count of 2 was one real
    // match and one accident of the test data.
    assert.equal(occurrences(Buffer.from("ours").toString("hex")), 1, "ours went in");
    ok("and the republished identity keeps every key, value and authority");
  }

  // -- browsing the marketplace ---------------------------------------------
  //
  // Against the live capture, so the shapes are the daemon's own rather than
  // ones invented here.
  {
    const offerReplies = {
      ...replies,
      getoffers: readFileSync(
        resolve(here, "../../../../fixtures/rpc/getoffers_vrsctest.json"), "utf8"),
    };
    const offerPost = (b) => {
      const reply = offerReplies[JSON.parse(b).method];
      assert.ok(reply, `nothing recorded for ${JSON.parse(b).method}`);
      return reply;
    };

    const a = new Answers();
    let listings;
    const asked = [];
    for (;;) {
      const s = planOffers({ target: VRSCTEST, isCurrency: true, withOfferBytes: true }, a);
      if (s.kind === "ready") { listings = s.value; break; }
      asked.push(s.ask.map((body) => JSON.parse(body).method));
      for (const body of s.ask) a.record(body, offerPost(body));
    }
    a.free();

    // **Two rounds, in this order, and deliberately so.** `browse` reads the
    // offers and only then the tip, which means the tip is never older than the
    // listings — an offer expiring in the gap is judged dead rather than alive.
    //
    // Both halves are asserted. A count alone would catch someone batching the
    // two reads into one round, but not someone swapping them: reading the tip
    // first is still two rounds and is unsafe in exactly the way this ordering
    // exists to prevent.
    assert.deepEqual(asked, [["getoffers"], ["getblockcount"]]);
    assert.ok(listings.length > 0);

    const listing = listings[0];
    // Either side can be currencies or an identity, and the discriminator has
    // to be there for a caller to tell.
    assert.ok(["currencies", "identity"].includes(listing.offering.kind));
    assert.ok(["currencies", "identity"].includes(listing.accepting.kind));
    // A price is text, verbatim from the daemon: it is a ratio, not an amount,
    // and it arrives already rounded by a double division.
    assert.equal(typeof listing.price, "string");
    // Amounts inside a side are decimal strings like all money.
    for (const side of [listing.offering, listing.accepting]) {
      if (side.kind === "currencies") {
        for (const amount of Object.values(side.amounts)) {
          assert.equal(typeof amount, "string");
          assert.match(amount, /^[0-9]+$/);
        }
      } else {
        // camelCase, like every other field — serde renames enum *variants*
        // by default, not the fields inside them.
        assert.equal(typeof side.identityId, "string");
        assert.equal(typeof side.systemId, "string");
      }
    }
    ok("the marketplace lists offers-then-tip, with prices as text");

    // -- and reading one against the chain ---------------------------------
    const withBytes = listings.find((l) => l.rawOffer);
    assert.ok(withBytes, "withOfferBytes must actually return the bytes");

    // `planOfferTerms` reads the funding output, so it needs that transaction.
    // Refusing an offer whose funding outpoint is not an offer funding output
    // is the check worth proving: it means the maker's signature covers
    // something other than what the offer claims.
    const termsReplies = {
      ...offerReplies,
      getrawtransaction: JSON.stringify({
        result: { vout: [{ valueSat: 1000, scriptPubKey: { hex: SCRIPT } }] },
      }),
    };
    const b = new Answers();
    let refusal;
    try {
      for (let i = 0; i < 6; i += 1) {
        const s = planOfferTerms({ offer: withBytes.rawOffer }, b);
        if (s.kind === "ready") break;
        for (const body of s.ask) {
          b.record(body, termsReplies[JSON.parse(body).method]);
        }
      }
    } catch (e) { refusal = e; }
    b.free();
    assert.ok(refusal, "an ordinary coin is not an offer funding output");
    assert.equal(refusal.name, "Offer");
    // The *reason*, not just the category: `Offer` covers malformed hex and a
    // missing vout too, and this test is named for one specific refusal.
    assert.match(refusal.message, /not an offer funding output/);
    ok("an offer over an ordinary output is refused, not completed");
  }

  // -- completing an offer, all the way to signed bytes ---------------------
  //
  // The only new binding that moves money, so it is driven to `"ready"` and the
  // outputs are read back. The offer is built offline by `verus_tx::make_offer`
  // from a derived key: a maker giving 5 coins and wanting 2, expiring at
  // 1_200_000.
  {
    const MAKER = "RVS1YahJsGq32HW11q7DaU5KyTMyAwaunK";
    const OFFER_FUNDING_TXID =
      "7777777777777777777777777777777777777777777777777777777777777777";
    const OFFER_FUNDING_SCRIPT =
      "1a040300010114dd0d776ec425b31c9738deba8fa2c4821d6177bdcc3b040311010114dd0d776ec425b31c9738deba8fa2c4821d6177bd20000000000000000000000000000000000000000000000000000000000000000075";
    const OFFER =
      "0400008085202f8901777777777777777777777777777777777777777777777777777777777777777700000000694c670183010121029c5530e4385ebc41cdaf8257edf9a2baaf8506a4099103211e6ed7382103ed6740bf96bb60e5aa5e73f0dcb88f6f0ac664a262fe984b50da2a48703a813da2039b3e7917612865e7c639b79cdc6e774f0c7eab7b2869bd337b8a67741a58c3d91cffffffff0100c2eb0b000000001976a914dd0d776ec425b31c9738deba8fa2c4821d6177bd88ac00000000804f12000000000000000000000000";
    const OFFERED = 5_00000000n;
    const DEMANDED = 2_00000000n;

    const takeReplies = {
      getblockcount: JSON.stringify({ result: TIP }),
      getrawtransaction: JSON.stringify({
        result: {
          confirmations: 12,
          vout: [{
            valueSat: Number(OFFERED),
            scriptPubKey: { hex: OFFER_FUNDING_SCRIPT },
          }],
        },
      }),
    };
    const takePost = (b) => {
      const reply = takeReplies[JSON.parse(b).method];
      assert.ok(reply, `nothing recorded for ${JSON.parse(b).method}`);
      return reply;
    };

    const drive = (request) => {
      const a = new Answers();
      try {
        for (;;) {
          const s = key.planTakeOffer(request, a);
          if (s.kind === "ready") return s.value;
          for (const body of s.ask) a.record(body, takePost(body));
        }
      } finally { a.free(); }
    };

    const request = {
      offer: OFFER,
      utxos: [{ txid: TXID, vout: 1, satoshis: String(SATS), scriptPubKey: SCRIPT }],
      recipient: address,
      changeAddress: address,
      fee: "20000",
    };
    const taken = drive(request);

    // The offered value came from the chain, not from the offer or the caller.
    assert.equal(taken.terms.offered, String(OFFERED));
    assert.equal(taken.terms.control, MAKER);
    assert.equal(taken.terms.fundingTxid, OFFER_FUNDING_TXID);
    assert.equal(taken.terms.demand.kind, "native");
    assert.equal(taken.terms.demand.amount, String(DEMANDED));
    assert.equal(taken.terms.demand.recipient, MAKER);
    assert.equal(taken.terms.confirmations, 12);

    // And the transaction pays what it should, where it should. Output 0 is
    // the maker's demand and must be untouched — appending to a
    // SIGHASH_SINGLE|ANYONECANPAY offer is only valid while output 0 stands.
    const outs = outputScripts(taken.hex).map((s) => decodeOutput(s));
    assert.equal(outs[0].kind, "pubKeyHash");
    assert.equal(outs[0].address, MAKER);
    assert.ok(
      outs.slice(1).some((o) => o.address === address),
      "what the maker offered has to land at the taker's recipient",
    );
    ok("an offer is completed against the value the chain reports");

    // The fee is the one absolute-satoshi figure a caller names here, so a
    // transposed digit goes straight to a miner. Twenty-nine coins is not a fee.
    assert.throws(
      () => drive({ ...request, fee: "2900000000" }),
      (e) => e.name === "FeeTooLarge",
    );
    ok("and an absurd miner fee is refused rather than paid");
  }

  // -- conversions, and the shapes the request permits but the meaning does not
  {
    const SHYLOCK = "iQihXUcQt8G9TSh58YoM5NRwC1nAyoazFR";
    const base = {
      from: VRSCTEST,
      amount: "150000000",
      kind: "intoFractional",
      into: SHYLOCK,
      recipient: address,
      fee: "20010",
    };

    const convertReplies = {
      ...replies,
      estimateconversion: JSON.stringify({
        result: { estimatedcurrencyout: 1.49165329 },
      }),
    };
    const convertPost = (b) => {
      const reply = convertReplies[JSON.parse(b).method];
      assert.ok(reply, `nothing recorded for ${JSON.parse(b).method}`);
      return reply;
    };
    const drive = (request) => {
      const a = new Answers();
      try {
        for (;;) {
          const s = key.planConvert(request, a);
          if (s.kind === "ready") return s.value;
          for (const body of s.ask) a.record(body, convertPost(body));
        }
      } finally { a.free(); }
    };

    const converted = drive(base);
    assert.match(converted.hex, /^[0-9a-f]+$/);
    assert.equal(converted.txid.length, 64);
    ok("a conversion is planned against the node's own estimate");

    // `via` names the fractional to route through, and only a reserveToReserve
    // conversion routes. Set beside any other kind it would do nothing — and a
    // caller who set it believed it did something, so it is refused rather
    // than ignored. That is the same rule the sanitizer applies to unknown
    // keys, extended to a key that is known but meaningless here.
    assert.throws(
      () => drive({ ...base, via: SHYLOCK }),
      (e) => e.name === "InvalidArgument" && /reserveToReserve/.test(e.message),
    );
    // And the mirror: routing without saying through what.
    assert.throws(
      () => drive({ ...base, kind: "reserveToReserve" }),
      (e) => e.name === "InvalidArgument" && /needs `via`/.test(e.message),
    );
    ok("`via` and the conversion kind have to agree");

    // Burning and minting are not conversions with a different string. A burn
    // cannot be undone and a mint needs an identity's authority; neither
    // should be reachable by editing one field.
    for (const kind of ["burn", "mint"]) {
      assert.throws(
        () => drive({ ...base, kind }),
        (e) => e.name === "InvalidArgument" && /planMint or planBurn/.test(e.message),
      );
    }
    assert.throws(
      () => drive({ ...base, kind: "intoFractionall" }),
      (e) => e.name === "InvalidArgument" && /unknown conversion kind/.test(e.message),
    );
    ok("a burn or a mint is not reachable by changing a conversion's kind");

    // Every fee a caller names outright is capped, not just the taker's.
    for (const plan of [
      () => drive({ ...base, fee: "2900000000" }),
      () => key.planBurn({ currency: SHYLOCK, amount: "1", fee: "2900000000" }, new Answers()),
      () => key.planMint(
        { currency: SHYLOCK, amount: "1", recipient: address, fee: "2900000000" },
        new Answers(),
      ),
    ]) {
      assert.throws(plan, (e) => e.name === "FeeTooLarge");
    }
    ok("an absurd fee is refused by every plan that takes one");
  }

  // -- a VerusID registration, end to end, driven from JavaScript -----------
  //
  // Two transactions with a wait between them, joined by a salt that exists
  // nowhere else. This drives the whole thing and puts the pending value
  // through `JSON.stringify`/`parse` between every step — because that is what
  // a page does, and if the salt did not survive it the fee would be spent for
  // nothing.
  {
    const COMMITMENT_HEIGHT = TIP;
    const regReplies = {
      ...replies,
      getblockcount: JSON.stringify({ result: TIP }),
      getblockhash: JSON.stringify({ result: "00".repeat(32) }),
      // The name is free: the daemon's own answer for an identity nobody owns.
      getidentity: JSON.stringify({ error: { code: -5, message: "Identity not found" } }),
      getcurrency: readFileSync(
        resolve(here, "../../../../fixtures/rpc/getcurrency_vrsctest.json"), "utf8"),
      // VRSCTEST's real registration fee is 100 coins, per the capture above,
      // so the address has to actually hold that much. Using the capture rather
      // than pinning a cheap fee keeps the chain-policy read in the path.
      getaddressutxos: JSON.stringify({
        result: [{
          address, blocktime: 1785262420, height: HEIGHT, isspendable: 1,
          outputIndex: 0, satoshis: 200_00000000, script: SCRIPT, txid: TXID,
        }],
      }),
    };
    const regPost = (b) => {
      const { method } = JSON.parse(b);
      const reply = regReplies[method];
      assert.ok(reply, `nothing recorded for ${method}`);
      return reply;
    };
    const drive = (call, post = regPost) => {
      const a = new Answers();
      try {
        for (;;) {
          const s = call(a);
          if (s.kind === "ready") return s.value;
          for (const body of s.ask) a.record(body, post(body));
        }
      } finally { a.free(); }
    };

    // Step one, with a salt we choose so the whole thing is reproducible.
    const SALT = "11".repeat(32);
    let pending = drive((a) => key.planRegistration({ name: "browsertest", salt: SALT }, a));

    assert.equal(pending.state, "awaitingCommitment");
    assert.equal(pending.name, "browsertest");
    assert.match(pending.commitmentHex, /^[0-9a-f]+$/);
    assert.equal(typeof pending.registrationFee, "string");
    ok("a name commitment is planned before anything is spent");

    // What a chosen salt reproduces is the **reservation**, and that is what
    // lets a page which lost its state re-derive its claim and go looking for
    // the commitment output on chain.
    //
    // It does not reproduce the commitment *transaction*: that spends whichever
    // outputs were available and expires relative to the tip. So this drives
    // the second plan against a **moved chain**, which is the situation
    // recovery actually happens in — and asserting equal txids there would be
    // asserting something false. An earlier version of this test fed identical
    // replies both times and "proved" reproducibility that does not hold.
    const later = { ...regReplies, getblockcount: JSON.stringify({ result: TIP + 500 }) };
    const again = drive(
      (a) => key.planRegistration({ name: "browsertest", salt: SALT }, a),
      (b) => later[JSON.parse(b).method] ?? regPost(b),
    );
    assert.notEqual(
      again.commitmentTxid,
      pending.commitmentTxid,
      "a different tip means different bytes, even for the same claim",
    );
    // The claim itself is identical, which is the part that matters.
    assert.deepEqual(
      JSON.parse(again.pending).reservation,
      JSON.parse(pending.pending).reservation,
    );
    ok("and a chosen salt reproduces the reservation, not the transaction");

    // A salt that is not a secret defeats the point of having one.
    assert.throws(
      () => drive((a) => key.planRegistration({ name: "x", salt: "00".repeat(32) }, a)),
      (e) => e.name === "InvalidArgument",
    );
    ok("an all-zero salt is refused");

    // Persist. This is the step whose absence costs the fee.
    const persisted = JSON.stringify(pending);
    pending = JSON.parse(persisted);

    // Anchor, persist again, then the page would post `commitmentHex`.
    // `anchored_at`, not `anchoredAt` — the blob is the flow's own
    // serialization. Reading the camelCase spelling made this assertion
    // vacuously true, so it proved nothing about which call set the anchor.
    const beforeAnchor = JSON.parse(pending.pending).anchored_at;
    pending = drive((a) => key.planCommitmentAnchor({ pending }, a));
    pending = JSON.parse(JSON.stringify(pending));
    assert.equal(pending.state, "awaitingCommitment");
    // The anchor has to actually land, or a reorg under this registration goes
    // unnoticed. Asserting only the state would pass with the anchor dropped.
    assert.equal(beforeAnchor, null, "planRegistration must not anchor");
    const anchor = JSON.parse(pending.pending).anchored_at;
    assert.ok(Array.isArray(anchor), "the anchor must be recorded");
    assert.equal(anchor[0], TIP);
    ok("the reorg anchor is recorded before the commitment goes out");

    // Step two is not reachable yet, and that has to be enforced rather than
    // trusted: running it against an unconfirmed commitment spends the
    // registration fee against an output the chain will not accept. In Rust
    // these are different types; across JSON it can only be a check.
    assert.throws(
      () => drive((a) => key.planRegistrationComplete({ pending }, a)),
      (e) => e.name === "WrongStep",
    );
    ok("and step two is refused until step one has confirmed");

    // Unconfirmed: still waiting.
    const waiting = drive(
      (a) => planCommitmentStatus({ pending }, a),
      (b) => {
        const { method } = JSON.parse(b);
        if (method === "getrawtransaction") {
          return JSON.stringify({ result: { confirmations: 0, vout: [] } });
        }
        return regPost(b);
      },
    );
    assert.equal(waiting.kind, "waiting");
    assert.equal(waiting.confirmations, 0);
    ok("an unconfirmed commitment reports waiting, not ready");

    // Confirmed: the commitment output has to be *found*, by matching the
    // script the reservation derives, rather than assumed to be output zero.
    const commitmentScript = outputScripts(pending.commitmentHex)[0];
    const confirmedPost = (b) => {
      const { method } = JSON.parse(b);
      if (method === "getrawtransaction") {
        return JSON.stringify({
          result: {
            confirmations: 1,
            vout: [{ valueSat: 0, scriptPubKey: { hex: commitmentScript } }],
          },
        });
      }
      return regPost(b);
    };
    const ready = drive((a) => planCommitmentStatus({ pending }, a), confirmedPost);
    assert.equal(ready.kind, "ready");
    assert.equal(ready.pending.state, "readyToRegister");
    ok("and a confirmed one moves to readyToRegister");

    // Step two, through storage like everything else.
    const readyPending = JSON.parse(JSON.stringify(ready.pending));
    const registered = drive(
      (a) => key.planRegistrationComplete({ pending: readyPending }, a),
      confirmedPost,
    );
    assert.match(registered.hex, /^[0-9a-f]+$/);
    assert.equal(registered.name, "browsertest");
    assert.match(registered.identityAddress, /^i/);
    assert.equal(typeof registered.feePaid, "string");
    assert.ok(BigInt(registered.feePaid) > 0n);
    ok("the registration itself is built and signed, salt intact through storage");
  }

  // -- defining and launching a currency ------------------------------------
  //
  // The launch fee is burned and an identity defines exactly one currency,
  // ever. So the checks that happen before signing are the whole value here.
  {
    const base = {
      name: "browsertest",
      parent: VRSCTEST,
      kind: "fractional",
      startBlock: TIP + 1000,
      currencies: [VRSCTEST, "iQihXUcQt8G9TSh58YoM5NRwC1nAyoazFR"],
      weights: ["50000000", "50000000"],
      minPreconversion: ["0", "0"],
      maxPreconversion: ["0", "0"],
    };
    const a = new Answers();

    // **The reserve arrays are read positionally.** Nothing on chain notices
    // when they are not the same length: the launch pays its fee and creates a
    // currency whose reserves are not what its author meant. So each is
    // checked against `currencies`, by name.
    for (const field of ["weights", "minPreconversion", "maxPreconversion"]) {
      const broken = { ...base, [field]: base[field].slice(0, 1) };
      assert.throws(
        () => key.planLaunch({ identity: "browsertest@", definition: broken }, a),
        (e) => e.name === "InvalidArgument" && e.message.includes(field),
        `${field} misaligned with currencies must be refused by name`,
      );
    }
    ok("a misaligned reserve array is refused, by the name of the array");

    // A basket with no reserves is not a basket, and a token with reserves is
    // not a token. Both build cleanly and mean something else.
    assert.throws(
      () => key.planLaunch({ identity: "browsertest@", definition: {
        ...base, currencies: [], weights: [], minPreconversion: [], maxPreconversion: [] } }, a),
      (e) => e.name === "InvalidArgument" && /at least one/.test(e.message),
    );
    assert.throws(
      () => key.planLaunch({ identity: "browsertest@", definition: { ...base, kind: "token" } }, a),
      (e) => e.name === "InvalidArgument" && /holds no reserves/.test(e.message),
    );
    ok("and a basket without reserves, or a token with them, is refused");

    // A height is a JavaScript number, so it can arrive fractional or negative.
    // Truncating either picks a block nobody asked for, and `startBlock` is
    // when the currency launches.
    for (const bad of [TIP + 0.5, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      assert.throws(
        () => key.planLaunch(
          { identity: "browsertest@", definition: { ...base, startBlock: bad } }, a),
        (e) => e.name === "InvalidArgument" && /block height/.test(e.message),
      );
    }
    ok("a start height that is not a whole block is refused, not truncated");

    // The daemon ignores an explicit conversions vector and derives launch
    // prices at launch; contributions need a funding output this SDK does not
    // build. Neither field exists here, so passing one is an unknown key.
    for (const field of ["conversions", "initialContributions", "preconverted"]) {
      assert.throws(
        () => key.planLaunch(
          { identity: "browsertest@", definition: { ...base, [field]: ["1"] } }, a),
        (e) => e.name === "UnknownField",
      );
    }
    ok("fields the daemon derives or this SDK cannot fund are not accepted");

    a.free();
  }

  // -- a token send, all the way to signed bytes -----------------------------
  //
  // The refusals above never reach the builder, so nothing was proving the
  // token path crosses the boundary correctly. This drives it to `"ready"` and
  // compares against `key.sendToken` given the same inputs — the direct call
  // being the one already checked against the TypeScript SDK's vectors.
  {
    const TOKEN = "iQihXUcQt8G9TSh58YoM5NRwC1nAyoazFR";
    // A reserve output holding the token, and the native coins for the fee.
    //
    // The script is generated by `verus_tx::cc::reserve_output_script` for this
    // key and this currency — a real reserve output, not a stub, because the
    // builder decodes it. Gating the test on an export that does not exist was
    // the first attempt, and a gated test is one that silently does not run.
    const tokenUtxo = {
      txid: "cc".repeat(32),
      vout: 0,
      satoshis: "0",
      scriptPubKey:
        "1a040300010114aabfb6281561808fe200ab7e186f0e3e0e82b381cc34040309010114aabfb6281561808fe200ab7e186f0e3e0e82b3811901e908e3e5c373389fa7ae5d4b22a87ffc204a74ffaed6c10075",
    };
    const nativeUtxo = {
      txid: TXID, vout: 1, satoshis: String(SATS), scriptPubKey: SCRIPT,
    };

    const a = new Answers();
    let planned;
    for (;;) {
      const s = key.planSendToken(
        { currency: TOKEN, to: PAYEE, amount: "50000000", tokenUtxos: [tokenUtxo] }, a);
      if (s.kind === "ready") { planned = s.value; break; }
      for (const body of s.ask) a.record(body, post(body));
    }
    a.free();

    const direct = key.sendToken({
      utxos: [tokenUtxo, nativeUtxo],
      recipients: [{ address: PAYEE, currency: TOKEN, amount: "50000000" }],
      changeAddress: address,
      expiryHeight: TIP + EXPIRY_BLOCKS,
    });
    assert.equal(planned.hex, direct.hex);
    assert.equal(planned.txid, direct.txid);
    ok("a planned token send is byte-identical to a directly built one");
  }

  // -- a currency launch, all the way to signed bytes -------------------------
  //
  // The most irreversible operation in the API, and until now every assertion
  // about it was a refusal. This drives it to `"ready"` and reads the currency
  // definition back out of the transaction the page would post.
  {
    const LAUNCH_ID = "iHiamgHF3VdUXq3A6s5Mu61uhJM398MoRb";
    const ID_SCRIPT =
      "47040300010315049c3a5eee28817dbe3012929998e6ba7a04c41fde1504333333333333333333333333333333333333333315044444444444444444444444444444444444444444cc4cf004030e010115049c3a5eee28817dbe3012929998e6ba7a04c41fde4c9b03000000000000000114aabfb6281561808fe200ab7e186f0e3e0e82b38101000000a6ef9ea235635e328124ff3429db9f9e91b64e2d0361707001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01086e6f74206d696e65003333333333333333333333333333333333333333444444444444444444444444444444444444444400a6ef9ea235635e328124ff3429db9f9e91b64e2d000000001b04030f0101150433333333333333333333333333333333333333331b04031001011504444444444444444444444444444444444444444475";

    const launchReplies = {
      ...replies,
      getidentity: JSON.stringify({
        result: {
          blockheight: HEIGHT, fullyqualifiedname: "app.VRSCTEST@", status: "active",
          txid: TXID, vout: 0,
          identity: {
            identityaddress: LAUNCH_ID, minimumsignatures: 1, name: "app",
            primaryaddresses: [address], version: 3,
          },
        },
      }),
      getrawtransaction: JSON.stringify({
        result: { vout: [{ valueSat: 0, scriptPubKey: { hex: ID_SCRIPT } }] },
      }),
      getcurrency: readFileSync(
        resolve(here, "../../../../fixtures/rpc/getcurrency_vrsctest.json"), "utf8"),
      getaddressutxos: JSON.stringify({
        result: [{
          address, blocktime: 1785262420, height: HEIGHT, isspendable: 1,
          outputIndex: 0, satoshis: 500_00000000, script: SCRIPT, txid: TXID,
        }],
      }),
    };
    const launchPost = (b) => {
      const reply = launchReplies[JSON.parse(b).method];
      assert.ok(reply, `nothing recorded for ${JSON.parse(b).method}`);
      return reply;
    };

    const a = new Answers();
    let launched;
    for (;;) {
      const s = key.planLaunch({
        identity: LAUNCH_ID,
        definition: {
          name: "app", parent: VRSCTEST, kind: "token", startBlock: TIP + 1000,
        },
      }, a);
      if (s.kind === "ready") { launched = s.value; break; }
      for (const body of s.ask) a.record(body, launchPost(body));
    }
    a.free();

    assert.equal(launched.currencyId, LAUNCH_ID, "the currency takes the identity's id");
    assert.equal(launched.startBlock, TIP + 1000);
    assert.equal(typeof launched.launchFee, "string");
    assert.ok(BigInt(launched.launchFee) > 0n);

    // The definition itself, read back out of the bytes rather than from the
    // binding's report of what it built.
    const defined = outputScripts(launched.hex)
      .map((script) => {
        try { return decodeOutput(script); } catch { return null; }
      })
      .find((out) => out && out.kind === "unsupportedCryptoCondition" && out.evalCode === 12);
    assert.ok(defined, "the launch carries a currency definition output");
    ok("a currency launch is planned, signed, and carries its definition");
  }

  // -- the stored registration is rebuilt, not trusted -----------------------
  //
  // `pending` used to be a sanitizer leaf, which made it the one request object
  // in the crate that `from_js` did not rebuild. Everything the top level
  // refuses was accepted one level down — including `state` supplied from a
  // polluted `Object.prototype`, which walks straight past the runtime step
  // check that stands in for Rust's type-level ordering.
  {
    // The same replies the registration block uses: a free name, chain policy,
    // and an address that can cover the fee.
    const pollReplies = {
      ...replies,
      getidentity: JSON.stringify({ error: { code: -5, message: "Identity not found" } }),
      getcurrency: readFileSync(
        resolve(here, "../../../../fixtures/rpc/getcurrency_vrsctest.json"), "utf8"),
      getaddressutxos: JSON.stringify({
        result: [{
          address, blocktime: 1785262420, height: HEIGHT, isspendable: 1,
          outputIndex: 0, satoshis: 200_00000000, script: SCRIPT, txid: TXID,
        }],
      }),
    };
    const pollPost = (b) => {
      const reply = pollReplies[JSON.parse(b).method];
      assert.ok(reply, `nothing recorded for ${JSON.parse(b).method}`);
      return reply;
    };

    const a = new Answers();
    const claimed = (() => {
      for (;;) {
        const s = key.planRegistration({ name: "pollution", salt: "22".repeat(32) }, a);
        if (s.kind === "ready") return s.value;
        for (const body of s.ask) a.record(body, pollPost(body));
      }
    })();
    a.free();

    const stripped = { ...claimed };
    delete stripped.state;
    Object.defineProperty(Object.prototype, "state", {
      value: "readyToRegister", configurable: true, writable: true,
    });
    try {
      const b = new Answers();
      assert.throws(
        () => key.planRegistrationComplete({ pending: stripped }, b),
        (e) => e.name === "InvalidArgument" || e.name === "UnknownField",
        "a state read off the prototype chain must not satisfy the step check",
      );
      b.free();
    } finally {
      delete Object.prototype.state;
    }

    // And a stray key inside the stored value is refused, with the path.
    const strayInside = { ...claimed, registratoinFee: "1" };
    const c = new Answers();
    assert.throws(
      () => key.planRegistrationComplete({ pending: strayInside }, c),
      (e) => e.name === "UnknownField",
    );
    c.free();
    ok("a stored registration is rebuilt like every other request object");
  }

  // -- an oversized reply is refused before it is copied ---------------------
  //
  // The ceiling exists because copying an unbounded body into linear memory
  // does not throw, it kills the instance — with any imported key inside it.
  // Enforcing it after the copy protected only callers who had already
  // survived the thing it guards against.
  {
    const a = new Answers();
    assert.throws(
      () => a.record("body", "x".repeat(300 * 1024 * 1024)),
      (e) => e.name === "ReplyTooLarge",
    );
    a.free();
    // The module is still usable, which is the whole point.
    assert.equal(parseCoins("1.5"), "150000000");
    ok("an oversized reply is refused by name, and the module survives it");
  }

  // -- the request sanitizer applies here too ------------------------------
  {
    const spare = new Answers();
    assert.throws(
      () => key.planSend({ to: PAYEE, satoshis: "1", expiryHieght: 1 }, spare),
      (e) => e.name === "UnknownField",
    );
    assert.throws(
      () => key.planSend({ to: PAYEE, satoshis: 150000000 }, spare),
      (e) => e.name === "InvalidArgument",
    );
    spare.free();
    ok("a plan request is sanitized like every other request");
  }

  key.free();
}

// Asserted, not just printed. A block that stopped running would otherwise
// only lower a number nobody reads — which is exactly how a silently skipped
// test survived in this file before.
const EXPECTED_CHECKS = 96;
assert.equal(
  checks,
  EXPECTED_CHECKS,
  `expected ${EXPECTED_CHECKS} checks; update this deliberately when adding one`,
);

console.log(`\n${checks} checks passed under node ${process.version}\n`);
