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
        planContentHistory, parseCoins, formatCoins, satsPerCoin, decodeOutput,
        tokenBalances, verifyMessage, signatureBlockHeight, vdxfKey,
        rootNamespace, identityId, validateMnemonic, mnemonicToSeed } = wasm;

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

  assert.equal(rounds, 1, "the tip and the outputs go out together");
  assert.deepEqual(
    posted.map((body) => JSON.parse(body).method).sort(),
    ["getaddressutxos", "getblockcount"],
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
    assert.equal(funding.utxos.length, 1);
    assert.equal(funding.utxos[0].scriptPubKey, SCRIPT);
    ok("spendable coins are reported with the tip they were judged against");
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

console.log(`\n${checks} checks passed under node ${process.version}\n`);
