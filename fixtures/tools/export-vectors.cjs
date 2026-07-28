/**
 * Regenerate fixtures/transparent/vectors.json from @chainvue/verus-sdk.
 *
 * The TypeScript SDK is daemon-proven and deterministic on this path (RFC6979
 * signing, no randomness), so its output is a byte-exact oracle for the Rust
 * implementation. The vectors it produces are COMMITTED test data — nothing is
 * fetched at build or test time, and this repo has no build dependency on the
 * TypeScript one.
 *
 * Run it only when a rule genuinely changes on the TypeScript side, and expect
 * to review the byte diff rather than rubber-stamp it: a change here means every
 * transaction the Rust code produces has moved.
 *
 *   SDK=/path/to/verus-sdk \
 *     NODE_PATH=$SDK/node_modules node fixtures/tools/export-vectors.cjs
 *
 * Requires a built checkout of verus-sdk (`pnpm build && pnpm bundle`).
 */

const SDK_PATH = process.env.SDK || "/Users/robertlech/Developer/verus-sdk";
const { VerusSDK } = require(`${SDK_PATH}/dist/bundle.js`);
const fs = require("node:fs");

const NETWORK = "testnet";
const TEST_WIF = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";
const TEST_ADDRESS = "RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX";
const TEST_ADDRESS_B = "RPsQDnaxXgrLjcVBh3SpvCpTabWxAdMdzu";
const TEST_ADDRESS_C = "RSS3Qz5hzEVSV6hziLXaD2xPbw9UVpJoXs";
const VRSCTEST_SYSTEM_ID = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";

function p2pkh(address) {
  const hash = require("bs58check").decode(address).slice(1);
  return "76a914" + Buffer.from(hash).toString("hex") + "88ac";
}
const SCRIPT = p2pkh(TEST_ADDRESS);


// A reserve (token-bearing) output script, built from the layout documented in
// crates/verus-tx/src/cc.rs. Used to synthesise a token-carrying UTXO to spend.
function varInt(value) {
  const out = [];
  let n = BigInt(value);
  let first = true;
  for (;;) {
    out.push(Number(n & 0x7fn) | (first ? 0 : 0x80));
    if (n <= 0x7fn) break;
    n = (n >> 7n) - 1n;
    first = false;
  }
  return Buffer.from(out.reverse());
}
function push(buf) {
  return Buffer.concat([Buffer.from([buf.length]), buf]);
}
function reserveOutputScript(destHash, currencyHash, amount) {
  const master = Buffer.concat([push(Buffer.from([3, 0, 1, 1])), push(destHash)]);
  const tokenOutput = Buffer.concat([varInt(1), currencyHash, varInt(amount)]);
  const params = Buffer.concat([
    push(Buffer.from([3, 9, 1, 1])), push(destHash), push(tokenOutput),
  ]);
  return Buffer.concat([push(master), Buffer.from([0xcc]), push(params), Buffer.from([0x75])]).toString("hex");
}
function hash160Of(address) {
  return Buffer.from(require("bs58check").decode(address).slice(1));
}

function utxo(txidPattern, satoshis, vout = 0, script = SCRIPT) {
  const txid = txidPattern.repeat(Math.ceil(64 / txidPattern.length)).slice(0, 64);
  return { txid, outputIndex: vout, satoshis, script };
}

// Each case exercises a distinct branch of the fee/selection/change logic.
const CASES = [
  {
    name: "single_utxo_single_output",
    why: "the baseline: one input, one recipient, change above dust",
    utxos: [utxo("aa", 100_000_000n)],
    outputs: [{ address: TEST_ADDRESS_B, satoshis: 50_000_000n }],
    expiryHeight: 0,
  },
  {
    name: "multi_utxo_selection",
    why: "needs two inputs; exercises the accumulation loop and its fee re-estimate",
    utxos: [utxo("aa", 30_000_000n), utxo("bb", 30_000_000n), utxo("cc", 30_000_000n)],
    outputs: [{ address: TEST_ADDRESS_B, satoshis: 45_000_000n }],
    expiryHeight: 0,
  },
  {
    name: "multi_output",
    why: "two recipients: numOutputs feeds the fee estimate, so this moves the change",
    utxos: [utxo("aa", 100_000_000n)],
    outputs: [
      { address: TEST_ADDRESS_B, satoshis: 20_000_000n },
      { address: TEST_ADDRESS_C, satoshis: 30_000_000n },
    ],
    expiryHeight: 0,
  },
  {
    name: "descending_selection_order",
    why: "candidates must be sorted largest-first regardless of input order",
    utxos: [utxo("aa", 1_000_000n), utxo("bb", 100_000_000n), utxo("cc", 5_000_000n)],
    outputs: [{ address: TEST_ADDRESS_B, satoshis: 60_000_000n }],
    expiryHeight: 0,
  },
  {
    name: "above_the_2_32_satoshi_blind_spot",
    why: "input value above 2^32 sats, where the JS fork's own fee guard truncates and goes blind",
    utxos: [utxo("aa", 50_000_000_000n)],
    outputs: [{ address: TEST_ADDRESS_B, satoshis: 40_000_000_000n }],
    expiryHeight: 0,
  },
  {
    name: "nonzero_expiry_height",
    why: "expiryHeight is committed to by the sighash, so a nonzero value must be carried",
    utxos: [utxo("aa", 100_000_000n)],
    outputs: [{ address: TEST_ADDRESS_B, satoshis: 50_000_000n }],
    expiryHeight: 1_234_567,
  },
];


const TOKEN = VerusSDK.deriveIdentityAddress("goldsendtoken", VRSCTEST_SYSTEM_ID);
const TOKEN_HASH = hash160Of(TOKEN);
const TOKEN_UTXO_SCRIPT = reserveOutputScript(hash160Of(TEST_ADDRESS), TOKEN_HASH, 100000000n);

CASES.push({
  name: "token_transfer_with_token_and_native_change",
  why: "two-phase selection: a token-bearing UTXO for the token, a native one for the fee; both token and native change",
  utxos: [utxo("cc", 0n, 0, TOKEN_UTXO_SCRIPT), utxo("aa", 100_000_000n)],
  outputs: [{ address: TEST_ADDRESS_B, satoshis: 40_000_000n, currency: TOKEN }],
  expiryHeight: 0,
});

const vectors = CASES.map((c) => {
  const result = VerusSDK.prototype.sendCurrency.call(
    { network: NETWORK },
    {
      wif: TEST_WIF,
      outputs: c.outputs.map((o) => ({
        currency: o.currency || VRSCTEST_SYSTEM_ID,
        satoshis: o.satoshis,
        address: o.address,
        addressType: "PKH",
      })),
      utxos: c.utxos,
      changeAddress: TEST_ADDRESS,
      expiryHeight: c.expiryHeight,
    },
  );
  return {
    name: c.name,
    why: c.why,
    wif: TEST_WIF,
    change_address: TEST_ADDRESS,
    expiry_height: c.expiryHeight,
    utxos: c.utxos.map((u) => ({
      txid: u.txid,
      vout: u.outputIndex,
      satoshis: Number(u.satoshis),
      script_pubkey: u.script,
    })),
    outputs: c.outputs.map((o) => ({ address: o.address, satoshis: Number(o.satoshis), currency: o.currency || null })),
    expected_signed_hex: result.signedTx,
    expected_txid: result.txid,
    expected_fee: Number(result.fee),
    expected_change: Number(result.nativeChange),
    expected_inputs_used: result.inputsUsed,
  };
});

const out = {
  source: "@chainvue/verus-sdk (TypeScript), generated by scratchpad/export-vectors.cjs",
  note: "The TypeScript SDK is daemon-proven and signs deterministically (RFC6979), so these bytes are an exact oracle.",
  network: NETWORK,
  vectors,
};
const path = require("node:path").join(__dirname, "..", "transparent", "vectors.json");
fs.mkdirSync(require("node:path").dirname(path), { recursive: true });
fs.writeFileSync(path, JSON.stringify(out, null, 2) + "\n");
for (const v of vectors) {
  console.log(`${v.name.padEnd(36)} fee=${v.expected_fee} change=${v.expected_change} inputs=${v.expected_inputs_used}`);
}
