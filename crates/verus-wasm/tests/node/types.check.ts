// Does the published TypeScript actually describe the API?
//
// `tsc --noEmit` on the generated `.d.ts` alone only proves it parses. This
// file *uses* it, the way an application would, so the declarations have to be
// right rather than merely well-formed:
//
//   * excess-property checking on these object literals fails if a field is
//     declared with the wrong name;
//   * the annotations fail if a field is missing, or typed as the wrong thing;
//   * the deliberate `@ts-expect-error` lines fail if a rule the API promises —
//     money is a string, an unknown field is not accepted — has quietly
//     stopped being expressed in the types.
//
// The last group is the point. A test that only writes *correct* code passes
// just as happily against a `.d.ts` full of `any`.
//
// Not compiled into anything: `tsc --noEmit` is the whole test.

import {
  Key,
  parseCoins,
  formatCoins,
  verifyMessage,
  signatureBlockHeight,
  decodeOutput,
  tokenBalances,
  vdxfKey,
  identityId,
  type SendRequest,
  type TokenSendRequest,
  type SignedTransaction,
  type VerifyRequest,
  type VerifyResult,
  type DecodedOutput,
  type Utxo,
  type TokenAmount,
} from "../../pkg/verus_wasm.js";

declare const key: Key;
declare const tip: number;

const utxo: Utxo = {
  txid: "aa".repeat(32),
  vout: 0,
  satoshis: "1000000000",
  scriptPubKey: "76a914" + "22".repeat(20) + "88ac",
};

const send: SendRequest = {
  utxos: [utxo],
  recipients: [{ address: "RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX", satoshis: parseCoins("1.5") }],
  changeAddress: key.address(),
  expiryHeight: tip + 20,
};

const tokens: TokenSendRequest = {
  utxos: [utxo],
  recipients: [{ address: "RQr2…", currency: "iJhCez…", amount: "100000000" }],
  changeAddress: key.address(),
};

// Optional fields must really be optional.
const minimal: SendRequest = {
  utxos: [utxo],
  recipients: [{ address: "RQr2…", satoshis: "1" }],
  changeAddress: "RQr2…",
};

const signed: SignedTransaction = key.send(send);
const alsoSigned: SignedTransaction = key.sendToken(tokens);
const hex: string = signed.hex;
const fee: string = signed.fee;
const change: string = signed.change;
const spent: string = signed.inputsUsed[0].txid;
const coins: string = formatCoins(signed.fee);
void [minimal, alsoSigned, hex, fee, change, spent, coins];

const verify: VerifyRequest = {
  identity: "iL9bc…",
  systemId: "iJhCez…",
  message: "log me in",
  signature: key.signMessage({
    identity: "iL9bc…", systemId: "iJhCez…", blockHeight: tip, message: "log me in",
  }),
  primaryAddresses: [key.address()],
  minimumSignatures: 1,
  currentHeight: tip,
  maxAgeBlocks: 60,
};
const claim: VerifyResult = verifyMessage(verify);
const why: "stale" | "future" | "threshold" | undefined = claim.reason;
void [signatureBlockHeight(verify.signature), why];

const output: DecodedOutput = decodeOutput(utxo.scriptPubKey);
if (output.kind === "unsupportedCryptoCondition") {
  const evalCode: number | undefined = output.evalCode;
  void evalCode;
}
const balances: TokenAmount[] = tokenBalances([utxo]);
const owed: string = balances[0].amount;
const which: string = balances[0].currency;
void [vdxfKey("app::profile", "VRSCTEST", "iJhCez…"), identityId("alice", null), owed, which];

// --- What the types must REFUSE. Each line fails the build if it compiles. ---

// Money is a string. A number is the mistake the whole convention exists for.
// @ts-expect-error satoshis is a decimal string, never a number
const floatMoney: Utxo = { ...utxo, satoshis: 1e8 };

// An unknown field is not part of the request — the runtime refuses it, and the
// types should say so before the code ever runs.
// @ts-expect-error expiryHieght is not a field of SendRequest
const typo: SendRequest = { ...send, expiryHieght: tip + 20 };

// The height bound is required: a verifier must not be able to forget it.
// @ts-expect-error currentHeight and maxAgeBlocks are required
const unbounded: VerifyRequest = {
  identity: "i…", systemId: "i…", message: "m", signature: "s",
  primaryAddresses: [], minimumSignatures: 1,
};

// A token recipient is not a native one. This is the shape a caller writes
// when they reach for `send` and meant `sendToken`; the runtime refuses it, and
// so must the types.
const confused: SendRequest = {
  ...send,
  // @ts-expect-error a native recipient has no currency
  recipients: [{ address: "R…", satoshis: "1", currency: "i…" }],
};

void [floatMoney, typo, unbounded, confused];
