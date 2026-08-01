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
  Answers,
  planHistory,
  parseCoins,
  formatCoins,
  verifyMessage,
  signatureBlockHeight,
  decodeOutput,
  tokenBalances,
  validateMnemonic,
  mnemonicToSeed,
  vdxfKey,
  identityId,
  type SendRequest,
  type TokenSendRequest,
  type SignedTransaction,
  type VerifyRequest,
  type VerifyResult,
  type DecodedOutput,
  type DecodedReserveOutput,
  type MnemonicCheck,
  type Utxo,
  type TokenAmount,
  type PlanSendRequest,
  type SendStep,
  type HistoryRequest,
  type HistoryStep,
  type HistoryEntry,
  type PlannedTransaction,
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

// Narrowing must produce fields that are PRESENT, not `T | undefined`. These
// annotations are the test: if the union collapsed back into one interface with
// optional fields, every line below fails to compile.
if (output.kind === "unsupportedCryptoCondition") {
  const evalCode: number = output.evalCode;
  // The flag a wallet needs to tell "undecodable and harmless" — a staker's
  // coinbase — from "undecodable and possibly holding your money".
  const mayCarryCurrency: boolean = output.mayCarryCurrency;
  void [evalCode, mayCarryCurrency];
}
if (output.kind === "identityCommitment") {
  const commitment: string = output.commitment;
  // Present and empty for an ordinary commitment; the advanced form carries
  // currency alongside the hash.
  const carried: TokenAmount[] = output.tokens;
  void [commitment, carried];
}
if (output.kind === "reserveTransfer") {
  const flags: number = output.flags;
  const fees: string = output.fees;
  // The real recipient, which is not `address` — that is the protocol's
  // transfer address, identical for every transfer on the chain.
  const recipient: string = output.recipient;
  void [flags, fees, recipient, output.feeCurrency, output.destinationCurrency];
}
if (output.kind === "reserveDeposit") {
  const controlling: string = output.controllingCurrency;
  void controlling;
}

// A `switch` over every member must leave `never` — the check that the union
// is closed, and the thing that makes adding a variant a compile error in
// consuming code rather than a silent fallthrough.
function describe(o: DecodedOutput): string {
  switch (o.kind) {
    case "pubKeyHash":
    case "pubKey":
    case "identityPayment":
      return o.address;
    case "reserveOutput":
      return `${o.address} holds ${o.tokens.length}`;
    case "identityPrimary":
      return `${o.name} ${o.minimumSignatures}/${o.primaryAddresses.length}`;
    case "identityCommitment":
      return o.commitment;
    case "reserveDeposit":
      return o.controllingCurrency;
    case "reserveTransfer":
      return `${o.recipient} via ${o.destinationCurrency}`;
    case "unsupportedCryptoCondition":
      return `eval ${o.evalCode}`;
    case "unknown":
      return "unknown";
    default: {
      const exhaustive: never = o;
      return exhaustive;
    }
  }
}
void describe(output);

// The individual members are exported too, so a wallet can write a handler per
// shape rather than one switch.
declare const one: DecodedReserveOutput;
const held: TokenAmount[] = one.tokens;
void held;

// `null` for "I do not know the chain's own currency id" — only reserve
// deposits and transfers need it, and they are refused without it.
const balances: TokenAmount[] = tokenBalances([utxo], null);
const balancesOnChain: TokenAmount[] = tokenBalances([utxo], "iJhCez…");
void balancesOnChain;
const owed: string = balances[0].amount;
const which: string = balances[0].currency;
void [vdxfKey("app::profile", "VRSCTEST", "iJhCez…"), identityId("alice", null), owed, which];

const phrase: MnemonicCheck = validateMnemonic("abandon … about");
const isValid: boolean = phrase.valid;
const howMany: number = phrase.words;
// `reason` must be a closed set, so a caller can switch on it exhaustively —
// and `wordCount` must be distinguishable, since it is the one that is NOT a
// problem for a transparent Verus key.
const phraseReason: "wordCount" | "unknownWord" | "checksum" | undefined = phrase.reason;
const at: number | undefined = phrase.position;
// Bytes, not hex: a Uint8Array can be zeroed when the caller is done.
const seed: Uint8Array = mnemonicToSeed("abandon … about", null);
void [isValid, howMany, phraseReason, at, seed];

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

// A field belongs to the shape that has it. Before the union these compiled
// and returned `undefined` at runtime — a wallet could read the fee off a plain
// payment and get nothing, with no signal that it had asked the wrong question.
// @ts-expect-error fees exists only on a reserveTransfer
const wrongShape: string = decodeOutput(utxo.scriptPubKey).fees;

// Narrowing to one member does not unlock another member's fields.
const narrowed = decodeOutput(utxo.scriptPubKey);
if (narrowed.kind === "reserveDeposit") {
  // @ts-expect-error a reserveDeposit has no recipient — that is a transfer
  const notHere: string = narrowed.recipient;
  void notHere;
}

// An unreadable output must not look payable: it carries no address at all,
// and the types have to say so or a caller will pay to `undefined`.
if (narrowed.kind === "unsupportedCryptoCondition") {
  // @ts-expect-error an unreadable output has no address
  const payable: string = narrowed.address;
  void payable;
}

// A reason outside the closed set is a typo in the caller's code, and the
// commonest one is assuming an "ok"/"valid" member exists alongside the
// failures. It does not — `valid` carries that.
// @ts-expect-error "valid" is not one of the reasons
const notAReason: boolean = validateMnemonic("…").reason === "valid";

// ---------------------------------------------------------------------------
// The flow bindings.
// ---------------------------------------------------------------------------

declare const answers: Answers;

const plan: PlanSendRequest = { to: "RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX", satoshis: "150000000" };
const step: SendStep = key.planSend(plan, answers);

// `ask` is a list of complete request bodies, so it has to be strings — a
// declaration that let them be objects would invite a caller to re-encode
// them, and a re-encoded body is a cache key that matches nothing.
const bodies: string[] = step.ask;

// The payload is optional, because an asking round has none. A `.d.ts` that
// declared it required would let a caller read `step.transaction.hex` on an
// "ask" round and get a runtime `TypeError`.
const built: PlannedTransaction | undefined = step.transaction;

// And a planned transaction is NOT a SignedTransaction: it carries no
// inputsUsed, because a flow does not report them and an empty list would be a
// lie about which coins are committed.
// @ts-expect-error a planned transaction does not list its inputs
const inputs = step.transaction?.inputsUsed;

const read: HistoryRequest = { addresses: ["RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX"] };
const reading: HistoryStep = planHistory(read, answers);
const entries: HistoryEntry[] | undefined = reading.entries;

// Money is a string here too, and the per-currency map is strings all the way
// down — this is exactly where a `Record<string, number>` would quietly round.
const moved: string | undefined = entries?.[0].netNative;
const perCurrency: Record<string, string> | undefined = entries?.[0].netCurrencies;

// @ts-expect-error an amount is a decimal string, never a number
const numericAmount: PlanSendRequest = { to: "R…", satoshis: 150000000 };

// @ts-expect-error a mistyped optional field is refused, as everywhere else
const misspelled: HistoryRequest = { addresses: [], startHieght: 1 };

// @ts-expect-error a height range is a number, not a decimal string
const stringHeight: HistoryRequest = { addresses: [], startHeight: "1" };

void [floatMoney, typo, unbounded, confused, wrongShape, notAReason];
void [bodies, built, inputs, entries, moved, perCurrency];
void [numericAmount, misspelled, stringHeight];
