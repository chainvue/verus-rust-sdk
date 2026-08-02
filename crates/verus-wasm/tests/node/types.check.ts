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
  planVerifyLogin,
  planSpendable,
  planContent,
  planOffers,
  planOfferTerms,
  planCommitmentStatus,
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
  type PlanSendTokenRequest,
  type PlanSendFromIdentityRequest,
  type PlanPublishRequest,
  type TransactionStep,
  type UpdateStep,
  type PlannedUpdate,
  type HistoryRequest,
  type HistoryStep,
  type HistoryEntry,
  type PlannedTransaction,
  type PlanStep,
  type VerifyLoginRequest,
  type LoggedIn,
  type SpendableRequest,
  type Funding,
  type ContentRequest,
  type Content,
  type OffersRequest,
  type Listing,
  type OfferSide,
  type OfferTerms,
  type Demand,
  type TakeOfferRequest,
  type Taken,
  type PlanConvertRequest,
  type PlanBurnRequest,
  type PlanMintRequest,
  type PlanRegistrationRequest,
  type Pending,
  type CommitmentStatus,
  type Registered,
  type PlanLaunchRequest,
  type CurrencyDefinition,
  type Launched,
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
const step: TransactionStep = key.planSend(plan, answers);

// `ask` is a list of complete request bodies, so it has to be strings — a
// declaration that let them be objects would invite a caller to re-encode
// them, and a re-encoded body is a cache key that matches nothing.
const bodies: string[] = step.ask;

// The payload is optional, because an asking round has none. A `.d.ts` that
// declared it required would let a caller read `step.transaction.hex` on an
// "ask" round and get a runtime `TypeError`.
const built: PlannedTransaction | undefined = step.value;

// And a planned transaction is NOT a SignedTransaction: it carries no
// inputsUsed, because a flow does not report them and an empty list would be a
// lie about which coins are committed.
// @ts-expect-error a planned transaction does not list its inputs
const inputs = step.value?.inputsUsed;

const read: HistoryRequest = { addresses: ["RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX"] };
const reading: HistoryStep = planHistory(read, answers);
const entries: HistoryEntry[] | undefined = reading.value;

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
// Every plan returns the same shape with a different payload, and the payload
// has to be typed — `PlanStep<unknown>` everywhere would mean casting at every
// call site, which is where the type would stop being checked at all.
const session: VerifyLoginStepPayload = planVerifyLogin(
  { identity: "alice@", signature: "…", audience: "https://example.com", challenge: "abc" },
  answers,
).value;
type VerifyLoginStepPayload = LoggedIn | undefined;

const spendable: Funding | undefined = planSpendable({ address: "R…" }, answers).value;
const stored: Content | undefined = planContent({ identity: "alice@" }, answers).value;

// Narrowing on `kind` is the intended ergonomics, and it has to actually work.
const narrowedPlan = planSpendable({ address: "R…" }, answers);
if (narrowedPlan.kind === "ready") {
  // @ts-expect-error a Funding has no `entries`
  const wrong = narrowedPlan.value?.entries;
  void wrong;
}

// The generic is real, not a name: a step's payload is not interchangeable.
// @ts-expect-error a spendable step does not carry a LoggedIn
const mismatched: PlanStep<LoggedIn> = planSpendable({ address: "R…" }, answers);

// On one line deliberately: `@ts-expect-error` covers the next *line*, not the
// next statement, so a multi-line literal puts the error out of its reach and
// the directive reads as unused.
// @ts-expect-error a login policy bound is a number of blocks, not a string
const badPolicy: VerifyLoginRequest = { identity: "a@", signature: "s", audience: "a", challenge: "b", maxAgeBlocks: "60" };

// @ts-expect-error an address is required
const noAddress: SpendableRequest = {};

// @ts-expect-error a mistyped optional field is refused here too
const strayKey: ContentRequest = { identity: "alice@", identityy: "x" };

// The write plans. A token send needs its token outputs named; money inside
// them is a string like everywhere else.
const tokenPlan: PlanSendTokenRequest = {
  currency: "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq",
  to: "RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX",
  amount: "150000000",
  tokenUtxos: [utxo],
};
const tokenStep: TransactionStep = key.planSendToken(tokenPlan, answers);

const idPlan: PlanSendFromIdentityRequest = {
  identity: "holder@", to: "RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX", satoshis: "1",
};
const idStep: TransactionStep = key.planSendFromIdentity(idPlan, answers);

const publishPlan: PlanPublishRequest = {
  identity: "app@", key: "iGRp1CGkuro3LtGazX8W1PRjVupPVfe8Pv", values: ["6d696e65"],
};
const update: PlannedUpdate | undefined = key.planPublish(publishPlan, answers).value;

// An update reports its fee, as a decimal string like every other amount.
const publishStep: UpdateStep = key.planPublish(publishPlan, answers);
const updateFee: string | undefined = publishStep.value?.fee;
// @ts-expect-error the fee is a decimal string, never a number
const numericFee: number | undefined = publishStep.value?.fee;

// @ts-expect-error a token amount is a decimal string, never a number
const numericToken: PlanSendTokenRequest = { currency: "i", to: "R", amount: 1, tokenUtxos: [] };

// @ts-expect-error values are hex strings, not bytes
const rawValues: PlanPublishRequest = { identity: "a@", key: "i", values: [new Uint8Array()] };

// Offers. Either side of an offer can be currencies or an identity, so the
// union has to narrow — a caller reading `identityId` off a currencies side
// would get `undefined` at runtime with no signal.
const browse: OffersRequest = { target: "iJhCez…", isCurrency: true };
const listings: Listing[] | undefined = planOffers(browse, answers).value;
const side: OfferSide | undefined = listings?.[0].offering;
if (side && side.kind === "identity") {
  const who: string = side.identityId;
  void who;
}
if (side && side.kind === "currencies") {
  // @ts-expect-error a currencies side names no identity
  const notHere = side.identityId;
  void notHere;
}

const terms: OfferTerms | undefined = planOfferTerms({ offer: "00" }, answers).value;
const demand: Demand | undefined = terms?.demand;
if (demand && demand.kind === "token") {
  const which: string = demand.currency;
  void which;
}
if (demand && demand.kind === "native") {
  // @ts-expect-error a native demand names no currency
  const noCurrency = demand.currency;
  void noCurrency;
}

// A price is text, and typing it as a number would be exactly the rounding the
// SDK refuses everywhere else.
// @ts-expect-error a price is verbatim text, not a number
const numericPrice: number | undefined = listings?.[0].price;

const take: TakeOfferRequest = {
  offer: "00", utxos: [utxo], recipient: "R…", changeAddress: "R…", fee: "20000",
};
const taken: Taken | undefined = key.planTakeOffer(take, answers).value;

// @ts-expect-error a miner fee is a decimal string, never a number
const numericTakeFee: TakeOfferRequest = { offer: "00", utxos: [], recipient: "R", changeAddress: "R", fee: 20000 };

// Conversions. The kind is a closed set, so a typo is a compile error rather
// than a runtime one — and `"burn"` is deliberately not in it.
const convert: PlanConvertRequest = {
  from: "iJhCez…", amount: "150000000", kind: "intoFractional",
  into: "iQihX…", recipient: "R…", fee: "20010",
};
const converted: TransactionStep = key.planConvert(convert, answers);

// @ts-expect-error a burn is not a conversion kind; planBurn exists separately
const burnAsKind: PlanConvertRequest = { ...convert, kind: "burn" };

// @ts-expect-error a mint is not a conversion kind either
const mintAsKind: PlanConvertRequest = { ...convert, kind: "mint" };

// @ts-expect-error and a misspelled kind does not silently become something
const typoKind: PlanConvertRequest = { ...convert, kind: "intoFractionall" };

const burn: PlanBurnRequest = { currency: "iQihX…", amount: "1", fee: "20010" };
const mint: PlanMintRequest = {
  currency: "iQihX…", amount: "1", recipient: "R…", fee: "20010",
};
void [key.planBurn(burn, answers), key.planMint(mint, answers)];

// @ts-expect-error minExpected is a decimal string, never a number
const numericFloor: PlanConvertRequest = { ...convert, minExpected: 1000 };

// Registration. The pending value is opaque and round-trips through storage,
// so it has to survive `JSON.parse(JSON.stringify(...))` as the same type.
const nameClaim: PlanRegistrationRequest = { name: "alice" };
const pending: Pending | undefined = key.planRegistration(nameClaim, answers).value;
const restored: Pending = JSON.parse(JSON.stringify(pending));

// The blob is a string, not an object: a page stores it, it does not read it.
// Typing it as an object would invite parsing and re-encoding, and a
// re-encoded blob is one whose salt nobody checked.
const blob: string | undefined = pending?.pending;
// @ts-expect-error the stored state is opaque text, not a structure
const peeked: { reservation: unknown } | undefined = pending?.pending;

// The step is a closed set, so a typo in a comparison is caught rather than
// silently never matching.
// @ts-expect-error "confirmed" is not one of the two steps
const badState: boolean = restored.state === "confirmed";

// The status union has to narrow — a caller reading `confirmations` off a
// "ready" status would get `undefined` at runtime with no signal.
const status: CommitmentStatus | undefined =
  planCommitmentStatus({ pending: restored }, answers).value;
if (status && status.kind === "waiting") {
  const seen: number = status.confirmations;
  void seen;
}
if (status && status.kind === "ready") {
  // @ts-expect-error a ready status reports no confirmation count
  const notHere = status.confirmations;
  void notHere;
}
if (status && status.kind === "reorged") {
  const why: string = status.detail;
  void why;
}

const registered: Registered | undefined =
  key.planRegistrationComplete({ pending: restored }, answers).value;
// Money is a string here too.
const paid: string | undefined = registered?.feePaid;

// @ts-expect-error a pinned fee is a decimal string, never a number
const numericPin: PlanRegistrationRequest = { name: "alice", pinFee: 10000000000 };

// A currency launch. The kind is a closed set and the reserve arrays are all
// strings, because they are money.
const definition: CurrencyDefinition = {
  name: "basket", parent: "iJhCez…", kind: "fractional", startBlock: 1200000,
  currencies: ["iJhCez…"], weights: ["100000000"],
};
const launched: Launched | undefined =
  key.planLaunch({ identity: "basket@", definition }, answers).value;
const burned: string | undefined = launched?.launchFee;

// @ts-expect-error a weight is a decimal string, never a number
const numericWeight: CurrencyDefinition = { ...definition, weights: [100000000] };

// @ts-expect-error a currency is either a token or a basket
const oddKind: CurrencyDefinition = { ...definition, kind: "nft" };

// @ts-expect-error a start height is a block number, not a decimal string
const stringStart: CurrencyDefinition = { ...definition, startBlock: "1200000" };

// @ts-expect-error the daemon derives launch prices; conversions is not settable
const setPrices: CurrencyDefinition = { ...definition, conversions: ["1"] };

// @ts-expect-error a contribution needs a funding output this SDK does not build
const handSet: CurrencyDefinition = { ...definition, initialContributions: ["1"] };

// One line, because `@ts-expect-error` covers the next line and not the next
// statement — a multi-line literal puts the error out of its reach.
// @ts-expect-error a pinned launch fee is a decimal string
const numericPinnedLaunch: PlanLaunchRequest = { identity: "b@", definition, pinLaunchFee: 1 };

void [numericAmount, misspelled, stringHeight];
void [launched, burned, numericWeight, oddKind, stringStart, setPrices, handSet, numericPinnedLaunch];
void [pending, restored, blob, peeked, badState, status, registered, paid, numericPin];
void [converted, burnAsKind, mintAsKind, typoKind, numericFloor];
void [listings, side, terms, demand, numericPrice, taken, numericTakeFee];
void [tokenStep, idStep, update, publishStep, updateFee, numericFee, numericToken, rawValues];
void [session, spendable, stored, mismatched, badPolicy, noAddress, strayKey];
