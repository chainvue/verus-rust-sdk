/**
 * An unspent output. `satoshis` is a decimal string, not a number — see the
 * note on `parseCoins`.
 */
export interface Utxo {
    /** The transaction that created it, in display order (as a daemon prints it). */
    txid: string;
    /** The output's index within that transaction. */
    vout: number;
    /** Its value in satoshis, as a decimal string. */
    satoshis: string;
    /** Its scriptPubKey, hex. */
    scriptPubKey: string;
}

/** One native payment. */
export interface Recipient {
    /** An `R…` address, or an `i…` VerusID. */
    address: string;
    /** How much, in satoshis, as a decimal string. */
    satoshis: string;
}

/** One token payment. */
export interface TokenRecipient {
    /** The `R…` address being paid. */
    address: string;
    /** Which token, named by its `i…` currency address. */
    currency: string;
    /** How much, in the token's smallest unit, as a decimal string. */
    amount: string;
}

/** What to build for a native send. */
export interface SendRequest {
    /** UTXOs available to spend. Every one must be plain P2PKH paying this key. */
    utxos: Utxo[];
    /** Where the value goes. */
    recipients: Recipient[];
    /** Where change returns. Must be an `R…` address. */
    changeAddress: string;
    /**
     * The height past which this transaction can no longer be mined. Omit, or
     * pass null, for one that never expires — which is a deliberate choice,
     * not a default. `0` is refused: on the wire it means "never", but here it
     * is far more likely to be an uninitialised counter than a decision.
     */
    expiryHeight?: number | null;
    /**
     * Fee rate in satoshis per kilobyte, as a decimal string. Omit for the
     * default. Capped at one coin per kilobyte.
     */
    feePerKb?: string | null;
}

/** What to build for a token send. */
export interface TokenSendRequest {
    /** Token-bearing reserve outputs, plus native P2PKH to pay the miner fee. */
    utxos: Utxo[];
    /** Where the tokens go. */
    recipients: TokenRecipient[];
    /** Where both token and native change return. Must be an `R…` address. */
    changeAddress: string;
    /** The height past which this transaction can no longer be mined. `0` is refused. */
    expiryHeight?: number | null;
    /** Fee rate in satoshis per kilobyte, as a decimal string. Capped at one coin per kilobyte. */
    feePerKb?: string | null;
}

/** One outpoint: which output of which transaction. */
export interface Outpoint {
    /** The transaction, in display order. */
    txid: string;
    /** The output index. */
    vout: number;
}

/** A signed transaction, ready to broadcast. */
export interface SignedTransaction {
    /** The raw transaction, hex — what `sendrawtransaction` takes. */
    hex: string;
    /** Its txid in display order, known before it is broadcast. */
    txid: string;
    /** The miner fee paid, in satoshis, as a decimal string. */
    fee: string;
    /** Change returned, in satoshis; "0" if it would have been dust. */
    change: string;
    /** The outpoints spent, in input order. */
    inputsUsed: Outpoint[];
}

/** What to sign as a VerusID. */
export interface SignRequest {
    /** The identity signing, as its `i…` address. */
    identity: string;
    /** The chain, as its `i…` currency address. */
    systemId: string;
    /** The height the signature commits to; normally the current tip. */
    blockHeight: number;
    /** The message text. */
    message: string;
    /**
     * An existing signature to add to, base64, for an identity needing more
     * than one key. Its height must equal `blockHeight`.
     */
    existing?: string | null;
}

/** What to check. */
export interface VerifyRequest {
    /** The identity claimed, as its `i…` address. */
    identity: string;
    /** The chain, as its `i…` currency address. */
    systemId: string;
    /** The message text that was signed. */
    message: string;
    /** The signature, base64. */
    signature: string;
    /**
     * The identity's primary addresses AT THE SIGNATURE'S BLOCK HEIGHT — not
     * today's. `getidentity` takes a height for exactly this reason. Read the
     * height with `signatureBlockHeight` before you fetch these.
     */
    primaryAddresses: string[];
    /** The identity's `minimumsignatures` at that same height. */
    minimumSignatures: number;
    /**
     * YOUR current chain tip. Required: the height is chosen by whoever
     * signed, so without bounding it against your own tip a key that was
     * rotated out still authenticates — it just stamps an old height.
     */
    currentHeight: number;
    /**
     * How far back of `currentHeight` a signature may be stamped. Required and
     * not defaulted: it is how long a login stays signable, and equally how
     * long a rotated-out key keeps working.
     */
    maxAgeBlocks: number;
}

/** The outcome of a verification. */
export interface VerifyResult {
    /** Whether the signature is within the height window AND meets the threshold. */
    valid: boolean;
    /** The height the signature commits to. */
    blockHeight: number;
    /** Every address recovered, deduplicated — including any that are not the identity's. */
    signers: string[];
    /** Why `valid` is false, when it is. Absent when it is true. */
    reason?: "stale" | "future" | "threshold";
}

/**
 * How much of which token.
 *
 * Returned by `tokenBalances`, and carried inside a decoded `reserveOutput`.
 * The amount is in the currency's smallest unit and is NOT the output's
 * satoshi value — a reserve output carries native value as well as its token.
 */
export interface TokenAmount {
    /** The currency, as its `i…` address. */
    currency: string;
    /** The amount in its smallest unit, as a decimal string. */
    amount: string;
}

/**
 * What a recovery phrase turned out to be.
 *
 * Read the three answers differently — treating them alike is the bug this
 * exists to prevent. `wordCount` means the phrase is **not a mnemonic**, which
 * is perfectly ordinary for a Verus phrase: `Key.fromSeedPhrase` accepts any
 * text and derives a real transparent key from it. There is simply no shielded
 * key. `unknownWord` and `checksum` mean the phrase looks like a mnemonic and
 * is broken — almost always one mistyped or swapped word, and worth stopping a
 * user for before they conclude their wallet is empty.
 */
export interface MnemonicCheck {
    /** Whether it is a valid BIP-39 English mnemonic. */
    valid: boolean;
    /** How many words were found, so a UI can say "11 of 12". */
    words: number;
    /** Why not, when it is not. Absent when `valid`. */
    reason?: "wordCount" | "unknownWord" | "checksum";
    /**
     * For `unknownWord`: which word, counting from 1.
     *
     * The word ITSELF is deliberately not reported. This value reaches logs,
     * crash reporters and screenshots, and a recovery phrase is the whole
     * wallet.
     */
    position?: number;
}

/**
 * What an output turned out to be. Switch on `kind`.
 *
 * A discriminated union, so a field belongs to the shape that has it and to no
 * other: `output.fees` is a compile error until `kind` has been narrowed to
 * `reserveTransfer`, and once narrowed it is a `string` rather than a
 * `string | undefined` you have to assert your way past.
 *
 * ```ts
 * switch (output.kind) {
 *   case "pubKeyHash": return pay(output.address);
 *   case "reserveOutput": return credit(output.address, output.tokens);
 *   default: return leaveAlone();   // including anything added later
 * }
 * ```
 *
 * A caller with no branch for `unsupportedCryptoCondition` is a caller that
 * will one day spend an output it could not read.
 */
export type DecodedOutput =
    | DecodedPubKeyHash
    | DecodedPubKey
    | DecodedReserveOutput
    | DecodedIdentityPayment
    | DecodedIdentityPrimary
    | DecodedIdentityCommitment
    | DecodedReserveDeposit
    | DecodedReserveTransfer
    | DecodedUnsupportedCryptoCondition
    | DecodedUnknown;

/** A plain payment. Native value only. */
export interface DecodedPubKeyHash {
    kind: "pubKeyHash";
    /** The `R…` address paid. */
    address: string;
}

/**
 * A payment to a bare public key — the shape a proof-of-work coinbase pays.
 * Native value only.
 */
export interface DecodedPubKey {
    kind: "pubKey";
    /** The address controlling that key, which is what a daemon shows. */
    address: string;
}

/** An output carrying token value. */
export interface DecodedReserveOutput {
    kind: "reserveOutput";
    /**
     * The destination. May be an `i…` address: tokens held by a VerusID are an
     * ordinary shape, and only the identity's authority can spend one.
     */
    address: string;
    /** Token value carried, IN ADDITION to the output's native value. */
    tokens: TokenAmount[];
}

/** Native value held for an identity. */
export interface DecodedIdentityPayment {
    kind: "identityPayment";
    /** The `i…` address of the identity. */
    address: string;
}

/** The identity object itself. */
export interface DecodedIdentityPrimary {
    kind: "identityPrimary";
    /** The `i…` address of the identity. */
    address: string;
    /** The identity's name. */
    name: string;
    /** The addresses that control it. */
    primaryAddresses: string[];
    /** How many of them a spend needs. */
    minimumSignatures: number;
}

/** A name commitment, the first half of registering an identity. */
export interface DecodedIdentityCommitment {
    kind: "identityCommitment";
    /** The destination. */
    address: string;
    /**
     * The 32-byte commitment as hex, in the order the script holds it.
     *
     * The daemon prints this reversed, the way it prints every hash — reverse
     * it before comparing with `registernamecommitment` output.
     */
    commitment: string;
    /**
     * Empty for every ordinary commitment; only the advanced form carries
     * currency alongside the hash.
     */
    tokens: TokenAmount[];
}

/** Reserves backing a currency. */
export interface DecodedReserveDeposit {
    kind: "reserveDeposit";
    /** The destination. */
    address: string;
    /** The currency whose reserves the output holds. */
    controllingCurrency: string;
    /**
     * As written, the chain's own currency included — `tokenBalances` removes
     * that part, this reports the payload.
     */
    tokens: TokenAmount[];
}

/** Value in flight: a conversion, a burn, or a cross-chain send. */
export interface DecodedReserveTransfer {
    kind: "reserveTransfer";
    /** The protocol's transfer address, not a recipient — see `recipient`. */
    address: string;
    /** The token value carried. */
    tokens: TokenAmount[];
    /** The raw flag word. */
    flags: number;
    /** The currency the fee is paid in. */
    feeCurrency: string;
    /** The fee, in the smallest unit, as a decimal string. */
    fees: string;
    /** The currency in the destination slot. */
    destinationCurrency: string;
    /**
     * Who the value is ultimately for.
     *
     * NOT `address` — that is the same for every transfer on the chain. The
     * real recipient travels in the payload.
     */
    recipient: string;
}

/** An eval code this SDK does not decode. Do not select it as funding. */
export interface DecodedUnsupportedCryptoCondition {
    kind: "unsupportedCryptoCondition";
    /** The eval code found. */
    evalCode: number;
    /**
     * Whether an output with that eval code is ABLE to hold a token.
     *
     * `false` is a proof of absence taken from the chain's own
     * `CScript::ReserveOutValue`, not a guess, so `tokenBalances` counts such
     * an output as zero rather than throwing. The commonest case is the
     * stakeguard output (eval code 1) of a proof-of-stake coinbase, which
     * every staking address holds.
     *
     * `true` means the output may carry currency this SDK cannot see, and
     * `tokenBalances` refuses the whole set rather than under-report it.
     */
    mayCarryCurrency: boolean;
}

/**
 * A shape this build does not know. Carries no address, so a caller switching
 * on `kind` treats it the way it treats anything else it does not recognise —
 * by leaving the output alone.
 */
export interface DecodedUnknown {
    kind: "unknown";
}

/**
 * What to pay, and to whom. The rest — which coins to spend, what the
 * transaction should expire at, where change returns — is the SDK's.
 */
export interface PlanSendRequest {
    /** Where the value is going. An `R…` address, or an `i…` VerusID. */
    to: string;
    /** How much, in satoshis, as a decimal string. */
    satoshis: string;
}

/**
 * A transaction a flow built and signed. **Not broadcast** — posting it is the
 * page's, deliberately, and exactly once.
 *
 * If that post fails at the network level the outcome is ambiguous: it may have
 * been relayed before the connection dropped. Do **not** recover by planning
 * again — a fresh plan re-reads the UTXO set, still sees the coins as unspent,
 * and spends them a second time. Read the transaction back by `txid` instead,
 * and re-post this same `hex` only if it is genuinely absent.
 */
export interface PlannedTransaction {
    /** The raw transaction, hex — what `sendrawtransaction` takes. */
    hex: string;
    /** Its txid in display order, computed from `hex` before anything is sent. */
    txid: string;
    /** The miner fee paid, in satoshis, including any dust folded into it. */
    fee: string;
    /** Change returned, in satoshis; `"0"` if it would have been dust. */
    change: string;
}

/**
 * One round of any plan: what it still needs, or what it produced.
 *
 * One shape for every `plan…` call. `value` is present exactly when `kind` is
 * `"ready"`, and `ask` is empty exactly then — so `if (step.kind === "ready")`
 * narrows `value` for you.
 */
export interface PlanStep<T> {
    /** `"ask"` while the plan still needs answers, `"ready"` when it is done. */
    kind: "ask" | "ready";
    /**
     * Complete JSON-RPC bodies to POST **verbatim**, then hand back through
     * `answers.record(body, reply)` with the body unchanged. Empty when ready.
     *
     * Independent of one another within a round, so fetch them concurrently.
     */
    ask: string[];
    /** What the plan produced. Present only when `kind` is `"ready"`. */
    value?: T;
}

/** Which addresses to report on, and over what stretch of chain. */
export interface HistoryRequest {
    /** The addresses. A node sees every one of them. */
    addresses: string[];
    /**
     * First block to search, inclusive. Pass both bounds or neither; omitting
     * both asks for the whole chain, which on a busy address is a large reply.
     */
    startHeight?: number;
    /** Last block to search, inclusive. */
    endHeight?: number;
}

/** One transaction that touched the addresses asked about. */
export interface HistoryEntry {
    /** The transaction, in display order. */
    txid: string;
    /** Block it was mined in. */
    height: number;
    /** Position within that block. */
    blockIndex: number;
    /**
     * The block's timestamp, in seconds. A plain number, unlike the amounts
     * here: a Unix timestamp is far inside what a float64 holds exactly.
     * Miner-chosen and only loosely monotonic — fine to display, not a source
     * of ordering.
     */
    blockTime: number;
    /**
     * Net native value in satoshis, as a decimal string, negative when more
     * left than arrived.
     *
     * `"0"` does not mean nothing happened: a token-only transfer moves no
     * native value at all. Read `netCurrencies` too.
     */
    netNative: string;
    /**
     * Net movement per currency, keyed by `i…` address, excluding the chain's
     * own currency. Currencies that net to exactly zero are absent rather than
     * `"0"`.
     */
    netCurrencies: Record<string, string>;
    /**
     * Whether any output belonging to these addresses was spent here. Distinct
     * from a negative net: a self-transfer spends an output and returns the
     * value, netting to just the fee.
     */
    spentSomething: boolean;
}

/** What a login challenge commits to. */
export interface LoginRequest {
    /**
     * Who is asking. Included in the signed text, so a signature made for one
     * site cannot be replayed at another.
     */
    audience: string;
    /** Random and single-use. 32 bytes of entropy, hex or base64, is ample. */
    challenge: string;
}

/** What to verify, and how strict to be about its age. */
export interface VerifyLoginRequest {
    /** The identity that supposedly signed — a name or an `i…` address. */
    identity: string;
    /** The signature it presented, base64. */
    signature: string;
    /** The audience the challenge was issued for. Must match. */
    audience: string;
    /** The challenge nonce. Must be the one this server issued. */
    challenge: string;
    /**
     * How old the signature's height may be, in blocks. Roughly a block a
     * minute on Verus, so 60 is an hour. Omit for that default.
     */
    maxAgeBlocks?: number;
    /** How far ahead of the tip a signature may be stamped. Omit for 2. */
    maxFutureBlocks?: number;
}

/** Who signed in, and under what authority. */
export interface LoggedIn {
    /** The fully qualified name, e.g. `alice.VRSCTEST@`. */
    name: string;
    /**
     * The identity's `i…` address. **Key the session on this, not on `name`** —
     * a name can be transferred to someone else, an `i` address cannot.
     */
    identityAddress: string;
    /** The height the signature was stamped with. */
    signedAt: number;
    /**
     * The addresses that actually signed, and were authorised to at that
     * height rather than at the tip.
     */
    signers: string[];
}

/** Whose coins to look at. */
export interface SpendableRequest {
    /** The address to assess. A node sees it. */
    address: string;
}

/**
 * What an address can actually spend right now — which is not its balance. A
 * balance counts what exists; this counts what a transaction can use.
 */
export interface Funding {
    /**
     * The chain tip this was decided against. Everything else here is a
     * statement about that height, not about now.
     */
    tip: number;
    /** Total spendable, in satoshis, as a decimal string. */
    total: string;
    /** The outputs a builder can use. */
    utxos: Utxo[];
    /**
     * Native value that exists but cannot be spent **yet** — mostly immature
     * coinbases, in satoshis as a decimal string.
     *
     * Part of the gap between a balance and a payment, not all of it: the
     * outputs counted in `other` carry native value too, and it is in neither
     * this figure nor `total`.
     */
    notYetSpendable: string;
    /**
     * How many outputs are not plain P2PKH: reserve outputs holding tokens,
     * identity outputs, anything CryptoCondition. Excluded from `utxos` because
     * spending one as ordinary funding destroys what it carries.
     *
     * A count, not the outputs: `getaddressutxos` does not say which token a
     * reserve output carries, so this flow cannot identify them. A wallet that
     * tracks its own token outputs passes them to the token send directly.
     */
    other: number;
}

/** Which identity's stored data to read. */
export interface ContentRequest {
    /** The identity holding it — a name or an `i…` address. */
    identity: string;
}

/**
 * One value stored under a VDXF key.
 *
 * A VDXF key is a one-way hash of a name, so for a key you did not create there
 * is no way to recover the name and therefore no way to know how to read the
 * bytes. This hands them over and stops. For your own keys that costs nothing —
 * you chose the encoding.
 */
export interface ContentValue {
    /**
     * The raw bytes as hex, for a key the daemon does not recognise — which is
     * every key an application defines for itself. Absent when the daemon
     * decoded the value, because the original bytes are then not in the reply.
     */
    hex?: string;
    /** The daemon's decoded rendering, when it had one. */
    structured?: unknown;
}

/**
 * What an identity stores, keyed by the VDXF key as a `contentmultimap` prints
 * it — an `i` address, **not** hex. The older `contentmap` spells its keys as
 * hex, so comparing a derived key against the wrong rendering finds nothing.
 */
export type Content = Record<string, ContentValue[]>;

/**
 * What each `plan…` call gives back.
 *
 * Aliases rather than separate interfaces: the shape is one thing, and only the
 * payload differs. Declaring six interfaces that agree on `kind` and `ask` and
 * disagree on one field name is how the payload field ends up called
 * `transaction` in one place and `entries` in another for no reason.
 */
export type TransactionStep = PlanStep<PlannedTransaction>;
/** @see Key.planPublish */
export type UpdateStep = PlanStep<PlannedUpdate>;
/** @see planHistory */
export type HistoryStep = PlanStep<HistoryEntry[]>;
/** The signature, base64. @see Key.planLogin */
export type LoginStep = PlanStep<string>;
/** @see planVerifyLogin */
export type VerifyLoginStep = PlanStep<LoggedIn>;
/** @see planSpendable */
export type SpendableStep = PlanStep<Funding>;
/** @see planContent */
export type ContentStep = PlanStep<Content>;

/** What token to move, and which outputs hold it. */
export interface PlanSendTokenRequest {
    /**
     * The token's currency id — an `i…` address. For a tokenised identity that
     * is the identity's own `i` address.
     */
    currency: string;
    /** Where the tokens are going. */
    to: string;
    /** How much, in the token's smallest unit, as a decimal string. */
    amount: string;
    /**
     * The outputs holding the token. **Not discovered for you**:
     * `getaddressutxos` reports a reserve output's native value, not which
     * token it carries, so recognising them means decoding each script. The
     * native coins for the miner fee *are* found automatically.
     */
    tokenUtxos: Utxo[];
}

/** A payment out of funds a VerusID holds. */
export interface PlanSendFromIdentityRequest {
    /** The identity paying — a name or an `i…` address. */
    identity: string;
    /** Where the value is going. */
    to: string;
    /** How much, in satoshis, as a decimal string. */
    satoshis: string;
}

/** What to store on a VerusID, and under which key. */
export interface PlanPublishRequest {
    /**
     * The identity to write to. **Prefer an `i…` address**: it *is* the
     * identity's id, so the binding can check the identity it is about to
     * rewrite against your own input without trusting the node. A `name@` has
     * to be resolved by the node, which a hostile endpoint can redirect.
     */
    identity: string;
    /** The VDXF key, as a `contentmultimap` spells it: an `i…` address. */
    key: string;
    /**
     * The values to store, each as hex. **Replaces whatever stood under the
     * key** — there is no append, because an update restates the whole
     * identity. Read first if you mean to add; an empty list removes the key.
     */
    values: string[];
}

/**
 * An identity update a flow built and signed. **Not broadcast.**
 *
 * A `PlannedTransaction` plus what the update will change. Storing data on an
 * identity costs a miner fee like any other transaction, and a wallet asking a
 * user to approve it should be able to say how much.
 */
export interface PlannedUpdate {
    /** The raw transaction, hex — what `sendrawtransaction` takes. */
    hex: string;
    /** Its txid in display order, computed from `hex` before anything is sent. */
    txid: string;
    /** The miner fee, in satoshis, paid from the funding address. */
    fee: string;
    /** Change returned, in satoshis; `"0"` if it would have been dust. */
    change: string;
    /** The key that will be written, as it appears in `contentmultimap`. */
    key: string;
    /** How many values will stand under it. Zero means the key is removed. */
    values: number;
}

/** What is standing on the marketplace against a currency or an identity. */
export interface OffersRequest {
    /** What to look for offers against. */
    target: string;
    /**
     * How to read `target`. Getting this wrong fails **quietly**: a currency
     * asked about as an identity comes back empty, which is indistinguishable
     * from a currency nobody is trading. A plain name is only ever an identity.
     */
    isCurrency: boolean;
    /**
     * Ask for each maker's signed half-transaction too. Without it a listing is
     * something to display; with it, something `planOfferTerms` can check and
     * `planTakeOffer` can complete. It makes the reply substantially larger.
     */
    withOfferBytes?: boolean;
}

/** Currency, possibly several at once. */
export interface OfferSideCurrencies {
    kind: "currencies";
    /** Keyed by currency `i` address; amounts in satoshis, decimal strings. */
    amounts: Record<string, string>;
}

/** A VerusID itself, changing hands. */
export interface OfferSideIdentity {
    kind: "identity";
    /** The identity's `i` address. */
    identityId: string;
    /** Its name, without the parent. */
    name: string;
    /** The system it lives on. */
    systemId: string;
}

/**
 * One side of an offer. Either side can be either kind, which is what makes an
 * identity sale and a token trade the same mechanism.
 */
export type OfferSide = OfferSideCurrencies | OfferSideIdentity;

/** One offer standing on the marketplace, read against a particular tip. */
export interface Listing {
    /** What the maker is giving. */
    offering: OfferSide;
    /** What the maker wants for it. */
    accepting: OfferSide;
    /** Height after which it can no longer be completed. Zero means never. */
    blockExpiry: number;
    /**
     * The transaction holding the output the maker signed away — **not** the id
     * of the offer transaction. The daemon calls this `txid`, which reads as
     * "this offer's transaction" and is the wrong thing to fetch.
     */
    fundingTxid: string;
    /** The maker's signed half-transaction, when `withOfferBytes` was set. */
    rawOffer?: string;
    /**
     * The daemon's own price, verbatim text — not a number and not an amount.
     * A price is a ratio between the two sides, so it is denominated in
     * nothing; and the daemon divides in `double` before printing, so it
     * arrives already rounded.
     */
    price: string;
    /** Which of the daemon's price buckets this was listed in. */
    bucket: string;
    /** Whether it could still be completed at the tip this was read against. */
    live: boolean;
}

/** An offer to read against the chain. */
export interface OfferTermsRequest {
    /** The maker's signed half-transaction, hex — a listing's `rawOffer`. */
    offer: string;
}

/** Native coins. */
export interface DemandNative {
    kind: "native";
    /** How much, in satoshis, as a decimal string. */
    amount: string;
    /** The address the maker wants paying. */
    recipient: string;
}

/** A token, as a reserve output. */
export interface DemandToken {
    kind: "token";
    /** Which token, by its `i` address. */
    currency: string;
    /** How much, in the token's smallest unit, as a decimal string. */
    amount: string;
    /** The address the maker wants paying. */
    recipient: string;
}

/** What a maker is asking to be paid. */
export type Demand = DemandNative | DemandToken;

/** An offer, checked against the chain rather than against the maker's word. */
export interface OfferTerms {
    /** The transaction holding the output the offer spends. */
    fundingTxid: string;
    /** Which output of it. */
    fundingVout: number;
    /**
     * What that output really holds, in satoshis — read from the chain, not
     * from the maker's message.
     */
    offered: string;
    /** The address that controls the funding output: the maker. */
    control: string;
    /** What the maker wants in return. */
    demand: Demand;
    /** Height after which this can no longer be completed. Zero means never. */
    expiryHeight: number;
    /**
     * Confirmations on the funding **transaction** — not proof the output is
     * still unspent, which the public node cannot answer. Zero means mempool.
     */
    confirmations: number;
}

/** What a taker supplies to complete an offer. */
export interface TakeOfferRequest {
    /** The maker's signed half-transaction, hex. */
    offer: string;
    /**
     * The outputs paying what the maker demands, plus the miner fee. Named
     * rather than discovered, because paying a token demand means spending
     * reserve outputs and `getaddressutxos` does not say which token an output
     * carries.
     */
    utxos: Utxo[];
    /** Where what the maker is giving should land — an `R…` address. */
    recipient: string;
    /** Where change returns. */
    changeAddress: string;
    /**
     * The miner fee, in satoshis, as a decimal string.
     *
     * Capped at one coin. This is the only place in the API where a caller
     * names an absolute fee, and therefore the only place a transposed digit
     * goes straight to a miner — `"2900000000"` reads as a plausible number
     * and is twenty-nine coins.
     */
    fee: string;
}

/** A completed offer, built and signed. **Not broadcast.** */
export interface Taken {
    /** The raw transaction, hex — what `sendrawtransaction` takes. */
    hex: string;
    /** Its txid in display order, computed from `hex` before anything is sent. */
    txid: string;
    /** The terms this was completed against, as read from the chain. */
    terms: OfferTerms;
}

/** @see planOffers */
export type OffersStep = PlanStep<Listing[]>;
/** @see planOfferTerms */
export type OfferTermsStep = PlanStep<OfferTerms>;
/** @see Key.planTakeOffer */
export type TakeOfferStep = PlanStep<Taken>;

/**
 * What to convert, into what, and on whose terms.
 *
 * A conversion is a **request at an unknown price**: the chain performs it when
 * it imports the output, a block later at best, at whatever the reserve ratios
 * are then. There is no slippage bound in the protocol.
 */
export interface PlanConvertRequest {
    /** The currency being spent, as an `i…` address. */
    from: string;
    /** How much of it, in satoshis, as a decimal string. */
    amount: string;
    /**
     * Which kind of conversion.
     *
     * Minting and burning are deliberately **not** here: a burn cannot be
     * undone and a mint needs a controlling identity's authority, and neither
     * should be reachable by changing a string. See `planBurn` and `planMint`.
     */
    kind: "intoFractional" | "intoReserve" | "reserveToReserve" | "preconvert";
    /** The currency being bought — the fractional, the reserve, or the target. */
    into: string;
    /**
     * The fractional to route through. Only for `"reserveToReserve"`, and
     * refused for any other kind rather than ignored.
     */
    via?: string;
    /** Where the result should land — an `R…` address. */
    recipient: string;
    /** The conversion fee, in satoshis, as a decimal string. Capped at one coin. */
    fee: string;
    /**
     * The least you are willing to accept, in satoshis.
     *
     * **Nothing enforces this on chain.** It refuses before signing if the
     * node's own estimate has already fallen below it, which is the only price
     * check that exists.
     */
    minExpected?: string;
    /**
     * Outputs carrying the source currency, when it is a token. Leave empty
     * when converting the chain's own currency.
     */
    tokenFunding?: Utxo[];
}

/** What to destroy. **A burn cannot be undone.** */
export interface PlanBurnRequest {
    /** The token's currency id, as an `i…` address. */
    currency: string;
    /** How much to destroy, in satoshis, as a decimal string. */
    amount: string;
    /** The conversion fee, in satoshis, as a decimal string. Capped at one coin. */
    fee: string;
    /** Outputs carrying the token. */
    tokenFunding?: Utxo[];
}

/** What to mint, and to whom. */
export interface PlanMintRequest {
    /**
     * The token's `i…` address — which is also the id of the identity that
     * controls it, and that coincidence is the whole mechanism. The mint is
     * funded from that identity's own outputs, so it must hold native coins.
     */
    currency: string;
    /** How much new supply, in satoshis, as a decimal string. */
    amount: string;
    /** Where it lands — an `R…` address. */
    recipient: string;
    /** The conversion fee, in satoshis, as a decimal string. Capped at one coin. */
    fee: string;
}
