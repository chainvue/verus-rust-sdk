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

/** One round of a payment plan. */
export interface SendStep {
    /** `"ask"` while the plan still needs answers, `"ready"` when it is done. */
    kind: "ask" | "ready";
    /**
     * Complete JSON-RPC bodies to POST **verbatim**, then hand back through
     * `answers.record(body, reply)` with the body unchanged. Empty when ready.
     *
     * Independent of one another within a round, so fetch them concurrently.
     */
    ask: string[];
    /** Present only when `kind` is `"ready"`. */
    transaction?: PlannedTransaction;
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

/** One round of a history read. */
export interface HistoryStep {
    /** `"ask"` while the read still needs answers, `"ready"` when it is done. */
    kind: "ask" | "ready";
    /** Complete JSON-RPC bodies to POST verbatim. Empty when ready. */
    ask: string[];
    /** The transactions, oldest first. Present only when `kind` is `"ready"`. */
    entries?: HistoryEntry[];
}
