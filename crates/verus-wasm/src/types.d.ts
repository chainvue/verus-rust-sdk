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

/** What an output turned out to be. Switch on `kind`. */
export interface DecodedOutput {
    kind: "pubKeyHash" | "pubKey" | "reserveOutput" | "identityPayment"
        | "identityPrimary" | "identityCommitment" | "reserveDeposit"
        | "reserveTransfer" | "unsupportedCryptoCondition" | "unknown";
    /**
     * The address paid or held for. Absent when the output could not be read.
     * For `pubKey` — the shape a proof-of-work coinbase pays — this is the
     * address controlling the key, and the output carries native value only.
     */
    address?: string;
    /**
     * For `reserveOutput`: token value carried, IN ADDITION to native value.
     *
     * `address` may be an `i…` address here: tokens held by a VerusID are an
     * ordinary shape, and only the identity's authority can spend one.
     */
    tokens?: TokenAmount[];
    /** For `identityPrimary`: the identity's name. */
    name?: string;
    /** For `identityPrimary`: the addresses that control it. */
    primaryAddresses?: string[];
    /** For `identityPrimary`: how many of them a spend needs. */
    minimumSignatures?: number;
    /**
     * For `unsupportedCryptoCondition`: the eval code found. This SDK cannot
     * spend the output whatever the code is — do not select it as funding.
     */
    evalCode?: number;
    /**
     * For `unsupportedCryptoCondition`: whether an output with that eval code
     * is ABLE to hold a token.
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
    mayCarryCurrency?: boolean;
    /**
     * For `identityCommitment`: the 32-byte commitment as hex, in the order
     * the script holds it.
     *
     * The daemon prints this reversed, the way it prints every hash — reverse
     * it before comparing with `registernamecommitment` output. `tokens` is
     * present and empty for every ordinary commitment; only the advanced form
     * carries currency alongside the hash.
     */
    commitment?: string;
    /** For `reserveDeposit`: the currency whose reserves the output holds. */
    controllingCurrency?: string;
    /** For `reserveTransfer`: the raw flag word. */
    flags?: number;
    /** For `reserveTransfer`: the currency the fee is paid in. */
    feeCurrency?: string;
    /** For `reserveTransfer`: the fee, in the smallest unit, as a string. */
    fees?: string;
    /** For `reserveTransfer`: the currency in the destination slot. */
    destinationCurrency?: string;
    /**
     * For `reserveTransfer`: who the value is ultimately for.
     *
     * NOT `address` — that is the protocol's transfer address, the same for
     * every transfer on the chain. The real recipient travels in the payload.
     */
    recipient?: string;
}
