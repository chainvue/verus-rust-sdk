//! Errors from building transparent transactions.

use thiserror::Error;
use verus_keys::KeyError;
use verus_wire::WireError;

/// Something the transaction builder refuses to do.
///
/// Every variant is a refusal. A builder that guesses produces a
/// plausible-but-wrong transaction, which is strictly worse than an error: the
/// caller may sign and broadcast it.
#[derive(Debug, Error)]
/// `#[non_exhaustive]`: this crate refuses new things as it learns what the
/// chain refuses, so variants get added routinely. A downstream `match` must
/// carry a wildcard arm rather than break on every such discovery.
#[non_exhaustive]
pub enum TxError {
    /// The selected UTXOs cannot cover the outputs plus the fee.
    #[error("insufficient funds: need {required} satoshis, have {available}")]
    InsufficientFunds {
        /// Outputs plus the estimated fee.
        required: u64,
        /// Total value of the UTXOs offered.
        available: u64,
    },

    /// The same outpoint was offered twice.
    #[error("duplicate UTXO {txid}:{vout}")]
    DuplicateUtxo {
        /// Transaction id, in display order.
        txid: String,
        /// Output index.
        vout: u32,
    },

    /// A funding UTXO whose script this crate cannot spend yet.
    ///
    /// Milestone 1 handles plain P2PKH only. A CryptoCondition output (a token,
    /// an identity, a reserve transfer) needs smart-output decoding that has not
    /// been ported — and guessing at it would misreport the transaction's value.
    #[error("unsupported funding script for {txid}:{vout}: only P2PKH is supported so far")]
    UnsupportedFundingScript {
        /// Transaction id, in display order.
        txid: String,
        /// Output index.
        vout: u32,
    },

    /// An identity object that could not be read.
    #[error("malformed identity: {0}")]
    MalformedIdentity(String),

    /// A funding UTXO held by a VerusID rather than by a key.
    ///
    /// Spending it needs the identity's authority — its primary addresses and
    /// signature threshold — which is a different operation from signing with a
    /// private key, and is not implemented.
    #[error(
        "{txid}:{vout} is held by identity {identity}, which cannot be spent with a key alone"
    )]
    IdentityHeldFunding {
        /// Transaction id, in display order.
        txid: String,
        /// Output index.
        vout: u32,
        /// The identity's 20-byte hash, hex encoded.
        identity: String,
    },

    /// Signing was asked to cover a different number of inputs than prevouts.
    ///
    /// The sighash commits to each prevout's script and value, so pairing them
    /// up wrongly signs a commitment the caller did not intend.
    #[error("{inputs} inputs but {prevouts} prevouts supplied")]
    PrevoutCountMismatch {
        /// How many inputs the transaction has.
        inputs: usize,
        /// How many prevouts were supplied.
        prevouts: usize,
    },

    /// A recipient that is not a plain `R` address.
    #[error("unsupported recipient address kind: only R-addresses are supported so far")]
    UnsupportedRecipient,

    /// No recipients were given.
    #[error("a transaction needs at least one output")]
    NoOutputs,

    /// An output of zero satoshis.
    #[error("output {index} has zero value")]
    ZeroValueOutput {
        /// Which output.
        index: usize,
    },

    /// `expiry_height` at or above the consensus threshold.
    ///
    /// Verus treats values from 500_000_000 upward as invalid. Note `0` is legal
    /// and means "never expires"; this crate does not default it, because
    /// choosing an expiry is the caller's decision.
    #[error("expiry height {0} must be below 500000000")]
    ExpiryHeightTooLarge(u32),

    /// Value is not conserved: inputs minus outputs does not equal the fee.
    ///
    /// This is the real backstop against a fee bug. It is exact-integer
    /// arithmetic, unlike the float-based guard in the JavaScript fork, which is
    /// blind above roughly 42.9 coins.
    #[error("value not conserved: inputs {inputs} - outputs {outputs} = {actual}, expected fee {expected}")]
    ValueNotConserved {
        /// Sum of selected input values.
        inputs: u64,
        /// Sum of all output values, change included.
        outputs: u64,
        /// What the difference actually is.
        actual: i128,
        /// What it should have been.
        expected: u64,
    },

    /// An identity name outside the conservative set this crate will commit to.
    ///
    /// Narrower than consensus on purpose: a name that differs only in case,
    /// whitespace or a dot derives a *different* identity, and the mistake is
    /// only visible once the commitment fee has been spent.
    #[error("identity name {0:?} must be 1-64 characters of a-z, 0-9, underscore or hyphen")]
    InvalidIdentityName(String),

    /// A signing threshold that cannot be met.
    #[error("min_sigs {min_sigs} cannot be met by {primaries} primary address(es)")]
    InvalidMinSigs {
        /// Signatures the identity would require.
        min_sigs: u32,
        /// Addresses available to sign.
        primaries: usize,
    },

    /// The name-commitment output is not the one this key committed to.
    ///
    /// Either the reservation (name, referral or salt) differs from step 1, or
    /// the commitment was locked to another key. Both produce a transaction the
    /// daemon rejects *after* the commitment has been spent, so it is refused
    /// before signing.
    #[error("the commitment output does not match this reservation and signing key")]
    CommitmentMismatch,

    /// A leading CryptoCondition input carrying native value.
    ///
    /// The registration accounting assumes leading inputs contribute nothing; a
    /// funded one would silently pay part of the registration fee and leave the
    /// conservation check reporting a fee that was never paid.
    #[error(
        "leading input {txid}:{vout} carries {satoshis} satoshis; expected a valueless output"
    )]
    LeadingInputCarriesValue {
        /// Transaction that created it, in display order.
        txid: String,
        /// Index within that transaction.
        vout: u32,
        /// The value it carries.
        satoshis: u64,
    },

    /// Value-bearing leading inputs mixed with P2PKH funding.
    ///
    /// The two funding sides have different fee sizing and different change
    /// destinations, and no path that mixes them has ever been proven on
    /// chain. Refused rather than half-supported: fund from the identity or
    /// from keys, not both in one transaction.
    #[error("value-bearing leading inputs cannot be mixed with P2PKH funding")]
    MixedFunding,

    /// A value-bearing leading input without an explicit change script.
    ///
    /// Change from identity-held funding must go somewhere deliberate; falling
    /// back to P2PKH change would silently move identity funds to a bare key.
    #[error("value-bearing leading inputs require an explicit change script")]
    MissingChangeScript,

    /// A VDXF name this crate will not derive a key for.
    ///
    /// Deliberately narrower than the daemon, which truncates and normalises:
    /// both would silently derive a different key than the caller wrote, and a
    /// data key that is silently different is data published where nobody
    /// looks.
    #[error("invalid VDXF name: {0}")]
    InvalidVdxfName(String),

    /// A decimal amount that is not one, or has more precision than a satoshi.
    #[error("{0:?} is not a valid amount of coins")]
    InvalidAmount(String),

    /// A miner fee far above anything the heuristic should produce.
    ///
    /// Exact conservation proves a transaction is internally consistent, not
    /// that its numbers are sane: it is equally happy to certify a fee of a
    /// thousand coins. This is the sanity half.
    #[error("miner fee of {fee} exceeds the {ceiling} ceiling; pass a higher one deliberately")]
    FeeTooLarge {
        /// What the fee came out as.
        fee: u64,
        /// The ceiling it passed.
        ceiling: u64,
    },

    /// An input with no signature at all.
    #[error("input {index} has no signature")]
    MissingSignature {
        /// Which input.
        index: usize,
    },

    /// A gathered signature that does not verify against the hash it covers.
    ///
    /// Either the partial transaction was altered after signing — changing an
    /// output or a value changes the sighash — or it was assembled with a script
    /// or value that does not match the output being spent.
    #[error("the signature on input {index} does not verify against this transaction")]
    InvalidSignature {
        /// Which input.
        index: usize,
    },

    /// A signed message that could not be read, or could not be produced.
    ///
    /// Distinct from [`TxError::InvalidSignature`], which is about an input of a
    /// transaction: this one carries no input index because a signed message has
    /// no inputs.
    #[error("invalid message signature: {0}")]
    MessageSignature(String),

    /// An offer this crate will not build or complete.
    #[error("invalid offer: {0}")]
    InvalidOffer(String),

    /// A currency definition this crate will not encode as described.
    #[error("invalid currency definition: {0}")]
    InvalidCurrencyDefinition(String),

    /// A multisig arrangement this crate will not build.
    #[error("invalid multisig: {0}")]
    InvalidMultisig(String),

    /// A conversion this crate will not build.
    #[error("invalid conversion: {0}")]
    InvalidConversion(String),

    /// A partial transaction that could not be read.
    #[error("malformed partial transaction: {0}")]
    MalformedPartialTransaction(String),

    /// An output could not be read while counting what an address holds.
    ///
    /// Separate from [`TxError::UnsupportedFundingScript`], which is about
    /// *spending*: this one says a balance would be wrong, not that a transfer
    /// would be. Both refuse rather than treating an unreadable smart output as
    /// native-only, which is the same rule the decoder enforces.
    #[error(
        "output {txid}:{vout} cannot be counted: {reason}. It may carry currency that would be \
         missing from a balance, so no balance is reported rather than one that is too small"
    )]
    UncountableOutput {
        /// The transaction that created it, display order.
        txid: String,
        /// Index of the output.
        vout: u32,
        /// Why it could not be counted.
        reason: String,
    },

    /// Amounts that overflow a u64 when summed.
    #[error("transaction value overflows a 64-bit integer")]
    ValueOverflow,

    /// A referral chain was supplied for a reservation that committed to no
    /// referral. The commitment fixes whether there is a referrer at all.
    #[error("a referral chain was supplied but the reservation committed to no referral")]
    ReferralNotCommitted,

    /// More referrers than the chain pays out.
    #[error("referral chain has {entries} entries but only {levels} levels are paid")]
    ReferralChainTooLong {
        /// Entries the caller supplied.
        entries: usize,
        /// Levels the chain pays.
        levels: u32,
    },

    /// `idreferrallevels` far beyond anything a real chain configures.
    ///
    /// It is node-sourced chain policy, like the registration fee it
    /// multiplies against in `verus_tx::register::registration_fees` — this
    /// crate cannot confirm it, only bound it. A value this large has no
    /// legitimate basis (VRSCTEST pays out 3) and, left unbounded, lets a
    /// caller-uncheckable multiplier reach the point where the fee split
    /// overflows: `u32::MAX` levels against a 100-coin fee panics in a debug
    /// build and silently returns an outlay of 14.10065407 coins in release,
    /// because plain `u64` multiplication wraps rather than erroring.
    #[error(
        "referral levels {levels} exceeds the sane ceiling of {max}; no real chain approaches this"
    )]
    ImplausibleReferralLevels {
        /// What was supplied.
        levels: u32,
        /// The ceiling it exceeded.
        max: u32,
    },

    /// A parent currency whose fee output this crate does not build.
    ///
    /// Retained for callers matching on it; nothing raises it today. Both
    /// shapes `PrecheckIdentityReservation` accepts are now built: a
    /// `proofprotocol` 2 parent takes a plain reserve output, and a token
    /// parent takes a `CReserveTransfer` burn.
    #[error("parent proofprotocol {0} is not one this crate builds a fee output for")]
    UnsupportedParentProofProtocol(u32),

    /// The signing key is not one of the identity's primary addresses.
    ///
    /// The identity output's condition can only be satisfied by a key the
    /// identity itself lists. Signing with any other key builds cleanly and is
    /// then rejected at script verification, which reports only that a script
    /// finished false.
    #[error("{address} is not one of the identity's primary addresses")]
    NotAPrimaryAddress {
        /// The address derived from the signing key.
        address: String,
    },

    /// Fewer signing keys than the identity's condition requires.
    #[error("{supplied} signing key(s) supplied but the identity requires {required}")]
    NotEnoughSigners {
        /// Keys the caller supplied.
        supplied: usize,
        /// Signatures the identity's current threshold demands.
        required: u32,
    },

    /// A fulfillment with no signatures in it.
    #[error("a CryptoCondition fulfillment needs at least one signature")]
    NoSignatures,

    /// An update would change who controls the identity.
    ///
    /// Refused unless the caller opts in. Publishing a threshold nobody can meet
    /// or addresses nobody holds makes the identity permanently unupdatable —
    /// the single VerusID mistake with no remedy.
    #[error("this update changes {field}, which moves control of the identity")]
    AuthorityChangeRefused {
        /// Which field the update would have altered.
        field: String,
    },

    /// The identity is already revoked.
    #[error("this identity is already revoked")]
    AlreadyRevoked,

    /// Recovering an identity that was never revoked.
    #[error("this identity is not revoked, so there is nothing to recover")]
    NotRevoked,

    /// A recovery that leaves the revoked flag set — it would spend the output
    /// and change nothing but the fee.
    #[error("the recovered identity still has the revoked flag set")]
    StillRevoked,

    /// A revocation nobody could undo.
    ///
    /// An identity whose recovery authority is itself cannot be recovered once
    /// revoked: the only party permitted to act is the revoked identity, which
    /// no longer can. The daemon refuses this too.
    #[error("recovery authority is the identity itself; revoking it would strand it permanently")]
    RevocationWouldStrand,

    /// An update the chain's timelock rules refuse.
    ///
    /// `CIdentity::IsInvalidMutation` guards the lock in four ways: a locked
    /// identity cannot be unlocked in the same transaction that unlocks it, an
    /// unlock can only ever move later, a delay cannot exceed
    /// `MAX_UNLOCK_DELAY`, and an absolute unlock height must be past the
    /// transaction's own expiry.
    ///
    /// The last one is the surprise: the height a caller must publish is
    /// computed from `nExpiryHeight`, not from the tip, so it cannot be worked
    /// out without knowing the expiry the transaction will carry.
    #[error("this update is refused by the timelock rules: {reason}")]
    TimelockRefused {
        /// Which rule, in terms of the values involved.
        reason: String,
    },

    /// The output being spent does not hold the identity being updated.
    #[error("the output being spent does not hold this identity")]
    IdentityOutputMismatch,

    /// A CryptoCondition payload too large for the push encodings this crate
    /// emits. Refusing beats writing an encoding no test covers.
    #[error("CryptoCondition payload of {0} bytes exceeds the supported push encoding")]
    CcPayloadTooLarge(usize),

    /// Not enough of a token to cover the requested transfer.
    #[error("insufficient token balance for currency {currency}: short by {missing}")]
    InsufficientTokens {
        /// Currency id, hex.
        currency: String,
        /// How much more is needed.
        missing: u64,
    },

    /// A funding UTXO carrying a CryptoCondition this crate cannot account for.
    ///
    /// Spending it would move value the builder cannot see — an identity, a
    /// reserve transfer — so it is refused rather than treated as native.
    #[error("funding UTXO {txid}:{vout} is a CryptoCondition with eval code {eval_code}, which is not supported")]
    UnsupportedFundingEval {
        /// Transaction id, display order.
        txid: String,
        /// Output index.
        vout: u32,
        /// The eval code found.
        eval_code: u8,
    },

    /// A CryptoCondition script that could not be parsed.
    ///
    /// Deliberately an error rather than a fallback to "native value only":
    /// treating an unreadable smart output as plain satoshis under-counts what a
    /// transaction spends, which is how token value gets burned.
    #[error("malformed CryptoCondition output: {0}")]
    MalformedCryptoCondition(String),

    /// A script this crate has no opinion about.
    #[error("unrecognised output script: {0}")]
    UnsupportedScript(String),

    /// A hex string that is not valid hex, or not the expected length.
    #[error("invalid transaction id: {0}")]
    InvalidTxid(String),

    /// Key handling failed.
    #[error(transparent)]
    Key(#[from] KeyError),

    /// Wire encoding failed.
    #[error(transparent)]
    Wire(#[from] WireError),
}
