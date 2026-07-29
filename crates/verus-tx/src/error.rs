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
