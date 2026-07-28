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

    /// A CryptoCondition payload too large for the push encodings this crate
    /// emits. Refusing beats writing an encoding no test covers.
    #[error("CryptoCondition payload of {0} bytes exceeds the supported push encoding")]
    CcPayloadTooLarge(usize),

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
