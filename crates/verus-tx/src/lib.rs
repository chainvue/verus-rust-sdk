//! Transparent Verus transactions: coin selection, fees, change, signing.
//!
//! Builds and signs; it never broadcasts and never touches the network. The
//! caller supplies UTXOs and takes the signed hex somewhere else.
//!
//! ```no_run
//! use verus_keys::{Address, PrivateKey};
//! use verus_tx::{build_transparent_send, Amount, Expiry, Recipient, SendParams, Txid, Utxo};
//!
//! let key = PrivateKey::from_wif("UusoQ…")?;
//! let utxos = [Utxo {
//!     txid: Txid::from_display_hex("aa…")?,
//!     vout: 0,
//!     satoshis: Amount::from_sat(100_000_000),
//!     script_pubkey: key.address().p2pkh_script_pubkey()?,
//! }];
//! let to = [Recipient {
//!     address: "RPsQ…".parse::<Address>()?,
//!     satoshis: Amount::from_sat(50_000_000),
//! }];
//!
//! let signed = build_transparent_send(
//!     &key,
//!     &SendParams::new(&utxos, &to, key.address(), Expiry::Never),
//! )?;
//! println!("{} ({} sat fee)", signed.txid, signed.fee);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Scope
//!
//! Native VRSC transfers between `R` addresses are complete and proven on chain.
//! Token outputs are being built up in [`cc`]; conversions, VerusID operations
//! and identity-held funds are not ported yet, and those inputs are **refused**,
//! never approximated.
//!
//! # Why the fee logic looks the way it does
//!
//! Fee estimation, coin selection and the dust rule are transcribed literally
//! from the TypeScript SDK, quirks included, because byte-for-byte agreement
//! with a daemon-proven implementation is the correctness gate. Improving the
//! heuristic would change change-output values and break that agreement — see
//! the notes in [`fee`].

#![doc(html_no_source)]

mod amount;
mod assemble;
pub mod cc;
mod currency;
pub mod decode;
mod error;
mod expiry;
pub mod fee;
pub mod identity;
pub mod partial;
pub mod register;
pub mod revoke;
mod send;
mod token;
mod txid;
pub mod update;

pub use amount::{Amount, SATS_PER_COIN};
pub use cc::{identity_payment_script, identity_primary_script, Destination};
pub use currency::CurrencyId;
pub use decode::{decode_output_script, OutputKind};
pub use error::TxError;
pub use expiry::{Expiry, DEFAULT_EXPIRY_BLOCKS, EXPIRY_HEIGHT_THRESHOLD};
pub use fee::{estimate_fee, select_utxos, Selection};
pub use identity::{Identity, EVAL_IDENTITY_PRIMARY};
pub use partial::{InputKind, PartialTransaction};
pub use register::{
    build_identity_registration, build_name_commitment, identity_id, CommitmentParams,
    NameReservation, RegistrationParams, SignedRegistration,
};
pub use revoke::{
    build_identity_recovery, build_identity_revocation, RecoveryParams, RevocationParams,
};
pub use send::{
    build_transparent_send, sign_p2pkh_inputs, Recipient, SendParams, SignedTransaction,
};
pub use token::{build_token_send, TokenRecipient, TokenSendParams};
pub use txid::Txid;
pub use update::{build_identity_update, UpdateParams};

/// An unspent output available to spend.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Utxo {
    /// Transaction that created it.
    pub txid: Txid,
    /// Index of the output within that transaction.
    pub vout: u32,
    /// What it is worth.
    pub satoshis: Amount,
    /// The scriptPubKey it pays to. Must be P2PKH for now.
    pub script_pubkey: Vec<u8>,
}
