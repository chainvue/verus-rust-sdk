//! Transparent Verus transactions: coin selection, fees, change, signing.
//!
//! Builds and signs; it never broadcasts and never touches the network. The
//! caller supplies UTXOs and takes the signed hex somewhere else.
//!
//! ```no_run
//! use verus_keys::{Address, PrivateKey};
//! use verus_tx::{build_transparent_send, Recipient, SendParams, Txid, Utxo};
//!
//! let key = PrivateKey::from_wif("UusoQ…")?;
//! let utxos = [Utxo {
//!     txid: Txid::from_display_hex("aa…")?,
//!     vout: 0,
//!     satoshis: 100_000_000,
//!     script_pubkey: key.address().p2pkh_script_pubkey()?,
//! }];
//! let to = [Recipient { address: "RPsQ…".parse::<Address>()?, satoshis: 50_000_000 }];
//!
//! let signed = build_transparent_send(
//!     &key,
//!     &SendParams::new(&utxos, &to, key.address(), 0),
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

pub mod cc;
pub mod decode;
mod error;
pub mod fee;
mod send;
mod token;
mod txid;

pub use decode::{decode_output_script, OutputKind};
pub use error::TxError;
pub use fee::{estimate_fee, select_utxos, Selection};
pub use send::{
    build_transparent_send, sign_p2pkh_inputs, Recipient, SendParams, SignedTransaction,
};
pub use token::{build_token_send, CurrencyId, TokenRecipient, TokenSendParams};
pub use txid::Txid;

/// An unspent output available to spend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    /// Transaction that created it.
    pub txid: Txid,
    /// Index of the output within that transaction.
    pub vout: u32,
    /// Value in satoshis.
    pub satoshis: u64,
    /// The scriptPubKey it pays to. Must be P2PKH for now.
    pub script_pubkey: Vec<u8>,
}
