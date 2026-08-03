//! The vocabulary every Verus transaction builder shares.
//!
//! Money, transaction ids, expiry heights, the error type, the
//! CryptoCondition output encoder, and the fee and coin-selection rules. This
//! is the bottom of the `verus-tx` stack: it builds no transaction of its own,
//! and everything above it — transparent sends, identities, currencies,
//! offers — is written in these types.
//!
//! Depend on this crate directly when all you need is to *talk about* an
//! amount or a UTXO. A price feed, a balance display or an RPC layer has no
//! business compiling the identity registration builder to get an [`Amount`].
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
pub mod cc;
mod currency;
mod error;
mod expiry;
pub mod fee;
mod txid;
mod utxo;

pub use amount::{Amount, SATS_PER_COIN};
pub use cc::{identity_payment_script, identity_primary_script, Destination};
pub use currency::CurrencyId;
pub use error::TxError;
pub use expiry::{Expiry, DEFAULT_EXPIRY_BLOCKS, EXPIRY_HEIGHT_THRESHOLD};
pub use fee::{estimate_fee, select_utxos, Selection};
pub use txid::Txid;
pub use utxo::Utxo;
