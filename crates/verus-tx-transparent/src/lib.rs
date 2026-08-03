//! Moving native VRSC between transparent addresses, and the assembly every
//! other builder reuses.
//!
//! Two things live here. [`build_transparent_send`] is the whole transparent
//! path — select inputs, compute the fee, place change, sign each P2PKH input —
//! and it is the transaction this SDK has proven on chain most often.
//! [`assemble`] is the part underneath it that the VerusID, currency and offer
//! builders share: given some leading outputs that must appear first, some
//! funding UTXOs and a change address, produce a signed transaction whose fee
//! and change agree with the TypeScript SDK byte for byte.
//!
//! Nothing here knows what a token, an identity or a conversion is. Those are
//! built one layer up, out of outputs handed to [`assemble`].

#![doc(html_no_source)]

pub mod assemble;
mod send;

pub use send::{
    build_transparent_send, sign_p2pkh_inputs, Recipient, SendParams, SignedTransaction,
};
