//! What a Verus output *means*, and how to read one back.
//!
//! Above the CryptoCondition encoder in `verus-tx-primitives` sits a second
//! layer: the payload structures the chain actually carries. A VerusID
//! ([`identity`]), the VDXF keys it publishes content under ([`vdxf`]), token
//! value ([`token`]), a conversion request ([`convert`]), and the decoder that
//! turns any output script back into one of them ([`decode`]).
//!
//! # Why these are one crate and not four
//!
//! They are mutually dependent, and not for a reason a boundary could remove.
//! [`decode`] reports a reserve transfer as a
//! [`convert::ReserveTransferPayload`], because reporting it as raw bytes
//! would push the parsing onto every caller. [`convert`] in turn refuses
//! funding [`token`] knows is unspendable. And [`balances`] answers "what does
//! this wallet hold" by decoding every output it was given, so it sits on top
//! of all three.
//!
//! Splitting them further would mean splitting the payload *types* from the
//! builders that write them — a much larger move than the one this refactor
//! made, and one that would scatter each structure's layout away from the
//! evidence that pins it.
//!
//! # The decoder is the security boundary
//!
//! [`decode::decode_output_script`] is the one function here that eats bytes an
//! attacker chose. It refuses rather than approximates: a smart output whose
//! payload does not unpack is an error, never a silent fallback to "native
//! value only", because that misreports what a UTXO is worth.

#![doc(html_no_source)]

pub mod balances;
pub mod convert;
pub mod decode;
pub mod identity;
pub mod token;
pub mod vdxf;

pub use balances::{token_balances, TokenBalances};
pub use convert::{
    build_conversion, build_conversion_transaction, ConversionKind, ConversionParams,
    ReserveTransfer, TransferDestination, EVAL_RESERVE_TRANSFER, RESERVE_TRANSFER_ADDRESS,
};
pub use decode::{decode_output_script, may_carry_currency, OutputKind, ADVANCED_COMMITMENT_KEY};
pub use identity::{
    identity_id, Identity, Timelock, EVAL_IDENTITY_PRIMARY, FLAG_LOCKED, FLAG_TOKENIZED_CONTROL,
    MAX_UNLOCK_DELAY,
};
pub use token::{build_token_send, TokenRecipient, TokenSendParams};
pub use vdxf::{data_key, qualified_key, root_namespace};
