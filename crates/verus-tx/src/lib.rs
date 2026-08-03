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

pub mod currency_definition;
pub mod currency_launch;
pub mod identity_spend;
pub mod multisig;
pub mod offer;
pub mod partial;
pub mod register;
pub mod revoke;
pub mod signature;
pub mod update;

// The primitives, re-exported so every path this crate published still
// resolves. `verus-tx` is becoming a facade over the crates it was split
// into; nothing here is a new name.
pub use verus_tx_primitives::{cc, fee};
pub use verus_tx_primitives::{
    estimate_fee, identity_payment_script, identity_primary_script, select_utxos, Amount,
    CurrencyId, Destination, Expiry, Selection, TxError, Txid, Utxo, DEFAULT_EXPIRY_BLOCKS,
    EXPIRY_HEIGHT_THRESHOLD, SATS_PER_COIN,
};
pub use verus_tx_protocol::{balances, convert, decode, identity, vdxf};
pub use verus_tx_protocol::{
    build_conversion, build_conversion_transaction, build_token_send, data_key,
    decode_output_script, may_carry_currency, qualified_key, root_namespace, token_balances,
    ConversionKind, ConversionParams, Identity, OutputKind, ReserveTransfer, Timelock,
    TokenBalances, TokenRecipient, TokenSendParams, TransferDestination, ADVANCED_COMMITMENT_KEY,
    EVAL_IDENTITY_PRIMARY, EVAL_RESERVE_TRANSFER, FLAG_LOCKED, FLAG_TOKENIZED_CONTROL,
    RESERVE_TRANSFER_ADDRESS,
};
pub use verus_tx_transparent::{
    build_transparent_send, sign_p2pkh_inputs, Recipient, SendParams, SignedTransaction,
};

pub use identity_spend::{build_identity_spend, IdentitySpendParams};
pub use partial::{InputKind, PartialTransaction};
pub use register::{
    build_identity_registration, build_name_commitment, identity_id, CommitmentParams,
    NameReservation, RegistrationParams, SignedRegistration, CENTRALIZED_PROOF_PROTOCOL,
};
pub use revoke::{
    build_identity_recovery, build_identity_revocation, RecoveryParams, RevocationParams,
};
pub use update::{build_identity_update, UpdateParams};
