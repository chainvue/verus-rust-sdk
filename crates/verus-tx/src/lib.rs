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
//! # This crate is a facade
//!
//! `src/lib.rs` is the whole of it: every name below is re-exported from one
//! of six crates, and importing through `verus_tx::…` gets all of them. That
//! is the path to keep using if you do not care how the pieces are arranged.
//!
//! | crate | what it holds |
//! |---|---|
//! | [`verus_tx_primitives`] | money, ids, expiry, errors, CryptoCondition encoding, fee and coin-selection rules |
//! | [`verus_tx_transparent`] | transparent sends, and the assembly every other builder reuses |
//! | [`verus_tx_protocol`] | what an output *means*: identities, VDXF, token outputs, reserve transfers, and the decoder |
//! | [`verus_tx_currency`] | defining and launching a currency |
//! | [`verus_tx_identity`] | the VerusID lifecycle, and message signing |
//! | [`verus_tx_market`] | offers, partially-signed transactions, script multisig |
//!
//! Depend on one directly when you want only part of this. Something that
//! merely needs to *talk about* an [`Amount`] or a [`CurrencyId`] — a price
//! feed, a balance display, an RPC layer — should take
//! [`verus_tx_primitives`] and not compile the identity registration builder
//! to get one.
//!
//! Those crates expose a little more than this facade does: helpers like
//! `assemble` and `Balances` are `pub` there because they cross a crate
//! boundary, and are not re-exported here. Nothing behind the facade is
//! promised to be stable in the way the names below are.
//!
//! # Why the fee logic looks the way it does
//!
//! Fee estimation, coin selection and the dust rule are transcribed literally
//! from the TypeScript SDK, quirks included, because byte-for-byte agreement
//! with a daemon-proven implementation is the correctness gate. Improving the
//! heuristic would change change-output values and break that agreement — see
//! the notes in [`fee`].

#![doc(html_no_source)]

// Every line below is a re-export, and no name here is new: this file is what
// makes the split invisible to anything that was already importing from
// `verus_tx`.
pub use verus_tx_currency::{currency_definition, currency_launch};
pub use verus_tx_identity::{
    build_identity_recovery, build_identity_registration, build_identity_revocation,
    build_identity_spend, build_identity_update, build_name_commitment, CommitmentParams,
    IdentitySpendParams, NameReservation, RecoveryParams, RegistrationParams, RevocationParams,
    SignedRegistration, UpdateParams, CENTRALIZED_PROOF_PROTOCOL,
};
pub use verus_tx_identity::{identity_spend, register, revoke, signature, update};
pub use verus_tx_market::{multisig, offer, partial};
pub use verus_tx_market::{InputKind, PartialTransaction};
pub use verus_tx_primitives::{cc, fee};
pub use verus_tx_primitives::{
    estimate_fee, identity_payment_script, identity_primary_script, select_utxos, Amount,
    CurrencyId, Destination, Expiry, Selection, TxError, Txid, Utxo, DEFAULT_EXPIRY_BLOCKS,
    EXPIRY_HEIGHT_THRESHOLD, SATS_PER_COIN,
};
pub use verus_tx_protocol::{balances, convert, decode, identity, vdxf};
pub use verus_tx_protocol::{
    build_conversion, build_conversion_transaction, build_token_send, data_key,
    decode_output_script, identity_id, may_carry_currency, qualified_key, root_namespace,
    token_balances, ConversionKind, ConversionParams, Identity, OutputKind, ReserveTransfer,
    Timelock, TokenBalances, TokenRecipient, TokenSendParams, TransferDestination,
    ADVANCED_COMMITMENT_KEY, EVAL_IDENTITY_PRIMARY, EVAL_RESERVE_TRANSFER, FLAG_LOCKED,
    FLAG_TOKENIZED_CONTROL, RESERVE_TRANSFER_ADDRESS,
};
pub use verus_tx_transparent::{
    build_transparent_send, sign_p2pkh_inputs, Recipient, SendParams, SignedTransaction,
};
