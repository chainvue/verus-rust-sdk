//! Every name `verus-tx` exported before the crate split must still resolve.
//!
//! The split moved 14,811 lines into six crates and left this one re-exporting
//! them. None of that is visible to a consumer *unless a name went missing* —
//! and a missing re-export fails nothing here, because the tests that would
//! have used it moved down alongside the code. It fails in someone else's
//! build.
//!
//! So this list was extracted mechanically from `src/lib.rs` as it stood at
//! 245ce35, the commit before the split: 63 root names and 17 public modules.
//! A `pub use` dropped while rearranging the facade is exactly the mistake
//! that would otherwise ship.
//!
//! Add to it when the facade gains a name worth promising. Do not remove from
//! it without deciding that the removal is a breaking change.

#![allow(unused_imports)]

use verus_tx::{
    balances, build_conversion, build_conversion_transaction, build_identity_recovery,
    build_identity_registration, build_identity_revocation, build_identity_spend,
    build_identity_update, build_name_commitment, build_token_send, build_transparent_send, cc,
    convert, currency_definition, currency_launch, data_key, decode, decode_output_script,
    estimate_fee, fee, identity, identity_id, identity_payment_script, identity_primary_script,
    identity_spend, may_carry_currency, multisig, offer, partial, qualified_key, register, revoke,
    root_namespace, select_utxos, sign_p2pkh_inputs, signature, token_balances, update, vdxf,
    Amount, CommitmentParams, ConversionKind, ConversionParams, CurrencyId, Destination, Expiry,
    Identity, IdentitySpendParams, InputKind, NameReservation, OutputKind, PartialTransaction,
    Recipient, RecoveryParams, RegistrationParams, ReserveTransfer, RevocationParams, Selection,
    SendParams, SignedRegistration, SignedTransaction, Timelock, TokenBalances, TokenRecipient,
    TokenSendParams, TransferDestination, TxError, Txid, UpdateParams, Utxo,
    ADVANCED_COMMITMENT_KEY, CENTRALIZED_PROOF_PROTOCOL, DEFAULT_EXPIRY_BLOCKS,
    EVAL_IDENTITY_PRIMARY, EVAL_RESERVE_TRANSFER, EXPIRY_HEIGHT_THRESHOLD, FLAG_LOCKED,
    FLAG_TOKENIZED_CONTROL, RESERVE_TRANSFER_ADDRESS, SATS_PER_COIN,
};

/// Resolution happens at compile time; reaching this at all is the pass.
#[test]
fn every_pre_split_name_still_resolves() {}
