//! Offline Verus SDK — build and sign transactions without a node.
//!
//! This crate is the facade: it re-exports a coherent API over `verus-wire`,
//! `verus-keys`, `verus-tx` and (behind the `shielded` feature) `verus-sapling`.
//! It builds and signs bytes; broadcasting is the consumer's job.
//!
//! ```text
//! default = transparent    send VRSC and tokens; no prover, no parameters
//! shielded                + find your notes and derive ZIP-32 keys
//! prover                  + BUILD t→z / z→z / z→t; needs the Sapling parameters
//! multicore               native-only speedup for the prover
//! ```
//!
//! `shielded` on its own deliberately cannot build a shielded transaction — it
//! is the light half a balance-only wallet wants, with no bellman in the
//! dependency graph. Ask for `prover` when you need to spend.

#![doc(html_no_source)]

pub use verus_keys;
pub use verus_wire;

#[cfg(feature = "transparent")]
pub use verus_tx;

#[cfg(feature = "shielded")]
pub use verus_sapling;

/// Money, and the transaction primitives every flow shares.
///
/// Re-exported here so a consumer writes `verus_sdk::money::Amount` rather than
/// reaching through the crate that happens to define it. The underlying crates
/// stay public — this is a shorter path to the same types, not a wrapper.
#[cfg(feature = "transparent")]
pub mod money {
    pub use verus_tx::{Amount, Expiry, Txid, Utxo, DEFAULT_EXPIRY_BLOCKS, SATS_PER_COIN};
}

/// Sending value: native coins and tokens.
#[cfg(feature = "transparent")]
pub mod send {
    pub use verus_tx::{
        build_token_send, build_transparent_send, CurrencyId, Recipient, SendParams,
        SignedTransaction, TokenRecipient, TokenSendParams,
    };
}

/// The VerusID lifecycle: register, update, revoke, recover.
///
/// The order matters more than it looks. A freshly registered identity is its
/// own revocation and recovery authority, which makes it **unrevokable** —
/// pointing recovery elsewhere is a decision at registration time, through
/// [`identity::RegistrationParams::with_authorities`], not a later refinement.
#[cfg(feature = "transparent")]
pub mod identity {
    pub use verus_tx::identity::{Identity, FLAG_LOCKED, FLAG_REVOKED};
    pub use verus_tx::register::{
        build_identity_registration, build_name_commitment, commitment_script, identity_id,
        registration_fees, CommitmentParams, NameReservation, ParentCurrencyFee,
        RegistrationParams, SignedRegistration,
    };
    pub use verus_tx::revoke::{
        build_identity_recovery, build_identity_revocation, RecoveryParams, RevocationParams,
    };
    pub use verus_tx::update::{build_identity_update, UpdateParams};
    pub use verus_tx::{identity_payment_script, identity_primary_script};
}

/// Signing across machines, for identities that need more than one key.
#[cfg(feature = "transparent")]
pub mod cosign {
    pub use verus_tx::partial::{
        CollectedSignature, InputKind, PartialInput, PartialTransaction, Summary,
    };
}

/// Reading what an output is, before deciding whether it can be spent.
#[cfg(feature = "transparent")]
pub mod decode {
    pub use verus_tx::{decode_output_script, Destination, OutputKind};
}
