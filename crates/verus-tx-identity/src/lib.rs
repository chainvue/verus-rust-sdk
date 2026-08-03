//! The VerusID lifecycle.
//!
//! Claiming a name ([`register`]), changing what an identity says
//! ([`update`]), taking it away and giving it back ([`revoke`]), spending
//! funds an identity holds ([`identity_spend`]), and proving a statement came
//! from one ([`signature`]).
//!
//! # An identity is not a key
//!
//! It is a chain object naming one or more primary addresses and how many must
//! sign — and that set can change, which is the entire point of a revocable,
//! recoverable identity. Every builder here therefore starts from the
//! identity *as the chain currently holds it* and republishes the whole
//! object; there is no partial update. That is also why [`signature`] commits
//! to a block height: a signature from a key rotated out last year must not
//! still verify.
//!
//! # Registration is two transactions and one unrecoverable secret
//!
//! A name is claimed by publishing a commitment, then revealing it. The salt
//! joining the two is **not recoverable from the chain**: lose it between the
//! steps and the commitment fee is burned with nothing to show. See
//! [`register::NameReservation`], which is serializable for exactly that
//! reason.

#![doc(html_no_source)]

pub mod identity_spend;
pub mod register;
pub mod revoke;
pub mod signature;
pub mod update;

pub use identity_spend::{build_identity_spend, IdentitySpendParams};
pub use register::{
    build_identity_registration, build_name_commitment, CommitmentParams, NameReservation,
    RegistrationParams, SignedRegistration, CENTRALIZED_PROOF_PROTOCOL,
};
pub use revoke::{
    build_identity_recovery, build_identity_revocation, RecoveryParams, RevocationParams,
};
pub use update::{build_identity_update, UpdateParams};
