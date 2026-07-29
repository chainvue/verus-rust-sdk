//! Revoking and recovering a VerusID.
//!
//! These are the two operations an identity's *authorities* perform on it,
//! rather than the identity performing on itself. Both spend the identity output
//! and republish it, exactly like [`crate::update`]; what differs is who signs
//! and which flag moves.
//!
//! * **Revoke** sets `FLAG_REVOKED`, signed by the identity's revocation
//!   authority. A revoked identity can no longer be updated or spent from by its
//!   own primary addresses.
//! * **Recover** clears that flag, signed by the recovery authority, and is the
//!   one operation allowed to hand the identity a new set of primary addresses —
//!   that is the point of it, since revocation usually means the old keys are
//!   compromised or lost.
//!
//! # Revoking into a dead end
//!
//! An identity whose recovery authority is *itself* cannot be recovered after
//! revocation: the only party who could act is the revoked identity, and it no
//! longer can. The daemon refuses such a revocation outright —
//!
//! ```text
//! Cannot revoke an identity with self as the recovery authority,
//! unless the ID has tokenized ID control
//! ```
//!
//! — and so does [`build_identity_revocation`], before anything is signed. A
//! freshly registered identity has exactly this shape by default, so pointing
//! recovery at another identity is a prerequisite for revocation ever being
//! usable, not a refinement.
//!
//! # Who signs
//!
//! The authority is another *identity*, and its primary addresses live in its
//! own on-chain object, which this crate cannot see from the identity being
//! revoked. So the caller supplies the authority's keys and this cannot check
//! them offline the way [`crate::update`] checks an identity's own primaries —
//! wrong keys produce a transaction the daemon rejects at script verification.
//! Signing with more keys than strictly needed is harmless; the daemon does it.

use verus_keys::{Address, PrivateKey};
use verus_wire::TxOut;

use crate::assemble::{assemble, check_expiry, check_p2pkh_funding, Assembly};
use crate::cc::identity_primary_script;
use crate::decode::{decode_output_script, OutputKind};
use crate::error::TxError;
use crate::fee::DEFAULT_FEE_PER_KB;
use crate::identity::{Identity, FLAG_REVOKED};
use crate::register::identity_id;
use crate::send::SignedTransaction;
use crate::Utxo;

/// What a revocation needs.
#[derive(Clone, Debug)]
pub struct RevocationParams<'a> {
    /// The output currently holding the identity.
    pub identity_output: &'a Utxo,
    /// P2PKH UTXOs to pay the miner fee from.
    pub utxos: &'a [Utxo],
    /// Where change goes.
    pub change_address: Address,
    /// Block height after which the transaction expires; `0` never expires.
    pub expiry_height: u32,
    /// Fee rate in satoshis per kilobyte.
    pub fee_per_kb: u64,
}

impl<'a> RevocationParams<'a> {
    /// Parameters with the default fee rate.
    pub fn new(
        identity_output: &'a Utxo,
        utxos: &'a [Utxo],
        change_address: Address,
        expiry_height: u32,
    ) -> Self {
        Self {
            identity_output,
            utxos,
            change_address,
            expiry_height,
            fee_per_kb: DEFAULT_FEE_PER_KB,
        }
    }
}

/// Revoke an identity: republish it with `FLAG_REVOKED` set.
///
/// The identity itself is taken from the output being spent and re-emitted
/// unchanged apart from the flag — a revocation is not an opportunity to edit
/// anything else, and taking the contents from the caller would let it become
/// one.
///
/// `authority_keys` must satisfy the *revocation authority's* condition. See the
/// module docs: they cannot be checked offline.
pub fn build_identity_revocation(
    funding_key: &PrivateKey,
    authority_keys: &[&PrivateKey],
    params: &RevocationParams<'_>,
) -> Result<SignedTransaction, TxError> {
    check_expiry(params.expiry_height)?;
    check_p2pkh_funding(params.utxos)?;

    let mut identity = current_identity(params.identity_output)?;
    if identity.is_revoked() {
        return Err(TxError::AlreadyRevoked);
    }

    // Revoking into a dead end. The daemon refuses this; so does this, before a
    // signature exists, because the result is unrecoverable by anyone.
    let id = identity_id(&identity.name, Some(identity.parent));
    if identity.recovery_authority == id {
        return Err(TxError::RevocationWouldStrand);
    }

    identity.flags |= FLAG_REVOKED;
    republish(
        funding_key,
        authority_keys,
        &identity,
        id,
        Common {
            identity_output: params.identity_output,
            utxos: params.utxos,
            change_address: &params.change_address,
            expiry_height: params.expiry_height,
            fee_per_kb: params.fee_per_kb,
        },
    )
}

/// What a recovery needs.
#[derive(Clone, Debug)]
pub struct RecoveryParams<'a> {
    /// The output currently holding the revoked identity.
    pub identity_output: &'a Utxo,
    /// The identity as it should read after recovery, stated in full and with
    /// `FLAG_REVOKED` clear.
    ///
    /// Unlike an update, this may legitimately carry new primary addresses and
    /// authorities: recovery exists because the old ones are gone. Nothing here
    /// second-guesses that, so it is also the one call that can hand the
    /// identity to the wrong keys permanently.
    pub identity: &'a Identity,
    /// P2PKH UTXOs to pay the miner fee from.
    pub utxos: &'a [Utxo],
    /// Where change goes.
    pub change_address: Address,
    /// Block height after which the transaction expires; `0` never expires.
    pub expiry_height: u32,
    /// Fee rate in satoshis per kilobyte.
    pub fee_per_kb: u64,
}

impl<'a> RecoveryParams<'a> {
    /// Parameters with the default fee rate.
    pub fn new(
        identity_output: &'a Utxo,
        identity: &'a Identity,
        utxos: &'a [Utxo],
        change_address: Address,
        expiry_height: u32,
    ) -> Self {
        Self {
            identity_output,
            identity,
            utxos,
            change_address,
            expiry_height,
            fee_per_kb: DEFAULT_FEE_PER_KB,
        }
    }
}

/// Recover a revoked identity: republish it with `FLAG_REVOKED` cleared.
///
/// `authority_keys` must satisfy the *recovery authority's* condition.
pub fn build_identity_recovery(
    funding_key: &PrivateKey,
    authority_keys: &[&PrivateKey],
    params: &RecoveryParams<'_>,
) -> Result<SignedTransaction, TxError> {
    check_expiry(params.expiry_height)?;
    check_p2pkh_funding(params.utxos)?;

    let current = current_identity(params.identity_output)?;
    if !current.is_revoked() {
        return Err(TxError::NotRevoked);
    }

    let id = identity_id(&current.name, Some(current.parent));
    if identity_id(&params.identity.name, Some(params.identity.parent)) != id {
        return Err(TxError::IdentityOutputMismatch);
    }
    // Recovering while leaving the flag set would spend the output and change
    // nothing that matters, at the cost of the fee.
    if params.identity.is_revoked() {
        return Err(TxError::StillRevoked);
    }

    republish(
        funding_key,
        authority_keys,
        params.identity,
        id,
        Common {
            identity_output: params.identity_output,
            utxos: params.utxos,
            change_address: &params.change_address,
            expiry_height: params.expiry_height,
            fee_per_kb: params.fee_per_kb,
        },
    )
}

/// The identity the output being spent actually holds.
fn current_identity(output: &Utxo) -> Result<Identity, TxError> {
    match decode_output_script(&output.script_pubkey)? {
        OutputKind::IdentityPrimary { identity } => Ok(*identity),
        _ => Err(TxError::IdentityOutputMismatch),
    }
}

/// The parts of either params struct that assembly needs.
struct Common<'a> {
    identity_output: &'a Utxo,
    utxos: &'a [Utxo],
    change_address: &'a Address,
    expiry_height: u32,
    fee_per_kb: u64,
}

/// Spend the identity output and publish the given identity in its place.
fn republish(
    funding_key: &PrivateKey,
    authority_keys: &[&PrivateKey],
    identity: &Identity,
    id: [u8; 20],
    common: Common<'_>,
) -> Result<SignedTransaction, TxError> {
    let script_pubkey = identity_primary_script(
        id,
        identity.to_bytes()?,
        identity.revocation_authority,
        identity.recovery_authority,
    )?;

    assemble(
        funding_key,
        authority_keys,
        Assembly {
            leading: core::slice::from_ref(common.identity_output),
            funding: common.utxos,
            outputs: vec![TxOut {
                value: 0,
                script_pubkey,
            }],
            burn: 0,
            // The identity output plus a change slot.
            fee_output_count: 2,
            change_address: common.change_address,
            expiry_height: common.expiry_height,
            fee_per_kb: common.fee_per_kb,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cc::Destination;
    use crate::Txid;

    const TEST_WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";
    const VRSCTEST: &str = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";

    fn key() -> PrivateKey {
        PrivateKey::from_wif(TEST_WIF).unwrap()
    }

    fn parent() -> [u8; 20] {
        VRSCTEST.parse::<Address>().unwrap().hash()
    }

    /// An identity whose authorities point at `authority`.
    fn identity(authority: [u8; 20], flags: u32) -> Identity {
        Identity {
            version: 3,
            flags,
            primary_addresses: vec![Destination::PubKeyHash(key().address().hash())],
            min_sigs: 1,
            parent: parent(),
            name: "rustrevoke".to_string(),
            content_multimap: Vec::new(),
            content_map: Vec::new(),
            revocation_authority: authority,
            recovery_authority: authority,
            private_addresses: Vec::new(),
            system_id: parent(),
            unlock_after: 0,
        }
    }

    fn identity_utxo(identity: &Identity) -> Utxo {
        Utxo {
            txid: Txid::from_internal([0xaa; 32]),
            vout: 0,
            satoshis: 0,
            script_pubkey: identity_primary_script(
                identity_id(&identity.name, Some(identity.parent)),
                identity.to_bytes().unwrap(),
                identity.revocation_authority,
                identity.recovery_authority,
            )
            .unwrap(),
        }
    }

    fn funding(key: &PrivateKey) -> Vec<Utxo> {
        vec![Utxo {
            txid: Txid::from_internal([0xbb; 32]),
            vout: 0,
            satoshis: 100_000_000,
            script_pubkey: key.address().p2pkh_script_pubkey().unwrap(),
        }]
    }

    /// The dead end the daemon also refuses: nobody could ever recover it.
    #[test]
    fn refuses_to_revoke_into_an_unrecoverable_state() {
        let key = key();
        let id = identity_id("rustrevoke", Some(parent()));
        let identity = identity(id, 0);
        let held = identity_utxo(&identity);
        let utxos = funding(&key);
        let params = RevocationParams::new(&held, &utxos, key.address(), 0);
        assert!(matches!(
            build_identity_revocation(&key, &[&key], &params),
            Err(TxError::RevocationWouldStrand)
        ));
    }

    /// With recovery pointed elsewhere, revocation sets the flag and changes
    /// nothing else.
    #[test]
    fn revocation_sets_only_the_flag() {
        let key = key();
        let identity = identity([0x42; 20], 0);
        let held = identity_utxo(&identity);
        let utxos = funding(&key);
        let params = RevocationParams::new(&held, &utxos, key.address(), 0);
        let signed = build_identity_revocation(&key, &[&key], &params).unwrap();

        // Re-decode what the transaction publishes.
        let raw = hex::decode(&signed.hex).unwrap();
        let published = find_identity(&raw);
        assert!(published.is_revoked());
        assert_eq!(published.primary_addresses, identity.primary_addresses);
        assert_eq!(published.min_sigs, identity.min_sigs);
        assert_eq!(
            published.revocation_authority,
            identity.revocation_authority
        );
        assert_eq!(published.recovery_authority, identity.recovery_authority);
    }

    #[test]
    fn refuses_to_revoke_twice() {
        let key = key();
        let identity = identity([0x42; 20], FLAG_REVOKED);
        let held = identity_utxo(&identity);
        let utxos = funding(&key);
        let params = RevocationParams::new(&held, &utxos, key.address(), 0);
        assert!(matches!(
            build_identity_revocation(&key, &[&key], &params),
            Err(TxError::AlreadyRevoked)
        ));
    }

    #[test]
    fn refuses_to_recover_an_identity_that_is_not_revoked() {
        let key = key();
        let identity = identity([0x42; 20], 0);
        let held = identity_utxo(&identity);
        let utxos = funding(&key);
        let params = RecoveryParams::new(&held, &identity, &utxos, key.address(), 0);
        assert!(matches!(
            build_identity_recovery(&key, &[&key], &params),
            Err(TxError::NotRevoked)
        ));
    }

    /// Recovering without clearing the flag spends the output and achieves
    /// nothing but the fee.
    #[test]
    fn refuses_a_recovery_that_leaves_the_flag_set() {
        let key = key();
        let revoked = identity([0x42; 20], FLAG_REVOKED);
        let held = identity_utxo(&revoked);
        let utxos = funding(&key);
        let params = RecoveryParams::new(&held, &revoked, &utxos, key.address(), 0);
        assert!(matches!(
            build_identity_recovery(&key, &[&key], &params),
            Err(TxError::StillRevoked)
        ));
    }

    /// Recovery clears the flag and may hand over new primary addresses.
    #[test]
    fn recovery_clears_the_flag_and_may_replace_the_keys() {
        let key = key();
        let revoked = identity([0x42; 20], FLAG_REVOKED);
        let held = identity_utxo(&revoked);
        let mut recovered = revoked.clone();
        recovered.flags = 0;
        recovered.primary_addresses = vec![Destination::PubKeyHash([0x77; 20])];
        let utxos = funding(&key);
        let params = RecoveryParams::new(&held, &recovered, &utxos, key.address(), 0);
        let signed = build_identity_recovery(&key, &[&key], &params).unwrap();

        let raw = hex::decode(&signed.hex).unwrap();
        let published = find_identity(&raw);
        assert!(!published.is_revoked());
        assert_eq!(
            published.primary_addresses,
            vec![Destination::PubKeyHash([0x77; 20])]
        );
    }

    /// Pull the published identity back out of a signed transaction by scanning
    /// for the output script that decodes as one.
    fn find_identity(raw: &[u8]) -> Identity {
        for start in 0..raw.len() {
            for end in (start + 40)..=raw.len() {
                if let Ok(OutputKind::IdentityPrimary { identity }) =
                    decode_output_script(&raw[start..end])
                {
                    return *identity;
                }
            }
        }
        panic!("no identity output in the transaction");
    }
}
