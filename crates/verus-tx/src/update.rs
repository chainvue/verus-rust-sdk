//! Updating a VerusID.
//!
//! An update spends the output that currently holds the identity and publishes a
//! new one in its place. There is no partial update at the protocol level: the
//! new output carries the **whole** identity object, so every field the caller
//! does not deliberately change must be carried over unchanged from the chain's
//! current copy.
//!
//! That is why this takes an [`Identity`] rather than a set of edits. The
//! intended flow is: read the current identity out of its output with
//! [`verus_tx_protocol::decode_output_script`], change what you mean to change, and hand the
//! whole thing back. An identity assembled from scratch will silently drop
//! whatever the chain already published — including, if you are careless with
//! `primary_addresses` or `min_sigs`, the authority to update it ever again.
//!
//! # Authority
//!
//! The identity output is a CryptoCondition whose master condition is `1-of-3`
//! over the identity, its revocation authority and its recovery authority. This
//! module signs as the identity: the keys must be `min_sigs` of the identity's
//! own `primary_addresses`, and they all go into a single fulfillment.
//! Revocation and recovery are different operations with different eval codes
//! and are not implemented here.
//!
//! The threshold that matters is the one on the **output being spent**, not the
//! one being published: raising `min_sigs` still only needs the old threshold to
//! authorise, and takes effect from the next update onward.
//!
//! Changing any of the four authority fields is refused unless
//! [`UpdateParams::allow_authority_change`] is set — see that field for why.
//!
//! Both thresholds are proven on VRSCTEST: `rustsdk@` (`1-of-1`) updated at
//! block 1166566, and `rustmulti@` (`2-of-2`) at block 1166732 with both
//! signatures in one fulfillment
//! (`9ff188d8fabbb338d11ed1405345783265a02c3afc8b5705ccd9d35e0d802303`).

use verus_keys::{Address, PrivateKey};

use crate::register::identity_id;
use verus_tx_primitives::cc::{identity_primary_script, Destination};
use verus_tx_primitives::fee::DEFAULT_FEE_PER_KB;
use verus_tx_primitives::Amount;
use verus_tx_primitives::Expiry;
use verus_tx_primitives::TxError;
use verus_tx_primitives::Utxo;
use verus_tx_protocol::decode::{decode_output_script, OutputKind};
use verus_tx_protocol::identity::Identity;
use verus_tx_transparent::assemble::{assemble, check_expiry, check_p2pkh_funding, Assembly};
use verus_tx_transparent::SignedTransaction;
use verus_wire::TxOut;

/// What to update, and what to fund it with.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct UpdateParams<'a> {
    /// The output currently holding the identity — what `getidentity` reports as
    /// its `txid`/`vout`. It carries no native value.
    pub identity_output: &'a Utxo,
    /// The identity as it should read AFTER the update, stated in full.
    pub identity: &'a Identity,
    /// P2PKH UTXOs to pay the miner fee from.
    pub utxos: &'a [Utxo],
    /// Where change goes.
    pub change_address: Address,
    /// When this transaction stops being minable. See [`Expiry`].
    pub expiry: Expiry,
    /// Fee rate in satoshis per kilobyte.
    pub fee_per_kb: u64,
    /// Permit changing who controls the identity.
    ///
    /// Off by default, and worth leaving off. An update that alters
    /// `primary_addresses`, `min_sigs`, or either authority is the one mistake
    /// with no remedy: publish a threshold nobody can meet, or addresses nobody
    /// holds, and the identity can never be updated again — not by the holder,
    /// not by the recovery authority, not by anyone. Changing content carries no
    /// such risk, which is why it does not need this.
    ///
    /// The check compares against the identity **as the chain currently has
    /// it**, decoded from the output being spent, not against anything the
    /// caller supplies.
    pub allow_authority_change: bool,
}

impl<'a> UpdateParams<'a> {
    /// Parameters with the default fee rate and authority changes refused.
    pub fn new(
        identity_output: &'a Utxo,
        identity: &'a Identity,
        utxos: &'a [Utxo],
        change_address: Address,
        expiry: Expiry,
    ) -> Self {
        Self {
            identity_output,
            identity,
            utxos,
            change_address,
            expiry,
            fee_per_kb: DEFAULT_FEE_PER_KB,
            allow_authority_change: false,
        }
    }

    /// Override the fee rate.
    pub fn with_fee_per_kb(mut self, fee_per_kb: u64) -> Self {
        self.fee_per_kb = fee_per_kb;
        self
    }

    /// Permit changing who controls the identity.
    ///
    /// Read [`UpdateParams::allow_authority_change`] before calling this: it is
    /// the one VerusID mistake with no remedy.
    pub fn allowing_authority_change(mut self) -> Self {
        self.allow_authority_change = true;
        self
    }
}

/// Build and sign an identity update.
///
/// `funding_key` pays the miner fee from `params.utxos`. `identity_keys` satisfy
/// the identity's own condition and must be `min_sigs` of its
/// `primary_addresses` — for the ordinary `1-of-1` identity both are the same
/// key, passed twice.
///
/// A key the identity does not list produces a transaction the daemon rejects at
/// script verification, reporting only that a script finished false, so it is
/// refused here instead.
pub fn build_identity_update(
    funding_key: &PrivateKey,
    identity_keys: &[&PrivateKey],
    params: &UpdateParams<'_>,
) -> Result<SignedTransaction, TxError> {
    check_expiry(params.expiry)?;
    check_p2pkh_funding(params.utxos)?;

    let identity = params.identity;
    let id = identity_id(&identity.name, Some(identity.parent));

    // The chain's copy is the authority on what is being spent and on who may
    // spend it. Everything below compares against this, never against the
    // caller's proposed identity — a caller who got the authority wrong would
    // otherwise be checked against their own mistake.
    let current = match decode_output_script(&params.identity_output.script_pubkey)? {
        OutputKind::IdentityPrimary { identity } => *identity,
        _ => return Err(TxError::IdentityOutputMismatch),
    };
    if identity_id(&current.name, Some(current.parent)) != id {
        return Err(TxError::IdentityOutputMismatch);
    }

    if !params.allow_authority_change {
        check_authority_unchanged(&current, identity)?;
    }

    // Satisfying the condition takes min_sigs signatures — the CURRENT
    // threshold, since that is what the output being spent commits to. An
    // update that raises the threshold still only needs the old one.
    if identity_keys.len() < current.min_sigs as usize {
        return Err(TxError::NotEnoughSigners {
            supplied: identity_keys.len(),
            required: current.min_sigs,
        });
    }
    for key in identity_keys {
        let signer = Destination::PubKeyHash(key.address().hash());
        if !current.primary_addresses.contains(&signer) {
            return Err(TxError::NotAPrimaryAddress {
                address: key.address().to_string(),
            });
        }
    }

    let script_pubkey = identity_primary_script(
        id,
        identity.to_bytes()?,
        identity.revocation_authority,
        identity.recovery_authority,
    )?;

    assemble(
        funding_key,
        identity_keys,
        Assembly {
            leading: core::slice::from_ref(params.identity_output),
            funding: params.utxos,
            outputs: vec![TxOut {
                value: 0,
                script_pubkey,
            }],
            burn: Amount::ZERO,
            // The identity output plus a change slot.
            fee_output_count: 2,
            change_address: &params.change_address,
            change_script: None,
            value_bearing_leading: false,
            expiry: params.expiry,
            fee_per_kb: params.fee_per_kb,
        },
    )
}

/// Refuse an update that moves control of the identity.
///
/// These four fields decide who may ever update, revoke or recover it. Content
/// is not checked: changing it is the normal reason to update at all.
fn check_authority_unchanged(current: &Identity, proposed: &Identity) -> Result<(), TxError> {
    let changed = |field: &str| {
        Err(TxError::AuthorityChangeRefused {
            field: field.to_string(),
        })
    };
    if current.primary_addresses != proposed.primary_addresses {
        return changed("primary_addresses");
    }
    if current.min_sigs != proposed.min_sigs {
        return changed("min_sigs");
    }
    if current.revocation_authority != proposed.revocation_authority {
        return changed("revocation_authority");
    }
    if current.recovery_authority != proposed.recovery_authority {
        return changed("recovery_authority");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use verus_tx_primitives::Txid;

    const TEST_WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";
    const VRSCTEST: &str = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";

    fn key() -> PrivateKey {
        PrivateKey::from_wif(TEST_WIF).unwrap()
    }

    /// A second, unrelated key — the co-signer of a multisig identity.
    fn other_key() -> PrivateKey {
        PrivateKey::from_bytes(&[0x27; 32], true).unwrap()
    }

    fn parent() -> [u8; 20] {
        VRSCTEST.parse::<Address>().unwrap().hash()
    }

    fn identity(primaries: Vec<Destination>, min_sigs: u32) -> Identity {
        Identity {
            version: 3,
            flags: 0,
            primary_addresses: primaries,
            min_sigs,
            parent: parent(),
            name: "rustsdk".to_string(),
            content_multimap: Vec::new(),
            content_map: Vec::new(),
            revocation_authority: identity_id("rustsdk", Some(parent())),
            recovery_authority: identity_id("rustsdk", Some(parent())),
            private_addresses: Vec::new(),
            system_id: parent(),
            unlock_after: 0,
        }
    }

    /// A single-signature identity controlled by `key()`.
    fn simple_identity() -> Identity {
        identity(vec![Destination::PubKeyHash(key().address().hash())], 1)
    }

    /// The output the chain currently holds this identity in.
    fn identity_utxo(identity: &Identity) -> Utxo {
        Utxo {
            txid: Txid::from_internal([0xaa; 32]),
            vout: 0,
            satoshis: Amount::from_sat(0),
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
            satoshis: Amount::from_sat(100_000_000),
            script_pubkey: key.address().p2pkh_script_pubkey().unwrap(),
        }]
    }

    /// Publishing content is the ordinary case and needs no opt-in.
    #[test]
    fn builds_an_update_spending_the_identity_output() {
        let key = key();
        let current = simple_identity();
        let held = identity_utxo(&current);
        let mut proposed = current.clone();
        proposed.content_map = vec![([0x01; 20], [0x02; 32])];
        let utxos = funding(&key);
        let params = UpdateParams::new(&held, &proposed, &utxos, key.address(), Expiry::Never);
        let signed = build_identity_update(&key, &[&key], &params).unwrap();
        assert_eq!(signed.inputs_used[0], (held.txid, held.vout));
        assert_eq!(signed.inputs_used.len(), 2);
    }

    /// Signing with a key the identity does not list would fail at script
    /// verification with an error that names neither the input nor the cause.
    #[test]
    fn refuses_a_key_that_is_not_a_primary_address() {
        let key = key();
        let current = identity(vec![Destination::PubKeyHash([0x99; 20])], 1);
        let held = identity_utxo(&current);
        let utxos = funding(&key);
        let params = UpdateParams::new(&held, &current, &utxos, key.address(), Expiry::Never);
        assert!(matches!(
            build_identity_update(&key, &[&key], &params),
            Err(TxError::NotAPrimaryAddress { .. })
        ));
    }

    /// A 2-of-2 identity signs with both keys, in one fulfillment.
    #[test]
    fn signs_a_multisig_identity_with_every_key() {
        let key = key();
        let other = other_key();
        let current = identity(
            vec![
                Destination::PubKeyHash(key.address().hash()),
                Destination::PubKeyHash(other.address().hash()),
            ],
            2,
        );
        let held = identity_utxo(&current);
        let utxos = funding(&key);
        let params = UpdateParams::new(&held, &current, &utxos, key.address(), Expiry::Never);
        let signed = build_identity_update(&key, &[&key, &other], &params).unwrap();

        // The fulfillment on input 0 carries a count of 2. Its layout is
        // version, hash type, count — after the outer push opcode.
        let raw = hex::decode(&signed.hex).unwrap();
        let fulfillment_count = raw
            .windows(3)
            .find(|w| w[0] == 1 && w[1] == 1 && (w[2] == 1 || w[2] == 2))
            .map(|w| w[2])
            .expect("a fulfillment header");
        assert_eq!(fulfillment_count, 2);
    }

    /// One signature cannot satisfy a 2-of-2 condition. Catching it here beats
    /// broadcasting a transaction that can never verify.
    #[test]
    fn refuses_fewer_keys_than_the_threshold() {
        let key = key();
        let other = other_key();
        let current = identity(
            vec![
                Destination::PubKeyHash(key.address().hash()),
                Destination::PubKeyHash(other.address().hash()),
            ],
            2,
        );
        let held = identity_utxo(&current);
        let utxos = funding(&key);
        let params = UpdateParams::new(&held, &current, &utxos, key.address(), Expiry::Never);
        assert!(matches!(
            build_identity_update(&key, &[&key], &params),
            Err(TxError::NotEnoughSigners {
                supplied: 1,
                required: 2
            })
        ));
    }

    /// The threshold that authorises is the one on the output being spent, not
    /// the one being published — so raising it needs only the old threshold.
    #[test]
    fn raising_the_threshold_authorises_against_the_old_one() {
        let key = key();
        let other = other_key();
        let current = simple_identity();
        let held = identity_utxo(&current);
        let mut proposed = current.clone();
        proposed
            .primary_addresses
            .push(Destination::PubKeyHash(other.address().hash()));
        proposed.min_sigs = 2;
        let utxos = funding(&key);
        let params = UpdateParams {
            allow_authority_change: true,
            ..UpdateParams::new(&held, &proposed, &utxos, key.address(), Expiry::Never)
        };
        // One key, because the CURRENT identity is 1-of-1.
        assert!(build_identity_update(&key, &[&key], &params).is_ok());
    }

    /// Each authority field is refused on its own, and named in the error.
    #[test]
    fn refuses_authority_changes_by_default() {
        let key = key();
        let current = simple_identity();
        let held = identity_utxo(&current);
        let utxos = funding(&key);

        let mut primaries = current.clone();
        primaries.primary_addresses = vec![Destination::PubKeyHash([0x99; 20])];
        let mut sigs = current.clone();
        sigs.min_sigs = 2;
        let mut revocation = current.clone();
        revocation.revocation_authority = [0x99; 20];
        let mut recovery = current.clone();
        recovery.recovery_authority = [0x99; 20];

        for (proposed, expected) in [
            (primaries, "primary_addresses"),
            (sigs, "min_sigs"),
            (revocation, "revocation_authority"),
            (recovery, "recovery_authority"),
        ] {
            let params = UpdateParams::new(&held, &proposed, &utxos, key.address(), Expiry::Never);
            match build_identity_update(&key, &[&key], &params) {
                Err(TxError::AuthorityChangeRefused { field }) => assert_eq!(field, expected),
                other => panic!("{expected} should have been refused, got {other:?}"),
            }
        }
    }

    /// Content changes are not authority changes and need no opt-in.
    #[test]
    fn content_changes_are_not_authority_changes() {
        let key = key();
        let current = simple_identity();
        let held = identity_utxo(&current);
        let mut proposed = current.clone();
        proposed.content_multimap = vec![([0x03; 20], vec![vec![0x04; 8]])];
        let utxos = funding(&key);
        let params = UpdateParams::new(&held, &proposed, &utxos, key.address(), Expiry::Never);
        assert!(build_identity_update(&key, &[&key], &params).is_ok());
    }

    /// Spending an output that holds a different identity — an update to
    /// `rustsdk` aimed at the output holding `someoneelse`. It would sign and
    /// serialize perfectly well, and be caught only by the daemon.
    #[test]
    fn refuses_an_output_that_holds_another_identity() {
        let key = key();
        let mut someone_else = simple_identity();
        someone_else.name = "someoneelse".to_string();
        let held = identity_utxo(&someone_else);
        let utxos = funding(&key);
        let ours = simple_identity();
        let params = UpdateParams::new(&held, &ours, &utxos, key.address(), Expiry::Never);
        assert!(matches!(
            build_identity_update(&key, &[&key], &params),
            Err(TxError::IdentityOutputMismatch)
        ));
    }

    /// An output that is not an identity at all.
    #[test]
    fn refuses_an_output_that_is_not_an_identity() {
        let key = key();
        let current = simple_identity();
        let held = Utxo {
            script_pubkey: key.address().p2pkh_script_pubkey().unwrap(),
            ..identity_utxo(&current)
        };
        let utxos = funding(&key);
        let params = UpdateParams::new(&held, &current, &utxos, key.address(), Expiry::Never);
        assert!(matches!(
            build_identity_update(&key, &[&key], &params),
            Err(TxError::IdentityOutputMismatch)
        ));
    }
}
