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
//! [`crate::decode_output_script`], change what you mean to change, and hand the
//! whole thing back. An identity assembled from scratch will silently drop
//! whatever the chain already published — including, if you are careless with
//! `primary_addresses` or `min_sigs`, the authority to update it ever again.
//!
//! # Authority
//!
//! The identity output is a CryptoCondition whose master condition is `1-of-3`
//! over the identity, its revocation authority and its recovery authority. This
//! module signs as the identity: the key must be one of the identity's own
//! `primary_addresses`. Revocation and recovery are different operations with
//! different eval codes and are not implemented here.
//!
//! `min_sigs` above 1 needs several signatures in one fulfillment, which this
//! does not build yet — it refuses rather than producing a transaction that
//! cannot satisfy its own condition.

use verus_keys::{Address, PrivateKey};

use crate::assemble::{assemble, check_expiry, check_p2pkh_funding, Assembly};
use crate::cc::{identity_primary_script, Destination};
use crate::error::TxError;
use crate::fee::DEFAULT_FEE_PER_KB;
use crate::identity::Identity;
use crate::register::identity_id;
use crate::send::SignedTransaction;
use crate::Utxo;
use verus_wire::TxOut;

/// What to update, and what to fund it with.
#[derive(Clone, Debug)]
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
    /// Block height after which the transaction expires; `0` never expires.
    pub expiry_height: u32,
    /// Fee rate in satoshis per kilobyte.
    pub fee_per_kb: u64,
}

impl<'a> UpdateParams<'a> {
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

/// Build and sign an identity update.
///
/// The signing key must be one of `identity.primary_addresses`; anything else
/// produces a transaction the daemon rejects at script verification, which
/// reports only that a script finished false.
pub fn build_identity_update(
    key: &PrivateKey,
    params: &UpdateParams<'_>,
) -> Result<SignedTransaction, TxError> {
    check_expiry(params.expiry_height)?;
    check_p2pkh_funding(params.utxos)?;

    let identity = params.identity;
    if identity.min_sigs != 1 {
        return Err(TxError::InvalidMinSigs {
            min_sigs: identity.min_sigs,
            primaries: identity.primary_addresses.len(),
        });
    }

    // Signing with a key the identity does not list is the failure this catches:
    // the transaction would build, sign, serialize, and then fail script
    // verification with nothing pointing at the cause.
    let signer = Destination::PubKeyHash(key.address().hash());
    if !identity.primary_addresses.contains(&signer) {
        return Err(TxError::NotAPrimaryAddress {
            address: key.address().to_string(),
        });
    }

    let identity_id = identity_id(&identity.name, Some(identity.parent));
    let script_pubkey = identity_primary_script(
        identity_id,
        identity.to_bytes()?,
        identity.revocation_authority,
        identity.recovery_authority,
    )?;

    // The identity output must be the one that actually holds this identity.
    // Spending some other output would still sign cleanly and would still be
    // rejected, so it is checked against the script the identity implies.
    if !params
        .identity_output
        .script_pubkey
        .starts_with(&master_prefix(identity_id))
    {
        return Err(TxError::IdentityOutputMismatch);
    }

    assemble(
        key,
        Assembly {
            leading: core::slice::from_ref(params.identity_output),
            funding: params.utxos,
            outputs: vec![TxOut {
                value: 0,
                script_pubkey,
            }],
            burn: 0,
            // The identity output plus a change slot.
            fee_output_count: 2,
            change_address: &params.change_address,
            expiry_height: params.expiry_height,
            fee_per_kb: params.fee_per_kb,
        },
    )
}

/// The leading bytes an identity output must have: a `1-of-3` master condition
/// whose first destination is this identity.
///
/// Comparing the whole script would be wrong — the output being spent holds the
/// *previous* contents, which are exactly what an update changes — so only the
/// part fixed by the identity id is checked.
///
/// ```text
/// PUSH(0x47) PUSH4(version 3, EVAL_NONE, m=1, n=3) PUSH(0x04 || identity_id)
/// ```
fn master_prefix(identity_id: [u8; 20]) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(28);
    prefix.extend_from_slice(&[0x47, 0x04, 0x03, 0x00, 0x01, 0x03, 0x15, 0x04]);
    prefix.extend_from_slice(&identity_id);
    prefix
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Txid;

    const TEST_WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";
    const VRSCTEST: &str = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";

    fn key() -> PrivateKey {
        PrivateKey::from_wif(TEST_WIF).unwrap()
    }

    fn identity(primary: Destination) -> Identity {
        let parent: Address = VRSCTEST.parse().unwrap();
        Identity {
            version: 3,
            flags: 0,
            primary_addresses: vec![primary],
            min_sigs: 1,
            parent: parent.hash(),
            name: "rustsdk".to_string(),
            content_multimap: Vec::new(),
            content_map: Vec::new(),
            revocation_authority: identity_id("rustsdk", Some(parent.hash())),
            recovery_authority: identity_id("rustsdk", Some(parent.hash())),
            private_addresses: Vec::new(),
            system_id: parent.hash(),
            unlock_after: 0,
        }
    }

    fn identity_utxo(identity: &Identity) -> Utxo {
        let parent: Address = VRSCTEST.parse().unwrap();
        let id = identity_id(&identity.name, Some(parent.hash()));
        Utxo {
            txid: Txid::from_internal([0xaa; 32]),
            vout: 0,
            satoshis: 0,
            script_pubkey: identity_primary_script(
                id,
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

    /// Signing with a key the identity does not list would fail at script
    /// verification with an error that names neither the input nor the cause.
    #[test]
    fn refuses_a_key_that_is_not_a_primary_address() {
        let key = key();
        let identity = identity(Destination::PubKeyHash([0x99; 20]));
        let held = identity_utxo(&identity);
        let utxos = funding(&key);
        let params = UpdateParams::new(&held, &identity, &utxos, key.address(), 0);
        assert!(matches!(
            build_identity_update(&key, &params),
            Err(TxError::NotAPrimaryAddress { .. })
        ));
    }

    /// A multisig identity needs several signatures in one fulfillment, which is
    /// not built yet — refusing beats emitting an unsatisfiable transaction.
    #[test]
    fn refuses_a_multisig_identity() {
        let key = key();
        let mut identity = identity(Destination::PubKeyHash(key.address().hash()));
        identity
            .primary_addresses
            .push(Destination::PubKeyHash([0x99; 20]));
        identity.min_sigs = 2;
        let held = identity_utxo(&identity);
        let utxos = funding(&key);
        let params = UpdateParams::new(&held, &identity, &utxos, key.address(), 0);
        assert!(matches!(
            build_identity_update(&key, &params),
            Err(TxError::InvalidMinSigs { .. })
        ));
    }

    /// Spending an output that does not hold this identity.
    #[test]
    fn refuses_an_output_that_holds_another_identity() {
        let key = key();
        let identity = identity(Destination::PubKeyHash(key.address().hash()));
        let mut held = identity_utxo(&identity);
        // Same shape, different identity id in the master condition.
        held.script_pubkey[8] ^= 0xff;
        let utxos = funding(&key);
        let params = UpdateParams::new(&held, &identity, &utxos, key.address(), 0);
        assert!(matches!(
            build_identity_update(&key, &params),
            Err(TxError::IdentityOutputMismatch)
        ));
    }

    /// The happy path: the update spends the identity output as input 0 and
    /// republishes the identity.
    #[test]
    fn builds_an_update_spending_the_identity_output() {
        let key = key();
        let mut identity = identity(Destination::PubKeyHash(key.address().hash()));
        identity.content_map = vec![([0x01; 20], [0x02; 32])];
        let held = identity_utxo(&identity);
        let utxos = funding(&key);
        let params = UpdateParams::new(&held, &identity, &utxos, key.address(), 0);
        let signed = build_identity_update(&key, &params).unwrap();
        assert_eq!(signed.inputs_used[0], (held.txid, held.vout));
        assert_eq!(signed.inputs_used.len(), 2);
    }
}
