//! Storing application data on a VerusID, and reading it back.
//!
//! A VerusID can carry a `contentmultimap`: any number of values under each of
//! any number of VDXF keys. That is the feature that makes an identity a place
//! to keep application state — a profile, a pointer, a credential — rather than
//! only a thing that signs.
//!
//! Both halves existed and were not joined. [`verus_tx::vdxf::data_key`]
//! derives the key offline, [`verus_tx::update`] republishes an identity, and
//! [`verus_rpc::ChainReader::identity_content`] reads one back. What was
//! missing was the path between them, and one specific piece of care it needs.
//!
//! # An update republishes the whole identity
//!
//! There is no "set this field" transaction. An update states the identity in
//! full, and **anything not carried over is erased** — content, authorities,
//! private addresses. So the object being edited must come from the chain, and
//! from the right place on it.
//!
//! [`publish`] decodes it from the **identity output's script**, not from the
//! JSON of `getidentity`. The script is the copy consensus reads; the JSON is a
//! rendering of it, and a rendering has fields the parser here does not model
//! and would therefore drop. Rebuilding an identity from its own JSON is how an
//! identity loses its content or its authority, permanently.
//!
//! Authority changes stay refused: `allow_authority_change` is never set here.
//! Publishing content cannot cost you the identity.
//!
//! # It moves bytes, not meaning — and that is the finished shape
//!
//! A multimap value is VDXF-typed data whose encoding depends on its key. This
//! module does not interpret it, and that is not a gap waiting to be filled.
//!
//! **A VDXF key is a one-way hash of a name.** `data_key` and the daemon's
//! `getvdxfid` both go name → key; there is no inverse, and none is possible.
//! So for a key you did not create, you cannot recover the name, and without
//! the name there is nothing to tell you how its values are encoded. Only the
//! key's creator knows that, and only by publishing the name can anyone else
//! learn it.
//!
//! Mainnet shows the shape of the problem: `vrsc@` and `Verus Coin Foundation@`
//! each publish one 30-byte value under `iSJ38vYX7qoCtotc9wBHb1vZdR3oTgoHCX`.
//! Trying candidate names against `getvdxfid` is the only way to search, and it
//! is a search, not a lookup. Anything this module claimed about those bytes
//! would be a guess — and guessing about a published format is how you write
//! data that nobody, including you, can read back.
//!
//! For an application storing **its own** data this costs nothing. It knows its
//! own names, chooses its own encoding under its own namespace, and gets the
//! bytes back exactly as written. If it wants anyone else to read them, the
//! thing to publish is the **name**, not the key.
//!
//! For someone else's content, this hands you the bytes and stops. That is the
//! honest end of the road rather than a missing feature.

use std::collections::BTreeMap;

use verus_keys::{Address, AddressKind, PrivateKey};
use verus_rpc::{Broadcaster, ChainReader, ContentValue};
use verus_tx::update::{build_identity_update, UpdateParams};
use verus_tx::{
    decode_output_script, Amount, CurrencyId, Expiry, Identity, OutputKind, Utxo,
    DEFAULT_EXPIRY_BLOCKS,
};

use crate::broadcast::Unsent;
use crate::error::FlowError;
use crate::funding;

/// Where a key lives, and which chain it is read on.
///
/// The namespace is the currency id a key hangs under — for an application, its
/// own identity's id, so its keys cannot collide with anyone else's.
///
/// The chain name matters in exactly **one** way, and it is narrower than it
/// sounds: a trailing component equal to the chain's own name is stripped, so
/// `a.vrsctest` and `a` are the same key on VRSCTEST and two different keys on
/// VRSC. A name that does not end in a chain name derives identically
/// everywhere. Worth stating precisely, because "derivation is chain-relative"
/// invites the belief that every key differs per chain, and it does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Namespace {
    /// The currency id keys hang under.
    pub namespace: CurrencyId,
    /// The chain the key will be read on — `"VRSCTEST"`, `"VRSC"`.
    pub chain_name: String,
}

impl Namespace {
    /// Keys under an identity of your own, which is the ordinary case.
    ///
    /// Namespacing by the identity that publishes the data is what stops two
    /// applications choosing the name `profile` from writing over each other.
    pub fn of_identity(identity_id: [u8; 20], chain_name: &str) -> Self {
        Self {
            namespace: CurrencyId::of_identity(identity_id),
            chain_name: chain_name.to_string(),
        }
    }

    /// The 20-byte VDXF key `name` resolves to here.
    pub fn key(&self, name: &str) -> Result<[u8; 20], FlowError> {
        Ok(verus_tx::vdxf::data_key(
            name,
            self.namespace,
            &self.chain_name,
        )?)
    }
}

/// Render a 20-byte VDXF key the way a `contentmultimap` prints it.
///
/// **An `i` address, not hex** — and the same identity object prints its
/// `contentmap` keys as hex, so the two maps disagree about how to spell the
/// same kind of value. Comparing a derived key against the wrong rendering
/// silently finds nothing.
#[must_use]
pub fn key_address(key: [u8; 20]) -> String {
    Address::new(AddressKind::Identity, key).to_string()
}

/// What stands under one key **now**.
///
/// Empty when the key is absent, which is the same answer as a key present with
/// no values — the chain does not distinguish them either.
///
/// # Why this reads the identity and not `getidentitycontent`
///
/// The obviously-named method is the wrong one. `getidentitycontent`
/// accumulates every value published across a height range, so a key written
/// once and then carried through a later update comes back **twice** — and an
/// application reading back its own data would see every revision it had ever
/// written, concatenated, with no way to tell which is current.
///
/// That is not a hypothesis. `vdxf1171008.VRSCTEST@` was registered, given one
/// key, then given a *second* key; the second update restated the first, as
/// every update must. `getidentity` reports the first key with one value.
/// `getidentitycontent` reports it with two. See [`read_history`] for when the
/// accumulating view is the one you want.
pub fn read(
    reader: &impl ChainReader,
    identity: &str,
    key: [u8; 20],
) -> Result<Vec<ContentValue>, FlowError> {
    Ok(read_all(reader, identity)?
        .get(&key_address(key))
        .cloned()
        .unwrap_or_default())
}

/// Every key an identity holds now, with its values.
pub fn read_all(
    reader: &impl ChainReader,
    identity: &str,
) -> Result<BTreeMap<String, Vec<ContentValue>>, FlowError> {
    let record = reader.identity(identity)?;
    Ok(verus_rpc::content_multimap(&record.identity)?)
}

/// Every value an identity has **ever** published under one key, oldest first.
///
/// The audit view. A key that has been rewritten appears once per update that
/// carried it, so this is a history rather than a state — see [`read`] for what
/// the identity actually holds.
pub fn read_history(
    reader: &impl ChainReader,
    identity: &str,
    key: [u8; 20],
) -> Result<Vec<ContentValue>, FlowError> {
    Ok(reader
        .identity_content(identity)?
        .content_multimap
        .get(&key_address(key))
        .cloned()
        .unwrap_or_default())
}

/// What [`publish`] changed, and the transaction that changed it.
///
/// From [`prepare_publish`] nothing has changed yet: the transaction exists but
/// has not been offered to a node, so read every field below in the future
/// tense until it has.
#[derive(Clone, Debug)]
pub struct Published {
    /// The transaction's id, computed locally from its bytes.
    pub txid: String,
    /// The key that was written, as it will appear in `contentmultimap`.
    pub key: String,
    /// How many values stand under it once the update confirms. Zero means the
    /// key was removed.
    pub values: usize,
}

/// Publish `values` under `key` on `identity`, replacing whatever was there.
///
/// An empty `values` removes the key. There is no "append": the whole identity
/// is restated, so the whole entry is restated with it — read first if you mean
/// to add.
///
/// `identity_keys` must satisfy the identity's own `min_sigs` from its primary
/// addresses; the first also pays the miner fee from `funding_address`.
///
/// # What is carried over
///
/// Everything. The identity is decoded from the output script consensus reads,
/// and only this one multimap entry is touched — see the module docs for why
/// that is not the obvious implementation. Authority changes are refused by the
/// builder and never permitted here.
pub fn publish(
    reader: &impl ChainReader,
    broadcaster: &impl Broadcaster,
    identity_keys: &[&PrivateKey],
    identity: &str,
    funding_address: &str,
    key: [u8; 20],
    values: Vec<Vec<u8>>,
) -> Result<Published, FlowError> {
    prepare_publish(
        reader,
        identity_keys,
        identity,
        funding_address,
        key,
        values,
    )?
    .broadcast(broadcaster)
}

/// Build the identity update without sending it.
///
/// The read-only half of [`publish`]. Every check [`publish`] makes is here,
/// including the one that stops a node redirecting the update to an identity
/// the caller never named — all of them read, none of them write.
pub fn prepare_publish(
    reader: &impl ChainReader,
    identity_keys: &[&PrivateKey],
    identity: &str,
    funding_address: &str,
    key: [u8; 20],
    values: Vec<Vec<u8>>,
) -> Result<Unsent<Published>, FlowError> {
    let first = identity_keys
        .first()
        .ok_or_else(|| FlowError::Content("publishing needs at least one key".into()))?;

    // The fee comes from `funding_address`, and its inputs are signed by the
    // first key. A mismatch builds and signs cleanly and then dies at the
    // daemon with a script-verify failure that names nothing.
    let signer = first.address().to_string();
    if signer != funding_address {
        return Err(FlowError::Content(format!(
            "the fee would be paid from {funding_address} but the first key controls {signer}"
        )));
    }

    // Issued together, unwrapped after: the funding lookup needs nothing from
    // the identity, and a `?` between them would make it a second network round
    // trip against a driver. See [`crate::drive`]. What *is* irreducible is the
    // step below — the transaction can only be asked for once the identity has
    // named its outpoint.
    let record = reader.identity(identity);
    let funding = funding::spendable(reader, funding_address);
    let (record, funding) = (record?, funding?);

    if record.is_revoked() {
        return Err(FlowError::Content(format!(
            "{identity} is revoked and cannot be updated"
        )));
    }
    let (txid, vout) = record.outpoint;

    // The identity as consensus holds it, decoded from its own output script.
    // Not from `record.identity`, which is a rendering — see the module docs.
    let raw = reader.raw_transaction(&txid.to_display_hex())?;
    let script = identity_output_script(&raw, vout)?;
    let mut object = match decode_output_script(&script)? {
        OutputKind::IdentityPrimary { identity } => *identity,
        other => {
            return Err(FlowError::Content(format!(
                "the output holding {identity} is not an identity: {other:?}"
            )))
        }
    };

    // **The decoded identity must be the one that was named.**
    //
    // Everything above came from the node: the outpoint from `getidentity`,
    // the transaction from `getrawtransaction`. A node that answers both with
    // some *other* identity the same key also controls produces an internally
    // consistent lie — the script matches the outpoint, the signature verifies
    // because the key is a primary address there too, and the caller
    // broadcasts a valid update to an identity they never named. Publishing an
    // empty value would then delete that identity's entry for the key.
    //
    // The sighash cannot catch this, because nothing about it is inconsistent.
    // The check that can is offline: derive the id from the name the caller
    // gave and compare against the object that came back.
    let expected = record.identity_address.parse::<Address>().map_err(|e| {
        FlowError::Content(format!(
            "{identity} reported the identity address {:?}, which does not parse: {e}",
            record.identity_address
        ))
    })?;
    let decoded_id = verus_tx::identity_id(&object.name, Some(object.parent));
    if expected.hash() != decoded_id {
        return Err(FlowError::Content(format!(
            "asked for {identity} but the output the node pointed at holds {}, whose id is {}              rather than {} — refusing to sign an update to an identity that was not named",
            object.name,
            key_address(decoded_id),
            record.identity_address
        )));
    }

    set_multimap_entry(&mut object, key, values.clone());

    // An identity output carries no native value. Reading it rather than
    // assuming means a nonzero one is named here instead of surfacing as an
    // opaque sighash rejection.
    let held = raw["vout"]
        .as_array()
        .and_then(|outs| outs.get(usize::try_from(vout).unwrap_or(usize::MAX)))
        .and_then(|out| out["valueSat"].as_u64())
        .unwrap_or(0);
    if held != 0 {
        return Err(FlowError::Content(format!(
            "the output holding {identity} carries {held} satoshis; identity outputs hold none,              so this is not the output it claims to be"
        )));
    }

    let identity_output = Utxo {
        txid,
        vout,
        satoshis: Amount::ZERO,
        script_pubkey: script,
    };
    let change: Address = funding_address.parse()?;

    // `UpdateParams::new` refuses authority changes by construction, and this
    // never opts out. Publishing content must not be able to cost the identity.
    let signed = build_identity_update(
        first,
        identity_keys,
        &UpdateParams::new(
            &identity_output,
            &object,
            &funding.utxos,
            change,
            Expiry::within(funding.tip, DEFAULT_EXPIRY_BLOCKS),
        ),
    )?;

    Ok(Unsent {
        hex: signed.hex.clone(),
        txid: signed.txid.clone(),
        outcome: Published {
            txid: signed.txid,
            key: key_address(key),
            values: values.len(),
        },
    })
}

/// Replace one multimap entry in place, leaving every other key alone.
///
/// The rewritten entry moves to the end. That changes the serialized bytes and
/// so the txid — which change anyway — and nothing else: the reference
/// implementation serializes insertion order without sorting, and the chain
/// accepts it.
fn set_multimap_entry(identity: &mut Identity, key: [u8; 20], values: Vec<Vec<u8>>) {
    identity.content_multimap.retain(|(k, _)| *k != key);
    if !values.is_empty() {
        identity.content_multimap.push((key, values));
    }
}

/// The script of output `vout` in a decoded transaction.
fn identity_output_script(raw: &serde_json::Value, vout: u32) -> Result<Vec<u8>, FlowError> {
    let hex_script = raw["vout"]
        .as_array()
        .and_then(|outs| outs.get(usize::try_from(vout).unwrap_or(usize::MAX)))
        .and_then(|out| out["scriptPubKey"]["hex"].as_str())
        .ok_or_else(|| {
            FlowError::Content(format!("the identity's transaction has no output {vout}"))
        })?;
    hex::decode(hex_script)
        .map_err(|e| FlowError::Content(format!("the identity output's script is not hex: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity_with(entries: Vec<([u8; 20], Vec<Vec<u8>>)>) -> Identity {
        Identity {
            version: 3,
            flags: 0,
            primary_addresses: Vec::new(),
            min_sigs: 1,
            parent: [0; 20],
            name: "app".into(),
            content_multimap: entries,
            content_map: Vec::new(),
            revocation_authority: [0; 20],
            recovery_authority: [0; 20],
            private_addresses: Vec::new(),
            system_id: [0; 20],
            unlock_after: 0,
        }
    }

    /// Writing one key must not disturb another. An update restates the whole
    /// identity, so a careless edit silently erases every other application's
    /// data on the same identity.
    #[test]
    fn writing_one_key_leaves_the_others_untouched() {
        let mut identity = identity_with(vec![
            ([0xaa; 20], vec![b"theirs".to_vec()]),
            ([0xbb; 20], vec![b"old".to_vec()]),
        ]);

        set_multimap_entry(&mut identity, [0xbb; 20], vec![b"new".to_vec()]);

        assert_eq!(identity.content_multimap.len(), 2);
        let theirs = identity
            .content_multimap
            .iter()
            .find(|(k, _)| *k == [0xaa; 20])
            .expect("the other key survives");
        assert_eq!(theirs.1, vec![b"theirs".to_vec()]);
    }

    /// The entry is replaced, not appended to — the identity is restated in
    /// full, so there is nothing to append to.
    #[test]
    fn writing_a_key_replaces_its_values() {
        let mut identity = identity_with(vec![([0xbb; 20], vec![b"one".to_vec()])]);
        set_multimap_entry(
            &mut identity,
            [0xbb; 20],
            vec![b"two".to_vec(), b"three".to_vec()],
        );

        assert_eq!(identity.content_multimap.len(), 1);
        assert_eq!(identity.content_multimap[0].1.len(), 2);
    }

    /// No values means the key goes away, rather than standing there empty.
    #[test]
    fn writing_nothing_removes_the_key() {
        let mut identity = identity_with(vec![
            ([0xaa; 20], vec![b"keep".to_vec()]),
            ([0xbb; 20], vec![b"drop".to_vec()]),
        ]);
        set_multimap_entry(&mut identity, [0xbb; 20], Vec::new());

        assert_eq!(identity.content_multimap.len(), 1);
        assert_eq!(identity.content_multimap[0].0, [0xaa; 20]);
    }

    /// The two content maps on one identity print their keys differently: the
    /// multimap as an `i` address, the older content map as hex. Comparing a
    /// derived key against the wrong spelling finds nothing and says nothing.
    #[test]
    fn a_multimap_key_renders_as_an_i_address_not_hex() {
        let rendered = key_address([0xab; 20]);
        assert!(rendered.starts_with('i'), "{rendered}");
        assert_eq!(rendered.len(), 34);
        assert_ne!(rendered, "ab".repeat(20));
    }

    /// Namespacing by the publishing identity is what keeps two applications
    /// that both chose the name `profile` from writing over each other.
    #[test]
    fn the_same_name_under_two_identities_is_two_keys() {
        let one = Namespace::of_identity([0x11; 20], "VRSCTEST");
        let two = Namespace::of_identity([0x22; 20], "VRSCTEST");
        assert_ne!(one.key("profile").unwrap(), two.key("profile").unwrap());
    }

    /// Finding the name behind a key is a **search**, not a lookup, and this is
    /// what that means in practice.
    ///
    /// Derivation is a hash, so it only runs one way: you can confirm a guess
    /// by deriving it and comparing, and you can do nothing else. A near-miss
    /// name yields a key with no resemblance to the right one, so there is no
    /// gradient to follow and no way to narrow the space — which is why a key
    /// published by someone else tells you nothing about how to read its
    /// values.
    #[test]
    fn a_key_can_be_confirmed_from_a_name_but_never_inverted() {
        let ns = Namespace::of_identity([0x11; 20], "VRSCTEST");

        let known = ns.key("profile").unwrap();
        assert_eq!(
            ns.key("profile").unwrap(),
            known,
            "a guess can be confirmed"
        );

        // One character out, and nothing about the result is closer.
        let near = ns.key("profil").unwrap();
        assert_ne!(near, known);
        let shared = near
            .iter()
            .zip(known.iter())
            .take_while(|(a, b)| a == b)
            .count();
        assert!(
            shared < 4,
            "a near-miss name must not leak a prefix of the right key: {shared} bytes shared"
        );
    }

    /// The one — and only — way derivation depends on where the key is read.
    ///
    /// A trailing component equal to the chain's own name is stripped. So
    /// `profile.vrsctest` is `profile` on VRSCTEST and something else on VRSC,
    /// while a name that does not end in a chain name is the same key
    /// everywhere. The first assertion is the trap; the second is what an
    /// earlier version of this module's documentation got wrong by implying
    /// every key is chain-specific.
    #[test]
    fn only_a_trailing_chain_name_makes_a_key_chain_specific() {
        let test = Namespace::of_identity([0x11; 20], "VRSCTEST");
        let main = Namespace::of_identity([0x11; 20], "VRSC");

        assert_ne!(
            test.key("profile.vrsctest").unwrap(),
            main.key("profile.vrsctest").unwrap(),
            "the chain's own name is stripped on one chain and not the other"
        );
        assert_eq!(
            test.key("profile.vrsctest").unwrap(),
            test.key("profile").unwrap(),
            "and stripping is what makes those the same key"
        );
        assert_eq!(
            test.key("profile").unwrap(),
            main.key("profile").unwrap(),
            "an ordinary name derives identically on every chain"
        );
    }
}

#[cfg(test)]
mod publish_tests {
    use super::*;
    use crate::testing::ScriptedReader;
    use serde_json::json;
    use verus_keys::PrivateKey;
    use verus_rpc::IdentityRecord;
    use verus_tx::{identity_id, Destination, Txid};

    /// A key nothing has ever been sent to, derived rather than written down
    /// so it cannot be mistaken for a funded one.
    fn test_key() -> PrivateKey {
        PrivateKey::from_bytes(&[0x7c; 32], true).expect("a valid scalar")
    }
    const IDENTITY_TX: [u8; 32] = [0x22; 32];

    /// An identity holding one key that belongs to somebody else's
    /// application, plus the key we are about to write.
    fn on_chain(key: &PrivateKey, theirs: [u8; 20]) -> (Identity, Vec<u8>) {
        let identity = Identity {
            version: 3,
            flags: 0,
            primary_addresses: vec![Destination::PubKeyHash(key.address().hash())],
            min_sigs: 1,
            parent: [0x2b; 20],
            name: "app".into(),
            content_multimap: vec![(theirs, vec![b"not mine".to_vec()])],
            content_map: Vec::new(),
            revocation_authority: [0x33; 20],
            recovery_authority: [0x44; 20],
            private_addresses: Vec::new(),
            system_id: [0x2b; 20],
            unlock_after: 0,
        };
        let id = identity_id(&identity.name, Some(identity.parent));
        let script = verus_tx::cc::identity_primary_script(
            id,
            identity.to_bytes().expect("identity encodes"),
            identity.revocation_authority,
            identity.recovery_authority,
        )
        .expect("script");
        (identity, script)
    }

    fn reader(key: &PrivateKey, script: &[u8], identity: &Identity) -> ScriptedReader {
        let id = identity_id(&identity.name, Some(identity.parent));
        let address = key.address().to_string();
        ScriptedReader::new(1_170_800)
            .with_utxo(&address, 1_170_000, 500_000_000)
            .with_identity(
                "app@",
                IdentityRecord {
                    fully_qualified_name: "app@".into(),
                    identity_address: key_address(id),
                    status: "active".into(),
                    outpoint: (Txid::from_internal(IDENTITY_TX), 0),
                    block_height: 1_170_000,
                    identity: json!({ "identityaddress": key_address(id) }),
                },
            )
            .with_raw_transaction(
                &Txid::from_internal(IDENTITY_TX).to_display_hex(),
                json!({ "vout": [{
                    "valueSat": 0,
                    "scriptPubKey": { "hex": hex::encode(script) }
                }] }),
            )
    }

    /// The invariant this whole module is shaped around, asserted on the bytes
    /// that would actually be broadcast rather than on a doc claim.
    ///
    /// An update republishes the identity in full. Writing our key must leave
    /// another application's key on the same identity exactly as it was — and
    /// must leave the authorities alone, which is the difference between an
    /// awkward bug and an identity nobody can ever update again.
    #[test]
    fn publishing_one_key_preserves_everything_else_in_the_broadcast_bytes() {
        let key = test_key();
        let theirs = [0xaa; 20];
        let (identity, script) = on_chain(&key, theirs);
        let reader = reader(&key, &script, &identity);

        let ours = [0xbb; 20];
        let published = publish(
            &reader,
            &reader,
            &[&key],
            "app@",
            &key.address().to_string(),
            ours,
            vec![b"mine".to_vec()],
        )
        .expect("publish");

        assert_eq!(published.values, 1);

        // Decode what was actually broadcast and read the identity back out of
        // it. Nothing here trusts the builder's own report.
        let raw = hex::decode(&reader.broadcasts()[0]).expect("broadcast hex");
        let tx = verus_wire::TxV4::deserialize(&raw).expect("parse");
        let republished = tx
            .outputs
            .iter()
            .find_map(
                |out| match verus_tx::decode_output_script(&out.script_pubkey) {
                    Ok(OutputKind::IdentityPrimary { identity }) => Some(*identity),
                    _ => None,
                },
            )
            .expect("the update carries an identity output");

        let their_entry = republished
            .content_multimap
            .iter()
            .find(|(k, _)| *k == theirs)
            .expect("another application's key must survive the update");
        assert_eq!(their_entry.1, vec![b"not mine".to_vec()]);

        let our_entry = republished
            .content_multimap
            .iter()
            .find(|(k, _)| *k == ours)
            .expect("our key was written");
        assert_eq!(our_entry.1, vec![b"mine".to_vec()]);

        // The fields that cannot be recovered if they are dropped.
        assert_eq!(republished.revocation_authority, [0x33; 20]);
        assert_eq!(republished.recovery_authority, [0x44; 20]);
        assert_eq!(republished.min_sigs, 1);
        assert_eq!(republished.primary_addresses.len(), 1);
        assert_eq!(republished.name, "app");
    }

    /// The redirection a node can attempt, and the check that stops it.
    ///
    /// Both the outpoint and the transaction come from the node. If it answers
    /// with a *different* identity the same key also controls, everything is
    /// internally consistent — the script matches the outpoint, the signature
    /// verifies — and the caller would broadcast a valid update to an identity
    /// they never named. Only an offline comparison against the name catches
    /// it.
    #[test]
    fn an_output_holding_a_different_identity_is_refused() {
        let key = test_key();
        let (identity, script) = on_chain(&key, [0xaa; 20]);
        let reader = reader(&key, &script, &identity);

        // The node points "app@" at an output that really holds "other@" —
        // a well-formed identity the same key controls.
        let mut other = identity.clone();
        other.name = "other".into();
        let other_id = identity_id(&other.name, Some(other.parent));
        let other_script = verus_tx::cc::identity_primary_script(
            other_id,
            other.to_bytes().expect("encodes"),
            other.revocation_authority,
            other.recovery_authority,
        )
        .expect("script");

        let lying = reader.with_raw_transaction(
            &Txid::from_internal(IDENTITY_TX).to_display_hex(),
            json!({ "vout": [{
                "valueSat": 0,
                "scriptPubKey": { "hex": hex::encode(&other_script) }
            }] }),
        );

        let error = publish(
            &lying,
            &lying,
            &[&key],
            "app@",
            &key.address().to_string(),
            [0xbb; 20],
            vec![b"mine".to_vec()],
        )
        .expect_err("an update to an unnamed identity must be refused");
        assert!(
            format!("{error}").contains("was not named"),
            "the error must say what happened: {error}"
        );
        assert!(lying.broadcasts().is_empty(), "nothing may be broadcast");
    }

    /// Paying the fee from an address the signing key does not control builds
    /// and signs cleanly, then dies at the daemon naming nothing. Caught here
    /// instead.
    #[test]
    fn funding_from_an_address_the_key_does_not_control_is_refused() {
        let key = test_key();
        let (identity, script) = on_chain(&key, [0xaa; 20]);
        let reader = reader(&key, &script, &identity);

        let error = publish(
            &reader,
            &reader,
            &[&key],
            "app@",
            "RJUgxvDnDLsRGCXNKDK56Rxngzh6m25J6F",
            [0xbb; 20],
            vec![b"mine".to_vec()],
        )
        .expect_err("mismatched funding must be refused");
        assert!(format!("{error}").contains("first key controls"), "{error}");
        assert!(reader.broadcasts().is_empty());
    }
}
