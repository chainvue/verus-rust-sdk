//! The rest of the VerusID lifecycle: update, revoke, recover.
//!
//! [`crate::prepare_registration`] covers bringing an identity into existence.
//! This module covers changing one that already exists, and it exists because
//! the step between "the user decided" and "the builder can be called" is the
//! same every time and expensive to get wrong.
//!
//! # Why a described change, and not a replacement
//!
//! [`UpdateParams::identity`](verus_tx::update::UpdateParams::identity) takes
//! the identity *as it should read afterwards, in full*. That is honest about
//! the protocol — an update republishes the whole object, so there is no such
//! thing as a partial one — and it makes every caller perform a
//! read-modify-write. Drop `content_multimap`, `private_addresses` or the
//! timelock while restating it and the chain accepts the result: the builder
//! cannot tell an omission from a deliberate removal.
//!
//! So this module does not take an identity. It takes an [`IdentityChange`]
//! whose fields are all `Option`, reads the current identity from the chain,
//! and applies only what was named. `None` means "leave it alone", and removing
//! something has to be spelled out as `Some(empty)`.
//!
//! Four fields are absent from [`IdentityChange`] on purpose — `name`,
//! `parent`, `system_id` and the raw `flags`. The first three are what the
//! identity *is* and changing them addresses a different identity; the flags
//! carry revocation and tokenized control, which belong to the operations that
//! own them. Leaving them out means no caller can clobber them by restating.
//!
//! # What is checked before anything is signed
//!
//! A revocation must be signed by the revocation authority and a recovery by
//! the recovery authority — **not** by the identity's own keys. Nothing offline
//! can tell whether the keys in hand qualify, because the authority is another
//! identity whose primary addresses live on the chain. The builders say so and
//! sign anyway.
//!
//! These flows ask. Before signing, the named authority is read and the keys
//! are checked against its primary addresses and threshold. That check is
//! **advisory**: it is the node's answer, so a lying node can fail a valid
//! revocation or pass an invalid one. It is worth having anyway, because of what
//! the alternative looks like on the wire — a rejected identity spend reports
//!
//! ```text
//! -26: 16: mandatory-script-verify-flag-failed
//! ```
//!
//! and names neither the condition that failed nor the authority that would
//! have satisfied it. Measured on VRSCTEST, 2026-08-05. A named refusal before
//! the fee is spent is strictly better than an anonymous one after.
//!
//! # These prepare, they do not send
//!
//! Every function here returns [`Unsent`]. Revocation cannot be undone without
//! the recovery authority, and recovery can hand an identity to the wrong keys
//! permanently, so the broadcast is a separate call the caller makes on purpose
//! — usually after showing a human what [`Unsent::txid`] is about to do.

use verus_keys::{Address, PrivateKey};
use verus_rpc::{ChainReader, IdentityRecord};
use verus_tx::revoke::{
    build_identity_recovery, build_identity_revocation, RecoveryParams, RevocationParams,
};
use verus_tx::update::{build_identity_update, UpdateParams};
use verus_tx::{
    decode_output_script, identity_id, Amount, Destination, Expiry, Identity, OutputKind, Timelock,
    Utxo, DEFAULT_EXPIRY_BLOCKS,
};

use crate::broadcast::Unsent;
use crate::error::FlowError;
use crate::funding;

/// Published content as [`Identity`] stores it: each VDXF key with every value
/// under it, in order.
pub type ContentMultimap = Vec<([u8; 20], Vec<Vec<u8>>)>;

/// A described change to an identity. `None` leaves a field as the chain has it.
///
/// Removing something is spelled `Some(empty)` — `with_content_multimap(vec![])`
/// erases published content, while leaving the field alone carries it over.
/// That asymmetry is the point: the destructive spelling is the longer one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct IdentityChange {
    /// Who may sign for the identity.
    pub primary_addresses: Option<Vec<Destination>>,
    /// How many of them must.
    pub min_sigs: Option<u32>,
    /// The single-valued content map, VDXF id to 32-byte hash.
    pub content_map: Option<Vec<([u8; 20], [u8; 32])>>,
    /// The multimap, VDXF id to raw values.
    pub content_multimap: Option<ContentMultimap>,
    /// Published Sapling addresses.
    pub private_addresses: Option<Vec<[u8; 43]>>,
    /// Who may revoke.
    pub revocation_authority: Option<[u8; 20]>,
    /// Who may recover.
    pub recovery_authority: Option<[u8; 20]>,
    /// The timelock, flag and height together. See [`Timelock`].
    pub timelock: Option<Timelock>,
    /// Permit changing who controls the identity.
    ///
    /// Off by default. Setting `primary_addresses`, `min_sigs` or either
    /// authority to a value that differs from the chain's is refused without
    /// this, by [`UpdateParams`] and against the identity as the chain
    /// currently has it.
    ///
    /// Read [`UpdateParams::allow_authority_change`] before setting it: an
    /// authority moved off the identity cannot be moved back by the identity,
    /// and a threshold nobody can meet ends the identity's life.
    pub allow_authority_change: bool,
}

impl IdentityChange {
    /// Change nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the primary addresses. Needs [`Self::allowing_authority_change`].
    #[must_use]
    pub fn with_primary_addresses(mut self, addresses: Vec<Destination>) -> Self {
        self.primary_addresses = Some(addresses);
        self
    }

    /// Replace the signing threshold. Needs [`Self::allowing_authority_change`].
    #[must_use]
    pub fn with_min_sigs(mut self, min_sigs: u32) -> Self {
        self.min_sigs = Some(min_sigs);
        self
    }

    /// Replace the content map. An empty vector erases it.
    #[must_use]
    pub fn with_content_map(mut self, map: Vec<([u8; 20], [u8; 32])>) -> Self {
        self.content_map = Some(map);
        self
    }

    /// Replace the content multimap. An empty vector erases it.
    #[must_use]
    pub fn with_content_multimap(mut self, map: ContentMultimap) -> Self {
        self.content_multimap = Some(map);
        self
    }

    /// Replace the published Sapling addresses. An empty vector erases them.
    #[must_use]
    pub fn with_private_addresses(mut self, addresses: Vec<[u8; 43]>) -> Self {
        self.private_addresses = Some(addresses);
        self
    }

    /// Point revocation at an identity. Needs [`Self::allowing_authority_change`].
    #[must_use]
    pub fn with_revocation_authority(mut self, authority: [u8; 20]) -> Self {
        self.revocation_authority = Some(authority);
        self
    }

    /// Point recovery at an identity. Needs [`Self::allowing_authority_change`].
    #[must_use]
    pub fn with_recovery_authority(mut self, authority: [u8; 20]) -> Self {
        self.recovery_authority = Some(authority);
        self
    }

    /// Set the timelock.
    #[must_use]
    pub fn with_timelock(mut self, timelock: Timelock) -> Self {
        self.timelock = Some(timelock);
        self
    }

    /// Permit the fields that decide who controls the identity to move.
    #[must_use]
    pub fn allowing_authority_change(mut self) -> Self {
        self.allow_authority_change = true;
        self
    }

    /// Whether anything at all was named.
    pub fn is_empty(&self) -> bool {
        *self == Self::default() || *self == Self::default().allowing_authority_change()
    }

    /// Apply what was named onto the identity the chain holds.
    fn apply_to(&self, identity: &mut Identity) {
        if let Some(addresses) = &self.primary_addresses {
            identity.primary_addresses = addresses.clone();
        }
        if let Some(min_sigs) = self.min_sigs {
            identity.min_sigs = min_sigs;
        }
        if let Some(map) = &self.content_map {
            identity.content_map = map.clone();
        }
        if let Some(map) = &self.content_multimap {
            identity.content_multimap = map.clone();
        }
        if let Some(addresses) = &self.private_addresses {
            identity.private_addresses = addresses.clone();
        }
        if let Some(authority) = self.revocation_authority {
            identity.revocation_authority = authority;
        }
        if let Some(authority) = self.recovery_authority {
            identity.recovery_authority = authority;
        }
        // Last, because it touches `flags` and reads the current ones.
        if let Some(timelock) = self.timelock {
            timelock.apply_to(identity);
        }
    }
}

/// An identity as consensus holds it, with the output that holds it.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Held {
    /// Decoded from the output script, not from `getidentity`'s rendering.
    pub identity: Identity,
    /// The output to spend, carrying the script the sighash will commit to.
    pub output: Utxo,
    /// What the node said about it, for the fields that are not in the object.
    pub record: IdentityRecord,
}

/// What an update will have done.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Updated {
    /// The transaction that carries it.
    pub txid: String,
    /// The identity it is about.
    pub identity: String,
    /// Whether it moves any of the fields that decide control.
    pub changes_authority: bool,
    /// Miner fee.
    pub fee: Amount,
    /// Change returned to the funding address.
    pub change: Amount,
}

/// What a revocation will have done.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Revoked {
    /// The transaction that carries it.
    pub txid: String,
    /// The identity it is about.
    pub identity: String,
    /// The authority whose keys signed it.
    pub authority: String,
    /// Miner fee.
    pub fee: Amount,
    /// Change returned to the funding address.
    pub change: Amount,
}

/// What a recovery will have done.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Recovered {
    /// The transaction that carries it.
    pub txid: String,
    /// The identity it is about.
    pub identity: String,
    /// The authority whose keys signed it.
    pub authority: String,
    /// Whether it hands the identity to different primary addresses.
    pub replaces_primary_addresses: bool,
    /// Miner fee.
    pub fee: Amount,
    /// Change returned to the funding address.
    pub change: Amount,
}

/// Read an identity the way consensus reads it, and find the output to spend.
///
/// Two requests, plus the one that cannot be issued until the first has named
/// the outpoint. The identity comes out of the **output script**, not out of
/// `getidentity`'s rendering: the rendering is a view, and an update has to
/// restate the object bit for bit.
///
/// # The check that matters
///
/// Everything here comes from the node — the outpoint from `getidentity`, the
/// transaction from `getrawtransaction`. A node that answers both with some
/// *other* identity the same key controls tells an internally consistent lie:
/// the script matches the outpoint, the signature verifies because the key is a
/// primary address there too, and the caller signs an update to an identity
/// they never named. The sighash cannot catch it, because nothing is
/// inconsistent.
///
/// Two comparisons do, and they are not equally strong. Naming an identity by
/// its **i-address** is checked against the decoded object with no node
/// involved, and closes the wholesale lie. A `name@` lookup can only be checked
/// against what the node itself reported, which catches a node inconsistent
/// with itself and not one that lies consistently. **Prefer the i-address** for
/// anything destructive.
pub fn current_identity(reader: &impl ChainReader, identity: &str) -> Result<Held, FlowError> {
    let record = reader.identity(identity)?;
    let (txid, vout) = record.outpoint;

    let raw = reader.raw_transaction(&txid.to_display_hex())?;
    let script = identity_output_script(&raw, vout)?;
    let object = match decode_output_script(&script)? {
        OutputKind::IdentityPrimary { identity } => *identity,
        other => {
            return Err(FlowError::Content(format!(
                "the output holding {identity} is not an identity: {other:?}"
            )))
        }
    };

    let expected = record.identity_address.parse::<Address>().map_err(|e| {
        FlowError::Content(format!(
            "{identity} reported the identity address {:?}, which does not parse: {e}",
            record.identity_address
        ))
    })?;
    let decoded_id = identity_id(&object.name, Some(object.parent));

    // The strong comparison, available only when the caller named an i-address.
    if let Ok(named) = identity.parse::<Address>() {
        if named.kind() == verus_keys::AddressKind::Identity && named.hash() != decoded_id {
            return Err(FlowError::Content(format!(
                "asked for {identity} but the output the node pointed at holds {}, whose id is \
                 {} — refusing to work on an identity that was not named",
                object.name,
                i_address(decoded_id)
            )));
        }
    }

    // The weak one, which is all a `name@` lookup allows.
    if expected.hash() != decoded_id {
        return Err(FlowError::Content(format!(
            "asked for {identity} but the output the node pointed at holds {}, whose id is {} \
             rather than {} — refusing to work on an identity that was not named",
            object.name,
            i_address(decoded_id),
            record.identity_address
        )));
    }

    // An identity output carries no native value. An **absent** `valueSat` is
    // refused rather than read as zero: the value below is hardcoded, so the
    // sighash would otherwise commit to an amount nobody checked.
    let held = raw["vout"]
        .as_array()
        .and_then(|outs| outs.get(usize::try_from(vout).unwrap_or(usize::MAX)))
        .and_then(|out| out["valueSat"].as_u64())
        .ok_or_else(|| {
            FlowError::Content(format!(
                "the node's copy of the output holding {identity} reports no valueSat, so there \
                 is nothing to check the zero-value rule against"
            ))
        })?;
    if held != 0 {
        return Err(FlowError::Content(format!(
            "the output holding {identity} carries {held} satoshis; identity outputs hold none, \
             so this is not the output it claims to be"
        )));
    }

    Ok(Held {
        identity: object,
        output: Utxo {
            txid,
            vout,
            satoshis: Amount::ZERO,
            script_pubkey: script,
        },
        record,
    })
}

/// Build an identity update from a described change, without sending it.
///
/// Reads the identity, applies what [`IdentityChange`] named, and leaves
/// everything else exactly as the chain has it. `funding_key` pays the miner
/// fee and receives the change; `identity_keys` must be `min_sigs` of the
/// identity's own primary addresses.
///
/// # Errors
///
/// [`FlowError::Content`] if the change names nothing, if the node's answers do
/// not agree about which identity is at the outpoint, or if the identity is
/// revoked — a revoked identity can only be recovered, and an update would spend
/// the fee to be rejected.
pub fn prepare_identity_update(
    reader: &impl ChainReader,
    funding_key: &PrivateKey,
    identity_keys: &[&PrivateKey],
    identity: &str,
    change: &IdentityChange,
) -> Result<Unsent<Updated>, FlowError> {
    if change.is_empty() {
        return Err(FlowError::Content(format!(
            "the change to {identity} names no field, so the update would spend a fee to \
             republish the identity unchanged"
        )));
    }
    if identity_keys.is_empty() {
        return Err(FlowError::Content(
            "an identity update needs at least one signing key".into(),
        ));
    }

    let change_address = funding_key.address().to_string();
    // Issued together, unwrapped after: neither read needs the other. A `?`
    // between them costs a round trip against a driver. See [`crate::drive`].
    let funding = funding::spendable(reader, &change_address);
    let held = current_identity(reader, identity);
    let (funding, held) = (funding?, held?);

    if held.identity.is_revoked() {
        return Err(FlowError::Content(format!(
            "{identity} is revoked; recover it before updating it"
        )));
    }

    let mut object = held.identity.clone();
    change.apply_to(&mut object);
    let changes_authority = object.primary_addresses != held.identity.primary_addresses
        || object.min_sigs != held.identity.min_sigs
        || object.revocation_authority != held.identity.revocation_authority
        || object.recovery_authority != held.identity.recovery_authority;

    let mut params = UpdateParams::new(
        &held.output,
        &object,
        &funding.utxos,
        change_address.parse::<Address>()?,
        Expiry::within(funding.tip, DEFAULT_EXPIRY_BLOCKS),
    )
    .at_tip(funding.tip);
    if change.allow_authority_change {
        params = params.allowing_authority_change();
    }

    let signed = build_identity_update(funding_key, identity_keys, &params)?;
    Ok(Unsent {
        hex: signed.hex.clone(),
        txid: signed.txid.clone(),
        outcome: Updated {
            txid: signed.txid,
            identity: identity.to_string(),
            changes_authority,
            fee: signed.fee,
            change: signed.change,
        },
    })
}

/// Build a revocation, without sending it.
///
/// `authority_keys` must satisfy the **revocation authority's** condition, not
/// the identity's own. They are checked against the authority the chain names
/// before anything is signed — see the module docs on why that check is
/// advisory and still worth making.
///
/// # Errors
///
/// [`FlowError::Content`] if the identity is already revoked, if it is its own
/// recovery authority (consensus refuses that revocation, since nobody could
/// then recover it), or if the keys do not satisfy the authority.
pub fn prepare_identity_revocation(
    reader: &impl ChainReader,
    funding_key: &PrivateKey,
    authority_keys: &[&PrivateKey],
    identity: &str,
) -> Result<Unsent<Revoked>, FlowError> {
    let change_address = funding_key.address().to_string();
    let funding = funding::spendable(reader, &change_address);
    let held = current_identity(reader, identity);
    let (funding, held) = (funding?, held?);

    if held.identity.is_revoked() {
        return Err(FlowError::Content(format!("{identity} is already revoked")));
    }

    let authority = held.identity.revocation_authority;
    check_authority(reader, &held, authority, authority_keys, "revocation")?;

    let signed = build_identity_revocation(
        funding_key,
        authority_keys,
        &RevocationParams::new(
            &held.output,
            &funding.utxos,
            change_address.parse::<Address>()?,
            Expiry::within(funding.tip, DEFAULT_EXPIRY_BLOCKS),
        ),
    )?;
    Ok(Unsent {
        hex: signed.hex.clone(),
        txid: signed.txid.clone(),
        outcome: Revoked {
            txid: signed.txid,
            identity: identity.to_string(),
            authority: i_address(authority),
            fee: signed.fee,
            change: signed.change,
        },
    })
}

/// Build a recovery, without sending it.
///
/// Clears `FLAG_REVOKED` and applies `restore` on top of the identity as the
/// chain has it. `authority_keys` must satisfy the **recovery authority's**
/// condition.
///
/// # This is the call that can give an identity away
///
/// Recovery exists because the old keys are gone, so unlike an update it may
/// legitimately replace `primary_addresses` and both authorities, and nothing
/// second-guesses that. Passing an empty `restore` recovers the identity to the
/// keys it already had — which is right only if those keys still exist.
/// [`Recovered::replaces_primary_addresses`] reports which of the two happened,
/// so a caller can show it before broadcasting.
pub fn prepare_identity_recovery(
    reader: &impl ChainReader,
    funding_key: &PrivateKey,
    authority_keys: &[&PrivateKey],
    identity: &str,
    restore: &IdentityChange,
) -> Result<Unsent<Recovered>, FlowError> {
    let change_address = funding_key.address().to_string();
    let funding = funding::spendable(reader, &change_address);
    let held = current_identity(reader, identity);
    let (funding, held) = (funding?, held?);

    if !held.identity.is_revoked() {
        return Err(FlowError::Content(format!(
            "{identity} is not revoked, so there is nothing to recover"
        )));
    }

    let authority = held.identity.recovery_authority;
    check_authority(reader, &held, authority, authority_keys, "recovery")?;

    // The builder refuses an identity that still reads as revoked, and the
    // caller should not have to know that. Clearing it here is the whole point
    // of the operation, not a choice.
    let mut object = held.identity.clone();
    object.flags &= !verus_tx::identity::FLAG_REVOKED;
    restore.apply_to(&mut object);
    let replaces_primary_addresses = object.primary_addresses != held.identity.primary_addresses;

    let signed = build_identity_recovery(
        funding_key,
        authority_keys,
        &RecoveryParams::new(
            &held.output,
            &object,
            &funding.utxos,
            change_address.parse::<Address>()?,
            Expiry::within(funding.tip, DEFAULT_EXPIRY_BLOCKS),
        ),
    )?;
    Ok(Unsent {
        hex: signed.hex.clone(),
        txid: signed.txid.clone(),
        outcome: Recovered {
            txid: signed.txid,
            identity: identity.to_string(),
            authority: i_address(authority),
            replaces_primary_addresses,
            fee: signed.fee,
            change: signed.change,
        },
    })
}

/// Start the countdown on a locked identity, without sending it.
///
/// # Why this is not just `with_timelock`
///
/// Unlocking is never instant. A locked identity has to publish an unlock
/// *height*, and consensus measures that height from the transaction's own
/// `nExpiryHeight` rather than from the tip: leaving a delay of `d` requires
/// publishing at least `d + expiry`. The expiry belongs to the transaction this
/// function is building, so a caller passing [`Timelock`] by hand is guessing
/// against a number they cannot see. Guess low and the daemon answers
/// `mandatory-script-verify-flag-failed`, after the fee.
///
/// So this reads the delay the chain holds, picks the expiry, and computes the
/// height from both. `extra_blocks` is added on top of the minimum for callers
/// who want the unlock later than the earliest consensus permits; `0` asks for
/// the earliest.
///
/// The identity stays locked until the chain passes the published height. This
/// transaction starts the clock; it does not stop the lock.
///
/// # Errors
///
/// [`FlowError::Content`] if the identity is not locked with a delay — an
/// identity already counting down has nothing to start, and an unlocked one has
/// nothing to do.
pub fn prepare_identity_unlock(
    reader: &impl ChainReader,
    funding_key: &PrivateKey,
    identity_keys: &[&PrivateKey],
    identity: &str,
    extra_blocks: u32,
) -> Result<Unsent<Updated>, FlowError> {
    if identity_keys.is_empty() {
        return Err(FlowError::Content(
            "starting an unlock needs at least one signing key".into(),
        ));
    }

    let change_address = funding_key.address().to_string();
    let funding = funding::spendable(reader, &change_address);
    let held = current_identity(reader, identity);
    let (funding, held) = (funding?, held?);

    if held.identity.is_revoked() {
        return Err(FlowError::Content(format!(
            "{identity} is revoked; recover it before unlocking it"
        )));
    }
    let delay = match held.identity.timelock() {
        Timelock::DelayAfterUnlock(delay) => delay,
        Timelock::UntilBlock(height) => {
            return Err(FlowError::Content(format!(
                "{identity} is already counting down to block {height}; there is nothing to start"
            )))
        }
        Timelock::None => return Err(FlowError::Content(format!("{identity} is not locked"))),
    };

    let expiry = Expiry::within(funding.tip, DEFAULT_EXPIRY_BLOCKS);
    // The floor consensus enforces, plus whatever the caller asked for on top.
    let unlock_at = delay
        .saturating_add(expiry.to_height())
        .saturating_add(extra_blocks);

    let mut object = held.identity.clone();
    Timelock::UntilBlock(unlock_at).apply_to(&mut object);

    let signed = build_identity_update(
        funding_key,
        identity_keys,
        &UpdateParams::new(
            &held.output,
            &object,
            &funding.utxos,
            change_address.parse::<Address>()?,
            expiry,
        )
        .at_tip(funding.tip),
    )?;
    Ok(Unsent {
        hex: signed.hex.clone(),
        txid: signed.txid.clone(),
        outcome: Updated {
            txid: signed.txid,
            identity: identity.to_string(),
            changes_authority: false,
            fee: signed.fee,
            change: signed.change,
        },
    })
}

/// Do these keys satisfy the identity `authority`?
///
/// Advisory, and deliberately so — every fact here is the node's. What it buys
/// is a refusal that names the authority and the shortfall, instead of the
/// anonymous script-verify failure consensus would report after the fee is
/// spent. See the module docs.
fn check_authority(
    reader: &impl ChainReader,
    held: &Held,
    authority: [u8; 20],
    keys: &[&PrivateKey],
    what: &str,
) -> Result<(), FlowError> {
    if keys.is_empty() {
        return Err(FlowError::Content(format!(
            "a {what} needs at least one key from the {what} authority"
        )));
    }

    let address = i_address(authority);
    let subject = identity_id(&held.identity.name, Some(held.identity.parent));

    // When the identity is its own authority — the shape every registration
    // starts in — the answer is already in hand, decoded from the output
    // script. Using it is one request fewer *and* stronger than the node's
    // rendering, which is all the other branch can have.
    let (primaries, min_sigs): (Vec<String>, u64) = if authority == subject {
        let primaries = held
            .identity
            .primary_addresses
            .iter()
            .filter_map(|destination| match destination {
                Destination::PubKeyHash(hash) => {
                    Some(Address::new(verus_keys::AddressKind::PubKeyHash, *hash).to_string())
                }
                _ => None,
            })
            .collect();
        (primaries, u64::from(held.identity.min_sigs))
    } else {
        let record = reader.identity(&address)?;
        let primaries = record.identity["primaryaddresses"]
            .as_array()
            .map(|found| {
                found
                    .iter()
                    .filter_map(|a| a.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let min_sigs = record.identity["minimumsignatures"].as_u64().unwrap_or(1);
        (primaries, min_sigs)
    };

    if primaries.is_empty() {
        return Err(FlowError::Content(format!(
            "the {what} authority {address} reports no primary addresses, so there is nothing to \
             check the keys against"
        )));
    }

    let holding = keys
        .iter()
        .filter(|key| primaries.contains(&key.address().to_string()))
        .count();
    if (holding as u64) < min_sigs {
        return Err(FlowError::Content(format!(
            "the {what} authority is {address}, which needs {min_sigs} of {} primary \
             address(es); {holding} of the {} key(s) supplied qualify. A {what} signed by the \
             identity's own keys is rejected by consensus without naming why.",
            primaries.len(),
            keys.len()
        )));
    }
    Ok(())
}

/// Render a 20-byte id as the `i` address that names it.
fn i_address(id: [u8; 20]) -> String {
    Address::new(verus_keys::AddressKind::Identity, id).to_string()
}

/// The script of the output an identity lives in, from a raw transaction.
fn identity_output_script(raw: &serde_json::Value, vout: u32) -> Result<Vec<u8>, FlowError> {
    let hex = raw["vout"]
        .as_array()
        .and_then(|outs| outs.get(usize::try_from(vout).unwrap_or(usize::MAX)))
        .and_then(|out| out["scriptPubKey"]["hex"].as_str())
        .ok_or_else(|| {
            FlowError::Content(format!(
                "the transaction holding the identity has no output {vout}"
            ))
        })?;
    hex::decode(hex)
        .map_err(|e| FlowError::Content(format!("the identity output script is not hex: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::ScriptedReader;
    use serde_json::json;
    use verus_rpc::IdentityRecord;
    use verus_tx::identity::FLAG_REVOKED;
    use verus_tx::Txid;

    /// Derived, so it cannot be mistaken for a funded key.
    fn test_key() -> PrivateKey {
        PrivateKey::from_bytes(&[0x7c; 32], true).expect("a valid scalar")
    }
    fn authority_key() -> PrivateKey {
        PrivateKey::from_bytes(&[0x5d; 32], true).expect("a valid scalar")
    }
    const IDENTITY_TX: [u8; 32] = [0x22; 32];
    const REVOCATION: [u8; 20] = [0x33; 20];
    const RECOVERY: [u8; 20] = [0x44; 20];

    /// An identity carrying something in every field a careless restatement
    /// would drop.
    fn populated(key: &PrivateKey, flags: u32) -> Identity {
        Identity {
            version: 3,
            flags,
            primary_addresses: vec![Destination::PubKeyHash(key.address().hash())],
            min_sigs: 1,
            parent: [0x2b; 20],
            name: "app".into(),
            content_multimap: vec![([0xaa; 20], vec![b"theirs".to_vec()])],
            content_map: vec![([0xcc; 20], [0x11; 32])],
            revocation_authority: REVOCATION,
            recovery_authority: RECOVERY,
            private_addresses: vec![[0x09; 43]],
            system_id: [0x2b; 20],
            unlock_after: 0,
        }
    }

    fn script_of(identity: &Identity) -> Vec<u8> {
        verus_tx::cc::identity_primary_script(
            identity_id(&identity.name, Some(identity.parent)),
            identity.to_bytes().expect("identity encodes"),
            identity.revocation_authority,
            identity.recovery_authority,
        )
        .expect("script")
    }

    fn reader_for(key: &PrivateKey, identity: &Identity) -> ScriptedReader {
        let id = identity_id(&identity.name, Some(identity.parent));
        ScriptedReader::new(1_170_800)
            .with_utxo(&key.address().to_string(), 1_170_000, 500_000_000)
            .with_identity(
                "app@",
                IdentityRecord {
                    fully_qualified_name: "app@".into(),
                    identity_address: i_address(id),
                    status: if identity.is_revoked() {
                        "revoked"
                    } else {
                        "active"
                    }
                    .into(),
                    outpoint: (Txid::from_internal(IDENTITY_TX), 0),
                    block_height: 1_170_000,
                    identity: json!({ "identityaddress": i_address(id) }),
                },
            )
            .with_raw_transaction(
                &Txid::from_internal(IDENTITY_TX).to_display_hex(),
                json!({ "vout": [{
                    "valueSat": 0,
                    "scriptPubKey": { "hex": hex::encode(script_of(identity)) }
                }] }),
            )
    }

    /// Register an authority identity the pre-check can resolve.
    fn with_authority(
        reader: ScriptedReader,
        id: [u8; 20],
        primary: &str,
        min_sigs: u32,
    ) -> ScriptedReader {
        reader.with_identity(
            &i_address(id),
            IdentityRecord {
                fully_qualified_name: "authority@".into(),
                identity_address: i_address(id),
                status: "active".into(),
                outpoint: (Txid::from_internal([0x77; 32]), 0),
                block_height: 1_170_000,
                identity: json!({
                    "identityaddress": i_address(id),
                    "primaryaddresses": [primary],
                    "minimumsignatures": min_sigs,
                }),
            },
        )
    }

    /// Read the identity back out of what would actually be broadcast.
    fn republished(hex: &str) -> Identity {
        let raw = hex::decode(hex).expect("hex");
        let tx = verus_wire::TxV4::deserialize(&raw).expect("parse");
        tx.outputs
            .iter()
            .find_map(|out| match decode_output_script(&out.script_pubkey) {
                Ok(OutputKind::IdentityPrimary { identity }) => Some(*identity),
                _ => None,
            })
            .expect("an identity output")
    }

    /// The property the whole module exists for, asserted on the bytes.
    ///
    /// Naming one field must leave every other field exactly as the chain had
    /// it — including the ones a hand-written read-modify-write forgets.
    #[test]
    fn naming_one_field_carries_every_other_one_through_to_the_broadcast_bytes() {
        let key = test_key();
        let identity = populated(&key, 0);
        let reader = reader_for(&key, &identity);

        let unsent = prepare_identity_update(
            &reader,
            &key,
            &[&key],
            "app@",
            &IdentityChange::new().with_content_map(vec![([0xdd; 20], [0x22; 32])]),
        )
        .expect("update");

        let after = republished(&unsent.hex);
        assert_eq!(
            after.content_map,
            vec![([0xdd; 20], [0x22; 32])],
            "the named field changed"
        );

        // Everything else, untouched.
        assert_eq!(after.content_multimap, identity.content_multimap);
        assert_eq!(after.private_addresses, identity.private_addresses);
        assert_eq!(after.revocation_authority, REVOCATION);
        assert_eq!(after.recovery_authority, RECOVERY);
        assert_eq!(after.primary_addresses, identity.primary_addresses);
        assert_eq!(after.min_sigs, identity.min_sigs);
        assert_eq!(after.flags, identity.flags);
        assert_eq!(after.unlock_after, identity.unlock_after);
        assert_eq!(after.name, identity.name);
        assert_eq!(after.parent, identity.parent);
        assert_eq!(after.system_id, identity.system_id);
        assert!(!unsent.outcome.changes_authority);
    }

    /// Erasing has to be spelled out, and then it really does erase.
    #[test]
    fn an_empty_vector_erases_where_none_carries_over() {
        let key = test_key();
        let identity = populated(&key, 0);
        let reader = reader_for(&key, &identity);

        let unsent = prepare_identity_update(
            &reader,
            &key,
            &[&key],
            "app@",
            &IdentityChange::new().with_content_multimap(Vec::new()),
        )
        .expect("update");

        let after = republished(&unsent.hex);
        assert!(
            after.content_multimap.is_empty(),
            "the named field was erased"
        );
        assert_eq!(
            after.content_map, identity.content_map,
            "the unnamed one survived"
        );
    }

    #[test]
    fn a_change_that_names_nothing_is_refused() {
        let key = test_key();
        let identity = populated(&key, 0);
        let reader = reader_for(&key, &identity);

        let err = prepare_identity_update(&reader, &key, &[&key], "app@", &IdentityChange::new())
            .expect_err("nothing to do");
        assert!(format!("{err}").contains("names no field"), "{err}");
    }

    /// The builder's guard still applies through the flow, and it compares
    /// against the chain rather than against anything the caller supplied.
    #[test]
    fn moving_an_authority_without_permission_is_refused() {
        let key = test_key();
        let identity = populated(&key, 0);
        let reader = reader_for(&key, &identity);

        let err = prepare_identity_update(
            &reader,
            &key,
            &[&key],
            "app@",
            &IdentityChange::new().with_recovery_authority([0x99; 20]),
        )
        .expect_err("authority change without opting in");
        assert!(matches!(err, FlowError::Tx(_)), "{err}");
    }

    #[test]
    fn moving_an_authority_with_permission_is_built_and_reported() {
        let key = test_key();
        let identity = populated(&key, 0);
        let reader = reader_for(&key, &identity);

        let unsent = prepare_identity_update(
            &reader,
            &key,
            &[&key],
            "app@",
            &IdentityChange::new()
                .with_recovery_authority([0x99; 20])
                .allowing_authority_change(),
        )
        .expect("update");

        assert!(unsent.outcome.changes_authority, "the caller must be told");
        assert_eq!(republished(&unsent.hex).recovery_authority, [0x99; 20]);
    }

    #[test]
    fn a_revoked_identity_cannot_be_updated() {
        let key = test_key();
        let identity = populated(&key, FLAG_REVOKED);
        let reader = reader_for(&key, &identity);

        let err = prepare_identity_update(
            &reader,
            &key,
            &[&key],
            "app@",
            &IdentityChange::new().with_content_map(Vec::new()),
        )
        .expect_err("revoked");
        assert!(format!("{err}").contains("recover it"), "{err}");
    }

    /// The check the daemon will not do for you in a form you can read.
    ///
    /// Signing a revocation with the identity's own keys is the natural
    /// mistake, and consensus answers it with an anonymous script failure after
    /// the fee is gone. This refuses first and names the authority.
    #[test]
    fn revoking_with_the_wrong_keys_is_refused_before_anything_is_signed() {
        let key = test_key();
        let identity = populated(&key, 0);
        let reader = with_authority(
            reader_for(&key, &identity),
            REVOCATION,
            &authority_key().address().to_string(),
            1,
        );

        let err = prepare_identity_revocation(&reader, &key, &[&key], "app@")
            .expect_err("the identity's own key is not the revocation authority");
        let message = format!("{err}");
        assert!(
            message.contains(&i_address(REVOCATION)),
            "must name the authority: {message}"
        );
        assert!(
            message.contains("0 of the 1 key(s)"),
            "must name the shortfall: {message}"
        );
    }

    #[test]
    fn revoking_with_the_authoritys_keys_is_built() {
        let key = test_key();
        let authority = authority_key();
        let identity = populated(&key, 0);
        let reader = with_authority(
            reader_for(&key, &identity),
            REVOCATION,
            &authority.address().to_string(),
            1,
        );

        let unsent =
            prepare_identity_revocation(&reader, &key, &[&authority], "app@").expect("revocation");
        assert_eq!(unsent.outcome.authority, i_address(REVOCATION));
        assert!(
            republished(&unsent.hex).is_revoked(),
            "the flag must be set"
        );
    }

    /// The shape every identity starts in: its own revocation authority.
    ///
    /// The keys are then checked against the identity decoded from the output
    /// script, so no lookup of the authority happens at all. The reader here
    /// deliberately has no entry for it — if the check reached for the node,
    /// this would fail rather than pass quietly.
    #[test]
    fn a_self_revoking_identity_is_checked_against_its_own_decoded_addresses() {
        let key = test_key();
        let mut identity = populated(&key, 0);
        identity.revocation_authority = identity_id(&identity.name, Some(identity.parent));
        let reader = reader_for(&key, &identity);

        let unsent = prepare_identity_revocation(&reader, &key, &[&key], "app@")
            .expect("the identity's own key is its revocation authority");
        assert!(republished(&unsent.hex).is_revoked());

        // And the wrong key is still refused, by the same offline comparison.
        let err = prepare_identity_revocation(&reader, &key, &[&authority_key()], "app@")
            .expect_err("a key the identity does not list");
        assert!(format!("{err}").contains("0 of the 1 key(s)"), "{err}");
    }

    #[test]
    fn recovering_an_identity_that_is_not_revoked_is_refused() {
        let key = test_key();
        let identity = populated(&key, 0);
        let reader = reader_for(&key, &identity);

        let err = prepare_identity_recovery(&reader, &key, &[&key], "app@", &IdentityChange::new())
            .expect_err("nothing to recover");
        assert!(format!("{err}").contains("not revoked"), "{err}");
    }

    /// Clearing the flag is the operation, not something the caller has to
    /// remember — the builder refuses an identity that still reads as revoked.
    #[test]
    fn recovery_clears_the_flag_and_can_hand_over_the_keys() {
        let key = test_key();
        let authority = authority_key();
        let identity = populated(&key, FLAG_REVOKED);
        let reader = with_authority(
            reader_for(&key, &identity),
            RECOVERY,
            &authority.address().to_string(),
            1,
        );

        let new_owner = Destination::PubKeyHash([0x66; 20]);
        let unsent = prepare_identity_recovery(
            &reader,
            &key,
            &[&authority],
            "app@",
            &IdentityChange::new().with_primary_addresses(vec![new_owner.clone()]),
        )
        .expect("recovery");

        assert!(
            unsent.outcome.replaces_primary_addresses,
            "the caller must be told"
        );
        let after = republished(&unsent.hex);
        assert!(!after.is_revoked(), "recovery clears the flag");
        assert_eq!(after.primary_addresses, vec![new_owner]);
        assert_eq!(
            after.content_multimap, identity.content_multimap,
            "content survives recovery"
        );
    }

    /// The trap the unlock flow exists for.
    ///
    /// A caller reaching for `with_timelock` has to publish an unlock height
    /// measured from the transaction's expiry, which the flow picks and they
    /// never see. The obvious guess — tip plus delay — is below the floor and
    /// consensus refuses it. Here that refusal is named, before signing.
    #[test]
    fn unlocking_by_hand_against_the_tip_is_refused_with_the_floor_named() {
        let key = test_key();
        let mut identity = populated(&key, 0);
        Timelock::DelayAfterUnlock(100).apply_to(&mut identity);
        let reader = reader_for(&key, &identity);

        // What someone reasoning from the tip would write.
        let err = prepare_identity_update(
            &reader,
            &key,
            &[&key],
            "app@",
            &IdentityChange::new().with_timelock(Timelock::UntilBlock(1_170_800 + 100)),
        )
        .expect_err("below the floor consensus enforces");
        let message = format!("{err}");
        assert!(
            message.contains("at least"),
            "must name the floor: {message}"
        );
        assert!(
            message.contains("expiry"),
            "must say where the floor comes from: {message}"
        );
    }

    /// And the flow computes it correctly instead.
    #[test]
    fn the_unlock_flow_publishes_the_delay_plus_this_transactions_expiry() {
        let key = test_key();
        let mut identity = populated(&key, 0);
        Timelock::DelayAfterUnlock(100).apply_to(&mut identity);
        let reader = reader_for(&key, &identity);

        let unsent = prepare_identity_unlock(&reader, &key, &[&key], "app@", 0).expect("unlock");
        let after = republished(&unsent.hex);

        let expiry = 1_170_800 + verus_tx::DEFAULT_EXPIRY_BLOCKS;
        assert_eq!(
            after.timelock(),
            Timelock::UntilBlock(100 + expiry),
            "the floor is the delay plus this transaction's own expiry height"
        );
        assert!(
            !after.is_locked(),
            "the flag comes off; the countdown is what keeps it locked"
        );
        assert_eq!(
            after.content_multimap, identity.content_multimap,
            "an unlock still republishes the identity in full"
        );
    }

    #[test]
    fn unlocking_something_that_is_not_locked_is_refused() {
        let key = test_key();
        let identity = populated(&key, 0);
        let reader = reader_for(&key, &identity);

        let err = prepare_identity_unlock(&reader, &key, &[&key], "app@", 0)
            .expect_err("nothing to unlock");
        assert!(format!("{err}").contains("not locked"), "{err}");
    }

    /// A delay above the cap is rejected, not silently shortened.
    ///
    /// The daemon's own `Lock()` helper clamps instead, which would hand back a
    /// timelock 21 years shorter than the one that was asked for.
    #[test]
    fn a_delay_beyond_the_maximum_is_refused_rather_than_clamped() {
        let key = test_key();
        let identity = populated(&key, 0);
        let reader = reader_for(&key, &identity);

        let err = prepare_identity_update(
            &reader,
            &key,
            &[&key],
            "app@",
            &IdentityChange::new()
                .with_timelock(Timelock::DelayAfterUnlock(verus_tx::MAX_UNLOCK_DELAY + 1)),
        )
        .expect_err("over the cap");
        assert!(format!("{err}").contains("exceeds the maximum"), "{err}");
    }

    /// An unlock may never be brought forward.
    #[test]
    fn shortening_a_running_countdown_is_refused() {
        let key = test_key();
        let mut identity = populated(&key, 0);
        Timelock::UntilBlock(1_180_000).apply_to(&mut identity);
        let reader = reader_for(&key, &identity);

        let err = prepare_identity_update(
            &reader,
            &key,
            &[&key],
            "app@",
            &IdentityChange::new().with_timelock(Timelock::UntilBlock(1_175_000)),
        )
        .expect_err("earlier than the current unlock");
        assert!(format!("{err}").contains("only move later"), "{err}");
    }

    /// A timelock is a flag and a height together, so it is the field most
    /// likely to be restated inconsistently by hand.
    #[test]
    fn a_timelock_is_applied_as_flag_and_height_together() {
        let key = test_key();
        let identity = populated(&key, 0);
        let reader = reader_for(&key, &identity);

        let unsent = prepare_identity_update(
            &reader,
            &key,
            &[&key],
            "app@",
            &IdentityChange::new().with_timelock(Timelock::DelayAfterUnlock(100)),
        )
        .expect("update");

        let after = republished(&unsent.hex);
        assert_eq!(after.timelock(), Timelock::DelayAfterUnlock(100));
        assert!(after.is_locked());
    }
}
