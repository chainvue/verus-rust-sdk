//! VerusIDs — reading an identity out of the output that holds it.
//!
//! A VerusID is not an address with extra fields. It is a serialized object
//! living in the `vdata` of an `EVAL_IDENTITY_PRIMARY` CryptoCondition output,
//! and the chain's copy of it *is* the identity: its authority (which keys may
//! sign, and how many), who may revoke it, who may recover it, and what content
//! it publishes. Reading that is the prerequisite for every operation on an
//! identity, because an update must restate the whole object.
//!
//! # Layout
//!
//! ```text
//! Principal:
//!   version              uint32 LE
//!   flags                uint32 LE
//!   primary_addresses    vector of destinations
//!   min_sigs             uint32 LE
//! Identity:
//!   parent               20 bytes
//!   name                 varslice, UTF-8
//!   content_multimap     (version >= 3)
//!   content_map          count, then 20-byte key + 32-byte value
//!   revocation_authority 20 bytes
//!   recovery_authority   20 bytes
//!   private_addresses    count, then 43 bytes each
//!   system_id            20 bytes      (version >= 2)
//!   unlock_after         uint32 LE     (version >= 2)
//! ```
//!
//! Note the mixed integer conventions: `uint32` little-endian for the scalar
//! fields, but CompactSize for every count. Both appear within a few bytes of
//! each other, and confusing them silently reinterprets the rest of the object.
//!
//! # Provenance
//!
//! Layout read from `Identity`/`Principal`/`ContentMultiMap` in
//! `verus-typescript-primitives`, then checked field by field against what a
//! daemon's `getidentity` reports for the same identities — see
//! `tests/identity_decode.rs`. The daemon is the oracle; the source is only the
//! map.

use verus_keys::hash160;
use verus_wire::hash::sha256d;

use verus_tx_primitives::cc::Destination;
use verus_tx_primitives::TxError;

/// Lowercase the way the C locale does: ASCII only, everything else untouched.
///
/// Rust's `to_lowercase` is Unicode-aware and would fold characters the daemon
/// leaves alone, deriving a different id for the same name. Names are restricted
/// to ASCII by the registration builder's `validate_name` anyway; this keeps the
/// derivation honest for anything that slips past a caller building ids
/// directly.
fn to_lower_c_locale(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii() {
                c.to_ascii_lowercase()
            } else {
                c
            }
        })
        .collect()
}

/// Derive a VerusID's 20-byte id from its name and parent.
///
/// ```text
/// id_hash = SHA256d(lowercase(name))
/// id_hash = SHA256d(parent || id_hash)      when there is a parent
/// id      = RIPEMD160(SHA256(id_hash))
/// ```
///
/// Note the parent goes in as its raw 20-byte hash, so an `R` address and an `i`
/// address with the same hash derive the same child — which is why callers must
/// pass a real parent identity and not merely something that decoded.
///
/// A root identity on a chain has that chain's system id as its parent: on
/// VRSCTEST every ordinary registration is a child of `VRSCTEST` itself.
/// # An all-zero parent is *no* parent
///
/// Folding twenty zero bytes in anyway gives a different id from the one
/// consensus assigns. `CIdentity::GetID` skips the combine when
/// `parent.IsNull()`; this combined unconditionally, and did not.
///
/// Established against the chain rather than against the source. `vrsc@`
/// carries a null parent, and its id on mainnet is `1af5b801…`, which is
/// exactly `hash160(sha256d("vrsc"))` — the uncombined form. Combining with
/// zeros yields `c980a9f6…`, an address nothing is at.
///
/// Only zero-parent identities were affected, which is why it went unnoticed:
/// every identity registered on a chain has that chain as its parent, so the
/// eight golden VerusID transactions and every registration flow are unchanged
/// by the fix. Chain roots — `vrsc@`, `vrsctest@` — are the exception, and an
/// identity update built for one would have published its output under an id
/// nobody holds.
pub fn identity_id(name: &str, parent: Option<[u8; 20]>) -> [u8; 20] {
    let mut id_hash = sha256d(to_lower_c_locale(name).as_bytes());
    if let Some(parent) = parent.filter(|parent| parent != &[0u8; 20]) {
        let mut combined = Vec::with_capacity(52);
        combined.extend_from_slice(&parent);
        combined.extend_from_slice(&id_hash);
        id_hash = sha256d(&combined);
    }
    hash160(&id_hash)
}

/// A Sapling payment address is 43 bytes, and serde only implements its traits
/// for arrays up to 32. Rather than pull in a dependency for one field, this
/// carries them as byte vectors and re-checks the length on the way back — a
/// stored identity with a 42-byte address is corrupt, not something to accept.
#[cfg(feature = "serde")]
mod sapling_addresses {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        addresses: &[[u8; 43]],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        addresses
            .iter()
            .map(|a| a.to_vec())
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<[u8; 43]>, D::Error> {
        Vec::<Vec<u8>>::deserialize(deserializer)?
            .into_iter()
            .map(|bytes| {
                let len = bytes.len();
                bytes.try_into().map_err(|_| {
                    serde::de::Error::custom(format!(
                        "a Sapling payment address is 43 bytes, got {len}"
                    ))
                })
            })
            .collect()
    }
}

pub use verus_tx_primitives::cc::{
    EVAL_IDENTITY_PRIMARY, EVAL_IDENTITY_RECOVER, EVAL_IDENTITY_REVOKE,
};

/// The first version that carries `system_id` and `unlock_after`.
const IDENTITY_VERSION_VAULT: u32 = 2;
/// The first version that carries a content multimap.
const IDENTITY_VERSION_PBAAS: u32 = 3;

/// Set when the identity has been revoked.
pub const FLAG_REVOKED: u32 = 0x8000;
/// Set when the identity's name is in use as an active currency.
pub const FLAG_ACTIVE_CURRENCY: u32 = 0x1;
/// Set when the identity is locked.
pub const FLAG_LOCKED: u32 = 0x2;

/// The longest unlock delay consensus accepts, in blocks — about 21 years at
/// one minute a block.
///
/// Two different behaviours hang off this number and it is worth knowing which
/// you are getting. Consensus **rejects** an identity whose lock delay exceeds
/// it (`CIdentity::IsInvalidMutation`). The daemon's own `CIdentity::Lock`
/// helper instead **clamps** silently, so asking it for more gives you a
/// different timelock than you requested rather than an error. This crate
/// rejects, matching consensus: a timelock quietly shortened by 21 years is not
/// a convenience.
pub const MAX_UNLOCK_DELAY: u32 = 60 * 24 * 22 * 365;
/// Set when revocation and recovery are controlled by whoever holds the
/// identity's token, rather than by the authorities below.
pub const FLAG_TOKENIZED_CONTROL: u32 = 0x4;

/// A VerusID as the chain stores it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Identity {
    /// Serialization version.
    pub version: u32,
    /// Status bits — see the `FLAG_*` constants.
    pub flags: u32,
    /// The addresses that may sign for this identity.
    pub primary_addresses: Vec<Destination>,
    /// How many of `primary_addresses` must sign. This is the identity's
    /// authority: `min_sigs` of `primary_addresses.len()`.
    pub min_sigs: u32,
    /// The parent identity's 20-byte id. Zero for a root identity.
    pub parent: [u8; 20],
    /// The name, without the parent qualification or the trailing `@`.
    pub name: String,
    /// Published content, keyed by VDXF id. Values are left as raw bytes:
    /// interpreting them needs the VDXF type system, which this crate does not
    /// implement, and guessing would be worse than handing them back untouched.
    pub content_multimap: Vec<([u8; 20], Vec<Vec<u8>>)>,
    /// The older single-valued content map: VDXF id to a 32-byte hash.
    pub content_map: Vec<([u8; 20], [u8; 32])>,
    /// The identity that may revoke this one.
    pub revocation_authority: [u8; 20],
    /// The identity that may recover this one after revocation.
    pub recovery_authority: [u8; 20],
    /// Sapling payment addresses published by the identity, 43 bytes each.
    #[cfg_attr(feature = "serde", serde(with = "sapling_addresses"))]
    pub private_addresses: Vec<[u8; 43]>,
    /// The system (chain) this identity lives on.
    pub system_id: [u8; 20],
    /// Block height before which a locked identity cannot be unlocked.
    pub unlock_after: u32,
}

/// How an identity's funds are timelocked.
///
/// # One field, two meanings
///
/// `unlock_after` on an [`Identity`] is **either an absolute height or a
/// relative delay**, and which one it is depends on [`FLAG_LOCKED`]. Writing the
/// wrong pairing produces an identity that looks locked and is not, or one that
/// unlocks 500 blocks after it was meant to. That is why this is a type rather
/// than two fields a caller sets by hand.
///
/// Both forms were taken from `setidentitytimelock` on VRSCTEST:
///
/// | request | flags | `timelock` |
/// |---|---|---|
/// | `{"unlockatblock": 1168230}` | `0` | `1168230` — an absolute height |
/// | `{"setunlockdelay": 100}` | `2` (`FLAG_LOCKED`) | `100` — a delay in blocks |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Timelock {
    /// No timelock. Funds are spendable now.
    None,
    /// Unlocks automatically once the chain passes this height.
    ///
    /// The countdown starts as soon as it is mined and cannot be paused. Note
    /// that [`FLAG_LOCKED`] is **clear** for this form — an identity with an
    /// absolute unlock height does not report itself as locked.
    UntilBlock(u32),
    /// Locked now; unlocks this many blocks after an unlock is *requested*.
    ///
    /// The delay does not start counting until then, so this locks the identity
    /// indefinitely until someone asks. Only revoke/recover can circumvent it.
    DelayAfterUnlock(u32),
}

impl Timelock {
    /// Read the timelock out of an identity.
    pub fn of(identity: &Identity) -> Self {
        if identity.flags & FLAG_LOCKED != 0 {
            Timelock::DelayAfterUnlock(identity.unlock_after)
        } else if identity.unlock_after != 0 {
            Timelock::UntilBlock(identity.unlock_after)
        } else {
            Timelock::None
        }
    }

    /// Write this timelock onto an identity, setting the flag to match.
    ///
    /// Leaves every other flag alone: an identity update restates the whole
    /// object, so clobbering the flags would silently un-revoke it or drop its
    /// tokenized control.
    pub fn apply_to(self, identity: &mut Identity) {
        match self {
            Timelock::None => {
                identity.flags &= !FLAG_LOCKED;
                identity.unlock_after = 0;
            }
            Timelock::UntilBlock(height) => {
                identity.flags &= !FLAG_LOCKED;
                identity.unlock_after = height;
            }
            Timelock::DelayAfterUnlock(blocks) => {
                identity.flags |= FLAG_LOCKED;
                identity.unlock_after = blocks;
            }
        }
    }

    /// Whether funds are spendable at `height`.
    ///
    /// A [`Timelock::DelayAfterUnlock`] is never spendable by this measure: the
    /// delay has not started, because no unlock has been requested. That is the
    /// honest answer — "when does this unlock" has no height until someone asks.
    pub fn spendable_at(self, height: u32) -> bool {
        match self {
            Timelock::None => true,
            Timelock::UntilBlock(unlock) => height >= unlock,
            Timelock::DelayAfterUnlock(_) => false,
        }
    }
}

impl Identity {
    /// The identity's timelock, with the flag and the field read together.
    pub fn timelock(&self) -> Timelock {
        Timelock::of(self)
    }

    /// Whether revocation and recovery are controlled by the identity's token
    /// rather than by its revocation and recovery authorities.
    ///
    /// When this is set the authority fields still exist and are still
    /// serialized, but consensus ignores them: whoever holds the token decides.
    /// A wallet that shows the recovery authority of a tokenized identity as
    /// "who can recover this" is showing something untrue.
    pub fn has_tokenized_control(&self) -> bool {
        self.flags & FLAG_TOKENIZED_CONTROL != 0
    }

    /// Whether the identity has been revoked.
    pub fn is_revoked(&self) -> bool {
        self.flags & FLAG_REVOKED != 0
    }

    /// Whether the identity is locked.
    pub fn is_locked(&self) -> bool {
        self.flags & FLAG_LOCKED != 0
    }

    /// Serialize the identity back to the bytes an output carries.
    ///
    /// Exactly inverts [`Identity::from_bytes`], which is what an update needs:
    /// an identity update restates the WHOLE object, so anything this drops or
    /// reorders is a silent change to the identity being published — including
    /// its authority.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TxError> {
        if self.version == 0 || self.version > IDENTITY_VERSION_PBAAS {
            return Err(malformed(&format!(
                "identity version {} is not one this crate encodes",
                self.version
            )));
        }
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        write_compact_size(&mut out, self.primary_addresses.len());
        for destination in &self.primary_addresses {
            write_var_slice(&mut out, &destination.to_push());
        }
        out.extend_from_slice(&self.min_sigs.to_le_bytes());

        out.extend_from_slice(&self.parent);
        write_var_slice(&mut out, self.name.as_bytes());

        if self.version >= IDENTITY_VERSION_PBAAS {
            write_compact_size(&mut out, self.content_multimap.len());
            for (key, values) in &self.content_multimap {
                out.extend_from_slice(key);
                write_compact_size(&mut out, values.len());
                for value in values {
                    write_var_slice(&mut out, value);
                }
            }
        } else if !self.content_multimap.is_empty() {
            // Encoding it anyway would produce bytes the chain reads as
            // something else entirely; dropping it would silently discard
            // published content.
            return Err(malformed(&format!(
                "version {} carries no content multimap, but {} entries were set",
                self.version,
                self.content_multimap.len()
            )));
        }

        write_compact_size(&mut out, self.content_map.len());
        for (key, value) in &self.content_map {
            out.extend_from_slice(key);
            out.extend_from_slice(value);
        }

        out.extend_from_slice(&self.revocation_authority);
        out.extend_from_slice(&self.recovery_authority);

        write_compact_size(&mut out, self.private_addresses.len());
        for address in &self.private_addresses {
            out.extend_from_slice(address);
        }

        if self.version >= IDENTITY_VERSION_VAULT {
            out.extend_from_slice(&self.system_id);
            out.extend_from_slice(&self.unlock_after.to_le_bytes());
        }
        Ok(out)
    }

    /// Parse an identity from the `vdata` payload of an `EVAL_IDENTITY_PRIMARY`
    /// output.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TxError> {
        let mut reader = Reader { bytes, offset: 0 };

        let version = reader.u32()?;
        if version == 0 || version > IDENTITY_VERSION_PBAAS {
            return Err(malformed(&format!(
                "identity version {version} is not one this crate decodes"
            )));
        }
        let flags = reader.u32()?;
        let count = reader.compact_size()?;
        let mut primary_addresses = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            primary_addresses.push(Destination::from_push(reader.var_slice()?)?);
        }
        let min_sigs = reader.u32()?;

        let parent = reader.array20()?;
        let name = String::from_utf8(reader.var_slice()?.to_vec())
            .map_err(|e| malformed(&format!("identity name is not UTF-8: {e}")))?;

        let mut content_multimap = Vec::new();
        if version >= IDENTITY_VERSION_PBAAS {
            let entries = reader.compact_size()?;
            for _ in 0..entries {
                let key = reader.array20()?;
                let values = reader.compact_size()?;
                let mut items = Vec::with_capacity(values.min(64));
                for _ in 0..values {
                    items.push(reader.var_slice()?.to_vec());
                }
                content_multimap.push((key, items));
            }
        }

        let entries = reader.compact_size()?;
        let mut content_map = Vec::with_capacity(entries.min(64));
        for _ in 0..entries {
            let key = reader.array20()?;
            let value: [u8; 32] = reader
                .take(32)?
                .try_into()
                .expect("Reader::take returns exactly the length asked for, or errors");
            content_map.push((key, value));
        }

        let revocation_authority = reader.array20()?;
        let recovery_authority = reader.array20()?;

        let count = reader.compact_size()?;
        let mut private_addresses = Vec::with_capacity(count.min(16));
        for _ in 0..count {
            private_addresses.push(
                reader
                    .take(43)?
                    .try_into()
                    .expect("Reader::take returns exactly the length asked for, or errors"),
            );
        }

        // Before the vault version there was no system id; the parent served as
        // one. Reproducing that here keeps the field meaningful for old
        // identities instead of leaving it zeroed.
        let (system_id, unlock_after) = if version >= IDENTITY_VERSION_VAULT {
            (reader.array20()?, reader.u32()?)
        } else {
            (parent, 0)
        };

        if reader.offset != bytes.len() {
            return Err(malformed(&format!(
                "{} trailing bytes after the identity",
                bytes.len() - reader.offset
            )));
        }

        Ok(Identity {
            version,
            flags,
            primary_addresses,
            min_sigs,
            parent,
            name,
            content_multimap,
            content_map,
            revocation_authority,
            recovery_authority,
            private_addresses,
            system_id,
            unlock_after,
        })
    }
}

fn malformed(detail: &str) -> TxError {
    TxError::MalformedIdentity(detail.to_string())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], TxError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| malformed("length overflows"))?;
        let slice = self.bytes.get(self.offset..end).ok_or_else(|| {
            malformed(&format!("wanted {count} bytes, {} left", self.remaining()))
        })?;
        self.offset = end;
        Ok(slice)
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn u32(&mut self) -> Result<u32, TxError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .expect("take(4) returns four bytes or errors"),
        ))
    }

    fn array20(&mut self) -> Result<[u8; 20], TxError> {
        Ok(self
            .take(20)?
            .try_into()
            .expect("take(20) returns twenty bytes or errors"))
    }

    /// CompactSize — the count encoding, NOT the `uint32` used for scalars.
    fn compact_size(&mut self) -> Result<usize, TxError> {
        let first = self.take(1)?[0];
        let value = match first {
            0..=0xfc => u64::from(first),
            0xfd => u64::from(u16::from_le_bytes(
                self.take(2)?
                    .try_into()
                    .expect("take(2) returns two bytes or errors"),
            )),
            0xfe => u64::from(u32::from_le_bytes(
                self.take(4)?
                    .try_into()
                    .expect("take(4) returns four bytes or errors"),
            )),
            _ => u64::from_le_bytes(
                self.take(8)?
                    .try_into()
                    .expect("take(8) returns eight bytes or errors"),
            ),
        };
        // A count can never exceed what is left to read, so a huge one is
        // corruption — and allocating for it first would be a denial of service.
        let value = usize::try_from(value).map_err(|_| malformed("count does not fit in usize"))?;
        if value > self.remaining() {
            return Err(malformed(&format!(
                "a count of {value} exceeds the {} bytes remaining",
                self.remaining()
            )));
        }
        Ok(value)
    }

    fn var_slice(&mut self) -> Result<&'a [u8], TxError> {
        let length = self.compact_size()?;
        self.take(length)
    }
}

/// CompactSize — matches [`Reader::compact_size`].
fn write_compact_size(out: &mut Vec<u8>, value: usize) {
    match value {
        0..=0xfc => out.push(u8::try_from(value).expect("the match arm bounds this to 0xfc")),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(
                &u16::try_from(value)
                    .expect("the match arm bounds this to 0xffff")
                    .to_le_bytes(),
            );
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(
                &u32::try_from(value)
                    .expect("the match arm bounds this to 0xffff_ffff")
                    .to_le_bytes(),
            );
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&(value as u64).to_le_bytes());
        }
    }
}

fn write_var_slice(out: &mut Vec<u8>, bytes: &[u8]) {
    write_compact_size(out, bytes.len());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::{Identity, Timelock, FLAG_LOCKED, FLAG_REVOKED, FLAG_TOKENIZED_CONTROL};

    fn blank() -> Identity {
        Identity {
            version: 3,
            flags: 0,
            primary_addresses: Vec::new(),
            min_sigs: 1,
            parent: [0; 20],
            name: "t".into(),
            content_multimap: Vec::new(),
            content_map: Vec::new(),
            revocation_authority: [0; 20],
            recovery_authority: [0; 20],
            private_addresses: Vec::new(),
            system_id: [0; 20],
            unlock_after: 0,
        }
    }

    /// The exact pairings `setidentitytimelock` produced on VRSCTEST.
    ///
    /// `{"unlockatblock": 1168230}` gave flags 0 and timelock 1168230;
    /// `{"setunlockdelay": 100}` gave flags 2 and timelock 100. The field is the
    /// same in both, which is precisely why the flag has to be read with it.
    #[test]
    fn the_two_timelock_forms_match_the_daemon() {
        let mut absolute = blank();
        Timelock::UntilBlock(1_168_230).apply_to(&mut absolute);
        assert_eq!(absolute.flags, 0);
        assert_eq!(absolute.unlock_after, 1_168_230);

        let mut delayed = blank();
        Timelock::DelayAfterUnlock(100).apply_to(&mut delayed);
        assert_eq!(delayed.flags, FLAG_LOCKED);
        assert_eq!(delayed.unlock_after, 100);
    }

    /// The same stored value reads as two different things. An identity with
    /// `unlock_after = 100` is either "unlocks at block 100" or "unlocks 100
    /// blocks after asked", and only the flag says which.
    #[test]
    fn the_same_field_means_different_things_under_the_flag() {
        let mut identity = blank();
        identity.unlock_after = 100;
        assert_eq!(Timelock::of(&identity), Timelock::UntilBlock(100));
        identity.flags |= FLAG_LOCKED;
        assert_eq!(Timelock::of(&identity), Timelock::DelayAfterUnlock(100));
    }

    #[test]
    fn a_timelock_round_trips_through_an_identity() {
        for timelock in [
            Timelock::None,
            Timelock::UntilBlock(1_168_230),
            Timelock::DelayAfterUnlock(100),
        ] {
            let mut identity = blank();
            timelock.apply_to(&mut identity);
            assert_eq!(Timelock::of(&identity), timelock);
        }
    }

    /// Applying a timelock must not disturb the other flags. An update restates
    /// the whole identity, so clobbering them would silently un-revoke it or
    /// drop its tokenized control.
    #[test]
    fn applying_a_timelock_leaves_other_flags_alone() {
        let mut identity = blank();
        identity.flags = FLAG_REVOKED | FLAG_TOKENIZED_CONTROL;
        Timelock::DelayAfterUnlock(50).apply_to(&mut identity);
        assert!(identity.is_revoked());
        assert!(identity.has_tokenized_control());
        assert!(identity.is_locked());

        Timelock::None.apply_to(&mut identity);
        assert!(identity.is_revoked(), "clearing the timelock un-revoked it");
        assert!(identity.has_tokenized_control());
        assert!(!identity.is_locked());
    }

    /// An absolute lock opens at its height. A delay never opens on its own,
    /// because the countdown has not started — reporting a height for it would
    /// be an invention.
    #[test]
    fn spendability_follows_the_form() {
        assert!(Timelock::None.spendable_at(0));
        assert!(!Timelock::UntilBlock(100).spendable_at(99));
        assert!(Timelock::UntilBlock(100).spendable_at(100));
        assert!(Timelock::UntilBlock(100).spendable_at(101));
        assert!(!Timelock::DelayAfterUnlock(1).spendable_at(u32::MAX));
    }

    /// An absolute timelock does NOT set FLAG_LOCKED, so `is_locked` is false
    /// for an identity whose funds are not yet spendable. Both are correct and
    /// they answer different questions.
    #[test]
    fn an_absolute_timelock_does_not_report_as_locked() {
        let mut identity = blank();
        Timelock::UntilBlock(1_000).apply_to(&mut identity);
        assert!(!identity.is_locked());
        assert!(!identity.timelock().spendable_at(999));
    }

    /// A timelock must survive the serialization an update publishes, or the
    /// lock is silently dropped by the very transaction meant to set it.
    #[test]
    fn a_timelock_survives_serialization() {
        for timelock in [
            Timelock::None,
            Timelock::UntilBlock(1_168_230),
            Timelock::DelayAfterUnlock(100),
        ] {
            let mut identity = blank();
            identity.primary_addresses =
                vec![verus_tx_primitives::cc::Destination::PubKeyHash([7; 20])];
            timelock.apply_to(&mut identity);
            let bytes = identity.to_bytes().expect("serialize");
            let read = Identity::from_bytes(&bytes).expect("parse");
            assert_eq!(read.timelock(), timelock);
            assert_eq!(read.flags, identity.flags);
        }
    }

    /// Tokenized control is read from the flag, and the authority fields stay
    /// populated even though consensus ignores them.
    #[test]
    fn tokenized_control_is_visible_and_does_not_erase_the_authorities() {
        let mut identity = blank();
        identity.revocation_authority = [0x11; 20];
        assert!(!identity.has_tokenized_control());
        identity.flags |= FLAG_TOKENIZED_CONTROL;
        assert!(identity.has_tokenized_control());
        assert_eq!(identity.revocation_authority, [0x11; 20]);
    }
}
