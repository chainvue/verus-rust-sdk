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

use crate::cc::Destination;
use crate::error::TxError;

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

/// `EVAL_IDENTITY_PRIMARY` — the output that holds a VerusID.
pub const EVAL_IDENTITY_PRIMARY: u8 = 14;
/// `EVAL_IDENTITY_REVOKE` — the condition letting the revocation authority spend.
pub const EVAL_IDENTITY_REVOKE: u8 = 15;
/// `EVAL_IDENTITY_RECOVER` — the condition letting the recovery authority spend.
pub const EVAL_IDENTITY_RECOVER: u8 = 16;

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

impl Identity {
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
                .expect("take returned the requested length");
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
                    .expect("take returned the requested length"),
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
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }

    fn array20(&mut self) -> Result<[u8; 20], TxError> {
        Ok(self.take(20)?.try_into().expect("twenty bytes"))
    }

    /// CompactSize — the count encoding, NOT the `uint32` used for scalars.
    fn compact_size(&mut self) -> Result<usize, TxError> {
        let first = self.take(1)?[0];
        let value = match first {
            0..=0xfc => u64::from(first),
            0xfd => u64::from(u16::from_le_bytes(
                self.take(2)?.try_into().expect("two bytes"),
            )),
            0xfe => u64::from(u32::from_le_bytes(
                self.take(4)?.try_into().expect("four bytes"),
            )),
            _ => u64::from_le_bytes(self.take(8)?.try_into().expect("eight bytes")),
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
        0..=0xfc => out.push(u8::try_from(value).expect("checked above")),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&u16::try_from(value).expect("checked above").to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&u32::try_from(value).expect("checked above").to_le_bytes());
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
