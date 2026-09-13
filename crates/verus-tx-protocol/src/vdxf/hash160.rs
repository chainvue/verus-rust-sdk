//! A 20-byte hash inside a VDXF object, and the one bit that decides how it is
//! written.
//!
//! Ported from `Hash160` in the TypeScript SDK (`src/vdxf/classes/Hash160.ts`).
//! The type exists because the same twenty bytes appear on the wire in two
//! different shapes, and nothing in the bytes themselves says which:
//!
//! ```text
//! varlength = false    <20 bytes>                 raw, length implied
//! varlength = true     compactSize(20) <20 bytes> length prefixed
//! ```
//!
//! A reader therefore has to be *told* which shape to expect, which is why
//! [`Hash160::deserialize`] takes `varlength` as an argument rather than
//! discovering it. Getting it wrong does not fail at the hash — it fails
//! several fields later, on an i-address read out of the middle of something
//! else.
//!
//! # `empty()` is a zero-length varlength hash, not twenty zero bytes
//!
//! This is the trap, and it is worth stating on its own because both spellings
//! are "an absent hash" to a reader and they are different bytes:
//!
//! ```text
//! Hash160::empty()               varlength, 0 bytes   -> 00
//! Hash160::of([0u8; 20], false)  raw, 20 zero bytes   -> 0000…00  (20 bytes)
//! ```
//!
//! `Hash160.getEmpty()` upstream is `new Hash160(Buffer.alloc(0), 0, true)` —
//! an empty buffer with `varlength` set — so it serializes to the single byte
//! `0x00`. Upstream's *default* constructor argument is `Buffer.alloc(20)` with
//! `varlength` false, which is the twenty-zero-byte form. An optional field
//! written as the wrong one of those is twenty bytes of desync in everything
//! that follows it.

use verus_keys::{Address, AddressKind};
use verus_tx_primitives::TxError;
use verus_wire::compact::write_var_slice;

use crate::decode::read_compact_size;

/// What `I_ADDR_VERSION` is upstream: the base58check version byte of an `i`
/// address.
///
/// Carried rather than assumed because [`Hash160::from_address`] keeps whatever
/// version the address it parsed had, exactly as upstream's `fromAddress` does.
const I_ADDR_VERSION: u8 = 102;

fn bad(detail: &str) -> TxError {
    TxError::MalformedVdxfObject(detail.to_string())
}

/// A hash inside a VDXF object: twenty bytes, or nothing, plus how to write it.
///
/// See the module docs for the `varlength` distinction and for why
/// [`Hash160::empty`] is not twenty zero bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hash160 {
    /// Zero or twenty bytes. The length is an invariant of this type rather
    /// than of upstream's, which accepts any buffer — see
    /// [`Hash160::deserialize`].
    hash: Vec<u8>,
    /// The base58check version byte the hash renders under. **Not serialized**
    /// — it exists so [`Hash160::to_address`] can say what the hash names.
    version: u8,
    /// Whether [`Hash160::serialize`] writes a CompactSize length first.
    varlength: bool,
}

impl Hash160 {
    /// Twenty bytes, to be written in the shape `varlength` selects.
    ///
    /// The version is an `i` address, which is what upstream's constructor
    /// defaults to and what every hash in a VDXF object names: an identity, a
    /// currency, or a VDXF key.
    pub fn of(hash: [u8; 20], varlength: bool) -> Self {
        Self {
            hash: hash.to_vec(),
            version: I_ADDR_VERSION,
            varlength,
        }
    }

    /// The absent hash: **zero length, varlength**, which serializes to the
    /// single byte `0x00`.
    ///
    /// `Hash160.getEmpty()`. Read the module docs before reaching for
    /// `Hash160::of([0u8; 20], _)` instead — they are not the same bytes, and
    /// this is the one an optional field is written as.
    pub fn empty() -> Self {
        Self {
            hash: Vec::new(),
            // Upstream passes 0 here rather than I_ADDR_VERSION, and it is
            // observable: `toAddress()` is null for an empty hash either way,
            // but the version survives into `toJson`.
            version: 0,
            varlength: true,
        }
    }

    /// The hash an `i`, `R` or script address carries.
    ///
    /// Keeps the address's own version byte, so `to_address` round-trips the
    /// spelling that went in rather than rewriting an `R` address as an `i`
    /// address.
    ///
    /// # Errors
    ///
    /// The address must be valid base58check with a version Verus uses.
    pub fn from_address(address: &str, varlength: bool) -> Result<Self, TxError> {
        let parsed: Address = address.parse()?;
        Ok(Self {
            hash: parsed.hash().to_vec(),
            version: parsed.kind().version(),
            varlength,
        })
    }

    /// The bytes, which are empty for [`Hash160::empty`] and twenty long
    /// otherwise.
    pub fn hash(&self) -> &[u8] {
        &self.hash
    }

    /// The base58check version byte this hash renders under. Zero for
    /// [`Hash160::empty`].
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Whether [`Hash160::serialize`] length-prefixes the hash.
    pub fn is_varlength(&self) -> bool {
        self.varlength
    }

    /// The address this names, or `None` when there is nothing to name.
    ///
    /// `None` for [`Hash160::empty`] — upstream's `toAddress()` returns `null`
    /// for a zero-length hash — and also for a version byte Verus does not use,
    /// which only [`Hash160::deserialize`] can produce and only by reading the
    /// wrong shape.
    pub fn to_address(&self) -> Option<Address> {
        let hash: [u8; 20] = self.hash.as_slice().try_into().ok()?;
        Some(Address::new(
            AddressKind::from_version(self.version).ok()?,
            hash,
        ))
    }

    /// How many bytes [`Hash160::serialize`] writes.
    ///
    /// `getByteLength()`. One more than the hash when varlength, because a
    /// CompactSize below `0xfd` is a single byte and these are never longer
    /// than twenty.
    pub fn byte_length(&self) -> usize {
        if self.varlength {
            // write_compact_size writes one byte for any length <= 0xfc.
            1 + self.hash.len()
        } else {
            self.hash.len()
        }
    }

    /// The bytes this hash occupies in a VDXF object.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.byte_length());
        if self.varlength {
            write_var_slice(&mut out, &self.hash);
        } else {
            out.extend_from_slice(&self.hash);
        }
        out
    }

    /// Read a hash back, advancing `offset`.
    ///
    /// `varlength` must match what the writer used; nothing in the bytes says
    /// which, so the caller's field layout decides. See the module docs.
    ///
    /// # Errors
    ///
    /// Refuses a buffer that ends early, and — unlike upstream, which accepts
    /// any length a varslice declares — refuses a varlength hash that is
    /// neither empty nor twenty bytes. Upstream only ever *writes* those two,
    /// so no payload it produces is affected; a third length is input nothing
    /// wrote, and carrying it forward would hand a caller a "hash160" that is
    /// not one.
    pub fn deserialize(bytes: &[u8], offset: &mut usize, varlength: bool) -> Result<Self, TxError> {
        let hash = if varlength {
            let length = read_compact_size(bytes, offset)?;
            let length = usize::try_from(length)
                .ok()
                .filter(|length| *length == 0 || *length == 20)
                .ok_or_else(|| {
                    bad(&format!(
                        "a varlength hash160 declares {length} bytes, not 0 or 20"
                    ))
                })?;
            let taken = bytes
                .get(*offset..*offset + length)
                .ok_or_else(|| bad("a varlength hash160 ended before its bytes"))?;
            *offset += length;
            taken.to_vec()
        } else {
            let taken = bytes
                .get(*offset..*offset + 20)
                .ok_or_else(|| bad("a hash160 ended before its twenty bytes"))?;
            *offset += 20;
            taken.to_vec()
        };
        Ok(Self {
            hash,
            // Upstream's `fromBuffer` hardcodes I_ADDR_VERSION, so a read-back
            // hash claims to be an i-address whatever was written — including
            // for the empty hash, whose version went out as 0. Ported rather
            // than corrected: `version` is not on the wire, so inventing a
            // different answer here would diverge from upstream's `toJson`
            // without any byte to justify it.
            version: I_ADDR_VERSION,
            varlength,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `sdk-ref-check@`'s system id on VRSCTEST — the same twenty bytes the
    /// real invoice in [`crate::base64url`] ends with, so this is a hash that
    /// appears on the wire rather than one invented here.
    const SYSTEM_ID: &str = "a6ef9ea235635e328124ff3429db9f9e91b64e2d";

    fn system_id() -> [u8; 20] {
        hex::decode(SYSTEM_ID)
            .expect("a literal this file controls")
            .try_into()
            .expect("twenty bytes")
    }

    /// The distinction the type exists for: the same twenty bytes, two lengths.
    #[test]
    fn varlength_prefixes_and_raw_does_not() {
        let raw = Hash160::of(system_id(), false);
        let varlength = Hash160::of(system_id(), true);

        assert_eq!(raw.serialize(), system_id().to_vec());
        assert_eq!(raw.byte_length(), 20);

        let mut expected = vec![0x14];
        expected.extend_from_slice(&system_id());
        assert_eq!(varlength.serialize(), expected);
        assert_eq!(varlength.byte_length(), 21);

        // Stated as the property that matters rather than as two lengths: the
        // prefix is the difference, and it is one byte because twenty is below
        // the CompactSize escape.
        assert_eq!(varlength.byte_length(), raw.byte_length() + 1);
    }

    /// The easy silent bug: `empty()` is one zero byte, not twenty.
    #[test]
    fn empty_is_a_zero_length_varlength_hash_not_twenty_zero_bytes() {
        let empty = Hash160::empty();
        assert_eq!(empty.serialize(), vec![0x00]);
        assert_eq!(empty.byte_length(), 1);
        assert!(empty.is_varlength());
        assert!(empty.hash().is_empty());
        assert_eq!(empty.version(), 0);
        assert!(empty.to_address().is_none(), "nothing to name");

        // What it is NOT. Both of these are "an absent hash" to a reader and
        // neither is the one an optional VDXF field is written as.
        let twenty_zeros = Hash160::of([0u8; 20], false);
        assert_eq!(twenty_zeros.serialize(), vec![0u8; 20]);
        assert_ne!(empty.serialize(), twenty_zeros.serialize());

        let twenty_zeros_prefixed = Hash160::of([0u8; 20], true);
        assert_eq!(twenty_zeros_prefixed.serialize().len(), 21);
        assert_ne!(empty.serialize(), twenty_zeros_prefixed.serialize());
    }

    /// An address's own version survives, so an `R` address is not rewritten as
    /// an `i` address on the way in.
    #[test]
    fn from_address_keeps_the_version_it_parsed() {
        let identity = Hash160::from_address("iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq", false).unwrap();
        assert_eq!(identity.version(), 102);
        assert_eq!(
            identity.to_address().unwrap().to_string(),
            "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq"
        );

        let key_hash = Hash160::from_address("RJGYC29RTSGQbWMrstQziJxfQaiDCjm5iP", true).unwrap();
        assert_eq!(key_hash.version(), 60);
        assert_eq!(
            key_hash.to_address().unwrap().to_string(),
            "RJGYC29RTSGQbWMrstQziJxfQaiDCjm5iP"
        );
        // The same hash, written two ways, because varlength is orthogonal to
        // what the hash names.
        assert_eq!(key_hash.serialize().len(), 21);
    }

    #[test]
    fn refuses_an_address_that_is_not_one() {
        assert!(Hash160::from_address("", false).is_err());
        assert!(Hash160::from_address("not-an-address", false).is_err());
        // Valid base58check, wrong payload length.
        assert!(Hash160::from_address("iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2y", false).is_err());
    }

    #[test]
    fn both_shapes_round_trip_when_the_reader_is_told_which() {
        for varlength in [false, true] {
            let written = Hash160::of(system_id(), varlength);
            let bytes = written.serialize();
            let mut offset = 0;
            let read = Hash160::deserialize(&bytes, &mut offset, varlength).unwrap();
            assert_eq!(offset, bytes.len(), "varlength={varlength}");
            assert_eq!(read, written, "varlength={varlength}");
        }
    }

    /// The empty hash round-trips as *an empty varlength hash*, but its version
    /// does not survive — upstream's reader hardcodes the i-address version.
    /// Pinned so the divergence is a decision rather than a surprise.
    #[test]
    fn reading_back_always_claims_the_i_address_version() {
        let bytes = Hash160::empty().serialize();
        let mut offset = 0;
        let read = Hash160::deserialize(&bytes, &mut offset, true).unwrap();
        assert_eq!(offset, 1);
        assert!(read.hash().is_empty());
        assert!(read.is_varlength());
        assert_eq!(read.version(), 102, "upstream writes 0 and reads 102");
        assert_ne!(read, Hash160::empty(), "which is exactly the asymmetry");
    }

    /// Reading the wrong shape is the failure this type exists to make
    /// explicit: twenty raw bytes read as varlength consumes the first byte as
    /// a length.
    #[test]
    fn the_wrong_shape_reads_the_wrong_thing() {
        let raw = Hash160::of(system_id(), false).serialize();
        let mut offset = 0;
        // 0xa6 is 166, which is neither 0 nor 20, so this is caught rather
        // than silently producing a 166-byte "hash".
        assert!(Hash160::deserialize(&raw, &mut offset, true).is_err());
    }

    #[test]
    fn refuses_truncated_and_impossible_lengths() {
        let mut offset = 0;
        assert!(Hash160::deserialize(&[], &mut offset, false).is_err());
        let mut offset = 0;
        assert!(Hash160::deserialize(&[0u8; 19], &mut offset, false).is_err());
        // A varlength hash that declares twenty and supplies nineteen.
        let mut bytes = vec![0x14];
        bytes.extend_from_slice(&[0u8; 19]);
        let mut offset = 0;
        assert!(Hash160::deserialize(&bytes, &mut offset, true).is_err());
        // A length upstream never writes.
        let mut offset = 0;
        assert!(Hash160::deserialize(&[0x07, 1, 2, 3, 4, 5, 6, 7], &mut offset, true).is_err());
    }

    /// A hash does not have to start at zero, and the offset is advanced by
    /// exactly what was read.
    #[test]
    fn reads_from_an_offset_inside_a_larger_buffer() {
        let mut bytes = vec![0xde, 0xad];
        bytes.extend_from_slice(&Hash160::of(system_id(), true).serialize());
        bytes.push(0xbe);
        let mut offset = 2;
        let read = Hash160::deserialize(&bytes, &mut offset, true).unwrap();
        assert_eq!(read.hash(), system_id());
        assert_eq!(offset, bytes.len() - 1, "the trailing byte is left alone");
    }
}
