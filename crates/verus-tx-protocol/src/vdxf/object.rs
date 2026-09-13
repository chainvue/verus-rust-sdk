//! The three-part frame every VDXF object is wrapped in.
//!
//! Ported from `VDXFObject` in the TypeScript SDK (`src/vdxf/index.ts:40`).
//! Every structured thing a wallet and an application exchange — a VerusPay
//! invoice, a login-consent request, a challenge, a response — is one of these
//! with a different payload inside, and they all share the same outer bytes:
//!
//! ```text
//! key_hash160 (20 bytes, present iff include_key)
//! varint(version)
//! compactSize(data.len())      -- always, even when data is empty
//! data
//! ```
//!
//! The key is the [`crate::vdxf::keys`] constant that says *what* the payload
//! is; the version is the payload's own version, not a version of this frame.
//! That the frame is uniform is the reason it is worth a type: the subclasses
//! differ only in how they read and write `data`, so the part that is easy to
//! get wrong is written and tested once.
//!
//! # `if (dataLength)` does not mean what it reads like
//!
//! Upstream's `toBuffer` guards the length prefix with `if (dataLength)`, which
//! reads as "an empty payload emits no `compactSize(0)`, not even a zero byte".
//! It does not mean that. This module said it did, and was wrong on the wire by
//! one byte for every empty-payload object; the correction is worth spelling out
//! because the `if` is right there in `index.ts` inviting the same mistake
//! again. Three lines have to be held together, not one
//! (`src/vdxf/index.ts:99-125`):
//!
//! ```text
//! byteLength()   counts varuint.encodingLength(dataLength) unconditionally,
//!                and that is 1 even when dataLength is 0
//!
//! toBuffer()     allocates Buffer.alloc(byteLength()) -- zero-filled, and
//!                therefore one byte longer than what it is about to write
//!                skips the writeVarSlice when dataLength is 0
//!                returns writer.buffer -- the WHOLE allocation, not a slice
//!                of it up to the writer's position
//! ```
//!
//! The counted prefix and the skipped write cancel. The byte is allocated,
//! nothing overwrites it, and it is still returned. A `compactSize(0)` is `0x00`
//! and an untouched byte of `Buffer.alloc` is `0x00`, so the frame upstream puts
//! on the wire is byte-identical to one that wrote the prefix. An empty-payload
//! object is twenty-two bytes with its key and two without it, ending in that
//! `0x00` — captured from the pinned library by the test
//! `an_empty_payload_still_carries_its_length_prefix`, which holds the hex.
//!
//! So this port writes the prefix unconditionally. That is one branch *fewer*
//! than transcribing the `if` would be, and it is the faithful choice rather
//! than a tidied one: transcribing the `if` alone reproduces half of a pair of
//! behaviours that only agree with the format together.
//!
//! # One quirk, ported literally: `offset < buffer.length - 1`
//!
//! Upstream's `fromBuffer` reads the payload only if that holds, comparing the
//! offset it was *given* against one less than the whole buffer's length. It
//! reads like an off-by-one and behaves like one: an object sitting at a
//! non-zero offset inside a larger buffer is judged by where it starts rather
//! than by what is left after it. It is transcribed literally and pinned by
//! `the_guard_uses_the_offset_it_was_called_with`.
//!
//! Its false branch is unreachable from anything a writer emits, and that is a
//! consequence of the section above rather than a separate fact: because the
//! prefix is always there, the shortest object any writer produces is two bytes,
//! and `called_at < len - 1` holds for every one of them. Reaching the other
//! side needs a buffer that ends one byte after the version, which this crate
//! and upstream both decline to write.
//!
//! Neither an empty payload nor the guard's false branch occurs on the VerusPay
//! or login-consent paths, where every object has a payload. Both are documented
//! at this length anyway, because the first reading of the `if` was wrong and
//! the next reader should not have to re-derive it from the TypeScript.

use verus_keys::{Address, AddressKind};
use verus_tx_primitives::cc::var_int;
use verus_tx_primitives::TxError;
use verus_wire::compact::write_var_slice;

use crate::base64url;
use crate::decode::{read_compact_size, read_var_int};

fn bad(detail: &str) -> TxError {
    TxError::MalformedVdxfObject(detail.to_string())
}

/// How many bytes `write_compact_size` writes for `n`, without writing them.
///
/// A second copy of `verus_wire`'s size classes, which is a thing to keep in
/// step — so `compact_size_length_agrees_with_the_writer` asserts the two at
/// every boundary rather than trusting that they do. The alternative was a
/// throwaway `Vec` per [`VdxfObject::byte_length`] call, and that function is
/// called once to size the buffer in every [`VdxfObject::serialize`].
fn compact_size_length(n: u64) -> usize {
    // The branches are in the order `verus_wire::compact::write_compact_size`
    // writes them, so the two read as the same function.
    if n < 0xfd {
        1
    } else if n <= 0xffff {
        3
    } else if n <= 0xffff_ffff {
        5
    } else {
        9
    }
}

/// `VDXF_OBJECT_DEFAULT_VERSION`: what upstream's constructor sets when the
/// caller names no version.
///
/// Individual payloads override it — the VerusPay invoice in this module's tests
/// is version 4 — so this is a default, not a constraint, and
/// [`VdxfObject::deserialize`] accepts any version the VARINT can hold. A
/// payload type that cares about its own versions checks them itself, which is
/// what upstream's `isValidVersion` hook is for.
pub const DEFAULT_VERSION: u64 = 1;

/// A VDXF object: a key saying what this is, a version, and an opaque payload.
///
/// `data` is bytes on purpose. This type is the *frame*; the payload structures
/// that go inside it are separate work, and keeping them out means the frame can
/// be proven against a real invoice without first being able to parse one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VdxfObject {
    key: [u8; 20],
    version: u64,
    data: Vec<u8>,
}

impl VdxfObject {
    /// A VDXF object with `data` as its payload.
    ///
    /// `key` is the twenty bytes a [`crate::vdxf::keys`] constant holds, or
    /// whatever [`crate::vdxf::data_key`] derived — the wire order, which is the
    /// *reverse* of the `hash160result` upstream's `keys.ts` prints. See
    /// [`crate::vdxf::keys`].
    pub fn new(key: [u8; 20], version: u64, data: Vec<u8>) -> Self {
        Self { key, version, data }
    }

    /// The twenty bytes naming what this object is, in wire order.
    pub fn key(&self) -> [u8; 20] {
        self.key
    }

    /// The key as the `i` address upstream calls a `vdxfid`.
    pub fn key_address(&self) -> Address {
        Address::new(AddressKind::Identity, self.key)
    }

    /// The payload's version.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The payload, undecoded.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// How many bytes [`VdxfObject::serialize`] writes.
    ///
    /// `byteLength()`. The CompactSize is always counted, an empty payload
    /// included, which is what upstream's `varuint.encodingLength(0)` gives —
    /// and the `if (dataLength)` in `toBuffer` does not take it back off again.
    /// See this module's docs for why.
    pub fn byte_length(&self, include_key: bool) -> usize {
        let key_length = if include_key { self.key.len() } else { 0 };
        let version_length = var_int(self.version).len();
        let data_prefix = compact_size_length(self.data.len() as u64);
        key_length + version_length + data_prefix + self.data.len()
    }

    /// The bytes this object travels as.
    ///
    /// `include_key` is upstream's `serializekey`: a nested object whose key the
    /// enclosing structure already wrote omits it, and a top-level one carries
    /// it. Getting it wrong shifts everything after it by twenty bytes.
    pub fn serialize(&self, include_key: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.byte_length(include_key));
        if include_key {
            out.extend_from_slice(&self.key);
        }
        out.extend_from_slice(&var_int(self.version));
        // Unconditional, an empty payload included. Upstream skips this write
        // when there is no data but counts the prefix in `byteLength` and
        // returns the whole zero-filled allocation, so the `0x00` is on the wire
        // either way. Module docs have the captured bytes.
        write_var_slice(&mut out, &self.data);
        out
    }

    /// The string a deeplink or a QR code carries: [`serialize`] through
    /// [`crate::base64url`].
    ///
    /// `VDXFObject.toString()`.
    ///
    /// [`serialize`]: VdxfObject::serialize
    pub fn to_base64url(&self, include_key: bool) -> String {
        base64url::encode(&self.serialize(include_key))
    }

    /// Read an object back, advancing `offset`.
    ///
    /// `key` mirrors upstream's optional third argument: `None` reads the
    /// twenty-byte key from the buffer, and `Some(key)` takes it from the caller
    /// because the enclosing structure already consumed it. Pass the wrong one
    /// and the version is read out of the middle of a hash.
    ///
    /// # Errors
    ///
    /// Refuses a buffer that ends before any of the three parts, a VARINT that
    /// overflows `u64`, a non-canonical CompactSize, and a declared payload
    /// length longer than what remains — nothing is allocated on a declared
    /// count.
    ///
    /// # The guard
    ///
    /// The payload is read only when the offset this was *called with* is below
    /// `bytes.len() - 1` — the offset it was handed, not the reader's position
    /// after the version. That is what upstream does, and the two differ for any
    /// object that does not start at zero.
    ///
    /// Every buffer a writer emits satisfies it, because the length prefix is
    /// always present and so the shortest object is two bytes. An empty payload
    /// therefore round-trips in both `include_key` settings, matching upstream:
    /// the trailing `0x00` is read as the `compactSize(0)` it is
    /// indistinguishable from, and the object re-serializes to the bytes it came
    /// from. The guard does not break that round trip; it only decides whether
    /// that byte is read as a length at all, and for these buffers it is.
    pub fn deserialize(
        bytes: &[u8],
        offset: &mut usize,
        key: Option<[u8; 20]>,
    ) -> Result<Self, TxError> {
        // Upstream compares the offset it was handed, not the reader's current
        // position, so this has to be captured before anything moves.
        let called_at = *offset;

        let key = match key {
            Some(key) => key,
            None => {
                let raw = bytes
                    .get(*offset..*offset + 20)
                    .ok_or_else(|| bad("a VDXF object ended before its key"))?;
                *offset += 20;
                raw.try_into().expect("the range above asked for 20 bytes")
            }
        };

        let version = read_var_int(bytes, offset)?;

        let data = if called_at < bytes.len().saturating_sub(1) {
            let length = read_compact_size(bytes, offset)?;
            let length = usize::try_from(length)
                .ok()
                .filter(|length| *length <= bytes.len().saturating_sub(*offset))
                .ok_or_else(|| {
                    bad(&format!(
                        "a VDXF object declares {length} bytes of data with {} left",
                        bytes.len().saturating_sub(*offset)
                    ))
                })?;
            let raw = bytes
                .get(*offset..*offset + length)
                .ok_or_else(|| bad("a VDXF object ended before its data"))?;
            *offset += length;
            raw.to_vec()
        } else {
            Vec::new()
        };

        Ok(Self { key, version, data })
    }

    /// Read an object from the text a deeplink or a QR code carries.
    ///
    /// # Errors
    ///
    /// Everything [`VdxfObject::deserialize`] and [`crate::base64url::decode`]
    /// refuse, plus trailing bytes: a deeplink is the whole object and nothing
    /// else, so bytes left over mean this is not the payload it claims to be.
    pub fn from_base64url(text: &str, key: Option<[u8; 20]>) -> Result<Self, TxError> {
        let bytes = base64url::decode(text)?;
        let mut offset = 0;
        let object = Self::deserialize(&bytes, &mut offset, key)?;
        if offset != bytes.len() {
            return Err(bad(&format!(
                "{} trailing bytes after a VDXF object",
                bytes.len() - offset
            )));
        }
        Ok(object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vdxf::keys::VERUSPAY_INVOICE_VDXF_KEY;
    use verus_wire::compact::write_compact_size;

    /// A real VerusPay invoice, as a QR code carries it.
    ///
    /// Produced by the TypeScript SDK, not by this module. It is the anchor for
    /// everything below: the frame has to read it, and has to write it back
    /// byte for byte.
    const INVOICE_QR: &str = "dgCq8t3nk3reqeFQANTiwij8jmIENAH_AOQLVAIAAAACFAAtMxHDi_0hkJLSrvRJgEvos77-pu-eojVjXjKBJP80KdufnpG2Ti0";

    /// The invoice's payload: the 52 bytes inside the frame.
    ///
    /// Opaque here on purpose — reading it is `VerusPayInvoiceDetails`, which is
    /// a separate piece of work. What this file has to establish is that the
    /// frame hands those 52 bytes over unchanged.
    const INVOICE_DATA: &str = "01ff00e40b54020000000214002d3311c38bfd219092d2aef449804be8b3befe\
                                a6ef9ea235635e328124ff3429db9f9e91b64e2d";

    fn invoice_data() -> Vec<u8> {
        hex::decode(INVOICE_DATA).expect("a literal this file controls")
    }

    /// The length prefix in the real invoice, read off the wire rather than
    /// computed here: `0x34` is 52, which is what the data is.
    #[test]
    fn the_real_invoices_length_prefix_is_its_data_length() {
        let bytes = base64url::decode(INVOICE_QR).unwrap();
        assert_eq!(bytes.len(), 74, "20 key + 1 version + 1 length + 52 data");
        assert_eq!(bytes[20], 0x04, "varint(4) — the invoice's own version");
        assert_eq!(bytes[21], 0x34, "compactSize(52)");
        assert_eq!(usize::from(bytes[21]), invoice_data().len());
        assert_eq!(&bytes[22..], invoice_data().as_slice());
    }

    #[test]
    fn reads_a_real_invoice_frame() {
        let invoice = VdxfObject::from_base64url(INVOICE_QR, None).unwrap();

        assert_eq!(invoice.key(), VERUSPAY_INVOICE_VDXF_KEY);
        assert_eq!(
            invoice.key_address().to_string(),
            "iEETy7La3FTN2Sd2hNRgepek5S8x8eeUeQ",
            "the vdxfid upstream's keys.ts gives for veruspay.vrsc::invoice"
        );
        assert_eq!(invoice.version(), 4);
        assert_eq!(invoice.data(), invoice_data().as_slice());
    }

    /// The round trip that makes this a port rather than a guess: the bytes out
    /// are the bytes in, including the string form.
    #[test]
    fn writes_the_real_invoice_back_byte_for_byte() {
        let invoice = VdxfObject::from_base64url(INVOICE_QR, None).unwrap();
        assert_eq!(invoice.to_base64url(true), INVOICE_QR);
        assert_eq!(
            invoice.serialize(true),
            base64url::decode(INVOICE_QR).unwrap()
        );
        assert_eq!(invoice.byte_length(true), 74);
    }

    /// Rebuilt from its parts rather than read, so the writer is checked
    /// independently of the reader.
    #[test]
    fn builds_the_real_invoice_from_its_parts() {
        let invoice = VdxfObject::new(VERUSPAY_INVOICE_VDXF_KEY, 4, invoice_data());
        assert_eq!(invoice.to_base64url(true), INVOICE_QR);
    }

    /// `include_key` is twenty bytes, and the key has to come back from the
    /// caller when it was not written.
    #[test]
    fn omitting_the_key_omits_exactly_twenty_bytes() {
        let invoice = VdxfObject::new(VERUSPAY_INVOICE_VDXF_KEY, 4, invoice_data());
        let with = invoice.serialize(true);
        let without = invoice.serialize(false);
        assert_eq!(with.len(), without.len() + 20);
        assert_eq!(&with[20..], without.as_slice());
        assert_eq!(invoice.byte_length(false), without.len());

        let mut offset = 0;
        let read = VdxfObject::deserialize(&without, &mut offset, Some(VERUSPAY_INVOICE_VDXF_KEY))
            .unwrap();
        assert_eq!(read, invoice);
        assert_eq!(offset, without.len());

        // Reading a keyless buffer as if it carried one takes the version out
        // of the middle of the payload. It does not have to fail; it has to
        // not be mistaken for success, which is why the caller decides.
        let mut offset = 0;
        let misread = VdxfObject::deserialize(&without, &mut offset, None);
        assert!(misread.is_err() || misread.unwrap() != invoice);
    }

    /// The `if (dataLength)` guard does *not* drop the length prefix.
    ///
    /// `byteLength` counts it, `toBuffer` allocates that many zero bytes and
    /// returns all of them, so skipping the write leaves a `0x00` exactly where
    /// the `compactSize(0)` would have gone. See this module's docs.
    ///
    /// The hex is upstream's, not this module's. Captured by running the pinned
    /// `verus-typescript-primitives` — `4243cd075b4f68df1ce72fd2fd9c9b18ac36767e`,
    /// the revision `fixtures/vdxf` pins — on an empty-payload object keyed with
    /// `veruspay.vrsc::invoice`:
    ///
    /// ```text
    /// const v = require('./dist/vdxf/index.js');
    /// const e = new v.BufferDataVdxfObject('', 'iEETy7La3FTN2Sd2hNRgepek5S8x8eeUeQ');
    /// // byteLength / toBuffer().length / toBuffer().toString('hex')
    /// includeKey=true   byteLength=22  actual=22  7600aaf2dde7937adea9e15000d4e2c228fc8e620100
    /// includeKey=false  byteLength=2   actual=2   0100
    /// ```
    ///
    /// `BufferDataVdxfObject` rather than the base `VDXFObject` because its
    /// `fromDataBuffer` reads a varslice, which is what this crate's
    /// [`VdxfObject::deserialize`] does; the base class's is a no-op that reads
    /// nothing, so it would not be the comparable reader. Both share `toBuffer`
    /// and `byteLength`, so the bytes above are the frame's and not the
    /// subclass's.
    #[test]
    fn an_empty_payload_still_carries_its_length_prefix() {
        const UPSTREAM_KEYED: &str = "7600aaf2dde7937adea9e15000d4e2c228fc8e620100";
        const UPSTREAM_KEYLESS: &str = "0100";

        let empty = VdxfObject::new(VERUSPAY_INVOICE_VDXF_KEY, DEFAULT_VERSION, Vec::new());

        let keyed = empty.serialize(true);
        assert_eq!(hex::encode(&keyed), UPSTREAM_KEYED);
        assert_eq!(keyed.len(), 22, "20 key + 1 version + 1 compactSize(0)");
        assert_eq!(&keyed[..20], &VERUSPAY_INVOICE_VDXF_KEY);
        assert_eq!(keyed[20], 0x01, "varint(DEFAULT_VERSION)");
        assert_eq!(
            keyed[21], 0x00,
            "compactSize(0) — the byte upstream allocates and declines to write"
        );
        assert_eq!(empty.byte_length(true), 22);

        let keyless = empty.serialize(false);
        assert_eq!(hex::encode(&keyless), UPSTREAM_KEYLESS);
        assert_eq!(empty.byte_length(false), 2);
    }

    /// An empty payload round-trips in both `include_key` settings — which is
    /// the opposite of what this test asserted when it was written.
    ///
    /// The old claim was an asymmetry: round-trips without its key and not with
    /// it, because at "twenty-one bytes" the guard held, the reader looked for a
    /// length nobody wrote, and the buffer had ended. There is no twenty-one-byte
    /// form. The prefix is always written, so the length the guard sends the
    /// reader looking for is there to be found, and nothing is truncated.
    ///
    /// Upstream agrees, reading back what it wrote (same pin, same object as
    /// `an_empty_payload_still_carries_its_length_prefix`, read with
    /// `fromBuffer`):
    ///
    /// ```text
    /// keyed:   len=22 called_at=0 guard(0 < 21)=true end=22 data="" reser=<the same 22 bytes>
    /// keyless: len=2  called_at=0 guard(0 < 1)=true  end=2  data="" reser=0100
    /// ```
    ///
    /// `end` is the full length in both, so the trailing `0x00` is *consumed* —
    /// read as the `compactSize(0)` it is indistinguishable from. The guard
    /// decides whether that byte is read as a length at all, not whether the
    /// round trip survives.
    #[test]
    fn an_empty_payload_round_trips_in_both_key_settings() {
        let empty = VdxfObject::new(VERUSPAY_INVOICE_VDXF_KEY, DEFAULT_VERSION, Vec::new());

        let keyless = empty.serialize(false);
        assert_eq!(keyless, vec![0x01, 0x00]);
        let mut offset = 0;
        let read = VdxfObject::deserialize(&keyless, &mut offset, Some(VERUSPAY_INVOICE_VDXF_KEY))
            .unwrap();
        assert_eq!(read, empty);
        assert_eq!(
            offset, 2,
            "0 < 2 - 1 holds, so the 0x00 is read as the length"
        );
        assert_eq!(read.serialize(false), keyless);

        let keyed = empty.serialize(true);
        let mut offset = 0;
        let read = VdxfObject::deserialize(&keyed, &mut offset, None).unwrap();
        assert_eq!(read, empty);
        assert_eq!(
            offset, 22,
            "0 < 22 - 1 holds too, and the whole frame is consumed"
        );
        assert_eq!(read.serialize(true), keyed);
    }

    /// The guard reads the offset it was handed, not the reader's position.
    ///
    /// Re-derived for the two-byte empty form rather than renumbered, and this
    /// buffer is the case where the two readings actually disagree: a keyless
    /// empty object at offset 2 of a four-byte buffer is *called* at 2 and
    /// `2 < 4 - 1` holds, so the payload is sought; the reader is at 3 once the
    /// version is consumed, and `3 < 3` would not hold. Upstream takes the first
    /// reading and reaches the end of the buffer (same pin):
    ///
    /// ```text
    /// buf=dead0100 len=4 called_at=2 guard(2 < 3)=true end=4 data=""
    /// ```
    #[test]
    fn the_guard_uses_the_offset_it_was_called_with() {
        let empty = VdxfObject::new(VERUSPAY_INVOICE_VDXF_KEY, DEFAULT_VERSION, Vec::new());
        let mut bytes = vec![0xde, 0xad];
        bytes.extend_from_slice(&empty.serialize(false));
        assert_eq!(hex::encode(&bytes), "dead0100");

        let mut offset = 2;
        let read =
            VdxfObject::deserialize(&bytes, &mut offset, Some(VERUSPAY_INVOICE_VDXF_KEY)).unwrap();
        assert_eq!(read, empty);
        assert_eq!(offset, 4, "the length at offset 3 was read, not skipped");

        // The other side of the guard, which no writer reaches: the prefix is
        // always written, so two bytes is the floor and `called_at < len - 1`
        // always holds for a serialized object. A buffer that ends one byte after
        // the version is the only shape that gets there, so it is hand-built —
        // called at 0 with `0 < 1 - 1` false, no payload is sought, and the
        // version stands alone. Pinned because `deserialize` still has the
        // branch, not because anything produces the bytes.
        let mut offset = 0;
        let read =
            VdxfObject::deserialize(&[0x01], &mut offset, Some(VERUSPAY_INVOICE_VDXF_KEY)).unwrap();
        assert_eq!(read, empty);
        assert_eq!(offset, 1);
    }

    /// A multi-byte version, because the frame's second field is a VARINT and a
    /// one-byte example would not show it.
    #[test]
    fn a_version_above_127_takes_two_bytes() {
        let object = VdxfObject::new(VERUSPAY_INVOICE_VDXF_KEY, 128, vec![0xaa]);
        let bytes = object.serialize(true);
        // 0x80 0x00 is the daemon's VARINT for 128 — base-128 with the
        // continuation bit, and the -1 on each carried group.
        assert_eq!(&bytes[20..22], &[0x80, 0x00]);
        assert_eq!(bytes[22], 0x01, "compactSize(1)");
        assert_eq!(object.byte_length(true), bytes.len());

        let mut offset = 0;
        assert_eq!(
            VdxfObject::deserialize(&bytes, &mut offset, None).unwrap(),
            object
        );
        assert_eq!(offset, bytes.len());
    }

    /// A payload long enough to need a three-byte CompactSize, so the length
    /// prefix is not only ever one byte in this file.
    #[test]
    fn a_long_payload_uses_the_compact_size_escape() {
        let data = vec![0x5a; 300];
        let object = VdxfObject::new(VERUSPAY_INVOICE_VDXF_KEY, 1, data.clone());
        let bytes = object.serialize(true);
        assert_eq!(&bytes[21..24], &[0xfd, 0x2c, 0x01], "compactSize(300)");
        assert_eq!(object.byte_length(true), 20 + 1 + 3 + 300);
        assert_eq!(bytes.len(), object.byte_length(true));

        let mut offset = 0;
        assert_eq!(
            VdxfObject::deserialize(&bytes, &mut offset, None)
                .unwrap()
                .data(),
            data.as_slice()
        );
    }

    #[test]
    fn refuses_hostile_and_truncated_frames() {
        let good = base64url::decode(INVOICE_QR).unwrap();

        // Truncated at every prefix. Every one of these must be an error and
        // none may panic — this is input a QR code supplied.
        for length in 0..good.len() {
            let mut offset = 0;
            let read = VdxfObject::deserialize(&good[..length], &mut offset, None);
            assert!(read.is_err(), "a {length}-byte prefix must not parse");
        }

        // A declared length longer than what remains. Nothing is allocated on
        // it.
        let mut overstated = good[..22].to_vec();
        overstated[21] = 0xfe;
        overstated.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        let mut offset = 0;
        assert!(VdxfObject::deserialize(&overstated, &mut offset, None).is_err());

        // A non-canonical CompactSize: `fd 34 00` for 52, which read_compact_size
        // refuses so that one payload has one spelling.
        let mut non_canonical = good[..21].to_vec();
        non_canonical.extend_from_slice(&[0xfd, 0x34, 0x00]);
        non_canonical.extend_from_slice(&invoice_data());
        let mut offset = 0;
        assert!(VdxfObject::deserialize(&non_canonical, &mut offset, None).is_err());

        // A VARINT that overflows u64 where the version goes.
        let mut overflowing = good[..20].to_vec();
        overflowing.extend_from_slice(&[0xff; 9]);
        overflowing.push(0x7f);
        let mut offset = 0;
        assert!(VdxfObject::deserialize(&overflowing, &mut offset, None).is_err());
    }

    /// Trailing bytes are refused through the string form, because a deeplink
    /// is the whole object.
    #[test]
    fn refuses_trailing_bytes_after_a_deeplink_object() {
        let mut bytes = base64url::decode(INVOICE_QR).unwrap();
        bytes.push(0x00);
        let text = base64url::encode(&bytes);
        assert!(VdxfObject::from_base64url(&text, None).is_err());
        // And the unmodified string is still fine, so the check is the trailing
        // byte and not the re-encoding.
        assert!(VdxfObject::from_base64url(INVOICE_QR, None).is_ok());
    }

    #[test]
    fn refuses_text_that_is_not_base64url() {
        assert!(VdxfObject::from_base64url("not base64url!", None).is_err());
        assert!(VdxfObject::from_base64url("", None).is_err());
    }

    /// [`compact_size_length`] is a second copy of `verus_wire`'s size classes.
    /// This is what keeps the copy honest: the writer is asked, at every
    /// boundary, and the two have to give the same answer.
    #[test]
    fn compact_size_length_agrees_with_the_writer() {
        for n in [
            0,
            1,
            0xfc,
            0xfd,
            0xfe,
            0xffff,
            0x1_0000,
            0xffff_ffff,
            0x1_0000_0000,
            u64::MAX,
        ] {
            let mut written = Vec::new();
            write_compact_size(&mut written, n);
            assert_eq!(compact_size_length(n), written.len(), "{n:#x}");
        }
    }

    /// `byte_length` is what sizes `serialize`'s buffer, so a disagreement is a
    /// reallocation at best and a wrong `dataByteLength` on the wire at worst.
    /// Asserted across every size class rather than at the three lengths the
    /// other tests happen to use.
    #[test]
    fn byte_length_is_exactly_what_serialize_writes() {
        for length in [0usize, 1, 0xfc, 0xfd, 0xfe, 0xffff, 0x1_0000] {
            for version in [0u64, 1, 0x7f, 0x80, 0x3fff, u64::MAX] {
                let object =
                    VdxfObject::new(VERUSPAY_INVOICE_VDXF_KEY, version, vec![0x7e; length]);
                for include_key in [false, true] {
                    assert_eq!(
                        object.byte_length(include_key),
                        object.serialize(include_key).len(),
                        "length={length} version={version} include_key={include_key}"
                    );
                }
            }
        }
    }
}
