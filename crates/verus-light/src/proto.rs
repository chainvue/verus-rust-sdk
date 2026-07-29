//! Just enough protobuf to talk to lightwalletd.
//!
//! # Why this is hand-written
//!
//! The obvious alternative is `prost` + `prost-build`, which needs a `protoc`
//! binary (or `protox`) at build time and adds code generation to every
//! consumer's CI. Against that: this crate needs **seven** messages, all of them
//! `proto3` scalars, `bytes`, `string` and one level of nesting. The generated
//! code would be larger than this file.
//!
//! The workspace already hand-writes its wire formats — transaction
//! serialization, satoshi VARINTs, CryptoCondition scripts — and tests them
//! against bytes a daemon actually produced. This follows that precedent, and
//! [`crate::messages`] is checked the same way: against response bodies captured
//! from a real server, committed under `fixtures/lightwalletd/`.
//!
//! The field numbers come from `fixtures/lightwalletd/*.proto`, copied verbatim
//! from the server this was developed against.
//!
//! # What is deliberately not supported
//!
//! Groups (wire types 3 and 4) were removed in `proto3` and are rejected rather
//! than skipped. Packed repeated fields never appear in these messages — every
//! `repeated` here is of a message type, which `proto3` cannot pack.

use crate::error::LightError;

/// A protobuf wire type.
pub(crate) const WIRE_VARINT: u8 = 0;
pub(crate) const WIRE_FIXED64: u8 = 1;
pub(crate) const WIRE_BYTES: u8 = 2;
pub(crate) const WIRE_FIXED32: u8 = 5;

/// A varint may not be longer than this: 64 bits at 7 bits per byte.
const MAX_VARINT_BYTES: usize = 10;

/// A bounds-checked reader over one protobuf message.
///
/// Every method returns `Err` rather than panicking on a truncated or
/// nonsensical body, because the bytes come from a server that may be
/// misbehaving, buggy, or not lightwalletd at all.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.offset >= self.bytes.len()
    }

    fn need(&self, n: usize) -> Result<(), LightError> {
        if self.offset + n > self.bytes.len() {
            return Err(LightError::Protobuf(format!(
                "wanted {n} bytes at offset {}, but the message is {} long",
                self.offset,
                self.bytes.len()
            )));
        }
        Ok(())
    }

    /// Read a base-128 varint.
    pub(crate) fn varint(&mut self) -> Result<u64, LightError> {
        let mut value: u64 = 0;
        let mut shift = 0;
        for count in 0..MAX_VARINT_BYTES {
            self.need(1)?;
            let byte = self.bytes[self.offset];
            self.offset += 1;
            // The 10th byte of a 64-bit varint carries only one meaningful bit.
            let part = u64::from(byte & 0x7f);
            if count == MAX_VARINT_BYTES - 1 && part > 1 {
                return Err(LightError::Protobuf(
                    "varint does not fit in 64 bits".into(),
                ));
            }
            value |= part << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
        Err(LightError::Protobuf(
            "varint is longer than 10 bytes".into(),
        ))
    }

    /// Read a field key, returning `(field number, wire type)`.
    pub(crate) fn tag(&mut self) -> Result<(u32, u8), LightError> {
        let key = self.varint()?;
        let wire = u8::try_from(key & 0x7).expect("three bits fit in a u8");
        let field = u32::try_from(key >> 3)
            .map_err(|_| LightError::Protobuf("field number does not fit in 32 bits".into()))?;
        if field == 0 {
            return Err(LightError::Protobuf("field number 0 is not valid".into()));
        }
        Ok((field, wire))
    }

    /// Read a length-delimited field's payload.
    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], LightError> {
        let len = self.varint()?;
        let len = usize::try_from(len)
            .map_err(|_| LightError::Protobuf("length does not fit in this platform".into()))?;
        self.need(len)?;
        let out = &self.bytes[self.offset..self.offset + len];
        self.offset += len;
        Ok(out)
    }

    /// Read a length-delimited field as UTF-8.
    pub(crate) fn string(&mut self) -> Result<String, LightError> {
        let raw = self.bytes()?;
        String::from_utf8(raw.to_vec())
            .map_err(|_| LightError::Protobuf("string field is not valid UTF-8".into()))
    }

    /// Read a length-delimited field as a fixed-size array.
    ///
    /// Hashes and commitments are all 32 bytes; a server sending 31 is a bug we
    /// want to hear about at the boundary, not a panic in the crypto later.
    pub(crate) fn array<const N: usize>(&mut self, what: &str) -> Result<[u8; N], LightError> {
        let raw = self.bytes()?;
        <[u8; N]>::try_from(raw).map_err(|_| {
            LightError::Protobuf(format!("{what} is {} bytes, expected {N}", raw.len()))
        })
    }

    /// Read a varint as a signed 32-bit value, the way `proto3` encodes `int32`.
    ///
    /// A negative `int32` is sign-extended to 64 bits before encoding, so
    /// `errorCode: -1` arrives as ten bytes, not one.
    pub(crate) fn int32(&mut self) -> Result<i32, LightError> {
        let raw = self.varint()?;
        // Taking the low word undoes that widening, and is a no-op for the
        // small positive codes that are the common case.
        let low = u32::try_from(raw & 0xffff_ffff).expect("masked to 32 bits");
        Ok(low.cast_signed())
    }

    /// Skip a field whose number we do not recognise.
    ///
    /// `proto3` requires unknown fields to be ignored, and lightwalletd forks do
    /// add fields — `chainMetadata` was field 8 on `CompactBlock` long after the
    /// original five. Erroring here would break against a newer server for no
    /// reason.
    pub(crate) fn skip(&mut self, wire: u8) -> Result<(), LightError> {
        match wire {
            WIRE_VARINT => {
                self.varint()?;
            }
            WIRE_FIXED64 => {
                self.need(8)?;
                self.offset += 8;
            }
            WIRE_BYTES => {
                self.bytes()?;
            }
            WIRE_FIXED32 => {
                self.need(4)?;
                self.offset += 4;
            }
            other => {
                return Err(LightError::Protobuf(format!(
                    "wire type {other} is not valid in proto3"
                )))
            }
        }
        Ok(())
    }
}

/// Append a base-128 varint.
pub(crate) fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = u8::try_from(value & 0x7f).expect("seven bits fit in a u8");
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn put_tag(out: &mut Vec<u8>, field: u32, wire: u8) {
    put_varint(out, (u64::from(field) << 3) | u64::from(wire));
}

/// Append a varint field, omitting it when zero.
///
/// `proto3` does not transmit a scalar equal to its default, and a server that
/// echoes the message back should see what a canonical encoder would send.
pub(crate) fn put_varint_field(out: &mut Vec<u8>, field: u32, value: u64) {
    if value == 0 {
        return;
    }
    put_tag(out, field, WIRE_VARINT);
    put_varint(out, value);
}

/// Append a length-delimited field, omitting it when empty.
pub(crate) fn put_bytes_field(out: &mut Vec<u8>, field: u32, value: &[u8]) {
    if value.is_empty() {
        return;
    }
    put_tag(out, field, WIRE_BYTES);
    put_varint(
        out,
        u64::try_from(value.len()).expect("a slice length fits in u64"),
    );
    out.extend_from_slice(value);
}
