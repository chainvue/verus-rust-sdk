//! Serializing fixed-size byte arrays as hex.
//!
//! Two reasons this exists rather than the derive.
//!
//! **43 bytes is past where serde stops.** Its array impls cover 0 to 32, and a
//! Sapling payment address is an 11-byte diversifier plus a 32-byte `pk_d`. So
//! the one field of [`DetectedNote`](crate::scan::DetectedNote) a wallet must
//! persist and serde cannot derive needs help regardless.
//!
//! **The derive writes bytes as decimal.** `[u8; 32]` serializes as
//! `[17,17,17,…]` — thirty-two numbers. A note store is a file someone opens
//! when a balance looks wrong, and a nullifier written as a hundred characters
//! of decimal cannot be matched against the same nullifier in a log line, an
//! explorer, or this SDK's own output, all of which are hex. So the byte fields
//! are written as hex too, and the file reads the way the rest of the workspace
//! talks.
//!
//! Hand-written rather than taken from `serde-big-array`, which solves only the
//! first problem. The whole implementation is below and is shorter than the
//! dependency justification would have been.
//!
//! # Not bech32
//!
//! A `zs…` address would be friendlier still, and encoding one returns a
//! `Result`. A serializer that can fail on well-formed input is a trap, and a
//! note store is not where you want to find that out.

use core::fmt;
use core::marker::PhantomData;

use serde::de::{DeserializeSeed, Unexpected, Visitor};
use serde::{Deserializer, Serializer};

/// Write `bytes` as lowercase hex.
///
/// # Errors
///
/// Whatever the serializer reports.
pub fn serialize<S: Serializer, const N: usize>(
    bytes: &[u8; N],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex::encode(bytes))
}

/// Reads a hex string into exactly `N` bytes.
///
/// A [`Visitor`] rather than `<&str>::deserialize`, and the difference is not
/// stylistic: `&str` only deserializes from formats that hand out a string
/// **borrowed from the input buffer**. `serde_json::from_str` does;
/// `from_reader`, `from_value`, a JSON string containing an escape, and every
/// binary format read from a stream do not. A wallet writing with `to_writer`
/// and reading with `from_reader` — the most ordinary loop there is — would
/// have found its own store unreadable.
struct HexVisitor<const N: usize>(PhantomData<[u8; N]>);

impl<const N: usize> Visitor<'_> for HexVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{N} bytes as hex")
    }

    fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Self::Value, E> {
        let bytes =
            hex::decode(text).map_err(|_| E::invalid_value(Unexpected::Str(text), &self))?;
        let length = bytes.len();
        <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| E::invalid_length(length, &self))
    }
}

/// Applies that visitor to one element of a sequence.
struct HexSeed<const N: usize>;

impl<'de, const N: usize> DeserializeSeed<'de> for HexSeed<N> {
    type Value = [u8; N];

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_str(HexVisitor::<N>(PhantomData))
    }
}

/// Read `N` bytes back from hex, refusing any other length.
///
/// The length check is the point. A truncated or padded address deserializes
/// into a note claiming to be paid somewhere it is not, and the first thing to
/// notice would be a change output paying an address nobody holds — after the
/// transaction is on chain.
///
/// # Errors
///
/// If the value is not a string, is not hex, or is not `N` bytes.
pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    deserializer.deserialize_str(HexVisitor::<N>(PhantomData))
}

/// The same, for a `Vec` of them — a list of nullifiers, say.
pub mod vec {
    use core::fmt;

    use serde::de::{SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};

    use super::HexSeed;

    /// Write each element as lowercase hex.
    ///
    /// # Errors
    ///
    /// Whatever the serializer reports.
    pub fn serialize<S: Serializer, const N: usize>(
        items: &[[u8; N]],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(items.iter().map(hex::encode))
    }

    struct VecVisitor<const N: usize>;

    impl<'de, const N: usize> Visitor<'de> for VecVisitor<N> {
        type Value = Vec<[u8; N]>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a sequence of {N}-byte hex strings")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            // The hint is the format's, so it is bounded before it is trusted:
            // a hostile store must not name a capacity this allocates for.
            let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(1024));
            while let Some(item) = seq.next_element_seed(HexSeed::<N>)? {
                items.push(item);
            }
            Ok(items)
        }
    }

    /// Read a sequence of hex strings back.
    ///
    /// # Errors
    ///
    /// If any element is not a string, is not hex, or is not `N` bytes.
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<Vec<[u8; N]>, D::Error> {
        deserializer.deserialize_seq(VecVisitor::<N>)
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Holder {
        #[serde(with = "super")]
        address: [u8; 43],
        #[serde(with = "super")]
        hash: [u8; 32],
        #[serde(with = "super::vec")]
        hashes: Vec<[u8; 32]>,
    }

    fn holder() -> Holder {
        Holder {
            address: core::array::from_fn(|i| u8::try_from(i).expect("a byte")),
            hash: [0xab; 32],
            hashes: vec![[0x01; 32], [0xfe; 32]],
        }
    }

    #[test]
    fn everything_round_trips_exactly() {
        let json = serde_json::to_string(&holder()).expect("serialize");
        assert_eq!(
            serde_json::from_str::<Holder>(&json).expect("deserialize"),
            holder()
        );
    }

    /// Hex, not decimal number arrays — this is a file someone reads.
    #[test]
    fn it_is_written_as_hex() {
        let json = serde_json::to_string(&holder()).expect("serialize");
        assert!(json.contains(&format!("\"{}\"", "ab".repeat(32))), "{json}");
        assert!(json.contains(&format!("\"{}\"", "01".repeat(32))), "{json}");
        // And nothing came out as a decimal byte list.
        assert!(!json.contains("171,171"), "{json}");
    }

    /// The bug this module was rewritten for.
    ///
    /// `<&str>::deserialize` only works where the format hands out a string
    /// borrowed from the input buffer. A wallet that writes with `to_writer`
    /// and reads with `from_reader` would otherwise find its own store
    /// unreadable — and the round-trip tests, which all used `from_str`, would
    /// not have noticed.
    #[test]
    fn it_reads_from_a_reader_and_not_only_from_a_str() {
        let json = serde_json::to_vec(&holder()).expect("serialize");
        let from_reader: Holder =
            serde_json::from_reader(std::io::Cursor::new(json.clone())).expect("from_reader");
        assert_eq!(from_reader, holder());

        // And through a `Value`, which config layers and migrations go via.
        let value: serde_json::Value = serde_json::from_slice(&json).expect("to value");
        assert_eq!(
            serde_json::from_value::<Holder>(value).expect("from_value"),
            holder()
        );
    }

    /// A JSON escape inside the hex string also defeats a borrowed `&str`.
    #[test]
    fn it_reads_a_string_carrying_an_escape() {
        let json = serde_json::to_string(&holder())
            .expect("serialize")
            .replacen("\"ab", "\"\\u0061b", 1);
        assert_eq!(
            serde_json::from_str::<Holder>(&json).expect("deserialize"),
            holder()
        );
    }

    /// A wrong length must not become an address.
    #[test]
    fn a_wrong_length_is_refused() {
        for length in [0usize, 42, 44, 32] {
            let json = serde_json::to_string(&holder())
                .expect("serialize")
                .replace(&hex::encode(holder().address), &"ab".repeat(length));
            assert!(
                serde_json::from_str::<Holder>(&json).is_err(),
                "{length} bytes should not deserialize as an address"
            );
        }
    }

    /// Including inside a sequence, where it would be easy to skip.
    #[test]
    fn a_wrong_length_inside_a_sequence_is_refused() {
        let json = serde_json::to_string(&holder())
            .expect("serialize")
            .replace(&"01".repeat(32), &"01".repeat(31));
        assert!(serde_json::from_str::<Holder>(&json).is_err(), "{json}");
    }

    #[test]
    fn anything_that_is_not_hex_is_refused() {
        let json = serde_json::to_string(&holder())
            .expect("serialize")
            .replace(&hex::encode(holder().address), &"zz".repeat(43));
        assert!(serde_json::from_str::<Holder>(&json).is_err());
    }
}
