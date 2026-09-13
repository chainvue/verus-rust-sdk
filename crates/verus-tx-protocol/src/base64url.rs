//! Unpadded URL-safe base64 — the text a VDXF deeplink or QR code carries.
//!
//! A VDXF object travels between a wallet and an application as a string, not
//! as bytes: `VDXFObject.toString()` in the TypeScript SDK is
//! `base64url.encode(this.toBuffer())`, and the result is pasted into a
//! `verus://` URI or drawn as a QR code. So the encoding is part of the
//! observable format, and it is **not** the base64 the rest of this workspace
//! uses.
//!
//! # Why this is not `verus-tx-identity`'s codec
//!
//! `verus_tx_identity::signature` already hand-rolls a base64. It is the wrong
//! one, in both halves of the alphabet and in the padding:
//!
//! | | alphabet | padding |
//! |---|---|---|
//! | signed messages (RFC 4648 §4) | `…+/` | `=` to a multiple of four |
//! | VDXF deeplinks (RFC 4648 §5) | `…-_` | none |
//!
//! Both substitutions are forced by the transport rather than chosen. `+` in a
//! URI query is a space, `/` is a path separator, and `=` terminates a query
//! parameter's value — a signature's base64 can afford all three because it
//! travels in a JSON string, and a deeplink cannot.
//!
//! Generalising the existing codec over its alphabet was considered and
//! rejected: it lives in a different crate, behind a `pub(crate)` boundary, and
//! the two would then share a parameterised decoder whose strictness has to
//! differ anyway (see below). Taking a dependency for a 64-character table was
//! rejected for its own reason — `cargo deny` wants a written justification for
//! every crate here, and "swap two characters" is not one.
//!
//! # This decoder is stricter than `npm base64url`, deliberately
//!
//! Upstream's decoder is `Buffer.from(text.replace(/-/g, '+').replace(/_/g,
//! '/'), 'base64')`, and Node's base64 parser is lenient: it accepts the
//! standard alphabet, accepts `=` padding, and ignores the bits left over in a
//! final incomplete group. Each of those means **two different strings decode
//! to the same bytes**, and this is a decoder for input an attacker supplies —
//! a deeplink arrives from a QR code somebody else printed.
//!
//! So [`decode`] refuses all three:
//!
//! * `+` and `/` are not in the alphabet. Accepting them would be actively
//!   wrong, not merely lax: a `+` that reaches this function has already been
//!   read as a space by anything that parsed the URI it came in, so the bytes
//!   recovered would not be the bytes sent.
//! * `=` is refused, because the encoder never writes it and accepting it gives
//!   `QQ` and `QQ==` as two spellings of one byte. That is the same rule
//!   [`crate::decode`]'s CompactSize reader applies to non-canonical lengths,
//!   for the same reason.
//! * leftover bits must be zero. [`encode`] always zero-fills them, so no
//!   string this workspace or upstream's encoder produces is affected; a string
//!   where they are set was not produced by an encoder at all.
//!
//! The asymmetry is intended and is the safe direction: everything [`encode`]
//! writes, [`decode`] reads back, and everything upstream's encoder writes,
//! [`decode`] reads back. Only strings no encoder produces are refused.

use verus_tx_primitives::TxError;

/// RFC 4648 §5, "base64url": the standard table with `-` for `+` and `_` for
/// `/`.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn bad(detail: &str) -> TxError {
    TxError::MalformedVdxfObject(detail.to_string())
}

/// Encode `bytes` as unpadded base64url.
///
/// The output is what `base64url.encode` in the TypeScript SDK produces, which
/// is what a `verus://` deeplink and a VerusPay QR code carry.
pub fn encode(bytes: &[u8]) -> String {
    // Every three input bytes are four characters; a trailing one or two bytes
    // are two or three characters and *no* padding, which is the whole point.
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let packed = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        // `chunk.len() + 1` characters carry `chunk.len()` bytes: 1 -> 2, 2 ->
        // 3, 3 -> 4. The bits below the ones emitted are the zeros this pads
        // the final group with, and `decode` requires them to be zero.
        for index in 0..=chunk.len() {
            let sextet = (packed >> (18 - 6 * index)) & 63;
            // `ALPHABET` has 64 entries and the mask is 0..64, so the index is
            // in range by construction.
            let position = usize::try_from(sextet).expect("a sextet fits a usize");
            out.push(char::from(ALPHABET[position]));
        }
    }
    out
}

/// Decode unpadded base64url.
///
/// # Errors
///
/// Refuses anything outside `A–Z a–z 0–9 - _`, a length that no base64 can
/// have (`len % 4 == 1`), and a final group whose unused bits are set. See the
/// module docs for why each refusal is there rather than Node's leniency.
pub fn decode(text: &str) -> Result<Vec<u8>, TxError> {
    let characters = text.as_bytes();
    // Four characters carry three bytes, three carry two and two carry one.
    // One leftover character carries nothing and cannot have been written by
    // any encoder.
    if characters.len() % 4 == 1 {
        return Err(bad(&format!(
            "{} characters is not a possible base64url length",
            characters.len()
        )));
    }
    let mut out = Vec::with_capacity(characters.len() / 4 * 3);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for (index, character) in characters.iter().enumerate() {
        // A 64-entry table, so `position` is 0..64 and every conversion below
        // is exact.
        let sextet = ALPHABET
            .iter()
            .position(|entry| entry == character)
            .and_then(|position| u32::try_from(position).ok())
            .ok_or_else(|| {
                // The offending *byte*, in hex, and where it was — not
                // `char::from(byte)`. The input is a `&str`, so a rejected byte
                // is often one unit of a multi-byte UTF-8 sequence, and naming
                // it as a Latin-1 codepoint prints a character that was never
                // in the string: the worst kind of diagnostic for somebody
                // working out what mangled their deeplink.
                bad(&format!(
                    "{text:?} is not unpadded URL-safe base64: byte {character:#04x} at \
                     index {index} is not in the alphabet"
                ))
            })?;
        accumulator = (accumulator << 6) | sextet;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let byte = u8::try_from((accumulator >> bits) & 0xff).expect("masked to one byte");
            out.push(byte);
        }
    }
    // Two or four bits can be left over. The encoder writes them as zero; a
    // string that sets them would decode to the same bytes as the canonical
    // spelling, so it is refused rather than silently accepted.
    if bits > 0 && accumulator & ((1 << bits) - 1) != 0 {
        return Err(bad(&format!(
            "{text:?} sets the {bits} unused bits of its final base64url group"
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real VerusPay invoice QR string, and the bytes it has to be.
    ///
    /// This is the anchor that makes the rest of the module evidence rather
    /// than a restatement: the string was produced by the TypeScript SDK's
    /// `base64url`, not by [`encode`], and nothing here chose its contents.
    /// Note what it proves about the two properties that differ from signed
    /// messages — it is 99 characters, which is not a multiple of four, so
    /// there is no padding; and it contains `_` and `-`, which the standard
    /// alphabet cannot produce.
    const INVOICE_QR: &str = "dgCq8t3nk3reqeFQANTiwij8jmIENAH_AOQLVAIAAAACFAAtMxHDi_0hkJLSrvRJgEvos77-pu-eojVjXjKBJP80KdufnpG2Ti0";

    /// The same invoice as bytes. Twenty bytes of VDXF key, then the frame.
    const INVOICE_BYTES: &str = "7600aaf2dde7937adea9e15000d4e2c228fc8e62\
                                 0434\
                                 01ff00e40b54020000000214002d3311c38bfd219092d2aef449804be8b3befe\
                                 a6ef9ea235635e328124ff3429db9f9e91b64e2d";

    fn invoice_bytes() -> Vec<u8> {
        hex::decode(INVOICE_BYTES).expect("a literal this file controls")
    }

    #[test]
    fn decodes_a_real_invoice_qr_string() {
        assert_eq!(decode(INVOICE_QR).unwrap(), invoice_bytes());
    }

    #[test]
    fn encodes_back_to_the_string_upstream_produced() {
        assert_eq!(encode(&invoice_bytes()), INVOICE_QR);
    }

    /// The two characters that separate this alphabet from the signed-message
    /// one really are produced, in a payload that exists.
    #[test]
    fn the_url_safe_alphabet_is_the_one_in_use() {
        assert!(INVOICE_QR.contains('-'), "no `-` to distinguish the table");
        assert!(INVOICE_QR.contains('_'), "no `_` to distinguish the table");
        assert!(!INVOICE_QR.contains('='), "padding was stripped");
        assert_ne!(INVOICE_QR.len() % 4, 0, "so padding is observably absent");
    }

    /// Every tail length round-trips, including the ones that would have
    /// carried padding.
    #[test]
    fn every_trailing_group_length_round_trips() {
        for length in 0..=48usize {
            // Deterministic rather than random: a failure names one input.
            let bytes: Vec<u8> = (0..length)
                .map(|index| u8::try_from(index * 7 % 256).expect("modulo 256"))
                .collect();
            let text = encode(&bytes);
            assert_eq!(text.len(), length * 4 / 3 + usize::from(length % 3 != 0));
            assert!(!text.contains('='), "{length}: padding leaked in");
            assert_eq!(decode(&text).unwrap(), bytes, "{length}");
        }
    }

    /// RFC 4648's own test vectors, in their base64url spelling.
    #[test]
    fn matches_rfc_4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), encoded, "{plain:?}");
            assert_eq!(decode(encoded).unwrap(), plain.as_bytes(), "{encoded:?}");
        }
    }

    /// The byte range where the two alphabets disagree, checked against the
    /// value the table assigns rather than against this module's own output.
    #[test]
    fn sextets_62_and_63_are_dash_and_underscore() {
        // 0xfb 0xf0 packs to sextets 62, 63, 0 — the two positions that differ
        // from RFC 4648 §4, where they are `+` and `/`.
        assert_eq!(encode(&[0xfb, 0xf0]), "-_A");
        assert_eq!(decode("-_A").unwrap(), vec![0xfb, 0xf0]);
    }

    #[test]
    fn refuses_what_no_encoder_writes() {
        // The standard alphabet's two characters, which a URI would mangle.
        assert!(decode("a+b").is_err());
        assert!(decode("a/b").is_err());
        // Padding: `QQ` is the canonical spelling of the same byte.
        assert!(decode("QQ==").is_err());
        assert!(decode("Zm8=").is_err());
        // Whitespace, which the signed-message decoder skips and this one does
        // not — a deeplink has no line wrapping to tolerate.
        assert!(decode("Zm9v Zm9v").is_err());
        assert!(decode("Zm9v\n").is_err());
        // A length no base64 has.
        assert!(decode("A").is_err());
        assert!(decode("Zm9vY").is_err());
        // Non-ASCII, and a character outside the table.
        assert!(decode("Zm9.").is_err());
        assert!(decode("Zm9é").is_err());
    }

    /// Non-canonical trailing bits, which Node accepts and this refuses.
    #[test]
    fn refuses_a_final_group_whose_unused_bits_are_set() {
        // `Zg` is "f": 0x66 is sextets 25, 32 — the low four bits of the
        // second sextet are unused. `Zh` through `Zv` set them and would all
        // decode to 0x66 under a lenient parser.
        assert_eq!(decode("Zg").unwrap(), b"f");
        for spelling in ["Zh", "Zi", "Zv"] {
            assert!(decode(spelling).is_err(), "{spelling} must be refused");
        }
        // The three-character case leaves two unused bits. `Zm8` is "fo";
        // `Zm9` sets one of them.
        assert_eq!(decode("Zm8").unwrap(), b"fo");
        assert!(decode("Zm9").is_err());
    }

    /// A sweep rather than hand-picked near-misses: whatever arrives, [`decode`]
    /// answers instead of panicking.
    ///
    /// The hand-written refusals above pin the *specific* inputs that matter —
    /// the wrong alphabet, the padding, the non-canonical bits. They cannot show
    /// the general property, because each one was chosen by somebody who already
    /// knew what the function does. This covers every single byte, every
    /// two-byte pair, and a deterministic walk over longer strings built from
    /// the characters most likely to be confused for the alphabet.
    ///
    /// Deterministic on purpose: a failure here names one input, and the same
    /// input, on every run. `rand` is not a dependency of this crate and should
    /// not become one for a test that does not need entropy.
    #[test]
    fn never_panics_on_anything_a_stranger_sends() {
        // Every byte that can stand alone in a `&str`, as a one- and two-
        // character string. A one-character string is also the `len % 4 == 1`
        // refusal, so this sweeps both paths.
        for first in 0..=0x7fu8 {
            let one = String::from(char::from(first));
            let _ = decode(&one);
            for second in 0..=0x7fu8 {
                let mut two = one.clone();
                two.push(char::from(second));
                let _ = decode(&two);
            }
        }

        // Non-ASCII, which reaches the decoder as several bytes and must be
        // refused by byte rather than by codepoint.
        for text in ["é", "€", "𝄞", "Zm9é", "é9mZ", "\u{0}", "Zm\u{0}9"] {
            assert!(decode(text).is_err(), "{text:?}");
        }

        // Longer strings from a 16-character pool weighted towards the
        // confusable: the four characters the two alphabets disagree on, plus
        // padding, whitespace and URI punctuation.
        const POOL: &[u8; 16] = b"A-_+/=. \nZm9vYg\t";
        let mut state: u32 = 0x1234_5678;
        for _ in 0..4000 {
            // A plain xorshift, inline because it is three lines and a test's
            // sequence generator is not worth a dependency.
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let length = usize::try_from(state % 24).expect("modulo 24");
            let text: String = (0..length)
                .map(|index| {
                    let pick = (state >> (index % 24)) ^ u32::try_from(index).expect("small");
                    let position = usize::try_from(pick % 16).expect("modulo 16");
                    char::from(POOL[position])
                })
                .collect();
            // Whatever comes back, it is an answer. And when it is `Ok`, the
            // bytes have to re-encode to the string that produced them —
            // anything accepted must have been canonical.
            if let Ok(bytes) = decode(&text) {
                assert_eq!(encode(&bytes), text, "accepted a non-canonical spelling");
            }
        }
    }

    /// The codec this replaces, stated as a property rather than as prose: the
    /// two alphabets do not agree on a payload that uses the high sextets.
    #[test]
    fn disagrees_with_standard_base64_exactly_where_expected() {
        let bytes = [0xfb, 0xf0, 0x00];
        // Standard base64 would be `+/AA`; this is the same four sextets.
        assert_eq!(encode(&bytes), "-_AA");
    }
}
