//! base58check with a leading version byte.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::KeyError;

/// Encode `payload` as base58check with `version` prepended.
///
/// # Why the checksum is computed here rather than by `bs58`
///
/// `payload` is sometimes a private key — [`crate::PrivateKey::to_wif`] is the
/// caller that matters — and `bs58::encode(..).with_check()` hashes it inside
/// `bs58`, where nothing can be wiped afterwards. Measured on wasm32, that left
/// a full canonical-order copy of the scalar in linear memory surviving
/// `free()`: SHA-256 buffers its input in a 64-byte block, and a 38-byte WIF
/// payload never fills a block, so it sat there until something else happened
/// to reuse the stack.
///
/// Doing the two hashes here puts every buffer holding the secret under this
/// function's control: the assembled `version ‖ payload ‖ checksum` lives in a
/// [`Zeroizing`] `Vec`, and the block buffer that saw the payload belongs to a
/// hasher this function owns.
///
/// **What actually removes the copy is the second pass, not the scrub below.**
/// `sha2` 0.10 has no `zeroize` feature and does not wipe its block buffer on
/// reset — but the second hash writes the 32-byte first digest into that same
/// buffer, overwriting the version byte and all but the last byte of the
/// payload before the hasher is dropped. That is structural, not luck: it
/// happens for the same reason on any optimizer setting.
///
/// Measured on wasm32 (uniform-fill search, so byte order cannot hide
/// anything): removing the explicit scrub changes **nothing** — 0 copies with
/// it and 0 without, on both `--release` + `wasm-opt` and `--dev`. It is kept
/// as belt-and-braces for the handful of trailing bytes the second pass does
/// not reach, and it is deliberately *not* described as what fixes this. Issue
/// #179 has the full numbers; re-run them before changing any of this, because
/// an earlier attempt that merely wrapped `bs58`'s own buffer relocated the
/// copy instead of removing it and looked like a fix.
pub fn encode_check(version: u8, payload: &[u8]) -> String {
    // Capacity for the whole frame up front: a realloc mid-build would copy the
    // secret into a fresh allocation and leave the old one unwiped behind it.
    let mut data = Zeroizing::new(Vec::with_capacity(payload.len() + 1 + CHECKSUM_LEN));
    data.push(version);
    data.extend_from_slice(payload);

    let mut hasher = Sha256::new();
    hasher.update(&data[..]);
    let first = Zeroizing::new(hasher.finalize_reset());
    hasher.update(&first[..]);
    // The second hash's input is already a digest, not the secret, so only the
    // first pass ever put key material into the block buffer.
    let checksum = hasher.finalize_reset();
    data.extend_from_slice(&checksum[..CHECKSUM_LEN]);

    // Belt-and-braces, and measured to make no difference on its own — see the
    // note above. The second pass has already overwritten all but the tail of
    // the block buffer; this clears that tail. Same instance deliberately: a
    // fresh `Sha256` would sit somewhere else and scrub nothing.
    hasher.update([0u8; BLOCK_LEN]);
    let _ = hasher.finalize();

    bs58::encode(&data[..]).into_string()
}

/// Bytes of double-SHA256 appended as the base58check checksum.
const CHECKSUM_LEN: usize = 4;

/// SHA-256's input block, and so the size of the buffer being scrubbed above.
const BLOCK_LEN: usize = 64;

/// Decode base58check, returning `(version, payload)`.
///
/// The checksum is verified; a single mistyped character is rejected rather than
/// decoding to a valid-looking but wrong payload.
pub fn decode_check(encoded: &str) -> Result<(u8, Vec<u8>), KeyError> {
    let data = bs58::decode(encoded)
        .with_check(None)
        .into_vec()
        .map_err(|e| KeyError::Base58(e.to_string()))?;
    let (version, payload) = data
        .split_first()
        .ok_or_else(|| KeyError::Base58("empty payload".into()))?;
    Ok((*version, payload.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hand-rolled checksum must agree with `bs58`'s own, byte for byte.
    ///
    /// This is the whole risk of computing it here: base58check is consensus
    /// data, and a checksum that differed even in one byte would mint WIFs and
    /// addresses the rest of the world rejects. `bs58`'s `with_check()` is
    /// still linked in — `decode_check` uses it — so it is available as an
    /// independent oracle rather than a second copy of the same belief.
    #[test]
    fn the_local_checksum_matches_bs58s_own() {
        for (version, len) in [(0x3c_u8, 20_usize), (0x80, 33), (0x00, 20), (0xbc, 33)] {
            for fill in [0x00_u8, 0x01, 0xa7, 0xff] {
                let payload = vec![fill; len];
                let mut framed = Vec::with_capacity(len + 1);
                framed.push(version);
                framed.extend_from_slice(&payload);

                assert_eq!(
                    encode_check(version, &payload),
                    bs58::encode(&framed).with_check().into_string(),
                    "version {version:#04x}, {len}-byte payload of {fill:#04x}"
                );
            }
        }
    }

    /// An empty payload is still a valid frame: version byte plus checksum.
    #[test]
    fn an_empty_payload_still_round_trips() {
        let encoded = encode_check(0x3c, &[]);
        assert_eq!(decode_check(&encoded).unwrap(), (0x3c, Vec::new()));
    }

    #[test]
    fn round_trips() {
        let encoded = encode_check(0x3c, &[0xab; 20]);
        assert_eq!(decode_check(&encoded).unwrap(), (0x3c, vec![0xab; 20]));
    }

    #[test]
    fn rejects_a_mistyped_character() {
        let good = encode_check(0x3c, &[0xab; 20]);
        let mut chars: Vec<char> = good.chars().collect();
        // Swap the last character for a different valid base58 one.
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'a' { 'b' } else { 'a' };
        let mutated: String = chars.into_iter().collect();
        assert!(matches!(decode_check(&mutated), Err(KeyError::Base58(_))));
    }
}
