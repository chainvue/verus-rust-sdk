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
/// `free()`: SHA-256 buffers its input in a 64-byte block, and the WIF frame is
/// 34 bytes (`0xbc ‖ 32-byte scalar ‖ 0x01`), so it never fills a block and sat
/// there until something else happened to reuse the stack.
///
/// Doing the two hashes here puts every buffer holding the secret under this
/// function's control: the assembled `version ‖ payload ‖ checksum` lives in a
/// [`Zeroizing`] `Vec`, and the block buffer that saw the payload belongs to a
/// hasher this function owns.
///
/// **The second pass is what clears the block buffer**, and it does so
/// completely. `sha2` 0.10 has no `zeroize` feature, and `BlockBuffer::reset`
/// only moves the cursor — it never zeroes the bytes — so after the *first*
/// digest the payload is still sitting there. Then:
///
/// - the second `update` writes the 32-byte first digest over offsets `0..32`;
/// - the second `finalize` runs `digest_pad`, which writes `0x80` at the cursor
///   and **zeros every byte from there to the end of the block** (then writes
///   the 8-byte bit length back over `56..64`, which overwrites zeros, not
///   payload).
///
/// The second pass's cursor is always 32, because its input is always a 32-byte
/// digest — so the post-state is invariably `digest ‖ 0x80 ‖ zeros ‖ bitlen`
/// whatever the payload length was. That is structural, not an optimizer
/// accident, which is why it does not depend on a build profile.
///
/// The argument covers `BlockBuffer` and nothing else. On wasm32 `sha2` uses
/// its soft backend, whose `compress` takes a 64-byte stack copy of the block
/// it is fed — that copy is covered by the *measurement* below, not by the
/// reasoning above.
///
/// Verified both ways rather than assumed. Measured on wasm32 with a
/// uniform-fill search (byte order cannot hide anything): the copy is gone on
/// `--release` + `wasm-opt` and on `--dev`, and it is *gone* rather than
/// relocated — an earlier attempt that merely wrapped `bs58`'s own `Vec` moved
/// it a few bytes and looked like a fix. Issue #179 has the addresses. Re-run
/// them before changing any of this.
///
/// Only the outbound path is covered. [`decode_check`] still verifies through
/// `bs58`, so `from_wif` has the same shape of exposure coming in; it should
/// get the same treatment only after the same measurement.
pub fn encode_check(version: u8, payload: &[u8]) -> String {
    // Capacity for the whole frame up front: a realloc mid-build would copy the
    // secret into a fresh allocation and leave the old one unwiped behind it.
    let mut data = Zeroizing::new(Vec::with_capacity(payload.len() + 1 + CHECKSUM_LEN));
    data.push(version);
    data.extend_from_slice(payload);

    let mut hasher = Sha256::new();
    hasher.update(&data[..]);
    // Kept in `Zeroizing` on measured grounds, not because the digest is
    // secret — it is `sha256(version ‖ payload)`, recomputable by anyone
    // holding the emitted string. Dropping the wrapper measurably leaves one
    // MORE copy of the scalar alive: a k256 construction spill at `1048132`
    // that the extra stack traffic here otherwise overwrites (4 regions after
    // `toWif` instead of 3, wasm32 release, 4/4 processes). That overwrite is
    // incidental and this does not pretend otherwise — but the choice is
    // between three copies and four, so it stays.
    //
    // Note this leans on `GenericArray: Zeroize`, which `verus-keys` gets only
    // transitively via `k256 -> elliptic-curve -> generic-array/zeroize` and
    // does not declare itself. `k256` is not optional here, so it holds.
    let first = Zeroizing::new(hasher.finalize_reset());
    hasher.update(&first[..]);
    // The second hash's input is already a digest, not the secret, so only the
    // first pass ever put key material into the block buffer.
    let checksum = hasher.finalize_reset();
    data.extend_from_slice(&checksum[..CHECKSUM_LEN]);

    bs58::encode(&data[..]).into_string()
}

/// Bytes of double-SHA256 appended as the base58check checksum.
const CHECKSUM_LEN: usize = 4;

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
