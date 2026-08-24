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
/// [`decode_check`] now does the same thing coming in, for the same measured
/// reason — the inbound leak was confined to the rejection paths, which is why
/// it took longer to find. See [`decode_check`].
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
///
/// # Why the checksum is verified here rather than by `bs58`
///
/// The mirror of [`encode_check`], and against a leak that was measured coming
/// in. `bs58::decode(..).with_check()` decodes into a `Vec` it owns and hashes
/// out of that `Vec` with a hasher it owns, so the frame passed through two
/// buffers this crate could not wipe.
///
/// Measured on wasm32, release + `wasm-opt`, the hasher's block buffer survived
/// every rejection that got as far as hashing: 64 bytes holding
/// `version ‖ 32-byte scalar ‖ flag` in canonical order, with a cursor byte at
/// offset `+64` equal to the frame length (`0x22` for a 34-byte frame, `0x23`
/// for 35) — the shape of `block_buffer::BlockBuffer<U64>`. That covers a
/// checksum mismatch, which is the likeliest rejection there is because it is
/// what a mistyped WIF produces, and then [`crate::PrivateKey::from_wif`]'s own
/// `WrongWifVersion` (what a pasted Bitcoin WIF hits), `WifCompressionFlag` and
/// `WifLength`. A malformed base58 character is the one exception: it is
/// rejected before anything is hashed and leaves nothing. Issue #203 has the
/// addresses.
///
/// The **success** path is not evidence either way, in either direction:
/// `SigningKey::from_slice`'s scalar multiplication runs far deeper on the
/// shadow stack and overwrites that block in passing, so measuring here after a
/// successful decode reads clean whatever this function does. Issue #186
/// records exactly that null, which is how a first attempt at this fix measured
/// as removing nothing.
///
/// So: decode with `check` disabled, into a [`Zeroizing`] `Vec` of ours via
/// `onto`, and compute both hashes here on a hasher this function owns.
///
/// **One owned hasher is the load-bearing part, not the two passes.** `bs58`
/// hashes twice as well, and its block still held the raw frame — because it
/// hashes through `Sha256::digest`, which is `default` + `update` +
/// `finalize(self)`, and `finalize` takes the hasher *by value*. The padding
/// that would have scrubbed the block runs in the moved-to copy while the
/// original slot keeps the frame, which is why the measured survivor is
/// unpadded with a live cursor rather than `digest ‖ 0x80 ‖ zeros ‖ bitlen`.
/// Here there is a single `hasher` binding and `finalize_reset(&mut self)`, so
/// the second pass writes into the same block: its `update` covers `0..32` with
/// the first digest and its `finalize` pads from cursor 32 to the end. See
/// [`encode_check`] for that argument at length, and for what it does not
/// cover — on wasm32 `sha2`'s soft backend takes a 64-byte stack copy of the
/// block inside `compress`, which only a measurement can speak for.
///
/// # What the caller still owns
///
/// The returned `Vec` is a plain copy of the payload and this function cannot
/// wipe it, so the signature stays `(u8, Vec<u8>)` and the obligation stays
/// with whoever asked. [`crate::PrivateKey::from_wif`] moves it into a
/// [`Zeroizing`] on the line after the call, *before* its own version, flag and
/// length checks, so all three of its early exits drop it wiped — that matters,
/// because those are three of the four rejection paths this fix is about.
/// [`crate::Address::from_str`] does not wrap it and does not need to: a
/// hash160 is public.
///
/// Do not weaken any of this on the strength of the reasoning above. It is the
/// reason to expect the result, not the result; what settles it is a
/// before/after over the *rejection* paths with a planted-leak control in the
/// same series, searched in both byte orders — canonical order for this
/// residue, `U256` limb order for the construction spills, neither search alone
/// being a null. The plant has to be published through a live export: a
/// `Box::leak` whose pointer is never read is deleted by the optimizer, and the
/// probe then reads falsely clean.
pub fn decode_check(encoded: &str) -> Result<(u8, Vec<u8>), KeyError> {
    // Ours rather than `bs58`'s: `into_vec()` hands the frame to a `Vec` it
    // allocated and drops it unwiped, including when the decode itself fails.
    // Capacity up front for the reason `encode_check` gives — `onto` resizes
    // this to the input length, and a realloc would copy the frame into a
    // fresh allocation and leave the old one behind.
    let mut data = Zeroizing::new(Vec::with_capacity(encoded.len()));
    bs58::decode(encoded)
        .onto(&mut *data)
        .map_err(|e| KeyError::Base58(e.to_string()))?;

    // The order below is `bs58`'s own `decode_check_into`, deliberately: length
    // first, then checksum, then the version split. base58check is consensus
    // data, so which inputs are accepted — and which error a short frame gets —
    // has to be what it was. Only the two messages change, and a caller has
    // nothing but the string to log: the short-frame one is `bs58`'s verbatim,
    // and the checksum one is its opening clause without the two digests it
    // used to print after it.
    if data.len() < CHECKSUM_LEN {
        return Err(KeyError::Base58(
            "provided string is too small to contain a checksum".into(),
        ));
    }
    let split = data.len() - CHECKSUM_LEN;

    let mut hasher = Sha256::new();
    hasher.update(&data[..split]);
    // Kept in `Zeroizing` to match `encode_check`, where dropping the wrapper
    // measurably left one MORE copy of the scalar alive. The digest is not
    // secret in either place, and that measurement was taken on the encode
    // side — it is not re-measured here, so this is symmetry, not evidence.
    // Same undeclared `GenericArray: Zeroize` note as over there.
    let first = Zeroizing::new(hasher.finalize_reset());
    hasher.update(&first[..]);
    // Second pass eats a digest, not the frame: only the first put key material
    // into the block buffer, and this pass is what clears it.
    let checksum = hasher.finalize_reset();
    // Not a constant-time comparison, and it does not need to be: whether a
    // checksum matches is exactly what this function reports to its caller.
    if checksum[..CHECKSUM_LEN] != data[split..] {
        return Err(KeyError::Base58("invalid checksum".into()));
    }

    let (version, payload) = data[..split]
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
    /// addresses the rest of the world rejects. Nothing in the shipped path
    /// uses `bs58`'s `check` feature any more — [`decode_check`] stopped when
    /// it took the checksum over too — so `with_check()` is linked in for these
    /// tests alone, which is what makes it an independent oracle here rather
    /// than a second copy of the same belief. Keep the feature on for that.
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

    /// And the local *verification* must accept and reject exactly what `bs58`
    /// does, frame for frame.
    ///
    /// The encode-side oracle above cannot see this half: it compares strings
    /// this crate produces, all of which have correct checksums by
    /// construction. What a decoder is for is the inputs that do not — a
    /// mistyped character shifts the whole bignum, so every byte of the frame
    /// changes and the checksum is the only thing standing between a typo and
    /// a payment to an address nobody controls. Disagreeing with `bs58` in
    /// either direction is a consensus bug: accepting more than it does mints
    /// addresses the network rejects, accepting less rejects keys that are
    /// perfectly valid.
    #[test]
    fn the_local_verification_accepts_exactly_what_bs58_accepts() {
        let mut cases: Vec<String> = Vec::new();
        for (version, len) in [(0x3c_u8, 20_usize), (0x80, 33), (0x00, 20), (0xbc, 33)] {
            let good = encode_check(version, &vec![0xa7; len]);
            // Every single-character substitution at three positions, plus the
            // untouched frame.
            for at in [0, good.len() / 2, good.len() - 1] {
                for replacement in ['1', 'z', 'Q', '5'] {
                    let mut chars: Vec<char> = good.chars().collect();
                    chars[at] = replacement;
                    cases.push(chars.into_iter().collect());
                }
            }
            cases.push(good);
        }
        // Frames too short to carry a checksum, an empty string, and text that
        // is not base58 at all.
        cases.extend([
            String::new(),
            "1".into(),
            "111".into(),
            "1111".into(),
            "z".into(),
            "not a wif".into(),
            "0OIl".into(),
        ]);

        for case in cases {
            let ours = decode_check(&case);
            let theirs = bs58::decode(&case).with_check(None).into_vec();
            assert_eq!(
                ours.is_ok(),
                theirs.is_ok(),
                "disagreed with bs58 about {case:?}: {ours:?} vs {theirs:?}"
            );
            if let (Ok((version, payload)), Ok(frame)) = (ours, theirs) {
                assert_eq!(frame[0], version, "version byte, {case:?}");
                assert_eq!(&frame[1..], &payload[..], "payload, {case:?}");
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
