//! base58check with a leading version byte.

use crate::error::KeyError;

/// Encode `payload` as base58check with `version` prepended.
pub fn encode_check(version: u8, payload: &[u8]) -> String {
    let mut data = Vec::with_capacity(payload.len() + 1);
    data.push(version);
    data.extend_from_slice(payload);
    bs58::encode(&data).with_check().into_string()
}

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
