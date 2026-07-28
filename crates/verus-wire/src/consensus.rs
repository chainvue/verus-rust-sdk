//! Consensus constants for Verus v4 (Sapling) transactions.

/// Overwintered v4 header word: the overwintered bit set, version 4.
///
/// Note this is the *header*, not the raw version — the sighash preimage and the
/// serialized transaction both commit to this word, not to `4`.
pub const V4_HEADER: u32 = 0x8000_0004;

/// Sapling version group id.
pub const SAPLING_VERSION_GROUP_ID: u32 = 0x892f_2085;

/// Verus consensus branch id — the *only* Verus-specific value in the entire
/// consensus path, injected into the sighash personalization.
///
/// It is the same on mainnet and on VRSCTEST: Verus consensus is frozen at
/// Sapling on both networks, so there is no branch-id-based network separation.
///
/// Watch the decimal form: `0x76b809bb` is 1_991_772_603. A historical typo of
/// 1_991_772_091 (`0x76b807bb`) produced transactions the daemon rejected with
/// `bad-txns-sapling-binding-signature-invalid`.
pub const VERUS_BRANCH_ID: u32 = 0x76b8_09bb;

/// `SIGHASH_ALL` — the only hash type this crate signs with today.
pub const SIGHASH_ALL: u32 = 1;

/// ZIP-243 BLAKE2b personalization for the prevouts hash.
pub const PREVOUT_PERSONAL: &[u8; 16] = b"ZcashPrevoutHash";
/// ZIP-243 BLAKE2b personalization for the sequence hash.
pub const SEQUENCE_PERSONAL: &[u8; 16] = b"ZcashSequencHash";
/// ZIP-243 BLAKE2b personalization for the outputs hash.
pub const OUTPUTS_PERSONAL: &[u8; 16] = b"ZcashOutputsHash";
/// ZIP-243 BLAKE2b personalization for the shielded-spends hash.
pub const SHIELDED_SPENDS_PERSONAL: &[u8; 16] = b"ZcashSSpendsHash";
/// ZIP-243 BLAKE2b personalization for the shielded-outputs hash.
pub const SHIELDED_OUTPUTS_PERSONAL: &[u8; 16] = b"ZcashSOutputHash";

/// First 12 bytes of the sighash personalization; the branch id (4 bytes, LE)
/// completes it to the 16 bytes BLAKE2b requires.
pub const SIGHASH_PREFIX: &[u8; 12] = b"ZcashSigHash";

/// The 16-byte sighash personalization for a consensus branch.
pub fn sighash_personal(branch_id: u32) -> [u8; 16] {
    let mut personal = [0u8; 16];
    personal[..12].copy_from_slice(SIGHASH_PREFIX);
    personal[12..].copy_from_slice(&branch_id.to_le_bytes());
    personal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_id_decimal_is_the_one_the_daemon_accepts() {
        // Pins the value whose decimal form has been mistyped before.
        assert_eq!(VERUS_BRANCH_ID, 1_991_772_603);
    }

    #[test]
    fn sighash_personalization_is_prefix_then_branch_le() {
        assert_eq!(
            sighash_personal(VERUS_BRANCH_ID),
            *b"ZcashSigHash\xbb\x09\xb8\x76"
        );
    }
}
