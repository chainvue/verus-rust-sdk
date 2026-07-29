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

/// `SIGHASH_ALL` — commits to every input and every output. The default, and
/// the only sane choice for an ordinary payment.
pub const SIGHASH_ALL: u32 = 1;
/// `SIGHASH_NONE` — commits to the inputs but to **no outputs at all**.
///
/// Anyone who holds the signed transaction can redirect every output. Only
/// meaningful when something else constrains where the money goes.
pub const SIGHASH_NONE: u32 = 2;
/// `SIGHASH_SINGLE` — commits to only the output at the same index as the input
/// being signed.
///
/// The basis of an offer: "I sign that I spend this and that output N pays me",
/// leaving every other output for a counterparty to fill in.
///
/// **A signature is invalid if there is no output at that index.** Bitcoin
/// famously returns the hash `1` in that case; ZIP-243 specifies a zero
/// `hashOutputs` instead, which is what Verus does — but the resulting signature
/// commits to nothing about the outputs, so this crate refuses to produce one.
pub const SIGHASH_SINGLE: u32 = 3;
/// `SIGHASH_ANYONECANPAY` — a modifier: commit to **only the input being
/// signed**, so anyone may add inputs of their own.
///
/// Combined with [`SIGHASH_SINGLE`] this is how a half-signed trade is
/// expressed: the signer commits to what they give and what they take, and a
/// counterparty supplies the rest.
pub const SIGHASH_ANYONECANPAY: u32 = 0x80;
/// The bits that select the base type, with [`SIGHASH_ANYONECANPAY`] masked off.
pub const SIGHASH_MASK: u32 = 0x1f;

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
