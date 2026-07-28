//! Hashes the Verus wire format needs.

use blake2b_simd::Params;
use sha2::{Digest, Sha256};

/// BLAKE2b-256 with a 16-byte personalization — the ZIP-243 hash construction.
pub fn blake2b_personal(personal: &[u8; 16], data: &[u8]) -> [u8; 32] {
    let hash = Params::new()
        .hash_length(32)
        .personal(personal)
        .to_state()
        .update(data)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// SHA-256 applied twice — the transaction id, in internal byte order.
///
/// Explorers and RPC display txids byte-REVERSED; see [`txid_display`].
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Hex of a 32-byte hash in DISPLAY order (byte-reversed), as RPC prints txids.
pub fn txid_display(txid_internal: &[u8; 32]) -> String {
    let mut bytes = *txid_internal;
    bytes.reverse();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256d_matches_the_known_empty_hash() {
        // SHA256d("") — a value any Bitcoin-lineage implementation agrees on.
        assert_eq!(
            txid_display(&sha256d(b"")),
            "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d"
        );
    }

    #[test]
    fn display_order_is_the_reverse_of_wire_order() {
        let mut internal = [0u8; 32];
        internal[0] = 0xaa;
        internal[31] = 0xbb;
        let shown = txid_display(&internal);
        assert!(shown.starts_with("bb"));
        assert!(shown.ends_with("aa"));
    }
}
