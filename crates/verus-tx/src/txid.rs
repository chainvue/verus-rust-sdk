//! Transaction ids, with the byte order made explicit.
//!
//! Verus (like Bitcoin) displays transaction ids **byte-reversed** from the
//! order they appear in the wire format. Mixing the two is a classic and
//! expensive bug — it produces a transaction that spends nothing, or spends the
//! wrong output — so this type refuses to let a caller be vague about which one
//! they have.

use core::fmt;
use core::str::FromStr;

use crate::error::TxError;

/// A transaction id, stored in internal (wire) order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Txid([u8; 32]);

impl Txid {
    /// From wire-order bytes.
    pub fn from_internal(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// From the hex an explorer or RPC shows.
    pub fn from_display_hex(hex_str: &str) -> Result<Self, TxError> {
        let mut bytes = [0u8; 32];
        let decoded =
            hex::decode(hex_str).map_err(|e| TxError::InvalidTxid(format!("not hex: {e}")))?;
        if decoded.len() != 32 {
            return Err(TxError::InvalidTxid(format!(
                "expected 32 bytes, got {}",
                decoded.len()
            )));
        }
        bytes.copy_from_slice(&decoded);
        bytes.reverse();
        Ok(Self(bytes))
    }

    /// Wire-order bytes.
    pub fn to_internal(self) -> [u8; 32] {
        self.0
    }

    /// The hex an explorer or RPC shows.
    pub fn to_display_hex(self) -> String {
        let mut bytes = self.0;
        bytes.reverse();
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl fmt::Display for Txid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_display_hex())
    }
}

impl FromStr for Txid {
    type Err = TxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_display_hex(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_internal_are_reverses() {
        let displayed = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let txid = Txid::from_display_hex(displayed).unwrap();
        assert_eq!(txid.to_display_hex(), displayed);
        assert_eq!(txid.to_internal()[0], 0x99);
    }

    #[test]
    fn rejects_a_short_txid() {
        assert!(matches!(
            Txid::from_display_hex("aabb"),
            Err(TxError::InvalidTxid(_))
        ));
    }
}
