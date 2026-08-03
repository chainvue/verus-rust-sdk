//! Currency ids, distinguishable from the other twenty-byte things.
//!
//! A currency id is the 20 bytes behind an `i` address — and so is an identity
//! id, and so is a script hash. They are the same shape, they are used side by
//! side, and until now they were the same *type*, so nothing stopped one being
//! passed where another belonged.
//!
//! That is not hypothetical here. A sub-identity's registration fee is paid in
//! the parent's currency, and the parent is an identity that is *also* a
//! currency — the same twenty bytes wearing both hats. The code that builds that
//! fee output has to convert between the two readings, and with a bare
//! `[u8; 20]` the conversion is invisible: it looks like passing a value along.
//! With a newtype it has to be written down, which is the point.
//!
//! The conversion is deliberately explicit rather than a `From` impl, so that
//! every place the two meanings coincide is greppable.

/// The 20 bytes identifying a currency.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CurrencyId([u8; 20]);

impl CurrencyId {
    /// From the 20 bytes behind an `i` address.
    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        CurrencyId(bytes)
    }

    /// The 20 bytes, for hashing into a script.
    pub const fn to_bytes(self) -> [u8; 20] {
        self.0
    }

    /// Read the currency an identity id names, when that identity is also a
    /// currency.
    ///
    /// Only true for an identity that has launched one — a sub-identity's
    /// parent, typically. Calling it on an ordinary VerusID produces a currency
    /// id that names nothing, and the daemon rejects whatever it is used for.
    /// Named rather than inferred so the assumption is visible at the call site.
    pub const fn of_identity(identity: [u8; 20]) -> Self {
        CurrencyId(identity)
    }
}

impl core::fmt::Display for CurrencyId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_its_bytes() {
        let id = CurrencyId::from_bytes([0x2b; 20]);
        assert_eq!(id.to_bytes(), [0x2b; 20]);
    }

    /// The coincidence the type exists to make visible: a parent identity and
    /// the currency it launched are the same bytes, and reading one as the other
    /// is a decision rather than an accident.
    #[test]
    fn an_identity_that_launched_a_currency_reads_as_both() {
        let identity = [0x9a; 20];
        assert_eq!(CurrencyId::of_identity(identity).to_bytes(), identity);
    }

    #[test]
    fn displays_as_hex() {
        assert_eq!(
            CurrencyId::from_bytes([0xab; 20]).to_string(),
            "ab".repeat(20)
        );
    }
}
