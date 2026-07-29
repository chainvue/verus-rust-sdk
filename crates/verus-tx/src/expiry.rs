//! When a transaction stops being minable.
//!
//! `expiryHeight` is a Verus/Zcash field with a trap in it: **zero means never
//! expires**. Every example in this repository passed `0`, which is the one
//! value a wallet should almost never choose.
//!
//! A transaction that never expires can be mined at any height, forever. The
//! failure that produces is not theoretical: a payment that does not confirm —
//! fee too low, a node that dropped it, a wallet restarted mid-broadcast — stays
//! valid indefinitely. The user gives up, spends the same coins elsewhere, and
//! then the original lands months later if any of its inputs are still unspent.
//! With an expiry, the transaction simply dies and the coins are provably free.
//!
//! So this type has no default. [`Expiry::Never`] still exists, because it is
//! legal and occasionally wanted, but it has to be *written*, and reading it in
//! a diff should prompt the question.
//!
//! ```
//! use verus_tx::Expiry;
//!
//! // A wallet that knows the chain tip:
//! let expiry = Expiry::within(1_167_200, 20);
//! assert_eq!(expiry.to_height(), 1_167_220);
//!
//! // Deliberate, and visible as such:
//! assert_eq!(Expiry::Never.to_height(), 0);
//! ```

use crate::error::TxError;

/// Verus rejects an expiry at or above this height.
pub const EXPIRY_HEIGHT_THRESHOLD: u32 = 500_000_000;

/// How many blocks ahead a wallet conventionally sets the expiry.
///
/// The value Verus's own wallets use. At roughly one block a minute it gives a
/// transaction about twenty minutes to confirm, which is long enough for a
/// normal fee and short enough that a stuck payment does not linger.
pub const DEFAULT_EXPIRY_BLOCKS: u32 = 20;

/// When a transaction stops being minable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Expiry {
    /// Valid forever. Serializes as `0`.
    ///
    /// Legal, and occasionally what you want — a transaction being co-signed
    /// over days cannot expire while it waits. For an ordinary payment it is the
    /// wrong answer: see the module docs.
    Never,
    /// Invalid once the chain passes this height.
    AtHeight(u32),
}

impl Expiry {
    /// `blocks` after the current tip.
    ///
    /// The usual choice. Pair with [`DEFAULT_EXPIRY_BLOCKS`] unless there is a
    /// reason to differ.
    pub fn within(current_height: u32, blocks: u32) -> Self {
        Expiry::AtHeight(current_height.saturating_add(blocks))
    }

    /// The value that goes on the wire.
    pub fn to_height(self) -> u32 {
        match self {
            Expiry::Never => 0,
            Expiry::AtHeight(height) => height,
        }
    }

    /// Read a wire value back. `0` is [`Expiry::Never`].
    pub fn from_height(height: u32) -> Self {
        match height {
            0 => Expiry::Never,
            height => Expiry::AtHeight(height),
        }
    }

    /// Refuse a height consensus will not accept.
    pub fn check(self) -> Result<(), TxError> {
        match self {
            Expiry::AtHeight(height) if height >= EXPIRY_HEIGHT_THRESHOLD => {
                Err(TxError::ExpiryHeightTooLarge(height))
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_is_zero_on_the_wire() {
        assert_eq!(Expiry::Never.to_height(), 0);
        assert_eq!(Expiry::from_height(0), Expiry::Never);
    }

    #[test]
    fn a_height_round_trips() {
        assert_eq!(Expiry::from_height(1_167_220), Expiry::AtHeight(1_167_220));
        assert_eq!(Expiry::AtHeight(1_167_220).to_height(), 1_167_220);
    }

    #[test]
    fn within_counts_from_the_tip() {
        assert_eq!(Expiry::within(1_167_200, 20), Expiry::AtHeight(1_167_220));
    }

    /// Saturating rather than wrapping: an absurd offset must not wrap around to
    /// a low height, which would produce a transaction that is already expired
    /// and looks deliberate.
    #[test]
    fn an_absurd_offset_saturates_instead_of_wrapping() {
        assert_eq!(
            Expiry::within(u32::MAX - 1, 100),
            Expiry::AtHeight(u32::MAX)
        );
    }

    #[test]
    fn refuses_a_height_consensus_rejects() {
        assert!(Expiry::AtHeight(EXPIRY_HEIGHT_THRESHOLD).check().is_err());
        assert!(Expiry::AtHeight(EXPIRY_HEIGHT_THRESHOLD - 1)
            .check()
            .is_ok());
        // Never is 0 on the wire, which is always below the threshold.
        assert!(Expiry::Never.check().is_ok());
    }
}
