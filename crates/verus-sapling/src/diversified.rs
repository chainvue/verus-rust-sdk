//! Many addresses, one key.
//!
//! A Sapling key does not have *an* address. It has 2^88 of them, indexed by a
//! **diversifier index**, and they are cryptographically unlinkable: without the
//! incoming viewing key, nothing about two of this wallet's addresses reveals
//! that they belong to the same wallet.
//!
//! Until now this crate exposed only [`default_address`](crate::derive), so
//! every payment a wallet received arrived at the same string. That is a real
//! privacy loss and it has nothing to do with the shielded pool: an address
//! reused across a forum post, an invoice and a donation page links those three
//! contexts to each other in public, before any transaction is even made.
//!
//! # The property that makes this cheap
//!
//! Every diversified address shares **one** incoming viewing key. Detection
//! works by trial-decrypting with that ivk, and the diversifier comes back out
//! of the note plaintext — so a wallet that hands out a thousand addresses
//! still does exactly one scan, and [`detect_notes`](crate::scan::detect_notes)
//! already finds notes to all of them with no changes.
//!
//! That is not an assumption here; `a_note_to_a_diversified_address_is_detected`
//! builds a real note to a non-default address and finds it.
//!
//! # Roughly half of all indices are invalid
//!
//! A diversifier is only usable if hashing it lands on a valid Jubjub group
//! element, which happens about half the time. So [`address_at`] returns
//! `Option`, and a wallet walking indices in order should use [`find_address`]
//! or [`addresses`] rather than assuming index *n* yields the *n*th address.
//!
//! This is also why the "default" address is not necessarily index 0 — it is the
//! address at the first *valid* index.
//!
//! # Losing the index is recoverable
//!
//! A wallet should record which index it handed to whom. If it does not, nothing
//! is lost: funds still arrive and still scan, and [`index_of`] recovers the
//! index from the address itself. That is worth stating plainly because the
//! other "write this down" value in this SDK — a name-commitment salt — is
//! **not** recoverable, and the two should not be filed under the same caution.

use sapling_crypto::zip32::DiversifiableFullViewingKey;
use sapling_crypto::PaymentAddress;
use zip32::DiversifierIndex;

use crate::error::SaplingError;

/// The largest diversifier index. Indices are 88-bit.
pub const MAX_DIVERSIFIER_INDEX: u128 = (1 << 88) - 1;

/// The address at exactly this index, or `None` if the index has no valid
/// diversifier.
///
/// About half of all indices do not, which is normal and not an error — see the
/// module docs. Use [`find_address`] to skip to the next usable one.
pub fn address_at(
    dfvk: &DiversifiableFullViewingKey,
    index: u128,
) -> Result<Option<[u8; 43]>, SaplingError> {
    Ok(dfvk
        .address(diversifier_index(index)?)
        .map(|address| address.to_bytes()))
}

/// The next usable address at or after `from`.
///
/// What a wallet actually wants: "give me a fresh address", with the invalid
/// indices skipped. Returns `None` only if the whole remaining range is
/// exhausted, which for any realistic starting point does not happen.
pub fn find_address(
    dfvk: &DiversifiableFullViewingKey,
    from: u128,
) -> Result<Option<(u128, [u8; 43])>, SaplingError> {
    Ok(dfvk
        .find_address(diversifier_index(from)?)
        .map(|(index, address)| (to_u128(&index), address.to_bytes())))
}

/// Which index produced this address, if it belongs to this key.
///
/// Two uses. A wallet that lost its records recovers them without a scan. And
/// given somebody else's address, `None` answers "is this one of mine?" —
/// useful before treating an address as a change target.
///
/// This needs the viewing key, which is the point: an observer holding two of
/// this wallet's addresses cannot do the same and learn they are related.
pub fn index_of(
    dfvk: &DiversifiableFullViewingKey,
    address: &[u8; 43],
) -> Result<Option<u128>, SaplingError> {
    let address = PaymentAddress::from_bytes(address)
        .ok_or_else(|| SaplingError::Address("not a valid Sapling payment address".into()))?;
    Ok(dfvk.decrypt_diversifier(&address).map(|(j, _)| to_u128(&j)))
}

/// Usable addresses in index order, starting at `from`.
///
/// Skips the invalid indices. Finite in principle and effectively endless in
/// practice, so take what you need:
///
/// ```
/// # use verus_sapling::{derive::{derive_account, COIN_TYPE_MAINNET}, scan::dfvk_from_extsk};
/// # use verus_sapling::diversified::addresses;
/// # let account = derive_account(&[7u8; 64], COIN_TYPE_MAINNET, 0).unwrap();
/// # let dfvk = dfvk_from_extsk(&*account.extsk).unwrap();
/// let batch: Vec<_> = addresses(&dfvk, 0).take(5).collect();
/// assert_eq!(batch.len(), 5);
/// // All different, and all belonging to the same key.
/// let distinct: std::collections::HashSet<_> = batch.iter().map(|(_, a)| *a).collect();
/// assert_eq!(distinct.len(), 5);
/// ```
pub fn addresses(
    dfvk: &DiversifiableFullViewingKey,
    from: u128,
) -> impl Iterator<Item = (u128, [u8; 43])> + '_ {
    let mut next = Some(from);
    core::iter::from_fn(move || {
        let start = next?;
        match find_address(dfvk, start) {
            Ok(Some((index, address))) => {
                // Step past the one just returned; stop at the end of the range
                // rather than wrapping back to the start.
                next = index.checked_add(1).filter(|n| *n <= MAX_DIVERSIFIER_INDEX);
                Some((index, address))
            }
            _ => {
                next = None;
                None
            }
        }
    })
}

/// Convert a `u128` index into the 88-bit form ZIP-32 uses.
fn diversifier_index(index: u128) -> Result<DiversifierIndex, SaplingError> {
    if index > MAX_DIVERSIFIER_INDEX {
        return Err(SaplingError::Derivation(format!(
            "diversifier index {index} exceeds the 88-bit range"
        )));
    }
    let bytes = index.to_le_bytes();
    let mut eleven = [0u8; 11];
    eleven.copy_from_slice(&bytes[..11]);
    Ok(DiversifierIndex::from(eleven))
}

fn to_u128(index: &DiversifierIndex) -> u128 {
    let mut bytes = [0u8; 16];
    bytes[..11].copy_from_slice(index.as_bytes());
    u128::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::{derive_account, COIN_TYPE_MAINNET};
    use crate::scan::dfvk_from_extsk;

    fn key() -> DiversifiableFullViewingKey {
        let account = derive_account(&[7u8; 64], COIN_TYPE_MAINNET, 0).expect("derive");
        dfvk_from_extsk(&*account.extsk).expect("dfvk")
    }

    /// The default address is the first *valid* index, which is not necessarily
    /// zero — the assumption a wallet makes if it treats index 0 as special.
    #[test]
    fn the_default_address_is_the_first_valid_index() {
        let dfvk = key();
        let (index, address) = find_address(&dfvk, 0).unwrap().expect("an address");
        assert_eq!(address, dfvk.default_address().1.to_bytes());
        assert_eq!(index, to_u128(&dfvk.default_address().0));
    }

    /// Roughly half of all indices have no valid diversifier. If this ever finds
    /// none in a thousand tries, `address_at` has stopped checking.
    #[test]
    fn about_half_of_all_indices_are_unusable() {
        let dfvk = key();
        let usable = (0..1_000u128)
            .filter(|i| address_at(&dfvk, *i).unwrap().is_some())
            .count();
        assert!(
            (350..650).contains(&usable),
            "{usable} of 1000 indices were usable, which is not close to half"
        );
    }

    /// Different indices give different addresses. Sharing a `pk_d` would make
    /// two addresses linkable on sight and defeat the entire point.
    #[test]
    fn every_address_is_distinct_including_its_public_key() {
        let dfvk = key();
        let batch: Vec<_> = addresses(&dfvk, 0).take(50).collect();
        assert_eq!(batch.len(), 50);

        let whole: std::collections::HashSet<_> = batch.iter().map(|(_, a)| *a).collect();
        assert_eq!(whole.len(), 50, "two indices produced the same address");

        // The diversifier is the first 11 bytes and pk_d the remaining 32. Both
        // must differ, not just the diversifier.
        let keys: std::collections::HashSet<_> =
            batch.iter().map(|(_, a)| a[11..].to_vec()).collect();
        assert_eq!(keys.len(), 50, "two addresses shared a public key");
    }

    /// Indices come back in increasing order and none is repeated.
    #[test]
    fn the_iterator_advances_and_does_not_repeat() {
        let dfvk = key();
        let indices: Vec<u128> = addresses(&dfvk, 0).take(30).map(|(i, _)| i).collect();
        assert!(indices.windows(2).all(|w| w[0] < w[1]), "{indices:?}");
    }

    /// Starting further along gives a different set — the index is honoured
    /// rather than ignored.
    #[test]
    fn starting_elsewhere_gives_different_addresses() {
        let dfvk = key();
        let (_, first) = find_address(&dfvk, 0).unwrap().unwrap();
        let (index, later) = find_address(&dfvk, 1_000).unwrap().unwrap();
        assert!(index >= 1_000);
        assert_ne!(first, later);
    }

    /// The recovery property: an address alone is enough to recover its index,
    /// given the viewing key. A wallet that loses its records is inconvenienced,
    /// not broken.
    #[test]
    fn an_index_can_be_recovered_from_its_address() {
        let dfvk = key();
        for (index, address) in addresses(&dfvk, 0).take(20) {
            assert_eq!(index_of(&dfvk, &address).unwrap(), Some(index));
        }
    }

    /// Someone else's address is not ours, and asking must not claim it is.
    #[test]
    fn a_foreign_address_has_no_index_under_our_key() {
        let ours = key();
        let theirs = {
            let account = derive_account(&[9u8; 64], COIN_TYPE_MAINNET, 0).unwrap();
            dfvk_from_extsk(&*account.extsk).unwrap()
        };
        let (_, foreign) = find_address(&theirs, 0).unwrap().unwrap();
        assert_eq!(index_of(&ours, &foreign).unwrap(), None);
    }

    /// Derivation is deterministic: the same key and index always give the same
    /// address, or a wallet cannot re-derive what it handed out.
    #[test]
    fn the_same_index_always_gives_the_same_address() {
        let first: Vec<_> = addresses(&key(), 0).take(10).collect();
        let second: Vec<_> = addresses(&key(), 0).take(10).collect();
        assert_eq!(first, second);
    }

    /// The 88-bit boundary is refused rather than silently truncated — a
    /// truncating conversion would map two indices onto one address.
    #[test]
    fn an_index_beyond_the_range_is_refused() {
        let dfvk = key();
        assert!(address_at(&dfvk, MAX_DIVERSIFIER_INDEX).is_ok());
        assert!(address_at(&dfvk, MAX_DIVERSIFIER_INDEX + 1).is_err());
        assert!(address_at(&dfvk, u128::MAX).is_err());
    }

    /// Every generated address must survive the `zs…` round trip a user pastes.
    #[test]
    fn diversified_addresses_encode_as_zs_addresses() {
        for (_, address) in addresses(&key(), 0).take(10) {
            let encoded = crate::zaddr::encode(&address).expect("encode");
            assert!(encoded.starts_with("zs1"));
            assert_eq!(crate::zaddr::decode(&encoded).expect("decode"), address);
        }
    }

    /// The claim the whole module rests on: one scan finds notes to *every*
    /// diversified address, because they share one incoming viewing key.
    ///
    /// Built as a real note and detected, rather than asserted in prose.
    #[test]
    fn a_note_to_a_diversified_address_is_detected() {
        use crate::scan::{detect_notes, CompactOutput, TreeStateBefore};
        use sapling_crypto::note_encryption::{
            sapling_note_encryption, SaplingDomain, Zip212Enforcement,
        };
        use sapling_crypto::value::NoteValue;
        use sapling_crypto::{Note, Rseed};

        let dfvk = key();
        // Deliberately NOT the default address — the 5th usable one.
        let (index, recipient) = addresses(&dfvk, 0).nth(4).expect("an address");
        assert_ne!(recipient, dfvk.default_address().1.to_bytes());

        let address = PaymentAddress::from_bytes(&recipient).expect("valid address");
        let note = Note::from_parts(
            address,
            NoteValue::from_raw(123_456),
            Rseed::AfterZip212([3u8; 32]),
        );

        let encryptor =
            sapling_note_encryption(None, note.clone(), [0u8; 512], &mut rand::rngs::OsRng);
        let enc = encryptor.encrypt_note_plaintext();
        let mut ciphertext = [0u8; 52];
        ciphertext.copy_from_slice(&enc[..52]);

        let output = CompactOutput {
            height: 1,
            tx_index: 0,
            output_index: 0,
            cmu: note.cmu().to_bytes(),
            epk: <SaplingDomain as zcash_note_encryption::Domain>::epk_bytes(encryptor.epk()).0,
            ciphertext,
        };

        // An empty tree: this note is the first commitment anywhere.
        let empty = TreeStateBefore {
            left: None,
            right: None,
            parents: Vec::new(),
        };

        let found = detect_notes(&dfvk, &empty, &[output], Zip212Enforcement::On).expect("detect");

        assert_eq!(found.len(), 1, "the note was not detected");
        assert_eq!(found[0].value, 123_456);
        assert_eq!(
            found[0].recipient, recipient,
            "detected, but attributed to the wrong address"
        );
        // And the wallet can tell which address was paid.
        assert_eq!(index_of(&dfvk, &found[0].recipient).unwrap(), Some(index));
    }
}
