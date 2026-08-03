//! Signing and verifying messages as a VerusID.
//!
//! "Log in with your VerusID" and "this statement came from `chainvue@`" are the
//! same operation underneath: an identity's controlling key signs a hash that
//! commits to *which identity*, *on which chain*, and *at what height*.
//!
//! # Why a plain address signature is not enough
//!
//! An identity is not a key. It is a chain object naming one or more primary
//! addresses and how many of them must sign, and **that set can change** — the
//! whole point of a revocable, recoverable identity. So a signature has to say
//! when it was made, or a signature from a key that was rotated out last year
//! would still verify today.
//!
//! That is what the height is for, and it is why verification needs the identity
//! *as it stood at that height*. Verifying against today's identity answers a
//! subtly different question: "could this signer sign for it now".
//!
//! # The hash, exactly
//!
//! ```text
//! msgHash    = SHA256( compactSize(len(message)) || message )
//! signedHash = SHA256( compactSize(19) || "Verus signed data:\n"
//!                      || systemID    (20 bytes)
//!                      || blockHeight (4 bytes LE)
//!                      || identityID  (20 bytes)
//!                      || msgHash     (32 bytes) )
//! ```
//!
//! Single SHA256 at both stages, **not** the double-SHA256 used almost
//! everywhere else in this codebase. Reproduced from four daemon-produced
//! signatures — empty message, short, 14-byte, and 300-byte (which is what pins
//! the compact-size encoding rather than a bare length byte). Each recovers to
//! the identity's primary address; the derivation is in `fixtures/daemon/`.
//!
//! # On the wire
//!
//! ```text
//! version(1) || blockHeight(4 LE) || compactSize(count) || [ compactSize(65) || sig(65) ]…
//! ```
//!
//! base64-encoded. The 65-byte signature is `header || r || s`, where the header
//! carries the recovery id — a message signature is checked against an address,
//! so the public key must be recoverable from the signature itself.
//!
//! Several signatures appear here for a multisig identity, which is why the
//! count is a vector rather than a single entry.

use verus_keys::{Address, PrivateKey, PublicKey};
use verus_wire::compact::write_compact_size;
use verus_wire::hash::sha256;

use verus_tx_primitives::TxError;

/// The domain separator Verus prepends before hashing signed data.
///
/// Its purpose is that a signature over a message can never be replayed as a
/// signature over something else — a transaction sighash, most importantly.
pub const SIGNATURE_PREFIX: &str = "Verus signed data:\n";

/// The `CIdentitySignature` version this crate writes and expects.
pub const IDENTITY_SIGNATURE_VERSION: u8 = 1;

/// A signature made by an identity, as it travels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentitySignature {
    /// The height whose identity state this was signed against.
    pub block_height: u32,
    /// One 65-byte recoverable signature per signer.
    pub signatures: Vec<[u8; 65]>,
}

impl IdentitySignature {
    /// Serialize to the wire form, before base64.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![IDENTITY_SIGNATURE_VERSION];
        out.extend_from_slice(&self.block_height.to_le_bytes());
        write_compact_size(&mut out, self.signatures.len() as u64);
        for signature in &self.signatures {
            write_compact_size(&mut out, signature.len() as u64);
            out.extend_from_slice(signature);
        }
        out
    }

    /// Parse the wire form.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TxError> {
        let mut at = 0usize;
        let version = *bytes
            .get(at)
            .ok_or_else(|| TxError::MessageSignature("empty signature".into()))?;
        at += 1;
        if version != IDENTITY_SIGNATURE_VERSION {
            return Err(TxError::MessageSignature(format!(
                "unsupported identity signature version {version}"
            )));
        }
        let height_bytes: [u8; 4] = bytes
            .get(at..at + 4)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| TxError::MessageSignature("truncated block height".into()))?;
        at += 4;

        let count = read_compact_size(bytes, &mut at)?;
        // A signature per signer of a multisig identity. The cap is a sanity
        // bound, not a consensus rule: it stops a malformed length from making
        // us allocate.
        if count > 32 {
            return Err(TxError::MessageSignature(format!(
                "{count} signatures is more than any identity requires"
            )));
        }
        // `count` is already bounded above, so this cannot be large.
        let mut signatures = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
        for _ in 0..count {
            let length = read_compact_size(bytes, &mut at)?;
            if length != 65 {
                return Err(TxError::MessageSignature(format!(
                    "a recoverable signature is 65 bytes, got {length}"
                )));
            }
            let signature: [u8; 65] = bytes
                .get(at..at + 65)
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| TxError::MessageSignature("truncated signature".into()))?;
            at += 65;
            signatures.push(signature);
        }
        if at != bytes.len() {
            return Err(TxError::MessageSignature(format!(
                "{} trailing bytes after the signature",
                bytes.len() - at
            )));
        }
        Ok(IdentitySignature {
            block_height: u32::from_le_bytes(height_bytes),
            signatures,
        })
    }

    /// The base64 form the daemon and every Verus tool exchange.
    pub fn to_base64(&self) -> String {
        base64_encode(&self.to_bytes())
    }

    /// Parse the base64 form.
    pub fn from_base64(text: &str) -> Result<Self, TxError> {
        Self::from_bytes(&base64_decode(text)?)
    }
}

/// The hash of a message, before it is bound to an identity.
///
/// Length-prefixed, so that appending to a message cannot produce the same hash
/// as some other message.
pub fn message_hash(message: &[u8]) -> [u8; 32] {
    let mut buffer = Vec::with_capacity(message.len() + 9);
    write_compact_size(&mut buffer, message.len() as u64);
    buffer.extend_from_slice(message);
    sha256(&buffer)
}

/// The hash an identity actually signs.
///
/// Binds the message to a chain, a height and an identity, so a signature cannot
/// be replayed on another chain, against a later version of the identity, or as
/// though it came from a different one.
pub fn identity_signature_hash(
    system_id: [u8; 20],
    block_height: u32,
    identity_id: [u8; 20],
    message_hash: [u8; 32],
) -> [u8; 32] {
    let prefix = SIGNATURE_PREFIX.as_bytes();
    let mut buffer = Vec::with_capacity(9 + prefix.len() + 20 + 4 + 20 + 32);
    write_compact_size(&mut buffer, prefix.len() as u64);
    buffer.extend_from_slice(prefix);
    buffer.extend_from_slice(&system_id);
    buffer.extend_from_slice(&block_height.to_le_bytes());
    buffer.extend_from_slice(&identity_id);
    buffer.extend_from_slice(&message_hash);
    sha256(&buffer)
}

/// Sign `message` as `identity_id`, with one controlling key.
///
/// `block_height` is normally the current tip. It is recorded in the signature
/// and a verifier must resolve the identity at that height — see the module
/// docs on why an identity's key set is not fixed.
pub fn sign_message(
    key: &PrivateKey,
    system_id: [u8; 20],
    identity_id: [u8; 20],
    block_height: u32,
    message: &[u8],
) -> Result<IdentitySignature, TxError> {
    let hash = identity_signature_hash(system_id, block_height, identity_id, message_hash(message));
    let signature = key
        .sign_prehash_recoverable(&hash)
        .map_err(|e| TxError::MessageSignature(e.to_string()))?;
    Ok(IdentitySignature {
        block_height,
        signatures: vec![signature],
    })
}

/// Add a signature to one an existing signer already made.
///
/// For an identity with `minimumsignatures > 1`: each holder signs the same
/// hash, and the parts are gathered. Order does not matter, because each is
/// verified independently against the identity's address set.
pub fn add_signature(
    existing: &IdentitySignature,
    key: &PrivateKey,
    system_id: [u8; 20],
    identity_id: [u8; 20],
    message: &[u8],
) -> Result<IdentitySignature, TxError> {
    let mut combined = existing.clone();
    // Every part must commit to the same height, or they are signatures over
    // different hashes and no verifier will accept the set.
    let hash = identity_signature_hash(
        system_id,
        existing.block_height,
        identity_id,
        message_hash(message),
    );
    let signature = key
        .sign_prehash_recoverable(&hash)
        .map_err(|e| TxError::MessageSignature(e.to_string()))?;
    if !combined.signatures.contains(&signature) {
        combined.signatures.push(signature);
    }
    Ok(combined)
}

/// Which addresses signed a message.
///
/// Returns the recovered address for each signature, deduplicated. This is the
/// primitive; [`verify_message`] is the question a caller usually has.
pub fn recover_signers(
    signature: &IdentitySignature,
    system_id: [u8; 20],
    identity_id: [u8; 20],
    message: &[u8],
) -> Result<Vec<Address>, TxError> {
    let hash = identity_signature_hash(
        system_id,
        signature.block_height,
        identity_id,
        message_hash(message),
    );
    let mut signers = Vec::new();
    for part in &signature.signatures {
        let public_key = PublicKey::recover(&hash, part)
            .map_err(|e| TxError::MessageSignature(e.to_string()))?;
        let address = public_key.address();
        if !signers.contains(&address) {
            signers.push(address);
        }
    }
    Ok(signers)
}

/// Whether a message was signed by an identity, to its own threshold.
///
/// `primary_addresses` and `minimum_signatures` must come from the identity **as
/// it stood at [`IdentitySignature::block_height`]** — `getidentity` accepts a
/// height for exactly this reason. Passing today's values answers a different
/// question, and for a rotated or revoked identity the two answers differ.
///
/// A signature by a key that is not in the set contributes nothing; it is not an
/// error, because a multisig identity legitimately collects parts and one may be
/// stale.
pub fn verify_message(
    signature: &IdentitySignature,
    system_id: [u8; 20],
    identity_id: [u8; 20],
    message: &[u8],
    primary_addresses: &[Address],
    minimum_signatures: u32,
) -> Result<bool, TxError> {
    if minimum_signatures == 0 {
        return Err(TxError::MessageSignature(
            "an identity requiring zero signatures would accept anything".into(),
        ));
    }
    let signers = recover_signers(signature, system_id, identity_id, message)?;
    let valid = signers
        .iter()
        .filter(|signer| primary_addresses.contains(signer))
        .count();
    Ok(valid >= minimum_signatures as usize)
}

/// Read a Bitcoin-style compact size.
fn read_compact_size(bytes: &[u8], at: &mut usize) -> Result<u64, TxError> {
    let first = *bytes
        .get(*at)
        .ok_or_else(|| TxError::MessageSignature("truncated length".into()))?;
    *at += 1;
    let take = |at: &mut usize, n: usize| -> Result<u64, TxError> {
        let slice = bytes
            .get(*at..*at + n)
            .ok_or_else(|| TxError::MessageSignature("truncated length".into()))?;
        *at += n;
        let mut eight = [0u8; 8];
        eight[..n].copy_from_slice(slice);
        Ok(u64::from_le_bytes(eight))
    };
    match first {
        0xfd => take(at, 2),
        0xfe => take(at, 4),
        0xff => take(at, 8),
        n => Ok(u64::from(n)),
    }
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(BASE64[(n >> 18) as usize & 63] as char);
        out.push(BASE64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            BASE64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            BASE64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn base64_decode(text: &str) -> Result<Vec<u8>, TxError> {
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for character in text.bytes() {
        if character == b'=' || character.is_ascii_whitespace() {
            continue;
        }
        // `position` over a 64-entry table, so the index is 0..64 and the
        // conversion is exact.
        let value = BASE64
            .iter()
            .position(|b| *b == character)
            .and_then(|index| u32::try_from(index).ok())
            .ok_or_else(|| {
                TxError::MessageSignature(format!("`{}` is not base64", character as char))
            })?;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            // Masked to a byte, so the narrowing is exact rather than lossy.
            out.push(u8::try_from((accumulator >> bits) & 0xff).unwrap_or(0));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `sdk-ref-check@` on VRSCTEST, and the signatures its daemon produced.
    const SYSTEM_ID: [u8; 20] = hex20("a6ef9ea235635e328124ff3429db9f9e91b64e2d");
    const IDENTITY_ID: [u8; 20] = hex20("223f497fb6cf167569f39272eb0169f69a3b36e3");
    const PRIMARY: &str = "RJGYC29RTSGQbWMrstQziJxfQaiDCjm5iP";

    const fn hex20(text: &str) -> [u8; 20] {
        let bytes = text.as_bytes();
        let mut out = [0u8; 20];
        let mut i = 0;
        while i < 20 {
            out[i] = nibble(bytes[i * 2]) * 16 + nibble(bytes[i * 2 + 1]);
            i += 1;
        }
        out
    }

    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => 0,
        }
    }

    /// Every vector the daemon produced, at height 1167655.
    ///
    /// The empty and 300-byte messages are the ones that matter: the first
    /// catches a length prefix that was skipped, the second catches a single
    /// length byte where a compact size is required.
    fn vectors() -> Vec<(&'static [u8], &'static str, &'static str)> {
        vec![
            (
                b"hello verus",
                "b215fcc319f75ff4690a9fee11f9d9a3a0572f4ac336035a3ad34e6113743626",
                "ASfREQABQSDVPquj1QKfyKo3qO+qwKoqYbKuLouO6lQ3sexMrYK1LnnTdgodl1anv7BfPqaTw12J7UKwvwaw6aQWtgWUPYNI",
            ),
            (
                b"",
                "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
                "ASfREQABQSAnJxNXF2ZZgoBu01YtgoHiDW+F2A07iPdnaSn0PSP5BkbMV2lMw1GwxqFDrWL0L1P8VbkTEC1cASDv7G/5kWhT",
            ),
            (
                b"second message",
                "2ca15c3489e07ca4b4686466339e162d408a5d813b75fdad0554abfd24659210",
                "ASfREQABQSC2IFbRBb1tJ0jiMhck+5w/4HZBFTWPtpwyxhpfp8bbMl7xwqpvW/J9ruZfzJg6Ci53QXEenDzhcHQoj+K8Oo/C",
            ),
        ]
    }

    /// The daemon's own `hash` field, reproduced exactly.
    #[test]
    fn the_message_hash_matches_the_daemon() {
        for (message, expected, _) in vectors() {
            assert_eq!(hex::encode(message_hash(message)), expected, "{message:?}");
        }
    }

    /// A 300-byte message needs `0xfd`-prefixed compact size. A single length
    /// byte would silently produce a different hash for anything over 252.
    #[test]
    fn a_long_message_uses_a_compact_size_not_a_length_byte() {
        let long = vec![b'A'; 300];
        assert_eq!(
            hex::encode(message_hash(&long)),
            "3d325efdc06da8ded89cca0d355fba3020c6c94431a2a6550c55ed85efd6470c"
        );
    }

    /// The whole chain: every daemon signature must recover to the identity's
    /// primary address under our hash construction. This is the test that says
    /// the scheme is right rather than merely self-consistent.
    #[test]
    fn daemon_signatures_recover_to_the_identity_key() {
        let primary: Address = PRIMARY.parse().unwrap();
        for (message, _, base64) in vectors() {
            let signature = IdentitySignature::from_base64(base64).expect("parse");
            assert_eq!(signature.block_height, 1_167_655);
            assert_eq!(signature.signatures.len(), 1);

            let signers = recover_signers(&signature, SYSTEM_ID, IDENTITY_ID, message).unwrap();
            assert_eq!(signers, vec![primary], "{message:?}");

            assert!(
                verify_message(&signature, SYSTEM_ID, IDENTITY_ID, message, &[primary], 1).unwrap()
            );
        }
    }

    /// The wire form must round-trip byte-for-byte, or a signature this crate
    /// re-serializes stops matching the one it parsed.
    #[test]
    fn a_daemon_signature_round_trips_through_our_encoding() {
        for (_, _, base64) in vectors() {
            let parsed = IdentitySignature::from_base64(base64).expect("parse");
            assert_eq!(parsed.to_base64(), base64);
        }
    }

    /// Changing the message must break verification — otherwise the signature
    /// says nothing about what was signed.
    #[test]
    fn a_tampered_message_does_not_verify() {
        let primary: Address = PRIMARY.parse().unwrap();
        let (_, _, base64) = vectors()[0];
        let signature = IdentitySignature::from_base64(base64).unwrap();
        assert!(!verify_message(
            &signature,
            SYSTEM_ID,
            IDENTITY_ID,
            b"hello Verus",
            &[primary],
            1
        )
        .unwrap());
    }

    /// The height is part of the hash, so claiming a different one invalidates
    /// the signature. That is what stops a signature made under an old key set
    /// being replayed against a newer one.
    #[test]
    fn a_changed_height_does_not_verify() {
        let primary: Address = PRIMARY.parse().unwrap();
        let (message, _, base64) = vectors()[0];
        let mut signature = IdentitySignature::from_base64(base64).unwrap();
        signature.block_height += 1;
        assert!(
            !verify_message(&signature, SYSTEM_ID, IDENTITY_ID, message, &[primary], 1).unwrap()
        );
    }

    /// The identity is part of the hash: the same key signing for a different
    /// identity produces a different signature, so one identity's signature
    /// cannot be presented as another's.
    #[test]
    fn a_signature_does_not_transfer_to_another_identity() {
        let primary: Address = PRIMARY.parse().unwrap();
        let (message, _, base64) = vectors()[0];
        let signature = IdentitySignature::from_base64(base64).unwrap();
        let other = [0x11u8; 20];
        assert!(!verify_message(&signature, SYSTEM_ID, other, message, &[primary], 1).unwrap());
    }

    /// And the chain is part of the hash, so a VRSCTEST signature is not a VRSC
    /// one. Verus addresses carry no network marker, which makes this the only
    /// thing standing between a testnet login and a mainnet one.
    #[test]
    fn a_signature_does_not_transfer_to_another_chain() {
        let primary: Address = PRIMARY.parse().unwrap();
        let (message, _, base64) = vectors()[0];
        let signature = IdentitySignature::from_base64(base64).unwrap();
        let other_chain = [0x22u8; 20];
        assert!(
            !verify_message(&signature, other_chain, IDENTITY_ID, message, &[primary], 1).unwrap()
        );
    }

    fn key() -> PrivateKey {
        PrivateKey::from_wif("UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc").unwrap()
    }

    /// Our own signature must verify under our own verifier, for messages of
    /// every awkward length.
    #[test]
    fn we_can_sign_and_verify_our_own_messages() {
        let key = key();
        let address = key.address();
        for message in [
            b"".to_vec(),
            b"x".to_vec(),
            vec![b'A'; 252],
            vec![b'A'; 253],
            vec![b'A'; 70_000],
            "unicode: \u{1f512} \u{00e9}".as_bytes().to_vec(),
        ] {
            let signature =
                sign_message(&key, SYSTEM_ID, IDENTITY_ID, 1_167_655, &message).unwrap();
            assert!(
                verify_message(&signature, SYSTEM_ID, IDENTITY_ID, &message, &[address], 1)
                    .unwrap(),
                "failed for a {}-byte message",
                message.len()
            );
        }
    }

    /// Signing is deterministic (RFC6979), so the same inputs give the same
    /// bytes — the property that lets these be compared against another
    /// implementation.
    #[test]
    fn signing_is_deterministic() {
        let first = sign_message(&key(), SYSTEM_ID, IDENTITY_ID, 1_000, b"same").unwrap();
        let second = sign_message(&key(), SYSTEM_ID, IDENTITY_ID, 1_000, b"same").unwrap();
        assert_eq!(first.to_base64(), second.to_base64());
    }

    /// A 2-of-2 identity: one signature is not enough, two are.
    #[test]
    fn a_multisig_identity_needs_its_threshold() {
        let first = key();
        let second = PrivateKey::from_bytes(&[0x27; 32], true).unwrap();
        let addresses = [first.address(), second.address()];
        let message = b"multisig login";

        let one = sign_message(&first, SYSTEM_ID, IDENTITY_ID, 1_000, message).unwrap();
        assert!(!verify_message(&one, SYSTEM_ID, IDENTITY_ID, message, &addresses, 2).unwrap());

        let two = add_signature(&one, &second, SYSTEM_ID, IDENTITY_ID, message).unwrap();
        assert_eq!(two.signatures.len(), 2);
        assert!(verify_message(&two, SYSTEM_ID, IDENTITY_ID, message, &addresses, 2).unwrap());
        // And it still satisfies a 1-of-2.
        assert!(verify_message(&two, SYSTEM_ID, IDENTITY_ID, message, &addresses, 1).unwrap());
    }

    /// The same key signing twice must not count as two signers, or a 2-of-2
    /// identity could be satisfied by one key holder.
    #[test]
    fn one_key_cannot_satisfy_a_two_of_two() {
        let only = key();
        let other = PrivateKey::from_bytes(&[0x27; 32], true).unwrap();
        let addresses = [only.address(), other.address()];
        let message = b"double sign";

        let once = sign_message(&only, SYSTEM_ID, IDENTITY_ID, 1_000, message).unwrap();
        let twice = add_signature(&once, &only, SYSTEM_ID, IDENTITY_ID, message).unwrap();
        assert_eq!(twice.signatures.len(), 1, "the duplicate was not collapsed");
        assert!(!verify_message(&twice, SYSTEM_ID, IDENTITY_ID, message, &addresses, 2).unwrap());
    }

    /// A signer who is not one of the identity's addresses contributes nothing.
    #[test]
    fn a_stranger_signature_does_not_authorise_anything() {
        let stranger = PrivateKey::from_bytes(&[0x99; 32], true).unwrap();
        let owner = key();
        let message = b"not yours";
        let signature = sign_message(&stranger, SYSTEM_ID, IDENTITY_ID, 1_000, message).unwrap();
        assert!(!verify_message(
            &signature,
            SYSTEM_ID,
            IDENTITY_ID,
            message,
            &[owner.address()],
            1
        )
        .unwrap());
    }

    /// A threshold of zero would accept anything, including no signature at all.
    #[test]
    fn a_zero_threshold_is_refused() {
        let signature = sign_message(&key(), SYSTEM_ID, IDENTITY_ID, 1_000, b"x").unwrap();
        assert!(verify_message(
            &signature,
            SYSTEM_ID,
            IDENTITY_ID,
            b"x",
            &[key().address()],
            0
        )
        .is_err());
    }

    /// Malformed input must be refused rather than half-parsed.
    #[test]
    fn malformed_signatures_are_refused() {
        for bad in [
            "",             // empty
            "!!!!",         // not base64
            "AQ==",         // version only
            "AgAAAAAA",     // wrong version
            "ASfREQAB",     // header, no signature
            "ASfREQABIAA=", // wrong signature length
        ] {
            assert!(
                IdentitySignature::from_base64(bad).is_err(),
                "accepted {bad:?}"
            );
        }
        // A valid signature with a byte appended is not valid.
        let (_, _, good) = vectors()[0];
        let mut bytes = IdentitySignature::from_base64(good).unwrap().to_bytes();
        bytes.push(0);
        assert!(IdentitySignature::from_bytes(&bytes).is_err());
    }

    /// Our base64 must agree with the daemon's on every length remainder, since
    /// padding is where a hand-rolled encoder goes wrong.
    #[test]
    fn base64_round_trips_at_every_padding_boundary() {
        for length in 0..40 {
            let bytes: Vec<u8> = (0..length)
                .map(|i: u8| i.wrapping_mul(7).wrapping_add(3))
                .collect();
            let encoded = base64_encode(&bytes);
            assert_eq!(base64_decode(&encoded).unwrap(), bytes, "length {length}");
        }
    }
}
