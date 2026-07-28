//! Private and public keys.

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::address::{hash160, Address, AddressKind};
use crate::base58::{decode_check, encode_check};
use crate::error::KeyError;

/// Version byte of a Verus WIF private key.
///
/// Bitcoin uses `0x80`; a Bitcoin WIF is never a valid Verus key, and is
/// rejected rather than silently accepted.
pub const WIF_VERSION: u8 = 0xbc;

/// A secp256k1 private key.
///
/// The wrapped [`SigningKey`] zeroizes its scalar on drop, and every byte buffer
/// this module derives from it is wrapped in [`Zeroizing`]. That shortens the
/// window in which key material sits in memory; it does not defend against a
/// host that can read the process, and nothing here pretends otherwise.
#[derive(Clone)]
pub struct PrivateKey {
    signing_key: SigningKey,
    /// Whether the matching public key is serialized compressed. This is part of
    /// the key's identity, not a formatting choice: it changes the address.
    compressed: bool,
}

impl core::fmt::Debug for PrivateKey {
    /// Deliberately opaque — a key must not reach a log through a derived
    /// `Debug`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("compressed", &self.compressed)
            .finish_non_exhaustive()
    }
}

impl PrivateKey {
    /// Build from raw scalar bytes.
    pub fn from_bytes(bytes: &[u8; 32], compressed: bool) -> Result<Self, KeyError> {
        let signing_key = SigningKey::from_slice(bytes).map_err(|_| KeyError::InvalidPrivateKey)?;
        Ok(Self {
            signing_key,
            compressed,
        })
    }

    /// Decode a WIF private key.
    ///
    /// Enforces the Verus version byte, the payload length, and — for the
    /// compressed form — that the trailing flag is exactly `0x01`. The daemon
    /// only ever emits `0x01`; anything else is malformed, and accepting it
    /// would report a valid key that fails later at signing.
    pub fn from_wif(wif: &str) -> Result<Self, KeyError> {
        let (version, payload) = decode_check(wif)?;
        let payload = Zeroizing::new(payload);
        if version != WIF_VERSION {
            return Err(KeyError::WrongWifVersion {
                found: version,
                expected: WIF_VERSION,
            });
        }
        let compressed = match payload.len() {
            32 => false,
            33 => {
                if payload[32] != 0x01 {
                    return Err(KeyError::WifCompressionFlag(payload[32]));
                }
                true
            }
            // The reported length includes the version byte, matching how the
            // TypeScript SDK counts it.
            other => return Err(KeyError::WifLength(other + 1)),
        };
        let mut scalar = Zeroizing::new([0u8; 32]);
        scalar.copy_from_slice(&payload[..32]);
        Self::from_bytes(&scalar, compressed)
    }

    /// Encode as a WIF private key.
    pub fn to_wif(&self) -> Zeroizing<String> {
        let mut payload = Zeroizing::new(Vec::with_capacity(33));
        payload.extend_from_slice(self.to_bytes().as_slice());
        if self.compressed {
            payload.push(0x01);
        }
        Zeroizing::new(encode_check(WIF_VERSION, &payload))
    }

    /// The raw scalar.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&self.signing_key.to_bytes());
        out
    }

    /// Whether the matching public key serializes compressed.
    pub fn is_compressed(&self) -> bool {
        self.compressed
    }

    /// The matching public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            verifying_key: *self.signing_key.verifying_key(),
            compressed: self.compressed,
        }
    }

    /// The `R` address this key controls.
    pub fn address(&self) -> Address {
        self.public_key().address()
    }

    /// Sign a 32-byte hash that was computed elsewhere.
    ///
    /// This is a *prehash* signer: it does not hash its input. Callers pass a
    /// sighash from `verus-wire`.
    ///
    /// Deterministic (RFC6979) with low-S normalization — the same properties
    /// `@noble/curves` gives the TypeScript SDK, which is what allows the two to
    /// be compared byte for byte. No randomness is involved, so there is no
    /// entropy source to fail and no nonce to reuse.
    pub fn sign_prehash(&self, hash: &[u8; 32]) -> Result<Signature, KeyError> {
        self.signing_key
            .sign_prehash(hash)
            .map_err(|_| KeyError::InvalidPrivateKey)
    }

    /// Sign a hash and return the compact 64-byte `r || s`.
    ///
    /// This is what a CryptoCondition fulfillment carries, where a P2PKH
    /// scriptSig would carry DER. Note there is no recovery byte and no trailing
    /// hash type: the fulfillment states the hash type once, for all of its
    /// signatures.
    pub fn sign_prehash_compact(&self, hash: &[u8; 32]) -> Result<[u8; 64], KeyError> {
        let signature = self.sign_prehash(hash)?;
        let mut out = [0u8; 64];
        out.copy_from_slice(&signature.to_bytes());
        Ok(out)
    }

    /// Sign a hash and return the DER encoding with `hash_type` appended — the
    /// exact bytes that go into a scriptSig.
    pub fn sign_prehash_der(&self, hash: &[u8; 32], hash_type: u8) -> Result<Vec<u8>, KeyError> {
        let signature = self.sign_prehash(hash)?;
        let mut out = signature.to_der().as_bytes().to_vec();
        out.push(hash_type);
        Ok(out)
    }
}

/// A secp256k1 public key, with the serialization form it was derived under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    verifying_key: VerifyingKey,
    compressed: bool,
}

impl PublicKey {
    /// Parse a SEC1 public key (33 bytes compressed, 65 uncompressed).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        let verifying_key =
            VerifyingKey::from_sec1_bytes(bytes).map_err(|_| KeyError::InvalidPublicKey)?;
        Ok(Self {
            verifying_key,
            compressed: bytes.len() == 33,
        })
    }

    /// SEC1 bytes, in the form this key was derived under.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.verifying_key
            .to_encoded_point(self.compressed)
            .as_bytes()
            .to_vec()
    }

    /// HASH160 of the serialized key — the 20 bytes an address carries.
    pub fn hash160(&self) -> [u8; 20] {
        hash160(&self.to_bytes())
    }

    /// The `R` address for this key.
    pub fn address(&self) -> Address {
        Address::new(AddressKind::PubKeyHash, self.hash160())
    }

    /// The underlying verifying key, for signature verification.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // From the TypeScript SDK's fixtures.
    const TEST_WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";
    const TEST_ADDRESS: &str = "RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX";
    const TEST_WIF_B: &str = "UtJXdBipt7XKxSe3AKFYhXizA5cgCM1ztQLVDANwHtfERydFEnPG";
    const TEST_ADDRESS_B: &str = "RPsQDnaxXgrLjcVBh3SpvCpTabWxAdMdzu";

    #[test]
    fn derives_the_addresses_the_typescript_sdk_derives() {
        for (wif, expected) in [(TEST_WIF, TEST_ADDRESS), (TEST_WIF_B, TEST_ADDRESS_B)] {
            let key = PrivateKey::from_wif(wif).unwrap();
            assert!(key.is_compressed());
            assert_eq!(key.address().to_string(), expected);
        }
    }

    #[test]
    fn wif_round_trips() {
        let key = PrivateKey::from_wif(TEST_WIF).unwrap();
        assert_eq!(*key.to_wif(), TEST_WIF);
    }

    #[test]
    fn rejects_a_bitcoin_wif() {
        // A canonical Bitcoin mainnet WIF: valid base58check, version 0x80.
        let bitcoin = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617";
        // Compare the error, not the Result: `PrivateKey` deliberately has no
        // `PartialEq`, since comparing secret scalars byte-wise is not something
        // a key type should make easy.
        assert_eq!(
            PrivateKey::from_wif(bitcoin).unwrap_err(),
            KeyError::WrongWifVersion {
                found: 0x80,
                expected: 0xbc
            }
        );
    }

    #[test]
    fn rejects_a_bogus_compression_flag() {
        let mut payload = vec![0x11; 32];
        payload.push(0x02); // the daemon only ever emits 0x01
        let wif = encode_check(WIF_VERSION, &payload);
        assert_eq!(
            PrivateKey::from_wif(&wif).unwrap_err(),
            KeyError::WifCompressionFlag(0x02)
        );
    }

    #[test]
    fn signing_is_deterministic() {
        // RFC6979: the same key and hash must always produce the same bytes.
        // This is what makes differential testing against the TypeScript SDK
        // possible at all.
        let key = PrivateKey::from_wif(TEST_WIF).unwrap();
        let hash = [0x42u8; 32];
        assert_eq!(
            key.sign_prehash_der(&hash, 1).unwrap(),
            key.sign_prehash_der(&hash, 1).unwrap()
        );
    }

    #[test]
    fn signatures_are_low_s() {
        // A high-S signature is malleable and the daemon rejects it. k256
        // normalizes by default; this pins that behavior rather than trusting it.
        let key = PrivateKey::from_wif(TEST_WIF).unwrap();
        for byte in 0u8..32 {
            let signature = key.sign_prehash(&[byte; 32]).unwrap();
            assert!(
                signature.normalize_s().is_none(),
                "signature for {byte} was not low-S"
            );
        }
    }

    #[test]
    fn debug_does_not_leak_the_key() {
        let key = PrivateKey::from_wif(TEST_WIF).unwrap();
        let rendered = format!("{key:?}");
        assert!(!rendered.contains(TEST_WIF));
        assert!(!rendered.contains(&hex::encode(*key.to_bytes())));
    }
}
