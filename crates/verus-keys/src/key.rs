//! Private and public keys.

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
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
///
/// # Known residue this crate cannot fix
///
/// On wasm32, constructing a key — `SigningKey::from_slice` -> `NonZeroScalar`
/// -> `Scalar::from_repr`, plus the public-key derivation that follows —
/// leaves compiler-spilled copies of the scalar sitting in linear memory:
/// seven of them, measured on `k256` 0.13.4 / `crypto-bigint` 0.5.5, release +
/// `wasm-opt`. Six are on the shadow stack, one on the heap. `SigningKey`
/// itself does implement `Drop`/`ZeroizeOnDrop`, so the *live* key is wiped;
/// these are spills the optimizer leaves around it, upstream of anything
/// `verus-keys` controls. They are bounded, not permanent: a single
/// subsequent key construction (`fromEntropy` + `free`) overwrites all seven
/// — 0 remaining, measured at churn = 1, 2, 5, 10, 20, 50, 200, and 500 —
/// which makes this materially weaker than a key that stays readable for the
/// life of the page, but it is not nothing, and exploiting it requires a
/// same-realm memory read the wasm bindings already disclaim defending
/// against.
///
/// What these copies *are* was settled by measurement rather than inference,
/// though not uniformly. Four of the seven are whole 116-byte `SigningKey`
/// records — 32 bytes of scalar in `U256` limb order, then the derived
/// `AffinePoint` as two `FieldElement10x26` (`[u32; 10]`, 26-bit limbs) plus an
/// `infinity` byte and padding — whose coordinates decode to exactly `k·G`,
/// checked against arithmetic computed outside this stack. A record carrying
/// the derived public point cannot predate the scalar multiplication, so for
/// those four a decode-side or hash-buffer origin is ruled out.
///
/// The other three are not records, and that argument does not reach them: one
/// carries the generator's `x` with the `infinity` byte set rather than `k·G`,
/// one is the same record written again 32 bytes earlier and overlapping it,
/// and one is a bare scalar copy. Their origin is unattributed. Issue #186 has
/// the addresses and the method.
///
/// The byte-order trap, because it is the detail that costs the most time to
/// rediscover: `k256` stores the scalar as `crypto_bigint::U256` limbs,
/// **little-endian on wasm32**. A memory search for the key in canonical
/// big-endian order finds none of these seven copies. Search with a uniform
/// fill (e.g. every byte set to the same value) instead, which reads
/// identically regardless of byte order. See issue #170 for the measurement
/// method and addresses.
///
/// `to_bytes`'s own source temporary does *not* contribute to this residue.
/// Measured separately: wrapping or explicitly zeroizing
/// `SigningKey::to_bytes`'s return leaves an unrelated canonical-order copy
/// in the same place either way. That copy belonged to `encode_check`'s
/// SHA-256 block buffer, not to `to_bytes` — and it is now gone, since
/// [`crate::base58::encode_check`] computes the checksum itself rather than
/// handing the secret to `bs58`. See issue #179.
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
    ///
    /// See the memory-hygiene note on [`PrivateKey`] itself for the residue
    /// this construction path leaves behind on wasm32, which this crate
    /// cannot fix.
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
    ///
    /// Decoding leaves nothing of its own behind on the success path: no
    /// canonical-order copy of the scalar survives anywhere in wasm32 linear
    /// memory after a successful `from_wif`. What it does cost is one extra
    /// construction copy — measured against `from_bytes` alone (`fromEntropy` +
    /// `free`, no encoding), seven copies of the scalar become eight, and the
    /// four full `SigningKey` records among them become five. The extra one is
    /// the same k256 residue documented on [`PrivateKey`], not decode residue.
    /// See issue #186.
    ///
    /// The *rejection* paths are a different matter, and all three checks
    /// below sit on them: by the time a wrong version byte, a bad compression
    /// flag or a wrong length is noticed, [`crate::base58::decode_check`] has
    /// already handed the payload over, so the `Zeroizing` wrap on the line
    /// after the call is the only thing that wipes it on the way out. See
    /// [`crate::base58::decode_check`] for the buffers on the other side of
    /// that call, and issue #203.
    pub fn from_wif(wif: &str) -> Result<Self, KeyError> {
        let (version, payload) = decode_check(wif)?;
        // Wrapped before the checks, not after: every `return Err` below drops
        // this, and an unwrapped `Vec` would be dropped unwiped on exactly the
        // paths that leave a mistyped WIF's scalar in memory.
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
        // `SigningKey::to_bytes` returns a plain `FieldBytes` (a `GenericArray`
        // with no `Drop`/zeroize of its own) holding the scalar in canonical
        // order. Wrapping it here is defensible hygiene and costs nothing
        // measurable — but measurement (issue #170) found no residual copy
        // attributable to this temporary specifically: the canonical-order
        // copy left behind on the wasm32 `to_wif` path comes from
        // `encode_check`'s SHA-256 block buffer, not from here. See the note
        // on `PrivateKey` for the full picture.
        let raw = Zeroizing::new(self.signing_key.to_bytes());
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&raw);
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

    /// Sign a hash and return the 65-byte **recoverable** form: a header byte
    /// carrying the recovery id, then `r || s`.
    ///
    /// This is what a signed *message* carries, as distinct from a transaction.
    /// A scriptSig can afford to state the public key separately; a message
    /// signature is checked against an address alone, so the key has to be
    /// recoverable from the signature itself.
    ///
    /// The header is `27 + recovery_id + 4` for a compressed key and
    /// `27 + recovery_id` for an uncompressed one — the Bitcoin convention Verus
    /// inherited. Getting the `+ 4` wrong recovers a valid but *different*
    /// public key, so the signature verifies against nothing and the failure
    /// looks like a wrong key rather than a wrong encoding.
    pub fn sign_prehash_recoverable(&self, hash: &[u8; 32]) -> Result<[u8; 65], KeyError> {
        let (signature, recovery_id) = self
            .signing_key
            .sign_prehash_recoverable(hash)
            .map_err(|_| KeyError::InvalidPrivateKey)?;
        let mut out = [0u8; 65];
        out[0] = 27 + recovery_id.to_byte() + if self.is_compressed() { 4 } else { 0 };
        out[1..].copy_from_slice(&signature.to_bytes());
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

    /// Whether `signature` is a valid DER signature over `hash` by this key.
    ///
    /// The hash type byte a scriptSig appends is **not** part of the signature;
    /// strip it before calling.
    pub fn verify_der(&self, hash: &[u8; 32], signature: &[u8]) -> bool {
        Signature::from_der(signature)
            .is_ok_and(|signature| self.verifying_key.verify_prehash(hash, &signature).is_ok())
    }

    /// Whether `signature` is a valid compact `r || s` signature over `hash`.
    ///
    /// The form a CryptoCondition fulfillment carries.
    pub fn verify_compact(&self, hash: &[u8; 32], signature: &[u8]) -> bool {
        let Ok(bytes): Result<[u8; 64], _> = signature.try_into() else {
            return false;
        };
        Signature::from_slice(&bytes)
            .is_ok_and(|signature| self.verifying_key.verify_prehash(hash, &signature).is_ok())
    }

    /// Recover the public key that produced a 65-byte recoverable signature.
    ///
    /// The inverse of [`PrivateKey::sign_prehash_recoverable`]. Recovery yields
    /// *some* key for any well-formed signature, so an `Ok` here proves nothing
    /// on its own — the caller must compare the result against the address it
    /// expected, and that comparison is the actual verification.
    pub fn recover(hash: &[u8; 32], signature: &[u8; 65]) -> Result<Self, KeyError> {
        use k256::ecdsa::RecoveryId;

        let header = signature[0];
        // 27..=30 uncompressed, 31..=34 compressed. Anything else is a different
        // encoding, and guessing would recover an unrelated key.
        if !(27..=34).contains(&header) {
            return Err(KeyError::InvalidSignature);
        }
        let compressed = header >= 31;
        let recovery_id =
            RecoveryId::from_byte((header - 27) & 3).ok_or(KeyError::InvalidSignature)?;
        let parsed =
            Signature::from_slice(&signature[1..]).map_err(|_| KeyError::InvalidSignature)?;
        let verifying_key = VerifyingKey::recover_from_prehash(hash, &parsed, recovery_id)
            .map_err(|_| KeyError::InvalidSignature)?;
        Ok(PublicKey {
            verifying_key,
            compressed,
        })
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
