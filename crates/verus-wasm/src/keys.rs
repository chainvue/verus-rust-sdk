//! The key, and the fact that it stays here.
//!
//! A [`Key`] holds a secp256k1 private key inside the WebAssembly module's own
//! linear memory. Everything that needs it — signing a transaction, signing a
//! login — is a method on it, so the secret is never handed back to JavaScript
//! to be passed around, logged, or accidentally serialized into application
//! state. That is the point of binding the SDK rather than reimplementing it in
//! JS, and it is worth being precise about what it does and does not buy:
//!
//! * A wallet's own code cannot leak the key by mistake, because it never holds
//!   one — only a handle.
//! * It is **not** a defence against a compromised page. Anything that can run
//!   script in the same realm can call the same methods, and can read the
//!   module's memory outright. WebAssembly is a compilation target, not a
//!   sandbox around the host that instantiated it.
//!
//! # Freeing
//!
//! `PrivateKey` wipes its bytes when it is dropped, and the drop happens when
//! JavaScript calls `key.free()`. Without that call the handle is reclaimed
//! only if the bundle was built with reference-type finalization, which is not
//! guaranteed — so a wallet that wants the wipe should call `free()` when it
//! locks, and not rely on the garbage collector to decide.

use wasm_bindgen::prelude::*;

use verus_keys::PrivateKey;

use crate::dto;
use crate::error::{WasmError, WasmResult};
use crate::types::JsText;

/// A private key, and the operations that need one.
#[wasm_bindgen]
pub struct Key {
    inner: PrivateKey,
}

impl Key {
    /// The key itself, for the builder modules in this crate.
    pub(crate) fn private(&self) -> &PrivateKey {
        &self.inner
    }
}

#[wasm_bindgen]
impl Key {
    /// Import a WIF private key — what `dumpprivkey` prints and every Verus
    /// wallet imports.
    #[wasm_bindgen(js_name = fromWif)]
    pub fn from_wif(wif: JsText) -> Result<Key, WasmError> {
        Ok(Key {
            inner: PrivateKey::from_wif(&dto::secret_text("wif", wif.as_ref())?)
                .map_err(WasmError::from)?,
        })
    }

    /// Build from 32 bytes of entropy you supply.
    ///
    /// The auditable path to a fresh key: pass 32 bytes from
    /// `crypto.getRandomValues`, or from a hardware source, and the module
    /// never has to be trusted about where the randomness came from. Refuses
    /// anything that is not exactly 32 bytes, and refuses the (astronomically
    /// unlikely, but not impossible) values that are not valid secp256k1
    /// scalars rather than silently clamping them.
    #[wasm_bindgen(js_name = fromEntropy)]
    pub fn from_entropy(entropy: &[u8]) -> Result<Key, WasmError> {
        Ok(Key {
            inner: private_key_from_entropy(entropy)?,
        })
    }

    /// Derive the key a Verus Mobile / Verus Desktop recovery phrase maps to.
    ///
    /// Whitespace and case are significant, and there is no key derivation
    /// function underneath — a single unsalted SHA-256, which is the
    /// ecosystem's format rather than a choice made here. A phrase you invented
    /// yourself is cheap to brute-force offline; import one a wallet generated,
    /// or use [`Key::from_entropy`].
    #[wasm_bindgen(js_name = fromSeedPhrase)]
    pub fn from_seed_phrase(phrase: JsText) -> Result<Key, WasmError> {
        Ok(Key {
            inner: verus_keys::private_key_from_seed_phrase(&dto::secret_text(
                "phrase",
                phrase.as_ref(),
            )?)
            .map_err(WasmError::from)?,
        })
    }

    /// Export the key as WIF.
    ///
    /// This is the secret in a JavaScript string, which is exactly what the
    /// rest of this type exists to avoid — a string the garbage collector may
    /// copy and will not wipe. Call it to show a user their backup, and not for
    /// anything else.
    ///
    /// The JavaScript string is built straight from the zeroizing buffer, so
    /// no plaintext copy is left behind on the Rust side. That is a deliberate
    /// detail rather than an incidental one: returning a `String` would clone
    /// the WIF into an ordinary allocation that is dropped **without** being
    /// wiped, and wasm's allocator does not zero freed memory — so a single
    /// `toWif()` used to leave the key readable in the module's linear memory
    /// for the lifetime of the page, surviving even `free()`. What this cannot
    /// fix is the copy JavaScript now holds; that one is the caller's.
    #[wasm_bindgen(js_name = toWif)]
    pub fn to_wif(&self) -> JsText {
        use wasm_bindgen::JsCast;
        let wif = self.inner.to_wif();
        JsValue::from_str(wif.as_str()).unchecked_into()
    }

    /// The `R…` address this key controls.
    pub fn address(&self) -> String {
        self.inner.address().to_string()
    }

    /// The public key, hex, in the compression this key was created with.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> String {
        hex::encode(self.inner.public_key().to_bytes())
    }

    /// The 20-byte hash of the public key, hex — the value that appears inside
    /// a P2PKH script and inside an identity's primary address list.
    pub fn hash160(&self) -> String {
        hex::encode(self.inner.public_key().hash160())
    }

    /// The P2PKH scriptPubKey paying this key, hex.
    ///
    /// Useful for building a UTXO by hand in a test, and for checking that an
    /// output a node reported really does pay you.
    #[wasm_bindgen(js_name = scriptPubKey)]
    pub fn script_pub_key(&self) -> Result<String, WasmError> {
        Ok(hex::encode(
            self.inner
                .address()
                .p2pkh_script_pubkey()
                .map_err(WasmError::from)?,
        ))
    }
}

/// Validate entropy and turn it into a key.
///
/// Separate from the binding so it is testable on the host. The 32-byte copy
/// this makes of the caller's entropy is wrapped in `Zeroizing`, for the same
/// reason `to_wif` wipes its own intermediate: a plain array left on the
/// stack is not cleared when the function returns, and wasm's allocator does
/// not zero freed memory either, so an unwiped copy would otherwise outlive
/// the call.
///
/// The buffer is allocated pre-zeroed *inside* `Zeroizing` and filled by
/// `copy_from_slice`, the same order `verus_keys::mnemonic_to_seed` fills its
/// own `Zeroizing<[u8; 64]>` — rather than building a plain `[u8; 32]` via
/// `try_from` and wrapping it afterwards, which would (release builds
/// observed to elide it, but that is the optimizer's call to make, not this
/// function's) leave a moment where the entropy exists outside `Zeroizing`'s
/// reach.
///
/// What this cannot reach, by construction: [`Key::to_wif`] → `to_wif` →
/// `PrivateKey::to_bytes` (`verus-keys/src/key.rs`) calls
/// `SigningKey::to_bytes()`, which is `secret_scalar.to_repr()` — a plain
/// `FieldBytes` that nothing zeroizes — before `verus-keys` copies it into
/// its own `Zeroizing<[u8; 32]>`. That source copy outlives the call, and it
/// is a fact about `to_wif`, readable from `k256`/`ecdsa`'s own source rather
/// than only measured.
///
/// Whether construction itself — `PrivateKey::from_bytes` below, and
/// `k256::SigningKey::from_slice` underneath it — is clean is, as of this
/// writing, **not settled**: a byte-for-byte reproduction of the caller's
/// entropy has been observed in linear memory after `fromEntropy` followed
/// immediately by `free()`, with no `to_wif` call anywhere in the run, on a
/// clean checkout of this exact commit. That conflicts with an earlier report
/// that the same scenario was clean, and the discrepancy has not yet been
/// reconciled — see the PR discussion rather than trusting either claim on
/// its own. Either way, it is pre-existing behaviour inside
/// `verus-keys`/`k256`, not something this function's own fix touches, and
/// out of scope for this change.
pub(crate) fn private_key_from_entropy(entropy: &[u8]) -> WasmResult<PrivateKey> {
    if entropy.len() != 32 {
        return Err(WasmError::new(
            "InvalidEntropy",
            format!(
                "a private key needs exactly 32 bytes of entropy, got {}",
                entropy.len()
            ),
        ));
    }
    let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(entropy);
    PrivateKey::from_bytes(&bytes, true).map_err(WasmError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A vector the TypeScript SDK and the daemon both agree on.
    const WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";

    /// The bindings take `JsText`, which cannot be constructed on the host, so
    /// the host tests build the same `Key` through its inner type. What the
    /// bindings themselves do with a non-string is asserted under node.
    fn key() -> Key {
        Key {
            inner: PrivateKey::from_wif(WIF).unwrap(),
        }
    }

    #[test]
    fn a_wif_round_trips_and_names_its_address() {
        let key = key();
        // `to_wif` returns a JS string, which only exists under wasm; the
        // round trip itself is asserted in `tests/node/differential.mjs`.
        assert_eq!(key.private().to_wif().as_str(), WIF);
        assert!(key.address().starts_with('R'), "{}", key.address());
        assert_eq!(key.public_key().len(), 66, "compressed public key");
        assert_eq!(key.hash160().len(), 40);
    }

    /// The script must pay the address the key reports, or a wallet checking a
    /// node's answer against `scriptPubKey()` would be checking nothing.
    #[test]
    fn the_script_pays_the_address() {
        let key = key();
        let script = hex::decode(key.script_pub_key().unwrap()).unwrap();
        let recovered = verus_keys::Address::from_p2pkh_script_pubkey(&script).unwrap();
        assert_eq!(recovered.to_string(), key.address());
    }

    #[test]
    fn entropy_must_be_exactly_thirty_two_bytes() {
        for length in [0usize, 16, 31, 33, 64] {
            let error = private_key_from_entropy(&vec![7u8; length]).expect_err("{length} bytes");
            assert_eq!(error.code(), "InvalidEntropy", "{length} bytes: {error}");
        }
        assert!(private_key_from_entropy(&[7u8; 32]).is_ok());
    }

    /// Zero is not a valid scalar. A library that clamped it would hand back a
    /// key the user does not control; this refuses.
    #[test]
    fn entropy_that_is_not_a_valid_scalar_is_refused_not_clamped() {
        let error = private_key_from_entropy(&[0u8; 32]).expect_err("zero is not a key");
        assert_eq!(error.code(), "InvalidPrivateKey", "{error}");
    }

    #[test]
    fn a_wif_is_not_accepted_as_a_seed_phrase() {
        assert!(verus_keys::private_key_from_seed_phrase(WIF).is_err());
        assert!(verus_keys::private_key_from_seed_phrase("   ").is_err());
    }
}
