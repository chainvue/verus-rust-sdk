//! Signing and verifying messages as a VerusID — "log in with Verus".
//!
//! This is a signature over data. Nothing here spends, and nothing here needs a
//! transaction: a browser signs a challenge with a key it holds, and a server
//! checks the result against what the chain says the identity's keys were.
//!
//! # What a verifier must do, and what it cannot skip
//!
//! A signature commits to a **block height**, and an identity's key set is not
//! fixed — it can be rotated, and it can be revoked. So verification takes the
//! identity's primary addresses and threshold **as they stood at that height**,
//! which is what `getidentity`'s height argument exists for. Passing today's
//! values answers a different question, and for a rotated identity the two
//! answers differ. [`verify_message`] therefore takes the address set as an
//! argument rather than pretending it can look one up: this crate has no node,
//! and inventing a default here would be inventing the wrong one.
//!
//! **That is only half the rule, and the missing half is the dangerous one.**
//! The height is chosen by whoever signs. A verifier that dutifully resolves
//! the identity *at the signature's height* and stops there has built an
//! authentication bypass: someone holding a key that was rotated out — stolen,
//! which is usually why it was rotated — signs today's challenge and stamps it
//! with an old height. The lookup finds that key in the primary set at that
//! height, the threshold is met, and the answer is yes. Rotation never takes
//! effect against an attacker who gets to pick when they are.
//!
//! So the height must also be **bounded against the verifier's own tip**, and
//! [`VerifyRequest`] makes that non-optional: `currentHeight` and
//! `maxAgeBlocks` are required fields, checked before any signature is
//! recovered. A signature from the future is refused; one older than the
//! window is refused. Choose the window from how long a login should stay
//! signable — minutes, not months — and note that it is also the window in
//! which a stolen key remains usable after rotation.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use verus_keys::PrivateKey;
use verus_tx::signature::{
    add_signature, recover_signers, sign_message, verify_message as verify, IdentitySignature,
};

use crate::dto::{self, Shape};
use crate::error::{WasmError, WasmResult};
use crate::keys::Key;
use crate::types::{JsText, SignRequestValue, VerifyRequestValue, VerifyResultValue};

/// What to sign.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignRequest {
    /// The identity signing, as its `i…` address.
    pub identity: String,
    /// The chain, as its `i…` currency address — the signature is bound to it,
    /// so one made on testnet cannot be replayed on mainnet.
    pub system_id: String,
    /// The height the signature commits to; normally the current tip.
    pub block_height: u32,
    /// The message text.
    pub message: String,
    /// An existing signature to add to, base64, for an identity that needs
    /// more than one key. Omit for the first signature.
    #[serde(default)]
    pub existing: Option<String>,
}

impl SignRequest {
    /// The keys a `SignRequest` object may carry.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[
            ("identity", None),
            ("systemId", None),
            ("blockHeight", None),
            ("message", None),
            ("existing", None),
        ],
    };
}

/// What to check.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifyRequest {
    /// The identity claimed, as its `i…` address.
    pub identity: String,
    /// The chain, as its `i…` currency address.
    pub system_id: String,
    /// The message text that was signed.
    pub message: String,
    /// The signature, base64 — what [`Key::sign_message`] returned.
    pub signature: String,
    /// The identity's primary addresses **at the signature's block height**.
    pub primary_addresses: Vec<String>,
    /// The identity's `minimumsignatures` at that same height.
    pub minimum_signatures: u32,
    /// The verifier's current chain tip.
    ///
    /// Required, because without it the signer chooses the height at which
    /// they are authenticated — see the module docs.
    pub current_height: u32,
    /// How far back of `currentHeight` a signature may be stamped.
    ///
    /// Required and not defaulted: the right window is a policy decision about
    /// how long a login stays signable, and it is also how long a rotated-out
    /// key keeps working. There is no value this crate could pick for you that
    /// would be right for both.
    pub max_age_blocks: u32,
}

impl VerifyRequest {
    /// The keys a `VerifyRequest` object may carry.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[
            ("identity", None),
            ("systemId", None),
            ("message", None),
            ("signature", None),
            ("primaryAddresses", None),
            ("minimumSignatures", None),
            ("currentHeight", None),
            ("maxAgeBlocks", None),
        ],
    };
}

/// The outcome of a verification.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResult {
    /// Whether enough of the identity's own keys signed.
    pub valid: bool,
    /// The height the signature commits to — the height at which
    /// `primaryAddresses` and `minimumSignatures` had to be read.
    pub block_height: u32,
    /// Every address recovered from the signature, in order, deduplicated.
    /// Includes any that are **not** the identity's: a signature part by a
    /// stranger is not an error, it simply counts for nothing.
    pub signers: Vec<String>,
    /// Why `valid` is false, when it is.
    ///
    /// `"stale"` — older than `maxAgeBlocks`; `"future"` — stamped ahead of
    /// `currentHeight`; `"threshold"` — not enough of the identity's own keys
    /// signed. Absent when `valid` is true. Reported rather than collapsed
    /// into a bare `false` because a verifier that starts refusing every login
    /// needs to know whether its clock, its node or its users changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Sign, or add to an existing signature. Host-testable core.
pub(crate) fn build_signature(key: &PrivateKey, request: &SignRequest) -> WasmResult<String> {
    let identity = dto::identity_id("identity", &request.identity)?;
    let system = dto::identity_id("systemId", &request.system_id)?;
    let message = request.message.as_bytes();
    let signature = match &request.existing {
        None => sign_message(key, system, identity, request.block_height, message)?,
        Some(existing) => {
            let existing = IdentitySignature::from_base64(existing)?;
            if existing.block_height != request.block_height {
                // Every part must commit to the same height or they are
                // signatures over different hashes, and the set verifies
                // nowhere. The SDK silently keeps the existing height; saying
                // so here is cheaper than a caller discovering it at the far
                // end of a multi-party signing round.
                return Err(WasmError::new(
                    "BlockHeightMismatch",
                    format!(
                        "the existing signature commits to height {}, not {}: \
                         every part of a multisig signature must use the same height",
                        existing.block_height, request.block_height
                    ),
                ));
            }
            add_signature(&existing, key, system, identity, message)?
        }
    };
    Ok(signature.to_base64())
}

/// Verify a signature. Host-testable core.
pub(crate) fn check_signature(request: &VerifyRequest) -> WasmResult<VerifyResult> {
    let identity = dto::identity_id("identity", &request.identity)?;
    let system = dto::identity_id("systemId", &request.system_id)?;
    let signature = IdentitySignature::from_base64(&request.signature)?;
    let message = request.message.as_bytes();
    let addresses = request
        .primary_addresses
        .iter()
        .enumerate()
        .map(|(index, text)| {
            dto::address(text).map_err(|error| {
                WasmError::new(
                    error.code(),
                    format!("primaryAddresses[{index}]: {}", error.message()),
                )
            })
        })
        .collect::<WasmResult<Vec<_>>>()?;
    let signers = recover_signers(&signature, system, identity, message)?;
    let signer_names: Vec<String> = signers.iter().map(ToString::to_string).collect();

    // The height window is checked BEFORE the threshold, and reported as its
    // own reason, so a verifier cannot read "not enough signatures" when what
    // actually happened is "this signature is from six months ago".
    let height = signature.block_height;
    let refuse = |reason: &str| VerifyResult {
        valid: false,
        block_height: height,
        signers: signer_names.clone(),
        reason: Some(reason.to_string()),
    };
    if height > request.current_height {
        return Ok(refuse("future"));
    }
    if request.current_height - height > request.max_age_blocks {
        return Ok(refuse("stale"));
    }

    let valid = verify(
        &signature,
        system,
        identity,
        message,
        &addresses,
        request.minimum_signatures,
    )?;
    Ok(VerifyResult {
        valid,
        block_height: height,
        signers: signer_names,
        reason: (!valid).then(|| "threshold".to_string()),
    })
}

/// Verify a message signature against an identity's keys.
///
/// Two obligations, both enforced rather than advised.
///
/// `primaryAddresses` and `minimumSignatures` must be the identity's values
/// **at the signature's height**, not today's — read the height first with
/// [`signature_block_height`], then ask `getidentity` for that height. And
/// `currentHeight`/`maxAgeBlocks` must bound that height against your own tip,
/// because otherwise the signer chooses when they are authenticated and a
/// rotated-out key still works. See the module docs.
///
/// ```js
/// const height = signatureBlockHeight(signature);
/// const tip    = await rpc("getblockcount", []);
/// const id     = await rpc("getidentity", [identity, height]);
///
/// const claim = verifyMessage({
///   identity, systemId, message, signature,
///   primaryAddresses:  id.identity.primaryaddresses,
///   minimumSignatures: id.identity.minimumsignatures,
///   currentHeight:     tip,
///   maxAgeBlocks:      60,          // ~1 hour on Verus
/// });
/// if (claim.valid) startSession(identity);
/// else console.warn("rejected:", claim.reason);   // "stale" | "future" | "threshold"
/// ```
#[wasm_bindgen(js_name = verifyMessage)]
pub fn verify_message(request: VerifyRequestValue) -> Result<VerifyResultValue, WasmError> {
    let request: VerifyRequest = dto::from_js(request.into())?;
    Ok(crate::to_js(&check_signature(&request)?)?.unchecked_into())
}

/// The height a signature commits to, without verifying it.
///
/// A verifier needs this before it can ask a node for the right key set, and
/// it is the one field readable from the signature alone.
#[wasm_bindgen(js_name = signatureBlockHeight)]
pub fn signature_block_height(signature: JsText) -> Result<u32, WasmError> {
    read_block_height(&dto::text("signature", signature.as_ref())?)
}

/// Host-testable core of [`signature_block_height`].
pub(crate) fn read_block_height(signature: &str) -> WasmResult<u32> {
    Ok(IdentitySignature::from_base64(signature)
        .map_err(WasmError::from)?
        .block_height)
}

#[wasm_bindgen]
impl Key {
    /// Sign a message as a VerusID.
    ///
    /// The key must be one of the identity's primary keys — nothing here can
    /// check that, because checking needs a node, and a signature by the wrong
    /// key is produced happily and verifies nowhere.
    ///
    /// Returns the signature in base64, the same encoding the daemon's
    /// `signmessage` prints and `verifymessage` accepts.
    ///
    /// ```js
    /// const signature = key.signMessage({
    ///   identity: "iL9bc…", systemId: chainId,
    ///   blockHeight: tip, message: challenge,
    /// });
    /// ```
    #[wasm_bindgen(js_name = signMessage)]
    pub fn sign_message(&self, request: SignRequestValue) -> Result<String, WasmError> {
        let request: SignRequest = dto::from_js(request.into())?;
        build_signature(self.private(), &request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VRSCTEST: &str = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";
    const IDENTITY: &str = "iL9bcBmaR6YF37UfrPdkAxVwXwAG72xebm";

    fn key(byte: u8) -> PrivateKey {
        PrivateKey::from_bytes(&[byte; 32], true).unwrap()
    }

    fn sign_request() -> SignRequest {
        SignRequest {
            identity: IDENTITY.into(),
            system_id: VRSCTEST.into(),
            block_height: SIGNED_AT,
            message: "log me in".into(),
            existing: None,
        }
    }

    /// The height every fixture signs at, and a tip a few blocks past it.
    const SIGNED_AT: u32 = 1_169_587;
    const TIP: u32 = SIGNED_AT + 5;

    fn verify_request(signature: String, addresses: Vec<String>, minimum: u32) -> VerifyRequest {
        VerifyRequest {
            identity: IDENTITY.into(),
            system_id: VRSCTEST.into(),
            message: "log me in".into(),
            signature,
            primary_addresses: addresses,
            minimum_signatures: minimum,
            current_height: TIP,
            max_age_blocks: 60,
        }
    }

    #[test]
    fn a_signature_verifies_against_the_key_that_made_it() {
        let signer = key(0x11);
        let signature = build_signature(&signer, &sign_request()).unwrap();
        let result = check_signature(&verify_request(
            signature,
            vec![signer.address().to_string()],
            1,
        ))
        .unwrap();
        assert!(result.valid);
        assert_eq!(result.block_height, SIGNED_AT);
        assert_eq!(result.signers, vec![signer.address().to_string()]);
    }

    /// The point of binding a signature to an identity and a chain: neither
    /// substitution may verify.
    #[test]
    fn a_signature_does_not_transfer_to_another_identity_or_chain() {
        let signer = key(0x11);
        let signature = build_signature(&signer, &sign_request()).unwrap();
        let addresses = vec![signer.address().to_string()];

        let mut other_identity = verify_request(signature.clone(), addresses.clone(), 1);
        other_identity.identity = dto::identity_address([0x99; 20]);
        assert!(!check_signature(&other_identity).unwrap().valid);

        let mut other_chain = verify_request(signature, addresses, 1);
        other_chain.system_id = dto::identity_address([0x88; 20]);
        assert!(!check_signature(&other_chain).unwrap().valid);
    }

    /// Changing the message must invalidate it — otherwise a signed challenge
    /// would authorise anything.
    #[test]
    fn a_signature_does_not_cover_a_different_message() {
        let signer = key(0x11);
        let signature = build_signature(&signer, &sign_request()).unwrap();
        let mut request = verify_request(signature, vec![signer.address().to_string()], 1);
        request.message = "log me in as someone else".into();
        assert!(!check_signature(&request).unwrap().valid);
    }

    /// A stranger's signature recovers an address, and counts for nothing.
    #[test]
    fn a_key_that_is_not_the_identitys_does_not_satisfy_the_threshold() {
        let stranger = key(0x77);
        let signature = build_signature(&stranger, &sign_request()).unwrap();
        let result = check_signature(&verify_request(
            signature,
            vec![key(0x11).address().to_string()],
            1,
        ))
        .unwrap();
        assert!(!result.valid);
        assert_eq!(result.signers, vec![stranger.address().to_string()]);
    }

    #[test]
    fn two_keys_satisfy_a_two_of_two_identity() {
        let first = key(0x11);
        let second = key(0x22);
        let one = build_signature(&first, &sign_request()).unwrap();
        let mut second_request = sign_request();
        second_request.existing = Some(one.clone());
        let both = build_signature(&second, &second_request).unwrap();

        let addresses = vec![first.address().to_string(), second.address().to_string()];
        assert!(
            !check_signature(&verify_request(one, addresses.clone(), 2))
                .unwrap()
                .valid,
            "one of two must not satisfy a 2-of-2"
        );
        let result = check_signature(&verify_request(both, addresses, 2)).unwrap();
        assert!(result.valid);
        assert_eq!(result.signers.len(), 2);
    }

    /// Signature parts over different heights are signatures over different
    /// hashes. The SDK keeps the first height silently; the binding refuses,
    /// because a caller who passed a new height meant it.
    #[test]
    fn adding_to_a_signature_at_a_different_height_is_refused() {
        let one = build_signature(&key(0x11), &sign_request()).unwrap();
        let mut later = sign_request();
        later.existing = Some(one);
        later.block_height = SIGNED_AT + 13;
        let error = build_signature(&key(0x22), &later).expect_err("heights must match");
        assert_eq!(error.code(), "BlockHeightMismatch", "{error}");
    }

    /// A verifier needs the height before it can fetch the right key set, so
    /// it must be readable without verifying first.
    #[test]
    fn the_height_is_readable_from_the_signature_alone() {
        let signature = build_signature(&key(0x11), &sign_request()).unwrap();
        assert_eq!(read_block_height(&signature).unwrap(), SIGNED_AT);
    }

    /// An identity requiring zero signatures would accept anything; the SDK
    /// refuses, and the refusal must survive the binding.
    #[test]
    fn a_threshold_of_zero_is_refused() {
        let signature = build_signature(&key(0x11), &sign_request()).unwrap();
        assert!(check_signature(&verify_request(signature, vec![], 0)).is_err());
    }

    /// **The finding this window exists for.** The signer picks the height. A
    /// verifier that resolves the identity at whatever height it was handed,
    /// and stops, authenticates a key its owner rotated away — the attacker
    /// simply stamps an old height. The key set at that height still contains
    /// the stolen key, so the threshold is met and the answer is yes.
    ///
    /// Note what is asserted: the signature is *cryptographically fine* and
    /// the threshold *is* met. Only the age refuses it.
    #[test]
    fn a_signature_stamped_before_the_window_is_refused() {
        let stolen = key(0x11);
        let mut old = sign_request();
        old.block_height = TIP - 5_000;
        let signature = build_signature(&stolen, &old).unwrap();

        // Resolved the way a careful verifier would: the identity's keys AT
        // the signature's height, where the rotated-out key is still present.
        let mut request = verify_request(signature, vec![stolen.address().to_string()], 1);
        request.max_age_blocks = 60;
        let result = check_signature(&request).unwrap();
        assert!(
            !result.valid,
            "a signature 5000 blocks old must not log anyone in"
        );
        assert_eq!(result.reason.as_deref(), Some("stale"));
        assert_eq!(
            result.signers,
            vec![stolen.address().to_string()],
            "the signature itself is sound; it is the age that refuses it"
        );

        // And the window is a real dial, not decoration.
        request.max_age_blocks = 10_000;
        assert!(check_signature(&request).unwrap().valid);
    }

    /// A height beyond the verifier's own tip cannot be honest.
    #[test]
    fn a_signature_stamped_in_the_future_is_refused() {
        let signer = key(0x11);
        let mut ahead = sign_request();
        ahead.block_height = TIP + 1;
        let signature = build_signature(&signer, &ahead).unwrap();
        let result = check_signature(&verify_request(
            signature,
            vec![signer.address().to_string()],
            1,
        ))
        .unwrap();
        assert!(!result.valid);
        assert_eq!(result.reason.as_deref(), Some("future"));
    }

    /// The three refusals must be distinguishable — a verifier that starts
    /// rejecting everything needs to know whether its node, its clock or its
    /// users changed.
    #[test]
    fn a_refusal_says_which_of_the_three_it_is() {
        let signer = key(0x11);
        let signature = build_signature(&signer, &sign_request()).unwrap();
        let stranger = check_signature(&verify_request(
            signature,
            vec![key(0x77).address().to_string()],
            1,
        ))
        .unwrap();
        assert!(!stranger.valid);
        assert_eq!(stranger.reason.as_deref(), Some("threshold"));
    }

    /// A pass must carry no reason, or a caller checking `reason` for
    /// trouble would find some on every successful login.
    #[test]
    fn a_valid_signature_carries_no_reason() {
        let signer = key(0x11);
        let signature = build_signature(&signer, &sign_request()).unwrap();
        let result = check_signature(&verify_request(
            signature,
            vec![signer.address().to_string()],
            1,
        ))
        .unwrap();
        assert!(result.valid);
        assert_eq!(result.reason, None);
    }

    #[test]
    fn a_malformed_signature_is_an_error_not_a_false() {
        let request = verify_request("not base64!!".into(), vec![], 1);
        assert!(check_signature(&request).is_err());
    }
}
