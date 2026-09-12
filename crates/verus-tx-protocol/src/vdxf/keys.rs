//! The VDXF keys the VerusPay and login-consent formats are addressed by.
//!
//! Every [`VdxfObject`](super::VdxfObject) names itself with twenty bytes, and
//! those twenty bytes are a derived constant: `veruspay.vrsc::invoice` is
//! `iEETy7La3FTN2Sd2hNRgepek5S8x8eeUeQ` for everybody, forever. Upstream keeps
//! them in a hand-maintained table (`src/vdxf/keys.ts`); this module keeps them
//! as constants *and re-derives every one of them in a test* from the qualified
//! name upstream records beside it, using [`super::data_key`] — the derivation
//! that is already byte-locked against `getvdxfid`.
//!
//! That is the point of the arrangement. Copying a table proves only that the
//! copy was faithful. Deriving the same twenty bytes from
//! `veruspay.vrsc::invoice` and finding upstream's published i-address is an
//! independent check of both sides: if this crate's derivation were wrong, or if
//! upstream's table had a slip in it, the test would say so.
//!
//! # Byte order — `hash160result` is printed backwards
//!
//! `keys.ts` gives each key three spellings and only two of them agree with the
//! wire:
//!
//! ```text
//! vdxfid        iEETy7La3FTN2Sd2hNRgepek5S8x8eeUeQ   base58check of the wire bytes
//! hash160result 628efc28c2e2d40050e1a9de7a93e7ddf2aa0076   REVERSED
//! indexid       xK4aRumetZg2ecW4Z45qdDBH769xxnaiEH   a different version byte
//! ```
//!
//! The constants here are the **wire** order — base58-decode the `vdxfid` — which
//! is what [`super::data_key`] returns and what appears at the front of a real
//! invoice's bytes. `hash160result` is printed txid-style, reversed, and
//! consuming it raw gives twenty bytes that are not any key. [`super`] carries
//! the same warning about the daemon's own `hash160result`, for the same reason.
//!
//! # Why only these, and not all eighty-three
//!
//! `keys.ts` has eighty-three entries. The sixteen here are the VerusPay and
//! login-consent ones, read off upstream's own imports rather than guessed:
//! `Request.ts`, `Response.ts`, `Challenge.ts`, `Decision.ts` and `Context.ts`
//! name the login-consent request, response, challenge, decision, context and
//! signature keys, the wallet scope, and the three identity facts a challenge may
//! ask for. The two redirect kinds are what `Challenge.ts`'s `RedirectUri` takes
//! as its key, and the two generic deeplink keys are the envelope a request
//! arrives in. `veruspay.vrsc::invoice` and its details key complete the set.
//!
//! Two things are deliberately left out of that list even though the same files
//! mention them. The `LOGIN_CONSENT_PROVISIONING_*` keys are a different format
//! with its own payloads, and the attestation, credential and wallet-backup keys
//! are several more. They are omitted for the reason the set is small at all: a
//! constant nothing reaches is a constant nothing checks, and each of those
//! should arrive with the code that reads its payload.
//!
//! # What was checked, and what it did not find
//!
//! All eighty-three entries were re-derived while choosing the sixteen, and all
//! eighty-three agree — both `vdxfid` against the derivation and
//! `hash160result` against the reverse of it. So the restriction here is about
//! what this crate has a use for, not about distrusting the rest of the table.
//! The same sweep found no `GENERIC_ENVELOPE_DEEPLINK_VDXF_KEY` in
//! `VerusCoin/verus-typescript-primitives` at all.

use verus_tx_primitives::CurrencyId;

/// Decode a hex literal this file controls into twenty bytes at compile time.
///
/// Same shape as the helper in `verus_tx_identity::signature`'s tests: there is
/// no const hex in the workspace's dependencies, and a byte-array literal for
/// sixteen keys would be unreadable and unreviewable against `keys.ts`.
const fn key(text: &str) -> [u8; 20] {
    let bytes = text.as_bytes();
    // A wrong-length literal is a typo in this file, and a compile-time panic
    // is the right place to find it.
    assert!(bytes.len() == 40, "a VDXF key is forty hex characters");
    let mut out = [0u8; 20];
    let mut index = 0;
    while index < 20 {
        out[index] = nibble(bytes[index * 2]) * 16 + nibble(bytes[index * 2 + 1]);
        index += 1;
    }
    out
}

const fn nibble(character: u8) -> u8 {
    match character {
        b'0'..=b'9' => character - b'0',
        b'a'..=b'f' => character - b'a' + 10,
        _ => panic!("a VDXF key is lowercase hex"),
    }
}

/// The namespace the two VerusPay keys live under: `veruspay.vrsc`,
/// `iAisVse7piEiE2VsixZx4SARyHzSpxYxgq`.
///
/// Not a VDXF key — an identity id, used as the namespace the keys hang off.
/// Note that it is **not** a root name: `veruspay` registered under `vrsc`, so
/// it is [`crate::identity_id`] with the `vrsc` root as its parent, and
/// [`super::root_namespace`] refuses it. That asymmetry is the namespace trap
/// [`super`] documents, met in the wild on the first format that uses it.
pub const VERUSPAY_NAMESPACE: CurrencyId =
    CurrencyId::from_bytes(key("4f7f7429b2a448da74f2c08ebbed43c338956847"));

/// `veruspay.vrsc::invoice` — `iEETy7La3FTN2Sd2hNRgepek5S8x8eeUeQ`.
///
/// A VerusPay invoice, the object a payment QR code carries.
pub const VERUSPAY_INVOICE_VDXF_KEY: [u8; 20] = key("7600aaf2dde7937adea9e15000d4e2c228fc8e62");

/// `veruspay.vrsc::invoice.details` — `iJNsPqAhjovi3iVR3hvLGqrQxcCkHq9n9H`.
///
/// The invoice's payload: who is being paid, in what, how much.
pub const VERUSPAY_INVOICE_DETAILS_VDXF_KEY: [u8; 20] =
    key("a3780dc7a9500b222e6ab2706d683195f1233a74");

/// `vrsc::request.generic` — `iLWiYHVjoTyoeKwji1B5vRT9Xr1aA9yyvX`.
///
/// The envelope a deeplink uses when the request inside it is one of several
/// kinds.
pub const GENERIC_REQUEST_DEEPLINK_VDXF_KEY: [u8; 20] =
    key("bae43defcc5355d18bfa961279cc313026c405bc");

/// `vrsc::response.generic` — `i9JzVt59mAVHqjc8WAQJx7bEFAQ4ffuhrC`.
///
/// The answering half of [`GENERIC_REQUEST_DEEPLINK_VDXF_KEY`].
pub const GENERIC_RESPONSE_DEEPLINK_VDXF_KEY: [u8; 20] =
    key("40033034e9795d9b7c2a78a04709a36ce741b64e");

/// `vrsc::identity.authentication.loginconsent.request` —
/// `i3dQmgjq8L8XFGQUrs9Gpo8zvPWqs1KMtV`.
pub const LOGIN_CONSENT_REQUEST_VDXF_KEY: [u8; 20] =
    key("01ae2ebd282c2c05a28a727b1a8d76fc6eb339c5");

/// `vrsc::identity.authentication.loginconsent.response` —
/// `i5fvfsaTFKtrHCPYQHTXRaXcyxHmJMxTMe`.
pub const LOGIN_CONSENT_RESPONSE_VDXF_KEY: [u8; 20] =
    key("181839a2b587ff8c71fb73df947341a8e5fada17");

/// `vrsc::identity.authentication.loginconsent.challenge` —
/// `i5maLnB62WmKKXFZniqDRU1JiC2Hd1xpVb`.
pub const LOGIN_CONSENT_CHALLENGE_VDXF_KEY: [u8; 20] =
    key("1929c03e8fa8d49c1f8db57626938afb57c4359c");

/// `vrsc::identity.authentication.loginconsent.decision` —
/// `iQP5eKQaYDV3FFXsq7276LyWxk4ttjuSdm`.
pub const LOGIN_CONSENT_DECISION_VDXF_KEY: [u8; 20] =
    key("e55308bc880a7d9cc01c84f94e2acced10a3ba89");

/// `vrsc::identity.authentication.loginconsent.context` —
/// `iBMochrKPSQfua5yZYWyd6p4QnREakqU44`.
pub const LOGIN_CONSENT_CONTEXT_VDXF_KEY: [u8; 20] =
    key("567b9a87b17131f6eeb2dd0bdd191ece4a5d603b");

/// `vrsc::identity.authentication.loginconsent.redirect` —
/// `iDXvHYhRpWcoARCEYeLv8GwkVdrbvSFuam`.
///
/// One of the two kinds a challenge's redirect URI can be: send the user here
/// when they are done.
pub const LOGIN_CONSENT_REDIRECT_VDXF_KEY: [u8; 20] =
    key("6e559518037ca6c9477af21ecc96bddc61c2d2a6");

/// `vrsc::identity.authentication.loginconsent.webhook` —
/// `iSaBWByu4zqhEZ6HQmFxvfR1HyiFuhnJfL`.
///
/// The other kind: post the response here instead.
pub const LOGIN_CONSENT_WEBHOOK_VDXF_KEY: [u8; 20] =
    key("fd5cc0ba219847926c86577a23565802a760e719");

/// `vrsc::identity.authentication.signature` —
/// `iPi1DPgDDu7hP1mAp5xJ8rHBWwXSzc6yA8`.
///
/// Upstream exports these twenty bytes under **two** names —
/// `IDENTITY_AUTH_SIG_VDXF_KEY` and `LOGIN_CONSENT_RESPONSE_SIG_VDXF_KEY` — with
/// the same `vdxfid` and the same qualified name. One constant here, because two
/// names for one value is two things to keep in step; the test asserts the
/// single qualified name both of them record.
pub const IDENTITY_AUTH_SIG_VDXF_KEY: [u8; 20] = key("ddef1d244c7a0f72b00509f017cf3dda63b9d406");

/// `vrsc::applications.wallet` — `i5JtwbP6zyMEAy9LLnRAGLgJQGdRFfsAu4`.
///
/// The scope a login-consent request asks for when it wants the wallet
/// application rather than a named one.
pub const WALLET_VDXF_KEY: [u8; 20] = key("141e0bf38714a7bd2773686cc0093feaed8684cb");

/// `vrsc::identity.address` — `i3a3M9n7uVtRYv1vhjmyb4DxY825AVAwic`.
///
/// One of the three identity facts a challenge may request. The set is closed
/// upstream: `Challenge.ts` accepts these three and nothing else.
pub const ID_ADDRESS_VDXF_KEY: [u8; 20] = key("010b0d3a575b98f99e5ddf0db6e7fd60d804fc63");

/// `vrsc::identity.parent` — `i6aJSTKfNiDZ4rPxj1pPh4Y8xDmh1GqYm9`.
pub const ID_PARENT_VDXF_KEY: [u8; 20] = key("220006d64df3a058bce6b41fa4a0189847e70bfe");

/// `vrsc::identity.systemid` — `iMZTNkNBgBXNHkMLipQw9wQb56pxBSEp3k`.
pub const ID_SYSTEMID_VDXF_KEY: [u8; 20] = key("c660f4fce3ca334daa914c18870c13c02ce7653e");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::identity_id;
    use crate::vdxf::{data_key, root_namespace};
    use verus_keys::{Address, AddressKind};

    /// Every constant above, with the two spellings `keys.ts` publishes for it:
    /// the qualified name it derives from and the `vdxfid` it derives to.
    ///
    /// Transcribed from `VerusCoin/verus-typescript-primitives`,
    /// `src/vdxf/keys.ts`. Nothing in this table is this crate's own output —
    /// that is what makes the test below a cross-check rather than a
    /// restatement.
    const UPSTREAM: &[([u8; 20], &str, &str)] = &[
        (
            VERUSPAY_INVOICE_VDXF_KEY,
            "veruspay.vrsc::invoice",
            "iEETy7La3FTN2Sd2hNRgepek5S8x8eeUeQ",
        ),
        (
            VERUSPAY_INVOICE_DETAILS_VDXF_KEY,
            "veruspay.vrsc::invoice.details",
            "iJNsPqAhjovi3iVR3hvLGqrQxcCkHq9n9H",
        ),
        (
            GENERIC_REQUEST_DEEPLINK_VDXF_KEY,
            "vrsc::request.generic",
            "iLWiYHVjoTyoeKwji1B5vRT9Xr1aA9yyvX",
        ),
        (
            GENERIC_RESPONSE_DEEPLINK_VDXF_KEY,
            "vrsc::response.generic",
            "i9JzVt59mAVHqjc8WAQJx7bEFAQ4ffuhrC",
        ),
        (
            LOGIN_CONSENT_REQUEST_VDXF_KEY,
            "vrsc::identity.authentication.loginconsent.request",
            "i3dQmgjq8L8XFGQUrs9Gpo8zvPWqs1KMtV",
        ),
        (
            LOGIN_CONSENT_RESPONSE_VDXF_KEY,
            "vrsc::identity.authentication.loginconsent.response",
            "i5fvfsaTFKtrHCPYQHTXRaXcyxHmJMxTMe",
        ),
        (
            LOGIN_CONSENT_CHALLENGE_VDXF_KEY,
            "vrsc::identity.authentication.loginconsent.challenge",
            "i5maLnB62WmKKXFZniqDRU1JiC2Hd1xpVb",
        ),
        (
            LOGIN_CONSENT_DECISION_VDXF_KEY,
            "vrsc::identity.authentication.loginconsent.decision",
            "iQP5eKQaYDV3FFXsq7276LyWxk4ttjuSdm",
        ),
        (
            LOGIN_CONSENT_CONTEXT_VDXF_KEY,
            "vrsc::identity.authentication.loginconsent.context",
            "iBMochrKPSQfua5yZYWyd6p4QnREakqU44",
        ),
        (
            LOGIN_CONSENT_REDIRECT_VDXF_KEY,
            "vrsc::identity.authentication.loginconsent.redirect",
            "iDXvHYhRpWcoARCEYeLv8GwkVdrbvSFuam",
        ),
        (
            LOGIN_CONSENT_WEBHOOK_VDXF_KEY,
            "vrsc::identity.authentication.loginconsent.webhook",
            "iSaBWByu4zqhEZ6HQmFxvfR1HyiFuhnJfL",
        ),
        (
            IDENTITY_AUTH_SIG_VDXF_KEY,
            "vrsc::identity.authentication.signature",
            "iPi1DPgDDu7hP1mAp5xJ8rHBWwXSzc6yA8",
        ),
        (
            WALLET_VDXF_KEY,
            "vrsc::applications.wallet",
            "i5JtwbP6zyMEAy9LLnRAGLgJQGdRFfsAu4",
        ),
        (
            ID_ADDRESS_VDXF_KEY,
            "vrsc::identity.address",
            "i3a3M9n7uVtRYv1vhjmyb4DxY825AVAwic",
        ),
        (
            ID_PARENT_VDXF_KEY,
            "vrsc::identity.parent",
            "i6aJSTKfNiDZ4rPxj1pPh4Y8xDmh1GqYm9",
        ),
        (
            ID_SYSTEMID_VDXF_KEY,
            "vrsc::identity.systemid",
            "iMZTNkNBgBXNHkMLipQw9wQb56pxBSEp3k",
        ),
    ];

    /// Mainnet's root currency id — `root_namespace("vrsc")`, which the module
    /// above already proves against a live `getvdxfid`.
    fn vrsc() -> CurrencyId {
        root_namespace("vrsc").expect("a root name")
    }

    /// Resolve the namespace half of a qualified name the way the daemon does,
    /// for the two shapes `keys.ts` actually uses.
    ///
    /// `vrsc` is a root name. `veruspay.vrsc` is **not** — it is an identity
    /// registered under `vrsc`, so it goes through [`identity_id`], and
    /// `root_namespace` refuses it. That distinction is the whole reason this
    /// helper exists rather than a call to `qualified_key`.
    fn namespace_of(uri: &str) -> CurrencyId {
        let (namespace, _) = uri.split_once("::").expect("a qualified name");
        match namespace.split_once('.') {
            None => root_namespace(namespace).expect("a root name"),
            Some((child, parent)) => {
                let parent = root_namespace(parent).expect("a root name");
                CurrencyId::from_bytes(identity_id(child, Some(parent.to_bytes())))
            }
        }
    }

    /// The check the table exists for: each constant is what this crate's own
    /// derivation produces from upstream's qualified name, and is what upstream's
    /// published i-address decodes to.
    ///
    /// Three independent statements per key, which is why a single typo cannot
    /// pass: the constant, the name, and the address have to agree.
    #[test]
    fn every_constant_derives_from_its_qualified_name_and_matches_upstreams_address() {
        for (constant, uri, vdxfid) in UPSTREAM {
            let (_, name) = uri.split_once("::").expect("a qualified name");
            let derived = data_key(name, namespace_of(uri), "VRSC")
                .unwrap_or_else(|error| panic!("{uri} does not derive: {error}"));
            assert_eq!(
                derived, *constant,
                "{uri}: the constant is not what the derivation produces"
            );
            assert_eq!(
                Address::new(AddressKind::Identity, *constant).to_string(),
                *vdxfid,
                "{uri}: the constant is not upstream's published vdxfid"
            );
        }
    }

    /// No two keys are the same twenty bytes, which a copy-paste slip in the
    /// constants above would produce and the per-key assertions would not catch
    /// on their own.
    #[test]
    fn the_constants_are_distinct() {
        let mut seen: Vec<[u8; 20]> = Vec::new();
        for (constant, uri, _) in UPSTREAM {
            assert!(!seen.contains(constant), "{uri} duplicates an earlier key");
            seen.push(*constant);
        }
        assert_eq!(seen.len(), 16, "the on-path set named in the module docs");
    }

    /// The VerusPay namespace, derived rather than copied — and the trap it
    /// demonstrates.
    #[test]
    fn the_veruspay_namespace_is_an_identity_under_vrsc_not_a_root_name() {
        assert_eq!(
            VERUSPAY_NAMESPACE.to_bytes(),
            identity_id("veruspay", Some(vrsc().to_bytes())),
        );
        assert_eq!(
            Address::new(AddressKind::Identity, VERUSPAY_NAMESPACE.to_bytes()).to_string(),
            "iAisVse7piEiE2VsixZx4SARyHzSpxYxgq",
            "the namespace upstream's keys.ts records for veruspay.vrsc"
        );
        // The trap: the root name `veruspay` is a different id entirely, and
        // `root_namespace` will not derive the two-component form at all.
        assert_ne!(
            VERUSPAY_NAMESPACE.to_bytes(),
            root_namespace("veruspay").unwrap().to_bytes()
        );
        assert!(root_namespace("veruspay.vrsc").is_err());
        // And it is the namespace the invoice keys really hang off.
        assert_eq!(
            data_key("invoice", VERUSPAY_NAMESPACE, "VRSC").unwrap(),
            VERUSPAY_INVOICE_VDXF_KEY
        );
    }

    /// `hash160result` in `keys.ts` is the wire bytes **reversed**, so consuming
    /// it raw gives twenty bytes that are not any key.
    ///
    /// Pinned because it is a one-line mistake with no symptom until a wallet
    /// looks for data under an address nothing is at.
    #[test]
    fn hash160result_is_the_reverse_of_the_wire_bytes() {
        // keys.ts: VERUSPAY_INVOICE_VDXF_KEY.hash160result
        let printed = hex::decode("628efc28c2e2d40050e1a9de7a93e7ddf2aa0076").unwrap();
        let mut reversed = printed.clone();
        reversed.reverse();
        assert_eq!(reversed, VERUSPAY_INVOICE_VDXF_KEY.to_vec());
        assert_ne!(printed, VERUSPAY_INVOICE_VDXF_KEY.to_vec());
    }

    /// The upstream source of record also exports these twenty bytes as
    /// `LOGIN_CONSENT_RESPONSE_SIG_VDXF_KEY`. One constant, one qualified name,
    /// asserted once — so the alias cannot drift from the thing it aliases.
    #[test]
    fn the_signature_key_has_one_value_under_both_upstream_names() {
        assert_eq!(
            data_key(
                "identity.authentication.signature",
                root_namespace("vrsc").unwrap(),
                "VRSC"
            )
            .unwrap(),
            IDENTITY_AUTH_SIG_VDXF_KEY
        );
    }
}
