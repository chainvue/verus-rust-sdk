//! VDXF keys, derived offline.
//!
//! A VDXF key is the 20 bytes that address a piece of data on an identity —
//! `getvdxfid`'s answer. It is pure hashing, so an application can compute the
//! keys it uses at build time and never ask a node for one. That matters in a
//! browser: it is one fewer round trip on every read, and the key an app writes
//! to is no longer something a node gets to decide.
//!
//! # The namespace trap
//!
//! A friendly namespace resolves as a **root** name. `myapp::profile` is keyed
//! under the id of the top-level name `myapp`, which is almost certainly not
//! the identity `myapp.VRSCTEST@` that an application actually registered. An
//! app with a chain-registered identity should namespace by that identity's
//! `i` address, and [`vdxf_key`] takes one directly for exactly that
//! reason. Getting it wrong publishes content where nothing will look for it,
//! silently and forever.

use wasm_bindgen::prelude::*;

use crate::dto;
use crate::error::{WasmError, WasmResult};
use crate::types::{JsOptionalText, JsText};

/// Host-testable core of [`vdxf_key`].
pub(crate) fn key_for_uri(uri: &str, chain_name: &str, chain_id: &str) -> WasmResult<String> {
    let chain = dto::currency("chainId", chain_id)?;
    Ok(dto::identity_address(
        verus_tx::qualified_key(uri, chain_name, chain).map_err(WasmError::from)?,
    ))
}

/// Host-testable core of [`vdxf_key_in`].
pub(crate) fn key_in(name: &str, namespace: &str, chain_name: &str) -> WasmResult<String> {
    let namespace = dto::currency("namespace", namespace)?;
    Ok(dto::identity_address(
        verus_tx::data_key(name, namespace, chain_name).map_err(WasmError::from)?,
    ))
}

/// Host-testable core of [`root_namespace`].
pub(crate) fn root_id(name: &str) -> WasmResult<String> {
    Ok(dto::identity_address(
        verus_tx::root_namespace(name)
            .map_err(WasmError::from)?
            .to_bytes(),
    ))
}

/// Host-testable core of [`identity_id`].
pub(crate) fn id_for(name: &str, parent: Option<&str>) -> WasmResult<String> {
    let parent = match parent {
        None => None,
        Some(text) => Some(dto::identity_id("parent", text)?),
    };
    Ok(dto::identity_address(verus_tx::identity_id(name, parent)))
}

/// The VDXF key for `uri`, as the daemon's `getvdxfid` computes it.
///
/// `uri` is a bare name (`"profile"`), or a namespaced one — either friendly
/// (`"myapp::profile"`, a **root** name; see the module docs) or, preferably,
/// by i-address (`"iRRhs…::profile"`).
///
/// `chainName` and `chainId` describe the chain the key will be read on:
/// `"VRSCTEST"` and its currency i-address. Both are constants for an
/// application that targets one chain.
///
/// Returns the i-address form — the same string `getvdxfid` prints as
/// `vdxfid`. Note that the daemon's `hash160result` field is the same bytes
/// printed in the opposite order; comparing against that rather than `vdxfid`
/// will look like a mismatch when nothing is wrong.
///
/// ```js
/// vdxfKey("iRRhsKoiBuMoyANFcQ2NMLJXDgfSHjgffS::profile", "VRSCTEST", chainId)
/// ```
#[wasm_bindgen(js_name = vdxfKey)]
pub fn vdxf_key(uri: JsText, chain_name: JsText, chain_id: JsText) -> Result<String, WasmError> {
    key_for_uri(
        &dto::text("uri", uri.as_ref())?,
        &dto::text("chainName", chain_name.as_ref())?,
        &dto::text("chainId", chain_id.as_ref())?,
    )
}

/// The VDXF key for `name` inside an explicit namespace.
///
/// The unambiguous form: no URI parsing, no root-name resolution, and the
/// namespace is whatever i-address you pass — normally your application
/// identity's. Prefer this over [`vdxf_key`] when the namespace is known.
#[wasm_bindgen(js_name = vdxfKeyIn)]
pub fn vdxf_key_in(
    name: JsText,
    namespace: JsText,
    chain_name: JsText,
) -> Result<String, WasmError> {
    key_in(
        &dto::text("name", name.as_ref())?,
        &dto::text("namespace", namespace.as_ref())?,
        &dto::text("chainName", chain_name.as_ref())?,
    )
}

/// The id of a top-level name, as an i-address.
///
/// This is what a friendly `ns::` namespace resolves to. Useful for seeing
/// where a `myapp::` key would actually land before committing to it.
#[wasm_bindgen(js_name = rootNamespace)]
pub fn root_namespace(name: JsText) -> Result<String, WasmError> {
    root_id(&dto::text("name", name.as_ref())?)
}

/// The i-address of an identity name, given its parent.
///
/// `identityId("alice", parentIAddress)` is the id of `alice.parent@`. Pass
/// `null` for a root name. This is the same derivation identity registration
/// uses, exposed because an application usually needs to *address* an identity
/// long before it registers one.
#[wasm_bindgen(js_name = identityId)]
pub fn identity_id(name: JsText, parent: JsOptionalText) -> Result<String, WasmError> {
    id_for(
        &dto::text("name", name.as_ref())?,
        dto::optional_text("parent", parent.as_ref())?.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// VRSCTEST's own currency id.
    const VRSCTEST: &str = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";

    /// Locked against `getvdxfid` on a live daemon, as `crates/verus-tx` locks
    /// the derivation itself. Repeated here because the binding adds two
    /// conversions on top — an i-address in and an i-address out — and either
    /// could be wrong while the derivation is right.
    #[test]
    fn known_keys_match_the_daemon() {
        for (uri, expected) in [
            ("test", "i67adKXncRAtgsmoZpSCRA6iba5U7SPgF4"),
            (
                "vrsc::identity.profile",
                "iJ1BsyA9mx5RVk3ePK2WDgFcFCcfsXkBbA",
            ),
            (
                "iKzX5FyzKzYxtcWKYveYKVfrz2LNXLj4xM::x",
                "i4BJreZax799f7H73eXwaJBUXxW7YbTRpw",
            ),
        ] {
            assert_eq!(
                key_for_uri(uri, "VRSCTEST", VRSCTEST).unwrap(),
                expected,
                "{uri}"
            );
        }
    }

    /// The explicit form and the URI form have to agree when the namespace is
    /// spelled the same way, or one of the two is lying about what it derives.
    #[test]
    fn the_explicit_form_agrees_with_the_uri_form() {
        let namespace = root_id("vrsc").unwrap();
        assert_eq!(namespace, "i5w5MuNik5NtLcYmNzcvaoixooEebB6MGV");
        assert_eq!(
            key_in("identity.profile", &namespace, "VRSCTEST").unwrap(),
            key_for_uri("vrsc::identity.profile", "VRSCTEST", VRSCTEST).unwrap()
        );
    }

    /// The trap, pinned: a friendly namespace is NOT the chain-local identity
    /// of the same name. If these ever became equal, the warning in the module
    /// docs would have quietly stopped being true.
    #[test]
    fn a_friendly_namespace_is_not_the_chain_local_identity() {
        // Both values are the daemon's own, for the currency this repo
        // launched on VRSCTEST: `rusttok1168500::` resolves to the ROOT name,
        // while the identity actually registered on the chain is a different
        // id entirely.
        assert_eq!(
            root_id("rusttok1168500").unwrap(),
            "iNE3BTd2SEo7UPQrsvDNikLNtfMkztxnSn"
        );
        assert_eq!(
            id_for("rusttok1168500", Some(VRSCTEST)).unwrap(),
            "iKzX5FyzKzYxtcWKYveYKVfrz2LNXLj4xM"
        );
    }

    #[test]
    fn a_name_the_daemon_would_rewrite_is_refused() {
        assert!(key_in("a*b", VRSCTEST, "VRSCTEST").is_err());
        assert!(root_id("a  b").is_err());
    }

    #[test]
    fn a_root_identity_id_needs_no_parent() {
        let root = id_for("vrsc", None).unwrap();
        assert_eq!(root, root_id("vrsc").unwrap());
    }
}
