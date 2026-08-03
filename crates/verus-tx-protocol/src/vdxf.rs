//! VDXF data keys, derived offline.
//!
//! VDXF is Verus's namespace for structured data. Every entry an application
//! writes into an identity's `contentmap` or `contentmultimap` is addressed by
//! a 20-byte key derived from a human-readable name — `vrsc::identity.profile`,
//! `myapp::settings.theme` — so that the same name yields the same key for
//! everyone, and two applications cannot collide without choosing to.
//!
//! Until now the only way to that key was asking a node (`getvdxfid`). This
//! module is the derivation itself, ported from `CVDXF::GetDataKey` in the
//! daemon's `pbaas/vdxf.cpp` and byte-locked against `getvdxfid` output — the
//! node becomes the test oracle instead of a runtime dependency, and an
//! offline signer can know where its data lives.
//!
//! # The derivation
//!
//! One primitive, applied recursively: a name component is hashed into its
//! parent as `hash160(sha256d(parent_20 ‖ sha256d(lowercase(component))))`,
//! where the root of a data key is the **namespace** — a currency id — hashed
//! under the literal separator string `"::"`. Dotted names nest right to left,
//! exactly like identity names: `a.b` is `a` under `b`.
//!
//! # What resolves to what — two traps
//!
//! * **A friendly namespace is a root name.** `rusttok1168500::x` derives its
//!   namespace as the *root* identity `rusttok1168500` — which is NOT
//!   `rusttok1168500.VRSCTEST@`. An application whose identity lives under a
//!   chain must namespace by its **`i` address**, not its friendly name. The
//!   daemon behaves identically; this is a property of VDXF, not this port.
//! * **The chain's own name is stripped when it qualifies.** On VRSCTEST,
//!   `a.vrsctest` and `a` are the same key, and `vrsctest::a` is `a` in the
//!   default namespace. That is why [`data_key`] takes the chain name: the
//!   derivation is chain-relative in exactly this one way.
//!
//! # Refusals
//!
//! The daemon accepts more than this module does. It truncates over-long
//! components to 64 bytes, normalises exotic UTF-8, strips characters from
//! its invalid list, hashes through embedded NULs, and silently discards
//! everything after an `@`; every one of those would derive a *different key
//! than the caller wrote*, so names that would need any of them are refused
//! instead. The contract is: **everything this module accepts, the daemon
//! derives identically; everything else is an error here, never a different
//! key.** `@` is refused for the same reason: `name@` is an identity, derived
//! by [`crate::identity_id`], not a data key.

use verus_keys::hash160;
use verus_wire::hash::sha256d;

use verus_tx_primitives::CurrencyId;
use verus_tx_primitives::TxError;

/// The literal separator hashed between a namespace and its keys.
///
/// `CVDXF::DATA_KEY_SEPARATOR`. It is hashed as the *name* `"::"` under the
/// namespace id — not split, not cleaned.
const DATA_KEY_SEPARATOR: &str = "::";

/// The longest a single name component may be, in bytes.
///
/// `KOMODO_ASSETCHAIN_MAXLEN - 1`. The daemon silently truncates longer ones,
/// which changes the key; this module refuses instead.
const MAX_COMPONENT: usize = 64;

/// One step of the chain: `component` hashed under an optional parent.
///
/// `CVDXF::GetID`. The component is lowercased first — derivation is
/// case-insensitive everywhere.
fn hash_component(component: &str, parent: Option<[u8; 20]>) -> [u8; 20] {
    let name_hash = sha256d(component.to_lowercase().as_bytes());
    match parent {
        None => hash160(&name_hash),
        Some(parent) => {
            let mut joined = [0u8; 52];
            joined[..20].copy_from_slice(&parent);
            joined[20..].copy_from_slice(&name_hash);
            hash160(&sha256d(&joined))
        }
    }
}

/// Check a single component against the conservative subset this module
/// derives for. See the module docs for why refusal beats daemon-compatible
/// silent rewriting.
fn check_component(component: &str, whole: &str) -> Result<(), TxError> {
    if component.is_empty() {
        return Err(TxError::InvalidVdxfName(format!(
            "{whole:?} has an empty name component"
        )));
    }
    if component.len() > MAX_COMPONENT {
        return Err(TxError::InvalidVdxfName(format!(
            "component {component:?} exceeds {MAX_COMPONENT} bytes; the daemon would silently truncate it"
        )));
    }
    if component != component.trim() {
        return Err(TxError::InvalidVdxfName(format!(
            "component {component:?} has leading or trailing whitespace"
        )));
    }
    if !component.is_ascii() {
        return Err(TxError::InvalidVdxfName(format!(
            "component {component:?} is not ASCII; the daemon's UTF-8 normalisation is not ported"
        )));
    }
    if component.contains(['@', ':', '/', '\\', '*', '?', '"', '<', '>', '|']) {
        // The daemon strips these via TrimSpaces' invalid-character list and
        // then errors on the mismatch — except where it silently rewrites.
        // Refusing them all means this port never derives a key the daemon
        // would not issue for the same string.
        return Err(TxError::InvalidVdxfName(format!(
            "component {component:?} contains a structural character"
        )));
    }
    if component.chars().any(|c| c.is_ascii_control()) {
        // NUL is the dangerous one: the daemon hashes through strlen(), so
        // "a\0b" derives as "a" there and as three bytes here. The rest of
        // the control range is refused with it — stricter than the daemon in
        // places, but stricter is the safe direction.
        return Err(TxError::InvalidVdxfName(format!(
            "component {component:?} contains a control character"
        )));
    }
    Ok(())
}

/// Split a dotted name into checked components, dropping one trailing empty
/// component (`"a."` is `"a"`, as the daemon reads it) and a trailing
/// component equal to the chain's name (`a.vrsctest` is `a` on VRSCTEST).
fn components<'a>(name: &'a str, chain_name: &str) -> Result<Vec<&'a str>, TxError> {
    let mut parts: Vec<&str> = name.split('.').collect();
    if parts.len() > 1 && parts.last() == Some(&"") {
        parts.pop();
    }
    if parts.len() > 1
        && parts
            .last()
            .is_some_and(|last| last.eq_ignore_ascii_case(chain_name))
    {
        parts.pop();
    }
    for part in &parts {
        check_component(part, name)?;
    }
    Ok(parts)
}

/// The VDXF data key for `name` in `namespace`.
///
/// This is what `getvdxfid` computes, offline. `namespace` is the currency id
/// the key lives under — for an application, usually its identity's `i`
/// address ([`CurrencyId::of_identity`]); for chain-global keys, the chain's
/// own currency id. `chain_name` is the chain the key will be read on
/// (`"VRSCTEST"`, `"VRSC"`) — see the module docs for the one way derivation
/// depends on it.
///
/// The returned 20 bytes are what goes in a `contentmultimap`; rendered as an
/// `i` address they are the `vdxfid` the daemon prints.
pub fn data_key(name: &str, namespace: CurrencyId, chain_name: &str) -> Result<[u8; 20], TxError> {
    let parts = components(name, chain_name)?;
    // The namespace is joined through the literal separator first.
    let mut parent = hash_component(DATA_KEY_SEPARATOR, Some(namespace.to_bytes()));
    // Then the name nests right to left, the same direction identity names do.
    for part in parts.iter().skip(1).rev() {
        parent = hash_component(part, Some(parent));
    }
    Ok(hash_component(parts[0], Some(parent)))
}

/// The id of a **root** name — `vrsc`, or any top-level identity.
///
/// `CVDXF::GetID` with no parent. This is how a friendly `ns::` namespace
/// resolves: `vrsc::…` keys live under `root_namespace("vrsc")`, which on any
/// chain is the id of mainnet's root currency. Remember the trap: this is not
/// the id of `name.VRSCTEST@` — a chain-local identity's id needs
/// [`crate::identity_id`] with its parent.
pub fn root_namespace(name: &str) -> Result<CurrencyId, TxError> {
    let mut parts: Vec<&str> = name.split('.').collect();
    if parts.len() > 1 && parts.last() == Some(&"") {
        parts.pop();
    }
    if parts.len() != 1 {
        return Err(TxError::InvalidVdxfName(format!(
            "{name:?} is not a root name; derive nested identities with identity_id"
        )));
    }
    check_component(parts[0], name)?;
    // The namespace position alone is dual-space-collapsed by the daemon
    // (`TrimSpaces(ns, removeDuals=true)`): "a  b" as a namespace is
    // rewritten there and hashed verbatim here, which would be a silent
    // divergence. Key components are NOT collapsed, so this check lives here
    // and not in check_component.
    if parts[0].contains("  ") {
        return Err(TxError::InvalidVdxfName(format!(
            "namespace {name:?} contains consecutive spaces, which the daemon rewrites"
        )));
    }
    Ok(CurrencyId::from_bytes(hash_component(parts[0], None)))
}

/// A `getvdxfid`-style URI: `name`, `ns::name`, or `i-address::name`.
///
/// Resolves the namespace the way the daemon does for the common forms: an
/// `i` address is used as-is; the chain's own name is the chain id; any other
/// friendly name is a **root** name via [`root_namespace`]. Then derives with
/// [`data_key`].
///
/// `chain_name` and `chain_id` describe the chain the key will be read on —
/// both are in `ChainReader::chain_info` for callers with a node, and both
/// are compile-time constants for an application that targets one chain.
pub fn qualified_key(
    uri: &str,
    chain_name: &str,
    chain_id: CurrencyId,
) -> Result<[u8; 20], TxError> {
    let (namespace, name) = match uri.split_once("::") {
        None => (chain_id, uri),
        Some((ns, rest)) => {
            if rest.contains("::") {
                return Err(TxError::InvalidVdxfName(format!(
                    "{uri:?} has more than one namespace separator"
                )));
            }
            // No special case for the chain's own name: on a root chain
            // (VRSC, VRSCTEST) the chain id IS the root id of its name, so
            // `vrsctest::a` falls through to root_namespace and lands on the
            // same key — and on a PBaaS chain, whose id is NOT its root name's
            // id, the daemon namespaces `chainname::x` under the ROOT name
            // too. Special-casing to `chain_id` here would diverge exactly
            // there. (`DecodeCurrencyName`'s chain-id branch requires a
            // parented, multi-component spelling — `chips.vrsc::x` — which
            // this port refuses.)
            if let Ok(address) = ns.parse::<verus_keys::Address>() {
                if address.kind() != verus_keys::AddressKind::Identity {
                    // The daemon accepts an R-address namespace (any
                    // DecodeDestination hit); a key-hash namespace is almost
                    // certainly a caller error, so it is refused rather than
                    // silently accepted.
                    return Err(TxError::InvalidVdxfName(format!(
                        "namespace {ns:?} is an address but not an i-address"
                    )));
                }
                (CurrencyId::from_bytes(address.hash()), rest)
            } else {
                (root_namespace(ns)?, rest)
            }
        }
    };
    data_key(name, namespace, chain_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use verus_keys::{Address, AddressKind};

    /// VRSCTEST's currency id.
    fn vrsctest() -> CurrencyId {
        CurrencyId::from_bytes(
            "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq"
                .parse::<Address>()
                .unwrap()
                .hash(),
        )
    }

    fn hex20(address: &str) -> [u8; 20] {
        address.parse::<Address>().unwrap().hash()
    }

    /// Every vector here is a live `getvdxfid` answer from `api.verustest.net`,
    /// captured 2026-07-30. The node is the oracle; this module must agree
    /// with it or it publishes data where nobody looks. Expected values are
    /// the daemon's `vdxfid` — the i-address rendering of the key, which is
    /// byte-order-unambiguous where the raw `hash160result` hex is printed
    /// reversed, txid-style.
    #[test]
    fn matches_the_daemon_on_every_captured_vector() {
        let cases: &[(&str, &str)] = &[
            ("test", "i67adKXncRAtgsmoZpSCRA6iba5U7SPgF4"),
            (
                "system.currency.export",
                "iMYMuZjVyw4ohvRLLyVnxgAWvaiVE1795B",
            ),
            ("a", "iPvvGS4BqZD1PHEesabBFzEWdGpXinKtgq"),
            ("a.b.c", "iGZSmKWWMvJ73Jc9EJHPCWBsSPsxV4XDvS"),
            ("a b", "i5EKis2NZXmGHogfNZsfUdYs3Bb63e6Z99"),
            // The chain's own name is stripped when it qualifies…
            ("a.vrsctest", "iPvvGS4BqZD1PHEesabBFzEWdGpXinKtgq"),
            ("a.", "iPvvGS4BqZD1PHEesabBFzEWdGpXinKtgq"),
            // …but another chain's name is an ordinary component.
            ("a.vrsc", "i9hXbVnGNoWqbupnsd3zJ1eJ3x12VMUWDP"),
            ("vrsctest::a", "iPvvGS4BqZD1PHEesabBFzEWdGpXinKtgq"),
            (
                "vrsc::identity.profile",
                "iJ1BsyA9mx5RVk3ePK2WDgFcFCcfsXkBbA",
            ),
            ("vrsc::a", "i4KSGXf9hXRuvdsMKjHQCotXPJ7vpCdKx5"),
            // Case-insensitive throughout.
            ("VRSC::A", "i4KSGXf9hXRuvdsMKjHQCotXPJ7vpCdKx5"),
            ("vrsc::a.b", "i6rCRXsyfkCqRnmW6KgQttpMVRKLQ4WHEw"),
            // A friendly namespace is a ROOT name…
            ("rusttok1168500::x", "iRpCx1n4eRyEC76wxNbtDr7cxFS98kvCUi"),
            // …and an i-address namespace is taken as-is.
            (
                "iKzX5FyzKzYxtcWKYveYKVfrz2LNXLj4xM::x",
                "i4BJreZax799f7H73eXwaJBUXxW7YbTRpw",
            ),
            // KEY components keep inner space runs verbatim — only the
            // namespace position is dual-collapsed by the daemon, and that
            // position refuses them here.
            ("a  b", "iBNkJ774DU8xxBWbxsz9xpL6Z8zGUjA2mw"),
        ];
        for (uri, expected) in cases {
            let key = qualified_key(uri, "VRSCTEST", vrsctest()).unwrap();
            assert_eq!(
                Address::new(AddressKind::Identity, key).to_string(),
                *expected,
                "{uri}"
            );
        }
    }

    /// The namespace ids the daemon reported alongside the keys above.
    #[test]
    fn namespaces_resolve_as_the_daemon_reports() {
        // vrsc:: — the root name, which is mainnet's chain id.
        assert_eq!(
            root_namespace("vrsc").unwrap().to_bytes(),
            hex20("i5w5MuNik5NtLcYmNzcvaoixooEebB6MGV")
        );
        // A friendly app namespace is ALSO a root name — not the identity
        // registered under a chain. The daemon reported iNE3BTd2…, and the
        // chain-local identity is iKzX5F…; they differ, and that difference is
        // the trap the module docs warn about.
        assert_eq!(
            root_namespace("rusttok1168500").unwrap().to_bytes(),
            hex20("iNE3BTd2SEo7UPQrsvDNikLNtfMkztxnSn")
        );
    }

    /// What the daemon refuses, this module refuses too — and what the daemon
    /// would silently rewrite, this module refuses on purpose.
    #[test]
    fn refuses_what_would_derive_a_different_key_than_written() {
        let chain = vrsctest();
        for bad in [
            "a..b",    // empty inner component (daemon: Invalid ID or URI format)
            ".a",      // empty leading component
            " a",      // leading whitespace
            "a:b",     // single colon is structural
            "x::y::z", // two namespaces
            "a@",      // the daemon DERIVES this as "a", discarding the @;
            //            refused here because silently-not-what-you-wrote
            "",                                      // nothing
            "a*b",                                   // in the daemon's invalid-character list
            "a?b",                                   // ditto
            "a\u{0}b", // the daemon hashes through strlen: "a\0b" derives as "a"
            "a\tb",    // control character
            "a  b::x", // a namespace the daemon dual-collapses to "a b"
            "RJGYC29RTSGQbWMrstQziJxfQaiDCjm5iP::x", // R-address namespace
        ] {
            assert!(
                qualified_key(bad, "VRSCTEST", chain).is_err(),
                "{bad:?} must be refused"
            );
        }
        // Over-long components are refused rather than truncated like the
        // daemon would — truncation silently changes the key.
        let long = "a".repeat(65);
        assert!(qualified_key(&long, "VRSCTEST", chain).is_err());
        // Non-ASCII is refused rather than UTF-8-normalised.
        assert!(qualified_key("café", "VRSCTEST", chain).is_err());
    }

    /// `data_key` with an explicit namespace equals the `ns::` URI form.
    #[test]
    fn explicit_namespace_and_uri_form_agree() {
        let ns = CurrencyId::from_bytes(hex20("iKzX5FyzKzYxtcWKYveYKVfrz2LNXLj4xM"));
        assert_eq!(
            data_key("x", ns, "VRSCTEST").unwrap(),
            qualified_key(
                "iKzX5FyzKzYxtcWKYveYKVfrz2LNXLj4xM::x",
                "VRSCTEST",
                vrsctest()
            )
            .unwrap()
        );
    }
}
