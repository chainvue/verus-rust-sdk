//! Rebuild all 25 daemon currency definitions byte-for-byte.
//!
//! The vectors in `fixtures/daemon/currency_definitions.json` are output scripts
//! `verusd` 1.2.17-2 produced on VRSCTEST. Each carries the daemon's own JSON
//! view of the definition alongside the bytes, so the encoder is driven from the
//! description and checked against the script.
//!
//! That makes this test self-validating in a useful way: if any field were read
//! wrongly — an amount off by a factor, a vector in the wrong order, a varint
//! where a fixed width belongs — the bytes would not match. Nothing here has to
//! be trusted, because the comparison is total.

use std::collections::BTreeMap;

use verus_tx::currency_definition::{
    currency_definition_script, option, CurrencyDefinition, Preallocation,
};
use verus_tx::{Amount, CurrencyId};

/// The daemon prints amounts as JSON floats. Reading one back through `f64` is
/// exactly the hazard `Amount` exists to prevent, so it is confined to this
/// helper, in a test, over values a daemon chose.
///
/// It is also self-checking: every amount feeds a byte comparison against the
/// daemon's own script, so a misread cannot pass. `{:.8}` then exact decimal
/// parsing keeps the conversion honest rather than multiplying by 1e8.
fn coins(value: &serde_json::Value) -> Amount {
    let float = value.as_f64().expect("an amount");
    Amount::from_coins_str(&format!("{float:.8}")).expect("an exact decimal")
}

fn sats(value: &serde_json::Value) -> u64 {
    coins(value).to_sat()
}

/// An `i` address is base58check over the same 20 bytes a currency id holds.
fn i_address(text: &str) -> CurrencyId {
    let address: verus_keys::Address = text.parse().expect("an i-address");
    CurrencyId::from_bytes(address.hash())
}

fn currency(value: &serde_json::Value) -> CurrencyId {
    i_address(value.as_str().expect("an i-address"))
}

fn currencies(value: Option<&serde_json::Value>) -> Vec<CurrencyId> {
    value
        .and_then(|v| v.as_array())
        .map(|list| list.iter().map(currency).collect())
        .unwrap_or_default()
}

fn amounts(value: Option<&serde_json::Value>) -> Vec<Amount> {
    value
        .and_then(|v| v.as_array())
        .map(|list| list.iter().map(coins).collect())
        .unwrap_or_default()
}

/// Weights are `int32` satoshi-scaled ratios.
fn weights(value: Option<&serde_json::Value>) -> Vec<i32> {
    value
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .map(|w| i32::try_from(sats(w)).expect("a weight fits int32"))
                .collect()
        })
        .unwrap_or_default()
}

fn integer(value: Option<&serde_json::Value>) -> u64 {
    value.and_then(serde_json::Value::as_u64).unwrap_or(0)
}

/// A daemon integer that belongs in a 32-bit field. `try_from` rather than `as`:
/// a truncated version or option word would silently describe a different
/// currency.
fn narrow<T: TryFrom<u64>>(value: Option<&serde_json::Value>) -> T {
    T::try_from(integer(value)).unwrap_or_else(|_| panic!("value does not fit its field"))
}

fn fee(value: Option<&serde_json::Value>) -> u64 {
    value.map(sats).unwrap_or(0)
}

/// Build a definition from the daemon's own JSON description of it.
fn from_daemon_json(definition: &serde_json::Value) -> CurrencyDefinition {
    let preallocations = definition
        .get("preallocations")
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .map(|entry| {
                    // Each entry is a single-key object: { "<i-address>": amount }.
                    let map: BTreeMap<String, serde_json::Value> =
                        serde_json::from_value(entry.clone()).expect("a preallocation entry");
                    let (address, amount) = map.iter().next().expect("one key");
                    Preallocation {
                        recipient: i_address(address).to_bytes(),
                        amount: coins(amount),
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    CurrencyDefinition {
        version: narrow(definition.get("version")),
        options: narrow(definition.get("options")),
        parent: currency(&definition["parent"]),
        name: definition["name"].as_str().expect("a name").to_string(),
        launch_system_id: currency(&definition["launchsystemid"]),
        system_id: currency(&definition["systemid"]),
        notarization_protocol: narrow(definition.get("notarizationprotocol")),
        proof_protocol: narrow(definition.get("proofprotocol")),
        start_block: integer(definition.get("startblock")),
        end_block: integer(definition.get("endblock")),
        initial_supply: definition
            .get("initialsupply")
            .map(coins)
            .unwrap_or(Amount::ZERO),
        preallocations,
        gateway_converter_issuance: Amount::ZERO,
        currencies: currencies(definition.get("currencies")),
        weights: weights(definition.get("weights")),
        conversions: amounts(definition.get("conversions")),
        min_preconversion: amounts(definition.get("minpreconversion")),
        max_preconversion: amounts(definition.get("maxpreconversion")),
        initial_contributions: amounts(definition.get("initialcontributions")),
        // The daemon never echoes `preconverted` in its JSON view, yet every
        // captured script carries it — equal to `initialcontributions`, because
        // a contribution made at definition time is already converted. So it is
        // mirrored here rather than left empty.
        preconverted: match definition.get("preconverted") {
            Some(explicit) => amounts(Some(explicit)),
            None => amounts(definition.get("initialcontributions")),
        },
        prelaunch_discount: fee(definition.get("prelaunchdiscount")),
        prelaunch_carveout: i32::try_from(fee(definition.get("prelaunchcarveout")))
            .expect("a carve-out fits int32"),
        notaries: currencies(definition.get("notaries")),
        min_notaries_confirm: integer(definition.get("minnotariesconfirm")),
        id_registration_fees: fee(definition.get("idregistrationfees")),
        id_referral_levels: integer(definition.get("idreferrallevels")),
        id_import_fees: fee(definition.get("idimportfees")),
    }
}

fn vectors() -> serde_json::Map<String, serde_json::Value> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/daemon/currency_definitions.json"
    );
    let file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("fixture")).expect("json");
    file["vectors"].as_object().expect("vectors").clone()
}

/// **The whole point.** Every committed daemon definition, rebuilt exactly.
#[test]
fn every_daemon_definition_is_reproduced_byte_for_byte() {
    let vectors = vectors();
    assert_eq!(vectors.len(), 25, "all the captured permutations");

    // Collect every mismatch rather than stopping at the first. Stopping hides
    // how wide a problem is, and with 25 vectors the difference between "one
    // field" and "everything" is the whole diagnosis.
    let mut failures = Vec::new();
    for (name, vector) in &vectors {
        let expected = vector["definition_script"]
            .as_str()
            .expect("a definition script");
        let definition = from_daemon_json(&vector["definition"]);

        match currency_definition_script(&definition) {
            Ok(built) if hex::encode(&built) == expected => {}
            Ok(built) => failures.push(format!(
                "{name}:\n  built    {}\n  expected {expected}",
                hex::encode(&built)
            )),
            Err(e) => failures.push(format!("{name}: {e}")),
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} definitions differ:\n{}",
        failures.len(),
        vectors.len(),
        failures.join("\n")
    );
}

/// The tokens and the baskets are both covered, so a pass is not an accident of
/// every vector being the same shape.
#[test]
fn the_vectors_cover_both_tokens_and_fractional_baskets() {
    let vectors = vectors();
    let mut tokens = 0;
    let mut fractional = 0;
    for vector in vectors.values() {
        if from_daemon_json(&vector["definition"]).is_fractional() {
            fractional += 1;
        } else {
            tokens += 1;
        }
    }
    assert!(tokens >= 10, "only {tokens} plain tokens");
    assert!(fractional >= 10, "only {fractional} fractional baskets");
}

/// A gateway or PBaaS definition carries trailing fields this does not write, so
/// it is refused rather than encoded short.
#[test]
fn gateway_and_pbaas_definitions_are_refused() {
    let parent = i_address("iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq");

    for extra in [option::GATEWAY, option::PBAAS, option::GATEWAY_CONVERTER] {
        let mut definition = CurrencyDefinition::token(parent, "whatever", 1_000);
        definition.options |= extra;
        assert!(
            currency_definition_script(&definition).is_err(),
            "options {extra:#x} should be refused"
        );
    }
}

/// A per-reserve vector of the wrong length would attribute an amount to the
/// wrong currency, which parses fine and means something else.
#[test]
fn a_short_per_reserve_vector_is_refused() {
    let parent = i_address("iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq");
    let other = i_address("i9G2QgG74f7tErEyF3cWp2x1exBGbFa19t");

    let mut definition = CurrencyDefinition::token(parent, "basket", 1_000);
    definition.options |= option::FRACTIONAL;
    definition.currencies = vec![parent, other];
    definition.weights = vec![50_000_000, 50_000_000];
    // Two reserves, one minimum.
    definition.min_preconversion = vec![Amount::from_sat(1)];

    let err = currency_definition_script(&definition).unwrap_err();
    assert!(err.to_string().contains("wrong currency"), "{err}");
}

/// A name is length-prefixed and capped at 64 bytes on the wire.
#[test]
fn an_overlong_name_is_refused() {
    let parent = i_address("iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq");
    let definition = CurrencyDefinition::token(parent, "n".repeat(65), 1_000);
    assert!(currency_definition_script(&definition).is_err());
}
