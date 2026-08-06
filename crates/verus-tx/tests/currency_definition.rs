//! Rebuild all 26 daemon currency definitions byte-for-byte.
//!
//! The vectors in `fixtures/daemon/currency_definitions.json` are output scripts
//! `verusd` 1.2.17-2 produced on VRSCTEST. Each carries the daemon's own JSON
//! view of the definition alongside the bytes, so the encoder is driven from the
//! description and checked against the script.
//!
//! One of them, `nft_tokenized_control`, is not a capture of our own request but
//! output 1 of a real NFT launch on VRSCTEST. It was the shape with no coverage
//! at all, and an NFT is the one definition whose fields cannot be read off the
//! type — see `CurrencyDefinition::nft`.
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
    value.map_or(0, sats)
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
        initial_supply: definition.get("initialsupply").map_or(Amount::ZERO, coins),
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
    assert_eq!(vectors.len(), 26, "all the captured permutations");

    // Collect every mismatch rather than stopping at the first. Stopping hides
    // how wide a problem is, and across 26 vectors the difference between "one
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

/// **`CurrencyDefinition::nft` reproduces a real NFT.**
///
/// Not "builds something plausible": the constructor's output is encoded and
/// compared against the definition script the daemon itself wrote for
/// `sdknftbeta` on VRSCTEST. Five fields have to agree for consensus to accept
/// an NFT and four of them are not guessable from the type, so this is exactly
/// the claim the constructor makes.
///
/// Two things are taken from the fixture rather than left as the constructor
/// set them, because they are the caller's to choose: the option bits beyond
/// `NFT_TOKEN` (this launch also set `SINGLECURRENCY`, which 13 of the 15 NFTs
/// on chain leave clear) and the parent's fee schedule.
#[test]
fn the_nft_constructor_reproduces_a_daemon_built_nft() {
    let vector = &vectors()["nft_tokenized_control"];
    let expected = vector["definition_script"].as_str().expect("script");
    let daemon = from_daemon_json(&vector["definition"]);

    let holder = daemon.preallocations[0].recipient;
    let mut built =
        CurrencyDefinition::nft(daemon.parent, &daemon.name, daemon.start_block, holder);
    built.options = daemon.options;
    built.id_registration_fees = daemon.id_registration_fees;
    built.id_referral_levels = daemon.id_referral_levels;
    built.id_import_fees = daemon.id_import_fees;

    assert_eq!(
        built, daemon,
        "the constructor's definition differs from the daemon's"
    );
    assert_eq!(
        hex::encode(currency_definition_script(&built).expect("encode")),
        expected,
        "and so do the bytes"
    );
}

/// An NFT under a **sub-identity** parent still reserves the system's currency.
///
/// The fixture NFT is defined at the root, where parent and system are the same
/// id — so it cannot tell the two apart, and a constructor following the parent
/// would pass every other test here. Seven of the fifteen NFTs on VRSCTEST are
/// this shape: `currencies == [systemid]` holds for all fifteen, `== [parent]`
/// for only eight.
#[test]
fn an_nft_under_a_sub_parent_reserves_the_system_not_the_parent() {
    let system = i_address("iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq");
    let sub_parent = i_address("i77n5FCqSBkXAK3UWHpdrPpdtXRc8sqjoz");

    // `token` sets the system to the parent; a currency under a sub-identity
    // lives on the chain's system, so the caller corrects it — and `currencies`
    // has to follow, which is the pair the encoder checks.
    let mut definition = CurrencyDefinition::nft(sub_parent, "under", 1_000, [0x2b; 20]);
    definition.system_id = system;
    definition.launch_system_id = system;
    definition.currencies = vec![system];
    assert!(
        currency_definition_script(&definition).is_ok(),
        "the system as reserve is the shape every NFT on chain has"
    );

    // Leaving `currencies` on the parent after moving the system is refused,
    // not silently encoded into a definition consensus would reject.
    let mut mismatched = definition.clone();
    mismatched.currencies = vec![sub_parent];
    let error = currency_definition_script(&mismatched)
        .expect_err("a reserve that is not the system is refused")
        .to_string();
    assert!(error.contains("reserve currency is its system"), "{error}");
}

/// The rules consensus enforces on an NFT, each broken on its own.
///
/// Consensus rejects every one of these with `-25: bad-txns-failed-precheck`,
/// which names neither the field nor what it wanted — `main.cpp:1513` replaces
/// the specific message with one generic string before it reaches the client.
/// Turning that into a local error with a name is most of the value here; the
/// rules are fixed rather than judgement calls.
#[test]
fn an_nft_that_cannot_be_valid_is_refused_locally() {
    let parent = i_address("iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq");
    let good = CurrencyDefinition::nft(parent, "anft", 1_000, [0x2b; 20]);
    assert!(
        currency_definition_script(&good).is_ok(),
        "the constructor's own output must encode"
    );

    // Each case breaks exactly one rule and asserts the refusal names it. A
    // test that only checked `is_err()` would pass on a definition refused for
    // an unrelated reason, which is how the generic per-reserve check masked
    // the empty-`currencies` case until the NFT rules were moved ahead of it.
    let refused = |label: &str, broken: &CurrencyDefinition, expected: &str| {
        let error = currency_definition_script(broken)
            .expect_err(&format!("{label}: consensus would refuse this"))
            .to_string();
        assert!(
            error.contains(expected),
            "{label}: the refusal must name what is wrong, got: {error}"
        );
    };

    let mut no_preallocation = good.clone();
    no_preallocation.preallocations.clear();
    refused("no preallocation at all", &no_preallocation, "one satoshi");

    let mut whole_coin = good.clone();
    whole_coin.preallocations[0].amount = Amount::from_sat(100_000_000);
    refused(
        "a whole coin instead of one satoshi",
        &whole_coin,
        "one satoshi",
    );

    let mut no_max = good.clone();
    no_max.max_preconversion.clear();
    refused("no max_preconversion", &no_max, "max_preconversion");

    let mut nonzero_max = good.clone();
    nonzero_max.max_preconversion = vec![Amount::from_sat(1)];
    refused(
        "a non-zero max_preconversion",
        &nonzero_max,
        "max_preconversion",
    );

    let mut no_reserve = good.clone();
    no_reserve.currencies.clear();
    refused("no reserve currency", &no_reserve, "reserve currency");

    // The trap the chain settles: seven of the fifteen NFTs on VRSCTEST sit
    // under a non-root parent and still hold the system's currency, so
    // following the parent here is wrong.
    let mut parent_as_reserve = good.clone();
    parent_as_reserve.parent = i_address("i77n5FCqSBkXAK3UWHpdrPpdtXRc8sqjoz");
    parent_as_reserve.currencies = vec![parent_as_reserve.parent];
    refused(
        "the parent as reserve, where it is not the system",
        &parent_as_reserve,
        "reserve currency is its system",
    );

    let mut declared_supply = good.clone();
    declared_supply.initial_supply = Amount::from_sat(100_000_000);
    refused(
        "a declared initial supply",
        &declared_supply,
        "initial_supply must be zero",
    );
}

/// The checks are for NFTs only. A plain token preallocates nothing, carries no
/// reserve and declares a supply — every one of the rules above — and must
/// still encode.
#[test]
fn the_nft_rules_do_not_touch_an_ordinary_token() {
    let parent = i_address("iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq");
    let mut token = CurrencyDefinition::token(parent, "atoken", 1_000);
    token.initial_supply = Amount::from_sat(100_000_000);
    assert!(currency_definition_script(&token).is_ok());
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
