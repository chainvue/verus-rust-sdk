//! Rebuild a whole `definecurrency` transaction's outputs, byte-for-byte.
//!
//! `definecurrency` does not broadcast, so a complete seven-output launch
//! transaction is free to capture. Both vectors in
//! `fixtures/daemon/currency_launch.json` came off `verusd` 1.2.17-2 on VRSCTEST
//! at tip 1168306.
//!
//! # Outputs 0–5 are checked; output 6 is not
//!
//! Change value is a function of which coins fund the transaction, so neither
//! this builder nor the daemon produces a byte-identical whole transaction — its
//! *script* is checked and its value is not. The six consensus-checked outputs
//! are compared in full, and those are the ones the daemon validates against
//! chain state.

use verus_tx::currency_definition::{option, CurrencyDefinition, Preallocation};
use verus_tx::currency_launch::{build_launch_outputs, LaunchContext};
use verus_tx::identity::Identity;
use verus_tx::{Amount, CurrencyId};

fn fixture() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/daemon/currency_launch.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("fixture")).expect("json")
}

fn i_address(text: &str) -> [u8; 20] {
    let address: verus_keys::Address = text.parse().expect("an i-address");
    address.hash()
}

/// A daemon integer narrowed to the field it belongs in. `try_from`, not `as`:
/// a truncated flags word describes a different identity.
fn narrow<T: TryFrom<u64>>(value: &serde_json::Value) -> T {
    T::try_from(value.as_u64().expect("an integer")).unwrap_or_else(|_| panic!("does not fit"))
}

fn coins(text: &str) -> Amount {
    Amount::from_coins_str(text).expect("an exact decimal")
}

/// The defining identity, as the chain holds it.
fn identity(fixture: &serde_json::Value) -> (Identity, [u8; 20]) {
    let json = &fixture["identity"];
    let parent = i_address(json["parent"].as_str().unwrap());
    let identity = Identity {
        version: narrow(&json["version"]),
        flags: narrow(&json["flags"]),
        primary_addresses: json["primaryaddresses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                // A primary address is an R address, so a key hash rather than
                // an identity — the destination kind is part of the bytes.
                let address: verus_keys::Address = a.as_str().unwrap().parse().unwrap();
                verus_tx::Destination::PubKeyHash(address.hash())
            })
            .collect(),
        min_sigs: narrow(&json["minimumsignatures"]),
        name: json["name"].as_str().unwrap().to_string(),
        parent,
        system_id: i_address(json["systemid"].as_str().unwrap()),
        revocation_authority: i_address(json["revocationauthority"].as_str().unwrap()),
        recovery_authority: i_address(json["recoveryauthority"].as_str().unwrap()),
        content_map: Vec::new(),
        content_multimap: Vec::new(),
        private_addresses: Vec::new(),
        unlock_after: 0,
    };
    (
        identity,
        i_address(json["identityaddress"].as_str().unwrap()),
    )
}

fn context(fixture: &serde_json::Value) -> LaunchContext {
    let (identity, identity_address) = identity(fixture);
    LaunchContext {
        identity,
        identity_address,
        height: narrow(&fixture["height"]),
        launch_fee: coins(fixture["launch_fee_coins"].as_str().unwrap()),
    }
}

/// The token the fixture's `token_simple` vector defines.
fn token_definition(fixture: &serde_json::Value) -> CurrencyDefinition {
    let json = &fixture["identity"];
    let parent = CurrencyId::from_bytes(i_address(json["parent"].as_str().unwrap()));
    let mut definition = CurrencyDefinition::token(
        parent,
        json["name"].as_str().unwrap(),
        fixture["height"].as_u64().unwrap() + 20,
    );
    // The daemon fills in what the request omits, so a vector's definition
    // carries chain defaults as well as what was asked for. Decoded from the
    // captured bytes rather than assumed: `idimportfees` defaults to 0.02 and
    // never appeared in the request.
    definition.id_registration_fees = coins("1.00000000").to_sat();
    definition.id_import_fees = coins("0.02000000").to_sat();
    definition
}

/// The basket the fixture's `fractional_one_reserve` vector defines.
fn fractional_definition(fixture: &serde_json::Value) -> CurrencyDefinition {
    let mut definition = token_definition(fixture);
    definition.options |= option::FRACTIONAL;
    definition.currencies = vec![definition.parent];
    definition.weights = vec![100_000_000];
    definition.conversions = vec![Amount::ZERO];
    definition.initial_supply = coins("1000.00000000");
    // This request set no identity fees at all, so the basket carries the
    // chain's own defaults — 100 to register a sub-identity and three referral
    // levels, which differ from the token vector only because that one asked.
    definition.id_registration_fees = coins("100.00000000").to_sat();
    definition.id_referral_levels = 3;
    definition = definition.with_contributions(vec![Amount::ZERO]);
    definition
}

/// Compare outputs 0 through 5 against the daemon's, and output 6's script.
fn assert_matches(name: &str, built: &[verus_wire::TxOut], expected: &serde_json::Value) {
    let expected = expected["outputs"].as_array().expect("outputs");
    assert_eq!(built.len(), 7, "{name}: a launch has seven outputs");
    assert_eq!(expected.len(), 7, "{name}: the fixture has seven");

    let mut failures = Vec::new();
    for (index, (ours, theirs)) in built.iter().zip(expected).enumerate() {
        let want_script = theirs["script"].as_str().unwrap();
        if hex::encode(&ours.script_pubkey) != want_script {
            failures.push(format!(
                "  output {index} script:\n    built    {}\n    expected {want_script}",
                hex::encode(&ours.script_pubkey)
            ));
        }
        // Output 6 is change; its value depends on the funding, not the launch.
        if index < 6 {
            let want_value = coins(theirs["value_coins"].as_str().unwrap());
            if Amount::from_sat(ours.value) != want_value {
                failures.push(format!(
                    "  output {index} value: built {} expected {want_value}",
                    Amount::from_sat(ours.value)
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{name}:\n{}", failures.join("\n"));
}

/// **A whole token launch, rebuilt.**
#[test]
fn a_token_launch_matches_the_daemon() {
    let fixture = fixture();
    let outputs = build_launch_outputs(&token_definition(&fixture), &context(&fixture)).unwrap();
    assert_matches(
        "token_simple",
        &outputs.outputs,
        &fixture["vectors"]["token_simple"],
    );
}

/// **A whole fractional basket launch, rebuilt.**
///
/// This one also exercises the single computed value in the launch: the
/// pre-launch conversion price, which is a Bancor price with the reserves
/// replaced by `SATOSHIDEN`. Nothing else in the seven outputs is arithmetic.
#[test]
fn a_fractional_launch_matches_the_daemon() {
    let fixture = fixture();
    let outputs =
        build_launch_outputs(&fractional_definition(&fixture), &context(&fixture)).unwrap();
    assert_matches(
        "fractional_one_reserve",
        &outputs.outputs,
        &fixture["vectors"]["fractional_one_reserve"],
    );
}

/// Half the launch fee funds the reserve deposit, rounded **up** so an odd fee
/// still matches consensus.
#[test]
fn the_reserve_deposit_takes_the_ceiling_half_of_the_launch_fee() {
    let fixture = fixture();
    let outputs = build_launch_outputs(&token_definition(&fixture), &context(&fixture)).unwrap();
    assert_eq!(outputs.reserve_deposit_value(), coins("100.00000000"));

    // An odd fee must round up, not down: 201 splits 101/100, not 100/100.
    let mut odd = context(&fixture);
    odd.launch_fee = Amount::from_sat(201);
    let outputs = build_launch_outputs(&token_definition(&fixture), &odd).unwrap();
    assert_eq!(outputs.reserve_deposit_value(), Amount::from_sat(101));
}

/// An identity may define a currency exactly once, and the daemon says so only
/// after the transaction is signed and submitted.
#[test]
fn an_identity_that_already_has_a_currency_is_refused() {
    let fixture = fixture();
    let mut used = context(&fixture);
    used.identity.flags |= verus_tx::identity::FLAG_ACTIVE_CURRENCY;

    let err = build_launch_outputs(&token_definition(&fixture), &used).unwrap_err();
    assert!(err.to_string().contains("only once"), "{err}");
}

/// The currency's id IS the defining identity's address. A typo in the name or
/// the wrong parent builds a transaction that signs cleanly and is rejected with
/// nothing to go on.
#[test]
fn a_name_that_does_not_derive_the_defining_identity_is_refused() {
    let fixture = fixture();
    let mut definition = token_definition(&fixture);
    definition.name = "not-the-identitys-name".into();

    let err = build_launch_outputs(&definition, &context(&fixture)).unwrap_err();
    assert!(err.to_string().contains("derives identity"), "{err}");
}

/// A start block at or below the tip would clear the launch immediately — for a
/// preconvert basket, an instant failure and refund.
#[test]
fn a_start_block_at_or_below_the_tip_is_refused() {
    let fixture = fixture();
    let context = context(&fixture);

    for start in [0, context.height - 1, context.height] {
        let mut definition = token_definition(&fixture);
        definition.start_block = u64::from(start);
        assert!(
            build_launch_outputs(&definition, &context).is_err(),
            "start_block {start} at tip {} should be refused",
            context.height
        );
    }
}

#[test]
fn a_zero_launch_fee_is_refused() {
    let fixture = fixture();
    let mut free = context(&fixture);
    free.launch_fee = Amount::ZERO;
    assert!(build_launch_outputs(&token_definition(&fixture), &free).is_err());
}

/// Preallocations are the token's supply in the notarized state, so a launch
/// that carries them must still reproduce the daemon's bytes — checked here only
/// insofar as it builds, since the fixture has no preallocating vector.
#[test]
fn a_preallocating_definition_still_builds() {
    let fixture = fixture();
    let (_, address) = identity(&fixture);
    let mut definition = token_definition(&fixture);
    definition.preallocations = vec![Preallocation {
        recipient: address,
        amount: coins("10.00000000"),
    }];
    assert!(build_launch_outputs(&definition, &context(&fixture)).is_ok());
}

// ----------------------------------------------------------------- assembling

use verus_keys::PrivateKey;
use verus_tx::currency_launch::{build_currency_launch, LaunchParams};
use verus_tx::{Expiry, Txid, Utxo};

fn signer() -> PrivateKey {
    PrivateKey::from_bytes(&[0x51; 32], true).unwrap()
}

/// An identity this key actually controls, so the launch can be signed.
fn controlled(fixture: &serde_json::Value) -> (Identity, [u8; 20]) {
    let (mut identity, _) = identity(fixture);
    identity.primary_addresses = vec![verus_tx::Destination::PubKeyHash(signer().address().hash())];
    let address = verus_tx::register::identity_id(&identity.name, Some(identity.parent));
    (identity, address)
}

fn identity_utxo(identity: &Identity, address: [u8; 20]) -> Utxo {
    Utxo {
        txid: Txid::from_internal([0xaa; 32]),
        vout: 0,
        satoshis: Amount::ZERO,
        script_pubkey: verus_tx::identity_primary_script(
            address,
            identity.to_bytes().unwrap(),
            identity.revocation_authority,
            identity.recovery_authority,
        )
        .unwrap(),
    }
}

fn funding(amount: &str) -> Vec<Utxo> {
    vec![Utxo {
        txid: Txid::from_internal([0xbb; 32]),
        vout: 0,
        satoshis: coins(amount),
        script_pubkey: signer().address().p2pkh_script_pubkey().unwrap(),
    }]
}

/// The registration fee leaves the transaction **without an output**, so a
/// launch costs more than its outputs add up to.
///
/// Verified against the daemon's own transaction: 205 in, 105 out, 100
/// unaccounted — exactly `launch_fee - reserve_deposit`. A builder that funded
/// only the outputs would come up 100 short and be rejected.
#[test]
fn the_registration_fee_is_funded_even_though_no_output_carries_it() {
    let fixture = fixture();
    let (identity, address) = controlled(&fixture);
    let mut context = context(&fixture);
    context.identity = identity.clone();
    context.identity_address = address;

    let mut definition = token_definition(&fixture);
    definition.name = identity.name.clone();

    let utxo = identity_utxo(&identity, address);
    let coins_in = funding("205.00000000");
    let signed = build_currency_launch(
        &signer(),
        &[&signer()],
        &LaunchParams {
            identity_output: &utxo,
            definition: &definition,
            context: &context,
            utxos: &coins_in,
            change_address: signer().address(),
            expiry: Expiry::AtHeight(context.height + 20),
            fee_per_kb: 100_000,
        },
    )
    .unwrap();

    let tx = verus_wire::TxV4::deserialize(&hex::decode(&signed.hex).unwrap()).unwrap();
    // Six consensus outputs plus change.
    assert_eq!(tx.outputs.len(), 7);
    assert_eq!(
        tx.inputs.len(),
        2,
        "the identity output and one funding coin"
    );

    let out: u64 = tx.outputs.iter().map(|o| o.value).sum();
    let unaccounted = coins("205.00000000").to_sat() - out;
    // 100 for the registration fee, plus the miner fee.
    assert!(
        unaccounted > coins("100.00000000").to_sat(),
        "only {unaccounted} left the transaction; the registration fee alone is 100"
    );
    assert!(
        unaccounted < coins("100.10000000").to_sat(),
        "{unaccounted} is far more than the fee plus a miner fee"
    );
}

/// Funding that covers the outputs but not the invisible registration fee must
/// be refused here, not by the daemon.
#[test]
fn funding_that_ignores_the_registration_fee_is_refused() {
    let fixture = fixture();
    let (identity, address) = controlled(&fixture);
    let mut context = context(&fixture);
    context.identity = identity.clone();
    context.identity_address = address;
    let mut definition = token_definition(&fixture);
    definition.name = identity.name.clone();

    let utxo = identity_utxo(&identity, address);
    // Enough for the reserve deposit and a fee, nothing for the burn.
    let coins_in = funding("101.00000000");
    assert!(build_currency_launch(
        &signer(),
        &[&signer()],
        &LaunchParams {
            identity_output: &utxo,
            definition: &definition,
            context: &context,
            utxos: &coins_in,
            change_address: signer().address(),
            expiry: Expiry::AtHeight(context.height + 20),
            fee_per_kb: 100_000,
        },
    )
    .is_err());
}

/// A key that is not one of the identity's primaries cannot sign its output, and
/// the daemon would only say so at broadcast.
#[test]
fn a_key_that_does_not_control_the_identity_is_refused() {
    let fixture = fixture();
    let (identity, address) = controlled(&fixture);
    let mut context = context(&fixture);
    context.identity = identity.clone();
    context.identity_address = address;
    let mut definition = token_definition(&fixture);
    definition.name = identity.name.clone();

    let stranger = PrivateKey::from_bytes(&[0x99; 32], true).unwrap();
    let utxo = identity_utxo(&identity, address);
    let coins_in = funding("205.00000000");
    let err = build_currency_launch(
        &stranger,
        &[&stranger],
        &LaunchParams {
            identity_output: &utxo,
            definition: &definition,
            context: &context,
            utxos: &coins_in,
            change_address: stranger.address(),
            expiry: Expiry::AtHeight(context.height + 20),
            fee_per_kb: 100_000,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("primary"), "{err}");
}
