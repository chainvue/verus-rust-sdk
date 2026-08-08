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

/// The identity output of an NFT launch carries a destination no other launch
/// does, and omitting it is refused by consensus with `-25:
/// bad-txns-failed-precheck` — which names nothing.
///
/// `CIdentity::IdentityUpdateOutputScript` (`src/key_io.cpp:1881`) pushes the
/// `EVAL_IDENTITY_RECOVER` contract key hash onto the recovery condition's
/// destinations under `HasTokenizedControl()`. `build_launch_outputs` sets that
/// flag for an NFT, so the script it builds has to agree with the flag it just
/// set.
///
/// Built through `CurrencyDefinition::nft` rather than by setting the bit on a
/// token: those are not the same thing, and `serialize_definition` refuses the
/// second — an NFT needs five fields to agree, not one.
#[test]
fn an_nft_launch_puts_the_recover_contract_in_the_identity_output() {
    let fixture = fixture();
    let (_, address) = identity(&fixture);
    let token = token_definition(&fixture);
    let mut definition =
        CurrencyDefinition::nft(token.parent, &token.name, token.start_block, address);
    // The parent's fee schedule is chain policy, carried over from the vector.
    definition.id_registration_fees = token.id_registration_fees;
    definition.id_import_fees = token.id_import_fees;

    let outputs = build_launch_outputs(&definition, &context(&fixture)).unwrap();
    let script = hex::encode(&outputs.outputs[0].script_pubkey);

    // The whole recovery condition, not just the key hash: `1-of-2` over the
    // recovery authority — which is not the identity's own address — and the
    // contract. A test for the hash alone would pass on a script that pushed it
    // into the wrong condition.
    let (id, _) = identity(&fixture);
    let recovery = format!(
        "300403100102 1504{} 14{}",
        hex::encode(id.recovery_authority),
        hex::encode(verus_tx::cc::IDENTITY_RECOVER_KEYHASH)
    )
    .replace(' ', "");
    assert!(
        script.ends_with(&format!("{recovery}75")),
        "an NFT launch's identity output must end in the tokenized-control \
         recovery condition\n  built: {script}\n  wanted tail: {recovery}75"
    );
}

/// The same launch without the NFT bit must not carry it — the destination is
/// not harmless padding, it hands the recovery path to a contract.
#[test]
fn a_plain_token_launch_leaves_the_recover_contract_out() {
    let fixture = fixture();
    let outputs = build_launch_outputs(&token_definition(&fixture), &context(&fixture)).unwrap();
    let script = hex::encode(&outputs.outputs[0].script_pubkey);
    assert!(
        !script.contains(&hex::encode(verus_tx::cc::IDENTITY_RECOVER_KEYHASH)),
        "a token launch must not carry the recover contract destination"
    );
}

/// A contribution the builder cannot express is refused rather than guessed.
///
/// Contributions are funded now — see
/// `the_contribution_output_matches_the_daemon_byte_for_byte` — but only in the
/// shape the captures prove: a single reserve, in the system's own currency.
///
/// A token contribution travels in the payload rather than the output's value
/// and needs token inputs to fund it, and no capture in this repository shows
/// that transaction. A currency definition is immutable and an identity defines
/// exactly one currency ever, so building one on a guess is unrecoverable.
#[test]
fn a_contribution_shape_no_capture_covers_is_refused() {
    let fixture = fixture();
    let mut definition = fractional_definition(&fixture);
    let other = CurrencyId::from_bytes(i_address("i77n5FCqSBkXAK3UWHpdrPpdtXRc8sqjoz"));
    definition.currencies = vec![other];
    definition = definition.with_contributions(vec![coins("3.00000000")]);

    let error = build_launch_outputs(&definition, &context(&fixture))
        .expect_err("a token contribution is refused")
        .to_string();
    assert!(error.contains("system's own currency"), "{error}");
}

/// All-zero contributions are the ordinary case and must still build.
///
/// The vector has to match the reserve list's *length*, so a fractional
/// currency and every NFT carry zeros. Refusing on "the vector is non-empty"
/// rather than "an amount is non-zero" would break both.
#[test]
fn zero_contributions_are_not_a_declaration_and_still_build() {
    let fixture = fixture();
    let definition = fractional_definition(&fixture);
    assert_eq!(definition.initial_contributions, vec![Amount::ZERO]);
    assert!(build_launch_outputs(&definition, &context(&fixture)).is_ok());

    let nft = CurrencyDefinition::nft(
        definition.parent,
        &definition.name,
        definition.start_block,
        [0x2b; 20],
    );
    assert_eq!(nft.initial_contributions, vec![Amount::ZERO]);
}

/// Encoding a definition that declares contributions stays legal.
///
/// The refusal belongs to *launching*, not to serializing: this crate has to
/// re-encode the daemon's own definitions byte for byte, and three of the
/// committed vectors carry contributions. Refusing in `serialize_definition`
/// would make those unreadable.
#[test]
fn a_contributing_definition_still_encodes() {
    let fixture = fixture();
    let definition = fractional_definition(&fixture).with_contributions(vec![coins("3.00000000")]);
    assert!(verus_tx::currency_definition::currency_definition_script(&definition).is_ok());
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
            identity.has_tokenized_control(),
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

/// Two NFT shapes a node would accept and nobody wants, refused here rather
/// than in the encoder.
///
/// Consensus checks a great deal about an NFT — the `isNFTMappedCurrency` block
/// in `pbaas/pbaas.cpp` pins the single satoshi and the option bits — but it
/// says nothing about which currency the NFT reserves or what `initialsupply`
/// claims. Both of these would be mined.
///
/// That is exactly why they belong to the builder and not to
/// `currency_definition_script`: the encoder's job is to refuse what a node
/// would refuse, and being stricter than the chain there would make a valid
/// definition unencodable. A caller with a reason to build one of these still
/// can; they just cannot reach it through this launch path.
///
/// The rules come from the fifteen NFTs live on VRSCTEST, all of which reserve
/// the system's currency and declare no supply.
#[test]
fn an_nft_the_chain_would_mine_but_nobody_wants_is_refused_by_the_builder() {
    let fixture = fixture();
    let (_, address) = identity(&fixture);
    let token = token_definition(&fixture);
    let good = || {
        let mut definition =
            CurrencyDefinition::nft(token.parent, &token.name, token.start_block, address);
        definition.id_registration_fees = token.id_registration_fees;
        definition.id_import_fees = token.id_import_fees;
        definition
    };
    assert!(
        build_launch_outputs(&good(), &context(&fixture)).is_ok(),
        "the constructor's own output must launch"
    );

    // The reserve follows the system, not the parent. Seven of the fifteen sit
    // under a non-root parent and still hold the system's currency, so
    // following the parent is the mistake worth naming.
    let mut parent_as_reserve = good();
    parent_as_reserve.currencies = vec![CurrencyId::from_bytes(i_address(
        "i77n5FCqSBkXAK3UWHpdrPpdtXRc8sqjoz",
    ))];
    let error = build_launch_outputs(&parent_as_reserve, &context(&fixture))
        .expect_err("a reserve that is not the system is refused")
        .to_string();
    assert!(error.contains("reserve currency is its system"), "{error}");

    // A supply figure competing with the one-satoshi preallocation. Harmless to
    // encode, unfixable once the currency is on chain.
    let mut declared_supply = good();
    declared_supply.initial_supply = Amount::from_sat(100_000_000);
    let error = build_launch_outputs(&declared_supply, &context(&fixture))
        .expect_err("a declared supply is refused")
        .to_string();
    assert!(error.contains("initial_supply should be zero"), "{error}");
}

/// The eighth output — the one that funds `initial_contributions` — rebuilt
/// byte for byte against the daemon's own.
///
/// `fixtures/daemon/currency_definitions.json` carries a whole
/// `full_transaction_hex` per vector, and `fractional_contrib` is **eight**
/// outputs where every launch without contributions is seven. The extra one
/// sits at index 5, immediately before the reserve deposit, and pays
/// `3.00095018` for a declared contribution of `3.0`.
///
/// That gap is the conversion fee being grossed over, and reproducing it
/// exactly is the whole point of this test — an approximate figure would leave
/// the reserve holding slightly less than the definition claims, permanently.
#[test]
fn the_contribution_output_matches_the_daemon_byte_for_byte() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/daemon/currency_definitions.json"
    );
    let file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("fixture")).expect("json");
    let vector = &file["vectors"]["fractional_contrib"];
    let captured = decode_outputs(vector["full_transaction_hex"].as_str().expect("hex"));
    assert_eq!(
        captured.len(),
        8,
        "a contributed launch is eight outputs, not seven"
    );

    let definition = vector["definition"].clone();
    let currency_id = i_address(definition["currencyid"].as_str().expect("currencyid"));

    let mut built = CurrencyDefinition::token(
        CurrencyId::from_bytes(i_address(definition["parent"].as_str().expect("parent"))),
        definition["name"].as_str().expect("name"),
        definition["startblock"].as_u64().expect("startblock"),
    );
    built.options = u32::try_from(definition["options"].as_u64().expect("options")).unwrap();
    built.currencies = vec![CurrencyId::from_bytes(i_address(
        definition["currencies"][0].as_str().expect("reserve"),
    ))];
    built.weights = vec![100_000_000];
    built.initial_supply = Amount::from_sat(1000_00000000);
    built = built.with_contributions(vec![Amount::from_sat(3_00000000)]);

    let fixture = fixture();
    let mut context = context(&fixture);
    context.identity_address = currency_id;
    // The capture's own start block is below this fixture's height. Only
    // output 5 is asserted on and it carries no height, so moving the tip
    // below the start block changes nothing this test reads.
    context.height = 1_167_800;

    let outputs = build_launch_outputs(&built, &context).expect("it builds");
    assert_eq!(
        outputs.outputs.len(),
        8,
        "the contribution output is emitted"
    );

    // Value AND script. The value is what the reserve receives; the script is
    // where it goes and under what terms. Either alone would pass on a wrong
    // transaction.
    let (value, script) = &captured[5];
    assert_eq!(
        outputs.outputs[5].value, *value,
        "the grossed-up contribution value must match the daemon exactly"
    );
    assert_eq!(
        hex::encode(&outputs.outputs[5].script_pubkey),
        *script,
        "the contribution output's script must match the daemon exactly"
    );

    // And the deposit it was inserted ahead of is still where it belongs.
    assert_eq!(outputs.outputs[6].value, captured[6].0);
}

/// Outputs of a raw transaction, as `(value, script hex)`.
fn decode_outputs(raw: &str) -> Vec<(u64, String)> {
    let bytes = hex::decode(raw).expect("hex");
    let mut i = 8usize; // header + version group id

    fn compact(bytes: &[u8], i: &mut usize) -> u64 {
        let n = bytes[*i];
        *i += 1;
        match n {
            0xfd => {
                let v = u64::from(u16::from_le_bytes([bytes[*i], bytes[*i + 1]]));
                *i += 2;
                v
            }
            0xfe => {
                let v = u64::from(u32::from_le_bytes(
                    bytes[*i..*i + 4].try_into().expect("4 bytes"),
                ));
                *i += 4;
                v
            }
            0xff => {
                let v = u64::from_le_bytes(bytes[*i..*i + 8].try_into().expect("8 bytes"));
                *i += 8;
                v
            }
            small => u64::from(small),
        }
    }

    let inputs = compact(&bytes, &mut i);
    for _ in 0..inputs {
        i += 36;
        let len = usize::try_from(compact(&bytes, &mut i)).expect("a script length");
        i += len + 4;
    }
    let count = compact(&bytes, &mut i);
    (0..count)
        .map(|_| {
            let value = u64::from_le_bytes(bytes[i..i + 8].try_into().expect("8 bytes"));
            i += 8;
            let len = usize::try_from(compact(&bytes, &mut i)).expect("a script length");
            let script = hex::encode(&bytes[i..i + len]);
            i += len;
            (value, script)
        })
        .collect()
}

/// The reserve deposit is still found once a contribution is inserted ahead of
/// it, and the transaction still carries it.
///
/// Both of these were wrong in the first draft of contribution support and
/// neither is visible in a byte comparison of the contribution output itself.
/// `reserve_deposit_value` read a fixed index 5, which a contribution now
/// occupies — so the burn arithmetic would have subtracted `3.00095018` from
/// the launch fee instead of `100`, under-burning by the whole registration
/// fee. And the builder truncated to a fixed six outputs, which would have
/// dropped the deposit from the transaction entirely.
#[test]
fn a_contribution_does_not_displace_the_reserve_deposit() {
    let fixture = fixture();
    let plain = build_launch_outputs(&fractional_definition(&fixture), &context(&fixture))
        .expect("a plain launch");
    assert_eq!(plain.deposit_index, 5);
    assert_eq!(plain.outputs.len(), 7);

    let mut contributed = fractional_definition(&fixture);
    contributed = contributed.with_contributions(vec![coins("3.00000000")]);
    let built = build_launch_outputs(&contributed, &context(&fixture)).expect("a funded launch");

    assert_eq!(built.outputs.len(), 8, "the contribution adds an output");
    assert_eq!(built.deposit_index, 6, "and pushes the deposit along");
    assert_eq!(
        built.reserve_deposit_value(),
        plain.reserve_deposit_value(),
        "the deposit is the same money whether or not a contribution rides with it"
    );
    assert_eq!(
        built.consensus_outputs(),
        7,
        "every output but the change slot is validated, so none may be truncated away"
    );
}
