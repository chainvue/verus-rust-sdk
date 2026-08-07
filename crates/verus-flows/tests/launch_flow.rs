//! The currency-launch flow against a scripted chain.
//!
//! The builders underneath are proven on chain (PROVEN.md: `rustcur1168400@`,
//! `rusttok1168500@`); what these tests pin is the *choreography* — that the
//! flow reads the identity from the chain's own bytes, checks what the daemon
//! would only reject after the fee, funds correctly and broadcasts.

use verus_flows::testing::ScriptedReader;
use verus_flows::{launch_currency, prepare_launch, FlowError};
use verus_keys::{Address, AddressKind, PrivateKey};
use verus_rpc::{CurrencyPolicy, IdentityRecord};
use verus_tx::currency_definition::CurrencyDefinition;
use verus_tx::identity::{Identity, FLAG_ACTIVE_CURRENCY};
use verus_tx::{identity_id, identity_primary_script, Amount, CurrencyId, Destination, Txid};
use verus_wire::TxV4;

const TEST_WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";
const VRSCTEST: &str = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";
const NAME: &str = "flowcur";

fn key() -> PrivateKey {
    PrivateKey::from_wif(TEST_WIF).unwrap()
}

fn parent() -> [u8; 20] {
    VRSCTEST.parse::<Address>().unwrap().hash()
}

fn identity(flags: u32) -> Identity {
    Identity {
        version: 3,
        flags,
        primary_addresses: vec![Destination::PubKeyHash(key().address().hash())],
        min_sigs: 1,
        parent: parent(),
        name: NAME.to_string(),
        content_multimap: Vec::new(),
        content_map: Vec::new(),
        revocation_authority: identity_id(NAME, Some(parent())),
        recovery_authority: identity_id(NAME, Some(parent())),
        private_addresses: Vec::new(),
        system_id: parent(),
        unlock_after: 0,
    }
}

fn identity_address() -> [u8; 20] {
    identity_id(NAME, Some(parent()))
}

fn holding_txid() -> Txid {
    Txid::from_internal([0xbb; 32])
}

/// The chain: a funded key, the identity record, the raw transaction holding
/// the identity's real output bytes, and a parent policy with the launch fee.
fn chain(flags: u32) -> ScriptedReader {
    chain_with_status(flags, "active")
}

fn chain_with_status(flags: u32, status: &str) -> ScriptedReader {
    let id = identity(flags);
    let script = identity_primary_script(
        identity_address(),
        id.to_bytes().unwrap(),
        id.revocation_authority,
        id.recovery_authority,
        id.has_tokenized_control(),
    )
    .unwrap();
    ScriptedReader::new(1_000)
        .with_utxo(&key().address().to_string(), 100, 400_00000000)
        .with_identity(
            &format!("{NAME}@"),
            IdentityRecord {
                fully_qualified_name: format!("{NAME}.VRSCTEST@"),
                identity_address: Address::new(AddressKind::Identity, identity_address())
                    .to_string(),
                status: status.into(),
                outpoint: (holding_txid(), 0),
                block_height: 900,
                identity: serde_json::json!({}),
            },
        )
        .with_raw_transaction(
            &holding_txid().to_display_hex(),
            serde_json::json!({
                "vout": [ { "valueSat": 0, "scriptPubKey": { "hex": hex::encode(&script) } } ]
            }),
        )
        .with_policy(CurrencyPolicy {
            currency_id: VRSCTEST.into(),
            name: "vrsctest".into(),
            id_registration_fee: Amount::from_coins_str("100").unwrap(),
            id_referral_levels: 3,
            id_import_fee: Amount::from_coins_str("0.02").unwrap(),
            currency_registration_fee: Amount::from_coins_str("200").unwrap(),
            proof_protocol: 1,
        })
}

fn definition() -> CurrencyDefinition {
    CurrencyDefinition::token(CurrencyId::from_bytes(parent()), NAME, 1_060)
}

/// A **valid** NFT, not a token with the bit flipped.
///
/// Five fields have to agree; `NFT_TOKEN` alone produces something consensus
/// refuses, and `serialize_definition` refuses it here first.
fn nft_definition() -> CurrencyDefinition {
    CurrencyDefinition::nft(
        CurrencyId::from_bytes(parent()),
        NAME,
        1_060,
        identity_address(),
    )
}

/// The whole choreography: seven outputs, funded, conserved, broadcast.
#[test]
fn launches_a_token_end_to_end() {
    let chain = chain(0);
    let launched = launch_currency(
        &chain,
        &chain,
        &[&key()],
        &format!("{NAME}@"),
        &definition(),
        None,
    )
    .expect("launch");

    assert_eq!(launched.currency_id, identity_address());
    assert_eq!(launched.start_block, 1_060);
    assert_eq!(launched.launch_fee, Amount::from_coins_str("200").unwrap());

    let broadcasts = chain.broadcasts();
    assert_eq!(broadcasts.len(), 1, "exactly one transaction broadcast");
    let tx = TxV4::deserialize(&hex::decode(&broadcasts[0]).unwrap()).unwrap();

    // Identity input first, then funding.
    assert_eq!(
        hex::encode(tx.inputs[0].txid_internal),
        hex::encode(holding_txid().to_internal())
    );
    assert_eq!(tx.outputs.len(), 7, "the launch shape plus change");

    // Half the launch fee becomes the reserve deposit (output 5); the other
    // half leaves the transaction without an output. Exact conservation:
    // inputs − outputs = miner fee + consumed half.
    let inputs: u64 = 400_00000000;
    let outputs: u64 = tx.outputs.iter().map(|o| o.value).sum();
    let consumed = inputs - outputs;
    assert!(
        consumed >= 100_00000000,
        "the consensus-consumed half of the fee is funded: {consumed}"
    );
}

/// An NFT is charged the parent's **identity import fee**, not its currency
/// registration fee.
///
/// Consensus picks between the two on the definition's own `NFT_TOKEN` bit —
/// `CCurrencyDefinition::GetCurrencyImportFee` returns `idImportFees` for a
/// tokenized-control currency. On VRSCTEST that is 0.02 against 200, four
/// orders of magnitude, and half of it becomes the reserve deposit at output 5.
///
/// Confirmed against the chain: both NFT launches on VRSCTEST carry a reserve
/// deposit of 0.01, which is `fee - fee/2` for a fee of 0.02.
///
/// Built through `CurrencyDefinition::nft` rather than by setting the bit on a
/// token, because those are not the same thing: the option bit alone leaves a
/// definition consensus refuses, and `serialize_definition` now says so
/// locally. This test asserted the fee on a definition that could never have
/// launched, which the fee fix on its own could not notice.
#[test]
fn an_nft_pays_the_parents_id_import_fee() {
    let chain = chain(0);
    let definition = nft_definition();

    let prepared =
        prepare_launch(&chain, &[&key()], &format!("{NAME}@"), &definition, None).expect("prepare");

    assert_eq!(
        prepared.outcome.launch_fee,
        Amount::from_coins_str("0.02").unwrap(),
        "an NFT pays idimportfees, not currencyregistrationfee"
    );

    // Not just the reported figure: the reserve deposit is built from it, and
    // that is where the money actually goes.
    let tx = TxV4::deserialize(&hex::decode(&prepared.hex).unwrap()).unwrap();
    assert_eq!(
        tx.outputs[5].value,
        Amount::from_coins_str("0.01").unwrap().to_sat(),
        "output 5 holds the ceiling half of the fee"
    );
}

/// The same definition without the NFT bit still pays 200 — the fee is chosen
/// by the bit, not by anything else that changed alongside it.
#[test]
fn a_token_still_pays_the_currency_registration_fee() {
    let chain = chain(0);
    let prepared = prepare_launch(&chain, &[&key()], &format!("{NAME}@"), &definition(), None)
        .expect("prepare");
    assert_eq!(
        prepared.outcome.launch_fee,
        Amount::from_coins_str("200").unwrap()
    );
}

/// A parent that carries no identity import fee refuses an NFT launch, and the
/// refusal names the field that was actually read — the two live in different
/// places in the parent's definition, so naming the wrong one sends the caller
/// to fix the wrong number.
#[test]
fn a_parent_without_an_id_import_fee_refuses_an_nft_and_says_which_fee() {
    let chain = chain(0).with_policy(CurrencyPolicy {
        currency_id: VRSCTEST.into(),
        name: "vrsctest".into(),
        id_registration_fee: Amount::from_coins_str("100").unwrap(),
        id_referral_levels: 3,
        id_import_fee: Amount::ZERO,
        currency_registration_fee: Amount::from_coins_str("200").unwrap(),
        proof_protocol: 1,
    });
    let err = prepare_launch(
        &chain,
        &[&key()],
        &format!("{NAME}@"),
        &nft_definition(),
        None,
    )
    .expect_err("a zero fee is refused");
    let message = err.to_string();
    assert!(
        message.contains("identity import fee"),
        "the refusal must name the field an NFT reads: {message}"
    );
    assert!(
        !message.contains("currency registration fee"),
        "and not the one it does not: {message}"
    );
}

/// An identity that already defines a currency is refused before any fee.
#[test]
fn refuses_an_identity_with_an_active_currency() {
    let chain = chain(FLAG_ACTIVE_CURRENCY);
    let err = launch_currency(
        &chain,
        &chain,
        &[&key()],
        &format!("{NAME}@"),
        &definition(),
        None,
    )
    .unwrap_err();
    assert!(err.to_string().contains("already defines"), "{err}");
    assert!(chain.broadcasts().is_empty());
}

/// A definition whose name is not the identity's dies at consensus, after the
/// fee — so it dies here instead.
#[test]
fn refuses_a_definition_that_names_a_different_identity() {
    let chain = chain(0);
    let wrong = CurrencyDefinition::token(CurrencyId::from_bytes(parent()), "othername", 1_060);
    let err =
        launch_currency(&chain, &chain, &[&key()], &format!("{NAME}@"), &wrong, None).unwrap_err();
    assert!(err.to_string().contains("othername"), "{err}");
}

/// A launch dated in the past is refused with the tip in the message.
#[test]
fn refuses_a_start_block_at_or_before_the_tip() {
    let chain = chain(0);
    let stale = CurrencyDefinition::token(CurrencyId::from_bytes(parent()), NAME, 1_000);
    let err =
        launch_currency(&chain, &chain, &[&key()], &format!("{NAME}@"), &stale, None).unwrap_err();
    assert!(err.to_string().contains("start_block"), "{err}");
}

/// A parent that reports no launch fee is refused — unless the caller pins
/// one, which is the escape hatch for a misreporting node.
#[test]
fn refuses_a_zero_launch_fee_unless_pinned() {
    let no_fee = chain(0).with_policy(CurrencyPolicy {
        currency_id: VRSCTEST.into(),
        name: "vrsctest".into(),
        id_registration_fee: Amount::from_coins_str("100").unwrap(),
        id_referral_levels: 3,
        id_import_fee: Amount::from_coins_str("0.02").unwrap(),
        currency_registration_fee: Amount::ZERO,
        proof_protocol: 1,
    });
    let err = launch_currency(
        &no_fee,
        &no_fee,
        &[&key()],
        &format!("{NAME}@"),
        &definition(),
        None,
    )
    .unwrap_err();
    assert!(err.to_string().contains("registration fee"), "{err}");

    let pinned = launch_currency(
        &no_fee,
        &no_fee,
        &[&key()],
        &format!("{NAME}@"),
        &definition(),
        Some(Amount::from_coins_str("200").unwrap()),
    )
    .expect("pinned fee launches");
    assert_eq!(pinned.launch_fee, Amount::from_coins_str("200").unwrap());
}

/// A key the identity does not list is refused by name, before signing.
#[test]
fn refuses_a_key_that_is_not_a_primary() {
    let chain = chain(0);
    let stranger = PrivateKey::from_bytes(&[0x27; 32], true).unwrap();
    let err = launch_currency(
        &chain,
        &chain,
        &[&stranger],
        &format!("{NAME}@"),
        &definition(),
        None,
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            FlowError::Tx(verus_tx::TxError::NotAPrimaryAddress { .. })
        ),
        "{err}"
    );
}

/// An outpoint that does not hold an identity output is named, not signed.
#[test]
fn refuses_a_holding_output_that_is_not_an_identity() {
    let chain = chain(0).with_raw_transaction(
        &holding_txid().to_display_hex(),
        serde_json::json!({
            "vout": [ { "valueSat": 0, "scriptPubKey": { "hex": "76a914aabfb6281561808fe200ab7e186f0e3e0e82b38188ac" } } ]
        }),
    );
    let err = launch_currency(
        &chain,
        &chain,
        &[&key()],
        &format!("{NAME}@"),
        &definition(),
        None,
    )
    .unwrap_err();
    assert!(err.to_string().contains("identity output"), "{err}");
}

/// The dedup is the flow's own addition over the builder: the same key twice
/// satisfies nothing.
#[test]
fn counts_distinct_signers_against_min_sigs() {
    let id = {
        let mut id = identity(0);
        id.min_sigs = 2;
        id.primary_addresses = vec![
            Destination::PubKeyHash(key().address().hash()),
            Destination::PubKeyHash([0x33; 20]),
        ];
        id
    };
    let script = identity_primary_script(
        identity_address(),
        id.to_bytes().unwrap(),
        id.revocation_authority,
        id.recovery_authority,
        id.has_tokenized_control(),
    )
    .unwrap();
    let chain = chain(0).with_raw_transaction(
        &holding_txid().to_display_hex(),
        serde_json::json!({
            "vout": [ { "valueSat": 0, "scriptPubKey": { "hex": hex::encode(&script) } } ]
        }),
    );
    let same_key = key();
    let err = launch_currency(
        &chain,
        &chain,
        &[&key(), &same_key],
        &format!("{NAME}@"),
        &definition(),
        None,
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            FlowError::Tx(verus_tx::TxError::NotEnoughSigners {
                supplied: 1,
                required: 2
            })
        ),
        "{err}"
    );
}

/// A definition whose parent is not the identity's parent dies at consensus,
/// after the fee — so it dies here.
#[test]
fn refuses_a_definition_with_the_wrong_parent() {
    let chain = chain(0);
    let mut wrong = definition();
    wrong.parent = CurrencyId::from_bytes([0x44; 20]);
    let err =
        launch_currency(&chain, &chain, &[&key()], &format!("{NAME}@"), &wrong, None).unwrap_err();
    assert!(err.to_string().contains("parent"), "{err}");
}

/// A node whose copy of the holding transaction lacks the output is refused,
/// naming the transaction.
#[test]
fn refuses_a_holding_transaction_without_the_output() {
    let chain = chain(0).with_raw_transaction(
        &holding_txid().to_display_hex(),
        serde_json::json!({ "vout": [] }),
    );
    let err = launch_currency(
        &chain,
        &chain,
        &[&key()],
        &format!("{NAME}@"),
        &definition(),
        None,
    )
    .unwrap_err();
    assert!(err.to_string().contains("no output"), "{err}");
}

/// No keys, no launch.
#[test]
fn refuses_an_empty_key_list() {
    let chain = chain(0);
    let err = launch_currency(
        &chain,
        &chain,
        &[],
        &format!("{NAME}@"),
        &definition(),
        None,
    )
    .unwrap_err();
    assert!(
        matches!(err, FlowError::Tx(verus_tx::TxError::NoSignatures)),
        "{err}"
    );
}

/// A revoked identity cannot define a currency.
#[test]
fn refuses_a_revoked_identity() {
    let chain = chain_with_status(0, "revoked");
    let err = launch_currency(
        &chain,
        &chain,
        &[&key()],
        &format!("{NAME}@"),
        &definition(),
        None,
    )
    .unwrap_err();
    assert!(
        matches!(err, FlowError::Tx(verus_tx::TxError::AlreadyRevoked)),
        "{err}"
    );
}

/// A definition claiming another system dies at consensus, after the fee — so
/// it dies here, and the wording names the rule.
#[test]
fn refuses_a_definition_for_another_system() {
    let chain = chain(0);
    let mut wrong = definition();
    wrong.system_id = CurrencyId::from_bytes([0x55; 20]);
    let err =
        launch_currency(&chain, &chain, &[&key()], &format!("{NAME}@"), &wrong, None).unwrap_err();
    assert!(err.to_string().contains("system"), "{err}");
}

/// H4: the launch fee is BURNED — half consumed by consensus with no output
/// at all — and by default is read straight from whatever the node reports.
/// A node claiming a fee far above the real 200-coin figure must be refused
/// by name, before any of the identity checks even matter.
#[test]
fn an_absurd_node_reported_launch_fee_is_refused() {
    let lying = chain(0).with_policy(CurrencyPolicy {
        currency_id: VRSCTEST.into(),
        name: "vrsctest".into(),
        id_registration_fee: Amount::from_coins_str("100").unwrap(),
        id_referral_levels: 3,
        id_import_fee: Amount::from_coins_str("0.02").unwrap(),
        currency_registration_fee: Amount::from_coins_str("999").unwrap(),
        proof_protocol: 1,
    });

    let err = launch_currency(
        &lying,
        &lying,
        &[&key()],
        &format!("{NAME}@"),
        &definition(),
        None,
    )
    .unwrap_err();
    match err {
        FlowError::ImplausibleNodeFee {
            operation,
            reported,
            ..
        } => {
            assert_eq!(operation, "currency launch");
            assert_eq!(reported, Amount::from_coins_str("999").unwrap());
        }
        other => panic!("expected ImplausibleNodeFee, got {other}"),
    }
    assert!(lying.broadcasts().is_empty());
}

/// The escape hatch: a caller who has independently confirmed the same
/// absurd-looking fee is genuinely correct can still launch, by pinning it —
/// proving the bar is bypassable is as important as proving it refuses.
#[test]
fn a_pinned_launch_fee_bypasses_the_node_trust_bar() {
    // The default `chain(0)` funds only 400 coins, enough for the real
    // 200-coin fee but not for the 999 pinned here — top it up so the only
    // thing under test is the trust bar, not funding.
    let lying = chain(0)
        .with_utxo(&key().address().to_string(), 50, 1500_00000000)
        .with_policy(CurrencyPolicy {
            currency_id: VRSCTEST.into(),
            name: "vrsctest".into(),
            id_registration_fee: Amount::from_coins_str("100").unwrap(),
            id_referral_levels: 3,
            id_import_fee: Amount::from_coins_str("0.02").unwrap(),
            currency_registration_fee: Amount::from_coins_str("999").unwrap(),
            proof_protocol: 1,
        });

    let launched = launch_currency(
        &lying,
        &lying,
        &[&key()],
        &format!("{NAME}@"),
        &definition(),
        Some(Amount::from_coins_str("999").unwrap()),
    )
    .expect("a pinned fee bypasses the trust bar");
    assert_eq!(launched.launch_fee, Amount::from_coins_str("999").unwrap());
}

/// The bar must not move for the real figure — `launches_a_token_end_to_end`
/// already funds and broadcasts a 200-coin launch; this re-asserts the fee
/// specifically, so a regression that tightened the bar too far shows up here
/// rather than only in the adversarial tests above.
#[test]
fn normal_launch_fees_are_unaffected_by_the_node_trust_bar() {
    let chain = chain(0);
    let launched = launch_currency(
        &chain,
        &chain,
        &[&key()],
        &format!("{NAME}@"),
        &definition(),
        None,
    )
    .expect("launch");
    assert_eq!(launched.launch_fee, Amount::from_coins_str("200").unwrap());
}

/// A node that omits valueSat is refused by name — signing over a guessed
/// amount would be rejected on chain with no explanation at all.
#[test]
fn refuses_a_holding_output_without_value_sat() {
    let id = identity(0);
    let script = identity_primary_script(
        identity_address(),
        id.to_bytes().unwrap(),
        id.revocation_authority,
        id.recovery_authority,
        id.has_tokenized_control(),
    )
    .unwrap();
    let chain = chain(0).with_raw_transaction(
        &holding_txid().to_display_hex(),
        serde_json::json!({
            "vout": [ { "scriptPubKey": { "hex": hex::encode(&script) } } ]
        }),
    );
    let err = launch_currency(
        &chain,
        &chain,
        &[&key()],
        &format!("{NAME}@"),
        &definition(),
        None,
    )
    .unwrap_err();
    assert!(err.to_string().contains("valueSat"), "{err}");
}
