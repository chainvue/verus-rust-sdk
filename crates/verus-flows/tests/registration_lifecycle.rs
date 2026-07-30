//! The two-step registration, and every way it can go sideways.
//!
//! These are the cases a live chain will not produce to order: a commitment that
//! never confirms, a chain that reorganises underneath one, a process that dies
//! between the two steps. The chain is scripted, nothing sleeps, and nothing
//! opens a socket.

use verus_flows::testing::ScriptedReader;
use verus_flows::{
    prepare_registration_with_salt, CommitmentStatus, FlowError, Pending, RegistrationOptions,
};
use verus_keys::PrivateKey;
use verus_rpc::{CurrencyPolicy, IdentityRecord};
use verus_tx::{Amount, Txid};

/// The public test key used across this repository. It holds nothing.
const TEST_WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";
/// A fixed salt. A real registration must use a CSPRNG; a test must not.
const SALT: [u8; 32] = [0x5a; 32];

fn key() -> PrivateKey {
    PrivateKey::from_wif(TEST_WIF).unwrap()
}

fn address() -> String {
    key().address().to_string()
}

fn vrsctest_policy() -> CurrencyPolicy {
    CurrencyPolicy {
        currency_id: "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq".into(),
        name: "VRSCTEST".into(),
        id_registration_fee: Amount::from_sat(100_00000000),
        id_referral_levels: 3,
        id_import_fee: Amount::from_sat(2_000_000),
        currency_registration_fee: Amount::from_sat(200_00000000),
        proof_protocol: 1,
    }
}

/// A chain with enough money at the test address to register a name.
fn funded_chain(tip: u32) -> ScriptedReader {
    ScriptedReader::new(tip)
        .with_policy(vrsctest_policy())
        .with_utxo(&address(), tip - 500, 200_00000000)
}

fn options() -> RegistrationOptions {
    RegistrationOptions::default()
}

/// The whole path, in the order a wallet would walk it.
#[test]
fn a_registration_runs_from_prepare_to_identity() {
    let chain = funded_chain(1_000);

    let pending =
        prepare_registration_with_salt(&chain, &key(), "flowtest", &options(), SALT).unwrap();
    assert_eq!(pending.name(), "flowtest");
    assert_eq!(pending.registration_fee.to_sat(), 100_00000000);

    // Nothing has been sent yet. That is the point of the split: the caller
    // gets a chance to persist the salt before any money moves.
    assert!(chain.broadcasts().is_empty());
    assert!(pending.anchored_at.is_none());

    let pending = pending.broadcast_commitment(&chain, &chain).unwrap();
    assert_eq!(chain.broadcasts().len(), 1);
    assert!(pending.anchored_at.is_some());

    let ready = match pending.poll(&chain).unwrap() {
        CommitmentStatus::Ready(ready) => ready,
        other => panic!("expected Ready, got {other:?}"),
    };

    let registered = ready.complete(&chain, &chain, &key()).unwrap();
    assert_eq!(registered.name, "flowtest");
    assert_eq!(registered.fee_paid.to_sat(), 100_00000000);
    assert_eq!(chain.broadcasts().len(), 2);
    // The identity id is computable before the identity exists.
    assert_ne!(registered.identity_address, [0u8; 20]);
}

/// The safety property the API is arranged around: everything needed to finish
/// is in hand *before* the commitment is broadcast, so a crash between the two
/// steps costs nothing but time.
#[test]
fn the_salt_is_persistable_before_any_money_moves() {
    let chain = funded_chain(1_000);
    let pending =
        prepare_registration_with_salt(&chain, &key(), "crashtest", &options(), SALT).unwrap();

    assert!(chain.broadcasts().is_empty());

    // A wallet would write this to disk here.
    let saved = serde_json::to_string(&pending).unwrap();
    assert!(saved.contains("salt"));

    // Simulate the process dying and a new one loading it.
    let restored: Pending<verus_flows::AwaitingCommitment> = serde_json::from_str(&saved).unwrap();
    assert_eq!(restored.reservation.salt, SALT);
    assert_eq!(restored.commitment_txid, pending.commitment_txid);
    assert_eq!(restored.commitment_hex, pending.commitment_hex);
    assert_eq!(restored.registration_fee, pending.registration_fee);

    // And the restored value can still finish the job.
    let pending = restored.broadcast_commitment(&chain, &chain).unwrap();
    assert!(matches!(
        pending.poll(&chain).unwrap(),
        CommitmentStatus::Ready(_)
    ));
}

/// A round trip after the commitment is broadcast has to carry the anchor too,
/// or the resumed process cannot detect a reorg that happened while it was down.
#[test]
fn a_resumed_registration_still_knows_where_it_was_anchored() {
    let chain = funded_chain(1_000);
    let pending = prepare_registration_with_salt(&chain, &key(), "resume", &options(), SALT)
        .unwrap()
        .broadcast_commitment(&chain, &chain)
        .unwrap();

    let saved = serde_json::to_string(&pending).unwrap();
    let restored: Pending<verus_flows::AwaitingCommitment> = serde_json::from_str(&saved).unwrap();
    assert_eq!(restored.anchored_at, pending.anchored_at);

    // The chain rewrote the block this was anchored to while the process was
    // down. The resumed value must notice.
    let (height, _) = restored.anchored_at.clone().unwrap();
    let mut anchored = restored;
    anchored.anchored_at = Some((height, "ff".repeat(32)));
    assert!(matches!(
        anchored.poll(&chain).unwrap(),
        CommitmentStatus::Reorged { .. }
    ));
}

/// A commitment sitting in the mempool is not ready, and polling must say so
/// rather than letting step 2 run.
#[test]
fn an_unconfirmed_commitment_reports_waiting() {
    let chain = funded_chain(1_000);
    let pending =
        prepare_registration_with_salt(&chain, &key(), "waiting", &options(), SALT).unwrap();
    let txid = pending.commitment_txid.clone();
    let pending = pending.broadcast_commitment(&chain, &chain).unwrap();

    // Zero confirmations: accepted, not mined.
    let chain = funded_chain(1_000).with_confirmations(&txid, 0);
    match pending.poll(&chain).unwrap() {
        CommitmentStatus::Waiting { confirmations } => assert_eq!(confirmations, 0),
        other => panic!("expected Waiting, got {other:?}"),
    }
}

/// A commitment the node has never heard of. The salt is still good, so this is
/// recoverable — but silently continuing would spend it against nothing.
#[test]
fn a_commitment_the_node_never_saw_is_reported_as_gone() {
    let chain = funded_chain(1_000);
    let pending = prepare_registration_with_salt(&chain, &key(), "vanished", &options(), SALT)
        .unwrap()
        .broadcast_commitment(&chain, &chain)
        .unwrap();

    // A chain that knows about some other transaction, but not this one.
    let chain = funded_chain(1_000).with_confirmations(&"cd".repeat(32), 5);
    assert!(matches!(
        pending.poll(&chain).unwrap(),
        CommitmentStatus::CommitmentGone
    ));
}

/// The chain got shorter. Anything read before is suspect, including whether
/// the commitment is still in a block.
#[test]
fn a_chain_that_shrank_is_reported_as_a_reorg() {
    let chain = funded_chain(1_000);
    let pending = prepare_registration_with_salt(&chain, &key(), "shrank", &options(), SALT)
        .unwrap()
        .broadcast_commitment(&chain, &chain)
        .unwrap();

    // The tip fell below where this was anchored.
    let chain = funded_chain(900);
    match pending.poll(&chain).unwrap() {
        CommitmentStatus::Reorged { detail } => assert!(detail.contains("below")),
        other => panic!("expected Reorged, got {other:?}"),
    }
}

/// Polling is one request. A flow that quietly made five would multiply against
/// public infrastructure nobody here pays for.
#[test]
fn polling_is_cheap() {
    let chain = funded_chain(1_000);
    let pending = prepare_registration_with_salt(&chain, &key(), "cheap", &options(), SALT)
        .unwrap()
        .broadcast_commitment(&chain, &chain)
        .unwrap();

    let before = chain.requests();
    let _ = pending.poll(&chain).unwrap();
    // confirmations, block_count and block_hash for the reorg check, then the
    // transaction again to locate the commitment output. Four, not per-output.
    assert!(
        chain.requests() - before <= 4,
        "one poll made {} requests",
        chain.requests() - before
    );
}

/// A name already on chain is refused before the commitment fee is spent.
/// Learning this afterwards costs real money.
#[test]
fn a_taken_name_is_refused_before_anything_is_paid() {
    let chain = funded_chain(1_000).with_identity(
        "taken@",
        IdentityRecord {
            fully_qualified_name: "taken.VRSCTEST@".into(),
            identity_address: "iPYbC4ExJ7dRBZnpxq2LGXGgkWDQNQR48g".into(),
            status: "active".into(),
            outpoint: (Txid::from_internal([0xaa; 32]), 0),
            block_height: 900,
            identity: serde_json::json!({}),
        },
    );

    match prepare_registration_with_salt(&chain, &key(), "taken", &options(), SALT) {
        Err(FlowError::NameTaken(name)) => assert_eq!(name, "taken@"),
        other => panic!("expected NameTaken, got {other:?}"),
    }
    assert!(chain.broadcasts().is_empty());
}

/// Not enough to pay the registration fee, so there is no point committing.
#[test]
fn an_underfunded_address_is_refused_before_the_commitment() {
    let chain = ScriptedReader::new(1_000)
        .with_policy(vrsctest_policy())
        .with_utxo(&address(), 500, 1_00000000);

    match prepare_registration_with_salt(&chain, &key(), "poor", &options(), SALT) {
        Err(FlowError::InsufficientFunds {
            needed, available, ..
        }) => {
            assert_eq!(needed.to_sat(), 100_00000000);
            assert_eq!(available.to_sat(), 1_00000000);
        }
        other => panic!("expected InsufficientFunds, got {other:?}"),
    }
    assert!(chain.broadcasts().is_empty());
}

/// The fee comes from the currency's own policy, not a constant. A different
/// currency charges differently, and PR #3 made that per-currency.
#[test]
fn the_fee_is_read_from_chain_policy() {
    let mut cheap = vrsctest_policy();
    cheap.id_registration_fee = Amount::from_sat(1_00000000);
    let chain =
        ScriptedReader::new(1_000)
            .with_policy(cheap)
            .with_utxo(&address(), 500, 200_00000000);

    let pending =
        prepare_registration_with_salt(&chain, &key(), "cheapname", &options(), SALT).unwrap();
    assert_eq!(pending.registration_fee.to_sat(), 1_00000000);
}

/// A node that misreports the fee is discovered only after the commitment is
/// spent, so a caller who knows better must be able to override it.
#[test]
fn a_caller_can_pin_the_fee_against_a_lying_node() {
    let mut lying = vrsctest_policy();
    lying.id_registration_fee = Amount::from_sat(1);
    let chain =
        ScriptedReader::new(1_000)
            .with_policy(lying)
            .with_utxo(&address(), 500, 200_00000000);

    let options = RegistrationOptions {
        pin_fee: Some(Amount::from_sat(100_00000000)),
        ..Default::default()
    };
    let pending = prepare_registration_with_salt(&chain, &key(), "pinned", &options, SALT).unwrap();
    assert_eq!(pending.registration_fee.to_sat(), 100_00000000);
}

/// The same salt and the same chain state must produce the same commitment.
/// Without that, none of the golden-bytes work upstream means anything here.
#[test]
fn preparation_is_deterministic() {
    let first =
        prepare_registration_with_salt(&funded_chain(1_000), &key(), "same", &options(), SALT)
            .unwrap();
    let second =
        prepare_registration_with_salt(&funded_chain(1_000), &key(), "same", &options(), SALT)
            .unwrap();
    assert_eq!(first.commitment_hex, second.commitment_hex);
    assert_eq!(first.commitment_txid, second.commitment_txid);
}

/// A different salt must produce a different commitment, or the hiding property
/// the two-step scheme depends on does not exist.
#[test]
fn a_different_salt_produces_a_different_commitment() {
    let first =
        prepare_registration_with_salt(&funded_chain(1_000), &key(), "same", &options(), SALT)
            .unwrap();
    let second = prepare_registration_with_salt(
        &funded_chain(1_000),
        &key(),
        "same",
        &options(),
        [0x77; 32],
    )
    .unwrap();
    assert_ne!(first.commitment_hex, second.commitment_hex);
}
