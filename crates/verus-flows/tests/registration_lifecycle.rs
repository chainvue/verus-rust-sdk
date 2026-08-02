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
use verus_wire::TxV4;

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

    let mut pending = pending;
    pending.broadcast_commitment(&chain, &chain).unwrap();
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

/// An **ambiguous** broadcast must not cost the caller their `Pending`.
///
/// The commitment may well be on the network — that is what makes the failure
/// ambiguous — and the salt inside the `Pending` cannot be recovered from
/// anywhere else, so handing it back only on success would destroy it in
/// exactly the case where it is still needed. The reorg anchor has to land too,
/// or the poll that follows the recovery has nothing to compare against and
/// silently stops detecting reorgs.
#[test]
fn an_uncertain_broadcast_leaves_the_caller_holding_the_commitment() {
    let chain = funded_chain(1_000)
        .failing_broadcast(verus_rpc::RpcError::Transport("connection reset".into()));
    let mut pending =
        prepare_registration_with_salt(&chain, &key(), "uncertain", &options(), SALT).unwrap();
    let salt = pending.reservation.salt;

    let error = pending
        .broadcast_commitment(&chain, &chain)
        .expect_err("a dropped connection is not a success");
    assert!(matches!(error, FlowError::BroadcastUncertain { .. }));

    // Still ours, still complete, and now anchored.
    assert_eq!(pending.reservation.salt, salt);
    assert!(
        pending.anchored_at.is_some(),
        "the anchor must be recorded whatever the broadcast then does"
    );
}

/// A **failed poll** must not cost the caller their commitment.
///
/// Polling is the step run in a loop against infrastructure nobody here owns,
/// so it is the one most likely to hit a timeout. When it took `self`, a single
/// transient failure dropped the `Pending` — and with it the salt that cannot
/// be recovered from the chain and a commitment fee already spent.
///
/// The unreachable node here is a `Cassette` with nothing recorded: every read
/// fails, which is the shape of a timeout without needing one.
///
/// The guard is stronger than this test: against the old `poll(self)` this
/// would not compile at all, because reading the salt afterwards is a use after
/// move. Written as a test anyway, so the *reason* is recorded next to it.
#[test]
fn a_poll_that_fails_leaves_the_commitment_in_hand() {
    let chain = funded_chain(1_000);
    let mut pending =
        prepare_registration_with_salt(&chain, &key(), "kept", &options(), SALT).unwrap();
    pending.broadcast_commitment(&chain, &chain).unwrap();
    let salt = pending.reservation.salt;

    let unreachable = verus_rpc::RpcClient::new(verus_rpc::Cassette::default());
    assert!(
        pending.poll(&unreachable).is_err(),
        "a node that answers nothing cannot report a status"
    );

    // Still ours, still complete, and still able to finish once the chain is
    // reachable again.
    assert_eq!(pending.reservation.salt, salt);
    assert!(matches!(
        pending.poll(&chain).unwrap(),
        CommitmentStatus::Ready(_)
    ));
}

/// `Pending::prepare` borrows rather than consumes, for the same reason.
///
/// It is also the read-only half a driver runs: it takes no `Broadcaster`, so
/// re-running it cannot send anything, and the same `Pending` can be asked for
/// the bytes twice.
#[test]
fn preparing_a_registration_neither_sends_nor_consumes() {
    let chain = funded_chain(1_000);
    let mut pending =
        prepare_registration_with_salt(&chain, &key(), "prepared", &options(), SALT).unwrap();
    pending.broadcast_commitment(&chain, &chain).unwrap();
    let ready = match pending.poll(&chain).unwrap() {
        CommitmentStatus::Ready(ready) => ready,
        other => panic!("expected Ready, got {other:?}"),
    };

    let before = chain.broadcasts().len();
    let first = ready.prepare(&chain, &key()).unwrap();
    let second = ready.prepare(&chain, &key()).unwrap();

    assert_eq!(chain.broadcasts().len(), before, "nothing may be sent");
    assert_eq!(first.hex, second.hex, "and it is deterministic");
    assert_eq!(first.txid, first.outcome.txid);
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
    let mut pending = restored;
    pending.broadcast_commitment(&chain, &chain).unwrap();
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
    let mut pending =
        prepare_registration_with_salt(&chain, &key(), "resume", &options(), SALT).unwrap();
    pending.broadcast_commitment(&chain, &chain).unwrap();

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
    let mut pending = pending;
    pending.broadcast_commitment(&chain, &chain).unwrap();

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
    let mut pending =
        prepare_registration_with_salt(&chain, &key(), "vanished", &options(), SALT).unwrap();
    pending.broadcast_commitment(&chain, &chain).unwrap();

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
    let mut pending =
        prepare_registration_with_salt(&chain, &key(), "shrank", &options(), SALT).unwrap();
    pending.broadcast_commitment(&chain, &chain).unwrap();

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
    let mut pending =
        prepare_registration_with_salt(&chain, &key(), "cheap", &options(), SALT).unwrap();
    pending.broadcast_commitment(&chain, &chain).unwrap();

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

/// A real, decodable identity for a scripted referrer.
///
/// It must be genuinely decodable: the chain walk finds the identity output
/// by decoding it, so a placeholder payload makes the walk silently see no
/// identity output at all — and then find no upstream referrers either, which
/// is the right answer for the wrong reason.
fn referrer_identity(hash: [u8; 20]) -> Vec<u8> {
    let identity = verus_tx::identity::Identity {
        version: 3,
        flags: 0,
        primary_addresses: vec![verus_tx::Destination::PubKeyHash(hash)],
        min_sigs: 1,
        parent: "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq"
            .parse::<verus_keys::Address>()
            .unwrap()
            .hash(),
        name: "referrer".into(),
        content_multimap: Vec::new(),
        content_map: Vec::new(),
        revocation_authority: hash,
        recovery_authority: hash,
        private_addresses: Vec::new(),
        system_id: "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq"
            .parse::<verus_keys::Address>()
            .unwrap()
            .hash(),
        unlock_after: 0,
    };
    verus_tx::identity_primary_script(hash, identity.to_bytes().unwrap(), hash, hash)
        .expect("identity script")
}

/// A referrer that exists on chain and was itself registered WITHOUT a
/// referral — the simple case, whose expected chain is just itself.
///
/// Scripting the referrer's registration transaction matters: consensus
/// derives the chain a new registration must pay by walking it, so a test
/// that skips it is not testing the referred path the chain actually judges.
fn with_unreferred_referrer(chain: ScriptedReader, referrer: &str) -> ScriptedReader {
    let hash = referrer.parse::<verus_keys::Address>().unwrap().hash();
    let registration = Txid::from_internal([0xcc; 32]);
    // The registration's shape: the identity output, then straight to the
    // reservation. No pay-to-identity outputs in between means no upstream
    // referrers to inherit.
    let identity_output = referrer_identity(hash);
    // Scripted under the `i` address, which is how the chain walk asks for it
    // — `referral_id` accepts either form, but the lookup normalises to the id.
    let identity_address =
        verus_keys::Address::new(verus_keys::AddressKind::Identity, hash).to_string();
    chain
        .with_identity(
            &identity_address,
            IdentityRecord {
                fully_qualified_name: format!("{referrer}@"),
                identity_address: identity_address.clone(),
                status: "active".into(),
                outpoint: (registration, 0),
                block_height: 500,
                identity: serde_json::json!({}),
            },
        )
        .with_raw_transaction(
            &registration.to_display_hex(),
            serde_json::json!({
                "vout": [
                    { "valueSat": 0, "scriptPubKey": { "hex": hex::encode(&identity_output) } },
                    { "valueSat": 0, "scriptPubKey": { "hex": "6a00" } }
                ]
            }),
        )
}

/// H2: a referred registration used to fail every single time. `Pending`
/// carried the referrer in the reservation but never carried
/// `idreferrallevels` through to step 2, so `build_identity_registration`
/// always saw `referral_levels == 0` and refused with `ReferralChainTooLong`
/// — after the commitment fee was already spent. This runs the referred path
/// end to end and checks the daemon's own fee split actually landed in the
/// broadcast transaction, not just that the call returned `Ok`.
#[test]
fn a_referred_registration_completes_and_pays_the_referrer() {
    let referrer = "RJUgxvDnDLsRGCXNKDK56Rxngzh6m25J6F";
    let chain = with_unreferred_referrer(funded_chain(1_000), referrer);

    let options = RegistrationOptions {
        referral: Some(referrer.to_string()),
        ..Default::default()
    };
    let pending =
        prepare_registration_with_salt(&chain, &key(), "referred", &options, SALT).unwrap();
    // The level count came from chain policy, not a default the caller has to
    // supply — this is exactly the field H2 adds.
    assert_eq!(pending.referral_levels, 3);

    let mut pending = pending;
    pending.broadcast_commitment(&chain, &chain).unwrap();
    let ready = match pending.poll(&chain).unwrap() {
        CommitmentStatus::Ready(ready) => ready,
        other => panic!("expected Ready, got {other:?}"),
    };

    // Before the fix this returned `Err(FlowError::Tx(TxError::ReferralChainTooLong { .. }))`.
    let registered = ready.complete(&chain, &chain, &key()).unwrap();
    assert_eq!(registered.name, "referred");

    // The daemon's own arithmetic for this policy: 100 VRSC over 3 levels
    // pays the referrer 20 and the registrant's outlay is 80 (see
    // `verus_tx::register::registration_fees`'s doc comment).
    let fees = verus_tx::register::registration_fees(Amount::from_sat(100_00000000), 3, true);
    assert_eq!(fees.referral_amount, Amount::from_sat(20_00000000));

    // Confirm the split actually applied to the broadcast bytes, not merely
    // to some fee arithmetic computed and discarded: the registration
    // transaction must carry an output paying the referrer exactly that much.
    let broadcasts = chain.broadcasts();
    assert_eq!(broadcasts.len(), 2, "commitment, then registration");
    let tx = TxV4::deserialize(&hex::decode(&broadcasts[1]).unwrap()).unwrap();
    assert!(
        tx.outputs
            .iter()
            .any(|out| out.value == fees.referral_amount.to_sat()),
        "no output paid the referrer's {} satoshis",
        fees.referral_amount.to_sat()
    );
}

/// A `Pending` persisted by a version of this crate before H2 added
/// `referral_levels` must still load. `#[serde(default)]` is what makes that
/// true — this pins it against a regression that would strand every
/// in-flight registration serialized before the upgrade.
#[test]
fn a_pending_persisted_before_referral_levels_existed_still_deserializes() {
    let chain = funded_chain(1_000);
    let pending =
        prepare_registration_with_salt(&chain, &key(), "oldformat", &options(), SALT).unwrap();
    let saved = serde_json::to_string(&pending).unwrap();

    // Simulate a JSON blob written by the pre-H2 version: strip the field
    // this fix added, exactly as an old file on disk would be missing it.
    let mut value: serde_json::Value = serde_json::from_str(&saved).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .remove("referral_levels")
        .expect("the field under test must actually be present before it is removed");
    let without_the_field = serde_json::to_string(&value).unwrap();

    let restored: Pending<verus_flows::AwaitingCommitment> =
        serde_json::from_str(&without_the_field).unwrap();
    assert_eq!(restored.referral_levels, 0);
    assert_eq!(restored.reservation.salt, SALT);
}

/// H4: the registration fee is BURNED, and by default is read straight from
/// whatever the node reports — exactly the value a hostile or misconfigured
/// node controls. A node claiming a fee far above anything real must be
/// refused by name, before the commitment is even built.
#[test]
fn an_absurd_node_reported_registration_fee_is_refused() {
    let mut lying = vrsctest_policy();
    lying.id_registration_fee = Amount::from_coins_str("999").unwrap();
    let chain =
        ScriptedReader::new(1_000)
            .with_policy(lying)
            .with_utxo(&address(), 500, 2000_00000000);

    match prepare_registration_with_salt(&chain, &key(), "absurdfee", &options(), SALT) {
        Err(FlowError::ImplausibleNodeFee {
            operation,
            reported,
            ..
        }) => {
            assert_eq!(operation, "identity registration");
            assert_eq!(reported, Amount::from_coins_str("999").unwrap());
        }
        other => panic!("expected ImplausibleNodeFee, got {other:?}"),
    }
    assert!(chain.broadcasts().is_empty());
}

/// The escape hatch: a caller who has independently confirmed the same
/// absurd-looking fee is genuinely correct can still get it signed, by
/// pinning it. Pinning is what makes the H4 bar bypassable at all — proving
/// it actually works is as important as proving the bar refuses by default.
#[test]
fn a_pinned_fee_bypasses_the_node_trust_bar() {
    let mut lying = vrsctest_policy();
    lying.id_registration_fee = Amount::from_coins_str("999").unwrap();
    let chain =
        ScriptedReader::new(1_000)
            .with_policy(lying)
            .with_utxo(&address(), 500, 2000_00000000);

    let options = RegistrationOptions {
        pin_fee: Some(Amount::from_coins_str("999").unwrap()),
        ..Default::default()
    };
    let pending =
        prepare_registration_with_salt(&chain, &key(), "pinnedabsurd", &options, SALT).unwrap();
    assert_eq!(
        pending.registration_fee,
        Amount::from_coins_str("999").unwrap()
    );
}

/// The bar must not move for anything a real chain actually charges — this is
/// `the_fee_is_read_from_chain_policy` and `a_caller_can_pin_the_fee_against_a_lying_node`
/// re-asserted with H4's bar in place, so a regression that tightened it too
/// far would show up here rather than only in the adversarial tests.
#[test]
fn normal_registration_fees_are_unaffected_by_the_node_trust_bar() {
    let chain = funded_chain(1_000);
    let pending =
        prepare_registration_with_salt(&chain, &key(), "normalfee", &options(), SALT).unwrap();
    assert_eq!(
        pending.registration_fee,
        Amount::from_coins_str("100").unwrap()
    );
}

/// Referral policy is node-supplied, and it decides the fee split step two
/// computes — so an implausible value must be refused BEFORE the commitment
/// is broadcast. Checked only in `complete()`, the same value costs the
/// caller a commitment fee and leaves them with a salt they can never use.
#[test]
fn an_implausible_referral_policy_is_refused_before_anything_is_broadcast() {
    let absurd = CurrencyPolicy {
        id_referral_levels: 10_000,
        ..vrsctest_policy()
    };
    let chain = funded_chain(1_000).with_policy(absurd);
    let options = RegistrationOptions {
        referral: Some("RJGYC29RTSGQbWMrstQziJxfQaiDCjm5iP".to_string()),
        ..RegistrationOptions::default()
    };

    match prepare_registration_with_salt(&chain, &key(), "reftest", &options, SALT) {
        Err(FlowError::ImplausibleReferralLevels { reported, .. }) => {
            assert_eq!(reported, 10_000);
        }
        other => panic!("expected ImplausibleReferralLevels, got {other:?}"),
    }
    assert!(
        chain.broadcasts().is_empty(),
        "nothing may be broadcast when the policy is refused"
    );
}

/// …but the levels are irrelevant when no referral is asked for, so the same
/// absurd policy must not block an ordinary registration.
#[test]
fn an_implausible_referral_policy_does_not_block_an_unreferred_registration() {
    let absurd = CurrencyPolicy {
        id_referral_levels: 10_000,
        ..vrsctest_policy()
    };
    let chain = funded_chain(1_000).with_policy(absurd);
    prepare_registration_with_salt(&chain, &key(), "noreftest", &options(), SALT)
        .expect("an unreferred registration ignores referral policy");
}

/// A currency that pays no referrals says so, rather than surfacing as
/// `ReferralChainTooLong` from inside the fee arithmetic after the commitment
/// has been spent.
#[test]
fn asking_for_a_referral_where_none_are_paid_is_refused_by_name() {
    let none_paid = CurrencyPolicy {
        id_referral_levels: 0,
        ..vrsctest_policy()
    };
    let chain = funded_chain(1_000).with_policy(none_paid);
    let options = RegistrationOptions {
        referral: Some("RJGYC29RTSGQbWMrstQziJxfQaiDCjm5iP".to_string()),
        ..RegistrationOptions::default()
    };

    match prepare_registration_with_salt(&chain, &key(), "noreferrals", &options, SALT) {
        Err(FlowError::CurrencyPaysNoReferrals { referrer }) => {
            assert_eq!(referrer, "RJGYC29RTSGQbWMrstQziJxfQaiDCjm5iP");
        }
        other => panic!("expected CurrencyPaysNoReferrals, got {other:?}"),
    }
    assert!(chain.broadcasts().is_empty());
}

/// **The case that was silently broken.** Consensus derives the referral
/// payouts a registration owes by walking the referrer's OWN registration
/// transaction (`identity.cpp`, `PrecheckIdentityReservation`: it builds
/// `checkReferrers` as `[referrer, ...upstream]` and refuses on
/// `referrers.size() != checkReferrers.size()`).
///
/// So referring to someone who was themselves referred means paying their
/// referrer too. The facade paid only the immediate referrer, which built a
/// transaction the chain rejects — discovered at broadcast, after the
/// commitment fee is spent. It never showed up on chain because the one
/// referred registration ever proven used an unreferred referrer, whose
/// expected chain is length one either way.
#[test]
fn a_referrer_who_was_themselves_referred_has_their_own_referrer_paid_too() {
    let referrer = "RJUgxvDnDLsRGCXNKDK56Rxngzh6m25J6F";
    let upstream = "RCebaYEbzesJFmMzzgHNLTdLMeeWsaVxjy";
    let referrer_hash = referrer.parse::<verus_keys::Address>().unwrap().hash();
    let upstream_hash = upstream.parse::<verus_keys::Address>().unwrap().hash();
    let registration = Txid::from_internal([0xdd; 32]);
    let identity_address =
        verus_keys::Address::new(verus_keys::AddressKind::Identity, referrer_hash).to_string();

    // The referrer's registration: identity output, then a pay-to-identity
    // output crediting THEIR referrer, then the reservation.
    let identity_output = referrer_identity(referrer_hash);
    let upstream_payout = verus_tx::identity_payment_script(upstream_hash).expect("payout script");

    let chain = funded_chain(1_000)
        .with_identity(
            &identity_address,
            IdentityRecord {
                fully_qualified_name: format!("{referrer}@"),
                identity_address: identity_address.clone(),
                status: "active".into(),
                outpoint: (registration, 0),
                block_height: 500,
                identity: serde_json::json!({}),
            },
        )
        .with_raw_transaction(
            &registration.to_display_hex(),
            serde_json::json!({
                "vout": [
                    { "valueSat": 0, "scriptPubKey": { "hex": hex::encode(&identity_output) } },
                    { "valueSat": 2000000000, "scriptPubKey": { "hex": hex::encode(&upstream_payout) } },
                    { "valueSat": 0, "scriptPubKey": { "hex": "6a00" } }
                ]
            }),
        );

    let options = RegistrationOptions {
        referral: Some(referrer.to_string()),
        ..Default::default()
    };
    let pending =
        prepare_registration_with_salt(&chain, &key(), "inherited", &options, SALT).unwrap();

    // Both referrers, in the order consensus expects: immediate first.
    assert_eq!(
        pending.referral_chain,
        vec![referrer_hash, upstream_hash],
        "the upstream referrer was not inherited from the referrer's registration"
    );

    let mut pending = pending;
    pending.broadcast_commitment(&chain, &chain).unwrap();
    let ready = match pending.poll(&chain).unwrap() {
        CommitmentStatus::Ready(ready) => ready,
        other => panic!("expected Ready, got {other:?}"),
    };
    ready.complete(&chain, &chain, &key()).unwrap();

    // Two payouts in the broadcast bytes, one per referrer.
    let broadcast = chain
        .broadcasts()
        .pop()
        .expect("the registration broadcast");
    let tx = TxV4::deserialize(&hex::decode(&broadcast).unwrap()).unwrap();
    let paid: Vec<[u8; 20]> = tx
        .outputs
        .iter()
        .filter_map(
            |out| match verus_tx::decode_output_script(&out.script_pubkey) {
                Ok(verus_tx::OutputKind::IdentityPayment { identity }) => Some(identity),
                _ => None,
            },
        )
        .collect();
    assert_eq!(
        paid,
        vec![referrer_hash, upstream_hash],
        "the transaction must pay both referrers, in order"
    );
}
