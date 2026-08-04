//! Splitting a payment across two machines, and what has to survive the split.
//!
//! The online half holds an address and no key; the offline half holds the key
//! and never sees a node. Between them travels a [`PartialTransaction`], which
//! is bytes on a screen or a USB stick.
//!
//! The claim being defended is narrow and total: **the two-machine path
//! produces the same transaction as the one-machine path.** Not an equivalent
//! one — the same bytes. A payment whose fee differs by a satoshi has a
//! different change output, a different txid, and is a different transaction
//! that happens to look similar. So the assertion here is on hex, not on fees
//! and amounts that agree individually.

use verus_flows::testing::ScriptedReader;
use verus_flows::{prepare_send, prepare_unsigned_send, FlowError};
use verus_keys::PrivateKey;
use verus_tx::{Amount, PartialTransaction, TxError};

/// Already public in this repository's fixtures, and holds nothing.
const TEST_WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";
/// A valid `R` address that is not the funding one.
const PAYEE: &str = "RHFuSSCAdBCbWt7wxSJeEXphH8W9XNQYs1";

fn key() -> PrivateKey {
    PrivateKey::from_wif(TEST_WIF).expect("the test WIF parses")
}

fn funded(tip: u32, satoshis: u64) -> ScriptedReader {
    ScriptedReader::new(tip).with_utxo(&key().address().to_string(), tip - 500, satoshis)
}

/// The whole point, in one assertion.
#[test]
fn signing_a_plan_offline_produces_the_transaction_the_online_path_would_have() {
    let amount = Amount::from_sat(1_00000000);

    // Machine A: sees the chain, holds an address.
    let chain = funded(1_000, 10_00000000);
    let mut partial = prepare_unsigned_send(&chain, &key().address(), PAYEE, amount)
        .expect("the watch-only half plans the payment");

    // The channel between them. Anything that cannot survive this is not an
    // air gap — it is two processes on one machine.
    let blob = partial.to_bytes().expect("a plan serializes");
    let mut carried = PartialTransaction::from_bytes(&blob).expect("and reads back");
    assert_eq!(carried, partial, "the channel changed the plan");

    // Machine B: holds the key, has never heard of a node.
    assert_eq!(
        carried.sign(&key()).expect("the key signs its own input"),
        1
    );
    let offline = carried
        .finalize()
        .expect("one signature is enough for P2PKH");

    // Machine A again, or anyone: broadcast what came back.
    let online = prepare_send(&funded(1_000, 10_00000000), &key(), PAYEE, amount)
        .expect("the one-machine path builds the same payment");

    assert_eq!(
        offline.hex, online.hex,
        "the air-gapped path built a different transaction"
    );
    assert_eq!(offline.txid, online.txid);
    assert_eq!(offline.fee, online.outcome.fee);

    // One thing the offline half genuinely cannot report: which output is
    // change. `finalize` sees a list of outputs and no idea which of them comes
    // back to the sender, so it says zero rather than guessing — while the
    // transaction it produced does return the change, byte for byte, as the
    // equality above establishes. A wallet that wants the figure has it on the
    // plan (`TransparentPlan::change`), on the machine that decided it.
    assert_eq!(offline.change, Amount::ZERO);
    assert_eq!(online.outcome.change, Amount::from_sat(8_99990000));

    // And signing the local copy gets there too, so the round trip through
    // `to_bytes` is not doing any of the work.
    partial.sign(&key()).expect("the same key signs");
    assert_eq!(
        partial.finalize().expect("finalizes").hex,
        online.hex,
        "the serialization round trip changed the result"
    );
}

/// What the offline machine gets to look at before it commits.
///
/// A signature is the irreversible step and the online machine chose the
/// outputs, so this is the only defence the signer has. It has to be complete
/// enough to act on: where the money goes, how much, what it costs, and whether
/// the signature actually binds those outputs.
#[test]
fn the_signer_can_see_where_the_money_goes_before_signing() {
    let chain = funded(1_000, 10_00000000);
    let partial = prepare_unsigned_send(
        &chain,
        &key().address(),
        PAYEE,
        Amount::from_sat(1_00000000),
    )
    .expect("plans");

    let summary = partial.summary().expect("summarises");

    assert_eq!(summary.total_in, Amount::from_sat(10_00000000));
    assert_eq!(
        summary.total_out.checked_add(summary.fee_and_burn),
        Some(summary.total_in),
        "the summary does not account for every satoshi"
    );

    // The payee, and change coming back to the funding address.
    let payee = summary
        .outputs
        .iter()
        .find(|(_, address)| address.map(|a| a.to_string()).as_deref() == Some(PAYEE))
        .expect("the payee is named in the summary");
    assert_eq!(payee.0, Amount::from_sat(1_00000000));
    assert!(
        summary
            .outputs
            .iter()
            .any(|(_, address)| *address == Some(key().address())),
        "change should be visible as returning to the sender"
    );

    // And the answer to the question that makes the rest of it meaningful.
    assert!(
        summary.commits_to_all_outputs(),
        "a plain send must be SIGHASH_ALL, or the outputs above are not what the \
         signature protects"
    );
}

/// Tampering after the fact is caught by whoever finalizes, not by the daemon.
///
/// This is the failure mode that matters if the channel is not trusted: a blob
/// that comes back altered. `finalize` re-verifies every signature against the
/// sighash it claims to cover, so the alteration fails here — with an error
/// that names the input — rather than at a node, whose answer is that a script
/// finished false.
#[test]
fn an_output_changed_after_signing_is_refused() {
    let chain = funded(1_000, 10_00000000);
    let mut partial = prepare_unsigned_send(
        &chain,
        &key().address(),
        PAYEE,
        Amount::from_sat(1_00000000),
    )
    .expect("plans");
    partial.sign(&key()).expect("signs");
    partial.finalize().expect("a faithful plan finalizes");

    // Redirect one satoshi. Nothing else about the transaction changes.
    partial.outputs[0].value -= 1;

    match partial.finalize() {
        Err(TxError::InvalidSignature { .. }) => {}
        Err(other) => panic!("expected a signature failure, got {other:?}"),
        Ok(_) => panic!("a transaction altered after signing was finalized anyway"),
    }
}

/// The watch-only half fails the same way the online one does.
///
/// Worth pinning because the failure happens on the machine that cannot fix
/// it: the signer would otherwise be handed a plan that cannot be funded and
/// would have to work out why.
#[test]
fn planning_more_than_the_address_holds_is_refused_before_the_gap() {
    let chain = funded(1_000, 1_00000000);
    match prepare_unsigned_send(
        &chain,
        &key().address(),
        PAYEE,
        Amount::from_sat(5_00000000),
    ) {
        Err(FlowError::InsufficientFunds { .. }) => {}
        Err(other) => panic!("expected InsufficientFunds, got {other:?}"),
        Ok(_) => panic!("planned a payment the address cannot fund"),
    }
}

/// The plan is inert: producing one broadcasts nothing.
///
/// The safety argument for re-running and for handing a plan around is that it
/// only reads. A `ScriptedReader` records what it was asked to send, so this is
/// checkable rather than assumed.
#[test]
fn planning_a_payment_sends_nothing() {
    let chain = funded(1_000, 10_00000000);
    prepare_unsigned_send(
        &chain,
        &key().address(),
        PAYEE,
        Amount::from_sat(1_00000000),
    )
    .expect("plans");
    assert!(
        chain.broadcasts().is_empty(),
        "planning a payment reached a node with it"
    );
}
