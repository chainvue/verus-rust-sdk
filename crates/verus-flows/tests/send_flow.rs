//! Paying someone, end to end against a scripted chain.

use verus_flows::testing::ScriptedReader;
use verus_flows::{prepare_send, send, FlowError};
use verus_keys::PrivateKey;
use verus_rpc::RpcError;
use verus_tx::{Amount, Txid};
use verus_wire::TxV4;

const TEST_WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";
/// A second address to pay. Valid, and not the funding one.
const PAYEE: &str = "RHFuSSCAdBCbWt7wxSJeEXphH8W9XNQYs1";

fn key() -> PrivateKey {
    PrivateKey::from_wif(TEST_WIF).unwrap()
}

fn address() -> String {
    key().address().to_string()
}

fn funded(tip: u32, satoshis: u64) -> ScriptedReader {
    ScriptedReader::new(tip).with_utxo(&address(), tip - 500, satoshis)
}

#[test]
fn a_payment_is_looked_up_built_signed_and_broadcast() {
    let chain = funded(1_000, 10_00000000);
    let sent = send(&chain, &chain, &key(), PAYEE, Amount::from_sat(1_00000000)).unwrap();

    assert_eq!(chain.broadcasts().len(), 1);
    assert_eq!(chain.broadcasts()[0], sent.hex);
    assert!(sent.fee.to_sat() > 0);
    // 10 in, 1 out, so change is most of it.
    assert!(sent.change.to_sat() > 8_00000000);
}

/// Expiry is set from the tip rather than left at "never".
///
/// Every example in this repository passed `Expiry::Never`, which is the one
/// value a wallet should almost never choose: a payment that does not confirm
/// stays valid indefinitely and can land months later against coins the user has
/// since spent. Flows know the tip, so they can do better.
#[test]
fn a_payment_expires_rather_than_lingering_forever() {
    let chain = funded(1_000, 10_00000000);
    let signed = prepare_send(&chain, &key(), PAYEE, Amount::from_sat(1_00000000)).unwrap();

    // Read expiryHeight back out of the bytes. The v4 trailer, for a
    // transaction with no shielded data, is fixed:
    //
    //   lockTime(4) expiryHeight(4) valueBalance(8) nSpend(1) nOutput(1) nJoinSplit(1)
    //
    // so the field sits 15 bytes from the end.
    let bytes = hex_bytes(&signed.hex);
    let end = bytes.len();
    let expiry = u32::from_le_bytes(bytes[end - 15..end - 11].try_into().unwrap());
    assert_eq!(expiry, 1_020, "expected tip + 20, got {expiry}");
    assert_ne!(
        expiry, 0,
        "an expiry of zero means never, which is the trap"
    );
}

/// A dry run cannot broadcast, and that is a signature rather than a promise:
/// `prepare_send` takes no `Broadcaster` at all.
#[test]
fn preparing_a_payment_sends_nothing() {
    let chain = funded(1_000, 10_00000000);
    let signed = prepare_send(&chain, &key(), PAYEE, Amount::from_sat(1_00000000)).unwrap();
    assert!(chain.broadcasts().is_empty());
    assert!(!signed.hex.is_empty());
}

/// The same payment prepared twice must produce the same bytes. Determinism is
/// what makes the differential vectors upstream meaningful.
#[test]
fn preparing_the_same_payment_twice_gives_the_same_bytes() {
    let first = prepare_send(
        &funded(1_000, 10_00000000),
        &key(),
        PAYEE,
        Amount::from_sat(5_000_000),
    )
    .unwrap();
    let second = prepare_send(
        &funded(1_000, 10_00000000),
        &key(),
        PAYEE,
        Amount::from_sat(5_000_000),
    )
    .unwrap();
    assert_eq!(first.hex, second.hex);
    assert_eq!(first.txid, second.txid);
}

#[test]
fn an_empty_address_cannot_be_funded_from() {
    let chain = ScriptedReader::new(1_000);
    match send(&chain, &chain, &key(), PAYEE, Amount::from_sat(1_000)) {
        Err(FlowError::InsufficientFunds { available, .. }) => assert_eq!(available.to_sat(), 0),
        other => panic!("expected InsufficientFunds, got {other:?}"),
    }
    assert!(chain.broadcasts().is_empty());
}

/// Coins that exist but cannot be spent yet. The balance looks fine and the
/// payment still must not be attempted.
#[test]
fn an_immature_coinbase_does_not_count_as_funds() {
    let chain = ScriptedReader::new(1_000)
        .with_utxo(&address(), 950, 10_00000000)
        .with_coinbase_at(950);

    match send(&chain, &chain, &key(), PAYEE, Amount::from_sat(1_00000000)) {
        Err(FlowError::InsufficientFunds { available, .. }) => assert_eq!(available.to_sat(), 0),
        other => panic!("expected InsufficientFunds, got {other:?}"),
    }
}

/// A rejected broadcast is a known outcome and must be reported as one.
#[test]
fn a_rejected_payment_reports_the_daemons_reason() {
    let chain = funded(1_000, 10_00000000).failing_broadcast(RpcError::Node {
        code: -26,
        message: "18: bad-txns-inputs-duplicate".into(),
    });
    match send(&chain, &chain, &key(), PAYEE, Amount::from_sat(1_00000000)) {
        Err(FlowError::Rpc(RpcError::Node { code, message })) => {
            assert_eq!(code, -26);
            assert!(message.contains("bad-txns"));
        }
        other => panic!("expected the node's own error, got {other:?}"),
    }
}

/// The important one. A dropped connection leaves the outcome unknown, and the
/// caller must get the bytes back rather than a silent retry.
#[test]
fn an_ambiguous_payment_hands_back_everything_needed_to_resolve_it() {
    let chain =
        funded(1_000, 10_00000000).failing_broadcast(RpcError::Transport("timed out".into()));

    match send(&chain, &chain, &key(), PAYEE, Amount::from_sat(1_00000000)) {
        Err(FlowError::BroadcastUncertain { txid, hex, .. }) => {
            assert_eq!(txid.len(), 64);
            assert!(!hex.is_empty());

            // Resolving it: ask whether the node has it. A chain that has never
            // seen it means resending is safe.
            let settled = funded(1_000, 10_00000000).with_confirmations(&"cd".repeat(32), 1);
            use verus_rpc::ChainReader;
            assert_eq!(settled.confirmations(&txid).unwrap(), None);
        }
        other => panic!("expected BroadcastUncertain, got {other:?}"),
    }
    // Nothing was retried behind the caller's back.
    assert!(chain.broadcasts().is_empty());
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

/// The same outpoint twice builds and signs cleanly, then dies at the daemon as
/// `bad-txns-inputs-duplicate` — after the caller has been shown a
/// transaction. A wallet concatenating two views of its own token outputs makes
/// exactly this mistake.
#[test]
fn a_token_output_listed_twice_is_refused_before_signing() {
    use verus_tx::{CurrencyId, Txid, Utxo};

    let chain = funded(1_000, 10_00000000);
    let token = Utxo {
        txid: Txid::from_internal([0x33; 32]),
        vout: 0,
        satoshis: verus_flows::Amount::ZERO,
        script_pubkey: verus_tx::cc::reserve_output_script(
            key().address().hash(),
            CurrencyId::from_bytes([0x22; 20]),
            1_000_000,
        )
        .expect("reserve script"),
    };

    let twice = [token.clone(), token];
    let error = verus_flows::prepare_send_token(
        &chain,
        &key(),
        CurrencyId::from_bytes([0x22; 20]),
        PAYEE,
        verus_flows::Amount::from_sat(500_000),
        &twice,
    )
    .expect_err("an outpoint can only be spent once");
    assert!(format!("{error}").contains("listed twice"), "{error}");
    assert!(chain.broadcasts().is_empty());
}

/// **Two payments in a row must not be the same transaction.**
///
/// `getaddressutxos` is confirmed-only, so an output already spent by an
/// unconfirmed transaction is still reported as unspent. Everything downstream
/// is deterministic on purpose — `select_utxos` orders by value, RFC6979 signs
/// reproducibly — so selecting it again rebuilds the first payment **byte for
/// byte**, txid included. Not a conflicting spend a node explains: a duplicate.
///
/// The determinism is right and is not what changed. The candidate set was
/// stale.
#[test]
fn a_second_payment_does_not_rebuild_the_first() {
    // Two coins, so a second payment is fundable once the first is excluded.
    let chain = ScriptedReader::new(1_000)
        .with_utxo(&address(), 500, 5_00000000)
        .with_utxo(&address(), 500, 5_00000000);

    let first = prepare_send(&chain, &key(), PAYEE, Amount::from_sat(1_00000000)).unwrap();

    // The chain now holds that transaction in its mempool, consuming the coin
    // it selected. `getaddressutxos` still reports both. The outpoint comes
    // from the signed bytes rather than from a guess about which coin the
    // selector preferred.
    let spent = {
        let tx = TxV4::deserialize(&hex::decode(&first.hex).unwrap()).unwrap();
        (
            Txid::from_internal(tx.inputs[0].txid_internal),
            tx.inputs[0].vout,
        )
    };
    let after = ScriptedReader::new(1_000)
        .with_utxo(&address(), 500, 5_00000000)
        .with_utxo(&address(), 500, 5_00000000)
        .with_mempool_spend(&address(), spent, 5_00000000);

    let second = prepare_send(&after, &key(), PAYEE, Amount::from_sat(1_00000000)).unwrap();

    assert_ne!(
        second.hex, first.hex,
        "the second payment must not be the first one rebuilt"
    );
    assert_ne!(second.txid, first.txid, "and must not share its txid");
    let second_input = {
        let tx = TxV4::deserialize(&hex::decode(&second.hex).unwrap()).unwrap();
        (
            Txid::from_internal(tx.inputs[0].txid_internal),
            tx.inputs[0].vout,
        )
    };
    assert_ne!(
        second_input, spent,
        "it must not spend the coin already in the mempool"
    );
}

/// Without the mempool read, the two payments above are identical.
///
/// The negative of the test above: nothing else in the pipeline distinguishes
/// them, which is exactly why excluding the coin is the whole fix.
#[test]
fn the_same_request_against_the_same_state_is_deterministic() {
    let chain = || {
        ScriptedReader::new(1_000)
            .with_utxo(&address(), 500, 5_00000000)
            .with_utxo(&address(), 500, 5_00000000)
    };
    let a = prepare_send(&chain(), &key(), PAYEE, Amount::from_sat(1_00000000)).unwrap();
    let b = prepare_send(&chain(), &key(), PAYEE, Amount::from_sat(1_00000000)).unwrap();
    assert_eq!(a.hex, b.hex, "determinism is deliberate and unchanged");
}

/// A coin spent in the mempool is reported as such, not as immature.
///
/// `immature` means "wait": telling a user to wait a hundred blocks for money
/// they have already spent would be worse than saying nothing.
#[test]
fn a_mempool_spent_coin_is_not_reported_as_immature() {
    let chain = ScriptedReader::new(1_000).with_utxo(&address(), 500, 5_00000000);
    let outpoint = {
        let funding = verus_flows::funding::spendable(&chain, &address()).unwrap();
        (funding.utxos[0].txid, funding.utxos[0].vout)
    };

    let after = ScriptedReader::new(1_000)
        .with_utxo(&address(), 500, 5_00000000)
        .with_mempool_spend(&address(), outpoint, 5_00000000);

    let funding = verus_flows::funding::spendable(&after, &address()).unwrap();
    assert!(funding.utxos.is_empty(), "the coin is gone, not available");
    assert!(funding.immature.is_empty(), "and it is not waiting");
    assert_eq!(funding.spent_unconfirmed.len(), 1);
    assert_eq!(funding.total, Amount::ZERO);
}

/// An unconfirmed **receipt** must not be mistaken for a spend.
///
/// Both are rows from the same call. Filtering on the wrong field would
/// withhold money that is arriving rather than leaving — a wallet that goes
/// broke the moment someone pays it.
#[test]
fn an_incoming_unconfirmed_payment_withholds_nothing() {
    let chain = ScriptedReader::new(1_000)
        .with_utxo(&address(), 500, 5_00000000)
        .with_incoming_payment(&address(), &"ab".repeat(32), 3_00000000);

    let funding = verus_flows::funding::spendable(&chain, &address()).unwrap();
    assert_eq!(
        funding.utxos.len(),
        1,
        "the confirmed coin is still spendable"
    );
    assert!(funding.spent_unconfirmed.is_empty());
}
