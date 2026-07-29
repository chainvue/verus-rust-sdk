//! End to end against VRSCTEST, through the public node only.
//!
//! Everything else in this crate proves the flows are *internally* consistent
//! against a chain that was written down. This proves the chain agrees.
//!
//! **Opt-in, and it spends real testnet coins:**
//!
//! ```sh
//! export VERUS_LIVE_KEY=<WIF>          # a funded VRSCTEST key
//! VERUS_LIVE_BROADCAST=1 cargo test -p verus-flows --test live_flows -- --nocapture --test-threads=1
//! ```
//!
//! The key is read from the environment and **never** written to this repository
//! — the WIF committed in the other test files is public, so anything sent to it
//! can be swept by anyone.
//!
//! Never in CI. `VERUS_LIVE_BROADCAST` is a separate variable from the
//! `VERUS_LIVE_RPC` used for read-only drift checks precisely so that a
//! scheduled job cannot broadcast by accident.
//!
//! The node is only ever asked to answer questions and to relay finished bytes.
//! It is never given a key, and never asked to build or sign anything.

use verus_flows::{prepare_send, send, spendable};
use verus_keys::PrivateKey;
use verus_rpc::{ChainReader, HttpTransport, RpcClient};
use verus_tx::Amount;

const ENDPOINT: &str = "https://api.verustest.net";

fn client() -> RpcClient<HttpTransport> {
    RpcClient::new(HttpTransport::new(ENDPOINT).expect("https endpoint"))
}

/// The funded key, from the environment. Absent means these tests skip.
fn live_key() -> Option<PrivateKey> {
    if std::env::var("VERUS_LIVE_BROADCAST").is_err() {
        eprintln!("skipping: set VERUS_LIVE_BROADCAST=1 and VERUS_LIVE_KEY=<WIF>");
        return None;
    }
    let wif = std::env::var("VERUS_LIVE_KEY")
        .expect("VERUS_LIVE_BROADCAST is set but VERUS_LIVE_KEY is not");
    Some(PrivateKey::from_wif(&wif).expect("VERUS_LIVE_KEY is not a valid WIF"))
}

/// Read-only: what the flow layer sees when it looks at a real address.
///
/// Runs under the read-only gate too, since it broadcasts nothing.
#[test]
fn funding_lookup_agrees_with_the_chain() {
    if std::env::var("VERUS_LIVE_RPC").is_err() && std::env::var("VERUS_LIVE_BROADCAST").is_err() {
        eprintln!("skipping: set VERUS_LIVE_RPC=1");
        return;
    }
    let client = client();
    let address = "RJUgxvDnDLsRGCXNKDK56Rxngzh6m25J6F";

    let funding = spendable(&client, address).expect("funding lookup");
    let balance = client.address_balance(&[address]).expect("balance");

    eprintln!(
        "{address}: {} spendable across {} outputs, {} immature, balance {}",
        funding.total.to_coins_string(),
        funding.utxos.len(),
        funding.immature_total().to_coins_string(),
        balance.balance.to_coins_string()
    );

    // Spendable plus immature must account for the whole balance. A gap means
    // the maturity filter is dropping something it should not.
    let accounted = funding
        .total
        .checked_add(funding.immature_total())
        .expect("no overflow");
    assert_eq!(accounted, balance.balance);
    assert!(funding.tip > 1_000_000);
}

/// Build a real transaction against real UTXOs and let the daemon parse it —
/// without broadcasting. The strongest check available that costs nothing.
#[test]
fn a_prepared_payment_decodes_on_the_daemon() {
    let Some(key) = live_key() else { return };
    let client = client();

    let signed = prepare_send(
        &client,
        &key,
        &key.address().to_string(),
        Amount::from_sat(1_000_000),
    )
    .expect("prepare");

    let decoded = client
        .decode_raw_transaction(&signed.hex)
        .expect("decoderawtransaction");

    assert_eq!(decoded["txid"].as_str(), Some(signed.txid.as_str()));
    assert_eq!(decoded["version"].as_u64(), Some(4));

    // The expiry flows set from the tip, rather than the "never" every example
    // in this repository used to pass.
    let expiry = decoded["expiryheight"].as_u64().expect("expiryheight");
    let tip = u64::from(client.block_count().expect("tip"));
    assert!(expiry > tip, "expiry {expiry} is not ahead of tip {tip}");
    assert!(
        expiry <= tip + 21,
        "expiry {expiry} is further out than expected"
    );

    eprintln!(
        "prepared {} — {} outputs, expiry {expiry} (tip {tip}), nothing broadcast",
        signed.txid,
        decoded["vout"].as_array().map_or(0, Vec::len)
    );
}

/// The real thing: a payment that lands on chain.
///
/// Pays the funding key back to itself, so the only cost is the miner fee.
#[test]
fn a_payment_reaches_the_chain() {
    let Some(key) = live_key() else { return };
    let client = client();
    let address = key.address().to_string();

    let before = spendable(&client, &address).expect("funding");
    eprintln!(
        "before: {} spendable across {} outputs",
        before.total.to_coins_string(),
        before.utxos.len()
    );

    let sent = send(
        &client,
        &client,
        &key,
        &address,
        Amount::from_sat(1_000_000),
    )
    .expect("send");

    eprintln!(
        "broadcast {} — fee {}, change {}",
        sent.txid,
        sent.fee.to_coins_string(),
        sent.change.to_coins_string()
    );

    // The node accepted it, so it knows about it.
    let confirmations = client.confirmations(&sent.txid).expect("confirmations");
    assert!(
        confirmations.is_some(),
        "the node accepted {} but does not know it",
        sent.txid
    );
    eprintln!("node has it at {confirmations:?} confirmations");
}
