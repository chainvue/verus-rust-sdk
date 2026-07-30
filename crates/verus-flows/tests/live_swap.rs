//! A complete marketplace order settled on VRSCTEST, through the public node.
//!
//! Two independent keys, two independent signatures, one transaction. The maker
//! signs an input under `SIGHASH_SINGLE | ANYONECANPAY` paired with the output
//! they want; the taker appends their own side and signs it under
//! `SIGHASH_ALL`. Neither ever holds the other's key, and nothing is escrowed.
//!
//! **Opt-in, and it spends real testnet coins:**
//!
//! ```sh
//! export VERUS_LIVE_KEY=<maker WIF>
//! export VERUS_LIVE_TAKER_KEY=<taker WIF>
//! VERUS_LIVE_SWAP=1 cargo test -p verus-flows --test live_swap -- --nocapture --test-threads=1
//! ```
//!
//! Both sides here are native VRSCTEST, so this proves the mechanism with the
//! simplest legs. Token demands are supported too — `take_offer` funds them
//! from reserve inputs — but that path is byte-verified only, never broadcast
//! (PROVEN.md keeps the ledger); this live test does not exercise it.

use verus_flows::{spendable, Broadcaster, ChainReader, HttpTransport, RpcClient};
use verus_keys::PrivateKey;
use verus_tx::offer::{fund_offer, make_offer, take_offer, OfferParams, TakeParams, Wanted};
use verus_tx::{Amount, Expiry, Txid, Utxo, DEFAULT_EXPIRY_BLOCKS};
use verus_wire::TxV4;

const ENDPOINT: &str = "https://api.verustest.net";
const FEE_PER_KB: u64 = 100_000;

fn client() -> RpcClient<HttpTransport> {
    RpcClient::new(HttpTransport::new(ENDPOINT).expect("https"))
}

fn keys() -> Option<(PrivateKey, PrivateKey)> {
    if std::env::var("VERUS_LIVE_SWAP").is_err() {
        eprintln!("skipping: set VERUS_LIVE_SWAP=1, VERUS_LIVE_KEY and VERUS_LIVE_TAKER_KEY");
        return None;
    }
    let maker = PrivateKey::from_wif(&std::env::var("VERUS_LIVE_KEY").expect("VERUS_LIVE_KEY"))
        .expect("maker WIF");
    let taker =
        PrivateKey::from_wif(&std::env::var("VERUS_LIVE_TAKER_KEY").expect("VERUS_LIVE_TAKER_KEY"))
            .expect("taker WIF");
    Some((maker, taker))
}

/// Wait for a transaction to confirm, or give up.
fn await_confirmation(client: &RpcClient<HttpTransport>, txid: &str) {
    for _ in 0..40 {
        if let Ok(Some(confirmations)) = client.confirmations(txid) {
            if confirmations > 0 {
                eprintln!("    confirmed ({confirmations})");
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(15));
    }
    panic!("{txid} never confirmed");
}

#[test]
fn two_parties_settle_a_marketplace_order() {
    let Some((maker, taker)) = keys() else { return };
    let client = client();

    let maker_address = maker.address();
    let taker_address = taker.address();
    eprintln!("maker {maker_address}\ntaker {taker_address}");

    let offered = Amount::from_sat(1_00000000); // the maker gives 1 VRSCTEST
    let wanted = Amount::from_sat(1_20000000); // and wants 1.2 back

    // --- step 1: the maker moves funds into an output an offer can be signed over
    let tip = client.block_count().expect("tip");
    let maker_funds = spendable(&client, &maker_address.to_string()).expect("maker funds");
    let funding_tx = fund_offer(
        &maker,
        &maker_funds.utxos,
        offered,
        &maker_address,
        Expiry::within(tip, DEFAULT_EXPIRY_BLOCKS),
        FEE_PER_KB,
    )
    .expect("fund the offer");

    eprintln!("  funding {}", funding_tx.txid);
    client
        .send_raw_transaction(&funding_tx.hex)
        .expect("broadcast the funding transaction");
    await_confirmation(&client, &funding_tx.txid);

    // Output 0 of that transaction is the offer's backing.
    let funding = Utxo {
        txid: Txid::from_display_hex(&funding_tx.txid).expect("txid"),
        vout: 0,
        satoshis: offered,
        script_pubkey: verus_tx::offer::offer_funding_script(maker_address.hash()).expect("script"),
    };

    // --- step 2: the maker signs the offer. Nothing is broadcast.
    let tip = client.block_count().expect("tip");
    let offer = make_offer(
        &maker,
        &OfferParams::new(
            &funding,
            Wanted::Native {
                amount: wanted,
                recipient: maker_address.hash(),
            },
            Expiry::within(tip, 200),
        ),
    )
    .expect("make the offer");
    eprintln!(
        "  offer signed: give {}, want {}",
        offered.to_coins_string(),
        wanted.to_coins_string()
    );

    // --- step 3: the taker completes it, with their own coins and their own key
    let taker_funds = spendable(&client, &taker_address.to_string()).expect("taker funds");
    assert!(
        taker_funds.total >= wanted,
        "the taker holds {} but the offer asks {}",
        taker_funds.total.to_coins_string(),
        wanted.to_coins_string()
    );

    let completed = take_offer(
        &taker,
        &TakeParams::new(
            &offer.hex,
            &taker_funds.utxos,
            taker_address.hash(),
            taker_address,
            offered,
            20_000,
        ),
    )
    .expect("take the offer");
    let completed_hex = hex::encode(&completed);

    // The maker's side must have survived completion untouched.
    let original = TxV4::deserialize(&hex::decode(&offer.hex).unwrap()).unwrap();
    let final_tx = TxV4::deserialize(&completed).unwrap();
    assert_eq!(final_tx.inputs[0], original.inputs[0]);
    assert_eq!(final_tx.outputs[0], original.outputs[0]);
    eprintln!(
        "  completed: {} inputs, {} outputs",
        final_tx.inputs.len(),
        final_tx.outputs.len()
    );

    // --- step 4: the network settles it
    let txid = client
        .send_raw_transaction(&completed_hex)
        .expect("the network must accept an order this SDK settled");
    eprintln!("  SETTLED {txid}");
    await_confirmation(&client, &txid);
}
