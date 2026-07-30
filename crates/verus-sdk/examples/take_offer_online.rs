//! Inspect a marketplace offer against the chain, then take it.
//! TAKING SPENDS REAL TESTNET COINS; inspection alone is free.
//!
//!   cargo run -p verus-sdk --features network --example take_offer_online < offer.hex
//!   VERUS_WIF=… TAKE=1 cargo run -p verus-sdk --features network --example take_offer_online < offer.hex
//!
//! The maker's hex says what they *claim* to give. The taker is the party at
//! risk — a maker who spent the funding output after publishing leaves an
//! offer that costs a fee to discover. `inspect` reads what the outpoint
//! **actually holds right now**, and `take` uses that figure, not the
//! caller's; a mistyped value cannot hand the difference to a miner.

use std::io::Read;

use verus_sdk::network::{inspect, take, Demand, HttpTransport, RpcClient, Taking};
use verus_sdk::verus_keys::PrivateKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut offer_hex = String::new();
    std::io::stdin().read_to_string(&mut offer_hex)?;
    let offer_hex = offer_hex.trim();

    let node = RpcClient::new(HttpTransport::new(
        std::env::var("VERUS_ENDPOINT").unwrap_or_else(|_| "https://api.verustest.net".into()),
    )?);

    // What is really on offer, read from the chain — not from the maker.
    let terms = inspect(&node, offer_hex)?;
    println!("on offer : {} VRSCTEST (verified on chain)", terms.offered);
    match &terms.demand {
        Demand::Native { amount, .. } => println!("demanded : {amount} VRSCTEST"),
        Demand::Token {
            currency, amount, ..
        } => println!("demanded : {amount} of token {currency}"),
    }
    if terms.expiry_height != 0 {
        println!("expires  : block {}", terms.expiry_height);
    }
    if terms.confirmations == 0 {
        println!("note     : funding is still in the mempool — wait before taking");
    }

    if std::env::var("TAKE").is_err() {
        println!("\ninspection only — set TAKE=1 and VERUS_WIF to complete it");
        return Ok(());
    }

    let key = PrivateKey::from_wif(&std::env::var("VERUS_WIF").map_err(|_| "set VERUS_WIF")?)?;
    let me = key.address();

    // NOTE: `take` spends every UTXO it is handed — there is no coin selection
    // inside. Passing everything is fine for a demo wallet with a few outputs;
    // a real wallet should select enough to cover the demand plus fee, and
    // scale the fee with the transaction size.
    let funding = verus_sdk::network::spendable(&node, &me.to_string())?;

    let taken = take(
        &node,
        &node,
        &key,
        &Taking::new(offer_hex, &funding.utxos, me.hash(), me, 20_000),
    )?;
    println!("settled: {}", taken.txid);
    Ok(())
}
