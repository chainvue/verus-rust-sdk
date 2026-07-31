//! What an address holds and what it can spend, through the public node.
//! Read-only.
//!
//!   VERUS_ADDRESS=R… cargo run -p verus-sdk --features network --example wallet_balance
//!
//! `spendable` answers three questions a wallet must keep apart: what is
//! spendable *now*, what exists but is immature coinbase, and what is held in
//! CryptoCondition outputs that the native builders rightly refuse as plain
//! funding. `token_balances` then says what those last outputs are actually
//! worth — which is the part a user cares about, and the part that is invisible
//! from a satoshi count, because a token's value is in the output's payload
//! rather than in its satoshi field.

use verus_sdk::network::{currency_names, spendable, HttpTransport, RpcClient};

fn endpoint() -> String {
    std::env::var("VERUS_ENDPOINT").unwrap_or_else(|_| "https://api.verustest.net".into())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = std::env::var("VERUS_ADDRESS").map_err(|_| "set VERUS_ADDRESS=R…")?;

    let node = RpcClient::new(HttpTransport::new(endpoint())?);
    let funding = spendable(&node, &address)?;

    println!("{address} at tip {}", funding.tip);
    println!(
        "  spendable {} native across {} output(s)",
        funding.total,
        funding.utxos.len()
    );
    if !funding.immature.is_empty() {
        println!(
            "  immature  {} native in {} coinbase output(s) — spendable after 100 confirmations",
            funding.immature_total(),
            funding.immature.len()
        );
    }

    // Decoded from outputs already fetched: no extra request, and the same
    // decoder `build_token_send` uses to select them.
    //
    // Reported rather than propagated, and deliberately AFTER the native
    // figures. Counting fails closed — an output this SDK cannot read might
    // carry a currency it cannot see, so no total is better than a small one —
    // and a proof-of-stake coinbase pays its first output to a stakeguard
    // CryptoCondition this SDK does not decode. So any address that has staked
    // recently cannot be given a token total, and aborting over that would
    // withhold the native balance it already knows, which helps nobody.
    match funding.token_balances() {
        Err(error) => println!("  tokens   unknown: {error}"),
        Ok(held) if held.is_empty() => {
            if !funding.other.is_empty() {
                println!(
                    "  {} CryptoCondition output(s) carrying no currency — identities, most likely",
                    funding.other.len()
                );
            }
        }
        Ok(held) => {
            // Names cost one request each, so they are asked for once, here,
            // and only because there is something to display. A node that
            // cannot be reached is an error; one that simply does not know a
            // currency leaves it unnamed.
            let names = currency_names(&node, held.keys().copied()).unwrap_or_default();
            println!("  tokens:");
            for (currency, amount) in &held {
                let id = verus_sdk::verus_keys::Address::new(
                    verus_sdk::verus_keys::AddressKind::Identity,
                    currency.to_bytes(),
                )
                .to_string();
                match names.get(currency) {
                    // A name comes from the node and is shown to a person, so
                    // it is printed beside the id that cannot lie rather than
                    // instead of it.
                    Some(name) => println!("    {amount:>16}  {name}@  ({id})"),
                    None => println!("    {amount:>16}  {id}"),
                }
            }
        }
    }

    match funding.immature_token_balances() {
        Ok(stuck) if stuck.is_empty() => {}
        Ok(stuck) => {
            println!("  tokens in outputs that are not spendable yet:");
            for (currency, amount) in &stuck {
                println!("    {amount:>16}  {}", hex::encode(currency.to_bytes()));
            }
        }
        Err(error) => println!("  unspendable outputs could not be counted: {error}"),
    }
    Ok(())
}
