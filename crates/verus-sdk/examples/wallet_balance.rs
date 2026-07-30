//! What an address can spend, through the public node. Read-only.
//!
//!   VERUS_ADDRESS=R… cargo run -p verus-sdk --features network --example wallet_balance
//!
//! `spendable` answers three different questions a wallet must keep apart:
//! what is spendable *now*, what exists but is immature coinbase, and what is
//! held in CryptoCondition outputs (tokens, identities) that the native
//! builders rightly refuse as plain funding.

use verus_sdk::network::{spendable, HttpTransport, RpcClient};

fn endpoint() -> String {
    std::env::var("VERUS_ENDPOINT").unwrap_or_else(|_| "https://api.verustest.net".into())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = std::env::var("VERUS_ADDRESS").map_err(|_| "set VERUS_ADDRESS=R…")?;

    let node = RpcClient::new(HttpTransport::new(endpoint())?);
    let funding = spendable(&node, &address)?;

    println!("{address} at tip {}", funding.tip);
    println!(
        "  spendable {} VRSCTEST across {} output(s)",
        funding.total,
        funding.utxos.len()
    );
    if !funding.immature.is_empty() {
        println!(
            "  immature  {} VRSCTEST in {} coinbase output(s) — spendable after 100 confirmations",
            funding.immature_total(),
            funding.immature.len()
        );
    }
    if !funding.other.is_empty() {
        println!(
            "  other     {} CryptoCondition output(s) — tokens or identities; see verus_sdk::send::build_token_send",
            funding.other.len()
        );
    }
    Ok(())
}
