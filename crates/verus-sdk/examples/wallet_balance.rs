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

use verus_sdk::network::{currency_names, native_currency, spendable, HttpTransport, RpcClient};

/// A currency's own i-address — the part of a token's identity that cannot
/// lie, and the only thing worth printing when the name is missing.
fn i_address(currency: &verus_sdk::verus_tx::CurrencyId) -> String {
    verus_sdk::verus_keys::Address::new(
        verus_sdk::verus_keys::AddressKind::Identity,
        currency.to_bytes(),
    )
    .to_string()
}

fn endpoint() -> String {
    std::env::var("VERUS_ENDPOINT").unwrap_or_else(|_| "https://api.verustest.net".into())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = std::env::var("VERUS_ADDRESS").map_err(|_| "set VERUS_ADDRESS=R…")?;

    let node = RpcClient::new(HttpTransport::new(endpoint())?);
    let funding = spendable(&node, &address)?;

    // One request, and a wallet would cache it forever: a chain's own currency
    // id never changes. It lets the counting below tell "this output holds a
    // token" from "this output names the chain's own currency for the chain's
    // accounting, and carries it as satoshis" — which is the whole difference
    // between a correct balance and one that reports the same money twice.
    // `None` here would still work; it would just refuse those two shapes.
    let native = native_currency(&node).ok();

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
    // figures. Counting fails closed — an output this SDK cannot read *and*
    // whose eval code could be hiding a currency is refused, because no total
    // is better than one that is quietly too small. That is a narrow set now:
    // both coinbase shapes and every identity output are countable. But a
    // wallet still must not withhold the native balance it already knows over
    // a token figure it does not, so the failure is a line, not an exit.
    match funding.token_balances(native) {
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
            // and only because there is something to display. A currency the
            // node simply does not have is left unnamed; anything else that
            // went wrong comes back beside the currency it went wrong for, so
            // one bad lookup costs one name rather than all of them. The `?`
            // is unreachable here — the outer error is only the driver's
            // sentinel, and this example drives nothing.
            let (names, unreadable) = currency_names(&node, held.keys().copied())?;
            println!("  tokens:");
            for (currency, amount) in &held {
                match names.get(currency) {
                    // A name comes from the node and is shown to a person, so
                    // it is printed beside the id that cannot lie rather than
                    // instead of it.
                    Some(name) => println!("    {amount:>16}  {name}@  ({})", i_address(currency)),
                    None => println!("    {amount:>16}  {}", i_address(currency)),
                }
            }
            // After the names, not instead of them: show what you have, then
            // say what you could not read. Silence here is what made a
            // single unreadable currency look like a wallet of nameless
            // tokens.
            if !unreadable.is_empty() {
                println!("  {} name(s) could not be read:", unreadable.len());
                for (currency, error) in &unreadable {
                    println!("    {}  {error}", i_address(currency));
                }
            }
        }
    }

    match funding.immature_token_balances(native) {
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
