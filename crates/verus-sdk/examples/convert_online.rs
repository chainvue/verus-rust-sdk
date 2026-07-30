//! Convert one currency into another. SPENDS REAL TESTNET COINS.
//!
//!   VERUS_WIF=… cargo run -p verus-sdk --features network --example convert_online -- VRSCTEST shylock 0.5
//!
//! Two-step on purpose: estimate first, then convert with the estimate as the
//! floor. The floor is checked **before signing and never again** — a
//! conversion is executed by the chain when the transfer is imported, at
//! whatever the price is then. `min_expected` catches a price that has already
//! moved; it cannot freeze one.

use verus_sdk::convert::ConversionKind;
use verus_sdk::money::Amount;
use verus_sdk::network::{convert, estimate, ChainReader, HttpTransport, RpcClient};
use verus_sdk::send::CurrencyId;
use verus_sdk::verus_keys::{Address, PrivateKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: convert_online <from-currency> <to-currency> <coins>";
    let from = args.next().ok_or(usage)?;
    let to = args.next().ok_or(usage)?;
    let amount = Amount::from_coins_str(&args.next().ok_or(usage)?)?;

    let key = PrivateKey::from_wif(&std::env::var("VERUS_WIF").map_err(|_| "set VERUS_WIF")?)?;
    let recipient = key.address().to_string();
    let node = RpcClient::new(HttpTransport::new(
        std::env::var("VERUS_ENDPOINT").unwrap_or_else(|_| "https://api.verustest.net".into()),
    )?);

    // Step 1: what does the node think this is worth right now?
    let quote = estimate(&node, &from, &to, amount, None)?;
    println!(
        "{} {from} → an estimated {} {to}",
        amount, quote.estimated_out
    );

    // Resolve both names to currency ids by asking the chain — the `i` address
    // is the 20 bytes a `CReserveTransfer` names a currency by. `estimate`
    // accepts friendly names, but `convert`'s source must be the id.
    let source_id = node.currency(&from)?.currency_id;
    let target_policy = node.currency(&to)?;
    let target = CurrencyId::from_bytes(target_policy.currency_id.parse::<Address>()?.hash());

    // Step 2: build, sign, broadcast — refusing if the estimate already slid
    // more than ~1% under what we just saw. This example buys a fractional
    // with one of its reserves; see `ConversionKind` for the other directions.
    // Divided before multiplied so the arithmetic cannot overflow a u64.
    let floor = Amount::from_sat(quote.estimated_out.to_sat() / 100 * 99);
    let sent = convert(
        &node,
        &node,
        &key,
        &source_id,
        amount,
        ConversionKind::IntoFractional { fractional: target },
        &recipient,
        Amount::from_sat(20_000),
        Some(floor),
        &[],
    )?;
    println!("broadcast: {}", sent.txid);
    println!("the conversion settles when the chain imports the transfer — usually the next block or two");
    Ok(())
}
