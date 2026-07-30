//! Make a marketplace offer. SPENDS REAL TESTNET COINS (the funding step).
//!
//!   VERUS_WIF=… cargo run -p verus-sdk --features network --example make_offer_online -- 1.0 1.2
//!
//! Offers `<give>` VRSCTEST and demands `<want>` VRSCTEST back. Two steps:
//!
//! 1. **Fund** — an ordinary transaction moves the offered coins into a
//!    CryptoCondition output an offer can be signed over. This broadcasts.
//! 2. **Sign** — the offer itself: a half-signed transaction under
//!    `SIGHASH_SINGLE | ANYONECANPAY`. This broadcasts NOTHING; the printed
//!    hex is the offer, and handing it to someone is what publishing means.
//!
//! An offer is a standing authorisation until taken, expired, or the funding
//! output is spent — there is no cancel message, which is why the expiry here
//! is short and deliberate.

use verus_sdk::money::{Amount, Expiry, Txid, Utxo, DEFAULT_FEE_PER_KB};
use verus_sdk::network::{broadcast, spendable, ChainReader, HttpTransport, RpcClient};
use verus_sdk::offer::{fund_offer, make_offer, offer_funding_script, OfferParams, Wanted};
use verus_sdk::verus_keys::PrivateKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: make_offer_online <give-coins> <want-coins>";
    let give = Amount::from_coins_str(&args.next().ok_or(usage)?)?;
    let want = Amount::from_coins_str(&args.next().ok_or(usage)?)?;

    let key = PrivateKey::from_wif(&std::env::var("VERUS_WIF").map_err(|_| "set VERUS_WIF")?)?;
    let me = key.address();
    let node = RpcClient::new(HttpTransport::new(
        std::env::var("VERUS_ENDPOINT").unwrap_or_else(|_| "https://api.verustest.net".into()),
    )?);

    // Step 1: move the offered coins into an output an offer can spend.
    let tip = node.block_count()?;
    let funding = spendable(&node, &me.to_string())?;
    let funded = fund_offer(
        &key,
        &funding.utxos,
        give,
        &me,
        Expiry::within(tip, 20),
        DEFAULT_FEE_PER_KB,
    )?;
    // The checked broadcast: refuses a node that answers about a different
    // transaction, and turns an ambiguous transport failure into
    // `BroadcastUncertain` — see send_online for how to resolve that.
    let funding_txid = broadcast(&node, &funded.hex, &funded.txid)?;
    println!("funding broadcast: {funding_txid}");
    println!("wait for it to confirm before publishing the offer");
    println!("(the funding expires ~20 blocks out if unconfirmed; the coins never left this key)");

    // Output 0 of the funding transaction is the offer's backing.
    let backing = Utxo {
        txid: Txid::from_display_hex(&funding_txid)?,
        vout: 0,
        satoshis: give,
        script_pubkey: offer_funding_script(me.hash())?,
    };

    // Step 2: sign the offer over that output. Nothing is broadcast — the hex
    // IS the offer. ~200 blocks ≈ 3–4 hours on VRSCTEST.
    let offer = make_offer(
        &key,
        &OfferParams::new(
            &backing,
            Wanted::Native {
                amount: want,
                recipient: me.hash(),
            },
            Expiry::within(tip, 200),
        ),
    )?;
    println!(
        "offer signed: give {} VRSCTEST, want {} VRSCTEST back",
        give, want
    );
    println!("offer hex (hand this to a taker):\n{}", offer.hex);
    Ok(())
}
