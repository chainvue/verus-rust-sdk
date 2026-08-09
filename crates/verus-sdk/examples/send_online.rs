//! Send VRSCTEST: lookup → build → sign → broadcast. SPENDS REAL TESTNET COINS.
//!
//!   VERUS_WIF=… cargo run -p verus-sdk --features network --example send_online -- R… 0.1
//!
//! The part worth copying is the error handling. A broadcast that fails at the
//! transport level is **ambiguous** — the node may have accepted and relayed
//! the transaction before the connection died. Retrying blind can double-spend
//! against yourself; the correct move is to re-read, which is exactly what the
//! `BroadcastUncertain` arm below does.

use verus_sdk::money::Amount;
use verus_sdk::network::{broadcast, send, ChainReader, FlowError, HttpTransport, RpcClient};
use verus_sdk::verus_keys::PrivateKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let to = args.next().ok_or("usage: send_online <address> <coins>")?;
    let coins = args.next().ok_or("usage: send_online <address> <coins>")?;

    let key = PrivateKey::from_wif(&std::env::var("VERUS_WIF").map_err(|_| "set VERUS_WIF")?)?;
    let amount = Amount::from_coins_str(&coins)?;
    let node = RpcClient::new(HttpTransport::new(
        std::env::var("VERUS_ENDPOINT").unwrap_or_else(|_| "https://api.verustest.net".into()),
    )?);

    // The same client is reader and broadcaster here. They are separate
    // parameters so a dry-run build can take a reader alone — or query one node
    // and hand the finished bytes to another.
    match send(&node, &node, &key, &to, amount) {
        Ok(sent) => println!("sent: {}", sent.txid),
        Err(FlowError::BroadcastUncertain { txid, hex, .. }) => {
            // The transaction is signed and MAY be on the network. Do not
            // rebuild and resend — ask first.
            match node.confirmations(&txid) {
                Ok(Some(_)) => println!("it arrived after all: {txid}"),
                Ok(None) => {
                    // Known absent: rebroadcasting the SAME bytes is safe.
                    // Through `broadcast`, not the raw trait method, so a
                    // `-27` here (mined between the check and this call) is
                    // still reported as success rather than a rejection.
                    println!("not found; rebroadcasting the same bytes");
                    let txid = broadcast(&node, &hex, &txid)?;
                    println!("sent: {txid}");
                }
                Err(e) => {
                    // Still can't reach the node. Surface the signed bytes so
                    // the operator can resolve it later — nothing else should
                    // spend these inputs until this is settled.
                    eprintln!("keep these bytes to rebroadcast once the node answers:\n{hex}");
                    return Err(format!("unresolved broadcast {txid}: {e}").into());
                }
            }
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
