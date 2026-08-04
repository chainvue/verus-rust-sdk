//! The online half of an air-gapped wallet: it can see, and it cannot spend.
//!
//! ```sh
//! # 1. plan a payment — needs an address, not a key
//! VERUS_ADDRESS=R… cargo run -p verus-sdk --features network --example airgap_watch \
//!   -- plan RHFuSSCAdBCbWt7wxSJeEXphH8W9XNQYs1 0.1
//!
//! # 2. carry the blob to the offline machine, sign it there (see `airgap_sign`)
//!
//! # 3. broadcast what comes back
//! cargo run -p verus-sdk --features network --example airgap_watch -- send <signed blob>
//! ```
//!
//! Defaults to `https://api.verustest.net`; set `VERUS_ENDPOINT` for another
//! node. **Step 3 spends real testnet coins.**
//!
//! # What makes this an air gap rather than a convention
//!
//! This program has no way to sign. Not "does not sign" — cannot: it never
//! sees a private key, and [`prepare_unsigned_send`] takes an [`Address`],
//! which is a fact about the type signature rather than a promise in a comment.
//! Its counterpart, `airgap_sign`, is compiled without the `network` feature
//! and therefore links no HTTP client at all; `verus-rpc`'s
//! `tests/offline_crates_stay_offline.rs` fails the build if that ever stops
//! being true.
//!
//! So each half is missing the capability that would make it dangerous, and
//! neither is missing it by discipline.
//!
//! # Why the blob is self-contained
//!
//! What travels between the two machines carries the prevout scripts and
//! values, not just the transaction. The ZIP-243 sighash commits to those, so a
//! signer told them over a *separate* channel could be told the wrong ones and
//! would produce a signature over a transaction it never saw. One blob, one
//! thing to check.
//!
//! # What this half deliberately does not do
//!
//! It does not remember the plan. Step 3 takes the blob back from the signer
//! and finalizes *that*, rather than matching a signature against something
//! kept here — so nothing on this machine has to be trusted between the two
//! steps, and a wallet built on this shape can be restarted between them.

use verus_sdk::cosign::PartialTransaction;
use verus_sdk::money::Amount;
use verus_sdk::network::{broadcast, prepare_unsigned_send, spendable, HttpTransport, RpcClient};
use verus_sdk::verus_keys::Address;

fn endpoint() -> String {
    std::env::var("VERUS_ENDPOINT").unwrap_or_else(|_| "https://api.verustest.net".into())
}

const USAGE: &str = "usage:\n  \
    airgap_watch plan <to-address> <amount>   (needs VERUS_ADDRESS)\n  \
    airgap_watch send <signed-blob-hex>";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let node = RpcClient::new(HttpTransport::new(endpoint())?);

    match arguments.first().map(String::as_str) {
        Some("plan") => {
            let (to, amount) = match arguments.get(1..3) {
                Some([to, amount]) => (to.clone(), amount.clone()),
                _ => return Err(USAGE.into()),
            };
            let from: Address = std::env::var("VERUS_ADDRESS")
                .map_err(|_| "set VERUS_ADDRESS=R… — the address to spend from")?
                .parse()?;
            plan(&node, &from, &to, Amount::from_coins_str(&amount)?)
        }
        Some("send") => {
            let blob = arguments.get(1).ok_or(USAGE)?;
            send(&node, blob)
        }
        _ => Err(USAGE.into()),
    }
}

fn plan(
    node: &RpcClient<HttpTransport>,
    from: &Address,
    to: &str,
    amount: Amount,
) -> Result<(), Box<dyn std::error::Error>> {
    // Printed before the plan because a plan that fails for want of funds
    // should say what there was, not just that there was not enough.
    let funding = spendable(node, &from.to_string())?;
    println!(
        "{from} holds {} spendable across {} output(s) at tip {}",
        funding.total,
        funding.utxos.len(),
        funding.tip
    );

    let partial = prepare_unsigned_send(node, from, to, amount)?;
    let summary = partial.summary()?;
    println!(
        "\nplanned: {} in, {} out, {} fee, {} input(s)",
        summary.total_in,
        summary.total_out,
        summary.fee_and_burn,
        partial.inputs.len()
    );

    println!("\ncarry this to the offline machine:\n");
    println!("{}", hex::encode(partial.to_bytes()?));
    Ok(())
}

fn send(node: &RpcClient<HttpTransport>, blob: &str) -> Result<(), Box<dyn std::error::Error>> {
    let partial = PartialTransaction::from_bytes(&hex::decode(blob.trim())?)?;

    // `finalize` re-verifies every signature against the sighash it claims to
    // cover, so a blob that was altered on the way back — or signed by the
    // wrong key — fails here, naming the input. The alternative is a node
    // answering that a script finished false, which names nothing.
    let signed = partial.finalize()?;
    println!("finalized {} ({} bytes)", signed.txid, signed.hex.len() / 2);

    let txid = broadcast(node, &signed.hex, &signed.txid)?;
    println!("broadcast {txid}");
    Ok(())
}
