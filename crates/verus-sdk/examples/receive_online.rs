//! The receiving half of a shielded wallet: create an account, record its
//! birthday, scan, and show what arrived — with memos. Read-only; spends
//! nothing.
//!
//! ```sh
//! # A new account. Record the birthday BEFORE showing anyone the address.
//! VERUS_SEED_HEX=… cargo run -p verus-sdk --features light --example receive_online
//!
//! # An existing one, from a recorded birthday.
//! VERUS_SEED_HEX=… VERUS_BIRTHDAY=1173600 \
//!   cargo run -p verus-sdk --features light --example receive_online
//! ```
//!
//! `VERUS_LIGHT_ENDPOINT` (default `http://127.0.0.1:8080`) is a grpcwebproxy
//! in front of lightwalletd; `VERUS_RPC` (default `https://api.verustest.net`)
//! is an ordinary daemon, used here only for the birthday.
//!
//! # The birthday is the whole difference between fast and unusable
//!
//! **Sapling activates at height 1 on Verus.** There is no activation floor to
//! fall back on the way there is on Zcash — "scan from activation" is "scan
//! from genesis", which is 1.17 million blocks on VRSCTEST and four times that
//! on mainnet. A wallet that does not record a birthday rescans all of it, every
//! restore.
//!
//! And the ordering is a trap with real teeth: a birthday taken *after* an
//! address has been given out is later than the first payment to it, and every
//! note before it is invisible. The wallet is quietly missing money and nothing
//! says so. Take the height first, persist it, then publish the address, and
//! subtract `REORG_CHECKPOINTS` blocks of slack — 200 extra blocks is seconds
//! of scanning, and a payment that landed in a block the chain later replaced,
//! below your birthday, is invisible forever.
//!
//! # This rescans from the birthday every run, and a wallet must not
//!
//! Kept simple so the birthday is the only moving part. A real wallet persists
//! its whole `ScanResult` (behind the `serde` feature) and calls `scan_after`,
//! which covers only the tail and refuses if the chain moved underneath it,
//! then folds the answer in with `absorb`. Copy that from
//! `crates/verus-flows/tests/persist_wallet_state.rs`, not from here — as
//! written, this re-fetches every memo it has ever displayed, on every
//! launch.
//!
//! # No spending key is involved
//!
//! Everything below runs on the *viewing* key. A watch-only wallet — a phone
//! showing a balance, a service watching for payments — needs exactly this and
//! nothing more.

use verus_sdk::light::{
    birthday, received, scan, GrpcWebTransport, LightClient, ScanResult, REORG_CHECKPOINTS,
};
use verus_sdk::network::{HttpTransport, RpcClient};
use verus_sdk::verus_sapling::derive::{derive_account, COIN_TYPE_MAINNET};
use verus_sdk::verus_sapling::scan::dfvk_from_bytes;
use verus_sdk::verus_sapling::zaddr;

type Error = Box<dyn std::error::Error>;

fn env_or(name: &str, fallback: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| fallback.to_string())
}

fn main() -> Result<(), Error> {
    let seed = hex::decode(
        std::env::var("VERUS_SEED_HEX")
            .map_err(|_| "set VERUS_SEED_HEX to a BIP-39 seed (see keygen_phrase)")?
            .trim(),
    )?;

    let light = LightClient::new(GrpcWebTransport::new(env_or(
        "VERUS_LIGHT_ENDPOINT",
        "http://127.0.0.1:8080",
    ))?);
    let node = RpcClient::new(HttpTransport::new(env_or(
        "VERUS_RPC",
        "https://api.verustest.net",
    ))?);

    // Derive first, so the account exists before anything is published — and
    // take the birthday in the same breath.
    let account = derive_account(&seed, COIN_TYPE_MAINNET, 0)?;
    let dfvk = dfvk_from_bytes(&account.dfvk)?;

    let from = match std::env::var("VERUS_BIRTHDAY") {
        Ok(recorded) => recorded.parse()?,
        Err(_) => {
            // A fresh account. Nothing can have been paid to an address nobody
            // has seen, so the tip now is a safe floor — minus the reorg
            // window, because a payment could still land in a block the chain
            // later replaces, and one below the birthday is invisible forever.
            let now = birthday(&node)?;
            let slack = u64::try_from(REORG_CHECKPOINTS).unwrap_or(200);
            let with_slack = now.saturating_sub(slack).max(1);
            println!("birthday {with_slack}  — persist this before publishing the address");
            with_slack
        }
    };

    println!("address  {}", zaddr::encode(&account.address)?);

    let tip = light.latest_block()?.height;
    println!(
        "scanning {from}..={tip} ({} blocks)",
        tip.saturating_sub(from) + 1
    );
    let found: ScanResult = scan(&light, &dfvk, from, tip)?;

    // `unspent`, not `notes`: the second reports money already gone.
    let unspent = found.unspent(&[]);
    println!(
        "\n{} note(s), {} zatoshi spendable",
        unspent.len(),
        found.balance(&[])
    );

    for note in &unspent {
        // The scan found the note from 52 compact bytes, which carry the value
        // and not the memo. This fetches the whole output and decrypts it —
        // one round trip per note, so a real wallet does it for what it is
        // about to display rather than for everything it holds.
        let full = received(&light, &dfvk, note)?;
        // Escaped, not printed raw. `memo_text` guarantees valid UTF-8, which
        // includes ESC and every other control character — anyone can pay this
        // address a memo of ANSI sequences that rewrite the terminal above.
        // A GUI has the same problem with a different alphabet.
        let memo = match full.memo_text() {
            Some("") | None => String::from("(no memo)"),
            Some(text) => {
                let safe: String = text
                    .chars()
                    .map(|c| if c.is_control() { '\u{fffd}' } else { c })
                    .collect();
                format!("“{safe}”")
            }
        };
        println!(
            "  block {:>8}  {:>14} zatoshi  {memo}",
            note.height, full.value
        );
    }

    if unspent.is_empty() {
        println!("\nNothing yet. Send this address some VRSCTEST and run it again.");
    }
    Ok(())
}
