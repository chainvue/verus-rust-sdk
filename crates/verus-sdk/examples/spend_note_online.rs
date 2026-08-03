//! Spend a shielded note through the whole stack: scan → witness → prove →
//! broadcast.
//!
//! **This spends real testnet coins when `VERUS_SPEND_BROADCAST=1`.** Without
//! it the transaction is built, proved and printed, and nothing is sent.
//!
//! ```sh
//! export VERUS_SHIELDED_EXTSK=…      # 169-byte extended spending key, hex
//! export VERUS_SPEND_TO=zs1…         # or an R address, or a VerusID
//! export VERUS_SPEND_SATS=10000000   # zatoshi to deliver
//! export VERUS_SPEND_FEE=30000       # zatoshi to the miner — no estimator, see below
//! export VERUS_SCAN_FROM=1167000     # first block to look for notes in
//! export VERUS_SAPLING_PARAMS="$HOME/Library/Application Support/ZcashParams"
//!
//! cargo run --release -p verus-sdk --features light,prover,multicore \
//!     --example spend_note_online
//! ```
//!
//! `VERUS_LIGHT_ENDPOINT` (default `http://127.0.0.1:8080`) is a grpcwebproxy in
//! front of lightwalletd; `VERUS_RPC` (default `https://api.verustest.net`) is
//! an ordinary Verus daemon. **Both are needed, and that is the point.** The
//! light server supplies every input to the witness — the frontier, the
//! commitments, the tree sizes — so checking those against each other proves
//! only that the server is self-consistent. The daemon supplies the block
//! header's `finalsaplingroot`, which consensus fixed, and the flow refuses to
//! prove anything that does not match it.
//!
//! # Two things this example will not do for you
//!
//! **It will not estimate the fee.** `estimatefee` prices a transaction by
//! serialized size against a transparent fee-per-kilobyte, and a shielded
//! transaction's size is mostly Groth16 proof. Pick the fee deliberately.
//!
//! **It will not remember your notes.** The scan here starts from
//! `VERUS_SCAN_FROM` every run, which is fine for a demo and wrong for a
//! wallet: a real one persists `DetectedNote`s and the nullifiers it has seen,
//! and rescans only the tail. Note that a spend is reported through
//! `ShieldedSpent::nullifiers` precisely so the wallet can mark its own notes
//! spent without waiting to see them in a block.

use std::time::Instant;

use verus_sdk::light::{
    plan_spend, prove_spend, scan, GrpcWebTransport, LightClient, ShieldedRecipient, SpendRequest,
    TransparentRecipient,
};
use verus_sdk::network::{HttpTransport, RpcClient};
use verus_sdk::verus_keys::Address;
use verus_sdk::verus_sapling::params::SaplingParams;
use verus_sdk::verus_sapling::scan::dfvk_from_extsk;
use verus_sdk::verus_sapling::zaddr;

type Error = Box<dyn std::error::Error>;

fn env_or(name: &str, fallback: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| fallback.to_string())
}

fn main() -> Result<(), Error> {
    // Read, never printed. The 169 bytes below are the only thing in this
    // process that can move the money.
    let extsk = hex::decode(
        std::env::var("VERUS_SHIELDED_EXTSK")
            .map_err(|_| "set VERUS_SHIELDED_EXTSK to the 169-byte extended spending key, hex")?
            .trim(),
    )?;
    let to = std::env::var("VERUS_SPEND_TO").map_err(|_| "set VERUS_SPEND_TO")?;
    let amount: u64 = std::env::var("VERUS_SPEND_SATS")
        .map_err(|_| "set VERUS_SPEND_SATS")?
        .parse()?;
    let fee: u64 = std::env::var("VERUS_SPEND_FEE")
        .map_err(|_| "set VERUS_SPEND_FEE — nothing here will guess it")?
        .parse()?;
    let scan_from: u64 = std::env::var("VERUS_SCAN_FROM")
        .map_err(|_| "set VERUS_SCAN_FROM")?
        .parse()?;

    let light = LightClient::new(GrpcWebTransport::new(env_or(
        "VERUS_LIGHT_ENDPOINT",
        "http://127.0.0.1:8080",
    ))?);
    let node = RpcClient::new(HttpTransport::new(env_or(
        "VERUS_RPC",
        "https://api.verustest.net",
    ))?);

    let dfvk = dfvk_from_extsk(&extsk)?;
    let tip = light.latest_block()?.height;
    eprintln!("light server tip {tip}, scanning from {scan_from}");

    let found = scan(&light, &dfvk, scan_from, tip)?;
    // `unspent`, not `notes`: the second reports money already spent, and a
    // spend built from it is refused by the daemon after the prover has run.
    let unspent = found.unspent(&[]);
    eprintln!(
        "{} note(s) worth {} zatoshi",
        unspent.len(),
        found.balance(&[])
    );
    for note in &unspent {
        eprintln!("  block {:>8}  {:>14} zatoshi", note.height, note.value);
    }

    // One destination, either kind. A shielded spend pays both from the same
    // bundle; splitting them here only keeps the example readable.
    let (shielded_to, transparent_to) = if to.starts_with(zaddr::HRP) {
        (
            vec![ShieldedRecipient::with_memo(
                zaddr::decode(&to)?,
                amount,
                "sent by verus-rust-sdk",
            )?],
            Vec::new(),
        )
    } else {
        (
            Vec::new(),
            vec![TransparentRecipient {
                address: to.parse::<Address>()?,
                amount,
            }],
        )
    };

    // Plan first, and print it. Everything up to here is cheap; the proof after
    // it is tens of seconds per note, so a caller gets to see what it is about
    // to pay for — including the anchor, already checked against the daemon's
    // own block header.
    // Checked, because this is the number the plan sets change aside against.
    // Nothing downstream would be wrong if it wrapped — `prove_spend` refuses a
    // plan that does not balance — but the shape a wallet copies should be the
    // one that cannot.
    let needed = amount.checked_add(fee).ok_or("amount plus fee overflows")?;
    let plan = plan_spend(&light, &node, &unspent, needed, None)?;
    eprintln!(
        "spending {} note(s) at anchor {} (height {}), {} zatoshi change",
        plan.notes().len(),
        hex::encode(plan.anchor()),
        plan.anchor_height(),
        plan.change()
    );

    // Required rather than defaulted. The obvious default is a `~`-relative
    // path, and `File::open` does not expand `~` — so the fallback would be
    // dead code that fails as "no such file" on a path that looks correct.
    let dir = std::env::var("VERUS_SAPLING_PARAMS")
        .map_err(|_| "set VERUS_SAPLING_PARAMS to the directory holding sapling-spend.params")?;
    eprintln!("loading Sapling parameters from {dir} …");
    let params = SaplingParams::from_files(
        format!("{dir}/sapling-spend.params"),
        format!("{dir}/sapling-output.params"),
    )?;

    let started = Instant::now();
    // `prove_spend` rather than `prepare_spend`, because the plan above already
    // did the fetching. `prepare_spend` is the one-call form for a caller with
    // nothing to show in between.
    let unsent = prove_spend(
        &params,
        &plan,
        &SpendRequest {
            extsk: &extsk,
            notes: &unspent,
            shielded_to: &shielded_to,
            transparent_to: &transparent_to,
            fee,
            change_address: None,
            anchor_height: None,
            expiry: None,
        },
    )?;
    eprintln!("proved in {:.1}s", started.elapsed().as_secs_f64());
    println!("txid  {}", unsent.txid);
    println!("bytes {}", unsent.hex.len() / 2);
    println!("hex   {}", unsent.hex);

    if std::env::var("VERUS_SPEND_BROADCAST").as_deref() != Ok("1") {
        eprintln!("not broadcast — set VERUS_SPEND_BROADCAST=1 to send it");
        return Ok(());
    }

    // One send, outside the build, through the half that takes a broadcaster.
    // A failure here is ambiguous by nature: read `FlowError::BroadcastUncertain`
    // before resending anything.
    let sent = unsent.broadcast(&node)?;
    println!("accepted {}", sent.txid);
    println!("nullifiers now published:");
    for nullifier in &sent.nullifiers {
        println!("  {}", hex::encode(nullifier));
    }
    Ok(())
}
