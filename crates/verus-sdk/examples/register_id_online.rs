//! Register a VerusID, resumably. SPENDS REAL TESTNET COINS (100+ VRSCTEST).
//!
//!   VERUS_WIF=… cargo run -p verus-sdk --features network --example register_id_online -- myname
//!
//! Registration is two transactions with a confirmation between them, and the
//! first commits to a **salt that exists nowhere but in your process**. Crash
//! after broadcasting step 1 without persisting the salt and the commitment
//! fee is gone for good — the chain cannot give the salt back.
//!
//! So the flow is shaped to make the safe order the easy one:
//!
//! 1. `prepare_registration` builds step 1 and broadcasts NOTHING.
//! 2. The `Pending` — salt included — is serialized to disk.
//! 3. Only then is the commitment broadcast.
//! 4. A crash at any later point resumes from the file.
//!
//! The typestate makes the expensive mistake unrepresentable: step 2 is only
//! reachable through `CommitmentStatus::Ready`, so "register before the
//! commitment confirmed" — rejected by the chain *after* the fee is spent —
//! cannot be written.

use std::io::Write;
use std::time::Duration;

use verus_sdk::network::{
    prepare_registration, AwaitingCommitment, CommitmentStatus, HttpTransport, Pending,
    RegistrationOptions, RpcClient, WaitPolicy,
};
use verus_sdk::verus_keys::PrivateKey;

/// Persist durably AND atomically: write a temp file, `sync_all`, then rename
/// over the target.
///
/// Both halves matter. `sync_all` because a buffered write that has not reached
/// the disk is not on disk if power goes. The rename because truncating the
/// file in place opens a window where the ONLY copy of the salt is a
/// half-written file — fatal on the re-persist that happens *after* the
/// commitment fee is spent. A rename is atomic on POSIX: interrupted, the old
/// (still valid) state survives.
fn persist(path: &str, json: &str) -> std::io::Result<()> {
    let tmp = format!("{path}.tmp");
    let mut file = std::fs::File::create(&tmp)?;
    file.write_all(json.as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let name = std::env::args()
        .nth(1)
        .ok_or("usage: register_id_online <name>")?;
    let key = PrivateKey::from_wif(&std::env::var("VERUS_WIF").map_err(|_| "set VERUS_WIF")?)?;
    let node = RpcClient::new(HttpTransport::new(
        std::env::var("VERUS_ENDPOINT").unwrap_or_else(|_| "https://api.verustest.net".into()),
    )?);

    let state_file = format!("pending-{name}.json");

    // Resume if a previous run left a pending registration behind.
    let pending: Pending<AwaitingCommitment> = match std::fs::read_to_string(&state_file) {
        Ok(saved) => {
            println!("resuming from {state_file}");
            serde_json::from_str(&saved)?
        }
        Err(_) => {
            // Builds and signs step 1, reads the real fee from the chain, and
            // refuses a taken name — all before any money moves.
            let pending =
                prepare_registration(&node, &key, &name, &RegistrationOptions::default())?;
            println!(
                "prepared: commitment {} — fee will be {} VRSCTEST",
                pending.commitment_txid, pending.registration_fee
            );

            // THE step that must come before any broadcast.
            persist(&state_file, &serde_json::to_string_pretty(&pending)?)?;
            println!("salt persisted to {state_file}");

            let mut pending = pending;
            pending.broadcast_commitment(&node, &node)?;
            // Re-persist: broadcasting recorded a (height, hash) anchor used to
            // notice reorgs. A resume from the pre-broadcast file still works —
            // it only polls without reorg detection for that run.
            persist(&state_file, &serde_json::to_string_pretty(&pending)?)?;
            println!("commitment broadcast");
            pending
        }
    };

    // One RPC per poll, no hidden sleeps — `poll` alone suits a GUI loop.
    let progress = |attempt: u32, confirmations: u32| {
        println!("  waiting… poll {attempt}, {confirmations} confirmation(s)");
    };
    match pending.wait_blocking(
        &node,
        &WaitPolicy::new(Duration::from_secs(15), 40, Box::new(progress)),
    )? {
        CommitmentStatus::Ready(ready) => {
            let registered = ready.complete(&node, &node, &key)?;
            std::fs::remove_file(&state_file).ok();
            println!(
                "registered {}@ — txid {}, fee {} VRSCTEST",
                registered.name, registered.txid, registered.fee_paid
            );
        }
        CommitmentStatus::Waiting { confirmations } => {
            println!(
                "still unconfirmed ({confirmations}); state kept in {state_file} — rerun to resume"
            );
        }
        CommitmentStatus::Reorged { detail } => {
            println!(
                "a reorg made the anchor suspect ({detail}); rerun to re-poll from {state_file}"
            );
        }
        CommitmentStatus::CommitmentGone => {
            // The node has never seen it: the broadcast may not have happened
            // (a crash between persisting and broadcasting lands here), or it
            // was dropped from a mempool. The salt is still good and the bytes
            // can still be mined, so re-broadcasting is the right move — the
            // expired case is its own arm now, precisely because it is not.
            println!(
                "the node has never seen the commitment — rebroadcast from {state_file} \
                 (commitment_hex)"
            );
        }
        CommitmentStatus::Expired { expiry_height, tip } => {
            // The one arm that must not say "try again": the expiry is inside
            // the signed bytes, so every retry earns the same rejection.
            println!(
                "the commitment expired at block {expiry_height} and the chain is at {tip} — \
                 re-broadcasting cannot help, the expiry is inside the signed bytes. Delete \
                 {state_file} and start over; the commitment fee already paid is lost."
            );
        }
        // `CommitmentStatus` is `#[non_exhaustive]`, so a later version can name
        // a state this example predates. Keep the file and say nothing about
        // what to do — the arms above disagree with each other about exactly
        // that, and an example that guessed would be teaching the guess.
        other => {
            println!(
                "the commitment is in a state this example does not know ({other:?}); \
                 {state_file} is kept — do not delete it until you know which"
            );
        }
    }
    Ok(())
}
