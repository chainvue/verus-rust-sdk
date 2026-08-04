//! The offline half of an air-gapped wallet: it holds the key and nothing else.
//!
//! ```sh
//! # look at what you are being asked to sign, and stop
//! cargo run -p verus-sdk --example airgap_sign -- <blob>
//!
//! # sign it
//! VERUS_WIF=U… cargo run -p verus-sdk --example airgap_sign -- <blob> --sign
//! ```
//!
//! No `--features network`, on purpose. This program links no HTTP client — not
//! disabled, absent — so it can run on a machine with no network interface, and
//! `verus-rpc`'s `tests/offline_crates_stay_offline.rs` fails the build if that
//! ever changes. Its counterpart `airgap_watch` is the half that can reach a
//! node, and it never sees a key.
//!
//! # Signing is the irreversible step
//!
//! The transaction arriving here was assembled somewhere else, by something
//! this machine has no reason to trust — that is the entire premise of keeping
//! the key over here. The blob is untrusted input, and the only defence is
//! looking at it, which is why this prints the summary and **stops** unless
//! `--sign` is passed.
//!
//! The three things worth reading in that summary:
//!
//! 1. **Where the money goes.** Every output, with its address where there is
//!    one. `?` means a CryptoCondition this summary does not decode — pipe the
//!    blob through the `decode_tx` example before signing one of those.
//! 2. **The fee.** Reported as `fee and burn`, because from inside a
//!    transaction the two are the same thing: value that goes in and does not
//!    come out. An implausible number here is the cheapest sign of a malformed
//!    or hostile plan.
//! 3. **Whether the signature binds the outputs above.** Under `SIGHASH_ALL` it
//!    does. Under anything else it does not, and the holder of the partial can
//!    still move the money — see [`Summary::commits_to_all_outputs`].
//!
//! # What a real signer would add
//!
//! A confirmation the user types, rather than a flag; the amounts shown against
//! an address book; and the whole thing on a screen the online machine cannot
//! draw on. None of that is SDK work, which is why it is not here.

use std::io::Read;

use verus_sdk::cosign::PartialTransaction;
use verus_sdk::verus_keys::PrivateKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let sign = arguments.iter().any(|argument| argument == "--sign");
    let blob = match arguments
        .iter()
        .find(|argument| !argument.starts_with("--"))
    {
        Some(argument) => argument.clone(),
        None => {
            let mut buffer = String::new();
            std::io::stdin().read_to_string(&mut buffer)?;
            buffer
        }
    };

    let mut partial = PartialTransaction::from_bytes(&hex::decode(blob.trim())?)?;
    let summary = partial.summary()?;

    println!("you are being asked to sign:\n");
    println!("  in    {}", summary.total_in);
    println!("  out   {}", summary.total_out);
    println!("  fee and burn  {}", summary.fee_and_burn);
    println!("\n  outputs");
    for (value, address) in &summary.outputs {
        println!(
            "    {value:>16}  →  {}",
            match address {
                Some(address) => address.to_string(),
                None => "? — a CryptoCondition this summary does not decode".to_string(),
            }
        );
    }
    println!(
        "\n  inputs  {} ({} already signed)",
        partial.inputs.len(),
        summary
            .signatures_per_input
            .iter()
            .filter(|count| **count > 0)
            .count()
    );

    // The check that decides whether any of the above is binding.
    if summary.commits_to_all_outputs() {
        println!("  scope   SIGHASH_ALL — your signature commits to every output listed");
    } else {
        println!(
            "  scope   NOT SIGHASH_ALL ({:?}) — the outputs above are not what your \
             signature protects, and whoever holds this can still move the money",
            summary.hash_types
        );
    }

    if !sign {
        println!("\nnothing signed. Pass --sign once you have read the above.");
        return Ok(());
    }

    let key = PrivateKey::from_wif(&std::env::var("VERUS_WIF").map_err(|_| "set VERUS_WIF=U…")?)?;
    let signed = partial.sign(&key)?;
    if signed == 0 {
        // Not a warning to bury. `sign` adds a signature only to an input the
        // key actually owns, so zero means this plan spends someone else's
        // coins — a wrong key, or a plan built for a different wallet.
        return Err("that key owns none of the inputs in this transaction".into());
    }
    println!("\nsigned {signed} input(s).");

    if partial.is_complete() {
        // Only a hint: `is_complete` cannot know that a 2-of-3 condition needs
        // two signatures, because the threshold lives in an identity object
        // this transaction does not contain.
        println!("every input carries a signature; send this back to be broadcast:\n");
    } else {
        println!("some inputs still need signatures; pass this to the next signer:\n");
    }
    println!("{}", hex::encode(partial.to_bytes()?));
    Ok(())
}
