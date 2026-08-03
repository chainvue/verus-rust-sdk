//! Generate a throwaway 24-word recovery phrase and the seed it maps to.
//!
//!   cargo run -p verus-sdk --example keygen_phrase
//!
//! Entropy comes straight from the OS. This is an EXAMPLE: a real wallet should
//! not print a recovery phrase to stdout, and it should show it once, to a
//! person, with the wallet's own warnings around it.
//!
//! # The entropy is the caller's, here as everywhere
//!
//! `verus-keys` has no RNG and this does not add one — the 32 bytes are read
//! here, in the application, exactly as `keygen` reads them for a transparent
//! key. Where they come from is the most security-critical decision a wallet
//! makes, and a library that quietly picked for you would move it somewhere
//! nobody reviews. A phrase from a weak source is not recoverable from later,
//! because it protects the wallet only for as long as nobody looks.
//!
//! `/dev/urandom` is a CSPRNG and it is **Unix-only** — this example does not
//! run on Windows, and a desktop wallet has to. The portable answer is the
//! `getrandom` crate (`getrandom::getrandom(&mut entropy)`) or `rand`'s
//! `OsRng`, both of which reach the same OS facility on every platform. The
//! file is opened directly here to keep the example dependency-free and to
//! make the source of the bytes impossible to miss.
//!
//! # Two key schedules, one phrase
//!
//! What comes out is a BIP-39 mnemonic, which is what the **shielded** side
//! needs: BIP-39 → ZIP-32 → a `zs…` address. The transparent side does not use
//! BIP-39 at all — it hashes the phrase text verbatim — so the same words drive
//! both, by different routes. `keygen_shielded` takes the seed printed below.

use std::fs::File;
use std::io::Read;

use verus_sdk::verus_keys::bip39::{mnemonic_from_entropy, mnemonic_to_seed};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut entropy = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut entropy)?;

    // 32 bytes is 256 bits, which is 24 words with an 8-bit checksum. There is
    // no length to choose and none to get wrong.
    let phrase = mnemonic_from_entropy(&entropy);

    // Verus wallets use no BIP-39 passphrase. It is a parameter rather than a
    // default because getting it wrong is undetectable: the seed is valid
    // either way and the wallet is simply empty.
    let seed = mnemonic_to_seed(&phrase, "")?;

    println!("phrase  {}", *phrase);
    println!("seed    {}", hex::encode(*seed));
    println!();
    println!("Feed the seed to keygen_shielded for the zs… address:");
    println!(
        "  cargo run -p verus-sdk --features shielded --example keygen_shielded \\\n    <<< '{{\"seed_hex\":\"{}\"}}'",
        hex::encode(*seed)
    );
    Ok(())
}
