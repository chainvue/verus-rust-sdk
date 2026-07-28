//! Generate a throwaway key and print its WIF and address.
//!
//!   cargo run -p verus-sdk --example keygen
//!
//! Entropy comes straight from the OS. This is an EXAMPLE: a real wallet should
//! not print a private key to stdout, and this crate deliberately offers no
//! `generate()` in the library — key generation belongs with the vault that will
//! store the result, not with the code that signs.

use std::fs::File;
use std::io::Read;

use verus_sdk::verus_keys::PrivateKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut entropy = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut entropy)?;

    let key = PrivateKey::from_bytes(&entropy, true)?;
    println!("wif     {}", *key.to_wif());
    println!("address {}", key.address());
    Ok(())
}
