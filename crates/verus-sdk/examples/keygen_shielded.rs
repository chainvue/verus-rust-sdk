//! Derive a shielded account from a BIP-39 seed on stdin.
//!
//! ```sh
//! cargo run -p verus-sdk --features shielded --example keygen_shielded <<< '{"seed_hex":"…"}'
//! ```
//!
//! The seed is the 64 bytes BIP-39 produces from a recovery phrase — this
//! example does not do PBKDF2, because turning a phrase into a seed is the
//! wallet's job and pasting a phrase into a shell is not something to make easy.
//!
//! Prints the `zs…` address and the viewing key. **The spending key is printed
//! too**, so redirect this to a file with restrictive permissions and treat it
//! the way you would treat any private key.
//!
//! Coin type defaults to 133, which is what a Verus Mobile wallet uses on
//! VRSCTEST as well as VRSC — see `verus_sapling::derive` for why.

use std::io::Read;

use serde_json::{json, Value};
use verus_sdk::verus_sapling::derive::{derive_account, COIN_TYPE_MAINNET};
use verus_sdk::verus_sapling::zaddr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let spec: Value = serde_json::from_str(&input)?;

    let seed = hex::decode(spec["seed_hex"].as_str().ok_or("spec.seed_hex")?)?;
    let coin_type = spec["coin_type"]
        .as_u64()
        .map_or(Ok(COIN_TYPE_MAINNET), u32::try_from)?;
    let account = spec["account"].as_u64().map_or(Ok(0), u32::try_from)?;

    let derived = derive_account(&seed, coin_type, account)?;
    println!(
        "{:#}",
        json!({
            "path": format!("m/32'/{coin_type}'/{account}'"),
            "address": zaddr::encode(&derived.address)?,
            "dfvk_hex": hex::encode(derived.dfvk),
            "extsk_hex": hex::encode(derived.extsk),
        })
    );
    Ok(())
}
