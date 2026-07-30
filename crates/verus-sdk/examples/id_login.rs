//! Log in with a VerusID: sign a challenge, then verify it. Spends nothing.
//!
//!   VERUS_WIF=… cargo run -p verus-sdk --features network --example id_login -- myname@
//!
//! Both halves in one process, so it doubles as the round-trip check: a server
//! would run only `verify_login`, against a challenge it minted itself.
//!
//! The signature commits to the chain, the identity and the block height —
//! verification resolves the identity **as it stood at that height**, not at
//! the tip, so a later key rotation does not retroactively invalidate old
//! logins (and a revoked identity stops producing verifiable new ones).

use std::io::Read;

use verus_sdk::network::{
    sign_login, verify_login, HttpTransport, LoginPolicy, LoginRequest, RpcClient,
};
use verus_sdk::verus_keys::PrivateKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let identity = std::env::args()
        .nth(1)
        .ok_or("usage: id_login <identity>@")?;
    let key = PrivateKey::from_wif(&std::env::var("VERUS_WIF").map_err(|_| "set VERUS_WIF")?)?;
    let node = RpcClient::new(HttpTransport::new(
        std::env::var("VERUS_ENDPOINT").unwrap_or_else(|_| "https://api.verustest.net".into()),
    )?);

    // The server's side, part 1: mint an unpredictable, single-use challenge.
    // (A real server stores it and rejects a second presentation. /dev/urandom
    // keeps this example dependency-free on Unix — use your platform's RNG, or
    // the `getrandom` crate, where that path does not exist.)
    let mut entropy = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut entropy)?;
    let request = LoginRequest {
        audience: "https://example.com".into(),
        challenge: hex::encode(entropy),
    };
    println!("challenge:\n{}", request.message_text());

    // The wallet's side: sign it with a key the identity lists as primary.
    let signature = sign_login(&node, &key, &identity, &request)?;
    println!("signed at block height {}", signature.block_height);

    // The server's side, part 2: verify, with an explicit freshness policy.
    let login = verify_login(
        &node,
        &identity,
        &signature,
        &request,
        &LoginPolicy::default(),
    )?;
    let signers: Vec<String> = login.signers.iter().map(ToString::to_string).collect();
    println!(
        "verified: {} ({}) signed by {}",
        login.name,
        login.identity_address,
        signers.join(", ")
    );
    Ok(())
}
