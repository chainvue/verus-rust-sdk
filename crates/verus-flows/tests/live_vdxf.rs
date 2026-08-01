//! Publishing data on a VerusID, proven by the chain rather than by argument.
//!
//! Everything else about [`verus_flows::vdxf`] is checked against bytes we
//! produced ourselves: the unit tests decode the transaction `publish` would
//! broadcast and assert that another key on the same identity survives. That is
//! a good test and it cannot answer the question that matters.
//!
//! An identity update **republishes the identity in full**, and anything not
//! carried over is erased permanently. Whether our reconstruction is faithful
//! is a question about what consensus accepts and what the chain then holds —
//! so the only instance that can answer it is the chain.
//!
//! ```sh
//! export VERUS_LIVE_KEY=<WIF>              # a key that controls the identity
//! export VERUS_LIVE_IDENTITY=name.VRSCTEST@  # optional; registers one if absent
//! VERUS_LIVE_VDXF=1 cargo test -p verus-flows --test live_vdxf -- --nocapture --test-threads=1
//! ```
//!
//! Without `VERUS_LIVE_IDENTITY` this **registers an identity and spends the
//! 100 VRSCTEST fee**, which is why it has a gate of its own rather than riding
//! on `VERUS_LIVE_BROADCAST`. Pointing it at an identity you already control
//! costs only miner fees, and is how to re-run it. Never in CI.
//!
//! The node is only ever asked questions and given finished bytes. It is never
//! given a key.

use verus_flows::identity::{CommitmentStatus, RegistrationOptions, WaitPolicy};
use verus_flows::{prepare_registration, vdxf};
use verus_keys::PrivateKey;
use verus_rpc::{ChainReader, ContentValue, HttpTransport, RpcClient};

const ENDPOINT: &str = "https://api.verustest.net";

fn client() -> RpcClient<HttpTransport> {
    RpcClient::new(HttpTransport::new(ENDPOINT).expect("https endpoint"))
}

fn live_key() -> Option<PrivateKey> {
    if std::env::var("VERUS_LIVE_VDXF").is_err() {
        eprintln!("skipping: set VERUS_LIVE_VDXF=1 and VERUS_LIVE_KEY=<WIF> (spends 100 VRSCTEST)");
        return None;
    }
    let wif =
        std::env::var("VERUS_LIVE_KEY").expect("VERUS_LIVE_VDXF is set but VERUS_LIVE_KEY is not");
    Some(PrivateKey::from_wif(&wif).expect("VERUS_LIVE_KEY is not a valid WIF"))
}

/// Wait for a transaction to be mined, polling somebody else's node gently.
fn wait_for(client: &RpcClient<HttpTransport>, txid: &str, what: &str) {
    for attempt in 0..40 {
        match client.confirmations(txid) {
            Ok(Some(confirmations)) if confirmations >= 1 => {
                eprintln!("  {what} confirmed at {confirmations}");
                return;
            }
            Ok(_) => {}
            Err(e) => eprintln!("  {what}: {e}"),
        }
        if attempt % 4 == 0 {
            eprintln!("  waiting for {what} ({txid})");
        }
        std::thread::sleep(std::time::Duration::from_secs(15));
    }
    panic!("{what} never confirmed: {txid}");
}

/// The whole thing: register an identity, write a key, write a **second** key,
/// and check the first is still exactly as it was.
///
/// The second write is the proof. The first only shows that publishing works;
/// it is the second that exercises the invariant the module is built around,
/// because that update had to carry the first key over untouched while
/// restating the identity in full. If the reconstruction drops anything, this
/// is where it shows — on the chain's own copy, read back through a fresh
/// request.
#[test]
fn a_second_publish_does_not_erase_the_first() {
    let Some(key) = live_key() else { return };
    let client = client();
    let address = key.address().to_string();

    // Re-running should not cost another registration.
    let qualified = match std::env::var("VERUS_LIVE_IDENTITY") {
        Ok(existing) => {
            eprintln!("using the existing identity {existing}");
            existing
        }
        Err(_) => register_one(&client, &key, &address),
    };

    let record = client.identity(&qualified).expect("the identity");
    let identity_id: [u8; 20] = record
        .identity_address
        .parse::<verus_keys::Address>()
        .expect("identity address")
        .hash();

    proof(&client, &key, &address, &qualified, identity_id, &record);
}

/// Register a fresh identity, spending the fee.
fn register_one(client: &RpcClient<HttpTransport>, key: &PrivateKey, address: &str) -> String {
    let tip = client.block_count().expect("tip");
    let name = format!("vdxf{tip}");
    eprintln!("registering {name}@ from {address}");

    let prepared = prepare_registration(client, key, &name, &RegistrationOptions::default())
        .expect("prepare registration");
    eprintln!(
        "  fee {} read from chain policy",
        prepared.registration_fee.to_coins_string()
    );

    let pending = prepared
        .broadcast_commitment(client, client)
        .expect("broadcast commitment");

    let policy = WaitPolicy::new(
        std::time::Duration::from_secs(20),
        30,
        Box::new(|attempt, confirmations| {
            eprintln!("    poll {attempt}: {confirmations} confirmations");
        }),
    );
    let ready = match pending
        .wait_blocking(client, &policy)
        .expect("wait for the commitment")
    {
        CommitmentStatus::Ready(ready) => ready,
        other => panic!("commitment did not become registerable: {other:?}"),
    };

    let registered = ready
        .complete(client, client, key)
        .expect("broadcast registration");
    eprintln!("  registered {name}@ in {}", registered.txid);
    wait_for(client, &registered.txid, "registration");
    format!("{name}.VRSCTEST@")
}

/// Write two keys and check the first survives the second.
fn proof(
    client: &RpcClient<HttpTransport>,
    key: &PrivateKey,
    address: &str,
    qualified: &str,
    identity_id: [u8; 20],
    record: &verus_rpc::IdentityRecord,
) {
    // Two keys of our own, under our own identity's namespace. The names are
    // ours, so we know how to read the values back — which is the whole
    // arrangement the module describes.
    let ns = vdxf::Namespace::of_identity(identity_id, "VRSCTEST");
    let first_key = ns.key("proof.first").expect("derive");
    let second_key = ns.key("proof.second").expect("derive");
    assert_ne!(first_key, second_key);

    let first_value = b"first value, must survive".to_vec();
    let second_value = b"second value".to_vec();

    // --- write one ---
    let published = vdxf::publish(
        client,
        client,
        &[key],
        qualified,
        address,
        first_key,
        vec![first_value.clone()],
    )
    .expect("publish the first key");
    eprintln!("  published {} in {}", published.key, published.txid);
    wait_for(client, &published.txid, "first publish");

    let read_back = vdxf::read(client, qualified, first_key).expect("read the first key");
    assert_eq!(
        read_back,
        vec![ContentValue::Bytes(first_value.clone())],
        "the bytes must come back exactly as written"
    );

    // --- write two, which restates the identity including key one ---
    let published = vdxf::publish(
        client,
        client,
        &[key],
        qualified,
        address,
        second_key,
        vec![second_value.clone()],
    )
    .expect("publish the second key");
    eprintln!("  published {} in {}", published.key, published.txid);
    wait_for(client, &published.txid, "second publish");

    // The proof.
    let first_after = vdxf::read(client, qualified, first_key).expect("read the first key again");
    assert_eq!(
        first_after,
        vec![ContentValue::Bytes(first_value)],
        "the second update republished the identity and must have carried the first key over \
         untouched — this is the erase invariant, and only the chain can confirm it"
    );

    let second_after = vdxf::read(client, qualified, second_key).expect("read the second key");
    assert_eq!(second_after, vec![ContentValue::Bytes(second_value)]);

    // The distinction this test discovered, pinned so it cannot be forgotten.
    //
    // `getidentitycontent` accumulates across the chain's whole history, so a
    // key carried through a later update comes back once per update that
    // carried it. The first run of this test asserted the accumulating view
    // and failed with the value duplicated — the transaction was correct and
    // the reader was not.
    let history = vdxf::read_history(client, qualified, first_key).expect("read the history");
    assert!(
        history.len() > first_after.len(),
        "the accumulating view must show more than the current one: {} vs {}",
        history.len(),
        first_after.len()
    );
    assert!(
        history.iter().all(|v| *v == first_after[0]),
        "every historical entry is the same value, republished"
    );
    eprintln!(
        "  current holds {} value, history reports {}",
        first_after.len(),
        history.len()
    );

    // And nothing else appeared or vanished.
    let all = vdxf::read_all(client, qualified).expect("read everything");
    assert_eq!(
        all.len(),
        2,
        "exactly the two keys we wrote should be published: {all:?}"
    );

    // The authorities are the fields with no remedy if they are dropped.
    let after = client.identity(qualified).expect("the identity after");
    assert_eq!(
        after.identity["revocationauthority"], record.identity["revocationauthority"],
        "the revocation authority must survive two updates"
    );
    assert_eq!(
        after.identity["recoveryauthority"], record.identity["recoveryauthority"],
        "the recovery authority must survive two updates"
    );
    assert_eq!(
        after.identity["primaryaddresses"], record.identity["primaryaddresses"],
        "the primary addresses must survive two updates"
    );

    eprintln!("PROVEN: {qualified} holds both keys after two full republications");
}
