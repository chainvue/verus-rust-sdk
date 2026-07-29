//! End to end against VRSCTEST, through the public node only.
//!
//! Everything else in this crate proves the flows are *internally* consistent
//! against a chain that was written down. This proves the chain agrees.
//!
//! **Opt-in, and it spends real testnet coins:**
//!
//! ```sh
//! export VERUS_LIVE_KEY=<WIF>          # a funded VRSCTEST key
//! VERUS_LIVE_BROADCAST=1 cargo test -p verus-flows --test live_flows -- --nocapture --test-threads=1
//! ```
//!
//! The key is read from the environment and **never** written to this repository
//! — the WIF committed in the other test files is public, so anything sent to it
//! can be swept by anyone.
//!
//! Never in CI. `VERUS_LIVE_BROADCAST` is a separate variable from the
//! `VERUS_LIVE_RPC` used for read-only drift checks precisely so that a
//! scheduled job cannot broadcast by accident.
//!
//! The node is only ever asked to answer questions and to relay finished bytes.
//! It is never given a key, and never asked to build or sign anything.

use verus_flows::{
    prepare_registration, prepare_send, send, sign_login, spendable, verify_login,
    CommitmentStatus, LoginPolicy, LoginRequest, RegistrationOptions, WaitPolicy,
};
use verus_keys::PrivateKey;
use verus_rpc::{ChainReader, HttpTransport, RpcClient};
use verus_tx::Amount;

const ENDPOINT: &str = "https://api.verustest.net";

fn client() -> RpcClient<HttpTransport> {
    RpcClient::new(HttpTransport::new(ENDPOINT).expect("https endpoint"))
}

/// The funded key, from the environment. Absent means these tests skip.
fn live_key() -> Option<PrivateKey> {
    if std::env::var("VERUS_LIVE_BROADCAST").is_err() {
        eprintln!("skipping: set VERUS_LIVE_BROADCAST=1 and VERUS_LIVE_KEY=<WIF>");
        return None;
    }
    let wif = std::env::var("VERUS_LIVE_KEY")
        .expect("VERUS_LIVE_BROADCAST is set but VERUS_LIVE_KEY is not");
    Some(PrivateKey::from_wif(&wif).expect("VERUS_LIVE_KEY is not a valid WIF"))
}

/// Read-only: what the flow layer sees when it looks at a real address.
///
/// Runs under the read-only gate too, since it broadcasts nothing.
#[test]
fn funding_lookup_agrees_with_the_chain() {
    if std::env::var("VERUS_LIVE_RPC").is_err() && std::env::var("VERUS_LIVE_BROADCAST").is_err() {
        eprintln!("skipping: set VERUS_LIVE_RPC=1");
        return;
    }
    let client = client();
    let address = "RJUgxvDnDLsRGCXNKDK56Rxngzh6m25J6F";

    let funding = spendable(&client, address).expect("funding lookup");
    let balance = client.address_balance(&[address]).expect("balance");

    eprintln!(
        "{address}: {} spendable across {} outputs, {} immature, balance {}",
        funding.total.to_coins_string(),
        funding.utxos.len(),
        funding.immature_total().to_coins_string(),
        balance.balance.to_coins_string()
    );

    // Spendable plus immature must account for the whole balance. A gap means
    // the maturity filter is dropping something it should not.
    let accounted = funding
        .total
        .checked_add(funding.immature_total())
        .expect("no overflow");
    assert_eq!(accounted, balance.balance);
    assert!(funding.tip > 1_000_000);
}

/// Build a real transaction against real UTXOs and let the daemon parse it —
/// without broadcasting. The strongest check available that costs nothing.
#[test]
fn a_prepared_payment_decodes_on_the_daemon() {
    let Some(key) = live_key() else { return };
    let client = client();

    let signed = prepare_send(
        &client,
        &key,
        &key.address().to_string(),
        Amount::from_sat(1_000_000),
    )
    .expect("prepare");

    let decoded = client
        .decode_raw_transaction(&signed.hex)
        .expect("decoderawtransaction");

    assert_eq!(decoded["txid"].as_str(), Some(signed.txid.as_str()));
    assert_eq!(decoded["version"].as_u64(), Some(4));

    // The expiry flows set from the tip, rather than the "never" every example
    // in this repository used to pass.
    let expiry = decoded["expiryheight"].as_u64().expect("expiryheight");
    let tip = u64::from(client.block_count().expect("tip"));
    assert!(expiry > tip, "expiry {expiry} is not ahead of tip {tip}");
    assert!(
        expiry <= tip + 21,
        "expiry {expiry} is further out than expected"
    );

    eprintln!(
        "prepared {} — {} outputs, expiry {expiry} (tip {tip}), nothing broadcast",
        signed.txid,
        decoded["vout"].as_array().map_or(0, Vec::len)
    );
}

/// The real thing: a payment that lands on chain.
///
/// Pays the funding key back to itself, so the only cost is the miner fee.
#[test]
fn a_payment_reaches_the_chain() {
    let Some(key) = live_key() else { return };
    let client = client();
    let address = key.address().to_string();

    let before = spendable(&client, &address).expect("funding");
    eprintln!(
        "before: {} spendable across {} outputs",
        before.total.to_coins_string(),
        before.utxos.len()
    );

    let sent = send(
        &client,
        &client,
        &key,
        &address,
        Amount::from_sat(1_000_000),
    )
    .expect("send");

    eprintln!(
        "broadcast {} — fee {}, change {}",
        sent.txid,
        sent.fee.to_coins_string(),
        sent.change.to_coins_string()
    );

    // The node accepted it, so it knows about it.
    let confirmations = client.confirmations(&sent.txid).expect("confirmations");
    assert!(
        confirmations.is_some(),
        "the node accepted {} but does not know it",
        sent.txid
    );
    eprintln!("node has it at {confirmations:?} confirmations");
}

/// The whole VerusID registration, through the public node.
///
/// This is the flow the typestate and the resumable `Pending` exist for, run
/// against a chain that will actually reject a mistake. It costs the
/// registration fee — 100 VRSCTEST — plus two miner fees.
///
/// The name is derived from the tip so repeated runs do not collide with an
/// identity this test registered earlier.
#[test]
fn a_verusid_registration_completes_on_chain() {
    let Some(key) = live_key() else { return };
    if std::env::var("VERUS_LIVE_REGISTER").is_err() {
        eprintln!("skipping: set VERUS_LIVE_REGISTER=1 (this spends the 100 VRSCTEST fee)");
        return;
    }
    let client = client();

    let tip = client.block_count().expect("tip");
    let name = format!("flow{tip}");
    eprintln!("registering {name}@");

    // Step 1, built and signed but NOT broadcast. The salt exists here.
    let prepared = prepare_registration(&client, &key, &name, &RegistrationOptions::default())
        .expect("prepare");
    eprintln!(
        "  prepared: fee {} read from chain policy, commitment {}",
        prepared.registration_fee.to_coins_string(),
        prepared.commitment_txid
    );

    // What a wallet must do before anything is spent: persist the salt.
    let persisted = serde_json::to_string(&prepared).expect("serialize");
    assert!(persisted.contains("salt"));

    let pending = prepared
        .broadcast_commitment(&client, &client)
        .expect("broadcast commitment");
    eprintln!("  commitment broadcast, waiting for a block");

    // Poll until it confirms. The interval is floored inside WaitPolicy; this
    // is somebody else's node.
    let policy = WaitPolicy::new(
        std::time::Duration::from_secs(20),
        30,
        Box::new(|attempt, confirmations| {
            eprintln!("    poll {attempt}: {confirmations} confirmations");
        }),
    );
    let ready = match pending.wait_blocking(&client, &policy).expect("wait") {
        CommitmentStatus::Ready(ready) => ready,
        other => panic!("commitment did not confirm: {other:?}"),
    };
    eprintln!("  commitment confirmed at vout {}", ready.commitment_vout);

    // Step 2, reachable only from a confirmed commitment.
    let registered = ready
        .complete(&client, &client, &key)
        .expect("registration");
    eprintln!(
        "  registration broadcast: {} (fee {})",
        registered.txid,
        registered.fee_paid.to_coins_string()
    );

    // And the chain agrees the identity exists.
    for attempt in 0..30 {
        std::thread::sleep(std::time::Duration::from_secs(20));
        match client.identity(&format!("{name}@")) {
            Ok(record) => {
                eprintln!(
                    "  {} exists at {} (block {})",
                    record.fully_qualified_name, record.identity_address, record.block_height
                );
                assert_eq!(record.fully_qualified_name, format!("{name}.VRSCTEST@"));
                assert!(!record.is_revoked());
                return;
            }
            Err(_) => eprintln!("    not visible yet ({attempt})"),
        }
    }
    panic!("{name}@ never appeared on chain");
}

/// The identity this session registered, whose primary key is the live one.
const OUR_IDENTITY: &str = "flow1167608@";

/// A signature we produce must be accepted by a Verus daemon, and a tampered
/// one must not.
///
/// The unit tests reproduce signatures the daemon made; this proves the other
/// direction, which is the one a "log in with VerusID" integration depends on.
/// Read-only — nothing is broadcast — but it needs the key that controls the
/// identity, so it runs under the broadcast gate.
#[test]
fn a_daemon_accepts_a_signature_we_produced() {
    let Some(key) = live_key() else { return };
    let client = client();

    let request = LoginRequest {
        audience: "https://example.invalid/login".into(),
        challenge: "b7f3c1a92e4d8006".into(),
    };

    let signature = sign_login(&client, &key, OUR_IDENTITY, &request).expect("sign");
    let encoded = signature.to_base64();
    eprintln!("signed at height {}: {encoded}", signature.block_height);

    // The message a verifier reconstructs from the same request.
    let message = request.message_text();

    assert!(
        client
            .verify_message(OUR_IDENTITY, &encoded, &message)
            .expect("verifymessage"),
        "the daemon rejected a signature we produced"
    );
    eprintln!("daemon accepted it");

    // And it must reject one over a different challenge.
    let other = LoginRequest {
        audience: request.audience.clone(),
        challenge: "0000000000000000".into(),
    };
    let other_message = other.message_text();
    assert!(
        !client
            .verify_message(OUR_IDENTITY, &encoded, &other_message)
            .expect("verifymessage"),
        "the daemon accepted a signature for a different challenge"
    );
    eprintln!("daemon rejected a tampered challenge");

    // Our own verifier must reach the same conclusion, against the identity as
    // it stood at the signature's height.
    let logged_in = verify_login(
        &client,
        OUR_IDENTITY,
        &signature,
        &request,
        &LoginPolicy::default(),
    )
    .expect("our own verification");
    assert_eq!(logged_in.name, "flow1167608.VRSCTEST@");
    assert_eq!(logged_in.signers, vec![key.address()]);
    eprintln!(
        "we verified it too: {} signed by {:?} at {}",
        logged_in.name, logged_in.signers, logged_in.signed_at
    );
}
