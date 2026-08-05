//! Who may change a VerusID's recovery authority, answered by consensus.
//!
//! The docs in [`verus_tx::update`] state the rule: each of the identity
//! output's three conditions guards its own fields, so `recovery_authority` can
//! only be changed by a transaction that satisfies the *recovery* condition. A
//! freshly registered identity is its own recovery authority, so its primary
//! keys satisfy that condition and can point it elsewhere; once it points at
//! somebody else, those same keys cannot move it back.
//!
//! Every word of that was read out of VerusCoin's `src/pbaas/identity.cpp`, and
//! reading source is not the same as being accepted by a node. Two things could
//! still be false: that this crate's fulfillment actually satisfies the recovery
//! condition in the self-authority case, and that the second half of the rule
//! bites at all. This test asks the chain.
//!
//! ```sh
//! export VERUS_LIVE_KEY=<WIF>                # a primary key of the identity
//! export VERUS_LIVE_IDENTITY=name.VRSCTEST@  # still its own recovery authority
//! export VERUS_LIVE_RECOVERY_TARGET=i...     # where recovery points afterwards
//! VERUS_LIVE_AUTHORITY=1 cargo test -p verus-flows --test live_authority -- --nocapture --test-threads=1
//! ```
//!
//! # This is one-way
//!
//! It has a gate of its own because it is not repeatable and not undoable. On
//! success the identity's recovery authority belongs to the target
//! **permanently** as far as this SDK is concerned: moving it back needs a
//! transaction signed as the recovery authority, which is a different eval code
//! and is not implemented here. Point it at an identity you control, or accept
//! that you are giving it away. Costs miner fees only. Never in CI.
//!
//! The node is only ever asked questions and given finished bytes. It is never
//! given a key.

use verus_flows::spendable;
use verus_keys::{Address, PrivateKey};
use verus_rpc::{Broadcaster, ChainReader, HttpTransport, RpcClient};
use verus_tx::update::{build_identity_update, UpdateParams};
use verus_tx::{
    decode_output_script, Amount, Expiry, Identity, OutputKind, Utxo, DEFAULT_EXPIRY_BLOCKS,
};

const ENDPOINT: &str = "https://api.verustest.net";

fn client() -> RpcClient<HttpTransport> {
    RpcClient::new(HttpTransport::new(ENDPOINT).expect("https endpoint"))
}

struct Setup {
    key: PrivateKey,
    identity: String,
    target: [u8; 20],
}

fn setup() -> Option<Setup> {
    if std::env::var("VERUS_LIVE_AUTHORITY").is_err() {
        eprintln!(
            "skipping: set VERUS_LIVE_AUTHORITY=1, VERUS_LIVE_KEY=<WIF>, \
             VERUS_LIVE_IDENTITY=<name@> and VERUS_LIVE_RECOVERY_TARGET=<i-address>. \
             This gives the recovery authority away permanently."
        );
        return None;
    }
    let wif = std::env::var("VERUS_LIVE_KEY").expect("VERUS_LIVE_KEY");
    let identity = std::env::var("VERUS_LIVE_IDENTITY").expect("VERUS_LIVE_IDENTITY");
    let target = std::env::var("VERUS_LIVE_RECOVERY_TARGET").expect("VERUS_LIVE_RECOVERY_TARGET");
    let target: Address = target.parse().expect("the target is an i-address");
    Some(Setup {
        key: PrivateKey::from_wif(&wif).expect("VERUS_LIVE_KEY is a WIF"),
        identity,
        target: target.hash(),
    })
}

/// Read the identity as consensus holds it — from its own output script, not
/// from `getidentity`'s rendering.
fn current(client: &RpcClient<HttpTransport>, name: &str) -> (Identity, Utxo) {
    let record = client.identity(name).expect("the identity");
    let (txid, vout) = record.outpoint;
    let raw = client
        .raw_transaction(&txid.to_display_hex())
        .expect("the transaction holding it");
    let hex = raw["vout"][vout as usize]["scriptPubKey"]["hex"]
        .as_str()
        .expect("the output script")
        .to_string();
    let script = hex::decode(&hex).expect("script hex");
    let identity = match decode_output_script(&script).expect("decode") {
        OutputKind::IdentityPrimary { identity } => *identity,
        other => panic!("not an identity output: {other:?}"),
    };
    let utxo = Utxo {
        txid,
        vout,
        satoshis: Amount::ZERO,
        script_pubkey: script,
    };
    (identity, utxo)
}

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

/// Sign an update that sets `recovery_authority` to `to`, and hand back the hex.
fn update_recovery_to(
    client: &RpcClient<HttpTransport>,
    key: &PrivateKey,
    name: &str,
    to: [u8; 20],
) -> String {
    let (mut identity, identity_output) = current(client, name);
    identity.recovery_authority = to;

    let address = key.address().to_string();
    let funding = spendable(client, &address).expect("funding");
    let signed = build_identity_update(
        key,
        &[key],
        &UpdateParams::new(
            &identity_output,
            &identity,
            &funding.utxos,
            address.parse::<Address>().expect("change address"),
            Expiry::within(funding.tip, DEFAULT_EXPIRY_BLOCKS),
        )
        .allowing_authority_change(),
    )
    .expect("the builder signs it — whether consensus agrees is the question");
    signed.hex
}

/// Both halves of the rule, in the order that makes the second one free.
#[test]
fn primary_keys_can_give_the_recovery_authority_away_but_cannot_take_it_back() {
    let Some(Setup {
        key,
        identity: name,
        target,
    }) = setup()
    else {
        return;
    };
    let client = client();

    // --- precondition: the identity is still its own recovery authority ---
    let (before, _) = current(&client, &name);
    let id = verus_tx::identity_id(&before.name, Some(before.parent));
    assert_eq!(
        before.recovery_authority, id,
        "this test only says anything on an identity that is still its own recovery authority"
    );
    assert_ne!(
        target, id,
        "pointing recovery back at itself would prove nothing"
    );
    eprintln!("{name} is its own recovery authority, as registered");

    // --- half one: the keys that are the recovery authority may move it ---
    let hex = update_recovery_to(&client, &key, &name, target);
    let txid = client
        .send_raw_transaction(&hex)
        .expect("consensus must accept an authority change signed by the authority itself");
    eprintln!("  broadcast {txid}");
    wait_for(&client, &txid, "the authority change");

    let (after, _) = current(&client, &name);
    assert_eq!(
        after.recovery_authority, target,
        "the chain must hold the new recovery authority"
    );
    assert_eq!(
        after.revocation_authority, before.revocation_authority,
        "nothing else about the authorities may have moved"
    );
    assert_eq!(
        after.primary_addresses, before.primary_addresses,
        "an update republishes the identity in full; the primary addresses must survive"
    );
    eprintln!("PROVEN: a self-authority identity can point recovery elsewhere after registration");

    // --- half two: the same keys may not move it again ---
    //
    // Free, because a transaction consensus rejects is never mined and costs
    // nothing. If this ever succeeds, the "no undo" half of the documented rule
    // is wrong and `allow_authority_change` is guarding much less than claimed.
    let hex = update_recovery_to(&client, &key, &name, id);
    match client.send_raw_transaction(&hex) {
        Err(e) => eprintln!("PROVEN: taking it back is refused — {e}"),
        Ok(txid) => panic!(
            "consensus accepted {txid}, which moved the recovery authority back to the identity \
             using only its primary keys. The rule documented in verus_tx::update is wrong."
        ),
    }
}
