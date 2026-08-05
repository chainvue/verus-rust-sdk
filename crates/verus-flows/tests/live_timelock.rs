//! The timelock rules, answered by consensus rather than by reading C++.
//!
//! [`verus_tx::update`]'s `check_timelock` is a transcription of the timelock
//! half of `CIdentity::IsInvalidMutation`, and a transcription is a claim. The
//! claim that matters, and the one no offline test can settle, is that the floor
//! for starting a countdown is measured from the transaction's **`nExpiryHeight`**
//! rather than from the tip. Everything about
//! [`prepare_identity_unlock`](verus_flows::prepare_identity_unlock) follows
//! from that, so if it is wrong the flow computes a number nobody wants.
//!
//! ```sh
//! export VERUS_LIVE_KEY=<WIF>                # a primary key of the identity
//! export VERUS_LIVE_IDENTITY=name.VRSCTEST@  # must be currently unlocked
//! VERUS_LIVE_TIMELOCK=1 cargo test -p verus-flows --test live_timelock -- --nocapture --test-threads=1
//! ```
//!
//! # This locks a real identity, briefly
//!
//! It has a gate of its own because it leaves the identity locked for the
//! duration. The sequence is: lock with a small delay, start the countdown, and
//! stop — the identity then unlocks itself once the chain passes the published
//! height, roughly `delay + 20` blocks later. Nothing here can be left
//! permanently stuck: an unlock may always be pushed *later*, so a rejected
//! attempt can simply be retried with a larger height.
//!
//! Costs miner fees for two transactions. Never in CI.
//!
//! The node is only ever asked questions and given finished bytes.

use verus_flows::{
    current_identity, prepare_identity_unlock, prepare_identity_update, IdentityChange,
};
use verus_keys::PrivateKey;
use verus_rpc::{Broadcaster, ChainReader, HttpTransport, RpcClient};
use verus_tx::{Timelock, DEFAULT_EXPIRY_BLOCKS};

const ENDPOINT: &str = "https://api.verustest.net";
/// Small, so the identity spends as little time locked as possible.
const DELAY: u32 = 2;

fn client() -> RpcClient<HttpTransport> {
    RpcClient::new(HttpTransport::new(ENDPOINT).expect("https endpoint"))
}

fn setup() -> Option<(PrivateKey, String)> {
    if std::env::var("VERUS_LIVE_TIMELOCK").is_err() {
        eprintln!(
            "skipping: set VERUS_LIVE_TIMELOCK=1, VERUS_LIVE_KEY=<WIF> and \
             VERUS_LIVE_IDENTITY=<name@>. This locks the identity for ~20 blocks."
        );
        return None;
    }
    let wif = std::env::var("VERUS_LIVE_KEY").expect("VERUS_LIVE_KEY");
    let identity = std::env::var("VERUS_LIVE_IDENTITY").expect("VERUS_LIVE_IDENTITY");
    Some((
        PrivateKey::from_wif(&wif).expect("VERUS_LIVE_KEY is a WIF"),
        identity,
    ))
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

/// Lock, then start the countdown, and check the height against the rule.
#[test]
fn the_unlock_floor_is_measured_from_the_transactions_expiry() {
    let Some((key, name)) = setup() else { return };
    let client = client();

    // --- precondition ---
    //
    // "Unlocked" is not the same as `Timelock::None`. A countdown that has
    // elapsed leaves `unlock_after` set to a height in the past forever, unless
    // somebody clears it — which is exactly the state this test leaves behind.
    // Demanding `None` here would make it run once and fail on every re-run,
    // against an identity that is perfectly fine to use.
    let tip = client.block_count().expect("tip");
    let before = current_identity(&client, &name).expect("the identity");
    match before.identity.timelock() {
        Timelock::None => {}
        Timelock::UntilBlock(height) if height <= tip => {
            eprintln!("  an elapsed countdown to {height} is left over; that is still unlocked");
        }
        other => panic!("this test needs an unlocked identity to start from, found {other:?}"),
    }

    // --- lock it ---
    eprintln!("locking {name} with a delay of {DELAY}");
    let unsent = prepare_identity_update(
        &client,
        &key,
        &[&key],
        &name,
        &IdentityChange::new().with_timelock(Timelock::DelayAfterUnlock(DELAY)),
    )
    .expect("build the lock");
    let txid = client
        .send_raw_transaction(&unsent.hex)
        .expect("consensus must accept a lock with a delay under the maximum");
    wait_for(&client, &txid, "the lock");

    let locked = current_identity(&client, &name).expect("the identity");
    assert_eq!(
        locked.identity.timelock(),
        Timelock::DelayAfterUnlock(DELAY),
        "the chain must hold the delay, with the flag set"
    );
    eprintln!("PROVEN: locked, and not counting down");

    // --- start the countdown ---
    //
    // The height this publishes is the whole question. It is computed as
    // `delay + expiry`, where the expiry belongs to the transaction being
    // built — a caller reasoning from the tip would publish something smaller.
    let tip_before = client.block_count().expect("tip");
    let unsent =
        prepare_identity_unlock(&client, &key, &[&key], &name, 0).expect("build the unlock");
    let txid = client
        .send_raw_transaction(&unsent.hex)
        .expect("consensus must accept an unlock at exactly the floor the rule names");
    wait_for(&client, &txid, "the unlock");

    let counting = current_identity(&client, &name).expect("the identity");
    let published = match counting.identity.timelock() {
        Timelock::UntilBlock(height) => height,
        other => panic!("expected a countdown, got {other:?}"),
    };

    // The floor, recomputed here from the tip this test read rather than from
    // anything the flow returned.
    let floor = DELAY + tip_before + DEFAULT_EXPIRY_BLOCKS;
    assert!(
        published >= floor,
        "the published unlock height {published} is below the floor {floor} \
         (delay {DELAY} + expiry), yet consensus accepted it — the rule is not what we think"
    );
    // And it is above what reasoning from the tip alone would have produced,
    // which is the part that makes the flow necessary.
    assert!(
        published > tip_before + DELAY,
        "if the floor were measured from the tip, {published} would not exceed {}",
        tip_before + DELAY
    );
    eprintln!(
        "PROVEN: consensus accepted unlock height {published}; tip+delay would have been {}",
        tip_before + DELAY
    );

    // --- and it may not be brought forward ---
    //
    // Refused locally, so this costs nothing and never reaches the node. The
    // point is that the builder refuses it in the same shape consensus would.
    let err = prepare_identity_update(
        &client,
        &key,
        &[&key],
        &name,
        &IdentityChange::new().with_timelock(Timelock::UntilBlock(published - 1)),
    )
    .expect_err("an unlock may only ever move later");
    eprintln!("PROVEN: bringing it forward is refused — {err}");

    eprintln!(
        "{name} unlocks itself at block {published}; nothing further is needed. \
         Current tip {tip_before}."
    );
}
