//! A real note's whole life, replayed from chain data.
//!
//! On 2026-07-29 this SDK generated a Sapling key, had 5 VRSCTEST shielded to it,
//! found the note through lightwalletd, witnessed it, proved a z→t spend and
//! broadcast it — every step through `verus-light`, `verus-flows` and
//! `verus-sapling`, with the key never leaving the process.
//!
//! ```text
//! funded   5af146d0583f535ece8518a1f3b7abaafae0b65155e4d05a90956367ecc91626  block 1167987
//! spent    8f9e0a6b1073349bd6f25433e617de3bd4826ab4afeae68b293d23d6e68a78c8  block 1167995
//! ```
//!
//! Both blocks are committed, so the whole lifecycle is a regression test that
//! runs offline on every push.
//!
//! # The key committed here is watch-only
//!
//! `DFVK` is a *diversifiable full viewing key*. It can find and value this
//! wallet's notes and can spend nothing — that needs the extended spending key,
//! which was written outside the repository and is not here. The address is
//! empty regardless: the note it once held is the one this test watches being
//! spent.

use verus_flows::scan;
use verus_light::{HttpResponse, LightClient, LightError, LightTransport};
use verus_sapling::scan::dfvk_from_bytes;

/// The watch-only key for the address that received the note.
const DFVK: &str = "549a3f248605a85c02f38a2a54ee7e44384b0b8f7a875fe5e99601dd3959b0e3\
                    2dcb8b5295047e9cccb092cd4553c15b1e230daa6cc96716e7b9604008eac528\
                    5a205bfb257a272d990607e45073be515724a4bc6456d6fb5d964fcc74ee3dff\
                    90ec3f14906942bb6f572090a83bb484320a9fe310cbba8cc58ccf878e57cd88";

const FUNDED_AT: u64 = 1_167_987;
const SPENT_AT: u64 = 1_167_995;
/// 5 VRSCTEST.
const VALUE: u64 = 500_000_000;

/// Serves the tree state, and whichever block-range fixture the test names.
///
/// The double must be honest about the range it was asked for: an earlier
/// version served all nine blocks whatever was requested, and `verus-light`'s
/// block-count check caught it — correctly, since a range that silently
/// contains more or fewer blocks than asked is exactly the failure that shifts
/// note positions.
struct Server(&'static str);

impl LightTransport for Server {
    fn call(&self, path: &str, _request: &[u8]) -> Result<HttpResponse, LightError> {
        let base = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/lightwalletd/");
        let name = if path.ends_with("GetTreeState") {
            "note_treestate_before.bin"
        } else if path.ends_with("GetBlockRange") {
            self.0
        } else {
            panic!("unexpected call to {path}")
        };
        Ok(HttpResponse {
            status: None,
            body: std::fs::read(format!("{base}{name}")).expect("fixture is committed"),
        })
    }
}

fn viewing_key() -> verus_sapling::scan::DiversifiableFullViewingKey {
    let bytes: [u8; 128] = hex::decode(DFVK.replace(char::is_whitespace, ""))
        .expect("hex")
        .try_into()
        .expect("128 bytes");
    dfvk_from_bytes(&bytes).expect("a viewing key")
}

/// The note is found, valued and positioned exactly as it was live.
///
/// Position 3176 is not reported by anything — it is counted, from the frontier
/// before block 1167987 plus every output in between. That it comes out right
/// here, from committed bytes, is what makes the count trustworthy.
#[test]
fn the_note_is_detected_at_the_position_it_really_had() {
    let client = LightClient::new(Server("note_blocks.bin"));
    let result = scan(&client, &viewing_key(), FUNDED_AT, SPENT_AT).unwrap();

    assert_eq!(result.notes.len(), 1, "exactly one note was ever paid here");
    let note = &result.notes[0];
    assert_eq!(note.height, FUNDED_AT);
    assert_eq!(note.value, VALUE);
    assert_eq!(note.position, 3176);
}

/// Detection alone would report five coins that are gone.
///
/// The nullifier of that same note appears in block 1167995, where this SDK
/// spent it. `balance` has to join the two, and a wallet that reports
/// `notes` without the join shows money it cannot spend.
#[test]
fn the_spent_note_is_worth_nothing() {
    let client = LightClient::new(Server("note_blocks.bin"));
    let result = scan(&client, &viewing_key(), FUNDED_AT, SPENT_AT).unwrap();

    // The note exists and is still detected...
    assert_eq!(result.notes.len(), 1);
    // ...and its nullifier is right there in the same range.
    assert!(result.nullifiers.contains(&result.notes[0].nullifier));

    assert!(result.unspent(&[]).is_empty());
    assert_eq!(result.balance(&[]), 0);
}

/// Scanning only up to the block before the spend must show it spendable —
/// otherwise the previous test would pass for the wrong reason.
#[test]
fn before_the_spend_the_note_was_spendable() {
    let client = LightClient::new(Server("note_blocks_before_spend.bin"));
    let result = scan(&client, &viewing_key(), FUNDED_AT, SPENT_AT - 1).unwrap();

    assert_eq!(result.unspent(&[]).len(), 1);
    assert_eq!(result.balance(&[]), VALUE);

    // And a wallet that scanned this range earlier, then learned the nullifier
    // from a later chunk, must still get zero.
    let nullifier = result.notes[0].nullifier;
    assert_eq!(result.balance(&[nullifier]), 0);
}

/// A different key must see nothing here — trial decryption is what separates
/// the wallets, and a scan that returned notes for any key would be worthless.
#[test]
fn another_wallet_sees_nothing() {
    let client = LightClient::new(Server("note_blocks.bin"));
    let stranger = verus_sapling::derive::derive_account(&[9u8; 64], 1, 0).unwrap();
    let dfvk = dfvk_from_bytes(&stranger.dfvk).unwrap();

    let result = scan(&client, &dfvk, FUNDED_AT, SPENT_AT).unwrap();
    assert!(result.notes.is_empty());
    // The nullifiers are public and still counted — they belong to whoever spent.
    assert!(!result.nullifiers.is_empty());
}
