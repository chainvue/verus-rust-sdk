//! Reading a memo off a payment that is really on the chain.
//!
//! `fixtures/daemon/shielded_memo.json` is the two shielded outputs of
//! `2e2b04df1161e220f6a3dfd80abb821e15723f42fea05dec2dc451da5bcd27f5` — the z→z
//! in `PROVEN.md`, block 1173695 — exactly as `getrawtransaction` reports them.
//! Output 0 paid 0.5 VRSCTEST to a second account with the memo `sent by
//! verus-rust-sdk`; output 1 is the change back to the first.
//!
//! The viewing key committed alongside them is the receiving account's
//! **diversifiable full viewing key**. It can find and value that wallet's
//! notes and can spend nothing; the spending key was written outside the
//! repository. The wallet is empty regardless — that note was spent by
//! `f46ed415…`, which is also in `PROVEN.md`.
//!
//! What this pins is the thing a scan cannot do. Detection reads 52 compact
//! bytes: enough for a value and a position, not for a memo, which lives in the
//! 580-byte `encCiphertext`. Everything below is the difference.

use verus_sapling::scan::{dfvk_from_bytes, read_note, DiversifiableFullViewingKey, FullOutput};
use verus_sapling::VERUS_ZIP212;

fn fixture() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/daemon/shielded_memo.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("fixture is committed"))
        .expect("json")
}

fn viewing_key(fixture: &serde_json::Value) -> DiversifiableFullViewingKey {
    let bytes: [u8; 128] = hex::decode(fixture["dfvk_hex"].as_str().expect("a key"))
        .expect("hex")
        .try_into()
        .expect("128 bytes");
    dfvk_from_bytes(&bytes).expect("a viewing key")
}

/// A 32-byte field the daemon printed in display (reversed) order.
fn reversed32(text: &str) -> [u8; 32] {
    let mut bytes: [u8; 32] = hex::decode(text)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    bytes.reverse();
    bytes
}

fn output_at(fixture: &serde_json::Value, index: usize) -> FullOutput {
    let out = &fixture["vShieldedOutput"][index];
    FullOutput {
        cv: reversed32(out["cv"].as_str().expect("cv")),
        cmu: reversed32(out["cmu"].as_str().expect("cmu")),
        epk: reversed32(out["ephemeralKey"].as_str().expect("epk")),
        enc: hex::decode(out["encCiphertext"].as_str().expect("enc")).expect("hex"),
        ct: hex::decode(out["outCiphertext"].as_str().expect("ct")).expect("hex"),
        proof: hex::decode(out["proof"].as_str().expect("proof")).expect("hex"),
    }
}

/// The memo comes back, off a real payment.
#[test]
fn the_memo_on_a_real_payment_is_readable_with_a_viewing_key() {
    let fixture = fixture();
    let dfvk = viewing_key(&fixture);

    let read = read_note(&dfvk, &output_at(&fixture, 0), VERUS_ZIP212)
        .expect("decryption ran")
        .expect("output 0 is this wallet's");

    assert_eq!(
        read.value,
        fixture["expected_value_zatoshi"].as_u64().expect("a value")
    );

    // Trailing zeros are padding, not content — a memo compared without
    // trimming them matches nothing.
    let end = read.memo.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
    assert_eq!(
        core::str::from_utf8(&read.memo[..end]).expect("utf-8"),
        fixture["expected_memo"].as_str().expect("a memo")
    );
}

/// The other output of the same transaction is not this wallet's.
///
/// Without this the test above proves only that *something* decrypted. A
/// Sapling bundle's outputs are shuffled and one of these two is the sender's
/// change — trial decryption is the only thing that separates them, and it has
/// to say no as reliably as it says yes.
#[test]
fn the_change_output_does_not_decrypt_under_the_recipients_key() {
    let fixture = fixture();
    let dfvk = viewing_key(&fixture);

    assert!(
        read_note(&dfvk, &output_at(&fixture, 1), VERUS_ZIP212)
            .expect("decryption ran")
            .is_none(),
        "the sender's change decrypted under the recipient's key"
    );
}

/// And a stranger's key reads neither.
#[test]
fn another_wallet_reads_nothing_from_it() {
    let fixture = fixture();
    let stranger = verus_sapling::derive::derive_account(&[3u8; 64], 1, 0).expect("derivation");
    let dfvk = dfvk_from_bytes(&stranger.dfvk).expect("a viewing key");

    for index in 0..2 {
        assert!(
            read_note(&dfvk, &output_at(&fixture, index), VERUS_ZIP212)
                .expect("decryption ran")
                .is_none(),
            "output {index} decrypted under an unrelated key"
        );
    }
}

/// The address the note paid is the one the fixture names.
///
/// A memo attached to the wrong recipient would be a wallet showing a payment
/// it did not receive.
#[test]
fn it_names_the_address_that_was_paid() {
    let fixture = fixture();
    let read = read_note(
        &viewing_key(&fixture),
        &output_at(&fixture, 0),
        VERUS_ZIP212,
    )
    .expect("decryption ran")
    .expect("ours");

    assert_eq!(
        verus_sapling::zaddr::encode(&read.recipient).expect("an address"),
        fixture["address"].as_str().expect("an address")
    );
}

// --------------------------------------------------- what a memo field means

use verus_flows::Received;

fn with_memo(bytes: &[u8]) -> Received {
    let mut memo = [0u8; 512];
    memo[..bytes.len()].copy_from_slice(bytes);
    Received {
        value: 1,
        recipient: [0u8; 43],
        memo,
    }
}

/// Text, with the padding trimmed.
#[test]
fn a_text_memo_comes_back_without_its_padding() {
    assert_eq!(
        with_memo(b"sent by verus-rust-sdk").memo_text(),
        Some("sent by verus-rust-sdk")
    );
    // And the real one, from the fixture, through the same path.
    let fixture = fixture();
    let read = read_note(
        &viewing_key(&fixture),
        &output_at(&fixture, 0),
        VERUS_ZIP212,
    )
    .expect("decryption ran")
    .expect("ours");
    let received = Received {
        value: read.value,
        recipient: read.recipient,
        memo: read.memo,
    };
    assert_eq!(
        received.memo_text(),
        Some(fixture["expected_memo"].as_str().expect("a memo"))
    );
}

/// `0xF6` then zeros is ZIP-302 for "no memo" — which is not an empty string.
///
/// A wallet that rendered it as `""` would show an empty speech bubble on every
/// payment that carried nothing, which is a different claim from "this payment
/// had no message".
#[test]
fn no_memo_is_none_and_not_an_empty_string() {
    let mut memo = [0u8; 512];
    memo[0] = 0xf6;
    assert_eq!(with_memo(&memo[..1]).memo_text(), None);

    // An all-zero field — what a builder writes when nothing was asked for —
    // is text of length zero, which is the empty string.
    assert_eq!(with_memo(&[]).memo_text(), Some(""));
}

/// The reserved leading bytes are not text, and must not be rendered as if
/// they were.
#[test]
fn reserved_encodings_are_refused_rather_than_guessed() {
    for lead in [0xf5u8, 0xf7, 0xfe, 0xff] {
        assert_eq!(
            with_memo(&[lead, b'h', b'i']).memo_text(),
            None,
            "0x{lead:02x} is reserved and was rendered anyway"
        );
    }
    // 0xF4 is the last lead byte in the *text* class, so the boundary is where
    // it says. Spelled as a complete UTF-8 sequence (U+10FFFF) rather than a
    // bare 0xF4, which is an unfinished four-byte sequence and would be refused
    // by the UTF-8 check for an unrelated reason — proving nothing about where
    // the reserved range starts.
    assert_eq!(
        with_memo(&[0xf4, 0x8f, 0xbf, 0xbf]).memo_text(),
        Some("\u{10ffff}")
    );
}

/// Bytes that are not UTF-8 are not text either.
#[test]
fn invalid_utf8_is_not_rendered_lossily() {
    assert_eq!(with_memo(&[0x00, 0xff, 0xfe]).memo_text(), None);
}

/// A memo that fills the field has no padding to trim.
#[test]
fn a_full_length_memo_survives() {
    let full = vec![b'a'; 512];
    let received = with_memo(&full);
    assert_eq!(received.memo_text().expect("text").len(), 512);
}

// ------------------------------------------------ the join, driven end to end

use verus_flows::{received, FlowError};
use verus_light::{HttpResponse, LightClient, LightError, LightTransport};
use verus_sapling::scan::DetectedNote;

/// A light server that serves the fixture's transaction and a compact block
/// pointing at it.
///
/// Built rather than captured because `received` is a *join* — a block range to
/// find the transaction, then the transaction itself — and the point is to
/// exercise both halves plus the checks between them. The shielded outputs are
/// the real ones; only the framing around them is synthetic.
struct Server {
    raw_tx: Vec<u8>,
    block: Vec<u8>,
}

impl LightTransport for Server {
    fn call(&self, path: &str, _request: &[u8]) -> Result<HttpResponse, LightError> {
        let body = if path.ends_with("GetBlockRange") {
            self.block.clone()
        } else if path.ends_with("GetTransaction") {
            self.raw_tx.clone()
        } else {
            panic!("unexpected call to {path}")
        };
        Ok(HttpResponse { status: None, body })
    }
}

fn varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = u8::try_from(value & 0x7f).expect("7 bits");
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}
fn varint_field(out: &mut Vec<u8>, field: u32, value: u64) {
    varint(out, u64::from(field) << 3);
    varint(out, value);
}
fn bytes_field(out: &mut Vec<u8>, field: u32, value: &[u8]) {
    varint(out, (u64::from(field) << 3) | 2);
    varint(out, u64::try_from(value.len()).expect("a length"));
    out.extend_from_slice(value);
}
fn framed(messages: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for message in messages {
        out.push(0);
        out.extend_from_slice(
            &u32::try_from(message.len())
                .expect("a length")
                .to_be_bytes(),
        );
        out.extend_from_slice(message);
    }
    let trailer = "grpc-status: 0\r\n";
    out.push(0x80);
    out.extend_from_slice(
        &u32::try_from(trailer.len())
            .expect("a length")
            .to_be_bytes(),
    );
    out.extend_from_slice(trailer.as_bytes());
    out
}

/// The real transaction, rebuilt around the real outputs.
fn server(fixture: &serde_json::Value) -> (Server, DetectedNote, [u8; 32]) {
    let outputs: Vec<FullOutput> = (0..2).map(|i| output_at(fixture, i)).collect();

    let tx = verus_wire::TxV4 {
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        value_balance: 30_000,
        shielded_spends: Vec::new(),
        shielded_outputs: outputs
            .iter()
            .map(|o| {
                let mut bytes = Vec::with_capacity(948);
                bytes.extend_from_slice(&o.cv);
                bytes.extend_from_slice(&o.cmu);
                bytes.extend_from_slice(&o.epk);
                bytes.extend_from_slice(&o.enc);
                bytes.extend_from_slice(&o.ct);
                bytes.extend_from_slice(&o.proof);
                bytes
            })
            .collect(),
        binding_sig: Some([0u8; 64]),
    };
    let raw = tx.serialize().expect("serialize");
    let hash = tx.txid().expect("a txid");

    // A CompactBlock holding one transaction, whose compact outputs carry the
    // real commitments — which is what `full_output` checks the served
    // transaction against.
    let mut compact_tx = Vec::new();
    varint_field(&mut compact_tx, 1, 0); // index
    bytes_field(&mut compact_tx, 2, &hash); // hash
    for out in &outputs {
        let mut compact_out = Vec::new();
        bytes_field(&mut compact_out, 1, &out.cmu);
        bytes_field(&mut compact_out, 2, &out.epk);
        bytes_field(&mut compact_out, 3, &out.enc[..52]);
        bytes_field(&mut compact_tx, 5, &compact_out);
    }
    let mut block = Vec::new();
    varint_field(&mut block, 2, 1_173_695);
    bytes_field(&mut block, 3, &[1u8; 32]);
    bytes_field(&mut block, 4, &[0u8; 32]);
    bytes_field(&mut block, 7, &compact_tx);

    let mut raw_message = Vec::new();
    bytes_field(&mut raw_message, 1, &raw); // RawTransaction.data is field 1

    let note = DetectedNote {
        height: 1_173_695,
        tx_index: 0,
        output_index: 0,
        position: 3183,
        value: fixture["expected_value_zatoshi"].as_u64().expect("a value"),
        recipient: verus_sapling::zaddr::decode(fixture["address"].as_str().expect("an address"))
            .expect("an address"),
        nullifier: [0u8; 32],
    };

    (
        Server {
            raw_tx: framed(&[raw_message]),
            block: framed(&[block]),
        },
        note,
        hash,
    )
}

/// The whole join: fetch, decrypt, cross-check, return the memo.
///
/// Every other test here calls `read_note` directly, which left `received` —
/// the function a wallet actually calls — covered only by one live run.
#[test]
fn received_returns_the_value_and_the_memo() {
    let fixture = fixture();
    let (server, note, _) = server(&fixture);
    let dfvk = viewing_key(&fixture);

    let got = received(&LightClient::new(server), &dfvk, &note).expect("it is ours");

    assert_eq!(got.value, note.value);
    assert_eq!(
        got.memo_text(),
        Some(fixture["expected_memo"].as_str().expect("a memo"))
    );
    assert_eq!(got.recipient, note.recipient);
}

/// A note the key cannot read is a named refusal, not a panic or a zero.
#[test]
fn a_note_that_does_not_decrypt_is_refused_by_name() {
    let fixture = fixture();
    let (server, mut note, _) = server(&fixture);
    // Output 1 is the sender's change — real, and not this wallet's.
    note.output_index = 1;

    match received(&LightClient::new(server), &dfvk_of_a_stranger(), &note) {
        Err(FlowError::Shielded(text)) => assert!(text.contains("does not decrypt"), "{text}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn dfvk_of_a_stranger() -> DiversifiableFullViewingKey {
    let account = verus_sapling::derive::derive_account(&[5u8; 64], 1, 0).expect("derivation");
    dfvk_from_bytes(&account.dfvk).expect("a viewing key")
}

/// The value cross-check fires when the scan and the ciphertext disagree.
///
/// It cannot happen against an honest chain — both numbers are bound to the
/// note commitment — but the check exists so a future weakening of
/// `full_output` does not pass silently, and a check nothing exercises is a
/// check nobody knows works.
#[test]
fn a_value_that_disagrees_with_the_scan_is_refused() {
    let fixture = fixture();
    let (server, mut note, _) = server(&fixture);
    note.value += 1;

    match received(&LightClient::new(server), &viewing_key(&fixture), &note) {
        Err(FlowError::Shielded(text)) => assert!(text.contains("decrypts to"), "{text}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// And so does the recipient cross-check.
#[test]
fn a_recipient_that_disagrees_with_the_scan_is_refused() {
    let fixture = fixture();
    let (server, mut note, _) = server(&fixture);
    note.recipient[0] ^= 0xff;

    match received(&LightClient::new(server), &viewing_key(&fixture), &note) {
        Err(FlowError::Shielded(text)) => assert!(text.contains("different address"), "{text}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}
