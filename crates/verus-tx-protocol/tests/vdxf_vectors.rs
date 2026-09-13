//! Drive all 20 golden vectors in `fixtures/vdxf/vectors.json` through the VDXF
//! primitives.
//!
//! The vectors and the code landed as two separate pieces of work, and until
//! this file existed they never met: the primitives were proven against a single
//! invoice pasted into a unit test, and the vectors were 1057 lines of JSON
//! nothing read. What follows is the join.
//!
//! # What the oracle is
//!
//! `VerusCoin/verus-typescript-primitives` at
//! `4243cd075b4f68df1ce72fd2fd9c9b18ac36767e` — the deployed upstream
//! TypeScript implementation that real wallets interoperate with. It is **not**
//! daemon-proven and cannot be: no RPC validates a VerusPay invoice or a
//! login-consent request, because neither ever reaches a validator. They travel
//! in QR codes and `x-callback-url` deeplinks. So agreeing with these bytes is
//! what makes a third-party wallet able to read an invoice this SDK writes, and
//! that is the whole claim — see `fixtures/vdxf/README.md`, which says so at
//! more length and refuses to imply more.
//!
//! # What this file proves
//!
//! For every vector: that the twenty-byte key, the version VARINT, the
//! CompactSize length and the payload this crate reads out of `full_hex` are the
//! ones upstream put in, that writing them back reproduces `full_hex` byte for
//! byte, that `byte_length` predicted it, and that the base64url text in
//! `qr_string` and in the deeplink is character for character what this crate's
//! encoder emits. Where a vector is signed, that the payload opens with the
//! [`Hash160`]s of the identities it names and that the signature rides inside
//! as a nested object.
//!
//! # What it cannot prove yet, and therefore does not claim
//!
//! **No invoice field semantics.** `VerusPayInvoiceDetails`,
//! `LoginConsentRequest` and the rest are issues #196 and #195; until they
//! exist, `VdxfObject::data` is `Vec<u8>` and an amount, a flags word or a
//! destination is an opaque run of bytes here. The vectors record all of them
//! (`details.amount`, `flags_decoded`, `credentials[]`, …) and this file reads
//! none of those fields, because asserting on them would mean asserting against
//! a parser that does not exist.
//!
//! **No hashes.** `details_sha256`, `*_hash_sigv1_h10000` and
//! `*_hash_sigv2_h10000` are untouched. `getDetailsHash` is a payload method,
//! and the sha256 of a byte string this file already compares exactly adds
//! nothing about *this* crate — it would check the fixture against itself.
//!
//! **No signature bytes.** The `signature` fields are RFC 4648 §4 base64, the
//! padded `+/` alphabet — which is precisely what [`base64url`] refuses, on
//! purpose. Decoding one needs the other codec, so what is asserted here is the
//! *frame* the signature rides in, not its content.
//!
//! **Two keys are not asserted against a constant.** The provisioning request
//! and response vdxfids are outside the sixteen on-path keys `vdxf::keys`
//! declares, so for those two the key is checked against the vector's own
//! published i-address and nothing more. `isTagged` and x-addresses have no
//! vectors at all — that waits on a public-API decision about `AddressKind`.

use std::collections::BTreeSet;

use verus_keys::{Address, AddressKind};
use verus_tx_protocol::base64url;
use verus_tx_protocol::vdxf::keys;
use verus_tx_protocol::vdxf::object::DEFAULT_VERSION;
use verus_tx_protocol::vdxf::{Hash160, VdxfObject};

/// The signed bit `setSigned()` ORs into a VerusPay invoice's version.
///
/// The trap this guards is in `fixtures/vdxf/README.md`: the version field of a
/// signed v4 invoice is `2147483652`, and comparing that to 4 without masking
/// rejects a perfectly good invoice as an unsupported version.
const SIGNED_BIT: u64 = 0x8000_0000;

/// The whole fixture file, as the house pattern loads one.
fn fixture() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/vdxf/vectors.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("the vdxf fixture"))
        .expect("the vdxf fixture is json")
}

/// The vectors, in file order — which is the order the generator emitted and
/// therefore the order `fixtures/vdxf/README.md` tabulates.
fn vectors() -> Vec<serde_json::Value> {
    fixture()["vectors"]
        .as_array()
        .expect("a vectors array")
        .clone()
}

/// A vector's `name` and `why`, for a failure message.
///
/// Every assertion below carries this rather than a byte index. `why` is the
/// sentence the generator wrote about what the vector exists to pin, so a
/// failure says which property broke and not merely where.
fn label(vector: &serde_json::Value) -> String {
    format!(
        "{} — {}",
        vector["name"].as_str().expect("a name"),
        vector["why"].as_str().expect("a why")
    )
}

/// A hex field as bytes, naming the vector if it is not hex.
fn hex_field(vector: &serde_json::Value, field: &str) -> Vec<u8> {
    hex::decode(
        vector[field]
            .as_str()
            .unwrap_or_else(|| panic!("{}: {field} is hex", label(vector))),
    )
    .unwrap_or_else(|error| panic!("{}: {field} is hex: {error}", label(vector)))
}

/// A decimal-string field as `u64`.
///
/// **Never `as_u64`, never `as_f64`.** Money and heights in this fixture are
/// `BN.toString(10)` output and are strings in the JSON precisely so that
/// nothing reading them can route a value through a double. Versions are
/// strings for the same reason, and are read the same way so the rule has no
/// exception to forget.
fn decimal(vector: &serde_json::Value, field: &str) -> u64 {
    let text = vector[field]
        .as_str()
        .unwrap_or_else(|| panic!("{}: {field} is a decimal string", label(vector)));
    text.parse()
        .unwrap_or_else(|error| panic!("{}: {field} = {text:?}: {error}", label(vector)))
}

/// The key constant a vector's `kind` says it must carry, where this crate has
/// one.
///
/// `None` is not "unknown" — it is the two provisioning kinds, whose vdxfids are
/// outside the sixteen keys `vdxf::keys` declares. An unrecognised kind panics
/// rather than returning `None`, so a regenerated fixture that adds a shape
/// fails here instead of being silently skipped.
fn expected_key(vector: &serde_json::Value) -> Option<[u8; 20]> {
    match vector["kind"].as_str().expect("a kind") {
        "veruspay_invoice" => Some(keys::VERUSPAY_INVOICE_VDXF_KEY),
        "login_consent_request" => Some(keys::LOGIN_CONSENT_REQUEST_VDXF_KEY),
        "login_consent_response" => Some(keys::LOGIN_CONSENT_RESPONSE_VDXF_KEY),
        // `vrsc::identity.provisioning.{request,response}` upstream. Not in the
        // on-path set, so the key is checked against the vector's own i-address
        // and not against a constant this crate does not have.
        "provisioning_request" | "provisioning_response" => None,
        other => panic!("{}: unknown kind {other:?}", label(vector)),
    }
}

/// Read `full_hex` back through the frame, insisting it accounts for every byte.
///
/// `None` for the key because `full_hex` is always the top-level object, the one
/// that carries its own key.
fn object_of(vector: &serde_json::Value) -> (VdxfObject, Vec<u8>) {
    let full = hex_field(vector, "full_hex");
    let mut offset = 0;
    let object = VdxfObject::deserialize(&full, &mut offset, None).unwrap_or_else(|error| {
        panic!("{}: full_hex does not deserialize: {error}", label(vector))
    });
    assert_eq!(
        offset,
        full.len(),
        "{}: the frame left {} trailing bytes",
        label(vector),
        full.len() - offset
    );
    (object, full)
}

/// The set this file was written against.
///
/// Not ceremony. Every test below loops over whatever the file holds, so a
/// fixture that lost half its vectors — or that quietly changed the pin it
/// claims to record — would still pass each of them. This is the assertion that
/// the loops are running over the thing described above.
#[test]
fn the_fixture_is_the_pin_this_file_was_written_against() {
    let fixture = fixture();
    assert_eq!(
        fixture["primitives_commit"].as_str(),
        Some("4243cd075b4f68df1ce72fd2fd9c9b18ac36767e"),
        "the oracle revision named in this file's docs and in fixtures/vdxf/README.md"
    );
    // The one number in this file that is a JSON number rather than a decimal
    // string, because it is the generator's own metadata and not a value out of
    // a payload. Everything inside a vector goes through `decimal`.
    assert_eq!(
        fixture["signed_blockheight"].as_u64(),
        Some(10_000),
        "the height the recorded signature hashes were taken at"
    );

    let vectors = vectors();
    assert_eq!(vectors.len(), 20, "all the generated vectors");

    let mut kinds: Vec<&str> = vectors
        .iter()
        .map(|vector| vector["kind"].as_str().expect("a kind"))
        .collect();
    kinds.sort_unstable();
    let mut counts: Vec<(&str, usize)> = Vec::new();
    for kind in kinds {
        match counts.last_mut() {
            Some((seen, count)) if *seen == kind => *count += 1,
            _ => counts.push((kind, 1)),
        }
    }
    assert_eq!(
        counts,
        vec![
            ("login_consent_request", 1),
            ("login_consent_response", 3),
            ("provisioning_request", 1),
            ("provisioning_response", 1),
            ("veruspay_invoice", 14),
        ],
        "the shapes fixtures/vdxf/README.md tabulates"
    );

    // The v3/v4 pair is the one thing the fixture README says must survive any
    // regeneration, because dropping either half collapses the only difference
    // between the two versions — VARINT against CompactSize for the invoice's
    // own variable-length integers.
    let v3 = vectors
        .iter()
        .filter(|v| v["veruspay_version"].as_str() == Some("3"))
        .count();
    let v4 = vectors
        .iter()
        .filter(|v| v["veruspay_version"].as_str() == Some("4"))
        .count();
    assert_eq!((v3, v4), (6, 8), "six shared shapes, plus two v4-only ones");
}

/// **The whole point.** Every vector's `full_hex` reads back through the frame
/// and writes back out of it, byte for byte, with `byte_length` agreeing.
#[test]
fn every_vector_is_the_frame_these_primitives_write() {
    let mut failures = Vec::new();
    for vector in &vectors() {
        let (object, full) = object_of(vector);

        // The key, three ways: against the vector's own published i-address,
        // against the constant where this crate has one, and against the raw
        // twenty bytes at the head of the buffer.
        let vdxfkey = vector["vdxfkey"].as_str().expect("a vdxfkey");
        if object.key_address().to_string() != vdxfkey {
            failures.push(format!(
                "{}: the key reads as {} and the vector names {vdxfkey}",
                label(vector),
                object.key_address()
            ));
        }
        if let Some(expected) = expected_key(vector) {
            if object.key() != expected {
                failures.push(format!(
                    "{}: the key is not the keys::* constant for its kind\n  read     {}\n  constant {}",
                    label(vector),
                    hex::encode(object.key()),
                    hex::encode(expected)
                ));
            }
        }
        if object.key() != full[..20] {
            failures.push(format!(
                "{}: the key is not full_hex's first twenty bytes",
                label(vector)
            ));
        }

        // Writing it back. `include_key` is the only knob, and it shifts
        // everything after it by twenty bytes when it is wrong, so both
        // settings are checked against the slices they must produce.
        if object.serialize(true) != full {
            failures.push(format!(
                "{}: serialize(true) is not full_hex\n  wrote    {}\n  expected {}",
                label(vector),
                hex::encode(object.serialize(true)),
                hex::encode(&full)
            ));
        }
        if object.serialize(false) != full[20..] {
            failures.push(format!(
                "{}: serialize(false) is not full_hex without its key",
                label(vector)
            ));
        }
        if object.byte_length(true) != full.len() || object.byte_length(false) != full.len() - 20 {
            failures.push(format!(
                "{}: byte_length says {}/{} and the bytes are {}/{}",
                label(vector),
                object.byte_length(true),
                object.byte_length(false),
                full.len(),
                full.len() - 20
            ));
        }

        // The text round trip, independent of whether the vector records it:
        // these are the two calls a wallet makes, and `from_base64url` also
        // refuses trailing bytes, which `deserialize` alone does not.
        match VdxfObject::from_base64url(&object.to_base64url(true), None) {
            Ok(read) if read == object => {}
            Ok(_) => failures.push(format!(
                "{}: the base64url round trip changed it",
                label(vector)
            )),
            Err(error) => failures.push(format!(
                "{}: its own base64url does not read back: {error}",
                label(vector)
            )),
        }
    }
    assert!(
        failures.is_empty(),
        "{} disagreements with the frame across the 20 vectors:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The base64url text, character for character.
///
/// This is the assertion that makes the codec's deliberate strictness safe to
/// keep: every one of these strings was produced by upstream's *lenient*
/// encoder, and this decoder accepts all of them. A rejection here would mean
/// the two alphabets really do differ somewhere, and the answer would be to find
/// out where — not to loosen the decoder.
#[test]
fn every_qr_string_is_the_frame_through_this_crates_base64url() {
    let mut seen = 0;
    let mut failures = Vec::new();
    for vector in &vectors() {
        // Response vectors carry no `qr_string`: upstream's `Response` has no
        // `toQrString()` at all. Skipped per-vector rather than assumed away.
        let Some(qr) = vector["qr_string"].as_str() else {
            continue;
        };
        seen += 1;
        let (object, full) = object_of(vector);

        match base64url::decode(qr) {
            Ok(decoded) if decoded == full => {}
            Ok(decoded) => failures.push(format!(
                "{}: qr_string decodes to {} bytes, not full_hex's {}",
                label(vector),
                decoded.len(),
                full.len()
            )),
            Err(error) => {
                failures.push(format!("{}: qr_string is rejected: {error}", label(vector)));
            }
        }
        if base64url::encode(&full) != qr {
            failures.push(format!(
                "{}: encode(full_hex) is not qr_string\n  wrote    {}\n  expected {qr}",
                label(vector),
                base64url::encode(&full)
            ));
        }
        if object.to_base64url(true) != qr {
            failures.push(format!(
                "{}: to_base64url(true) is not qr_string",
                label(vector)
            ));
        }
        match VdxfObject::from_base64url(qr, None) {
            Ok(read) if read == object => {}
            Ok(_) => failures.push(format!(
                "{}: from_base64url(qr_string) is a different object",
                label(vector)
            )),
            Err(error) => failures.push(format!(
                "{}: from_base64url(qr_string) fails: {error}",
                label(vector)
            )),
        }
    }
    assert_eq!(
        seen, 15,
        "the fourteen invoices and the login-consent request"
    );
    assert!(
        failures.is_empty(),
        "{} disagreements across the {seen} vectors that carry a qr_string:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The deeplink: which half of the frame travels in it, and the exact text.
///
/// `include_key` is not a detail here — it is the difference between the two
/// kinds. An invoice's deeplink already names the key in its path, so the
/// payload omits it and has to be read back with `Some(key)`; a login-consent
/// request's payload is the whole object, key included, and reads back with
/// `None`. Getting the pair the wrong way round produces twenty bytes of
/// rubbish where the version belongs, which is exactly what this pins.
#[test]
fn the_deeplink_carries_the_frame_with_or_without_its_key() {
    // The URI scheme is the wallet application's own vdxfid, lowercased — which
    // ties `WALLET_VDXF_KEY` to text a wallet has to match on.
    let scheme = Address::new(AddressKind::Identity, keys::WALLET_VDXF_KEY)
        .to_string()
        .to_lowercase();

    let mut seen = 0;
    let mut failures = Vec::new();
    for vector in &vectors() {
        if vector["deeplink_payload_hex"].is_null() {
            continue;
        }
        seen += 1;
        let (object, full) = object_of(vector);
        let payload = hex_field(vector, "deeplink_payload_hex");
        let vdxfkey = vector["vdxfkey"].as_str().expect("a vdxfkey");
        let kind = vector["kind"].as_str().expect("a kind");

        // Which half, and the `Option<[u8; 20]>` that reads it back.
        let (include_key, expected, hint) = match kind {
            "veruspay_invoice" => (false, &full[20..], Some(object.key())),
            "login_consent_request" => (true, &full[..], None),
            other => panic!(
                "{}: kind {other:?} carries a deeplink and this test does not know its shape",
                label(vector)
            ),
        };
        if payload != expected {
            failures.push(format!(
                "{}: deeplink_payload_hex is not serialize({include_key})",
                label(vector)
            ));
        }
        if object.serialize(include_key) != payload {
            failures.push(format!(
                "{}: serialize({include_key}) is not deeplink_payload_hex",
                label(vector)
            ));
        }
        let encoded = base64url::encode(&payload);
        match VdxfObject::from_base64url(&encoded, hint) {
            Ok(read) if read == object => {}
            Ok(_) => failures.push(format!(
                "{}: the deeplink payload reads back as a different object",
                label(vector)
            )),
            Err(error) => failures.push(format!(
                "{}: the deeplink payload does not read back: {error}",
                label(vector)
            )),
        }

        // And the URI text itself, in two shapes. An invoice puts the payload in
        // the path; a request puts it in a query parameter named for the same
        // key. Both are asserted whole rather than by a `contains`, so a scheme
        // or a separator that moved is a failure.
        let Some(uri) = vector["deeplink_uri"].as_str() else {
            failures.push(format!(
                "{}: carries a deeplink payload and no deeplink_uri",
                label(vector)
            ));
            continue;
        };
        let expected_uri = match kind {
            "veruspay_invoice" => format!("{scheme}://x-callback-url/{vdxfkey}/{encoded}"),
            _ => format!("{scheme}://x-callback-url/{vdxfkey}/?{vdxfkey}={encoded}"),
        };
        if uri != expected_uri {
            failures.push(format!(
                "{}: the deeplink uri is not what this crate composes\n  expected {expected_uri}\n  vector   {uri}",
                label(vector)
            ));
        }
    }
    assert_eq!(
        seen, 15,
        "the fourteen invoices and the login-consent request"
    );
    assert!(
        failures.is_empty(),
        "{} disagreements across the {seen} deeplinks:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The version, and the masking trap.
///
/// Three statements per invoice, none of which alone is enough: the frame's
/// version is the `serialized_version` the oracle recorded, that number with its
/// top bit cleared is the invoice's declared `veruspay_version`, and the bit
/// itself is the vector's `signed` flag. A reader that forgot the mask passes
/// the first and fails the second.
#[test]
fn an_invoices_signed_flag_lives_in_the_top_bit_of_its_version() {
    let mut invoices = 0;
    let mut signed = 0;
    let mut failures = Vec::new();
    for vector in &vectors() {
        let (object, _) = object_of(vector);

        // Only the invoices carry a version of their own. For everything else
        // the frame version is upstream's `VDXFObject` constructor default,
        // which is a real cross-check of `DEFAULT_VERSION` rather than a
        // placeholder.
        if vector["serialized_version"].is_null() {
            if object.version() != DEFAULT_VERSION {
                failures.push(format!(
                    "{}: frame version {} is not the upstream default {DEFAULT_VERSION}",
                    label(vector),
                    object.version()
                ));
            }
            continue;
        }
        invoices += 1;

        let serialized = decimal(vector, "serialized_version");
        let declared = decimal(vector, "veruspay_version");
        let is_signed = vector["signed"].as_bool().expect("a signed flag");
        if is_signed {
            signed += 1;
        }

        if object.version() != serialized {
            failures.push(format!(
                "{}: the frame's version is {} and the oracle wrote {serialized}",
                label(vector),
                object.version()
            ));
        }
        if object.version() & !SIGNED_BIT != declared {
            failures.push(format!(
                "{}: masking the signed bit off {} gives {} and not {declared}",
                label(vector),
                object.version(),
                object.version() & !SIGNED_BIT
            ));
        }
        if (object.version() & SIGNED_BIT != 0) != is_signed {
            failures.push(format!(
                "{}: version {} says signed={} and the vector says {is_signed}",
                label(vector),
                object.version(),
                object.version() & SIGNED_BIT != 0
            ));
        }
    }
    assert_eq!(invoices, 14, "every vector with a veruspay version");
    assert_eq!(signed, 3, "the signed invoices, one v3 and two v4");
    assert!(
        failures.is_empty(),
        "{} version disagreements:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The payload the frame hands over is the details the oracle recorded.
///
/// Exactly, for an unsigned invoice. For a signed one `details_hex` is the
/// *tail* of the payload rather than all of it — the signed path prepends
/// `system_id`, `signing_id` and the signature — so the claim is a suffix, and
/// `every_signed_payload_opens_with_the_identities_it_names` accounts for the
/// rest of the bytes so that the two together are total.
#[test]
fn the_payload_is_the_details_the_oracle_recorded() {
    let mut seen = 0;
    let mut failures = Vec::new();
    for vector in &vectors() {
        if vector["details_hex"].is_null() {
            continue;
        }
        seen += 1;
        let (object, _) = object_of(vector);
        let details = hex_field(vector, "details_hex");
        let is_signed = vector["signed"].as_bool().expect("a signed flag");

        if is_signed {
            if !object.data().ends_with(&details) {
                failures.push(format!(
                    "{}: the payload does not end with details_hex",
                    label(vector)
                ));
            }
        } else if object.data() != details.as_slice() {
            failures.push(format!(
                "{}: the payload is not details_hex\n  read     {}\n  expected {}",
                label(vector),
                hex::encode(object.data()),
                hex::encode(&details)
            ));
        }
    }
    assert_eq!(seen, 14, "every invoice records its details separately");
    assert!(
        failures.is_empty(),
        "{} payload disagreements:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Every signed payload opens with fixed-length [`Hash160`]s of the identities
/// the vector names, followed by the signature as a nested object.
///
/// Two things worth a reader's attention, both read off these bytes rather than
/// assumed:
///
/// * The hashes are **not** varlength. A CompactSize length in front of each
///   would shift the signature by two bytes, and nothing in the bytes says
///   which form was used — the field layout decides, which is why
///   `Hash160::deserialize` takes `varlength` from the caller.
/// * The version byte is not serialized, so a hash read back cannot say whether
///   it was written as an `i` or an `R` address. The provisioning request's
///   `signing_address` is the one `R` address in these payloads and it comes
///   back as the `i` spelling of the same twenty bytes; the assertion says so
///   rather than hiding it, because the payload types will have to re-stamp the
///   version the way upstream's `ProvisioningRequest` does.
/// * Whether the signature carries its own key is **not uniform**. A signed
///   invoice writes the signature object without its key; a login-consent or
///   provisioning message writes it with `IDENTITY_AUTH_SIG_VDXF_KEY` in front.
///   Same signature, same version, twenty bytes apart — which is exactly the
///   mistake `VdxfObject::deserialize`'s third argument exists to let a caller
///   avoid, and it is load-bearing on a real format rather than hypothetical.
#[test]
fn every_signed_payload_opens_with_the_identities_it_names() {
    let mut seen = 0;
    let mut failures = Vec::new();
    for vector in &vectors() {
        let (object, _) = object_of(vector);
        let data = object.data();

        // The identity fields sit at the top level for an invoice and inside
        // `request`/`response` for the rest. A provisioning request names one
        // address and not two, and it is an R-address — a different version
        // byte in the same field position.
        let inner = if vector["request"].is_object() {
            &vector["request"]
        } else if vector["response"].is_object() {
            &vector["response"]
        } else {
            vector
        };
        let named = |field: &str| -> Option<String> {
            vector[field]
                .as_str()
                .or_else(|| inner[field].as_str())
                .map(str::to_owned)
        };
        let leading: Vec<String> = match (named("system_id"), named("signing_id")) {
            (Some(system), Some(signing)) => vec![system, signing],
            _ => match named("signing_address") {
                Some(address) => vec![address],
                // An unsigned invoice: no identity fields, nothing to check.
                None => continue,
            },
        };
        seen += 1;

        let mut offset = 0;
        let mut broke = false;
        for address in &leading {
            match Hash160::deserialize(data, &mut offset, false) {
                Ok(read) => {
                    // `from_address` is the writing half: what the vector names
                    // has to serialize back to the bytes just consumed.
                    let written = Hash160::from_address(address, false)
                        .expect("the vector names a valid address")
                        .serialize();
                    if written != data[offset - written.len()..offset] {
                        failures.push(format!(
                            "{}: from_address({address}) does not write the bytes at {}",
                            label(vector),
                            offset - written.len()
                        ));
                        broke = true;
                    }
                    if read.hash() != &written[..] {
                        failures.push(format!(
                            "{}: the payload's hash at {} is not {address}'s",
                            label(vector),
                            offset - written.len()
                        ));
                        broke = true;
                    }
                    // The version byte is **not on the wire**, so what a hash
                    // read back renders as is decided by the field layout and
                    // not by the bytes. Every `i` address therefore round-trips
                    // to itself, and the provisioning request's `R` address does
                    // not: `deserialize` hands back the `i` spelling of the same
                    // twenty bytes, exactly as upstream's `Hash160.fromBuffer`
                    // does before `ProvisioningRequest` re-stamps it with
                    // `R_ADDR_VERSION`. Pinned in both directions because a
                    // payload reader that forgets it shows a user the wrong
                    // address for the right key.
                    let rendered = read.to_address().map(|a| a.to_string());
                    let expected = if address.starts_with('i') {
                        Some(address.clone())
                    } else {
                        Some(
                            Address::new(
                                AddressKind::Identity,
                                written[..].try_into().expect("twenty bytes"),
                            )
                            .to_string(),
                        )
                    };
                    if rendered != expected {
                        failures.push(format!(
                            "{}: the hash at {} renders as {rendered:?} and not {expected:?}",
                            label(vector),
                            offset - written.len()
                        ));
                        broke = true;
                    }
                }
                Err(error) => {
                    failures.push(format!(
                        "{}: no hash160 for {address}: {error}",
                        label(vector)
                    ));
                    broke = true;
                }
            }
        }
        if broke {
            continue;
        }
        assert_eq!(
            offset,
            20 * leading.len(),
            "{}: a fixed-length hash160 is twenty bytes and nothing else",
            label(vector)
        );

        // The signature, as a nested object. An invoice omits its key.
        let keyed = vector["kind"].as_str() != Some("veruspay_invoice");
        let hint = if keyed {
            None
        } else {
            Some(keys::IDENTITY_AUTH_SIG_VDXF_KEY)
        };
        match VdxfObject::deserialize(data, &mut offset, hint) {
            Ok(signature) => {
                if signature.key() != keys::IDENTITY_AUTH_SIG_VDXF_KEY {
                    failures.push(format!(
                        "{}: the signature's key is {} and not identity.authentication.signature",
                        label(vector),
                        signature.key_address()
                    ));
                }
                if signature.version() != DEFAULT_VERSION {
                    failures.push(format!(
                        "{}: the signature object's version is {}",
                        label(vector),
                        signature.version()
                    ));
                }
                // Its payload is the signature's own bytes. They are not
                // compared to the vector's `signature` field, which is RFC 4648
                // §4 base64 and not this crate's codec — see the module docs.
                // What is checked is that the length the frame declared is the
                // length the recorded base64 would decode to, so a frame read
                // twenty bytes off cannot pass.
                let base64 = inner["signature"].as_str().expect("a signature");
                let expected =
                    base64.len() / 4 * 3 - base64.chars().rev().take_while(|c| *c == '=').count();
                if signature.data().len() != expected {
                    failures.push(format!(
                        "{}: the signature frame declares {} bytes and its base64 is {expected}",
                        label(vector),
                        signature.data().len()
                    ));
                }
                // And the nested object writes back exactly the slice it was
                // read from, which is the statement that `include_key` was
                // right — it is twenty bytes of difference.
                let start = 20 * leading.len();
                if signature.serialize(keyed) != data[start..offset] {
                    failures.push(format!(
                        "{}: the signature does not write back the bytes it was read from",
                        label(vector)
                    ));
                }
            }
            Err(error) => failures.push(format!(
                "{}: the signature object does not read back: {error}",
                label(vector)
            )),
        }

        // What remains is the payload proper. For an invoice that is exactly
        // `details_hex`, which closes the gap
        // `the_payload_is_the_details_the_oracle_recorded` left open for the
        // signed cases.
        if let Some(details) = vector["details_hex"].as_str() {
            let details = hex::decode(details).expect("hex");
            if data[offset..] != details {
                failures.push(format!(
                    "{}: the bytes after the signature are not details_hex",
                    label(vector)
                ));
            }
        }
    }
    assert_eq!(
        seen, 9,
        "three signed invoices, one login-consent request, three login-consent responses, and two \
         provisioning messages — the request among them naming a single R-address where the rest \
         name two i-addresses"
    );
    assert!(
        failures.is_empty(),
        "{} disagreements across the {seen} signed payloads:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Every address any vector names round-trips through [`Hash160`], in both the
/// shapes it can be written in.
///
/// Collected by walking the whole fixture for 34-character strings starting `i`
/// or `R` rather than from a list of field names: the vectors name addresses in
/// a dozen places — vdxf keys, salts, challenge ids, context keys, a signing
/// address, a destination — and a list would go stale the first time one moved.
/// Thirty distinct addresses come out, twenty-eight `i` and two `R`, and the
/// assertion on that count is what stops the walk from silently collecting
/// nothing.
#[test]
fn every_address_the_vectors_name_round_trips_through_hash160() {
    fn collect(value: &serde_json::Value, into: &mut BTreeSet<String>) {
        match value {
            serde_json::Value::String(text) if text.len() == 34 && text.starts_with(['i', 'R']) => {
                into.insert(text.clone());
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    collect(item, into);
                }
            }
            serde_json::Value::Object(fields) => {
                for field in fields.values() {
                    collect(field, into);
                }
            }
            _ => {}
        }
    }

    let mut addresses = BTreeSet::new();
    for vector in &vectors() {
        collect(vector, &mut addresses);
    }
    assert_eq!(
        addresses.len(),
        30,
        "the distinct addresses the vectors name"
    );
    assert_eq!(
        addresses.iter().filter(|a| a.starts_with('R')).count(),
        2,
        "the provisioning signing address, named twice"
    );

    let mut failures = Vec::new();
    for address in &addresses {
        let Ok(fixed) = Hash160::from_address(address, false) else {
            failures.push(format!("{address}: not an address this crate reads"));
            continue;
        };
        if fixed.to_address().map(|a| a.to_string()).as_deref() != Some(address.as_str()) {
            failures.push(format!(
                "{address}: round-trips to {:?}",
                fixed.to_address().map(|a| a.to_string())
            ));
            continue;
        }
        // Fixed length: twenty bytes, no prefix.
        if fixed.byte_length() != 20 || fixed.serialize().len() != 20 {
            failures.push(format!("{address}: a fixed hash160 is not twenty bytes"));
        }
        // Varlength: the same twenty bytes behind a CompactSize, which for
        // twenty is the single byte 0x14. Both forms appear in these payloads,
        // and the reader is told which rather than guessing.
        let varlength = Hash160::from_address(address, true).expect("the same address");
        let written = varlength.serialize();
        if written.len() != 21 || written[0] != 20 || written[1..] != *fixed.hash() {
            failures.push(format!(
                "{address}: varlength writes {}",
                hex::encode(&written)
            ));
        }
        let mut offset = 0;
        match Hash160::deserialize(&written, &mut offset, true) {
            Ok(read) if read.hash() == fixed.hash() && offset == 21 => {}
            Ok(_) => failures.push(format!("{address}: varlength does not read back")),
            Err(error) => failures.push(format!("{address}: varlength is rejected: {error}")),
        }
    }
    assert!(
        failures.is_empty(),
        "{} disagreements across the {} addresses:\n{}",
        failures.len(),
        addresses.len(),
        failures.join("\n")
    );
}
