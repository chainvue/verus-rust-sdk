//! Drive the fourteen VerusPay invoices in `fixtures/vdxf/vectors.json` through
//! [`VerusPayInvoice`] **field by field**.
//!
//! `vdxf_vectors.rs` already drives all twenty vectors through the *frame* — the
//! twenty-byte key, the version VARINT, the length prefix, and the opaque
//! payload inside. Until this file existed that payload was `Vec<u8>` and an
//! amount, a flag word or a destination was indistinguishable from any other
//! byte. This is the half that reads it.
//!
//! # What the oracle is
//!
//! `VerusCoin/verus-typescript-primitives` at
//! `4243cd075b4f68df1ce72fd2fd9c9b18ac36767e`. Not daemon-proven and cannot be:
//! no RPC validates an invoice, because an invoice never reaches a validator —
//! it travels in a QR code and a deeplink. Agreeing with these bytes is what
//! makes a third-party wallet able to read an invoice this SDK writes, and that
//! is the whole claim. `fixtures/vdxf/README.md` says so at more length and
//! refuses to imply more.
//!
//! These are somebody else's bytes, which is the point. CONTRIBUTING: "a test
//! that only checks our own output against our own expectations proves nothing."
//!
//! # What is asserted, per invoice
//!
//! Every field of `details` the vector records, against the parsed structure:
//! the flag word and all ten booleans `flags_decoded` names, the amount, the
//! destination (its type byte, the address it spells as, and for the shielded
//! one the `zs…` address itself), the requested currency, the expiry height, the
//! slippage bound, and the accepted systems **in order**. Then `details_hex` and
//! `details_sha256` for the details alone; `serialized_version` including its
//! signed bit; `full_hex`, `qr_string`, `deeplink_payload_hex` and
//! `deeplink_uri` for the whole invoice; `system_id`, `signing_id` and the
//! signature bytes where there is one; and `details_hash_sigv1_h10000` /
//! `_sigv2_h10000` for the three signed invoices. Every vector also round-trips
//! from its own QR string and its own deeplink back to an equal value.
//!
//! # What is not, and why
//!
//! **`isTagged` and x-addresses.** There are deliberately no vectors — see
//! `fixtures/vdxf/README.md` — because an x-address has no
//! `verus_keys::AddressKind` variant, and widening that public enum is a
//! decision of its own. `VerusPayInvoiceDetails::deserialize` refuses a tagged
//! invoice rather than half-reading one, and `refuses_a_tagged_invoice` pins
//! that refusal.
//!
//! **The signature's validity.** Checking it needs the signing identity as it
//! stood at the signature's height, which needs a node; that lives with
//! `verify_login` in `verus-flows`. What is asserted here is the input to that
//! check — `getDetailsHash` at both signature versions — and the bytes the
//! signature travels as.

use verus_keys::{Address, AddressKind};
use verus_tx_primitives::cc::Destination;
use verus_tx_primitives::CurrencyId;
use verus_tx_protocol::vdxf::{keys, VdxfObject};
use verus_tx_protocol::veruspay::{
    InvoiceDestination, RequestedAmount, SignatureVersion, VerusPayInvoice, VerusPayInvoiceDetails,
    VerusPayVersion, FLAG_ACCEPTS_ANY_AMOUNT, FLAG_ACCEPTS_ANY_DESTINATION,
    FLAG_ACCEPTS_CONVERSION, FLAG_ACCEPTS_NON_VERUS_SYSTEMS,
    FLAG_DESTINATION_IS_SAPLING_PAYMENT_ADDRESS, FLAG_EXCLUDES_VERUS_BLOCKCHAIN, FLAG_EXPIRES,
    FLAG_IS_PRECONVERT, FLAG_IS_TAGGED, FLAG_IS_TESTNET, FLAG_VALID,
};

/// The whole fixture file, as the house pattern loads one.
fn fixture() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/vdxf/vectors.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("the vdxf fixture"))
        .expect("the vdxf fixture is json")
}

/// The invoice vectors, in file order.
fn invoices() -> Vec<serde_json::Value> {
    fixture()["vectors"]
        .as_array()
        .expect("a vectors array")
        .iter()
        .filter(|vector| vector["kind"].as_str() == Some("veruspay_invoice"))
        .cloned()
        .collect()
}

/// A vector's `name` and `why`, for a failure message.
///
/// `why` is the sentence the generator wrote about what the vector exists to
/// pin, so a failure says which property broke and not merely where.
fn label(vector: &serde_json::Value) -> String {
    format!(
        "{} — {}",
        vector["name"].as_str().expect("a name"),
        vector["why"].as_str().expect("a why")
    )
}

/// A decimal-string field as `u64`.
///
/// **Never `as_u64`, never `as_f64`.** Money and heights in this fixture are
/// `BN.toString(10)` output and are strings precisely so that nothing reading
/// them can route a value through a double. `"10000000000"` is a hundred coins
/// in satoshis, and it is already past where an `f64` stops being exact for the
/// arithmetic a wallet does next.
fn decimal(value: &serde_json::Value, what: &str) -> u64 {
    let text = value
        .as_str()
        .unwrap_or_else(|| panic!("{what} is a decimal string, got {value}"));
    text.parse()
        .unwrap_or_else(|error| panic!("{what} = {text:?}: {error}"))
}

/// The twenty bytes behind an `i` address, as a currency id.
fn currency(value: &serde_json::Value, what: &str) -> CurrencyId {
    let text = value
        .as_str()
        .unwrap_or_else(|| panic!("{what} is an address, got {value}"));
    CurrencyId::from_bytes(
        text.parse::<Address>()
            .unwrap_or_else(|error| panic!("{what} = {text:?}: {error}"))
            .hash(),
    )
}

/// RFC 4648 §4 base64 — the padded `+/` alphabet the `signature` fields use.
///
/// Written here rather than taken as a dependency because it is *not* what this
/// crate's `base64url` does, deliberately: that codec refuses `+`, `/` and `=`
/// so that one payload has one spelling. A signature is the one field in these
/// vectors carrying the other alphabet, it is test input rather than anything
/// the library parses, and what it produces is cross-checked against the payload
/// bytes in `every_signed_invoice_carries_the_signature_the_oracle_recorded` —
/// so a bug in these few lines cannot pass silently.
fn base64_standard(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut accumulator: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for byte in text.bytes().take_while(|byte| *byte != b'=') {
        let index = ALPHABET
            .iter()
            .position(|candidate| *candidate == byte)
            .and_then(|index| u32::try_from(index).ok())
            .unwrap_or_else(|| panic!("{text:?} is not standard base64 at {byte:?}"));
        accumulator = (accumulator << 6) | index;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((accumulator >> bits) & 0xff).expect("masked to eight bits"));
        }
    }
    out
}

/// A vector's `full_hex` as bytes.
fn full_hex(vector: &serde_json::Value) -> Vec<u8> {
    hex::decode(vector["full_hex"].as_str().expect("full_hex")).expect("full_hex is hex")
}

/// The invoice a vector describes, read back out of its own `full_hex`.
///
/// Reading rather than constructing is the direction that matters: these bytes
/// came from somewhere else, and the first thing a wallet does with an invoice
/// is parse one it did not write.
fn parse(vector: &serde_json::Value) -> VerusPayInvoice {
    let full = full_hex(vector);
    let mut offset = 0;
    let object = VdxfObject::deserialize(&full, &mut offset, None)
        .unwrap_or_else(|error| panic!("{}: the frame does not read: {error}", label(vector)));
    VerusPayInvoice::from_vdxf_object(&object)
        .unwrap_or_else(|error| panic!("{}: the invoice does not read: {error}", label(vector)))
}

/// `veruspay_version` as the enum.
fn version(vector: &serde_json::Value) -> VerusPayVersion {
    match decimal(&vector["veruspay_version"], "veruspay_version") {
        3 => VerusPayVersion::V3,
        4 => VerusPayVersion::V4,
        other => panic!("{}: unknown veruspay version {other}", label(vector)),
    }
}

/// The set this file was written against, so that a fixture which lost half its
/// invoices cannot pass every loop below by running over nothing.
#[test]
fn the_fixture_holds_the_fourteen_invoices_this_file_was_written_against() {
    let fixture = fixture();
    assert_eq!(
        fixture["primitives_commit"].as_str(),
        Some("4243cd075b4f68df1ce72fd2fd9c9b18ac36767e"),
        "the oracle revision named in this file's docs"
    );
    let invoices = invoices();
    assert_eq!(invoices.len(), 14, "every VerusPay invoice vector");

    let names: Vec<&str> = invoices
        .iter()
        .map(|vector| vector["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(
        names,
        vec![
            "invoice_v3_basic",
            "invoice_v3_any_amount_any_destination",
            "invoice_v3_accepts_conversion",
            "invoice_v3_accepts_conversion_expires",
            "invoice_v3_two_nonverus_systems_expires",
            "invoice_v3_signed_two_nonverus_systems_expires",
            "invoice_v4_basic",
            "invoice_v4_any_amount_any_destination",
            "invoice_v4_accepts_conversion",
            "invoice_v4_accepts_conversion_expires",
            "invoice_v4_two_nonverus_systems_expires",
            "invoice_v4_signed_two_nonverus_systems_expires",
            "invoice_v4_signed_sapling_destination",
            "invoice_v4_any_amount_any_destination_preconvert",
        ],
        "the six shared shapes across v3 and v4, plus the two v4-only ones"
    );
}

/// **The whole point.** Every field the oracle recorded is the field this crate
/// reads, and writing them back reproduces the bytes.
#[test]
fn every_invoice_reads_back_field_for_field_and_writes_back_byte_for_byte() {
    let mut failures = Vec::new();
    for vector in &invoices() {
        let name = label(vector);
        let invoice = parse(vector);
        let version = version(vector);
        let details = invoice.details();
        let recorded = &vector["details"];
        let mut check = |condition: bool, what: &str| {
            if !condition {
                failures.push(format!("{name}: {what}"));
            }
        };

        check(
            invoice.version() == version,
            "the version is not the vector's",
        );

        // The flag word, computed from the fields rather than stored beside
        // them — so this is the assertion that the derivation agrees with what
        // the oracle wrote.
        let flags = details
            .flags(version)
            .unwrap_or_else(|error| panic!("{name}: flags: {error}"));
        let expected_flags = decimal(&recorded["flags"], "details.flags");
        check(
            flags == expected_flags,
            &format!("flags derive to {flags} and the oracle wrote {expected_flags}"),
        );

        // All ten booleans, against the oracle's own decode of the same word.
        let decoded = &vector["flags_decoded"];
        for (key, bit) in [
            ("acceptsConversion", FLAG_ACCEPTS_CONVERSION),
            ("acceptsNonVerusSystems", FLAG_ACCEPTS_NON_VERUS_SYSTEMS),
            ("expires", FLAG_EXPIRES),
            ("acceptsAnyAmount", FLAG_ACCEPTS_ANY_AMOUNT),
            ("acceptsAnyDestination", FLAG_ACCEPTS_ANY_DESTINATION),
            ("excludesVerusBlockchain", FLAG_EXCLUDES_VERUS_BLOCKCHAIN),
            ("isTestnet", FLAG_IS_TESTNET),
            ("isPreconvert", FLAG_IS_PRECONVERT),
            (
                "destinationIsSaplingPaymentAddress",
                FLAG_DESTINATION_IS_SAPLING_PAYMENT_ADDRESS,
            ),
            ("isTagged", FLAG_IS_TAGGED),
        ] {
            let expected = decoded[key].as_bool().unwrap_or_else(|| {
                panic!(
                    "{name}: flags_decoded.{key} is a boolean, got {}",
                    decoded[key]
                )
            });
            check(
                (flags & bit != 0) == expected,
                &format!(
                    "flags_decoded.{key} is {expected} and the word says {}",
                    flags & bit != 0
                ),
            );
        }
        check(flags & FLAG_VALID != 0, "VERUSPAY_VALID is not set");

        // The amount. Absent means *absent*, not zero.
        match (&details.amount, recorded.get("amount")) {
            (RequestedAmount::Exact(amount), Some(expected)) => {
                let expected = decimal(expected, "details.amount");
                check(
                    *amount == expected,
                    &format!("the amount reads {amount} and the oracle wrote {expected}"),
                );
            }
            (RequestedAmount::Any, None) => {}
            (read, expected) => check(
                false,
                &format!("the amount reads {read:?} and the oracle wrote {expected:?}"),
            ),
        }

        // The destination, in all three shapes.
        match (&details.destination, recorded.get("destination")) {
            (InvoiceDestination::Any, None) => {}
            (InvoiceDestination::Transparent(destination), Some(expected)) => {
                let kind = expected["type"]
                    .as_u64()
                    .unwrap_or_else(|| panic!("{name}: details.destination.type is a number"));
                let read_type = match &destination.recipient {
                    Destination::PubKey(_) => 1,
                    Destination::PubKeyHash(_) => 2,
                    Destination::ScriptHash(_) => 3,
                    Destination::Identity(_) => 4,
                };
                check(
                    read_type == kind,
                    &format!("the destination type reads {read_type} and the oracle wrote {kind}"),
                );
                // The trap this resolves: nothing in the twenty bytes says `R`
                // or `i`. The type byte does, and `recipient_address` is where
                // it is read off.
                let spelled = details
                    .destination
                    .recipient_address()
                    .map(|address| address.to_string());
                let expected_address = expected["address"].as_str().map(str::to_owned);
                check(
                    spelled == expected_address,
                    &format!(
                        "the destination spells as {spelled:?} and the oracle wrote \
                         {expected_address:?}"
                    ),
                );
                check(
                    destination.auxiliary.is_empty() && destination.gateway.is_none(),
                    "the destination grew an auxiliary or a gateway leg",
                );
            }
            (InvoiceDestination::Sapling(sapling), Some(expected)) => {
                // The one vector whose destination is a string rather than an
                // object, and the one place this crate's forty-three opaque
                // bytes are checked against the address they name.
                let expected_address = expected.as_str().unwrap_or_else(|| {
                    panic!("{name}: a Sapling destination is recorded as a zs… string")
                });
                let encoded = verus_sapling::zaddr::encode(&sapling.to_bytes())
                    .unwrap_or_else(|error| panic!("{name}: the 43 bytes do not encode: {error}"));
                check(
                    encoded == expected_address,
                    &format!(
                        "the shielded destination is {encoded} and the oracle wrote \
                         {expected_address}"
                    ),
                );
                check(
                    verus_sapling::zaddr::decode(expected_address).ok() == Some(sapling.to_bytes()),
                    "the oracle's zs… address does not decode to the bytes on the wire",
                );
                check(
                    sapling.diversifier().len() == 11 && sapling.pk_d().len() == 32,
                    "a Sapling address is 11 bytes of diversifier and 32 of pk_d",
                );
            }
            (read, expected) => check(
                false,
                &format!("the destination reads {read:?} and the oracle wrote {expected:?}"),
            ),
        }

        let expected_currency = currency(&recorded["requestedcurrencyid"], "requestedcurrencyid");
        check(
            details.requested_currency == expected_currency,
            &format!(
                "the requested currency reads {} and the oracle wrote {expected_currency}",
                details.requested_currency
            ),
        );

        check(
            details.expiry_height
                == recorded
                    .get("expiryheight")
                    .map(|value| decimal(value, "expiryheight")),
            &format!(
                "the expiry height reads {:?} and the oracle wrote {:?}",
                details.expiry_height,
                recorded.get("expiryheight")
            ),
        );
        check(
            details.max_estimated_slippage
                == recorded
                    .get("maxestimatedslippage")
                    .map(|value| decimal(value, "maxestimatedslippage")),
            &format!(
                "the slippage bound reads {:?} and the oracle wrote {:?}",
                details.max_estimated_slippage,
                recorded.get("maxestimatedslippage")
            ),
        );

        // Order is on the wire, so this is a sequence comparison and not a set
        // one.
        let expected_systems: Vec<CurrencyId> = recorded
            .get("acceptedsystems")
            .and_then(|systems| systems.as_array())
            .map(|systems| {
                systems
                    .iter()
                    .map(|system| currency(system, "acceptedsystems[]"))
                    .collect()
            })
            .unwrap_or_default();
        check(
            details.accepted_systems == expected_systems,
            &format!(
                "the accepted systems read {:?} and the oracle wrote {expected_systems:?}",
                details.accepted_systems
            ),
        );

        // And back out again. `details_hex` is the details alone — the tail of a
        // signed invoice's payload and the whole of an unsigned one's.
        let details_hex = hex::encode(
            details
                .serialize(version)
                .unwrap_or_else(|error| panic!("{name}: the details do not serialize: {error}")),
        );
        let expected_details_hex = vector["details_hex"].as_str().expect("details_hex");
        check(
            details_hex == expected_details_hex,
            &format!("details_hex\n  wrote    {details_hex}\n  expected {expected_details_hex}"),
        );
        check(
            details.byte_length(version).ok() == Some(expected_details_hex.len() / 2),
            "byte_length does not predict what serialize writes",
        );
        let sha = hex::encode(
            details
                .sha256(version)
                .unwrap_or_else(|error| panic!("{name}: the details do not hash: {error}")),
        );
        let expected_sha = vector["details_sha256"].as_str().expect("details_sha256");
        check(
            sha == expected_sha,
            &format!("details_sha256\n  wrote    {sha}\n  expected {expected_sha}"),
        );

        // The whole invoice, through the frame.
        let expected_version = decimal(&vector["serialized_version"], "serialized_version");
        check(
            invoice.serialized_version() == expected_version,
            &format!(
                "the serialized version is {} and the oracle wrote {expected_version}",
                invoice.serialized_version()
            ),
        );
        let full = hex::encode(
            invoice
                .to_vdxf_object()
                .unwrap_or_else(|error| panic!("{name}: no frame: {error}"))
                .serialize(true),
        );
        let expected_full = vector["full_hex"].as_str().expect("full_hex");
        check(
            full == expected_full,
            &format!("full_hex\n  wrote    {full}\n  expected {expected_full}"),
        );
    }
    assert!(
        failures.is_empty(),
        "{} disagreements with the oracle across the 14 invoices:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The signed/unsigned distinction, which the type carries rather than a flag
/// beside it, and the three fields a signed invoice prepends.
#[test]
fn every_signed_invoice_carries_the_signature_the_oracle_recorded() {
    let mut signed = 0;
    let mut failures = Vec::new();
    for vector in &invoices() {
        let name = label(vector);
        let invoice = parse(vector);
        let is_signed = vector["signed"].as_bool().expect("a signed flag");

        if !is_signed {
            // The security-relevant half: an unsigned invoice must not be able
            // to present as one somebody vouched for.
            if invoice.is_signed() || invoice.signature().is_some() {
                failures.push(format!(
                    "{name}: reads as signed and the oracle says it is not"
                ));
            }
            continue;
        }
        signed += 1;

        let Some(signature) = invoice.signature() else {
            failures.push(format!(
                "{name}: the oracle says signed and this reads unsigned"
            ));
            continue;
        };
        let expected_system = currency(&vector["system_id"], "system_id");
        let expected_signing = vector["signing_id"].as_str().expect("signing_id");
        if signature.system_id != expected_system {
            failures.push(format!(
                "{name}: the system id reads {} and the oracle wrote {expected_system}",
                signature.system_id
            ));
        }
        // The signing id is an identity and is typed as twenty bytes rather than
        // a `CurrencyId`, so this is the assertion that `signing_identity()`
        // re-stamps them as the `i` address the oracle named — which is not a
        // guess, because the field decides the version and nothing on the wire
        // does.
        if signature.signing_identity().to_string() != expected_signing {
            failures.push(format!(
                "{name}: the signing id reads {} and the oracle wrote {expected_signing}",
                signature.signing_identity()
            ));
        }
        let expected_bytes = base64_standard(vector["signature"].as_str().expect("a signature"));
        if signature.signature != expected_bytes {
            failures.push(format!(
                "{name}: the signature bytes are {} and the oracle wrote {}",
                hex::encode(&signature.signature),
                hex::encode(&expected_bytes)
            ));
        }

        // The prefix accounts for exactly the bytes `details_hex` is not, which
        // is what makes the two claims together total.
        let full = full_hex(vector);
        let details_hex = vector["details_hex"].as_str().expect("details_hex");
        let mut offset = 0;
        let object = VdxfObject::deserialize(&full, &mut offset, None).expect("a frame");
        let prefix_len = object.data().len() - details_hex.len() / 2;
        if prefix_len != 20 + 20 + 1 + 1 + expected_bytes.len() {
            failures.push(format!(
                "{name}: the signed prefix is {prefix_len} bytes, not two hashes plus a keyless \
                 signature object over {} bytes",
                expected_bytes.len()
            ));
        }
        // Read straight off the payload: the two hashes come first, raw, and the
        // byte after them is the signature object's *version*. A twenty-byte key
        // there instead is the asymmetry the module documents — a signed invoice
        // omits it where a login-consent message writes it.
        if object.data()[40] != 1 {
            failures.push(format!(
                "{name}: byte 40 of the payload is {:#04x}, not the signature object's version — \
                 which means it is carrying its key",
                object.data()[40]
            ));
        }
        // And the signature bytes really are where the frame says.
        let at = 42;
        if object.data()[at..at + expected_bytes.len()] != expected_bytes[..] {
            failures.push(format!(
                "{name}: the signature does not sit at offset {at} of the payload"
            ));
        }
    }
    assert_eq!(signed, 3, "one signed v3 invoice and two signed v4 ones");
    assert!(
        failures.is_empty(),
        "{} signature disagreements:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// `getDetailsHash`, at both signature versions, for the three invoices that
/// have one.
///
/// **The argument pair matters.** Version 1 puts the Verus data-signature prefix
/// first and version 2 puts it after the signing id, so they are different
/// hashes of the same invoice — and both are reachable from a wallet, which is
/// why recording only the default would leave the one a verifier needs for an
/// older signature untested.
#[test]
fn the_details_hash_is_the_oracles_at_both_signature_versions() {
    let height = u32::try_from(
        fixture()["signed_blockheight"]
            .as_u64()
            .expect("the height the recorded hashes were taken at"),
    )
    .expect("a block height");
    assert_eq!(
        height, 10_000,
        "the height the field names are spelled with"
    );

    let mut seen = 0;
    let mut failures = Vec::new();
    for vector in &invoices() {
        if vector["details_hash_sigv2_h10000"].is_null() {
            continue;
        }
        seen += 1;
        let name = label(vector);
        let invoice = parse(vector);
        for (field, signature_version) in [
            ("details_hash_sigv1_h10000", SignatureVersion::V1),
            ("details_hash_sigv2_h10000", SignatureVersion::V2),
        ] {
            let expected = vector[field].as_str().expect("a hash");
            let computed = hex::encode(
                invoice
                    .details_hash(height, signature_version)
                    .unwrap_or_else(|error| panic!("{name}: {field}: {error}")),
            );
            if computed != expected {
                failures.push(format!(
                    "{name}: {field}\n  computed {computed}\n  expected {expected}"
                ));
            }
        }
        // The two are not the same hash, which is the reason both are recorded.
        if invoice.details_hash(height, SignatureVersion::V1).unwrap()
            == invoice.details_hash(height, SignatureVersion::V2).unwrap()
        {
            failures.push(format!("{name}: the two signature versions hash alike"));
        }
        // And the height is committed to, which is what stops a signature being
        // replayed at another height.
        if invoice.details_hash(height, SignatureVersion::V2).unwrap()
            == invoice
                .details_hash(height + 1, SignatureVersion::V2)
                .unwrap()
        {
            failures.push(format!("{name}: the height does not change the hash"));
        }
    }
    assert_eq!(seen, 3, "the signed invoices");
    assert!(
        failures.is_empty(),
        "{} details-hash disagreements:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The QR string and the deeplink, character for character, and back again.
///
/// The scheme is the lowercased vdxfid of `vrsc::applications.wallet` and the
/// payload is a **path segment**. `verus://x-callback-url/…` is a link Verus
/// Mobile routes to a different parser and rejects, so this crate offers no way
/// to compose one — which is why the assertion is on the whole string rather
/// than on a `contains`.
#[test]
fn every_qr_string_and_deeplink_is_what_this_crate_composes() {
    let mut failures = Vec::new();
    for vector in &invoices() {
        let name = label(vector);
        let invoice = parse(vector);

        let qr = vector["qr_string"].as_str().expect("a qr_string");
        let composed = invoice.to_qr_string().expect("a qr string");
        if composed != qr {
            failures.push(format!(
                "{name}: qr_string\n  wrote    {composed}\n  expected {qr}"
            ));
        }
        match VerusPayInvoice::from_qr_string(qr) {
            Ok(read) if read == invoice => {}
            Ok(_) => failures.push(format!(
                "{name}: the QR string reads back as a different invoice"
            )),
            Err(error) => {
                failures.push(format!("{name}: the QR string does not read back: {error}"));
            }
        }

        let uri = vector["deeplink_uri"].as_str().expect("a deeplink_uri");
        let composed = invoice.to_wallet_deeplink_uri().expect("a deeplink");
        if composed != uri {
            failures.push(format!(
                "{name}: deeplink_uri\n  wrote    {composed}\n  expected {uri}"
            ));
        }
        match VerusPayInvoice::from_wallet_deeplink_uri(uri) {
            Ok(read) if read == invoice => {}
            Ok(_) => failures.push(format!(
                "{name}: the deeplink reads back as a different invoice"
            )),
            Err(error) => {
                failures.push(format!("{name}: the deeplink does not read back: {error}"));
            }
        }

        // The deeplink payload is the frame **without** its key, because the
        // path already names it. Getting that the wrong way round is twenty
        // bytes of rubbish where the version belongs.
        let payload = vector["deeplink_payload_hex"].as_str().expect("a payload");
        let written = hex::encode(invoice.to_vdxf_object().expect("a frame").serialize(false));
        if written != payload {
            failures.push(format!(
                "{name}: deeplink_payload_hex\n  wrote    {written}\n  expected {payload}"
            ));
        }
        let full = vector["full_hex"].as_str().expect("full_hex");
        if payload != &full[40..] {
            failures.push(format!(
                "{name}: the deeplink payload is not full_hex minus its twenty-byte key"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} deeplink disagreements:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The v3/v4 pair: where the two encodings differ, and where they provably
/// cannot.
///
/// The six shared cases exist twice because the version changes the *encoding*
/// and not the fields: v3 writes its variable-length integers as Satoshi
/// VARINTs, v4 as Bitcoin CompactSizes. But the two agree byte for byte on any
/// value below `0x80` — a VARINT is one byte up to `0x7f`, a CompactSize up to
/// `0xfc` — so "the pair must differ" is false for an invoice whose every
/// variable-length integer is small, and `invoice_v3_any_amount_any_destination`
/// is exactly that: a flag word of 49 and nothing else, identical under both.
///
/// So the property asserted is the sharp one. The encodings agree **if and only
/// if** every variable-length integer in the invoice is below `0x80`, and where
/// they disagree the v3 bytes must not read as v4 into something that writes
/// back unchanged — a quiet wrong answer being the failure mode that matters for
/// a payment request.
#[test]
fn the_two_encodings_differ_exactly_where_a_value_crosses_0x80() {
    /// The values `writeVarUInt` handles. The accepted-systems *count* is not
    /// among them: upstream's `writeArray` is a CompactSize in both versions.
    fn var_uints(details: &VerusPayInvoiceDetails, version: VerusPayVersion) -> Vec<u64> {
        let mut values = vec![details.flags(version).expect("flags")];
        if let RequestedAmount::Exact(amount) = details.amount {
            values.push(amount);
        }
        values.extend(details.expiry_height);
        values.extend(details.max_estimated_slippage);
        values
    }

    let invoices = invoices();
    let mut pairs = 0;
    let mut identical = 0;
    for v3 in &invoices {
        let name = v3["name"].as_str().expect("a name");
        let Some(stem) = name.strip_prefix("invoice_v3_") else {
            continue;
        };
        let Some(v4) = invoices
            .iter()
            .find(|candidate| candidate["name"].as_str() == Some(&format!("invoice_v4_{stem}")))
        else {
            continue;
        };
        pairs += 1;

        // Same details, recorded twice.
        assert_eq!(
            v3["details"], v4["details"],
            "{name}: the pair must describe the same invoice"
        );

        let details = parse(v3).details().clone();
        let all_small = var_uints(&details, VerusPayVersion::V3)
            .iter()
            .all(|value| *value < 0x80);
        let same_bytes = v3["details_hex"] == v4["details_hex"];
        assert_eq!(
            same_bytes, all_small,
            "{name}: the encodings agree iff every variable-length integer is below 0x80"
        );
        if same_bytes {
            identical += 1;
            continue;
        }

        // Where they do differ, the v3 bytes must not read as v4 into something
        // that writes back unchanged: either the reader refuses, or what it
        // produces re-serializes differently and the mistake is visible.
        let bytes = hex::decode(v3["details_hex"].as_str().expect("hex")).expect("hex");
        let mut offset = 0;
        if let Ok(read) =
            VerusPayInvoiceDetails::deserialize(&bytes, &mut offset, VerusPayVersion::V4)
        {
            assert_ne!(
                read.serialize(VerusPayVersion::V4).ok().as_deref(),
                Some(bytes.as_slice()),
                "{name}: v3 bytes read as v4 and wrote back identically, which would mean the two \
                 encodings agree where the fixture says they do not"
            );
        }
    }
    assert_eq!(pairs, 6, "the six shapes recorded under both versions");
    assert_eq!(
        identical, 1,
        "only invoice_*_any_amount_any_destination has no integer above 0x7f"
    );
}

/// A tagged invoice is refused rather than half-read.
///
/// There are deliberately no tagged vectors — `fixtures/vdxf/README.md` says
/// why: an x-address has no `verus_keys::AddressKind` variant and widening that
/// public enum is a decision of its own. So the flag is set here on top of a
/// real vector's bytes, and what is pinned is the *refusal*: a
/// `CompactXAddressObject` follows the flag, the bytes after it cannot be
/// skipped without parsing it, and a partial answer about a payment request is
/// worse than an error.
#[test]
fn refuses_a_tagged_invoice() {
    let basic = invoices()
        .into_iter()
        .find(|vector| vector["name"].as_str() == Some("invoice_v4_basic"))
        .expect("invoice_v4_basic");
    let bytes = hex::decode(basic["details_hex"].as_str().expect("hex")).expect("hex");

    // It parses as it stands…
    let mut offset = 0;
    let details =
        VerusPayInvoiceDetails::deserialize(&bytes, &mut offset, VerusPayVersion::V4).unwrap();
    assert_eq!(offset, bytes.len());
    assert_eq!(details.flags(VerusPayVersion::V4).unwrap(), FLAG_VALID);

    // …and not with the tag bit set, whatever follows it.
    let mut tagged = Vec::new();
    verus_wire::compact::write_compact_size(&mut tagged, FLAG_VALID | FLAG_IS_TAGGED);
    tagged.extend_from_slice(&bytes[1..]);
    let mut offset = 0;
    assert!(
        VerusPayInvoiceDetails::deserialize(&tagged, &mut offset, VerusPayVersion::V4).is_err(),
        "a tagged invoice must be refused, not half-read"
    );
}

/// The key every invoice is addressed by, and the only one this crate will read.
///
/// `veruspay.vrsc::invoice` — under the **VerusPay identity's** namespace, not
/// the chain's. An object addressed by anything else is not an invoice, however
/// well its payload happens to parse.
#[test]
fn an_invoice_is_only_ever_addressed_by_the_veruspay_invoice_key() {
    for vector in &invoices() {
        let full = full_hex(vector);
        let mut offset = 0;
        let object = VdxfObject::deserialize(&full, &mut offset, None).expect("a frame");
        assert_eq!(
            object.key_address().to_string(),
            "iEETy7La3FTN2Sd2hNRgepek5S8x8eeUeQ",
            "{}",
            label(vector)
        );
        assert_eq!(object.key(), keys::VERUSPAY_INVOICE_VDXF_KEY);
    }

    // And a payload that would parse, under a key that is not the invoice's.
    let basic = invoices()
        .into_iter()
        .find(|vector| vector["name"].as_str() == Some("invoice_v4_basic"))
        .expect("invoice_v4_basic");
    let full = full_hex(&basic);
    let mut offset = 0;
    let object = VdxfObject::deserialize(&full, &mut offset, None).expect("a frame");
    assert!(VerusPayInvoice::from_vdxf_object(&object).is_ok());

    let elsewhere = VdxfObject::new(
        keys::LOGIN_CONSENT_REQUEST_VDXF_KEY,
        object.version(),
        object.data().to_vec(),
    );
    assert!(VerusPayInvoice::from_vdxf_object(&elsewhere).is_err());
    // The i-address rendering of that same wrong key, so the refusal is visibly
    // about the key and not about the payload.
    assert_eq!(
        Address::new(AddressKind::Identity, keys::LOGIN_CONSENT_REQUEST_VDXF_KEY).to_string(),
        "i3dQmgjq8L8XFGQUrs9Gpo8zvPWqs1KMtV"
    );
}
