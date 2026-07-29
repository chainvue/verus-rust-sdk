//! What a misbehaving, buggy or hostile light server can do to this client.
//!
//! Following the `verus-tx` decoder-robustness precedent: every case must be an
//! `Err`, and none may panic. A light client is exposed to whatever the server
//! feels like sending, and the consequences of believing it are a corrupt
//! witness or a wallet that reports the wrong balance.

use verus_light::{GrpcStatus, HttpResponse, LightClient, LightError, LightTransport};

/// A transport that answers with whatever it was constructed with.
struct Canned {
    status: Option<GrpcStatus>,
    body: Vec<u8>,
}

impl LightTransport for Canned {
    fn call(&self, _path: &str, _request: &[u8]) -> Result<HttpResponse, LightError> {
        Ok(HttpResponse {
            status: self.status.clone(),
            body: self.body.clone(),
        })
    }
}

fn with(status: Option<GrpcStatus>, body: Vec<u8>) -> LightClient<Canned> {
    LightClient::new(Canned { status, body })
}

/// Wrap a message in a grpc-web data frame.
fn frame(message: &[u8]) -> Vec<u8> {
    let mut out = vec![0];
    out.extend_from_slice(&u32::try_from(message.len()).unwrap().to_be_bytes());
    out.extend_from_slice(message);
    out
}

/// A grpc-web trailer frame.
fn trailer(text: &str) -> Vec<u8> {
    let mut out = vec![0x80];
    out.extend_from_slice(&u32::try_from(text.len()).unwrap().to_be_bytes());
    out.extend_from_slice(text.as_bytes());
    out
}

fn ok_status() -> Option<GrpcStatus> {
    Some(GrpcStatus {
        code: 0,
        message: String::new(),
    })
}

/// The failure this whole design exists to prevent.
///
/// lightwalletd reports an application error as a *trailers-only* response:
/// HTTP 200, an **empty body**, and `Grpc-Status` in the HTTP headers. Asking
/// for a range past the tip does exactly this — captured live, 2026-07-29.
///
/// A client that only parses trailer frames sees zero frames and reports zero
/// blocks. For `GetBlockRange` that is indistinguishable from "those blocks held
/// no shielded outputs", so a wallet would scan past its own notes and show a
/// balance of nothing, with no error anywhere.
#[test]
fn a_trailers_only_error_is_an_error_and_not_an_empty_range() {
    let client = with(
        Some(GrpcStatus {
            code: 2,
            message: "block requested is newer than latest block".into(),
        }),
        Vec::new(),
    );

    let err = client.block_range(9_000_000, 9_000_001).unwrap_err();
    match err {
        LightError::Status { code, ref message } => {
            assert_eq!(code, 2);
            assert!(message.contains("newer than latest block"), "{message}");
        }
        other => panic!("expected a status error, got {other:?}"),
    }
}

#[test]
fn a_body_with_no_status_anywhere_is_refused() {
    // Not an empty success: a response that never said it succeeded.
    let err = with(None, Vec::new()).latest_block().unwrap_err();
    assert!(matches!(err, LightError::Framing(_)), "{err:?}");
}

#[test]
fn a_trailer_frame_reporting_failure_is_an_error() {
    let body = trailer("grpc-status: 5\r\ngrpc-message: no such transaction\r\n");
    let err = with(None, body).transaction(&[0u8; 32]).unwrap_err();
    match err {
        LightError::Status { code, ref message } => {
            assert_eq!(code, 5);
            assert_eq!(message, "no such transaction");
        }
        other => panic!("expected a status error, got {other:?}"),
    }
}

/// The same proxy capitalises the header and lower-cases the trailer, in one
/// conversation. Matching case-sensitively would drop half of them.
#[test]
fn status_header_names_are_case_insensitive() {
    let body = trailer("Grpc-Status: 13\r\nGRPC-MESSAGE: internal\r\n");
    let err = with(None, body).latest_block().unwrap_err();
    assert!(
        matches!(err, LightError::Status { code: 13, .. }),
        "{err:?}"
    );
}

#[test]
fn a_truncated_frame_header_is_refused() {
    let mut body = frame(&[]);
    body.extend_from_slice(&[0x00, 0x00]); // two stray bytes, not a header
    let err = with(ok_status(), body).latest_block().unwrap_err();
    assert!(matches!(err, LightError::Framing(_)), "{err:?}");
}

#[test]
fn a_frame_claiming_more_than_it_carries_is_refused() {
    // Header says 1000 bytes; three follow.
    let body = vec![0x00, 0x00, 0x00, 0x03, 0xe8, 0x01, 0x02, 0x03];
    let err = with(ok_status(), body).latest_block().unwrap_err();
    assert!(matches!(err, LightError::Framing(_)), "{err:?}");
}

#[test]
fn a_varint_that_never_terminates_is_refused() {
    let message = vec![
        0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    let err = with(ok_status(), frame(&message))
        .latest_block()
        .unwrap_err();
    assert!(matches!(err, LightError::Protobuf(_)), "{err:?}");
}

#[test]
fn a_proto2_group_is_refused_rather_than_skipped() {
    // Field 9, wire type 3 (start group) — removed in proto3. Skipping it
    // blindly would desynchronise the reader against the rest of the message.
    let err = with(ok_status(), frame(&[(9 << 3) | 3]))
        .latest_block()
        .unwrap_err();
    assert!(matches!(err, LightError::Protobuf(_)), "{err:?}");
}

#[test]
fn a_hash_of_the_wrong_length_is_refused_at_the_boundary() {
    // BlockID.hash (field 2) with 31 bytes instead of 32.
    let mut message = vec![(2 << 3) | 2, 31];
    message.extend_from_slice(&[0xab; 31]);
    let err = with(ok_status(), frame(&message))
        .latest_block()
        .unwrap_err();
    match err {
        LightError::Protobuf(ref text) => assert!(text.contains("31 bytes"), "{text}"),
        other => panic!("expected a protobuf error, got {other:?}"),
    }
}

/// `proto3` requires unknown fields to be ignored, and lightwalletd forks do add
/// them — `chainMetadata` arrived as field 8 long after the original seven.
/// Erroring would break this client against a newer server for no reason.
#[test]
fn an_unknown_field_is_skipped() {
    let mut message = vec![(1 << 3), 0x2a]; // height = 42
    message.extend_from_slice(&[(99 << 3) | 2, 3, 1, 2, 3]); // unknown, length-delimited
    message.extend_from_slice(&[(100 << 3), 0x07]); // unknown, varint
    let mut with_hash = message.clone();
    with_hash.push((2 << 3) | 2);
    with_hash.push(32);
    with_hash.extend_from_slice(&[0u8; 32]);

    let tip = with(ok_status(), frame(&with_hash)).latest_block().unwrap();
    assert_eq!(tip.height, 42);
}

#[test]
fn a_gap_in_a_block_range_is_refused() {
    /// A CompactBlock carrying only its height.
    fn block(height: u64) -> Vec<u8> {
        let mut out = vec![2 << 3];
        let mut value = height;
        loop {
            let byte = u8::try_from(value & 0x7f).unwrap();
            value >>= 7;
            if value == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        out
    }

    // Asked for 100..=102, served 100, 102, 103 — the server skipped one.
    let mut body = frame(&block(100));
    body.extend_from_slice(&frame(&block(102)));
    body.extend_from_slice(&frame(&block(103)));
    body.extend_from_slice(&trailer("grpc-status: 0\r\n"));

    let err = with(None, body).block_range(100, 102).unwrap_err();
    match err {
        LightError::Protobuf(ref text) => assert!(text.contains("expected block 101"), "{text}"),
        other => panic!("expected a protobuf error, got {other:?}"),
    }
}

#[test]
fn a_short_block_range_is_refused() {
    let body = [frame(&[2 << 3, 100]), trailer("grpc-status: 0\r\n")].concat();
    // Asked for two blocks, served one. Silently accepting it would report the
    // missing block as free of shielded activity.
    let err = with(None, body).block_range(100, 101).unwrap_err();
    match err {
        LightError::Protobuf(ref text) => assert!(text.contains("asked for 2 blocks"), "{text}"),
        other => panic!("expected a protobuf error, got {other:?}"),
    }
}

#[test]
fn an_absurd_block_range_is_refused_before_it_is_sent() {
    let client = with(ok_status(), Vec::new());

    let err = client.block_range(200, 100).unwrap_err();
    assert!(matches!(err, LightError::Refused(_)), "{err:?}");

    let err = client
        .block_range(0, verus_light::MAX_BLOCK_RANGE + 1)
        .unwrap_err();
    match err {
        LightError::Refused(ref text) => assert!(text.contains("split the range"), "{text}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_failed_send_is_an_error_even_though_the_call_succeeded() {
    // SendResponse { errorCode: -26, errorMessage: "16: mempool min fee not met" }
    // A non-zero code inside a perfectly successful gRPC call: the transaction
    // was rejected, and returning Ok here would report it as broadcast.
    let mut message = vec![1 << 3];
    // -26 as a proto3 int32: sign-extended to 64 bits, so ten varint bytes.
    let widened = u64::from((-26i32).cast_unsigned()) | 0xffff_ffff_0000_0000;
    let mut value = widened;
    loop {
        let byte = u8::try_from(value & 0x7f).unwrap();
        value >>= 7;
        if value == 0 {
            message.push(byte);
            break;
        }
        message.push(byte | 0x80);
    }
    let text = b"16: mempool min fee not met";
    message.push((2 << 3) | 2);
    message.push(u8::try_from(text.len()).unwrap());
    message.extend_from_slice(text);

    let err = with(ok_status(), frame(&message))
        .send_transaction(&[0xde, 0xad])
        .unwrap_err();
    match err {
        LightError::Status { code, ref message } => {
            assert_eq!(code, -26);
            assert!(message.contains("mempool min fee"), "{message}");
        }
        other => panic!("expected a status error, got {other:?}"),
    }
}

#[test]
fn a_truncated_commitment_tree_is_refused() {
    use verus_light::TreeState;
    let state = TreeState {
        network: "VRSCTEST".into(),
        height: 1,
        hash: String::new(),
        time: 0,
        // A present left node whose 32 bytes are missing.
        tree: "01abcd".into(),
    };
    assert!(state.leaf_count().is_err());
}

#[test]
fn trailing_bytes_after_a_commitment_tree_are_refused() {
    use verus_light::TreeState;
    let state = TreeState {
        network: "VRSCTEST".into(),
        height: 1,
        hash: String::new(),
        time: 0,
        // left absent, right absent, zero parents — then a stray byte.
        tree: "000000ff".into(),
    };
    let err = state.leaf_count().unwrap_err();
    match err {
        LightError::Protobuf(ref text) => assert!(text.contains("left over"), "{text}"),
        other => panic!("expected a protobuf error, got {other:?}"),
    }
}
