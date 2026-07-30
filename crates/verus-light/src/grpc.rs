//! grpc-web framing, and the three places a gRPC status can hide.
//!
//! A grpc-web body is a sequence of length-prefixed frames:
//!
//! ```text
//! flags: u8      0x00 = message, 0x80 = trailers
//! length: u32    big-endian
//! payload        `length` bytes
//! ```
//!
//! # The status is not always in the body
//!
//! This is the detail that makes a naive client silently wrong, so it is worth
//! stating plainly. A lightwalletd error arrives as a **trailers-only**
//! response: HTTP 200, an empty body, and `Grpc-Status` among the HTTP
//! *headers*. Asking for a block range past the tip returns exactly that.
//!
//! A client that only parses trailer frames sees an empty body and concludes
//! **zero blocks** — which for `GetBlockRange` is indistinguishable from "no
//! shielded activity in that range". A wallet would scan straight past its own
//! notes and report a balance of nothing. So the status is read from headers
//! *and* from a trailer frame, and a response carrying neither is an error
//! rather than an empty success.
//!
//! Header names are matched case-insensitively: the proxy this was developed
//! against sends `Grpc-Status` in headers and `grpc-status` in trailers, in the
//! same conversation.

use crate::error::LightError;

/// Set in a frame's flag byte to mark it as trailers rather than a message.
const FLAG_TRAILERS: u8 = 0x80;

/// Set in a frame's flag byte to mark its payload as compressed.
///
/// This client advertises no `grpc-accept-encoding` and never sends
/// `grpc-encoding`, so a compliant server never sets this bit. A server that
/// sets it anyway is not one this crate can talk to: handing the compressed
/// bytes to [`crate::proto`] as if they were plaintext protobuf would not
/// panic (the reader is bounds-checked) but would silently decode garbage
/// fields instead of the real message, which is worse than an error.
const FLAG_COMPRESSED: u8 = 0x01;

/// The content type that selects grpc-web with protobuf payloads.
pub(crate) const CONTENT_TYPE: &str = "application/grpc-web+proto";

/// Wrap one protobuf message in a grpc-web request frame.
pub(crate) fn frame_request(message: &[u8]) -> Vec<u8> {
    let len = u32::try_from(message.len()).expect("a request message is far below 4 GiB");
    let mut out = Vec::with_capacity(5 + message.len());
    out.push(0);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(message);
    out
}

/// A gRPC status, from wherever it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcStatus {
    /// The numeric gRPC status code; zero means success.
    pub code: i32,
    /// The server's `grpc-message`, verbatim. Empty when the server sent none.
    pub message: String,
}

impl GrpcStatus {
    /// Turn a non-zero status into an error, and a zero one into `Ok`.
    pub(crate) fn check(self) -> Result<(), LightError> {
        if self.code == 0 {
            return Ok(());
        }
        Err(LightError::Status {
            code: self.code,
            message: self.message,
        })
    }
}

/// Parse `grpc-status` / `grpc-message` out of HTTP-style header lines.
///
/// Used for both the response headers and the trailer frame, which carry the
/// same `name: value` shape.
pub fn parse_status(text: &str) -> Option<GrpcStatus> {
    let mut code = None;
    let mut message = String::new();
    for line in text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        // Case-insensitive: the same proxy sends `Grpc-Status` in headers and
        // `grpc-status` in trailers.
        if name.trim().eq_ignore_ascii_case("grpc-status") {
            code = value.parse::<i32>().ok();
        } else if name.trim().eq_ignore_ascii_case("grpc-message") {
            message = value.to_string();
        }
    }
    code.map(|code| GrpcStatus { code, message })
}

/// The messages and trailing status decoded from one grpc-web body.
pub(crate) struct Body<'a> {
    pub(crate) messages: Vec<&'a [u8]>,
    pub(crate) status: Option<GrpcStatus>,
}

/// Split a grpc-web body into its messages and its trailer status.
///
/// Refuses trailing bytes that are not a whole frame, rather than returning the
/// messages decoded so far: a truncated response and a complete one must not
/// look alike, for the same reason [`Body`] carries the status.
pub(crate) fn decode_body(body: &[u8]) -> Result<Body<'_>, LightError> {
    let mut messages = Vec::new();
    let mut status: Option<GrpcStatus> = None;
    let mut offset = 0;

    while offset < body.len() {
        // `offset < body.len()` here, so `body.len() - offset` cannot
        // underflow. Written this way rather than `offset + 5 > body.len()`
        // for the same reason as the frame-length check below: a naive
        // addition can overflow `usize`, which on wasm32 (an explicitly
        // supported target — see `lib.rs`, `transport.rs`) is only 32 bits
        // wide and far easier to reach than on a 64-bit host.
        if 5 > body.len() - offset {
            return Err(LightError::Framing(format!(
                "{} trailing bytes: not enough for a frame header",
                body.len() - offset
            )));
        }
        let flags = body[offset];
        let len = u32::from_be_bytes(
            body[offset + 1..offset + 5]
                .try_into()
                .expect("a four byte window"),
        );
        let len = usize::try_from(len).map_err(|_| {
            LightError::Framing("frame length does not fit in this platform".into())
        })?;
        offset += 5;
        // Same overflow hazard as the header check above: `len` is a 32-bit
        // value the server chose, up to 4 GiB, and `offset + len` can wrap a
        // 32-bit `usize` well before it reaches anything close to
        // `body.len()`. Comparing against `body.len() - offset` (safe here
        // because `offset <= body.len()` after the header check just above)
        // cannot overflow.
        if len > body.len() - offset {
            return Err(LightError::Framing(format!(
                "frame claims {len} bytes but only {} remain",
                body.len() - offset
            )));
        }
        let payload = &body[offset..offset + len];
        offset += len;

        if flags & FLAG_TRAILERS == 0 {
            if flags & FLAG_COMPRESSED != 0 {
                return Err(LightError::Framing(
                    "message frame is compressed, and this client does not implement grpc compression"
                        .into(),
                ));
            }
            messages.push(payload);
        } else {
            let text = std::str::from_utf8(payload)
                .map_err(|_| LightError::Framing("trailer frame is not valid UTF-8".into()))?;
            // A response can carry more than one trailer frame, and only one
            // of them needs to mention `grpc-status` for the call to have
            // failed. Overwriting unconditionally here means a later trailer
            // frame that carries no status — metadata-only, or from a proxy
            // that appends its own — erases an error status the server
            // already reported, which is exactly the silent-empty-success
            // failure mode this module's docs warn about. `Option::or` keeps
            // whatever this frame found, falling back to what an earlier
            // frame found only when this one found nothing.
            status = parse_status(text).or(status);
        }
    }

    Ok(Body { messages, status })
}
