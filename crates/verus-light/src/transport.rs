//! How a request reaches the server.
//!
//! The trait is the whole extension point: implement it over `fetch` for wasm,
//! over your own connection pool, or over a recorded fixture for tests. The
//! framing, encoding and decoding all live above it, so an implementor moves
//! bytes and nothing else.

use crate::error::LightError;
use crate::grpc::GrpcStatus;

/// A server's answer, before any grpc-web framing is interpreted.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// `grpc-status` / `grpc-message` from the **HTTP headers**, when present.
    ///
    /// This is not redundant with the trailer frame in the body. An error
    /// response has an empty body and carries its status here instead — see
    /// [`crate::grpc`] for why ignoring it makes a client silently wrong.
    pub status: Option<GrpcStatus>,
    /// The raw response body: zero or more grpc-web frames.
    pub body: Vec<u8>,
}

/// Somewhere to send a framed grpc-web request.
pub trait LightTransport {
    /// POST `request` to `path` and return the response.
    ///
    /// `path` is a gRPC method path such as
    /// `cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTreeState`. `request` is
    /// already grpc-web framed; an implementor should send it verbatim and set
    /// `Content-Type: application/grpc-web+proto`.
    ///
    /// A non-2xx HTTP status should be an `Err`, but a 200 carrying a non-zero
    /// `grpc-status` header should **not** — return it in
    /// [`HttpResponse::status`] and let the caller classify it.
    fn call(&self, path: &str, request: &[u8]) -> Result<HttpResponse, LightError>;
}

#[cfg(feature = "grpc-web")]
pub use blocking::GrpcWebTransport;

#[cfg(feature = "grpc-web")]
mod blocking {
    use std::io::Read;
    use std::time::Duration;

    use super::{HttpResponse, LightTransport};
    use crate::error::LightError;
    use crate::grpc::{parse_status, CONTENT_TYPE};

    /// Cap on a single response body.
    ///
    /// A block range is the one call that can return a lot: roughly 100 bytes
    /// per shielded output plus ~50 per block. 64 MiB covers a very large sweep
    /// while still refusing a server that intends to exhaust memory.
    const DEFAULT_MAX_RESPONSE: u64 = 64 * 1024 * 1024;

    /// A blocking grpc-web transport over HTTP/1.1.
    ///
    /// Deliberately not native gRPC. grpc-web needs no HTTP/2 stack and no async
    /// runtime, so this crate stays synchronous like the rest of the workspace —
    /// and the same framing is what a browser must use anyway, so one transport
    /// serves both a server-side caller and a future wasm build.
    ///
    /// The cost is that it needs a grpc-web proxy in front of lightwalletd
    /// rather than talking to port 9067 directly. That is a deployment
    /// requirement, and it is stated rather than hidden.
    pub struct GrpcWebTransport {
        agent: ureq::Agent,
        base: String,
        max_response: u64,
    }

    impl GrpcWebTransport {
        /// Point a transport at a grpc-web endpoint.
        ///
        /// Refuses plaintext `http://` to a non-loopback host: a light client
        /// leaks which blocks it fetches, and over the open internet that is
        /// also modifiable in flight. Loopback is allowed because the intended
        /// deployment is an SSH tunnel or a local proxy, where TLS would be
        /// ceremony.
        pub fn new(base: impl Into<String>) -> Result<Self, LightError> {
            let base = base.into();
            let base = base.trim_end_matches('/').to_string();
            Self::check_scheme(&base)?;
            let agent = ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(10))
                .timeout(Duration::from_mins(2))
                .build();
            Ok(Self {
                agent,
                base,
                max_response: DEFAULT_MAX_RESPONSE,
            })
        }

        /// Change the response size cap.
        #[must_use]
        pub fn with_max_response(mut self, bytes: u64) -> Self {
            self.max_response = bytes;
            self
        }

        fn check_scheme(base: &str) -> Result<(), LightError> {
            if base.starts_with("https://") {
                return Ok(());
            }
            let Some(rest) = base.strip_prefix("http://") else {
                return Err(LightError::Refused(format!(
                    "endpoint must start with http:// or https://, got {base}"
                )));
            };
            let host = rest.split(['/', ':']).next().unwrap_or("");
            if host == "localhost" || host == "127.0.0.1" || host == "[::1]" {
                return Ok(());
            }
            Err(LightError::Refused(format!(
                "refusing plaintext http:// to {host}: use https://, or tunnel to loopback"
            )))
        }
    }

    impl LightTransport for GrpcWebTransport {
        fn call(&self, path: &str, request: &[u8]) -> Result<HttpResponse, LightError> {
            let url = format!("{}/{}", self.base, path);
            let response = self
                .agent
                .post(&url)
                .set("Content-Type", CONTENT_TYPE)
                .set("X-Grpc-Web", "1")
                .send_bytes(request)
                .map_err(|e| LightError::Transport(e.to_string()))?;

            // ureq matches header names case-insensitively, which matters: this
            // proxy capitalises them in headers and not in trailers.
            let status = match response.header("grpc-status") {
                Some(code) => parse_status(&format!(
                    "grpc-status: {code}\ngrpc-message: {}",
                    response.header("grpc-message").unwrap_or_default()
                )),
                None => None,
            };

            // Read one byte past the cap so an oversized body is an explicit
            // error. Truncating instead would hand the framing decoder a
            // half-frame and report it as a malformed server.
            let mut body = Vec::new();
            response
                .into_reader()
                .take(self.max_response.saturating_add(1))
                .read_to_end(&mut body)
                .map_err(|e| LightError::Transport(format!("reading the response body: {e}")))?;
            if u64::try_from(body.len()).expect("a body length fits in u64") > self.max_response {
                return Err(LightError::Transport(format!(
                    "response exceeds the {} byte cap; ask for a smaller block range",
                    self.max_response
                )));
            }

            Ok(HttpResponse { status, body })
        }
    }
}
