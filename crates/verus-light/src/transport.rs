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
        ///
        /// Also refuses `user:password@` in the endpoint, on **either**
        /// scheme. This transport never sends credentials, so they can only
        /// have arrived by mistake — and left in place they reach every
        /// request and land in `ureq`'s error text, which embeds the whole
        /// URL. If an endpoint is being read from an environment variable or
        /// a config file, that is the form this will reject.
        pub fn new(base: impl Into<String>) -> Result<Self, LightError> {
            let base = base.into();
            let base = base.trim_end_matches('/').to_string();
            Self::check_scheme(&base)?;
            let agent = ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(10))
                .timeout(Duration::from_mins(2))
                // `.redirects(0)`: the bare default follows up to five
                // redirects, including an https-to-http downgrade and a
                // redirect to a different host entirely — so a proxy
                // answering a call with a 307 could hand this request to
                // somewhere the caller never asked to send it, leaking which
                // method is being called and to whom. Refusing to follow any
                // redirect closes both at once: `ureq::AgentBuilder` also has
                // an `https_only` option, but that would additionally reject
                // the plaintext loopback connections this transport
                // deliberately allows (`check_scheme` above), so it is not
                // used here — the same call `verus-rpc`'s transport makes,
                // for the same reason. Because ureq only turns a >=400
                // response into an `Err`, a refused redirect still arrives
                // here as an ordinary `Ok` response; `call` below checks for
                // one explicitly rather than letting it be misread as a
                // malformed grpc-web reply.
                .redirects(0)
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

        /// Refuse an endpoint this transport should never have been handed.
        ///
        /// Two independent decisions live here, and they are deliberately
        /// sequenced so neither can shadow the other. The **userinfo** rule
        /// applies to both schemes: this crate has no `Credentials` type, no
        /// zeroize-on-drop and no redacting `Debug`, so a `user:pass@` in an
        /// endpoint is never intentional, and TLS does not make it meaningful
        /// — it only stops a network observer reading it, while it still
        /// reaches a terminal or a log through `ureq`'s error text, which
        /// embeds the whole URL. The **plaintext** rule applies to `http://`
        /// alone. Running the first before the second is what keeps
        /// `https://user:pass@evil.example` from being waved through.
        ///
        /// `verus-rpc` deliberately does the opposite and *supports* userinfo,
        /// because it has a `Credentials` type that zeroizes on drop and
        /// redacts in `Debug`, and it strips the userinfo with
        /// `split_userinfo` before its own scheme check. That asymmetry is
        /// intentional and should not be "harmonised" — #161 exists precisely
        /// because a check was once copied between these two crates without
        /// the thing that made it safe.
        ///
        /// # Agreeing with the parser that actually connects
        ///
        /// The authority is bounded here by hand, and `ureq` finds it with the
        /// `url` crate's WHATWG parser. Anywhere the two disagree, this
        /// function is validating a different string than the one the request
        /// is sent to — which is not a hypothetical: `https:///user:pass@host`
        /// was accepted outright, because a leading `/` made the authority
        /// read as empty here while WHATWG collapses those slashes and reads
        /// the userinfo. So the two normalisation rules WHATWG applies before
        /// the authority even starts are applied here too: ASCII tab, CR and
        /// LF are removed from the whole URL, and any run of `/` or `\` after
        /// the scheme is skipped. `\` also ends the authority, as it does
        /// there.
        ///
        /// `the_authority_we_validate_is_the_one_ureq_connects_to` in
        /// `tests/transport_hardening.rs` pins the agreement against the real
        /// parser rather than against a string form, so the next divergence
        /// fails there instead of in production.
        fn check_scheme(base: &str) -> Result<(), LightError> {
            // WHATWG removes these three bytes from a URL entirely before
            // parsing it, so a check that keeps them is looking at a string
            // ureq never sees. `https://\t/user:pass@host` is the shape that
            // matters: the tab makes the authority read as `\t` here while
            // the parser sees `https:///user:pass@host` and finds credentials.
            let scrubbed: String;
            let base = if base.bytes().any(|b| matches!(b, b'\t' | b'\r' | b'\n')) {
                scrubbed = base
                    .chars()
                    .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
                    .collect();
                scrubbed.as_str()
            } else {
                base
            };

            let (rest, is_tls) = if let Some(rest) = base.strip_prefix("https://") {
                (rest, true)
            } else if let Some(rest) = base.strip_prefix("http://") {
                (rest, false)
            } else {
                // Never echo the raw endpoint here: this is the arm a stray
                // leading space (a YAML value, an env var) or an uppercase
                // `HTTPS://` typo falls into, and both are exactly the kind
                // of mistake that has real credentials sitting in the rest
                // of the string. Report only the scheme — `" http"` still
                // shows the stray space, `"HTTPS"` still shows the casing —
                // and nothing past the `://` ever reaches the message. A
                // `base.split("://").next()` would look equivalent but is
                // not: with no `://` anywhere (`user:pass@host`, no scheme
                // at all) that yields the *entire* string unchanged, so the
                // separator's presence is checked explicitly instead.
                //
                // Nor is "whatever precedes the first `://`" necessarily a
                // scheme: `user:SECRET@https://node.example` — the mangled
                // form of `https://user:SECRET@node.example` — puts a
                // password before the `://` too, so a bare prefix still
                // leaks it. A real scheme can never itself contain `:`, `@`
                // or `/`; `" http"`, `"\thttp"`, `"HTTPS"` and `"http "`
                // don't, so the check costs nothing on the cases this is
                // meant to diagnose while refusing to print anything on the
                // ones it isn't.
                let scheme = match base.find("://") {
                    Some(end) if !base[..end].contains([':', '@', '/']) => &base[..end],
                    _ => "",
                };
                return Err(LightError::Refused(format!(
                    "endpoint must start with http:// or https://, got scheme {scheme:?}"
                )));
            };
            // Skip the slashes WHATWG collapses. For a special scheme it
            // consumes *any* run of `/` or `\` after `scheme:` before the
            // authority starts, so `https:///user:pass@host` addresses
            // `host` with credentials — while bounding the authority without
            // this made it read as empty and sailed past the `@` check below.
            let rest = rest.trim_start_matches(['/', '\\']);
            // Bound the authority the way that parser would: up to the first
            // '/', '\', '?' or '#'. Everything below compares against this,
            // not against `rest`, so a path segment can never be mistaken
            // for part of the host.
            let authority_end = rest.find(['/', '\\', '?', '#']).unwrap_or(rest.len());
            let authority = &rest[..authority_end];
            // `user:pass@host` puts the host *after* the `@`, so a check
            // that only looks at a leading `[::1]` and ignores the rest
            // would accept `http://[::1]@evil.example/` — the bracket reads
            // as loopback, but the request goes to `evil.example`. This
            // crate has no use for userinfo in an endpoint (unlike
            // `verus-rpc`, which carries node credentials), so refuse it
            // outright rather than parse around it.
            //
            // This runs *before* the `is_tls` shortcut below, and must keep
            // doing so. When it sat after it, the whole check was dead on
            // the TLS path: `https://user:pass@evil.example` was accepted
            // outright, and a later transport failure — a DNS miss is
            // enough — surfaced `ureq`'s own error text, which embeds the
            // full URL, straight through `LightError::Transport`.
            //
            // The refusal must not itself leak whatever was in there: unlike
            // `verus-rpc`'s `Credentials`, nothing here is going to zeroize
            // or redact this string on the way to a `Debug` impl or a log
            // line, so the message reports only what follows the last `@`
            // — never the authority as a whole, which is where a password
            // would be sitting. `rsplit_once`, not `split_once`: an `@`
            // inside the password (`user:pa@ss@host`) splits early under
            // `split_once` and lets the password tail through.
            if let Some((_, host_part)) = authority.rsplit_once('@') {
                return Err(LightError::Refused(format!(
                    "refusing endpoint for {host_part}: this endpoint takes no \
                     user:password@ — remove it, this transport never sends credentials"
                )));
            }
            // Everything past this point is the plaintext rule, which TLS
            // genuinely does settle.
            if is_tls {
                return Ok(());
            }
            // Whatever trails a host must be nothing, or a `:` followed only
            // by digits — anything else past this point is refused outright
            // rather than trusted to fail later in ureq's own url parsing.
            // Shared by both branches below so "safe" is a property of the
            // parse here, not a hope pinned on whatever a different parser
            // downstream happens to reject.
            let port_is_numeric = |after: &str| {
                after.is_empty()
                    || (after.starts_with(':')
                        && after.len() > 1
                        && after[1..].bytes().all(|b| b.is_ascii_digit()))
            };
            // An IPv6 literal such as "[::1]:9067" contains colons inside
            // the brackets; splitting on ':' the way the plain-host branch
            // below does stops at the first one *inside* the address ("[")
            // and never matches, so `http://[::1]:9067` was always refused
            // even though it is loopback. The host ends at the matching `]`,
            // not at a colon — and only a numeric port may follow it; any
            // other trailer (a missing `]`, or text glued on after it) is
            // refused rather than guessed at.
            if let Some(after_bracket) = authority.strip_prefix('[') {
                let Some((host, after)) = after_bracket.split_once(']') else {
                    return Err(LightError::Refused(format!(
                        "refusing plaintext http:// to [{after_bracket}: unterminated IPv6 literal"
                    )));
                };
                if host == "::1" && port_is_numeric(after) {
                    return Ok(());
                }
                return Err(LightError::Refused(format!(
                    "refusing plaintext http:// to [{host}]: use https://, or tunnel to loopback"
                )));
            }
            let colon = authority.find(':').unwrap_or(authority.len());
            let (host, after) = authority.split_at(colon);
            if (host == "localhost" || host == "127.0.0.1") && port_is_numeric(after) {
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

            // With `redirects(0)` set above, ureq neither follows a 3xx nor
            // treats it as an `Err` — it only does that for >=400 — so a
            // refused redirect reaches this point looking like any other
            // response. Name it explicitly rather than let it fall through
            // to a generic "no grpc-status" framing error further down.
            if (300..400).contains(&response.status()) {
                return Err(LightError::Transport(format!(
                    "server returned a redirect ({}); redirects are refused, call the endpoint directly",
                    response.status()
                )));
            }

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
            if u64::try_from(body.len())
                .expect("a usize length fits in u64 on every target this builds for")
                > self.max_response
            {
                return Err(LightError::Transport(format!(
                    "response exceeds the {} byte cap; ask for a smaller block range",
                    self.max_response
                )));
            }

            Ok(HttpResponse { status, body })
        }
    }
}
