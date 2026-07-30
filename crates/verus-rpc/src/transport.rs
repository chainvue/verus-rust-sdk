//! How a request reaches a node.
//!
//! Behind a trait so the crate does not force an HTTP client on anyone. A wasm
//! build supplies one over `fetch`; a test supplies one that answers from a
//! canned string and touches no network at all.

use crate::error::RpcError;

/// A request body, which only this crate can construct.
///
/// This is what makes the crate's claim about method names true rather than
/// aspirational. [`Transport`] is the documented extension point, so if it took
/// a plain `&str` anyone holding one could post `z_sendmany` in a line and the
/// typed-methods-only design would be decoration. With an opaque body, an
/// implementor can *deliver* a request but cannot *compose* one.
///
/// A `Transport` implementation can of course ignore the body and send whatever
/// it likes — but that is code inside the caller's own process, which is outside
/// any boundary this crate can draw.
pub struct RequestBody(String);

impl RequestBody {
    /// Only [`crate::envelope`] builds these.
    pub(crate) fn new(body: String) -> Self {
        RequestBody(body)
    }

    /// The bytes to send.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Delivers a JSON-RPC request body and returns the reply body.
///
/// Implementations should not interpret either: parsing, error mapping and
/// retry policy all belong above this line. In particular a transport must
/// **not** retry — a failed `sendrawtransaction` is ambiguous, and a silent
/// retry turns "did it broadcast?" into a question nobody can answer.
pub trait Transport {
    /// POST `body` and return the response text.
    fn post(&self, body: &RequestBody) -> Result<String, RpcError>;
}

/// A blocking HTTP transport.
///
/// Deliberately simple: no retries, no connection pooling, no timeouts beyond
/// the one configured. A wallet that needs those should wrap this or implement
/// [`Transport`] itself — burying retry logic in a transport is how a
/// double-broadcast becomes hard to reason about.
#[cfg(feature = "http")]
pub struct HttpTransport {
    url: String,
    auth: Option<Credentials>,
    agent: ureq::Agent,
    max_response_bytes: usize,
}

/// RPC credentials, kept out of logs and wiped on drop.
///
/// These authorise reading and broadcasting, not spending — this crate never
/// sends a spending key anywhere. They still identify you to a node, so they get
/// the same handling the workspace gives key material.
#[cfg(feature = "http")]
struct Credentials {
    user: String,
    password: String,
}

#[cfg(feature = "http")]
impl Drop for Credentials {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.user.zeroize();
        self.password.zeroize();
    }
}

#[cfg(feature = "http")]
impl core::fmt::Debug for HttpTransport {
    /// Never prints credentials.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HttpTransport")
            .field("url", &self.url)
            .field("auth", &self.auth.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "http")]
impl HttpTransport {
    /// The default ceiling on a reply, so a hostile or overloaded node cannot
    /// exhaust memory. Generous next to a large `getaddressutxos`.
    pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

    /// A transport for a public node, which needs no credentials.
    ///
    /// Refuses plaintext `http://` for anything but loopback: every address you
    /// query would otherwise be readable by any observer on the path. Call
    /// [`HttpTransport::allow_plaintext`] to override deliberately.
    ///
    /// Credentials embedded as `https://user:password@host/` are moved into
    /// the transport's own zeroizing store rather than left in the URL. They
    /// authenticate exactly as before; they simply stop appearing in logs.
    pub fn new(url: impl Into<String>) -> Result<Self, RpcError> {
        let (url, auth) = split_userinfo(url.into().trim());
        check_scheme(&url)?;
        let mut transport = Self::unchecked(url);
        transport.auth = auth;
        Ok(transport)
    }

    /// A transport that permits plaintext to any host.
    ///
    /// For a node reached over a tunnel or a trusted private network. Everything
    /// you ask is visible to anything between you and it.
    pub fn allow_plaintext(url: impl Into<String>) -> Self {
        let (url, auth) = split_userinfo(url.into().trim());
        let mut transport = Self::unchecked(url);
        transport.auth = auth;
        transport
    }

    fn unchecked(url: String) -> Self {
        Self {
            url,
            auth: None,
            agent: base_agent()
                .timeout(std::time::Duration::from_secs(30))
                .build(),
            max_response_bytes: Self::DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    /// A transport for a private node behind RPC basic auth.
    ///
    /// These credentials authorise *reading* and broadcasting. They are not a
    /// spending key, and this crate never sends one — but they still identify
    /// you to that node, so treat them as a secret.
    /// Overrides anything the URL carried.
    pub fn with_auth(mut self, user: impl Into<String>, password: impl Into<String>) -> Self {
        self.auth = Some(Credentials {
            user: user.into(),
            password: password.into(),
        });
        self
    }

    /// How long to wait for a reply.
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.agent = base_agent().timeout(timeout).build();
        self
    }

    /// Cap the reply size.
    pub fn with_max_response_bytes(mut self, bytes: usize) -> Self {
        self.max_response_bytes = bytes;
        self
    }
}

/// The `ureq::AgentBuilder` every constructor starts from, with the timeout
/// still unset — every caller of this immediately chains `.timeout(..)`, so
/// setting one here would just be overwritten.
///
/// `.redirects(0)`: the bare default follows up to five redirects, including
/// an https-to-http downgrade and a redirect to a different host entirely —
/// so a node answering `sendrawtransaction` with a 307 could hand the signed
/// bytes to somewhere the caller never asked to send them, or move a
/// supposedly-TLS connection to cleartext. Refusing to follow any redirect
/// closes both at once: `ureq::AgentBuilder` also has an `https_only` option,
/// but that would additionally reject the plaintext loopback connections this
/// transport deliberately allows (`is_loopback`, [`HttpTransport::allow_plaintext`]),
/// so it is not used here. A redirect response still arrives as ordinary,
/// inert reply text — [`HttpTransport::post`] hands it to the JSON-RPC parser
/// like any other body, which fails it for not being JSON-RPC, rather than
/// silently chasing it.
#[cfg(feature = "http")]
fn base_agent() -> ureq::AgentBuilder {
    ureq::AgentBuilder::new().redirects(0)
}

/// Whether `url` may be used at all.
///
/// Matches `crates/verus-light::transport::GrpcWebTransport::check_scheme`:
/// case-insensitive, trimmed, and an **allowlist** rather than a denylist. The
/// check this replaced only rejected a url that literally started with the
/// lowercase text `"http://"` — `"HTTP://evil.example"` and `" http://evil.example"`
/// (a leading space) both slipped past it and were then handed to `ureq` as
/// cleartext to a remote host, because failing to recognise a scheme is not
/// the same as refusing it.
#[cfg(feature = "http")]
fn check_scheme(url: &str) -> Result<(), RpcError> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return Ok(());
    }
    match lower.strip_prefix("http://") {
        Some(rest) if is_loopback(rest) => Ok(()),
        _ => Err(RpcError::InsecureUrl(url.to_string())),
    }
}

/// Whether the text after `http://` names the local machine.
///
/// Takes the part of the url *after* the scheme, so a caller who wants a
/// bracketed IPv6 literal can be checked without also re-deciding what counts
/// as a scheme.
#[cfg(feature = "http")]
fn is_loopback(rest: &str) -> bool {
    if let Some(after_bracket) = rest.strip_prefix('[') {
        // An IPv6 literal such as "[::1]:27486/…": splitting on `:` the way
        // the plain-host branch below does would stop at the first colon
        // *inside* the address and never match anything, refusing
        // `http://[::1]:8080` even though it is loopback. The host ends at
        // the matching `]`, not at a colon.
        return after_bracket.split(']').next() == Some("::1");
    }
    let host = rest.split(['/', ':']).next().unwrap_or("");
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1"
}

/// Split `user:password@` off a URL's authority.
///
/// Returns the URL without the userinfo, and the credentials if there were
/// any. **Both halves matter.**
///
/// Leaving the userinfo in the URL leaks it: `self.url` reaches the `Debug`
/// impl, an [`RpcError::InsecureUrl`], and the url `ureq` embeds in its own
/// error text on a transport failure — so splitting once here, at
/// construction, makes all three safe where redacting at each call site is
/// one missed spot away from `http://user:hunter2@host/` in a log.
///
/// But simply *deleting* it silently breaks authentication, because `ureq`
/// builds an `Authorization: Basic` header from a URL's userinfo when no auth
/// header is set — a caller who passed `https://user:pass@node/` would go from
/// authenticated to a bare 401 with nothing naming the cause. So the
/// credentials are moved into [`Credentials`], which zeroizes on drop and
/// redacts in `Debug`, and this crate sends the header itself. Anything set
/// through [`HttpTransport::with_auth`] wins, matching `ureq`'s own
/// precedence.
///
/// The authority ends at the first `/`, `?` or `#`: without the last two,
/// `https://host?x=a@b` would take the `@` in the query for userinfo and
/// mangle the URL down to `https://b`.
#[cfg(feature = "http")]
fn split_userinfo(url: &str) -> (String, Option<Credentials>) {
    let Some(scheme_end) = url.find("://") else {
        return (url.to_string(), None);
    };
    let after_scheme = &url[scheme_end + 3..];
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    let Some(at) = authority.rfind('@') else {
        return (url.to_string(), None);
    };
    let userinfo = &authority[..at];
    // `https://@host/` carries no credentials. `ureq` sends no header for an
    // empty user and password, so neither should this — otherwise the
    // degenerate form would start sending `Basic Og==` ("`:`").
    if userinfo.is_empty() || userinfo == ":" {
        let cleaned = format!("{}{}", &url[..scheme_end + 3], &after_scheme[at + 1..]);
        return (cleaned, None);
    }
    let (user, password) = match userinfo.split_once(':') {
        Some((user, password)) => (user.to_string(), password.to_string()),
        None => (userinfo.to_string(), String::new()),
    };
    let cleaned = format!("{}{}", &url[..scheme_end + 3], &after_scheme[at + 1..]);
    (cleaned, Some(Credentials { user, password }))
}

#[cfg(feature = "http")]
impl Transport for HttpTransport {
    fn post(&self, body: &RequestBody) -> Result<String, RpcError> {
        let mut request = self
            .agent
            .post(&self.url)
            .set("content-type", "application/json");
        if let Some(credentials) = &self.auth {
            let encoded = base64_basic(&credentials.user, &credentials.password);
            request = request.set("authorization", &format!("Basic {encoded}"));
        }
        let response = match request.send_string(body.as_str()) {
            Ok(response) => response,
            // A daemon reports RPC errors with a non-2xx status AND a JSON body;
            // the body is the useful part, so it is passed up rather than
            // collapsed into the status code.
            Err(ureq::Error::Status(_, response)) => response,
            Err(e) => return Err(RpcError::Transport(e.to_string())),
        };
        read_capped(response, self.max_response_bytes)
    }
}

/// Read a reply, refusing one larger than the cap rather than allocating it.
#[cfg(feature = "http")]
fn read_capped(response: ureq::Response, cap: usize) -> Result<String, RpcError> {
    use std::io::Read;
    let mut text = String::new();
    response
        .into_reader()
        // One byte over the cap so the limit can be detected rather than
        // silently truncating a reply into invalid JSON.
        .take(cap as u64 + 1)
        .read_to_string(&mut text)
        .map_err(|e| RpcError::Transport(e.to_string()))?;
    if text.len() > cap {
        return Err(RpcError::ResponseTooLarge { cap });
    }
    Ok(text)
}

/// Base64 for the one header that needs it, rather than a dependency.
#[cfg(feature = "http")]
fn base64_basic(user: &str, password: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let input = format!("{user}:{password}");
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(all(test, feature = "http"))]
mod tests {
    use super::*;

    /// RFC 4648 vectors, so the hand-rolled encoder is not trusted on sight.
    #[test]
    fn basic_auth_encodes_as_base64() {
        assert_eq!(base64_basic("", ""), "Og==");
        assert_eq!(base64_basic("a", "b"), "YTpi");
        assert_eq!(base64_basic("user", "password"), "dXNlcjpwYXNzd29yZA==");
        assert_eq!(
            base64_basic("Aladdin", "open sesame"),
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
    }

    /// The old check only matched a literal, lowercase `"http://"` prefix, so
    /// an uppercase scheme or a leading space slipped past it and was sent in
    /// cleartext to a remote host. `check_scheme` must catch both.
    #[test]
    fn an_uppercase_or_leading_space_scheme_does_not_bypass_the_check() {
        assert!(check_scheme("HTTP://evil.example").is_err());
        assert!(check_scheme(" http://evil.example").is_err());
        assert!(check_scheme("Http://evil.example").is_err());
    }

    #[test]
    fn a_url_with_no_recognised_scheme_is_refused() {
        assert!(check_scheme("evil.example/rpc").is_err());
        assert!(check_scheme("ftp://evil.example").is_err());
    }

    #[test]
    fn https_is_always_fine() {
        assert!(check_scheme("https://example.com").is_ok());
        assert!(check_scheme("HTTPS://example.com").is_ok());
    }

    #[test]
    fn plaintext_to_loopback_is_fine_and_to_anywhere_else_is_not() {
        assert!(check_scheme("http://127.0.0.1:8080").is_ok());
        assert!(check_scheme("http://localhost/").is_ok());
        assert!(check_scheme("http://LOCALHOST/").is_ok());
        assert!(check_scheme("http://evil.example").is_err());
        // A userinfo prefix must not let a host smuggle past the check by
        // resembling loopback in the wrong component.
        assert!(check_scheme("http://127.0.0.1@evil.example/").is_err());
    }

    /// `rest.split([':'])` on an IPv6 literal stops at the first colon
    /// *inside* the address (`"["`) and never matches, so plain loopback
    /// worked while `http://[::1]:27486` was refused as insecure. Bracketed
    /// IPv6 needs its own parse.
    #[test]
    fn ipv6_loopback_with_and_without_a_port_is_recognised() {
        assert!(is_loopback("[::1]:27486/"));
        assert!(is_loopback("[::1]"));
        assert!(!is_loopback("[::2]:27486/"));
    }

    #[test]
    fn userinfo_is_moved_out_of_the_url_rather_than_lost() {
        let (url, auth) = split_userinfo("http://user:hunter2@host.example/rpc");
        assert_eq!(url, "http://host.example/rpc");
        let auth = auth.expect("credentials were carried out of the url");
        assert_eq!(auth.user, "user");
        assert_eq!(auth.password, "hunter2");

        // A url with no userinfo is returned untouched, with no credentials.
        let (url, auth) = split_userinfo("https://host.example/rpc");
        assert_eq!(url, "https://host.example/rpc");
        assert!(auth.is_none());

        let (url, auth) = split_userinfo("not a url");
        assert_eq!(url, "not a url");
        assert!(auth.is_none());

        // A bare username with no password is still credentials.
        let (url, auth) = split_userinfo("https://user@host.example/");
        assert_eq!(url, "https://host.example/");
        let auth = auth.expect("a bare username is still userinfo");
        assert_eq!(auth.user, "user");
        assert_eq!(auth.password, "");

        // An `@` in the query is not userinfo — bounding the authority only
        // at `/` used to rewrite this to `https://b`, a different host.
        let (url, auth) = split_userinfo("https://host.example?x=a@b");
        assert_eq!(url, "https://host.example?x=a@b");
        assert!(auth.is_none());
    }
}
