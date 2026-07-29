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
    pub fn new(url: impl Into<String>) -> Result<Self, RpcError> {
        let url = url.into();
        if url.starts_with("http://") && !is_loopback(&url) {
            return Err(RpcError::InsecureUrl(url));
        }
        Ok(Self::unchecked(url))
    }

    /// A transport that permits plaintext to any host.
    ///
    /// For a node reached over a tunnel or a trusted private network. Everything
    /// you ask is visible to anything between you and it.
    pub fn allow_plaintext(url: impl Into<String>) -> Self {
        Self::unchecked(url.into())
    }

    fn unchecked(url: String) -> Self {
        Self {
            url,
            auth: None,
            // Built once: a poll loop over twenty minutes would otherwise pay
            // for a fresh TLS handshake every time.
            agent: ureq::AgentBuilder::new()
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
    pub fn with_auth(mut self, user: impl Into<String>, password: impl Into<String>) -> Self {
        self.auth = Some(Credentials {
            user: user.into(),
            password: password.into(),
        });
        self
    }

    /// How long to wait for a reply.
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.agent = ureq::AgentBuilder::new().timeout(timeout).build();
        self
    }

    /// Cap the reply size.
    pub fn with_max_response_bytes(mut self, bytes: usize) -> Self {
        self.max_response_bytes = bytes;
        self
    }
}

/// Whether a URL names the local machine.
#[cfg(feature = "http")]
fn is_loopback(url: &str) -> bool {
    let host = url
        .trim_start_matches("http://")
        .split(['/', ':'])
        .next()
        .unwrap_or("");
    host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host == "::1"
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
}
