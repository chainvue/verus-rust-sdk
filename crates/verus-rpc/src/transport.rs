//! How a request reaches a node.
//!
//! Behind a trait so the crate does not force an HTTP client on anyone. A wasm
//! build supplies one over `fetch`; a test supplies one that answers from a
//! canned string and touches no network at all.

use crate::error::RpcError;

/// Delivers a JSON-RPC request body and returns the reply body.
///
/// Implementations should not interpret either: parsing, error mapping and
/// retry policy all belong above this line.
pub trait Transport {
    /// POST `body` and return the response text.
    fn post(&self, body: &str) -> Result<String, RpcError>;
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
    auth: Option<(String, String)>,
    timeout: std::time::Duration,
}

#[cfg(feature = "http")]
impl HttpTransport {
    /// A transport for a public node, which needs no credentials.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            auth: None,
            timeout: std::time::Duration::from_secs(30),
        }
    }

    /// A transport for a private node behind RPC basic auth.
    ///
    /// These credentials authorise *reading* and broadcasting. They are not a
    /// spending key, and this crate never sends one — but they still identify
    /// you to that node, so treat them as a secret.
    pub fn with_auth(mut self, user: impl Into<String>, password: impl Into<String>) -> Self {
        self.auth = Some((user.into(), password.into()));
        self
    }

    /// How long to wait for a reply.
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

#[cfg(feature = "http")]
impl Transport for HttpTransport {
    fn post(&self, body: &str) -> Result<String, RpcError> {
        let agent = ureq::AgentBuilder::new()
            .timeout(self.timeout)
            .build();
        let mut request = agent
            .post(&self.url)
            .set("content-type", "application/json");
        if let Some((user, password)) = &self.auth {
            let encoded = base64_basic(user, password);
            request = request.set("authorization", &format!("Basic {encoded}"));
        }
        match request.send_string(body) {
            Ok(response) => response
                .into_string()
                .map_err(|e| RpcError::Transport(e.to_string())),
            // A daemon reports RPC errors with a non-2xx status AND a JSON body;
            // the body is the useful part, so it is passed up rather than
            // collapsed into the status code.
            Err(ureq::Error::Status(_, response)) => response
                .into_string()
                .map_err(|e| RpcError::Transport(e.to_string())),
            Err(e) => Err(RpcError::Transport(e.to_string())),
        }
    }
}

/// Base64 for the one header that needs it, rather than a dependency.
#[cfg(feature = "http")]
fn base64_basic(user: &str, password: &str) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
        assert_eq!(base64_basic("Aladdin", "open sesame"), "QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
    }
}
