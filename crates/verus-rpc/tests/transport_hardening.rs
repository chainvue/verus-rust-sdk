//! `HttpTransport` itself, rather than the JSON-RPC layer above it.
//!
//! `hostile_transport.rs` exercises what a node's *reply* can do through a
//! fake [`Transport`]; the transport-level fixes audited here — the scheme
//! allowlist, the redirect policy, IPv6 loopback, and keeping credentials out
//! of anything printed — live inside `HttpTransport` itself and can only be
//! observed through its real, public API. Two tests below run a throwaway
//! HTTP listener on loopback to do that; nothing here reaches beyond
//! `127.0.0.1`.

#![cfg(feature = "http")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::time::Duration;

use verus_rpc::{ChainReader, HttpTransport, RpcClient, RpcError};

/// Read a request's headers, then answer with `response` and drain whatever
/// the client still has queued before closing.
///
/// Both halves are load-bearing, and both were learned the hard way. Reading
/// once returns whatever arrived in a single chunk, so asserting on a header
/// found in that slice is a coin flip. And stopping at the end of the headers
/// leaves the POST body unread — closing a socket with data still queued
/// sends an RST, and ureq 2.12.1 *panics* (`response.rs`, `read_exact` →
/// `InvalidInput`) rather than erroring when its own read is cut off that way,
/// which fails the test for a reason unrelated to what it asserts.
fn serve_once(stream: &mut std::net::TcpStream, response: &[u8]) -> String {
    let mut request = Vec::new();
    let mut chunk = [0u8; 512];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => request.extend_from_slice(&chunk[..n]),
        }
    }
    let _ = stream.write_all(response);
    let _ = stream.flush();
    let mut discard = [0u8; 512];
    while matches!(stream.read(&mut discard), Ok(n) if n > 0) {}
    String::from_utf8_lossy(&request).to_string()
}

/// The scheme check used to fail open: it only rejected a url that literally
/// started with the lowercase text `"http://"`, so anything that merely
/// looked different — a different case, a leading space — was accepted and
/// then sent to a remote host in cleartext.
#[test]
fn a_disguised_plaintext_scheme_is_still_refused() {
    for url in [
        "HTTP://evil.example",
        "Http://evil.example",
        " http://evil.example",
        "http://evil.example",
    ] {
        match HttpTransport::new(url) {
            Err(RpcError::InsecureUrl(_)) => {}
            other => panic!("{url:?} should have been refused, got {other:?}"),
        }
    }
}

/// The replacement check is an allowlist: something that is not `http://` or
/// `https://` at all — no scheme, or a scheme this crate has no opinion about
/// — must be refused rather than passed through uninspected.
#[test]
fn a_url_with_an_unrecognised_scheme_is_refused() {
    assert!(HttpTransport::new("ftp://example.com").is_err());
    assert!(HttpTransport::new("example.com/rpc").is_err());
}

/// `https://` needs no loopback exception, and plaintext to loopback stays
/// allowed — the fix must not have turned the allowlist into a ban on `http`
/// entirely.
#[test]
fn https_and_loopback_plaintext_both_still_work() {
    assert!(HttpTransport::new("https://example.com").is_ok());
    assert!(HttpTransport::new("http://127.0.0.1:8080").is_ok());
    assert!(HttpTransport::new("http://localhost/").is_ok());
}

/// `rest.split(['/', ':'])` on `"[::1]:27486"` yields `"["`, which never
/// matches — so `http://[::1]:8080` was refused as insecure even though it
/// names the local machine. It should be accepted like any other loopback
/// address.
#[test]
fn ipv6_loopback_is_accepted() {
    assert!(HttpTransport::new("http://[::1]:8080").is_ok());
    assert!(HttpTransport::new("http://[::1]/").is_ok());
    // A non-loopback IPv6 literal must still be refused.
    assert!(HttpTransport::new("http://[::2]:8080").is_err());
}

/// Credentials embedded in a url must still AUTHENTICATE.
///
/// The first fix for the leak simply deleted `user:pass@` from the url — and
/// silently broke every caller using the classic `https://user:pass@node/`
/// form, because `ureq` turns a url's userinfo into an `Authorization: Basic`
/// header when none is set. The daemon would answer 401 and nothing would
/// name the cause. Redaction has to MOVE the credentials, not discard them,
/// so this asserts the header still reaches the wire.
#[test]
fn userinfo_embedded_in_a_url_still_authenticates() {
    let node = TcpListener::bind("127.0.0.1:0").expect("bind node listener");
    let node_addr = node.local_addr().expect("node addr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = node.accept() {
            let request = serve_once(
                &mut stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            );
            let _ = tx.send(request);
        }
    });

    let transport = HttpTransport::allow_plaintext(format!("http://user:hunter2@{node_addr}/"))
        .with_timeout(Duration::from_secs(5));
    let client = RpcClient::new(transport);
    let _ = client.chain_info();

    let request = rx
        .recv_timeout(Duration::from_millis(2_000))
        .expect("the node was contacted");
    // base64("user:hunter2")
    let expected = "Basic dXNlcjpodW50ZXIy";
    assert!(
        request.contains(expected),
        "the embedded credentials never reached the wire:\n{request}"
    );
}

/// …and must not appear anywhere they are printed.
///
/// `Credentials` set through `with_auth` are zeroized and never printed; a
/// url with `user:pass@` embedded directly did not get the same treatment.
/// Neither the `Debug` impl nor the `InsecureUrl` error should ever show one.
#[test]
fn userinfo_embedded_in_a_url_never_appears_in_debug_output_or_an_error() {
    let transport = HttpTransport::allow_plaintext("http://user:hunter2@example.com/rpc");
    let debug = format!("{transport:?}");
    assert!(!debug.contains("hunter2"), "leaked in Debug: {debug}");
    assert!(!debug.contains("user:"), "leaked in Debug: {debug}");

    // A url can carry userinfo *and* still be insecure (non-loopback http),
    // which is exactly where the error message used to embed it verbatim.
    match HttpTransport::new("http://user:hunter2@evil.example/rpc") {
        Err(RpcError::InsecureUrl(message)) => {
            assert!(!message.contains("hunter2"), "leaked in error: {message}");
        }
        other => panic!("expected InsecureUrl, got {other:?}"),
    }
}

/// The bare `ureq::AgentBuilder` this crate used to build followed up to five
/// redirects by default — including to a different host entirely, which
/// means a node could answer `sendrawtransaction` with a redirect and this
/// client would hand the signed bytes to wherever the `Location` header
/// pointed. `.redirects(0)` must stop that: this spins up a real HTTP server
/// that 302s every request to a second, "attacker" listener, and asserts the
/// attacker is never contacted.
#[test]
fn a_redirect_to_another_host_is_never_followed() {
    let attacker = TcpListener::bind("127.0.0.1:0").expect("bind attacker listener");
    let attacker_addr = attacker.local_addr().expect("attacker addr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        // Any connection at all here means the redirect was followed.
        if attacker.accept().is_ok() {
            let _ = tx.send(());
        }
    });

    let node = TcpListener::bind("127.0.0.1:0").expect("bind node listener");
    let node_addr = node.local_addr().expect("node addr");
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = node.accept() {
            // Same read-then-drain discipline as the auth test: this listener
            // asserts nothing about the request, but leaving the body unread
            // is what sends the RST that makes ureq panic.
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{attacker_addr}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = serve_once(&mut stream, response.as_bytes());
        }
    });

    let transport = HttpTransport::allow_plaintext(format!("http://{node_addr}/"))
        .with_timeout(Duration::from_secs(5));
    let client = RpcClient::new(transport);
    // The 302 is not valid JSON-RPC either way, so this call fails — what
    // matters is *which* host was asked.
    let _ = client.chain_info();

    assert!(
        rx.recv_timeout(Duration::from_millis(1_000)).is_err(),
        "the redirect to the second host was followed"
    );
}

/// An `@` in the query string is not userinfo. Bounding the authority only at
/// `/` took `https://host?x=a@b` for a credentialled url and mangled it down
/// to `https://b` — a different host entirely.
#[test]
fn an_at_sign_in_the_query_is_not_mistaken_for_credentials() {
    let transport = HttpTransport::new("https://node.example?filter=a@b").expect("valid https");
    let debug = format!("{transport:?}");
    assert!(
        debug.contains("node.example"),
        "the host was rewritten: {debug}"
    );
}
