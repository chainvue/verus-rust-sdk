//! `GrpcWebTransport` itself, rather than the client logic above it.
//!
//! Mirrors `verus-rpc`'s `transport_hardening.rs`: the IPv6 loopback fix and
//! the redirect policy audited here live inside `GrpcWebTransport::new` and
//! `GrpcWebTransport::call` and can only be observed through the real, public
//! API. The redirect test below runs a throwaway HTTP listener on loopback to
//! do that; nothing here reaches beyond `127.0.0.1`.

#![cfg(feature = "grpc-web")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;

use verus_light::{GrpcWebTransport, LightError, LightTransport};

/// Read a request's headers, then answer with `response` and drain whatever
/// the client still has queued before closing.
///
/// Both halves are load-bearing. Reading once returns whatever arrived in a
/// single chunk, so asserting on a header found in that slice is a coin flip.
/// And stopping at the end of the headers leaves the POST body unread —
/// closing a socket with data still queued sends an RST, and ureq 2.12.1
/// panics rather than errors when its own read is cut off that way, which
/// would fail the test for a reason unrelated to what it asserts.
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

/// `rest.split(['/', ':'])` on `"[::1]:9067"` yields `"["`, which never
/// matches — so `http://[::1]:9067` was refused as insecure even though it
/// names the local machine. It should be accepted like any other loopback
/// address, and a non-loopback IPv6 literal must still be refused rather than
/// the fix accidentally widening what counts as loopback.
#[test]
fn ipv6_loopback_is_accepted_and_non_loopback_is_still_refused() {
    assert!(GrpcWebTransport::new("http://[::1]:9067").is_ok());
    assert!(GrpcWebTransport::new("http://[::1]/").is_ok());
    assert!(GrpcWebTransport::new("http://[::2]:9067").is_err());
    assert!(GrpcWebTransport::new("http://[::2]").is_err());
}

/// `user:pass@host` puts the real host *after* the `@`, so a check that only
/// reads a leading bracket group and stops would see `[::1]`, call it
/// loopback, and let the request go to whatever follows — an early version
/// of the IPv6 fix above did exactly that, accepting `http://[::1]@evil.example/`
/// and sending the request to `evil.example` in cleartext.
///
/// Every url below names `[::1]` first but is really addressed elsewhere: an
/// explicit `@evil.example`, a port folded in before the `@`, a suffix glued
/// straight onto the bracket that is not a port at all, a bracket that never
/// closes, or (the tab) a byte a url parser strips before ever comparing
/// anything — accepted today for the same reason as the others, but not
/// obviously so from the rest of this list; a future reader should not have
/// to rediscover that a parser normalizes it away.
///
/// Collected into one assertion rather than short-circuiting on the first
/// failure, so a regression that only reopens one of these forms still shows
/// up as a failure here instead of hiding behind whichever case sorts first.
#[test]
fn a_bracket_that_reads_as_loopback_does_not_override_what_follows_it() {
    let still_accepted: Vec<&str> = [
        "http://[::1]@evil.example/",
        "http://[::1]:9067@evil.example/",
        "http://[::1]x@evil.example",
        "http://[::1].evil.example",
        "http://[::1]evil.example",
        "http://[::1",
        "http://[::1]\t@evil.example",
    ]
    .into_iter()
    .filter(|url| GrpcWebTransport::new(*url).is_ok())
    .collect();
    assert!(
        still_accepted.is_empty(),
        "should all have been refused, but accepted: {still_accepted:?}"
    );
}

/// The refusal above must not itself leak what it refused: pre-fix, a url
/// with userinfo was already rejected for an unrelated reason (the whole
/// pre-`@` token never matched `localhost`), and that rejection's message
/// held only the *user*, never the password — `rest.split([...]).next()`
/// stops at the first `:` or `/`. Reintroducing the userinfo error must not
/// regress that: a constructor error is exactly what lands in a terminal or
/// a log.
#[test]
fn the_userinfo_refusal_does_not_print_the_password() {
    // `GrpcWebTransport` has no `Debug` impl, which `expect_err` requires on
    // the `Ok` side — map it away first.
    let err = GrpcWebTransport::new("http://rpcuser:s3cr3t-password@127.0.0.1:9067/")
        .map(|_| ())
        .expect_err("userinfo must be refused");
    let message = err.to_string();
    assert!(
        !message.contains("s3cr3t-password"),
        "the password leaked into the error message: {message}"
    );
}

/// The bare `ureq::AgentBuilder` this crate used to build followed up to five
/// redirects by default — including to a different host entirely, so a proxy
/// answering a call with a redirect could hand it to wherever `Location`
/// pointed, leaking which method was being called and to whom. `.redirects(0)`
/// must stop that: this spins up a real HTTP server that 302s every request
/// to a second, "attacker" listener, and asserts the attacker is never
/// contacted, and that the 3xx surfaces as a clear transport error rather
/// than a response that looks like any other.
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
            // Same read-then-drain discipline as `serve_once` needs: this
            // listener asserts nothing about the request, but leaving the
            // body unread is what sends the RST that makes ureq panic.
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{attacker_addr}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = serve_once(&mut stream, response.as_bytes());
        }
    });

    let transport = GrpcWebTransport::new(format!("http://{node_addr}")).expect("valid endpoint");
    let err = transport
        .call(
            "cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock",
            &[],
        )
        .unwrap_err();

    // Check the channel first: `call` has already returned by this point, and
    // a followed redirect would have opened its connection to the attacker
    // over loopback microseconds earlier — a blocking wait buys nothing a
    // non-blocking check doesn't already have, and checking the error message
    // first (as an earlier version of this test did) let every mutation slip
    // past this assertion undetected, since the message assertion below
    // always fired first.
    assert!(
        rx.try_recv().is_err(),
        "the redirect to the second host was followed"
    );
    assert!(
        matches!(err, LightError::Transport(ref message) if message.contains("redirect")),
        "expected a redirect-specific transport error, got {err:?}"
    );
}
