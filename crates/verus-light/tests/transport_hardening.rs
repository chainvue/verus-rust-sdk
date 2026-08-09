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
use std::time::Duration;

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
    assert!(
        matches!(err, LightError::Transport(ref message) if message.contains("redirect")),
        "expected a redirect-specific transport error, got {err:?}"
    );

    assert!(
        rx.recv_timeout(Duration::from_secs(1)).is_err(),
        "the redirect to the second host was followed"
    );
}
