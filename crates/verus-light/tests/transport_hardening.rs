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

    // A password that itself contains `@` is what actually distinguishes
    // `rsplit_once('@')` from `split_once('@')`: with a single `@` in the
    // whole authority, either one finds the same split, so a mutation from
    // `rsplit` to `split` would pass the case above undetected. Here the
    // password's own `@` gives `split_once` a *different*, earlier split
    // than `rsplit_once` — `split_once` would take `pa` as the redacted
    // "user" part and let `ss-w0rd@127.0.0.1:9067` — the rest of the
    // password plus the host — through into the message.
    let err = GrpcWebTransport::new("http://rpcuser:pa@ss-w0rd@127.0.0.1:9067/")
        .map(|_| ())
        .expect_err("userinfo must be refused");
    let message = err.to_string();
    assert!(
        !message.contains("ss-w0rd"),
        "the password leaked into the error message: {message}"
    );
}

/// The userinfo refusal above must apply to `https://` too, and for a while it
/// did not: `check_scheme` returned `Ok(())` for `https://` *before* running
/// any authority check, so every url below was accepted outright. TLS settles
/// the plaintext question and nothing else — this crate has no `Credentials`
/// type, no zeroize-on-drop and no redacting `Debug`, so `user:pass@` in an
/// endpoint is never intentional whatever the scheme.
///
/// It is not only about what is *sent*: an accepted endpoint reaches
/// `call()`, and an ordinary transport failure (a DNS miss will do) surfaces
/// `ureq`'s own error text — which embeds the full url, userinfo included —
/// through `LightError::Transport`.
///
/// Collected rather than short-circuited, for the same reason as the bracket
/// test above.
#[test]
fn https_does_not_skip_the_userinfo_refusal() {
    let still_accepted: Vec<&str> = [
        "https://rpcuser:s3cr3t-password@evil.example",
        "https://rpcuser:s3cr3t-password@evil.example/path",
        // The bracket-reads-as-loopback shape, on the TLS path this time.
        "https://[::1]@evil.example/",
        "https://user@evil.example",
    ]
    .into_iter()
    .filter(|url| GrpcWebTransport::new(*url).is_ok())
    .collect();
    assert!(
        still_accepted.is_empty(),
        "should all have been refused, but accepted: {still_accepted:?}"
    );
}

/// The fix above must not drag the `http://` loopback grammar onto the TLS
/// path with it. `https://` is exactly as permissive as it always was about
/// *hosts* — any host, any port, any path — and only the userinfo rule is
/// new. Without this, hoisting the authority checks could silently start
/// refusing every ordinary remote lightwalletd endpoint.
#[test]
fn https_still_accepts_ordinary_endpoints() {
    let refused: Vec<&str> = [
        "https://node.example",
        "https://node.example/",
        "https://node.example:443/path",
        "https://[::1]:9067/",
        "https://127.0.0.1:9067",
        // An `@` *past* the authority is not userinfo and must not be read as
        // such. This is what pins the `find(['/', '?', '#'])` bound: swapping
        // `authority` for `rest` in the refusal would still pass every other
        // test here while breaking each of these.
        "https://node.example/p@th",
        "https://node.example/?token=a@b",
        "https://node.example#frag@ment",
    ]
    .into_iter()
    .filter(|url| GrpcWebTransport::new(*url).is_err())
    .collect();
    assert!(
        refused.is_empty(),
        "should all have been accepted, but refused: {refused:?}"
    );
}

/// The `https://` userinfo refusal must redact exactly as the `http://` one
/// does — same `rsplit_once('@')` reasoning, same mutation risk. See
/// `the_userinfo_refusal_does_not_print_the_password` for why a password
/// containing `@` is the case that actually pins `rsplit` over `split`.
#[test]
fn the_https_userinfo_refusal_does_not_print_the_password() {
    for case in [
        "https://rpcuser:s3cr3t-password@node.example/",
        "https://rpcuser:pa@ss-w0rd@node.example/",
    ] {
        let err = GrpcWebTransport::new(case)
            .map(|_| ())
            .expect_err("userinfo must be refused");
        let message = err.to_string();
        assert!(
            !message.contains("s3cr3t-password") && !message.contains("ss-w0rd"),
            "the password leaked into the error message for {case:?}: {message}"
        );
    }
}

/// An endpoint we accept must be one `ureq` sends without credentials.
///
/// Every other test here asserts against a *string form*, which is exactly how
/// `https:///user:pass@host` slipped through: the authority was bounded by hand
/// at the first `/`, so a leading slash made it read as empty and the userinfo
/// check saw nothing — while `ureq`'s parser collapses those slashes and
/// addresses `host` with the credentials attached. Two parsers, two answers,
/// and the wrong one was doing the refusing.
///
/// So this pins the property that actually matters, against the real parser
/// rather than a transcription of it: **if we accept an endpoint, `url` must
/// agree it carries no username and no password.** A future divergence — a
/// separator WHATWG honours and this does not, a normalisation step it applies
/// first — fails here rather than in someone's log.
///
/// `url` is a dev-dependency for this test alone; `ureq` already builds the
/// same version, and cargo unifies them.
#[test]
fn the_authority_we_validate_is_the_one_ureq_connects_to() {
    // Shapes that differ between a hand-rolled bound and WHATWG: collapsed
    // slashes, backslashes, the tab/CR/LF the parser strips outright, and an
    // `@` that is genuinely past the authority and must stay allowed.
    let corpus = [
        "https://user:pass@evil.example",
        "https:///user:pass@evil.example",
        "https:////user:pass@evil.example",
        "https://\\/user:pass@evil.example",
        "https:/\\/user:pass@evil.example",
        "https://\t/user:pass@evil.example",
        "https://\r\n/user:pass@evil.example",
        "https://user:pa@ss-w0rd@evil.example",
        "https://[::1]@evil.example/",
        "https://node.example",
        "https://node.example/",
        "https://node.example:443/path",
        "https://node.example/p@th",
        "https://node.example/?token=a@b",
        "https://node.example#frag@ment",
        "https://[::1]:9067/",
        "http://localhost:9067",
        "http://127.0.0.1",
        "http://[::1]:9067",
        "http:///user:pass@evil.example",
        "http://user:pass@localhost",
    ];

    let mut leaked = Vec::new();
    for endpoint in corpus {
        if GrpcWebTransport::new(endpoint).is_err() {
            continue;
        }
        // `new` trims trailing slashes and `call` appends "/<path>", so this
        // is the shape ureq is actually handed.
        let parsed = match url::Url::parse(&format!("{}/x", endpoint.trim_end_matches('/'))) {
            Ok(parsed) => parsed,
            // If the parser refuses it outright, ureq cannot send credentials
            // anywhere — the request simply fails. Not a leak.
            Err(_) => continue,
        };
        if !parsed.username().is_empty() || parsed.password().is_some() {
            leaked.push((endpoint, parsed.host_str().unwrap_or("?").to_string()));
        }
    }
    assert!(
        leaked.is_empty(),
        "accepted endpoints that ureq would send credentials for: {leaked:?}"
    );
}

/// The *other* arm of `check_scheme`  — an endpoint that never even matches
/// `http://` or `https://` — used to echo the whole endpoint verbatim into
/// its refusal. The inputs that land here are mundane, not adversarial: an
/// uppercase `HTTPS://` typo, or a leading space pasted in from a YAML value
/// or an environment variable, and both are places a real password plausibly
/// sits. This must never print the password, only the scheme.
#[test]
fn the_unrecognised_scheme_refusal_does_not_print_the_password() {
    let cases = [
        "HTTPS://user:s3cr3t-password@host/",
        " http://user:s3cr3t-password@localhost/",
        "ftp://user:s3cr3t-password@host/",
        "user:s3cr3t-password@localhost",
        // The mangled form of `https://user:pass@host` — credentials typed
        // *before* the scheme instead of after it. Whatever precedes the
        // first `://` here is not a scheme at all, so taking it verbatim
        // would leak the password the same way the bare `user:pass@host`
        // case above does.
        "user:s3cr3t-password@https://node.example",
    ];
    for case in cases {
        let err = GrpcWebTransport::new(case)
            .map(|_| ())
            .expect_err("an unrecognised scheme must be refused");
        let message = err.to_string();
        assert!(
            !message.contains("s3cr3t-password"),
            "the password leaked into the error message for {case:?}: {message}"
        );
    }
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
