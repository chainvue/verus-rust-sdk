//! The offline crates must not acquire an HTTP stack.
//!
//! `verus-wire`, `verus-keys`, `verus-tx` and `verus-sapling` never open a
//! socket. That is not a style preference: it is what makes them usable from an
//! air-gapped signer, a hardware wallet and a wasm build, and what keeps them
//! deterministically testable byte-for-byte against the TypeScript SDK.
//!
//! Until now the claim was enforced by nothing but care. A transitive dependency
//! that quietly pulls in `reqwest` would break it silently — the crates would
//! still compile, still pass every test, and still be unusable in the
//! environments they were built for.

use std::process::Command;

/// Anything that can open a socket.
const NETWORK_CRATES: &[&str] = &[
    "ureq",
    "reqwest",
    "hyper",
    "curl",
    "isahc",
    "surf",
    "attohttpc",
    "tonic",
    "tokio",
    "async-std",
    "rustls",
    "native-tls",
    "openssl",
];

fn dependency_tree(package: &str) -> String {
    let output = Command::new(env!("CARGO"))
        .args([
            "tree",
            "-p",
            package,
            "-e",
            "normal",
            "--all-features",
            "--prefix",
            "none",
        ])
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
        .output()
        .expect("cargo tree runs");
    assert!(
        output.status.success(),
        "cargo tree -p {package} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn the_offline_crates_pull_in_no_http_stack() {
    for package in ["verus-wire", "verus-keys", "verus-tx", "verus-sapling"] {
        let tree = dependency_tree(package);
        for network in NETWORK_CRATES {
            // Match a crate name at the start of a line, so `tokio-util` in
            // someone's description does not read as `tokio`.
            let found = tree
                .lines()
                .any(|line| line.split_whitespace().next() == Some(network));
            assert!(
                !found,
                "{package} depends on {network}: it is supposed to be socket-free\n{tree}"
            );
        }
    }
}

/// The facade must stay usable without a network stack too — a consumer taking
/// `verus-sdk` for its builders should not link an HTTP client to get them.
#[test]
fn the_facade_pulls_in_no_http_stack_by_default() {
    let tree = dependency_tree("verus-sdk");
    for network in NETWORK_CRATES {
        let found = tree
            .lines()
            .any(|line| line.split_whitespace().next() == Some(network));
        assert!(
            !found,
            "verus-sdk depends on {network} with all features on\n{tree}"
        );
    }
}

/// And the check must be capable of finding something, or it passes vacuously.
/// `verus-rpc` and `verus-light` *do* carry an HTTP client, by design.
#[test]
fn the_check_can_actually_detect_an_http_stack() {
    for package in ["verus-rpc", "verus-light"] {
        let tree = dependency_tree(package);
        assert!(
            tree.lines()
                .any(|line| line.split_whitespace().next() == Some("ureq")),
            "{package} should carry ureq under --all-features; the check found nothing:\n{tree}"
        );
    }
}
