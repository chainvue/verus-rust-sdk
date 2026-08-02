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

/// The facade features that must never pull in an HTTP stack. One list, used
/// both to build the `--features` argument under test and to classify the
/// feature set — two copies would let a feature be "classified offline" while
/// never actually being screened.
const OFFLINE_FEATURES: &[&str] = &["transparent", "shielded", "prover", "multicore", "serde"];

/// The facade features that exist to pull the network half in.
const NETWORK_FEATURES: &[&str] = &["network", "light"];

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

fn dependency_tree_with(package: &str, feature_args: &[&str]) -> String {
    // `--target all`, not the host default. `verus-wasm` already carries a
    // `[target.'cfg(target_arch = "wasm32")'.dependencies]` section, and a
    // host-resolved tree cannot see inside one — so a wasm-gated HTTP client
    // (`reqwest` compiles to wasm over `fetch`, and would be *useful* there)
    // would ship in the browser artifact while this test reported it clean.
    //
    // That is the one place where the screen being wrong matters most: the
    // browser is the environment the claim is really about.
    let mut args = vec![
        "tree", "-p", package, "-e", "normal", "--prefix", "none", "--target", "all",
    ];
    args.extend_from_slice(feature_args);
    let output = Command::new(env!("CARGO"))
        .args(&args)
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

fn dependency_tree(package: &str) -> String {
    dependency_tree_with(package, &["--all-features"])
}

#[test]
fn the_offline_crates_pull_in_no_http_stack() {
    // `verus-wasm` is on this list for a sharper reason than the rest: it is
    // the crate a browser loads, and a browser is the one place where an HTTP
    // client compiled into the module would be both useless — `wasm32` has no
    // sockets — and a misrepresentation of what the page talks to. It builds
    // and signs; the page does the fetching.
    for package in [
        "verus-wire",
        "verus-keys",
        "verus-tx",
        "verus-sapling",
        "verus-wasm",
    ] {
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

/// The facade must stay usable without a network stack — a consumer taking
/// `verus-sdk` for its builders should not link an HTTP client to get them.
///
/// Checked with every *offline* feature enabled, not `--all-features`: the
/// `network` and `light` features exist precisely to pull the HTTP half in, so
/// the claim being defended is "you get a socket only by asking for one".
#[test]
fn the_facade_pulls_in_no_http_stack_without_network() {
    let features = OFFLINE_FEATURES.join(",");
    let tree = dependency_tree_with("verus-sdk", &["--features", &features]);
    for network in NETWORK_CRATES {
        let found = tree
            .lines()
            .any(|line| line.split_whitespace().next() == Some(network));
        assert!(
            !found,
            "verus-sdk depends on {network} without the network feature\n{tree}"
        );
    }
}

/// And opting in does what it says: `network` carries the HTTP client. This is
/// the detectability check for the test above — if the feature wiring broke,
/// both halves of the claim should fail, not silently pass.
#[test]
fn the_facades_network_feature_carries_the_http_stack() {
    let tree = dependency_tree_with("verus-sdk", &["--features", "network"]);
    assert!(
        tree.lines()
            .any(|line| line.split_whitespace().next() == Some("ureq")),
        "verus-sdk --features network should carry ureq; the wiring is broken:\n{tree}"
    );
}

/// Same for `light`: it must actually wire in the lightwalletd client. `ureq`
/// alone would not prove that — it already arrives through the implied
/// `network` — so this looks for `verus-light` itself.
#[test]
fn the_facades_light_feature_carries_the_lightwalletd_client() {
    let tree = dependency_tree_with("verus-sdk", &["--features", "light"]);
    assert!(
        tree.lines()
            .any(|line| line.split_whitespace().next() == Some("verus-light")),
        "verus-sdk --features light should carry verus-light; the wiring is broken:\n{tree}"
    );
}

/// The offline feature list above is hardcoded, and that is a drift risk: a
/// feature added to `verus-sdk` later would silently escape the no-HTTP check.
/// This pins the full feature set, so adding one fails *here* until the person
/// adding it decides which side of the offline/network line it lives on.
#[test]
fn every_facade_feature_is_classified_as_offline_or_network() {
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
        .output()
        .expect("cargo metadata runs");
    assert!(output.status.success(), "cargo metadata failed");
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata emits JSON");

    let features: Vec<&str> = metadata["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .find(|p| p["name"] == "verus-sdk")
        .expect("verus-sdk is in the workspace")["features"]
        .as_object()
        .expect("features")
        .keys()
        .map(String::as_str)
        .collect();

    for feature in features {
        assert!(
            feature == "default"
                || OFFLINE_FEATURES.contains(&feature)
                || NETWORK_FEATURES.contains(&feature),
            "verus-sdk grew a feature {feature:?} this test does not classify: add it to \
             OFFLINE_FEATURES (which also puts it under the no-HTTP screen) or to \
             NETWORK_FEATURES, whichever is true"
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
