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
///
/// `socket2` and `mio` are the ones that matter most here: nearly every Rust
/// network stack (Tokio's reactor included) bottoms out in one or both, so an
/// HTTP client arriving under a name not otherwise on this list would still
/// be caught through them. `polling`, `minreq` and `smol` are smaller
/// runtimes/clients that reach the network the same way `async-std` and
/// `tokio` do, and belong on the list for the same reason those do.
///
/// If one of these ever shows up in an offline crate's tree for a real,
/// audited non-network reason — `mio` for file-watching, `polling` for
/// terminal input, that kind of thing — the fix is to say so in a comment on
/// that entry (or split it into a separate, narrower list), not to delete the
/// name. Deleting it re-opens the gap this list exists to close.
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
    "socket2",
    "mio",
    "polling",
    "minreq",
    "smol",
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

/// Whether `crate_name` names a package in a `cargo tree --prefix none`
/// listing. Matches a crate name at the start of a line, so `tokio-util` in
/// someone's description does not read as `tokio`.
///
/// The one predicate every assertion below shares, on purpose: a copy pasted
/// into the tests that check this rule would let the tests and the rule
/// drift apart, so that the tests kept passing after the rule itself changed.
fn tree_contains(tree: &str, crate_name: &str) -> bool {
    tree.lines()
        .any(|line| line.split_whitespace().next() == Some(crate_name))
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
            assert!(
                !tree_contains(&tree, network),
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
        assert!(
            !tree_contains(&tree, network),
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
        tree_contains(&tree, "ureq"),
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
        tree_contains(&tree, "verus-light"),
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
            tree_contains(&tree, "ureq"),
            "{package} should carry ureq under --all-features; the check found nothing:\n{tree}"
        );
    }
}

/// `socket2`, `mio`, `polling`, `minreq` and `smol` were added to
/// `NETWORK_CRATES` by this change, and none of them is a real dependency —
/// direct or transitive — of anything in this workspace today: `ureq` 2.x
/// talks to `std::net` directly and pulls in neither `mio` nor `socket2`.
/// (`mio` and `socket2` do show up in `cargo tree`'s default output, but only
/// under `verus-sdk`'s `drive_async` example, as dev-dependencies of `tokio`
/// and `reqwest` — outside the `-e normal` edges this screen walks, and not
/// something that ships.)
///
/// That means the tests above never exercise the five new names against a
/// tree that could contain them, so nothing here proves the screen would
/// actually catch one if it arrived. Two things can still be pinned without a
/// real occurrence to point at:
///
/// - that the names are actually on the list, so a future edit cannot delete
///   one back off `NETWORK_CRATES` without a test noticing;
/// - that the shared matching rule (`tree_contains`, the same function every
///   real assertion above calls) tells a crate from a same-prefixed neighbor
///   — `mio` from `mio-extras`, `socket2` from `socket2-util` — which is a
///   real property of the production rule, not a fact about these five names.
///
/// What this cannot do is prove the rule would fire on a genuine, present-day
/// `mio`/`socket2`/etc. line, because there isn't one in this workspace to
/// test against.
#[test]
fn the_newly_added_transport_crates_are_on_the_list_and_the_matcher_respects_word_boundaries() {
    for network in ["socket2", "mio", "polling", "minreq", "smol"] {
        assert!(
            NETWORK_CRATES.contains(&network),
            "{network} was removed from NETWORK_CRATES: this is a silent regression, \
             re-opening the exact gap issue #142 closed"
        );
    }

    // Same-prefixed neighbors must not read as the crate itself — the same
    // guard the `tokio` / `tokio-util` comment on `tree_contains` describes,
    // checked here for the names this change adds. Goes through the shared
    // predicate, not a copy of it, so this actually guards production code.
    let decoy_tree = "mio-extras v2.0.0\nsocket2-util v0.1.0\n";
    for network in ["mio", "socket2"] {
        assert!(
            !tree_contains(decoy_tree, network),
            "tree_contains false-positived on a `{network}`-prefixed neighbor:\n{decoy_tree}"
        );
    }
}
