//! The minimum supported Rust version is declared in three places. They must
//! agree.
//!
//! * `rust-toolchain.toml` — what a contributor's `cargo` picks up.
//! * `Cargo.toml`'s `rust-version` — what a consumer's resolver honours.
//! * `.github/workflows/ci.yml` — what actually gets compiled before merge.
//!
//! `dtolnay/rust-toolchain` reads its version from the workflow input and
//! **not** from `rust-toolchain.toml`, so the two can silently disagree.
//! `CONTRIBUTING.md` warns about this in prose — "change one, change the
//! other" — and prose does not fail a build.
//!
//! The failure is quiet and one-directional. Raise the CI pin without raising
//! `rust-version` and CI goes green on a compiler newer than the one this
//! crate promises to build on; the first person to find out is a consumer on
//! the older toolchain, at `cargo build`. Raise `rust-version` without CI and
//! nothing verifies the new floor at all.
//!
//! This is the cheapest possible check and it replaces a comment with a test.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root is two levels above this crate")
}

fn read(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// `channel = "1.95.0"` -> `1.95.0`
fn toolchain_file_version(text: &str) -> String {
    text.lines()
        .find_map(|line| line.trim().strip_prefix("channel"))
        .and_then(|rest| rest.split('"').nth(1))
        .expect("rust-toolchain.toml declares a channel")
        .to_string()
}

/// `rust-version = "1.95"` -> `1.95`
fn manifest_version(text: &str) -> String {
    text.lines()
        .find_map(|line| line.trim().strip_prefix("rust-version"))
        .and_then(|rest| rest.split('"').nth(1))
        .expect("the workspace manifest declares rust-version")
        .to_string()
}

/// Every `toolchain: '1.95.0'` in the workflow, so a job added later that
/// pins a different version is caught too.
fn workflow_versions(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.trim().strip_prefix("toolchain:"))
        .map(|rest| rest.trim().trim_matches(['\'', '"']).to_string())
        // `nightly` is deliberate — the fuzz job needs `-Zsanitizer`, and it
        // is not claiming to be the MSRV.
        .filter(|version| version != "nightly")
        .collect()
}

#[test]
fn every_declaration_of_the_msrv_agrees() {
    let toolchain = toolchain_file_version(&read("rust-toolchain.toml"));
    let manifest = manifest_version(&read("Cargo.toml"));
    let workflow = workflow_versions(&read(".github/workflows/ci.yml"));

    assert!(
        !workflow.is_empty(),
        "no pinned toolchain found in ci.yml — the MSRV is not being compiled anywhere"
    );

    for pinned in &workflow {
        assert_eq!(
            pinned, &toolchain,
            "ci.yml pins {pinned} but rust-toolchain.toml says {toolchain}; \
             dtolnay/rust-toolchain reads the workflow, not the file, so these \
             drift silently"
        );
    }

    // `rust-version` may be `1.95` where the toolchain is `1.95.0`: cargo
    // treats a two-component version as "any patch of that minor". Anything
    // else is a mismatch.
    assert!(
        toolchain == manifest || toolchain.strip_prefix(&format!("{manifest}.")).is_some(),
        "Cargo.toml promises rust-version {manifest} but the toolchain is {toolchain}"
    );
}
