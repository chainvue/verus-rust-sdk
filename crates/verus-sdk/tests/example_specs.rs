//! The checked-in example specs must actually run.
//!
//! `examples/specs/*.json` exist so that every example in the README is one
//! copy-pasted line rather than a schema a reader has to fill in. That only
//! holds while they work, and a spec is exactly the kind of thing that rots
//! silently: it is not compiled, nothing imports it, and an example whose
//! field names drift leaves the file behind, still valid JSON, still wrong.
//!
//! So each one is actually run here, against the same example binary a reader
//! invokes. That is slower than parsing the JSON and checking for keys, and it
//! is the only version of this test that can fail for the right reason —
//! asserting that `spec.utxos` exists would not have noticed a builder that
//! started refusing the transaction the spec describes.
//!
//! Specs deliberately absent:
//!
//! * `spend_note` — needs a spending key for a note that exists on chain.
//!   The repository has the note (`fixtures/daemon/sapling_tree.json`) and not
//!   the key, which is correct: the key controls real testnet money. Use
//!   `spend_note_online`, which assembles the same inputs from a scan.
//! * The online examples — they need a node, and a test that needs a node is
//!   not run by default here. See `tests/live_daemon.rs` in `verus-rpc`.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

/// The feature set this test binary was compiled with, as a `--features`
/// argument.
///
/// Reconstructed rather than hardcoded so the examples are built with the
/// *same* feature resolution as the harness around them. A hardcoded string
/// would make Cargo rebuild `verus-sdk` from scratch on any job whose flags
/// differ from it, and would quietly test a different build than the one the
/// `#[cfg(feature = …)]` gates below selected.
fn features() -> String {
    let mut on = Vec::new();
    for (name, enabled) in [
        ("transparent", cfg!(feature = "transparent")),
        ("shielded", cfg!(feature = "shielded")),
        ("prover", cfg!(feature = "prover")),
        ("multicore", cfg!(feature = "multicore")),
        ("serde", cfg!(feature = "serde")),
        ("network", cfg!(feature = "network")),
        ("light", cfg!(feature = "light")),
    ] {
        if enabled {
            on.push(name);
        }
    }
    on.join(",")
}

fn repo_root() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

/// Build every example once, and answer where the binaries landed.
///
/// One `cargo build`, not one `cargo run` per example. The naive version —
/// `cargo run --example` inside each test, which is exactly the command a
/// reader types — costs two minutes rather than two seconds, because the nine
/// nested Cargo processes all queue on the same build lock. What the tests
/// actually need is the binary; this builds it and then runs it directly.
fn examples_dir() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let status = Command::new(env!("CARGO"))
            .args([
                "build",
                "--quiet",
                "-p",
                "verus-sdk",
                "--features",
                &features(),
                "--examples",
            ])
            .current_dir(repo_root())
            .status()
            .expect("cargo build starts");
        assert!(status.success(), "the examples do not build");

        // This test binary is `<target>/<profile>/deps/example_specs-<hash>`,
        // and the examples are its siblings' neighbours. Derived rather than
        // assumed, so a custom CARGO_TARGET_DIR or a non-debug profile does
        // not silently run a stale binary from somewhere else.
        let mut path = std::env::current_exe().expect("the test knows its own path");
        path.pop();
        if path.ends_with("deps") {
            path.pop();
        }
        path.join("examples")
    })
}

/// Run `example` with `specs/<spec>.json` on stdin and return its stdout.
///
/// Panics with the example's own stderr, which is where the useful message is:
/// a spec that has drifted fails as `Error: "spec.recipients"`, naming the
/// field, and swallowing that would leave only "exit code 1".
fn run(example: &str, spec: &str) -> String {
    let root = repo_root();
    let spec_path = root.join("crates/verus-sdk/examples/specs").join(spec);
    let json = std::fs::read(&spec_path)
        .unwrap_or_else(|e| panic!("{} is missing: {e}", spec_path.display()));

    let binary = examples_dir().join(example);
    let mut child = Command::new(&binary)
        .current_dir(&root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("{} does not run: {e}", binary.display()));

    use std::io::Write as _;
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(&json)
        .expect("the spec is written to the example");

    let output = child.wait_with_output().expect("the example finishes");
    assert!(
        output.status.success(),
        "`cargo run --example {example} < specs/{spec}` failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("the example prints UTF-8")
}

/// A signed transaction, whichever example produced it.
fn assert_signed(out: &str, example: &str) {
    let value: serde_json::Value =
        serde_json::from_str(out).unwrap_or_else(|e| panic!("{example} printed non-JSON: {e}"));
    let hex = value["hex"].as_str().unwrap_or_else(|| {
        panic!("{example} printed no `hex`: {out}");
    });
    assert!(!hex.is_empty(), "{example} produced an empty transaction");
    assert!(
        value["txid"].as_str().is_some_and(|t| t.len() == 64),
        "{example} produced no usable txid: {out}"
    );
}

#[test]
fn the_send_spec_reproduces_the_differential_vector() {
    let out = run("send", "send.json");
    let value: serde_json::Value = serde_json::from_str(&out).expect("JSON");

    // Not merely "it built something". `specs/send.json` is the first vector
    // of `fixtures/transparent/vectors.json`, which is byte-checked against the
    // TypeScript SDK — so the expected txid is known, and this pins the spec to
    // the same bytes the differential covers.
    let vectors: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo_root().join("fixtures/transparent/vectors.json"))
            .expect("vectors"),
    )
    .expect("JSON");
    let expected = &vectors["vectors"][0]["expected_txid"];
    assert_eq!(
        value["txid"], *expected,
        "specs/send.json no longer builds the transaction its vector describes"
    );
}

#[test]
fn the_send_token_spec_conserves_its_tokens() {
    let out = run("send_token", "send_token.json");
    let value: serde_json::Value = serde_json::from_str(&out).expect("JSON");
    assert_signed(&out, "send_token");

    // Token value in must equal token value out, or the difference was
    // destroyed. The builder enforces it; this asserts the spec still
    // exercises the case where it matters, i.e. one with token change.
    assert!(
        !value["tokens_in"].as_array().expect("tokens_in").is_empty(),
        "send_token.json stopped spending any token: {out}"
    );
}

#[test]
fn the_registration_specs_build_both_halves() {
    let step1 = run("register_id", "register_id.step1.json");
    assert_signed(&step1, "register_id step 1");

    let step2 = run("register_id", "register_id.step2.json");
    assert_signed(&step2, "register_id step 2");

    // Step 2 spends the commitment step 1 creates, and step 1's salt is
    // random — so a checked-in step 2 is only valid against the *recorded*
    // step 1, not a fresh one. If this ever fails, regenerate both together.
    let first: serde_json::Value = serde_json::from_str(&step1).expect("JSON");
    let spec: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            repo_root().join("crates/verus-sdk/examples/specs/register_id.step2.json"),
        )
        .expect("step 2 spec"),
    )
    .expect("JSON");
    assert_ne!(
        spec["salt"], first["salt"],
        "step 1 is supposed to draw a fresh salt every run; if these match, \
         the example stopped generating one"
    );
}

#[test]
fn the_identity_specs_update_and_revoke_the_identity_the_registration_built() {
    assert_signed(&run("update_id", "update_id.json"), "update_id");
    // Revocation is refused for an identity that is its own revocation
    // authority — so this passing also confirms the registration spec still
    // points its authorities elsewhere, which is the whole reason it does.
    assert_signed(&run("revoke_id", "revoke_id.json"), "revoke_id");
}

#[cfg(feature = "shielded")]
#[test]
fn the_read_notes_spec_still_decrypts_the_note_it_is_about() {
    let out = run("read_notes", "read_notes.json");
    let value: serde_json::Value = serde_json::from_str(&out).expect("JSON");
    let notes = value["notes"].as_array().expect("notes");
    assert_eq!(notes.len(), 1, "expected exactly our own note: {out}");

    // The values recorded in `fixtures/daemon/shielded_memo.json`, which came
    // off VRSCTEST. A viewing key recovers all three.
    assert_eq!(notes[0]["satoshis"], 50_000_000);
    assert_eq!(notes[0]["memo"], "sent by verus-rust-sdk");
}

#[cfg(feature = "shielded")]
#[test]
fn the_shielded_keygen_spec_derives_the_documented_account() {
    let out = run("keygen_shielded", "keygen_shielded.json");
    let value: serde_json::Value = serde_json::from_str(&out).expect("JSON");
    assert_eq!(
        value["path"], "m/32'/133'/0'",
        "the derivation path changed: {out}"
    );
    assert!(
        value["address"]
            .as_str()
            .is_some_and(|a| a.starts_with("zs1")),
        "no shielded address: {out}"
    );
}

/// `shield` needs the ~50 MB of Sapling parameters, so it runs only where they
/// are. Skipped rather than failed: their absence says nothing about the spec.
#[cfg(feature = "prover")]
#[test]
fn the_shield_spec_builds_a_proof_where_the_parameters_exist() {
    if std::env::var("VERUS_SAPLING_PARAMS").is_err() {
        eprintln!("skipping: set VERUS_SAPLING_PARAMS to the ZcashParams directory");
        return;
    }
    let out = run("shield", "shield.json");
    let value: serde_json::Value = serde_json::from_str(&out).expect("JSON");
    assert_signed(&out, "shield");
    assert!(
        value["value_balance"].as_i64().is_some_and(|v| v < 0),
        "a t→z moves value INTO the pool, so valueBalance must be negative: {out}"
    );
}
