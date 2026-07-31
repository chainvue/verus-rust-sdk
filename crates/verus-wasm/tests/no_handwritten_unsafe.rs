//! This crate relaxes `unsafe_code`, so something else has to hold the line.
//!
//! Every other crate in the workspace inherits `unsafe_code = "forbid"`. This
//! one cannot: `#[wasm_bindgen]` expands to `unsafe extern` shims and `unsafe
//! impl` marker traits, and `forbid` cannot be overridden by an `allow` inside
//! a macro expansion. Relaxing the lint is therefore forced — but it relaxes it
//! for *everything*, including code someone writes by hand.
//!
//! So the property the lint protected is restated as something a lint cannot
//! express and this test can: **the binding macro may emit unsafe; a person may
//! not write it.** Every byte of `unsafe` in the compiled crate comes from
//! `wasm-bindgen`'s expansion, and is auditable by reading `wasm-bindgen`
//! rather than by reading this crate.

use std::fs;
use std::path::Path;

/// The crate's own sources, recursively.
fn sources(directory: &Path, into: &mut Vec<(String, String)>) {
    for entry in fs::read_dir(directory).expect("the source directory is readable") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            sources(&path, into);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = fs::read_to_string(&path).expect("a source file is readable");
            into.push((path.display().to_string(), text));
        }
    }
}

/// Whether `line` writes `unsafe` as Rust rather than mentioning it in prose.
///
/// Doc comments and ordinary comments discuss the word — this file is full of
/// it — so they are excluded. What is left is code.
fn writes_unsafe(line: &str) -> bool {
    let code = line.trim_start();
    if code.starts_with("//") || code.starts_with("*") || code.starts_with("#!") {
        return false;
    }
    let code = code.split("//").next().unwrap_or(code);
    code.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|word| word == "unsafe")
}

#[test]
fn no_source_file_in_this_crate_writes_unsafe() {
    let mut files = Vec::new();
    sources(
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src")),
        &mut files,
    );
    assert!(!files.is_empty(), "the crate has sources to check");

    for (path, text) in &files {
        for (number, line) in text.lines().enumerate() {
            assert!(
                !writes_unsafe(line),
                "{path}:{} writes `unsafe`. This crate relaxes `unsafe_code` only so \
                 that `#[wasm_bindgen]` can expand; hand-written unsafe is not covered \
                 by that reason and is not reviewed by anyone.\n  {line}",
                number + 1
            );
        }
    }
}

/// And the detector must be able to find something, or it passes vacuously.
#[test]
fn the_check_can_actually_detect_unsafe() {
    assert!(writes_unsafe("    unsafe { *pointer }"));
    assert!(writes_unsafe("unsafe impl Send for Handle {}"));
    assert!(writes_unsafe(
        "pub unsafe fn read(p: *const u8) -> u8 { *p }"
    ));
    // …and must not fire on prose, or every doc comment here would trip it.
    assert!(!writes_unsafe("//! hand-written unsafe is not permitted"));
    assert!(!writes_unsafe(
        "    /// unsafe extern shims come from the macro"
    ));
    assert!(!writes_unsafe(
        "    let x = 1; // unsafe would be wrong here"
    ));
    // A variable that merely contains the word is not the keyword.
    assert!(!writes_unsafe("    let unsafely_named = 1;"));
}
