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

/// Every text file in the crate, recursively.
///
/// Deliberately not filtered to `*.rs`. `include!` takes any path, so code in
/// `evil.rs.in` compiles exactly as if it had been typed into `lib.rs` while
/// having the wrong extension to be noticed — and `build.rs` is compiled too.
/// The cost of reading a few extra files is nothing next to a check that can be
/// stepped around by renaming one.
fn sources(directory: &Path, into: &mut Vec<(String, String)>) {
    for entry in fs::read_dir(directory).expect("the crate directory is readable") {
        let path = entry.expect("a directory entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // `pkg` is the built wasm bundle and `target` is build output; neither
        // is this crate's source, and both are large.
        if name == "pkg" || name == "target" || name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            sources(&path, into);
        } else if let Ok(text) = fs::read_to_string(&path) {
            // Unreadable as UTF-8 means it is not source, so it cannot be
            // `include!`d as source either.
            into.push((path.display().to_string(), text));
        }
    }
}

/// The lines of `text` that write `unsafe` as Rust, with their 1-based numbers.
///
/// Four things say the word without being it, and all four are excluded:
/// comments (`//`, `/*`, a continuation `*`, and `#` for TOML), and **string
/// literals**. The literals are why this walks a whole file rather than a line
/// at a time — a Rust string can span lines, and this file's own panic message
/// does, so a continuation line has to be known to be inside one. Getting that
/// wrong is what made an earlier version report itself.
///
/// Raw strings (`r#"…"#`) are **not** understood: their inner quotes toggle the
/// state the wrong way, so their contents read as code. That is left alone
/// deliberately, because it errs toward a false *positive* — a contributor who
/// puts the word in a raw string gets a loud failing test, never a silent
/// bypass — and a bypass is the only failure this check exists to prevent.
fn offending_lines(text: &str) -> Vec<(usize, String)> {
    let mut offenders = Vec::new();
    let mut inside_string = false;
    let mut escaped = false;

    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        let is_comment = !inside_string
            && ["//", "/*", "*", "#"]
                .iter()
                .any(|opener| trimmed.starts_with(opener));

        let mut bare = String::with_capacity(line.len());
        let mut chars = line.chars().peekable();
        while let Some(character) = chars.next() {
            if inside_string {
                match character {
                    _ if escaped => escaped = false,
                    '\\' => escaped = true,
                    '"' => inside_string = false,
                    _ => {}
                }
                continue;
            }
            // An ordinary comment ends the line for our purposes, but only
            // outside a string — a `//` inside one is just text.
            if character == '/' && chars.peek() == Some(&'/') {
                break;
            }
            if character == '"' {
                inside_string = true;
                escaped = false;
                continue;
            }
            bare.push(character);
        }
        // A string left open at end of line continues; a Rust literal that is
        // not continued would not compile, so this cannot silently swallow a
        // whole file of real code.

        if is_comment {
            continue;
        }
        if bare
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .any(|word| word == "unsafe")
        {
            offenders.push((index + 1, line.to_string()));
        }
    }
    offenders
}

/// Whether a single line writes `unsafe`. Convenience for the self-test.
fn writes_unsafe(line: &str) -> bool {
    !offending_lines(line).is_empty()
}

#[test]
fn no_source_file_in_this_crate_writes_unsafe() {
    let mut files = Vec::new();
    sources(Path::new(env!("CARGO_MANIFEST_DIR")), &mut files);
    assert!(
        files.len() > 5,
        "the crate has sources to check, got {}",
        files.len()
    );
    // The scan must actually reach the crate's own modules, not merely find
    // *some* files.
    assert!(
        files.iter().any(|(path, _)| path.ends_with("src/dto.rs")),
        "the scan did not reach the crate's modules"
    );

    let offenders: Vec<String> = files
        .iter()
        .flat_map(|(path, text)| {
            offending_lines(text)
                .into_iter()
                .map(move |(number, line)| format!("{path}:{number}\n  {line}"))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "hand-written `unsafe`. This crate relaxes the lint only so that the binding \
         macro can expand; code a person writes is not covered by that reason and is \
         reviewed by nobody.\n{}",
        offenders.join("\n")
    );
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
    // A string literal says it without being it — which is what the lines
    // just above are, since the scan reads this file too.
    assert!(!writes_unsafe(
        "    let message = \"unsafe is forbidden here\";"
    ));
    assert!(!writes_unsafe("    assert!(check(\"unsafe { *p }\"));"));
    // But code beside a literal is still code.
    assert!(writes_unsafe("    let m = \"note\"; unsafe { read() }"));
    // Comment styles from the other languages the scan reaches.
    assert!(!writes_unsafe("# unsafe extern shims, in a TOML comment"));
    assert!(!writes_unsafe("/** unsafe, in a JSDoc block */"));
}
