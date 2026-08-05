//! This crate must never generate a key.
//!
//! Every constructor here takes bytes the caller supplies. That is the whole
//! security position of the crate, and it is worth stating why it is a position
//! rather than an omission.
//!
//! # Entropy cannot be tested, so it must be visible
//!
//! Everything else in this crate is deterministic and therefore checkable: a
//! phrase maps to an address, and a vector proves it. The one thing no test can
//! check is where random bytes came from — 32 bytes from a hardware source and
//! 32 bytes from `sha256(counter)` are statistically indistinguishable, because
//! entropy is a property of the process that produced them, not of the bytes.
//!
//! The only defence against that is to put the entropy source where a reviewer
//! sees it. So a caller writes
//!
//! ```no_run
//! # use verus_keys::PrivateKey;
//! let mut entropy = [0u8; 32];
//! getrandom::getrandom(&mut entropy)?;              // in the application
//! let key = PrivateKey::from_bytes(&entropy, true)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! and the choice is one line in their own code. Add a `PrivateKey::generate()`
//! and that decision moves into a dependency, where every consumer inherits it
//! silently and none of them can audit it. That is the shape of the incidents
//! this guards against: the generator lived in the library or the firmware, its
//! users had no visibility into it, and the keys it produced were valid,
//! well-formed, and searchable.
//!
//! # What this test can and cannot do
//!
//! It cannot stop anyone determined — a contributor who wants a generator will
//! edit this file too. What it does is make that edit **loud**: the invariant
//! stops being something a reviewer has to remember and becomes something a
//! diff shows them, on a line whose only purpose is to say what is being given
//! up.
//!
//! # Why this is not a dependency-tree test
//!
//! `verus-keys` declares no RNG, but `rand_core` and `getrandom` *are* in its
//! tree, pulled in by `k256` for the traits `elliptic-curve` is generic over.
//! So "no RNG in the dependency graph" is not true and cannot be asserted. What
//! is true, and what matters, is that no code in this crate calls one — a
//! generator would have to be written here, and that is what is checked.

use std::path::{Path, PathBuf};

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file under `src/`.
fn sources() -> Vec<PathBuf> {
    fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("src/ is readable").flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else if path.extension().is_some_and(|e| e == "rs") {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    walk(&crate_root().join("src"), &mut found);
    assert!(!found.is_empty(), "found no sources to check");
    found
}

/// Strip `//` and `//!` comments, so prose about randomness does not trip the
/// scan. Doc comments here discuss `OsRng` and entropy at length, and a check
/// that fired on documentation would be turned off within a week.
fn code_only(text: &str) -> String {
    text.lines()
        .map(|line| match line.find("//") {
            Some(at) => &line[..at],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// No randomness is drawn anywhere in this crate.
#[test]
fn nothing_in_this_crate_asks_for_random_bytes() {
    // Every way to reach an RNG that this crate's dependencies actually offer.
    // `k256` re-exports `elliptic-curve`'s generic constructors, so the k256
    // spellings are listed too: `SigningKey::random(&mut rng)` needs no `rand`
    // import at all and would otherwise pass unnoticed.
    const FORBIDDEN: &[&str] = &[
        "OsRng",
        "thread_rng",
        "getrandom",
        "rand::",
        "rand_core",
        "SeedableRng",
        // `::` on purpose. The needle is `StdRng::from_entropy()`, which seeds a
        // PRNG from the OS; without the separator it also matches
        // `bip39::mnemonic_from_entropy`, which *takes* 32 bytes from the caller
        // and is precisely the shape this crate is supposed to have. Caught by
        // the first run of this test, which is the argument for writing the
        // detectability check below.
        "::from_entropy(",
        "::random(",
        "random_bytes",
    ];

    for path in sources() {
        let text = std::fs::read_to_string(&path).expect("a source file is readable");
        let code = code_only(&text);
        for needle in FORBIDDEN {
            assert!(
                !code.contains(needle),
                "{} mentions `{needle}` in code.\n\n\
                 This crate is not allowed to generate randomness. If a key needs to be \
                 created, the caller supplies the 32 bytes — see this file's header for \
                 why that is the security position and not an oversight.",
                path.strip_prefix(crate_root()).unwrap_or(&path).display()
            );
        }
    }
}

/// And no public item offers to make a key out of nothing.
///
/// The check above would already catch an implementation, but this catches the
/// *shape* — a `generate()` that took an RNG from the caller would pass the scan
/// and still move the decision into this crate's API, where the next convenience
/// wrapper defaults it.
#[test]
fn no_public_item_offers_to_generate_a_key() {
    const FORBIDDEN: &[&str] = &[
        "pub fn generate",
        "pub fn random",
        "pub fn new_random",
        "pub fn from_rng",
    ];

    for path in sources() {
        let text = std::fs::read_to_string(&path).expect("a source file is readable");
        let code = code_only(&text);
        for needle in FORBIDDEN {
            assert!(
                !code.contains(needle),
                "{} declares `{needle}…`.\n\n\
                 Key generation belongs with the vault that will store the result, not \
                 with the code that signs. See this file's header.",
                path.strip_prefix(crate_root()).unwrap_or(&path).display()
            );
        }
    }
}

/// The scan must be able to find something, or it passes vacuously.
///
/// Every assertion above is a `!contains`, and those keep passing if the file
/// list is empty, the reader silently returns nothing, or `code_only` eats the
/// whole file. This plants each forbidden string in a string that goes through
/// exactly the same pipeline and checks it is seen.
#[test]
fn the_scan_can_actually_detect_a_generator() {
    let planted = "fn oops() { let mut r = OsRng; }\n\
                   pub fn generate() -> PrivateKey { todo!() }\n\
                   let k = SigningKey::random(&mut rng);";
    let code = code_only(planted);

    for needle in ["OsRng", "pub fn generate", "::random("] {
        assert!(
            code.contains(needle),
            "the scan would not have found `{needle}`; it is checking nothing"
        );
    }

    // And the comment stripper must not be so eager that it hides real code.
    let with_comment = code_only("let mut r = OsRng; // a comment mentioning thread_rng");
    assert!(with_comment.contains("OsRng"), "the stripper ate real code");
    assert!(
        !with_comment.contains("thread_rng"),
        "the stripper left comment text in, so prose can fail the build"
    );
}
