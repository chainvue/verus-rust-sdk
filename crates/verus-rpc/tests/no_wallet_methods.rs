//! The crate must not be able to ask a node to use a key.
//!
//! This is the enforcement the crate's central claim rests on. The typed
//! `Method` enum makes the emittable set finite, but an enum alone does not stop
//! a name being inlined as a literal somewhere else — so this checks the
//! **source text** as well. A check that only asked the enum about itself would
//! be self-referential and would pass no matter what the code did.

use std::fs;
use std::path::{Path, PathBuf};

/// Methods that make a node hold, use or reveal a key, or sign on your behalf.
///
/// Two entries look like they ought to be needed and are not:
/// `registernamecommitment` and `registeridentity`. Both are wallet methods, and
/// this SDK builds and signs both halves of a registration itself.
const WALLET_METHODS: &[&str] = &[
    "sendcurrency",
    "z_sendmany",
    "z_shieldcoinbase",
    "z_mergetoaddress",
    "sendtoaddress",
    "sendmany",
    "sendfrom",
    "signrawtransaction",
    "signmessage",
    "signfile",
    "signdata",
    "fundrawtransaction",
    "registeridentity",
    "registernamecommitment",
    "updateidentity",
    "revokeidentity",
    "recoveridentity",
    "setidentitytimelock",
    "definecurrency",
    "makeoffer",
    "takeoffer",
    "closeoffers",
    "dumpprivkey",
    "importprivkey",
    "z_exportkey",
    "z_importkey",
    "dumpwallet",
    "z_exportwallet",
    "walletpassphrase",
    "addmultisigaddress",
];

fn source_files(dir: &Path, into: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("readable directory").flatten() {
        let path = entry.path();
        if path.is_dir() {
            source_files(&path, into);
        } else if path.extension().is_some_and(|e| e == "rs") {
            into.push(path);
        }
    }
}

fn crate_sources() -> Vec<PathBuf> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    source_files(&src, &mut files);
    assert!(!files.is_empty(), "found no source files to check");
    files
}

#[test]
fn no_wallet_method_name_appears_anywhere_in_the_crate() {
    let mut offences = Vec::new();
    for file in crate_sources() {
        let text = fs::read_to_string(&file).expect("readable source");
        for (number, line) in text.lines().enumerate() {
            // Doc comments name these deliberately, to say they are absent.
            if line.trim_start().starts_with("//") {
                continue;
            }
            for method in WALLET_METHODS {
                if line.contains(method) {
                    offences.push(format!(
                        "{}:{}: {method}",
                        file.file_name().unwrap_or_default().to_string_lossy(),
                        number + 1
                    ));
                }
            }
        }
    }

    assert!(
        offences.is_empty(),
        "wallet methods must not be reachable from this crate:\n  {}",
        offences.join("\n  ")
    );
}

/// The check above must be capable of finding something, or it passes vacuously
/// and protects nothing.
#[test]
fn the_search_can_actually_find_a_method_name() {
    let found = crate_sources().iter().any(|file| {
        fs::read_to_string(file)
            .map(|text| text.contains("sendrawtransaction"))
            .unwrap_or(false)
    });
    assert!(
        found,
        "the search found no method name at all, so it proves nothing"
    );
    assert!(WALLET_METHODS.len() > 20);
}
