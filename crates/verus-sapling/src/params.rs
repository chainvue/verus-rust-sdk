//! Loading the Sapling Groth16 proving parameters.
//!
//! Verus uses the **stock Zcash Sapling parameters, byte for byte** — the same
//! files a `zcashd` or `verusd` install already has. There is no Verus-specific
//! ceremony and no Verus-specific circuit; the only Verus-specific value on the
//! whole shielded path is the consensus branch id that goes into the sighash.
//!
//! ```text
//! sapling-spend.params    ~47 MB  sha256 8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13
//! sapling-output.params  ~3.5 MB  sha256 2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4
//! ```
//!
//! **Those hashes are enforced here, not merely printed.** Wrong parameters do
//! not fail loudly: at best they produce proofs a daemon rejects after thirty
//! seconds of work, and at worst — with a *maliciously constructed* CRS rather
//! than a merely corrupt one — Groth16's zero-knowledge property no longer
//! holds, so the proofs a wallet publishes can leak what they were meant to
//! hide. That is the one failure on this whole path that is silent and
//! irreversible, which is why it is checked rather than documented.
//!
//! An earlier version of this module argued that hashing against a constant in
//! the same binary "proves very little". That is wrong in the case that
//! matters: the binary and the parameter files routinely have *different*
//! trust levels — the binary is package-managed or signed, while the params
//! are fetched by a shell script into a user-writable directory, which is
//! exactly the file an attacker can reach. Checking costs ~100 ms against a
//! 30-second proof.
//!
//! It is also what makes upstream's `verify_point_encodings = false` sound:
//! `sapling-crypto` permits skipping that only for a caller "verifying the
//! parameters in another way (such as checking the hash of the parameters file
//! on disk)" — which is now precisely what this does.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use sapling_crypto::circuit::{OutputParameters, SpendParameters};
use sha2::{Digest, Sha256};

use crate::error::SaplingError;

/// SHA-256 of `sapling-spend.params` from the Zcash ceremony.
pub const SPEND_PARAMS_SHA256: [u8; 32] =
    hex_literal("8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13");

/// SHA-256 of `sapling-output.params` from the Zcash ceremony.
pub const OUTPUT_PARAMS_SHA256: [u8; 32] =
    hex_literal("2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4");

/// Decode a 64-character hex literal at compile time.
const fn hex_literal(text: &str) -> [u8; 32] {
    let bytes = text.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(bytes[i * 2]) * 16 + nibble(bytes[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("parameter hash constants are lowercase hex"),
    }
}

/// Refuse parameters that are not the ones from the ceremony.
fn check_params(bytes: &[u8], expected: [u8; 32], name: &str) -> Result<(), SaplingError> {
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    if actual != expected {
        return Err(SaplingError::Params(format!(
            "{name} has sha256 {}, not the ceremony's {} — refusing to prove with parameters \
             that are not the ones consensus verifies against",
            hex::encode(actual),
            hex::encode(expected)
        )));
    }
    Ok(())
}

/// The proving parameters, held together because every proving call needs both.
pub struct SaplingParams {
    /// Parameters for the spend circuit.
    pub spend: SpendParameters,
    /// Parameters for the output circuit.
    pub output: OutputParameters,
}

impl SaplingParams {
    /// Read the parameters from two files on disk.
    ///
    /// Reading ~50 MB and deserializing it is slow — on the order of seconds.
    /// Load once and keep the result alive; do not call this per transaction.
    pub fn from_files(
        spend_path: impl AsRef<Path>,
        output_path: impl AsRef<Path>,
    ) -> Result<Self, SaplingError> {
        let spend_path = spend_path.as_ref();
        let output_path = output_path.as_ref();
        // Read whole, then hash, then parse: the integrity check has to cover
        // the same bytes the circuit is built from, and a streaming check
        // would have to trust that nothing re-read them differently.
        let spend = read_file(spend_path)?;
        let output = read_file(output_path)?;
        check_params(
            &spend,
            SPEND_PARAMS_SHA256,
            &spend_path.display().to_string(),
        )?;
        check_params(
            &output,
            OUTPUT_PARAMS_SHA256,
            &output_path.display().to_string(),
        )?;
        Self::from_verified(&spend, &output)
    }

    /// Read the parameters from memory — for callers that fetch them rather than
    /// reading a filesystem (a browser, an embedded target).
    pub fn from_bytes(spend: &[u8], output: &[u8]) -> Result<Self, SaplingError> {
        check_params(spend, SPEND_PARAMS_SHA256, "spend parameters")?;
        check_params(output, OUTPUT_PARAMS_SHA256, "output parameters")?;
        Self::from_verified(spend, output)
    }

    /// Parse bytes whose hashes have already been checked.
    fn from_verified(spend: &[u8], output: &[u8]) -> Result<Self, SaplingError> {
        // `verify_point_encodings = false` is sound *because* the caller above
        // checked the hash — see the module docs.
        let spend = SpendParameters::read(spend, false)
            .map_err(|e| SaplingError::Params(format!("spend parameters: {e}")))?;
        let output = OutputParameters::read(output, false)
            .map_err(|e| SaplingError::Params(format!("output parameters: {e}")))?;
        Ok(Self { spend, output })
    }
}

fn read_file(path: &Path) -> Result<Vec<u8>, SaplingError> {
    let mut file = BufReader::new(open(path)?);
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes)
        .map_err(|e| SaplingError::Params(format!("read {}: {e}", path.display())))?;
    Ok(bytes)
}

fn open(path: &Path) -> Result<File, SaplingError> {
    File::open(path).map_err(|e| SaplingError::Params(format!("open {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The constants must be the hashes the module docs print, decoded — a
    /// typo in either would be caught only by a failing 30-second proof.
    #[test]
    fn the_hash_constants_match_the_documented_ceremony_files() {
        assert_eq!(
            hex::encode(SPEND_PARAMS_SHA256),
            "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13"
        );
        assert_eq!(
            hex::encode(OUTPUT_PARAMS_SHA256),
            "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4"
        );
    }

    /// Substituted parameters are refused before a single constraint is built.
    ///
    /// This is the finding's whole point: a corrupt file merely wastes a proof,
    /// but a *maliciously constructed* one can break zero-knowledge and leak
    /// what the proof was meant to hide — silently, and after publication.
    #[test]
    fn parameters_that_are_not_the_ceremonys_are_refused() {
        let Err(err) =
            SaplingParams::from_bytes(b"not the spend parameters", b"nor the output ones")
        else {
            panic!("substituted parameters must not load");
        };
        let message = err.to_string();
        assert!(message.contains("sha256"), "{message}");
        assert!(
            message.contains("8e48ffd23abb3a5f"),
            "the refusal must name the hash that was expected: {message}"
        );
    }

    /// And the check runs before parsing, so a file that is both wrong AND
    /// well-formed cannot slip through on the strength of parsing cleanly.
    #[test]
    fn the_hash_is_checked_before_the_circuit_is_parsed() {
        // Empty input parses as a truncation error if it ever reaches the
        // reader; the hash check must speak first.
        let Err(err) = SaplingParams::from_bytes(b"", b"") else {
            panic!("empty parameters are refused");
        };
        assert!(err.to_string().contains("sha256"), "{err}");
    }
}
