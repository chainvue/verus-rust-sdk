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
//! **Verify those hashes.** Wrong parameters do not fail loudly — they produce
//! proofs that a daemon silently rejects, or worse. This module does not hash
//! the files itself: a check against a constant compiled into the same binary
//! that consumes them proves very little, and the real trust anchor is the file
//! the operator obtained from the Zcash ceremony or their own node.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use sapling_crypto::circuit::{OutputParameters, SpendParameters};

use crate::error::SaplingError;

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
        let spend = SpendParameters::read(BufReader::new(open(spend_path)?), false)
            .map_err(|e| SaplingError::Params(format!("{}: {e}", spend_path.display())))?;
        let output = OutputParameters::read(BufReader::new(open(output_path)?), false)
            .map_err(|e| SaplingError::Params(format!("{}: {e}", output_path.display())))?;
        Ok(Self { spend, output })
    }

    /// Read the parameters from memory — for callers that fetch them rather than
    /// reading a filesystem (a browser, an embedded target).
    pub fn from_bytes(spend: &[u8], output: &[u8]) -> Result<Self, SaplingError> {
        let spend = SpendParameters::read(spend, false)
            .map_err(|e| SaplingError::Params(format!("spend parameters: {e}")))?;
        let output = OutputParameters::read(output, false)
            .map_err(|e| SaplingError::Params(format!("output parameters: {e}")))?;
        Ok(Self { spend, output })
    }
}

fn open(path: &Path) -> Result<File, SaplingError> {
    File::open(path).map_err(|e| SaplingError::Params(format!("open {}: {e}", path.display())))
}
