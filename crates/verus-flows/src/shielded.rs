//! Finding, valuing and witnessing shielded notes from a light server.
//!
//! `verus-sapling` can detect notes, witness them, prove and sign spends. It
//! cannot fetch anything. `verus-light` can fetch, and knows nothing about
//! notes. This module is the join, and it is where the two subtle invariants
//! live.
//!
//! # Positions are derived, not reported
//!
//! Nothing in a compact block says where a note sits in the commitment tree.
//! The position is *counted*: the tree size before the scanned range fixes the
//! first output's index, and every subsequent output — yours or anyone's —
//! advances it by one.
//!
//! That makes the scan fragile in a specific way. **Every** Sapling output in
//! the range must be seen, in order, with no gaps. A dropped block, a reordered
//! chunk or a silently short range does not fail: it shifts every position after
//! it, and a note witnessed at the wrong position produces a proof the daemon
//! rejects as `bad-txns-shielded-requirements-not-met` after the prover has been
//! paid for. So this module checks continuity at three levels — heights,
//! `prevHash` chaining, and the server's own tree-size counter — rather than
//! trusting any one of them.
//!
//! # A note is not spendable just because you own it
//!
//! Detection finds notes paid *to* you. Whether one is still yours depends on
//! whether its nullifier has appeared in a later block, which is a separate
//! question answered by the same scan. [`ScanResult::unspent`] joins them; using
//! [`ScanResult::notes`] directly reports money you have already spent.

use verus_light::{LightClient, LightTransport};
use verus_sapling::scan::{
    detect_notes, CompactOutput, DetectedNote, DiversifiableFullViewingKey, FullOutput,
    TreeStateBefore,
};
use verus_sapling::witness::NoteWitness;
use verus_sapling::VERUS_ZIP212;

use crate::error::FlowError;

/// How many blocks to ask for in one call.
///
/// Under `verus_light::MAX_BLOCK_RANGE`, because a scan chunk also has to fit in
/// memory as decoded structs, not just as a response body.
const SCAN_CHUNK: u64 = 1_000;

/// Everything one scan of a block range learned.
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Notes paid to this viewing key, with absolute tree positions.
    ///
    /// Includes notes that have since been spent — see [`Self::unspent`].
    pub notes: Vec<DetectedNote>,
    /// Every nullifier seen in the range, from anyone's transactions.
    ///
    /// A note is spent exactly when its nullifier appears here or in any earlier
    /// block, which is why a wallet must keep these across scans rather than
    /// only the notes.
    pub nullifiers: Vec<[u8; 32]>,
    /// First block scanned.
    pub from: u64,
    /// Last block scanned, inclusive.
    pub to: u64,
    /// Hash of the last block scanned, so the next scan can prove it continues
    /// the same chain rather than a reorged one.
    pub tip_hash: [u8; 32],
}

impl ScanResult {
    /// Notes whose nullifiers have not been seen — the ones still spendable.
    ///
    /// `already_spent` carries nullifiers observed *before* this range. A wallet
    /// that scans in chunks must pass them, or a note spent in an earlier chunk
    /// reappears as spendable and the balance is wrong in the dangerous
    /// direction.
    #[must_use]
    pub fn unspent(&self, already_spent: &[[u8; 32]]) -> Vec<DetectedNote> {
        self.notes
            .iter()
            .filter(|note| {
                !self.nullifiers.contains(&note.nullifier)
                    && !already_spent.contains(&note.nullifier)
            })
            .cloned()
            .collect()
    }

    /// Total value of the unspent notes, in zatoshi.
    #[must_use]
    pub fn balance(&self, already_spent: &[[u8; 32]]) -> u64 {
        self.unspent(already_spent)
            .iter()
            .map(|note| note.value)
            .sum()
    }
}

/// Trial-decrypt every Sapling output between `from` and `to` inclusive.
///
/// Fetches in chunks, and re-anchors each chunk on its own `GetTreeState` rather
/// than carrying a running count across calls — an arithmetic slip in that
/// running count is exactly the failure this whole module is shaped to avoid,
/// and one extra round trip per thousand blocks is a cheap way not to have it.
///
/// Positions are cross-checked against the server's own
/// `saplingCommitmentTreeSize` on every chunk boundary.
pub fn scan<T: LightTransport>(
    light: &LightClient<T>,
    dfvk: &DiversifiableFullViewingKey,
    from: u64,
    to: u64,
) -> Result<ScanResult, FlowError> {
    if to < from {
        return Err(FlowError::Shielded(format!(
            "scan range {from}..={to} runs backwards"
        )));
    }
    if from == 0 {
        // There is no block -1 to take a frontier from, and Sapling did not
        // activate at genesis anyway.
        return Err(FlowError::Shielded(
            "a scan must start at height 1 or later".into(),
        ));
    }

    let mut notes = Vec::new();
    let mut nullifiers = Vec::new();
    let mut tip_hash = [0u8; 32];
    let mut previous_hash: Option<[u8; 32]> = None;

    let mut chunk_start = from;
    while chunk_start <= to {
        let chunk_end = (chunk_start + SCAN_CHUNK - 1).min(to);

        // The frontier immediately before this chunk fixes the first output's
        // absolute position.
        let frontier = light
            .tree_state(chunk_start - 1)
            .map_err(|e| FlowError::Shielded(format!("tree state at {}: {e}", chunk_start - 1)))?;
        let tree_before = TreeStateBefore::from_hex(&frontier.tree).map_err(|e| {
            FlowError::Shielded(format!("commitment tree at {}: {e}", frontier.height))
        })?;

        // Two independent statements of the same number, by unrelated routes: a
        // serialized Merkle frontier and a varint counter. Checking them against
        // each other costs nothing and catches a frontier taken at the wrong
        // height, which fails nowhere else.
        let counted = frontier
            .leaf_count()
            .map_err(|e| FlowError::Shielded(format!("leaf count: {e}")))?;
        let parsed = tree_before
            .size()
            .map_err(|e| FlowError::Shielded(format!("tree size: {e}")))?;
        if counted != parsed {
            return Err(FlowError::Shielded(format!(
                "the frontier at {} holds {parsed} commitments but its own encoding counts \
                 {counted}; the tree state cannot be trusted to position a note",
                frontier.height
            )));
        }

        let blocks = light
            .block_range(chunk_start, chunk_end)
            .map_err(|e| FlowError::Shielded(format!("blocks {chunk_start}..={chunk_end}: {e}")))?;

        // `verus-light` already refuses gaps and out-of-order heights. This
        // checks the stronger property: that the blocks are the same chain, and
        // the same chain as the previous chunk.
        for block in &blocks {
            if let Some(expected) = previous_hash {
                if block.prev_hash != expected {
                    return Err(FlowError::Shielded(format!(
                        "block {} does not follow the previous block; the chain was reorged \
                         under the scan and every position after it would be wrong",
                        block.height
                    )));
                }
            }
            previous_hash = Some(block.hash);
        }

        // Flatten to a contiguous run of outputs. Order is the tree's order:
        // by block, then by transaction, then by output.
        let mut outputs = Vec::new();
        for block in &blocks {
            for tx in &block.transactions {
                nullifiers.extend(tx.nullifiers.iter().copied());
                for (index, out) in tx.outputs.iter().enumerate() {
                    outputs.push(CompactOutput {
                        height: block.height,
                        tx_index: tx.index,
                        output_index: u64::try_from(index).expect("an index fits in u64"),
                        cmu: out.cmu,
                        epk: out.epk,
                        ciphertext: out.ciphertext,
                    });
                }
            }
        }

        // The server's counter must agree with the count we are about to assume.
        if let Some(last) = blocks.last() {
            if let Some(reported) = last.tree_size {
                let expected = parsed + u64::try_from(outputs.len()).expect("a count fits in u64");
                if reported != expected {
                    return Err(FlowError::Shielded(format!(
                        "after blocks {chunk_start}..={chunk_end} the tree should hold {expected} \
                         commitments but the server reports {reported}; positions in this range \
                         cannot be derived"
                    )));
                }
            }
            tip_hash = last.hash;
        }

        notes.extend(
            detect_notes(dfvk, &tree_before, &outputs, VERUS_ZIP212)
                .map_err(|e| FlowError::Shielded(format!("trial decryption: {e}")))?,
        );

        chunk_start = chunk_end + 1;
    }

    Ok(ScanResult {
        notes,
        nullifiers,
        from,
        to,
        tip_hash,
    })
}

/// A note with everything a spend needs: the full output, and a witness
/// advanced to a chosen anchor height.
pub struct WitnessedNote {
    /// The note as the scan found it.
    pub note: DetectedNote,
    /// The complete 948-byte output description, fetched whole because the
    /// compact form served for detection is only the first 52 ciphertext bytes
    /// and cannot be decrypted to a spendable note.
    pub output: FullOutput,
    /// The Merkle path, advanced to `anchor_height`.
    pub witness: NoteWitness,
}

impl WitnessedNote {
    /// The anchor this witness roots to.
    ///
    /// **Check it before proving.** A frontier from the wrong height fails
    /// nowhere else: the note decrypts, the witness builds, the proof generates
    /// after ~20 seconds, and only the daemon objects.
    #[must_use]
    pub fn anchor(&self) -> [u8; 32] {
        self.witness.anchor()
    }
}

/// Fetch a note's full output and witness it up to `anchor_height`.
///
/// Every note in one transaction must share an anchor, because a Sapling bundle
/// carries exactly one — so witness them all to the same height.
///
/// This is several round trips: the frontier before the note's block, the blocks
/// from there to the anchor, and the transaction that created the note.
pub fn witness_note<T: LightTransport>(
    light: &LightClient<T>,
    note: &DetectedNote,
    anchor_height: u64,
) -> Result<WitnessedNote, FlowError> {
    if anchor_height < note.height {
        return Err(FlowError::Shielded(format!(
            "cannot witness a note from block {} at an earlier anchor {anchor_height}",
            note.height
        )));
    }

    let frontier = light
        .tree_state(note.height - 1)
        .map_err(|e| FlowError::Shielded(format!("tree state at {}: {e}", note.height - 1)))?;
    let tree_before = TreeStateBefore::from_hex(&frontier.tree)
        .map_err(|e| FlowError::Shielded(format!("commitment tree: {e}")))?;

    let own_block = light
        .block_range(note.height, note.height)
        .map_err(|e| FlowError::Shielded(format!("block {}: {e}", note.height)))?;
    let block_cmus = own_block[0].commitments();

    // Find the note's own commitment among the block's, by position rather than
    // by searching for a value: the position is what the scan derived, and a
    // mismatch here means the scan and this lookup disagree about the block.
    let base = tree_before
        .size()
        .map_err(|e| FlowError::Shielded(format!("tree size: {e}")))?;
    let index = note
        .position
        .checked_sub(base)
        .and_then(|i| usize::try_from(i).ok());
    let Some(index) = index.filter(|i| *i < block_cmus.len()) else {
        return Err(FlowError::Shielded(format!(
            "note at position {} is not in block {}, which holds positions {}..{}",
            note.position,
            note.height,
            base,
            base + u64::try_from(block_cmus.len()).expect("a count fits in u64")
        )));
    };

    let height = u32::try_from(note.height)
        .map_err(|_| FlowError::Shielded("block height does not fit in 32 bits".into()))?;
    let mut witness = NoteWitness::new(&tree_before, &block_cmus, index, height)
        .map_err(|e| FlowError::Shielded(format!("witnessing the note: {e}")))?;

    // Advance one block at a time, including blocks with no shielded activity:
    // skipping an empty block loses track of the height, and the witness is then
    // silently wrong.
    let mut next = note.height + 1;
    while next <= anchor_height {
        let end = (next + SCAN_CHUNK - 1).min(anchor_height);
        let blocks = light
            .block_range(next, end)
            .map_err(|e| FlowError::Shielded(format!("blocks {next}..={end}: {e}")))?;
        for block in &blocks {
            let height = u32::try_from(block.height)
                .map_err(|_| FlowError::Shielded("block height does not fit in 32 bits".into()))?;
            witness
                .apply_block(height, &block.commitments())
                .map_err(|e| FlowError::Shielded(format!("advancing to {}: {e}", block.height)))?;
        }
        next = end + 1;
    }

    let output = full_output(light, note)?;

    Ok(WitnessedNote {
        note: note.clone(),
        output,
        witness,
    })
}

/// Fetch the complete output description that created a note.
///
/// Detection works on 52 compact ciphertext bytes, which is enough to know a
/// note is yours and what it is worth, and **not** enough to spend it or read
/// its memo — both need the full 580-byte `encCiphertext`.
pub fn full_output<T: LightTransport>(
    light: &LightClient<T>,
    note: &DetectedNote,
) -> Result<FullOutput, FlowError> {
    // One fetch of the note's block supplies both the transaction to ask for and
    // the commitment to check the answer against.
    let blocks = light
        .block_range(note.height, note.height)
        .map_err(|e| FlowError::Shielded(format!("block {}: {e}", note.height)))?;
    let compact = blocks[0]
        .transactions
        .iter()
        .find(|tx| tx.index == note.tx_index)
        .ok_or_else(|| {
            FlowError::Shielded(format!(
                "block {} has no shielded transaction at index {}",
                note.height, note.tx_index
            ))
        })?;

    let index = usize::try_from(note.output_index)
        .map_err(|_| FlowError::Shielded("output index does not fit in this platform".into()))?;
    let expected_cmu = compact
        .outputs
        .get(index)
        .map(|out| out.cmu)
        .ok_or_else(|| FlowError::Shielded(format!("no compact output at index {index}")))?;

    let raw = light
        .transaction(&compact.hash)
        .map_err(|e| FlowError::Shielded(format!("fetching the note's transaction: {e}")))?;

    let tx = verus_wire::TxV4::deserialize(&raw.data)
        .map_err(|e| FlowError::Shielded(format!("parsing the note's transaction: {e}")))?;

    let bytes = tx.shielded_outputs.get(index).ok_or_else(|| {
        FlowError::Shielded(format!(
            "transaction has {} shielded outputs, but the note is at index {index}",
            tx.shielded_outputs.len()
        ))
    })?;

    let output = parse_full_output(bytes)?;

    // The full transaction the server returned must actually contain the note
    // the compact block advertised. Without this a substituted transaction would
    // simply fail to decrypt, and read as a corrupt wallet rather than a lying
    // server.
    if output.cmu != expected_cmu {
        return Err(FlowError::Shielded(format!(
            "the output at index {index} of the full transaction is not the note the compact \
             block reported at position {}",
            note.position
        )));
    }

    Ok(output)
}

/// Split a 948-byte Sapling output description into its fields.
fn parse_full_output(bytes: &[u8]) -> Result<FullOutput, FlowError> {
    const LEN: usize = 32 + 32 + 32 + 580 + 80 + 192;
    if bytes.len() != LEN {
        return Err(FlowError::Shielded(format!(
            "a Sapling output description is {LEN} bytes, got {}",
            bytes.len()
        )));
    }
    let array = |from: usize, to: usize| -> [u8; 32] {
        bytes[from..to].try_into().expect("a 32 byte window")
    };
    Ok(FullOutput {
        cv: array(0, 32),
        cmu: array(32, 64),
        epk: array(64, 96),
        enc: bytes[96..676].to_vec(),
        ct: bytes[676..756].to_vec(),
        proof: bytes[756..948].to_vec(),
    })
}
