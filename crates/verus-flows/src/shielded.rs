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
//! Those checks run *within* one [`scan`]. A wallet's steady state is not one
//! scan, though — it is the tail, every few minutes, for years. [`scan_after`]
//! is that call, and it carries the same guarantee across the boundary: the
//! first block of the new range must descend from the last block of the old
//! one, or it refuses.
//!
//! # What those checks are, and are not, worth
//!
//! They defeat accidental corruption and lazy lying. They do **not** make a
//! light server trustworthy: all three read values the server itself supplies,
//! so a fully self-consistent fabricated chain passes every one, and the
//! tree-size check is skipped outright when the server declines to send chain
//! metadata. Compact-block hashes are never verified against consensus here —
//! that is the lightwalletd trust model, not an oversight.
//!
//! The real backstop is downstream: a witness anchors to a root, and a root
//! the chain does not have produces a transaction the daemon rejects. Check
//! [`WitnessedNote::anchor`] against a block header you trust before paying
//! for a proof. A balance reported here is a *claim by the server* until
//! something anchors it.
//!
//! # A note is not spendable just because you own it
//!
//! Detection finds notes paid *to* you. Whether one is still yours depends on
//! whether its nullifier has appeared in a later block, which is a separate
//! question answered by the same scan. [`ScanResult::unspent`] joins them; using
//! [`ScanResult::notes`] directly reports money you have already spent.

use verus_light::{LightClient, LightTransport};
#[cfg(feature = "prover")]
use verus_sapling::build::NoteToSpend;
use verus_sapling::scan::{
    detect_notes, CompactOutput, DetectedNote, DiversifiableFullViewingKey, FullOutput,
    TreeStateBefore,
};
use verus_sapling::witness::NoteWitness;
use verus_sapling::VERUS_ZIP212;

use crate::error::FlowError;

pub mod planning;

#[cfg(feature = "prover")]
pub mod spending;

pub use planning::{
    check_anchor, plan_spend, select_notes, shared_anchor, SpendPlan, MAX_SPEND_NOTES,
};

#[cfg(feature = "prover")]
pub use spending::{
    min_relay_fee, prepare_spend, prove_spend, serialized_size, spend, transparent_script,
    ShieldedRecipient, ShieldedSpent, SpendRequest, TransparentRecipient, DEFAULT_TRANSACTION_FEE,
    P2PKH_OUTPUT_BYTES, SHIELDED_OUTPUT_BYTES, SHIELDED_OVERHEAD_BYTES, SHIELDED_SPEND_BYTES,
};

/// How many blocks to ask for in one call.
///
/// Under `verus_light::MAX_BLOCK_RANGE`, because a scan chunk also has to fit in
/// memory as decoded structs, not just as a response body.
const SCAN_CHUNK: u64 = 1_000;

/// How many recent block hashes a [`ScanResult`] remembers.
///
/// These are what makes a reorg *recoverable* rather than merely detectable.
/// Detecting one is cheap — [`scan_after`] refuses a range that does not
/// descend from the last — but the wallet then has to roll back, and rolling
/// back safely means being able to prove the shortened state still describes
/// the live chain. One tip hash cannot do that: truncate to any earlier height
/// and there is nothing left to check the next scan against.
///
/// Two hundred blocks is far past any reorg a Verus chain has had, and costs
/// 8 KB. A fork deeper than this is not recoverable from a stored result at
/// all, and [`ScanResult::rewind_to`] says so rather than guessing.
pub const REORG_CHECKPOINTS: usize = 200;

/// A nullifier, and the block it was seen in.
///
/// The height is not decoration. A reorg can un-spend a note — the transaction
/// that published its nullifier may simply not be on the new chain — and a
/// wallet that cannot tell which nullifiers came from the dead blocks has two
/// bad options: keep them all, and a note that is spendable again stays hidden
/// until a full rescan; or drop them all, and a note that really is spent
/// reappears as spendable. Knowing the height makes the rollback exact instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SeenNullifier {
    /// The block it appeared in.
    pub height: u64,
    /// The nullifier itself, from anyone's transaction.
    #[cfg_attr(feature = "serde", serde(with = "verus_sapling::serde_hex"))]
    pub nullifier: [u8; 32],
}

/// A block hash at a height, kept so a rewind can be checked rather than hoped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Checkpoint {
    /// The height.
    pub height: u64,
    /// The hash of the block at it.
    #[cfg_attr(feature = "serde", serde(with = "verus_sapling::serde_hex"))]
    pub hash: [u8; 32],
}

/// Everything one scan of a block range learned.
///
/// **Persist this.** A scan is expensive and its result cannot be recovered
/// from a UTXO set — nothing on chain says which outputs are yours — so a
/// wallet that keeps only a balance rescans from its birthday on every launch.
/// Behind the `serde` feature the whole thing round-trips, notes and observed
/// nullifiers together, which is the pair [`Self::unspent`] needs and the pair
/// that is wrong in the dangerous direction if they are stored apart.
///
/// Then reload it, pass it to [`scan_after`] — which scans only the tail and
/// proves it continues the same chain — and fold the answer back in with
/// [`Self::absorb`]. `scan_after` returns the tail alone, so storing its result
/// *in place of* this one throws the wallet's history away.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    pub nullifiers: Vec<SeenNullifier>,
    /// First block scanned.
    pub from: u64,
    /// Last block scanned, inclusive.
    pub to: u64,
    /// Hash of the last block scanned, so the next scan can prove it continues
    /// the same chain rather than a reorged one.
    ///
    /// [`scan_after`] is what does that. Hand it a persisted result and the
    /// first block of the new range has to descend from this hash, or the scan
    /// is refused as [`FlowError::Reorged`] rather than quietly returning notes
    /// at positions the chain no longer agrees with.
    #[cfg_attr(feature = "serde", serde(with = "verus_sapling::serde_hex"))]
    pub tip_hash: [u8; 32],
    /// The most recent [`REORG_CHECKPOINTS`] block hashes, oldest first.
    ///
    /// What [`Self::rewind_to`] uses. The last entry is always
    /// [`Self::to`]/[`Self::tip_hash`]; the rest are how far back a rollback
    /// can be *verified* rather than guessed.
    pub checkpoints: Vec<Checkpoint>,
}

impl ScanResult {
    /// Fold a continuation into this result.
    ///
    /// [`scan_after`] returns **only the tail** — the notes and nullifiers in
    /// the blocks it just scanned — in the same type that holds a wallet's
    /// whole state. Storing that in place of the old one throws the wallet's
    /// history away; storing the notes but not the nullifiers is worse, because
    /// a note spent in the old range comes back as spendable. This is the
    /// merge, so neither is left to be got right by hand.
    ///
    /// ```no_run
    /// # use verus_flows::{scan_after, ScanResult};
    /// # use verus_light::{LightClient, LightTransport};
    /// # use verus_sapling::scan::DiversifiableFullViewingKey;
    /// # fn poll<T: LightTransport>(
    /// #     light: &LightClient<T>,
    /// #     dfvk: &DiversifiableFullViewingKey,
    /// #     wallet: &mut ScanResult,
    /// #     tip: u64,
    /// # ) -> Result<(), verus_flows::FlowError> {
    /// let tail = scan_after(light, dfvk, wallet, tip)?;
    /// wallet.absorb(tail)?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// [`FlowError::Shielded`] if `next` does not start exactly where this
    /// result ended. A gap would mean blocks nobody scanned — and every note
    /// position after such a gap is derived from a count that skipped them.
    pub fn absorb(&mut self, next: ScanResult) -> Result<(), FlowError> {
        if next.from != self.to + 1 {
            return Err(FlowError::Shielded(format!(
                "a scan of {}..={} does not continue one that ended at {}; absorbing it would \
                 leave a gap, and every note position after a gap is wrong",
                next.from, next.to, self.to
            )));
        }
        // An empty continuation — `scan_after` with nothing new — ends before
        // it begins and moves nothing.
        if next.to < next.from {
            return Ok(());
        }
        // A tail this crate produced always ends its window at its own tip.
        // Every field here is public, though, so a hand-built one need not —
        // and a window that does not end where the result says it does makes a
        // later `rewind_to` land on a stale hash. Refused at the boundary
        // instead of surfacing as a refused scan two calls later.
        match next.checkpoints.last() {
            Some(last) if last.height == next.to && last.hash == next.tip_hash => {}
            _ => {
                return Err(FlowError::Shielded(format!(
                    "the continuation's checkpoints do not end at its own tip ({}); absorbing it \
                     would leave a window that cannot be rewound to",
                    next.to
                )))
            }
        }

        self.notes.extend(next.notes);
        self.nullifiers.extend(next.nullifiers);
        self.checkpoints.extend(next.checkpoints);
        trim_checkpoints(&mut self.checkpoints);
        self.to = next.to;
        self.tip_hash = next.tip_hash;
        Ok(())
    }

    /// Roll back to `height`, dropping exactly what the blocks above it
    /// contributed.
    ///
    /// This is the other half of [`scan_after`]'s refusal. Detecting a reorg is
    /// cheap; acting on one means shortening the wallet's state to a block the
    /// live chain still has — and being able to *prove* the shortened state is
    /// still right, which one tip hash cannot do.
    ///
    /// Notes above `height` go, because their tree positions are counted
    /// through blocks that no longer exist. Nullifiers above `height` go too:
    /// a reorg can un-spend a note, and keeping a nullifier from a dead block
    /// would hide a note that is spendable again until the next full rescan.
    /// Both are recovered by scanning forward, which is the point of stopping
    /// at a height that can be checked.
    ///
    /// # The recovery loop
    ///
    /// A reorg's depth is not reported by anything, so finding it is a search —
    /// but a *verified* one, because each attempt is checked:
    ///
    /// ```no_run
    /// # use verus_flows::{scan_after, FlowError, ScanResult};
    /// # use verus_light::{LightClient, LightTransport};
    /// # use verus_sapling::scan::DiversifiableFullViewingKey;
    /// # fn recover<T: LightTransport>(
    /// #     light: &LightClient<T>,
    /// #     dfvk: &DiversifiableFullViewingKey,
    /// #     wallet: &mut ScanResult,
    /// #     tip: u64,
    /// # ) -> Result<(), FlowError> {
    /// let mut back = 1;
    /// loop {
    ///     match scan_after(light, dfvk, wallet, tip) {
    ///         Ok(tail) => break wallet.absorb(tail)?,
    ///         Err(FlowError::Reorged(_)) => {
    ///             // Each rewind is checkable, so going too shallow fails
    ///             // loudly on the next attempt instead of silently mixing
    ///             // positions from two chains.
    ///             wallet.rewind_to(wallet.to.saturating_sub(back))?;
    ///             back *= 2;
    ///         }
    ///         Err(other) => return Err(other),
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// When `rewind_to` runs out of checkpoints it says so, and the answer then
    /// is a fresh [`scan`] from the wallet's birthday — there is nothing left
    /// to verify against.
    ///
    /// # Between the rewind and the absorb, the state is not to be trusted
    ///
    /// A rewind drops the nullifiers the dead blocks carried, and the spends
    /// they described may well be on the live chain at different heights. Until
    /// the forward scan re-observes them and [`Self::absorb`] folds them back
    /// in, [`Self::unspent`] and [`Self::balance`] **overstate**: a note that is
    /// really spent looks spendable.
    ///
    /// It heals — the forward scan collects every nullifier in the range it
    /// covers — but not until the loop above finishes. So inside it: do not
    /// show a balance, do not select notes for a spend (the daemon will reject
    /// the double-spend after the proof has been paid for), and prefer not to
    /// persist. Recovery is one atomic step from the wallet's point of view,
    /// even though it takes several calls.
    ///
    /// The opposite choice would not heal at all. Keeping the dead blocks'
    /// nullifiers would hide a note that a reorg made spendable again, with
    /// nothing to correct it short of a full rescan — understating a balance
    /// silently and indefinitely, rather than overstating it for the length of
    /// one recovery.
    ///
    /// # Errors
    ///
    /// [`FlowError::Shielded`] if `height` is above [`Self::to`] (nothing to
    /// roll back), or if no checkpoint covers it — either because it is older
    /// than [`REORG_CHECKPOINTS`] blocks or because this result never reached
    /// it.
    pub fn rewind_to(&mut self, height: u64) -> Result<(), FlowError> {
        if height > self.to {
            return Err(FlowError::Shielded(format!(
                "cannot rewind to {height}: this result only reaches {}",
                self.to
            )));
        }
        let Some(checkpoint) = self
            .checkpoints
            .iter()
            .find(|point| point.height == height)
            .copied()
        else {
            let oldest = self.checkpoints.first().map_or(self.to, |p| p.height);
            return Err(FlowError::Shielded(format!(
                "no checkpoint at {height}; this result can be rewound to {oldest} at the \
                 earliest, and anything older needs a fresh scan because there is nothing left \
                 to verify the result against"
            )));
        };

        self.notes.retain(|note| note.height <= height);
        self.nullifiers.retain(|seen| seen.height <= height);
        self.checkpoints.retain(|point| point.height <= height);
        self.to = height;
        self.tip_hash = checkpoint.hash;
        Ok(())
    }

    /// The earliest height [`Self::rewind_to`] can still verify.
    ///
    /// A wallet searching for a fork point needs to know when to stop searching
    /// and rescan instead.
    #[must_use]
    pub fn earliest_rewind(&self) -> Option<u64> {
        self.checkpoints.first().map(|point| point.height)
    }

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
                !self
                    .nullifiers
                    .iter()
                    .any(|seen| seen.nullifier == note.nullifier)
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

/// Keep only the most recent [`REORG_CHECKPOINTS`] entries.
fn trim_checkpoints(checkpoints: &mut Vec<Checkpoint>) {
    if checkpoints.len() > REORG_CHECKPOINTS {
        checkpoints.drain(..checkpoints.len() - REORG_CHECKPOINTS);
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
    scan_following(light, dfvk, from, to, None)
}

/// Scan the blocks a previous scan did not, and prove they continue the same
/// chain.
///
/// This is the call a wallet actually lives in. The first scan is a one-off;
/// every scan after it is this one, every few minutes, for the life of the
/// wallet.
///
/// # What it closes
///
/// Within one [`scan`] the blocks are checked to chain — heights, `prevHash`,
/// and the server's own tree-size counter. **Across** calls nothing was
/// checked, and a wallet's steady state is entirely across calls.
/// [`ScanResult::tip_hash`] has always been documented "so the next scan can
/// prove it continues the same chain rather than a reorged one", and until now
/// no function accepted it.
///
/// The gap matters because of what a reorg does here. It does not fail loudly:
/// it *shifts note positions*, and a note witnessed at the wrong position
/// produces a proof the daemon rejects only after the prover has been paid for
/// — which is the failure this whole module is shaped to avoid.
///
/// # What to do when it refuses
///
/// [`FlowError::Reorged`] means the chain that `previous` described is not the
/// chain the server is serving now. It is **not transient**: retrying with the
/// same `previous` fails identically for as long as that fork stands, so a poll
/// loop that treats it as a hiccup spins forever.
///
/// The remedy is to scan again from further back and **discard the notes and
/// nullifiers at or above the fork**, because their positions are derived from
/// blocks that no longer exist. How far back is the wallet's call: this crate
/// does not search for the fork point, since doing so means guessing how deep
/// to look and re-fetching until it stops being wrong.
///
/// [`ScanResult::rewind_to`] is how, and it is a *verified* search rather than a
/// guess: each rewind lands on a block whose hash the result still holds, so
/// rolling back too little fails loudly on the next `scan_after` instead of
/// succeeding and quietly mixing positions from two chains. Its own docs carry
/// the loop.
///
/// # What comes back, and what to do with it
///
/// **Only the tail.** The notes and nullifiers in the blocks this call
/// scanned, in the same type that holds a wallet's whole state — so store it
/// *in addition to* what you have, with [`ScanResult::absorb`], never in place
/// of it.
///
/// # Nothing new is not an error
///
/// A polling wallet asks far more often than blocks arrive. When `to` is the
/// height `previous` already reached, the answer is an empty range — `from`
/// one past `to` — carrying the same tip hash, so it can be fed straight back
/// in or absorbed with no effect.
///
/// A `to` *below* that is [`FlowError::NotReady`], not a reorg: a server can be
/// behind because it is still syncing or because a load balancer moved, and
/// both serve the same chain with less of it. Retry before rolling anything
/// back.
///
/// # Errors
///
/// [`FlowError::Reorged`] if the blocks do not continue `previous`;
/// [`FlowError::NotReady`] if the server is behind `previous`; and everything
/// [`scan`] can report.
pub fn scan_after<T: LightTransport>(
    light: &LightClient<T>,
    dfvk: &DiversifiableFullViewingKey,
    previous: &ScanResult,
    to: u64,
) -> Result<ScanResult, FlowError> {
    if to < previous.to {
        // Deliberately NOT `Reorged`. A server offering a shorter chain is
        // usually not lying: a node still syncing after a restart, or a
        // load-balanced name that rotated to a replica behind the others,
        // serves the *same* chain and simply has less of it. Every block
        // already scanned is still on it. Calling that a reorg would push a
        // wallet into the reorg remedy — discard notes, rescan — for a
        // condition whose correct response is to wait.
        return Err(FlowError::NotReady(format!(
            "the last scan reached block {}, and this server is only at {to}; it is behind, or \
             the chain was reorged. Retry before rolling anything back — a lagging server \
             catches up and a reorg does not",
            previous.to
        )));
    }
    if to == previous.to {
        // Nothing new. An empty range, spelled the way an empty range is: it
        // starts one past where the last scan ended and ends before it began.
        // Claiming `from == to == previous.to` would assert that block was
        // scanned *by this call* and held nothing — false whenever the previous
        // scan found a note or a nullifier there, and a wallet reconciling by
        // range would then drop it.
        return Ok(ScanResult {
            notes: Vec::new(),
            nullifiers: Vec::new(),
            from: previous.to + 1,
            to: previous.to,
            tip_hash: previous.tip_hash,
            // No new blocks, so no new checkpoints. Absorbing this leaves the
            // wallet's own window untouched, which is what keeps a rewind
            // possible through any number of idle polls.
            checkpoints: Vec::new(),
        });
    }
    scan_following(light, dfvk, previous.to + 1, to, Some(previous.tip_hash))
}

/// The body of [`scan`], with the option of proving the first block continues
/// something already scanned.
fn scan_following<T: LightTransport>(
    light: &LightClient<T>,
    dfvk: &DiversifiableFullViewingKey,
    from: u64,
    to: u64,
    follows: Option<[u8; 32]>,
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
    let mut checkpoints: Vec<Checkpoint> = Vec::new();
    let mut tip_hash = [0u8; 32];
    // Seeded when this scan continues another: the very first block then has to
    // chain to the last block of that one, which is the check that was missing
    // across calls.
    let mut previous_hash: Option<[u8; 32]> = follows;

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
                    // `Reorged`, not `Shielded`: a wallet's response is to roll
                    // back and rescan, and that is the same response whether
                    // the break is inside this scan or between this one and the
                    // last. One variant, one arm to match.
                    return Err(FlowError::Reorged(format!(
                        "block {} does not follow the block before it; the chain was reorged \
                         and every note position after the break would be wrong",
                        block.height
                    )));
                }
            }
            previous_hash = Some(block.hash);
            checkpoints.push(Checkpoint {
                height: block.height,
                hash: block.hash,
            });
        }
        // Bounded as we go rather than at the end: a scan of a million blocks
        // must not hold a million hashes to throw all but two hundred away.
        trim_checkpoints(&mut checkpoints);

        // Flatten to a contiguous run of outputs. Order is the tree's order:
        // by block, then by transaction, then by output.
        let mut outputs = Vec::new();
        for block in &blocks {
            for tx in &block.transactions {
                nullifiers.extend(tx.nullifiers.iter().map(|nullifier| SeenNullifier {
                    height: block.height,
                    nullifier: *nullifier,
                }));
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

    debug_assert_eq!(
        checkpoints.last().map(|point| point.hash),
        Some(tip_hash),
        "the last checkpoint and the tip hash must be the same block"
    );
    Ok(ScanResult {
        notes,
        nullifiers,
        from,
        to,
        tip_hash,
        checkpoints,
    })
}

/// A note with everything a spend needs.
///
/// Deliberately carries every field of `verus_sapling::build::NoteToSpend`, not
/// just the witness. The first attempt held only the note, the output and the
/// witness — which reads as sufficient and is not: `NoteToSpend` also wants the
/// frontier and the block's commitments, and a caller would have had to refetch
/// both after this function had already done it. Producing a value that cannot
/// be handed to the next function is not an ergonomics problem, it is an
/// invitation to fetch the frontier at the wrong height.
pub struct WitnessedNote {
    /// The note as the scan found it.
    pub note: DetectedNote,
    /// The complete 948-byte output description, fetched whole because the
    /// compact form served for detection is only the first 52 ciphertext bytes
    /// and cannot be decrypted to a spendable note.
    pub output: FullOutput,
    /// The commitment tree immediately before the note's block.
    pub tree_before_block: TreeStateBefore,
    /// Every Sapling commitment in the note's block, in order.
    pub block_cmus: Vec<[u8; 32]>,
    /// Index of this note's own commitment among them.
    pub my_cmu_index: usize,
    /// The Merkle path, advanced to the anchor height that was asked for.
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

    /// Borrow this as a `NoteToSpend`, ready for
    /// `verus_sapling::build_shielded_spend`.
    ///
    /// `extsk_bytes` is the 169-byte extended spending key. It is passed here
    /// rather than stored on the struct so a scan, a witness and a balance can
    /// all be computed by a watch-only wallet that never holds one.
    #[cfg(feature = "prover")]
    #[must_use]
    pub fn to_spend<'a>(&'a self, extsk_bytes: &'a [u8]) -> NoteToSpend<'a> {
        NoteToSpend {
            extsk_bytes,
            output: &self.output,
            tree_before_block: &self.tree_before_block,
            block_cmus: &self.block_cmus,
            my_cmu_index: self.my_cmu_index,
            advanced_witness: Some(&self.witness),
        }
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
        tree_before_block: tree_before,
        block_cmus,
        my_cmu_index: index,
        witness,
    })
}

/// What a viewing key can read off an incoming note.
///
/// Detection ([`scan`]) works on 52 compact ciphertext bytes — enough to know a
/// note is yours and what it is worth, and **not** enough to read its memo,
/// which lives in the full 580-byte `encCiphertext`. [`received`] fetches that
/// and decrypts it.
#[derive(Debug, Clone)]
pub struct Received {
    /// Value in zatoshi, as the *full* decryption reports it.
    ///
    /// Cross-checked against what detection reported. They come from different
    /// ciphertexts, so a disagreement means the server did not serve the
    /// transaction the compact block advertised.
    pub value: u64,
    /// The address the note pays to — one of this wallet's, possibly a
    /// diversified one it has not seen before.
    pub recipient: [u8; 43],
    /// The raw 512-byte ZIP-302 memo field. Use [`Self::memo_text`] unless you
    /// have your own encoding.
    pub memo: [u8; 512],
}

impl Received {
    /// The memo as text, when it is text.
    ///
    /// ZIP-302 puts the meaning in the first byte: `0x00..=0xF4` is UTF-8 with
    /// trailing zeros to pad, `0xF6` followed by zeros means "no memo", `0xFF`
    /// is arbitrary application data, and the rest is reserved.
    ///
    /// `None` covers every not-text case together, deliberately: a wallet that
    /// rendered arbitrary bytes as lossy UTF-8 would be showing a user
    /// something that was never meant to be read that way. An empty *text*
    /// memo is `Some("")`, which is a different thing from "no memo" and stays
    /// distinguishable — and [`Self::memo`] is public for a wallet that wants
    /// the `0xFF` payload.
    ///
    /// Text ending in a zero byte is not representable: the format pads with
    /// zeros, so a sender's encoder cannot express it either. Interior zeros
    /// survive.
    #[must_use]
    pub fn memo_text(&self) -> Option<&str> {
        match self.memo[0] {
            // The not-text classes, stated rather than inferred. Every byte in
            // this range is also an invalid UTF-8 lead byte — Unicode stops at
            // U+10FFFF, so 0xF5 and above start nothing — which means the
            // `from_utf8` below would reject them all on its own and no test
            // can tell this arm from its absence.
            //
            // Kept anyway, because what it encodes is the ZIP-302 rule and not
            // a coincidence about UTF-8. Anything that later softened the
            // decode — a lossy fallback, say — would silently start rendering
            // arbitrary application data as text without this.
            0xf5..=0xff => None,
            _ => {
                let end = self
                    .memo
                    .iter()
                    .rposition(|byte| *byte != 0)
                    .map_or(0, |last| last + 1);
                core::str::from_utf8(&self.memo[..end]).ok()
            }
        }
    }
}

/// Read an incoming note in full: its value, the address it paid, and its memo.
///
/// The join between what a scan found and what a wallet shows. A
/// [`DetectedNote`] carries a value and a position and no memo, because
/// detection reads only the compact prefix; this fetches the whole output
/// description and decrypts it with the viewing key. No spending key is
/// involved — a watch-only wallet displays incoming payments with exactly this.
///
/// It costs a round trip per note, so call it for what is being displayed
/// rather than for everything a scan returned.
///
/// That round trip is also the one place this module departs from a uniform
/// access pattern: a scan asks for every block in a range and reveals nothing,
/// while this asks for *exactly* the transactions your notes are in. A light
/// server learns which of them are yours. Unavoidable if you want the memo, and
/// worth knowing before doing it for a wallet's whole history.
///
/// # Errors
///
/// [`FlowError::Shielded`] if the server does not serve the transaction the
/// compact block advertised, if the output does not decrypt under this key, or
/// if the full decryption disagrees with detection about the value.
pub fn received<T: LightTransport>(
    light: &LightClient<T>,
    dfvk: &DiversifiableFullViewingKey,
    note: &DetectedNote,
) -> Result<Received, FlowError> {
    let output = full_output(light, note)?;
    let read = verus_sapling::scan::read_note(dfvk, &output, VERUS_ZIP212)
        .map_err(|e| FlowError::Shielded(format!("decrypting the note: {e}")))?
        .ok_or_else(|| {
            FlowError::Shielded(format!(
                "the output at {}:{} does not decrypt under this viewing key, though the scan \
                 reported it as ours",
                note.height, note.output_index
            ))
        })?;

    // Belt and braces, and honestly labelled as such: both values are bound to
    // the note commitment, and `full_output` has already required the compact
    // and full commitments to match — so reaching either branch below takes a
    // break in that binding, not a lying server. Kept because it costs a
    // comparison and because a future change to `full_output` could weaken what
    // it checks without anyone noticing here.
    if read.value != note.value {
        return Err(FlowError::Shielded(format!(
            "the note at {}:{} decrypts to {} zatoshi but the scan found {}; the transaction \
             served is not the one the compact block advertised",
            note.height, note.output_index, read.value, note.value
        )));
    }
    if read.recipient != note.recipient {
        return Err(FlowError::Shielded(format!(
            "the note at {}:{} decrypts to a different address than the scan reported",
            note.height, note.output_index
        )));
    }

    Ok(Received {
        // From the decryption, not from the scan. Indistinguishable while the
        // check above holds — which is the point of the check — but it is the
        // ciphertext that is authoritative about what the note is worth.
        value: read.value,
        recipient: read.recipient,
        memo: read.memo,
    })
}

/// The height a newly created account can start scanning from.
///
/// A wallet that does not record one rescans the whole chain on every restore,
/// and on Verus there is no shortcut to fall back on: **Sapling activates at
/// height 1**, so "start at activation" is the same as starting at genesis —
/// 1.17 million blocks on VRSCTEST as of 2026-08-03, and four times that on
/// mainnet.
///
/// # Record it *before* the address is used
///
/// The ordering is the whole trap. A birthday taken after an address has been
/// given out is a birthday later than the first payment to it, and every note
/// before it is invisible — a wallet that is quietly missing money, with
/// nothing to indicate it. Take this the moment the account is derived, and
/// persist it before showing anyone the address.
///
/// # How much slack
///
/// [`REORG_CHECKPOINTS`] blocks. This module already argues that 200 is "far
/// past any reorg a Verus chain has had" and sizes its rollback window to it —
/// so the same number is the right floor here, and saying "a few" while
/// budgeting 200 one screen up was an inconsistency worth naming.
///
/// The asymmetry decides it. Two hundred blocks of extra scanning is seconds.
/// A payment that landed in a block the chain later replaced, below a birthday
/// chosen ten blocks back, is invisible forever — and nothing reports it,
/// because a scan cannot know what it was never asked to look at.
///
/// # Errors
///
/// [`FlowError::Rpc`] if the node cannot be reached.
pub fn birthday(reader: &impl verus_rpc::ChainReader) -> Result<u64, FlowError> {
    Ok(u64::from(reader.block_count()?))
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
