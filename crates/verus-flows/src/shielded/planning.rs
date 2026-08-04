//! Everything a spend must get right *before* it is worth paying for a proof.
//!
//! Note selection, witnessing to a shared anchor, and checking that anchor
//! against consensus are all cheap; the Groth16 proof that follows is tens of
//! seconds per note. So they live here, outside the `prover` feature, and
//! [`plan_spend`] can be run by a watch-only wallet that has no spending key
//! and no bellman in its dependency tree.
//!
//! # The anchor is checked against a second source
//!
//! A witness roots to an anchor, and an anchor the chain has never had produces
//! a transaction the daemon rejects with `bad-txns-shielded-requirements-not-met`
//! — after the prover has run. Every input to that anchor comes from the light
//! server: the frontier, the commitments, the tree sizes. Checking the result
//! against the same server's arithmetic proves only that it is self-consistent,
//! which is precisely what [`super`]'s own docs warn is not worth much.
//!
//! So [`plan_spend`] takes a [`ChainReader`] as well and compares the anchor it
//! computed against the `finalsaplingroot` in that block's header — a value
//! consensus fixed, read from unrelated infrastructure. Getting it wrong is not
//! hypothetical: a frontier taken at the wrong height was confirmed on
//! 2026-07-28 to fail nowhere locally and only at the daemon.

use verus_light::{LightClient, LightTransport};
use verus_rpc::ChainReader;
use verus_sapling::scan::DetectedNote;

use crate::error::FlowError;

use super::{witness_note, WitnessedNote};

/// Most notes this crate will put into one spend.
///
/// Not a consensus limit. Every note costs a Groth16 spend proof — tens of
/// seconds of CPU each — and 384 bytes of transaction, so a wallet that
/// accidentally selected two hundred dust notes would appear to hang.
/// Exceeding it is refused rather than silently truncated: truncation would
/// build a transaction paying less value than the caller asked to send.
pub const MAX_SPEND_NOTES: usize = 10;

/// Notes chosen, witnessed and anchored — everything a build needs except the
/// spending key and the prover.
///
/// Read-only from outside this crate, and that is load-bearing rather than
/// tidy. Every `SpendPlan` in existence came out of [`plan_spend`], which
/// checked its anchor against consensus before returning — so a plan reaching
/// the prover has an anchor the chain really had.
///
/// The fields are therefore reachable only through the accessors below.
/// `#[non_exhaustive]` alone would not do it: it blocks *construction* and not
/// *mutation*, so with public fields `plan.anchor = whatever` would still
/// compile in a caller's crate, and the builder's own `expected_anchor` guard
/// would not notice — it compares against this same value. An earlier version
/// of this doc claimed `#[non_exhaustive]` made the guarantee structural. It
/// did not.
pub struct SpendPlan {
    /// The selected notes, each witnessed to [`Self::anchor_height`].
    pub(crate) notes: Vec<WitnessedNote>,
    /// The anchor every one of them roots to, confirmed against the chain's
    /// own `finalsaplingroot`.
    pub(crate) anchor: [u8; 32],
    /// The height that anchor came from.
    pub(crate) anchor_height: u64,
    /// The chain tip **as the [`ChainReader`] reports it**, when the plan was
    /// made.
    ///
    /// Recorded because it is not the anchor height: a caller may pin a deeper
    /// anchor deliberately, and an expiry counted from the anchor would then be
    /// behind the tip before the transaction was even built.
    ///
    /// It comes from the daemon rather than the light server, and that is not
    /// incidental. Expiry is the only consensus field in a shielded spend
    /// derived from a *height*, and it decides how long the transaction stays
    /// minable. A light server that answered `GetLatestBlock` with 499 999 979
    /// would produce a transaction valid for centuries instead of twenty
    /// minutes — one that a user watches expire, settles around, and then finds
    /// mined months later against notes they may have since spent. That is
    /// value lost rather than a transaction rejected, and it is the one thing
    /// in this module a hostile light server could otherwise reach. The
    /// transparent flows have always counted expiry from `funding.tip`, which
    /// is the same reader; this matches them.
    pub(crate) tip: u64,
    /// Total value of the selected notes.
    pub(crate) total_in: u64,
    /// What the notes are worth beyond what the spend costs, and so what has to
    /// come back as change. Shielded value cannot be split at the input: a note
    /// enters a spend whole.
    pub(crate) change: u64,
}

impl SpendPlan {
    /// The selected notes, each witnessed to [`Self::anchor_height`].
    #[must_use]
    pub fn notes(&self) -> &[WitnessedNote] {
        &self.notes
    }

    /// The anchor every one of them roots to, confirmed against the chain's own
    /// `finalsaplingroot` before this plan was returned.
    #[must_use]
    pub fn anchor(&self) -> [u8; 32] {
        self.anchor
    }

    /// The height that anchor came from.
    #[must_use]
    pub fn anchor_height(&self) -> u64 {
        self.anchor_height
    }

    /// The chain tip the [`ChainReader`] reported, which the expiry is counted
    /// from. See the field docs for why it is not the light server's.
    #[must_use]
    pub fn tip(&self) -> u64 {
        self.tip
    }

    /// Total value of the selected notes.
    #[must_use]
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    /// What comes back as change.
    #[must_use]
    pub fn change(&self) -> u64 {
        self.change
    }
}

/// Written out rather than derived: a [`WitnessedNote`] carries a Merkle path
/// and a whole block's commitments, and printing those buries the five numbers
/// a caller is actually looking at.
impl core::fmt::Debug for SpendPlan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SpendPlan")
            .field("notes", &self.notes.len())
            .field("anchor", &hex::encode(self.anchor))
            .field("anchor_height", &self.anchor_height)
            .field("tip", &self.tip)
            .field("total_in", &self.total_in)
            .field("change", &self.change)
            .finish()
    }
}

/// Select notes, witness them to a shared anchor, and check that anchor.
///
/// `needed` is everything the transaction must cover — the outputs *and* the
/// fee. Passing the outputs alone builds a plan that cannot pay for itself, and
/// the builder would then refuse it after the fetches.
///
/// `anchor_height` of `None` uses the lower of the two tips — the light
/// server's and the daemon's — so the anchor is a height both of them have.
/// Pin it deeper for reorg safety; the expiry is counted from the chain tip
/// either way, not from the anchor.
///
/// # Errors
///
/// [`FlowError::InsufficientFunds`] if the notes cannot cover `needed`.
/// [`FlowError::Shielded`] if `needed` is zero, if the anchor height is below a
/// selected note's own block, if the witnesses disagree about the anchor, or if
/// the anchor is not the one the chain committed to. [`FlowError::Rpc`] if the
/// daemon cannot be reached — its tip is needed even when the anchor is
/// pinned.
pub fn plan_spend<T: LightTransport>(
    light: &LightClient<T>,
    reader: &impl ChainReader,
    notes: &[DetectedNote],
    needed: u64,
    anchor_height: Option<u64>,
) -> Result<SpendPlan, FlowError> {
    // Zero would select no notes and then fail as "a spend needs at least one
    // note", which describes the symptom rather than the mistake — `needed` is
    // outputs *and* fee, and a caller who passed only the outputs of an empty
    // recipient list lands here.
    if needed == 0 {
        return Err(FlowError::Shielded(
            "a spend must cover something: `needed` is the outputs plus the fee, and it is zero"
                .into(),
        ));
    }
    let selected = select_notes(notes, needed)?;

    // Two tips, from two parties, for two different jobs.
    //
    // The daemon's is the one the expiry is counted from — see `SpendPlan::tip`
    // for why that must not be the light server's. Asked for even when the
    // anchor is pinned, because `prove_spend` needs it either way.
    let tip = u64::from(reader.block_count()?);
    // The light server's bounds what it can actually witness to.
    let light_tip = light
        .latest_block()
        .map_err(|e| FlowError::Shielded(format!("light server tip: {e}")))?
        .height;
    // Defaulting to the lower of the two keeps the anchor at a height *both*
    // sources have. Two honest sources are routinely a block apart, and taking
    // the light server's alone meant asking the daemon to confirm a
    // `finalsaplingroot` for a block it had not seen yet — a plan that failed
    // for no reason but ordinary skew, with an error that named nothing a
    // caller could act on.
    let anchor_height = anchor_height.unwrap_or_else(|| tip.min(light_tip));
    // A note cannot be witnessed before it existed. Checked here so the failure
    // names the note, rather than surfacing as a witness error several round
    // trips later.
    if let Some(late) = selected.iter().find(|note| note.height > anchor_height) {
        return Err(FlowError::Shielded(format!(
            "the note from block {} cannot be witnessed at anchor height {anchor_height}, which \
             is earlier",
            late.height
        )));
    }

    let witnessed = selected
        .iter()
        .map(|note| witness_note(light, note, anchor_height))
        .collect::<Result<Vec<_>, _>>()?;
    let anchor = shared_anchor(&witnessed)?;
    check_anchor(reader, anchor_height, anchor)?;

    let total_in = sum_values(&selected)?;
    // `select_notes` guarantees `needed <= total_in`, so this cannot wrap.
    // Written as a checked subtraction anyway, because a wrapped change value
    // is a transaction that pays a miner everything.
    let change = total_in.checked_sub(needed).ok_or_else(|| {
        FlowError::Shielded("the selected notes do not cover the outputs and the fee".into())
    })?;

    Ok(SpendPlan {
        notes: witnessed,
        anchor,
        anchor_height,
        tip,
        total_in,
        change,
    })
}

/// Total value of some notes, refusing rather than wrapping.
///
/// A wrap needs values no honest chain produces, but a [`SpendPlan`] is also
/// the *watch-only* product this module exists to make available without a
/// prover — there is no builder downstream to re-check it, and a wrapped total
/// would be shown to someone as their balance.
fn sum_values(notes: &[DetectedNote]) -> Result<u64, FlowError> {
    notes.iter().try_fold(0u64, |total, note| {
        total.checked_add(note.value).ok_or_else(|| {
            FlowError::Shielded("these notes are worth more than a u64 can hold".into())
        })
    })
}

/// Pick notes covering `needed`, largest first.
///
/// Largest-first because the cost of a shielded input is a Groth16 proof rather
/// than a few hundred bytes: taking the fewest notes that cover the amount is
/// the difference between one proof and ten. It does mean a wallet's dust is
/// never swept by an ordinary payment — consolidating is then a deliberate act
/// rather than something a payment does behind the user's back.
///
/// A wallet wanting a different policy — oldest first for privacy, smallest
/// first to consolidate — selects for itself and passes the result in. Note
/// what that does and does not buy: this function still runs over whatever it
/// is given, so a caller's set is taken **whole only when every note in it is
/// needed**. Hand it four notes where two would cover the amount and the two
/// largest are what gets spent. Sizing the set to the amount is the way to make
/// the choice stick.
///
/// # Errors
///
/// [`FlowError::InsufficientFunds`] when the notes cannot cover `needed`, and
/// [`FlowError::Shielded`] when covering it would take more than
/// [`MAX_SPEND_NOTES`].
pub fn select_notes(notes: &[DetectedNote], needed: u64) -> Result<Vec<DetectedNote>, FlowError> {
    let available = sum_values(notes)?;
    if available < needed {
        return Err(FlowError::InsufficientFunds {
            needed: verus_tx::Amount::from_sat(needed),
            available: verus_tx::Amount::from_sat(available),
            address: "the shielded pool".into(),
            utxos: notes.len(),
        });
    }

    let mut candidates: Vec<DetectedNote> = notes.to_vec();
    // Descending by value, then by position so the choice is deterministic when
    // two notes are worth the same — a spend built twice from the same wallet
    // state should select the same notes.
    candidates.sort_by(|a, b| b.value.cmp(&a.value).then(a.position.cmp(&b.position)));

    let mut selected = Vec::new();
    let mut running: u64 = 0;
    for note in candidates {
        if running >= needed {
            break;
        }
        running = running.saturating_add(note.value);
        selected.push(note);
    }

    if selected.len() > MAX_SPEND_NOTES {
        return Err(FlowError::Shielded(format!(
            "covering {needed} zatoshi takes {} notes, more than the {MAX_SPEND_NOTES} this crate \
             will prove in one transaction; consolidate first, or send less",
            selected.len()
        )));
    }
    Ok(selected)
}

/// The anchor every witness agrees on.
///
/// # Errors
///
/// [`FlowError::Shielded`] if they disagree, or if there are no notes.
pub fn shared_anchor(witnessed: &[WitnessedNote]) -> Result<[u8; 32], FlowError> {
    let mut anchors = witnessed.iter().map(WitnessedNote::anchor);
    let first = anchors
        .next()
        .ok_or_else(|| FlowError::Shielded("a spend needs at least one note".into()))?;
    if anchors.any(|anchor| anchor != first) {
        // `build_shielded_spend` refuses this too. Caught here it costs a
        // comparison instead of the first proof.
        return Err(FlowError::Shielded(
            "the selected notes witness to different anchors, so they cannot share a bundle; \
             they were not all advanced to the same height"
                .into(),
        ));
    }
    Ok(first)
}

/// Compare a computed anchor against the chain's own record of it.
///
/// The block header's `finalsaplingroot` is the root of the commitment tree
/// after that block — exactly what a witness advanced through that block roots
/// to. It reaches us from a Verus daemon rather than from the light server that
/// supplied every input to the computation, which is the only reason this check
/// is worth anything.
///
/// Headers display the root reversed, the way they display a txid.
///
/// # Errors
///
/// [`FlowError::Shielded`] if the node does not report the field, reports one
/// that is not 32 bytes, or reports a different root. [`FlowError::Rpc`] if the
/// block cannot be read at all — an unreachable node must not read as an
/// anchor that checks out.
pub fn check_anchor(
    reader: &impl ChainReader,
    anchor_height: u64,
    anchor: [u8; 32],
) -> Result<(), FlowError> {
    let block = reader.block(&anchor_height.to_string())?;
    let reported = block["finalsaplingroot"].as_str().ok_or_else(|| {
        FlowError::Shielded(format!(
            "block {anchor_height} carries no finalsaplingroot, so the anchor cannot be checked \
             against consensus"
        ))
    })?;
    let mut bytes = hex::decode(reported).map_err(|e| {
        FlowError::Shielded(format!("finalsaplingroot of block {anchor_height}: {e}"))
    })?;
    let length = bytes.len();
    bytes.reverse();
    let expected: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        FlowError::Shielded(format!(
            "finalsaplingroot of block {anchor_height} is {length} bytes, not 32"
        ))
    })?;
    if expected != anchor {
        return Err(FlowError::Shielded(format!(
            "the witness roots to {} but block {anchor_height} committed to {}; the light \
             server's commitments do not describe this chain, and proving against them would \
             cost ~30 seconds to be told so by the daemon",
            hex::encode(anchor),
            hex::encode(expected)
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(value: u64, position: u64) -> DetectedNote {
        DetectedNote {
            height: 1_000 + position,
            tx_index: 0,
            output_index: 0,
            position,
            value,
            recipient: [u8::try_from(position % 256).expect("a byte"); 43],
            nullifier: [u8::try_from(position % 256).expect("a byte"); 32],
        }
    }

    #[test]
    fn the_fewest_notes_that_cover_it_are_taken_largest_first() {
        let notes = [note(1, 0), note(500, 1), note(100, 2)];
        let selected = select_notes(&notes, 550).expect("covered");
        assert_eq!(
            selected.iter().map(|n| n.value).collect::<Vec<_>>(),
            vec![500, 100]
        );
    }

    #[test]
    fn one_note_is_enough_when_one_note_covers_it() {
        let notes = [note(500, 0), note(500, 1)];
        assert_eq!(select_notes(&notes, 500).expect("covered").len(), 1);
    }

    /// Two notes of equal value must not select differently between runs: a
    /// wallet rebuilding the same payment should reach the same transaction.
    #[test]
    fn equal_notes_are_broken_by_position_not_by_input_order() {
        let ascending = [note(100, 3), note(100, 7)];
        let descending = [note(100, 7), note(100, 3)];
        assert_eq!(
            select_notes(&ascending, 100).expect("covered")[0].position,
            select_notes(&descending, 100).expect("covered")[0].position
        );
    }

    #[test]
    fn not_enough_value_is_insufficient_funds_not_a_short_selection() {
        let notes = [note(100, 0), note(100, 1)];
        match select_notes(&notes, 500) {
            Err(FlowError::InsufficientFunds {
                needed, available, ..
            }) => {
                assert_eq!(needed.to_sat(), 500);
                assert_eq!(available.to_sat(), 200);
            }
            other => panic!("expected InsufficientFunds, got {other:?}"),
        }
    }

    /// Refused, not truncated. Truncating would build a transaction paying less
    /// than was asked for, which is the one outcome worse than an error.
    #[test]
    fn too_many_notes_is_refused_rather_than_cut_short() {
        let notes: Vec<DetectedNote> = (0..=MAX_SPEND_NOTES)
            .map(|i| note(10, u64::try_from(i).expect("a position")))
            .collect();
        let needed = 10 * u64::try_from(notes.len()).expect("a count");
        match select_notes(&notes, needed) {
            Err(FlowError::Shielded(message)) => {
                assert!(message.contains("consolidate"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        // And exactly MAX_SPEND_NOTES is still allowed, so the bound is the one
        // it says it is rather than one note tighter.
        assert_eq!(
            select_notes(&notes, needed - 10).expect("covered").len(),
            MAX_SPEND_NOTES
        );
    }

    #[test]
    fn a_zero_value_note_never_pads_a_selection() {
        let notes = [note(0, 0), note(100, 1)];
        let selected = select_notes(&notes, 100).expect("covered");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].value, 100);
    }
}
