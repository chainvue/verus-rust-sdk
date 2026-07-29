//! Keeping a note spendable as the chain grows.
//!
//! A witness is a Merkle path from one note's commitment to the tree root. The
//! root moves every time anyone anywhere adds a shielded output, so a witness
//! built at the note's own block is only valid at *that* anchor — and a daemon
//! only accepts anchors it still remembers.
//!
//! [`witness_anchor`](crate::scan::witness_anchor) computes exactly that
//! one-block anchor, which is enough to spend a note immediately and useless a
//! week later. Keeping it usable means **advancing** it: appending every
//! commitment added since, block by block, forever, for every note the wallet
//! holds. That maintenance is the substance of a shielded wallet, and it is what
//! this type is for.
//!
//! ```text
//! new(tree before block, block cmus, index)   note is positioned, anchor = end of its block
//!   ├── apply_block(h+1, cmus)                anchor moves forward
//!   ├── apply_block(h+2, cmus)
//!   └── …                                     spend at any anchor a node still has
//! ```
//!
//! # The rules that are not optional
//!
//! **Every block, in order, exactly once.** A witness is a fold over every
//! commitment the chain has appended. Skip a block and the path is wrong; apply
//! one twice and it is wrong. Neither is detected here — both produce a witness
//! that builds, proves, and is rejected by the daemon as
//! `bad-txns-shielded-requirements-not-met`, after the proof has been paid for.
//! [`NoteWitness::next_height`] exists so a caller can assert the block it is
//! about to apply is the one expected; use it.
//!
//! **Blocks with no shielded outputs still count** — as an `apply_block` with an
//! empty slice. Nothing changes in the tree, but the height advances, and a
//! wallet that skips empty blocks loses track of where it is.
//!
//! **A reorg invalidates the witness.** This type only moves forward, exactly
//! like the tree it mirrors. If the chain rolls back past a block that was
//! applied, the witness is wrong and cannot be repaired by appending; the wallet
//! must keep a copy from before the rolled-back range and continue from there.
//! Keeping periodic copies is the caller's job — see [`NoteWitness::anchor`].

use sapling_crypto::{Anchor, IncrementalWitness, MerklePath, Node};

use crate::error::SaplingError;
use crate::scan::{build_witness, TreeStateBefore};

/// A note's Merkle path, advanceable as blocks arrive.
#[derive(Clone)]
pub struct NoteWitness {
    inner: IncrementalWitness,
    /// Height of the last block folded in.
    height: u32,
}

impl NoteWitness {
    /// Position a note in the tree and witness it up to the end of its block.
    ///
    /// `tree_before_block` is the frontier *immediately before* the note's block
    /// — `z_gettreestate(height - 1)`. `block_cmus` is every Sapling commitment
    /// in the note's block, in order, and `my_cmu_index` is where this note's
    /// own commitment sits among them.
    ///
    /// **Do not assume the note is at index 0.** The Sapling builder shuffles a
    /// bundle's outputs; two transactions built the same way put the note at
    /// different indices. Find it by trial decryption.
    pub fn new(
        tree_before_block: &TreeStateBefore,
        block_cmus: &[[u8; 32]],
        my_cmu_index: usize,
        block_height: u32,
    ) -> Result<Self, SaplingError> {
        let (_, _) = build_witness(tree_before_block, block_cmus, my_cmu_index)?;
        // Rebuild the incremental form rather than the finished path: the point
        // of this type is that it can still be advanced.
        let mut tree = crate::scan::commitment_tree(tree_before_block)?;
        for cmu in block_cmus.iter().take(my_cmu_index + 1) {
            tree.append(node(cmu)?)
                .map_err(|_| SaplingError::Witness("commitment tree is full".into()))?;
        }
        let mut inner = IncrementalWitness::from_tree(tree)
            .ok_or_else(|| SaplingError::Witness("no note commitment to witness".into()))?;
        for cmu in block_cmus.iter().skip(my_cmu_index + 1) {
            inner
                .append(node(cmu)?)
                .map_err(|_| SaplingError::Witness("witness is full".into()))?;
        }
        Ok(Self {
            inner,
            height: block_height,
        })
    }

    /// Fold in one block's commitments and advance the height.
    ///
    /// `cmus` is every Sapling output commitment in that block, in order —
    /// including those belonging to other people, which is most of them. An
    /// empty slice is correct and expected for a block with no shielded
    /// activity.
    ///
    /// Refuses a height that is not the next one, which is the only one of the
    /// three ways to corrupt a witness that can be caught locally.
    pub fn apply_block(&mut self, height: u32, cmus: &[[u8; 32]]) -> Result<(), SaplingError> {
        if height != self.next_height() {
            return Err(SaplingError::Witness(format!(
                "witness is at height {}, so the next block is {}, not {height}",
                self.height,
                self.next_height()
            )));
        }
        for cmu in cmus {
            self.inner
                .append(node(cmu)?)
                .map_err(|_| SaplingError::Witness("witness is full".into()))?;
        }
        self.height = height;
        Ok(())
    }

    /// The height this witness has been advanced to.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// The block that must be applied next.
    pub fn next_height(&self) -> u32 {
        self.height.saturating_add(1)
    }

    /// The anchor this witness currently roots to.
    ///
    /// Worth recording alongside a stored witness: it is what a spend commits
    /// to, and comparing it against the `finalsaplingroot` of the block at
    /// [`height`](Self::height) is the one end-to-end check that the fold has
    /// stayed correct.
    pub fn anchor(&self) -> [u8; 32] {
        self.inner.root().to_bytes()
    }

    /// The Merkle path a spend needs.
    pub fn path(&self) -> Result<MerklePath, SaplingError> {
        self.inner
            .path()
            .ok_or_else(|| SaplingError::Witness("witness has no path".into()))
    }

    /// The anchor as the prover wants it.
    pub fn to_anchor(&self) -> Anchor {
        Anchor::from(self.inner.root())
    }
}

fn node(cmu: &[u8; 32]) -> Result<Node, SaplingError> {
    Option::from(Node::from_bytes(*cmu))
        .ok_or_else(|| SaplingError::Witness("commitment is not a valid tree node".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/daemon/sapling_tree.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).expect("fixture")).expect("json")
    }

    fn wire_cmus(fixture: &serde_json::Value) -> Vec<[u8; 32]> {
        fixture["block_1166308_cmus_display_order"]
            .as_array()
            .expect("cmus")
            .iter()
            .map(|c| {
                let mut bytes: [u8; 32] = hex::decode(c.as_str().expect("hex"))
                    .expect("hex")
                    .try_into()
                    .expect("32 bytes");
                bytes.reverse();
                bytes
            })
            .collect()
    }

    fn tree() -> TreeStateBefore {
        TreeStateBefore::from_hex(
            fixture()["frontier_before_block_1166308_hex"]
                .as_str()
                .expect("frontier"),
        )
        .expect("tree")
    }

    /// Where the real note sits in its block. Not zero, which is the point.
    fn my_index() -> usize {
        usize::try_from(fixture()["my_cmu_index"].as_u64().expect("index")).expect("fits")
    }

    /// A fresh witness must agree with the one-shot builder — this type is the
    /// same fold, kept open rather than finished.
    #[test]
    fn a_new_witness_matches_the_one_shot_anchor() {
        let cmus = wire_cmus(&fixture());
        let witness = NoteWitness::new(&tree(), &cmus, my_index(), 1_166_308).unwrap();
        let expected = crate::scan::witness_anchor(&tree(), &cmus, my_index()).unwrap();
        assert_eq!(witness.anchor(), expected);
        assert_eq!(witness.height(), 1_166_308);
    }

    /// An empty block still advances the height. A wallet that skips them loses
    /// its place, and the next real block is then applied at the wrong point.
    #[test]
    fn an_empty_block_advances_the_height_but_not_the_anchor() {
        let cmus = wire_cmus(&fixture());
        let mut witness = NoteWitness::new(&tree(), &cmus, my_index(), 1_166_308).unwrap();
        let before = witness.anchor();
        witness.apply_block(1_166_309, &[]).unwrap();
        assert_eq!(witness.anchor(), before);
        assert_eq!(witness.height(), 1_166_309);
    }

    /// Appending commitments moves the anchor — which is the whole reason a
    /// witness has to be maintained rather than built once.
    #[test]
    fn applying_a_block_moves_the_anchor() {
        let cmus = wire_cmus(&fixture());
        let mut witness = NoteWitness::new(&tree(), &cmus, my_index(), 1_166_308).unwrap();
        let before = witness.anchor();
        witness.apply_block(1_166_309, &[[7u8; 32]]).unwrap();
        assert_ne!(witness.anchor(), before);
    }

    /// The one corruption that can be caught locally. A skipped block produces a
    /// witness that proves and is then rejected on chain, so refusing here is
    /// the difference between an error and a wasted proof.
    #[test]
    fn refuses_a_block_out_of_order() {
        let cmus = wire_cmus(&fixture());
        let mut witness = NoteWitness::new(&tree(), &cmus, my_index(), 1_166_308).unwrap();
        // Skipping 1_166_309.
        assert!(witness.apply_block(1_166_310, &[]).is_err());
        // Replaying the block it is already at.
        assert!(witness.apply_block(1_166_308, &[]).is_err());
        assert!(witness.apply_block(1_166_309, &[]).is_ok());
    }

    /// Order within a block matters as much as order between blocks: the same
    /// commitments in a different sequence are a different tree.
    #[test]
    fn commitment_order_within_a_block_changes_the_anchor() {
        let cmus = wire_cmus(&fixture());
        let mut forwards = NoteWitness::new(&tree(), &cmus, my_index(), 1).unwrap();
        let mut backwards = NoteWitness::new(&tree(), &cmus, my_index(), 1).unwrap();
        forwards.apply_block(2, &[[1u8; 32], [2u8; 32]]).unwrap();
        backwards.apply_block(2, &[[2u8; 32], [1u8; 32]]).unwrap();
        assert_ne!(forwards.anchor(), backwards.anchor());
    }
}
