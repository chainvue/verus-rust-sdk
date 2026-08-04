//! Client-side note detection (trial decryption).
//!
//! A light wallet must find its own shielded notes WITHOUT a full node and
//! WITHOUT `z_listunspent`. It does this by trial-decrypting the compact Sapling
//! outputs served by lightwalletd (`GetBlockRange`) with its incoming viewing
//! key. This module is the read-side counterpart to the offline signer: it takes
//! a viewing key (or spending key) and the compact outputs of a block range and
//! returns the notes that belong to the wallet, each with the data a later
//! `z2z`/`z2t` spend needs (absolute tree position + nullifier).
//!
//! Only the incoming viewing key is needed to *detect* a note; the nullifier
//! (used to tell whether a detected note has since been spent) additionally
//! needs the nullifier-deriving key and the note's absolute position in the
//! commitment tree. We recover position authoritatively from the same
//! `CommitmentTree` the witness builder uses: the tree state at the block BEFORE
//! the scanned range fixes the position of the first output, and every
//! subsequent output (mine or not) advances it by one.
//!
//! Trial decryption is cheap (no proving) — this runs in milliseconds, unlike
//! the ~5–20 s spend/output proving. It is a pure read path: no signatures, no
//! transaction assembly.

use sapling_crypto::keys::PreparedIncomingViewingKey;
use sapling_crypto::note::ExtractedNoteCommitment;
use sapling_crypto::note_encryption::{
    try_sapling_compact_note_decryption, CompactOutputDescription, Zip212Enforcement,
};
pub use sapling_crypto::zip32::DiversifiableFullViewingKey;
use sapling_crypto::zip32::ExtendedSpendingKey;
use sapling_crypto::{CommitmentTree, Node};
use zcash_note_encryption::{EphemeralKeyBytes, COMPACT_NOTE_SIZE};

use crate::error::SaplingError;

/// One compact Sapling output to trial-decrypt, in global chain order. The
/// identity fields (`height`/`tx_index`/`output_index`) are opaque to the crypto
/// and echoed back on a hit so the caller can locate the note.
pub struct CompactOutput {
    /// Block height the output was mined in.
    pub height: u64,
    /// Index of its transaction within that block.
    pub tx_index: u64,
    /// Index of this output within that transaction.
    pub output_index: u64,
    /// Note commitment.
    pub cmu: [u8; 32],
    /// Ephemeral public key used to encrypt the note.
    pub epk: [u8; 32],
    /// First 52 bytes (`COMPACT_NOTE_SIZE`) of the output's `encCiphertext`.
    pub ciphertext: [u8; COMPACT_NOTE_SIZE],
}

/// A detected note (an output that decrypted under the wallet's ivk), with
/// everything a later spend or spent-check needs.
///
/// **This is the struct a wallet persists.** A scan is expensive and its result
/// is not recoverable from a UTXO set — nothing on chain says which outputs are
/// yours — so a wallet that forgets these rescans from its birthday on every
/// launch. Behind the `serde` feature it round-trips; see
/// [`serde_hex`](mod@crate::serde_hex) for how the byte fields are written.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DetectedNote {
    /// Block height the note was mined in.
    pub height: u64,
    /// Index of its transaction within that block.
    pub tx_index: u64,
    /// Index of this output within that transaction.
    pub output_index: u64,
    /// Absolute position (0-based leaf index) in the note-commitment tree.
    pub position: u64,
    /// Note value in zatoshi.
    pub value: u64,
    /// 43-byte Sapling payment address this note pays to (one of the wallet's).
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_hex"))]
    pub recipient: [u8; 43],
    /// Note nullifier — matches this note's entry in a future spend's
    /// `vShieldedSpend`; a wallet marks the note spent when it sees this
    /// nullifier in a compact block.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_hex"))]
    pub nullifier: [u8; 32],
}

pub(crate) fn node(bytes: [u8; 32]) -> Result<Node, SaplingError> {
    Option::<Node>::from(Node::from_bytes(bytes))
        .ok_or_else(|| SaplingError::InvalidTreeState("bad tree node bytes".into()))
}

/// The commitment tree just BEFORE the scanned range, needed to fix absolute
/// positions. Same parsed shape (`left`/`right`/`parents`) the witness builder
/// consumes, from `z_gettreestate` / lightwalletd `GetTreeState(startHeight-1)`.
pub struct TreeStateBefore {
    /// Left child of the incomplete frontier node, if present.
    pub left: Option<[u8; 32]>,
    /// Right child of the incomplete frontier node, if present.
    pub right: Option<[u8; 32]>,
    /// Ancestors along the frontier, root-ward; `None` marks an empty slot.
    pub parents: Vec<Option<[u8; 32]>>,
}

impl TreeStateBefore {
    /// Parse the serialized commitment tree a daemon returns.
    ///
    /// Both `z_gettreestate` (as `sapling.commitments.finalState`) and
    /// `getsaplingtree` (as `tree`) hand back this encoding:
    ///
    /// ```text
    /// left:    00 | 01 <32 bytes>
    /// right:   00 | 01 <32 bytes>
    /// parents: <CompactSize count> then that many of the same optional node
    /// ```
    ///
    /// Getting this frontier is the hard part of spending a note offline. It is
    /// the one input a signing host cannot compute for itself: the path to a
    /// note depends on every commitment added before it, and a frontier cannot
    /// be walked backwards — a later tree tells you nothing about an earlier
    /// one. So capture it BEFORE the transaction that creates the note is mined,
    /// or be able to ask a node for it at that height afterwards.
    pub fn from_serialized(bytes: &[u8]) -> Result<Self, SaplingError> {
        let mut reader = TreeReader { bytes, offset: 0 };
        let left = reader.optional_node()?;
        let right = reader.optional_node()?;
        let count = reader.compact_size()?;
        // A Sapling tree is 32 levels deep, so more parents than that is a
        // corrupt blob rather than a very large tree.
        if count > 32 {
            return Err(SaplingError::InvalidTreeState(format!(
                "{count} parents, but a Sapling tree has at most 32 levels"
            )));
        }
        let mut parents = Vec::with_capacity(count);
        for _ in 0..count {
            parents.push(reader.optional_node()?);
        }
        if reader.offset != bytes.len() {
            return Err(SaplingError::InvalidTreeState(format!(
                "{} trailing bytes after the commitment tree",
                bytes.len() - reader.offset
            )));
        }
        Ok(Self {
            left,
            right,
            parents,
        })
    }

    /// Parse the hex form, as it appears in a JSON-RPC reply.
    pub fn from_hex(hex_str: &str) -> Result<Self, SaplingError> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| SaplingError::InvalidTreeState(format!("tree is not hex: {e}")))?;
        Self::from_serialized(&bytes)
    }

    /// How many notes the tree holds — the absolute position the next appended
    /// commitment will take.
    pub fn size(&self) -> Result<u64, SaplingError> {
        Ok(commitment_tree(self)?.size() as u64)
    }

    /// The Merkle root of this tree, in wire order.
    ///
    /// Worth checking against the `finalsaplingroot` of the block the tree was
    /// taken at: it is the one end-to-end confirmation that the frontier was
    /// parsed correctly, and a wrong frontier produces a witness that roots to
    /// an anchor no node has ever seen.
    pub fn root(&self) -> Result<[u8; 32], SaplingError> {
        Ok(commitment_tree(self)?.root().to_bytes())
    }
}

struct TreeReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl TreeReader<'_> {
    fn byte(&mut self) -> Result<u8, SaplingError> {
        let byte = *self
            .bytes
            .get(self.offset)
            .ok_or_else(|| SaplingError::InvalidTreeState("tree ended early".into()))?;
        self.offset += 1;
        Ok(byte)
    }

    fn optional_node(&mut self) -> Result<Option<[u8; 32]>, SaplingError> {
        match self.byte()? {
            0 => Ok(None),
            1 => {
                let end = self.offset + 32;
                let node: [u8; 32] = self
                    .bytes
                    .get(self.offset..end)
                    .ok_or_else(|| SaplingError::InvalidTreeState("node ended early".into()))?
                    .try_into()
                    .expect("the range above asked for exactly 32 bytes");
                self.offset = end;
                Ok(Some(node))
            }
            other => Err(SaplingError::InvalidTreeState(format!(
                "expected an optional-node tag of 0 or 1, found {other}"
            ))),
        }
    }

    /// CompactSize. Only the single-byte form can occur here — the count is a
    /// tree depth — so anything larger is refused rather than decoded.
    fn compact_size(&mut self) -> Result<usize, SaplingError> {
        match self.byte()? {
            n if n < 0xfd => Ok(usize::from(n)),
            other => Err(SaplingError::InvalidTreeState(format!(
                "parent count uses the multi-byte CompactSize form ({other:#04x})"
            ))),
        }
    }
}

/// Rebuild the note-commitment tree a daemon reported, so both the scanner (for
/// absolute positions) and the spend builder (for witnesses) read it the same way.
pub(crate) fn commitment_tree(state: &TreeStateBefore) -> Result<CommitmentTree, SaplingError> {
    let left = state.left.map(node).transpose()?;
    let right = state.right.map(node).transpose()?;
    let parents = state
        .parents
        .iter()
        .map(|p| p.map(node).transpose())
        .collect::<Result<Vec<Option<Node>>, SaplingError>>()?;
    CommitmentTree::from_parts(left, right, parents)
        .map_err(|_| SaplingError::InvalidTreeState("tree parents too deep".into()))
}

/// Trial-decrypt `outputs` (in global chain order, contiguous from the block
/// after `tree_before`) and return the notes belonging to the wallet.
///
/// `dfvk` supplies both the incoming viewing key (detection) and the
/// nullifier-deriving key (nullifier). `tree_before` fixes the first output's
/// absolute position; positions must be contiguous, so `outputs` MUST contain
/// EVERY Sapling output in the range, not only candidates.
///
/// # A detected note is a claim, not a proof
///
/// Decryption is as strict as the protocol allows — the note commitment is
/// recomputed and a mismatch refused — but it is recomputed against the *cmu
/// the caller supplied*, and nothing here proves that output is on the chain.
/// So whoever supplies the outputs can:
///
/// * synthesise a payment to your address, inflating a displayed balance; and
/// * insert or drop outputs, shifting positions so nullifiers come out wrong
///   and spent notes look unspent.
///
/// Neither can move funds — a note is not consumed until the chain accepts a
/// nullifier, so every such mistake ends in a rejected transaction rather than
/// a loss. But a balance from this function is only as good as the source of
/// the outputs until a witness anchors to a root you have checked.
pub fn detect_notes(
    dfvk: &DiversifiableFullViewingKey,
    tree_before: &TreeStateBefore,
    outputs: &[CompactOutput],
    zip212: Zip212Enforcement,
) -> Result<Vec<DetectedNote>, SaplingError> {
    let ivk = dfvk.fvk().vk.ivk();
    let prepared_ivk = PreparedIncomingViewingKey::new(&ivk);
    let nk = &dfvk.fvk().vk.nk;

    let tree = commitment_tree(tree_before)?;
    let base_position = tree.size() as u64;

    let mut found = Vec::new();
    for (i, out) in outputs.iter().enumerate() {
        let position = base_position + i as u64;
        let cmu = Option::from(ExtractedNoteCommitment::from_bytes(&out.cmu))
            .ok_or_else(|| SaplingError::InvalidTreeState("bad compact note commitment".into()))?;
        let cod = CompactOutputDescription {
            ephemeral_key: EphemeralKeyBytes(out.epk),
            cmu,
            enc_ciphertext: out.ciphertext,
        };
        if let Some((note, addr)) = try_sapling_compact_note_decryption(&prepared_ivk, &cod, zip212)
        {
            found.push(DetectedNote {
                height: out.height,
                tx_index: out.tx_index,
                output_index: out.output_index,
                position,
                value: note.value().inner(),
                recipient: addr.to_bytes(),
                nullifier: note.nf(nk, position).0,
            });
        }
    }
    Ok(found)
}

/// A full Sapling output description (raw wire bytes) — enough to fully decrypt
/// the note, including its memo.
pub struct FullOutput {
    /// Value commitment.
    pub cv: [u8; 32],
    /// Note commitment.
    pub cmu: [u8; 32],
    /// Ephemeral public key.
    pub epk: [u8; 32],
    /// Encrypted note plaintext, 580 bytes — the memo lives in here, which is
    /// why detection alone (52 compact bytes) cannot recover it.
    pub enc: Vec<u8>,
    /// Outgoing ciphertext, 80 bytes.
    pub ct: Vec<u8>,
    /// Groth16 proof, 192 bytes.
    pub proof: Vec<u8>,
}

/// The full decryption of an incoming note: its value, the address it pays to,
/// and the 512-byte memo field.
pub struct ReadNote {
    /// Note value in zatoshi.
    pub value: u64,
    /// Raw 43-byte Sapling payment address the note pays to.
    pub recipient: [u8; 43],
    /// The 512-byte memo field, zero-padded (ZIP-302).
    pub memo: [u8; 512],
}

/// Fully decrypt one output with the wallet's incoming viewing key — recovering
/// the value, recipient, AND memo (compact detection cannot: the memo lives in
/// the full 580-byte `encCiphertext`, not the 52-byte compact prefix). Returns
/// `None` if the output is not for this key. This is how a light wallet shows
/// the memo on an incoming private payment, client-side.
pub fn read_note(
    dfvk: &DiversifiableFullViewingKey,
    out: &FullOutput,
    zip212: Zip212Enforcement,
) -> Result<Option<ReadNote>, SaplingError> {
    use sapling_crypto::bundle::{GrothProofBytes, OutputDescription};
    use sapling_crypto::note::ExtractedNoteCommitment;
    use sapling_crypto::value::ValueCommitment;
    use zcash_note_encryption::EphemeralKeyBytes;

    if out.enc.len() != 580 || out.ct.len() != 80 || out.proof.len() != 192 {
        return Err(SaplingError::InvalidTreeState(
            "output field size mismatch (enc=580, ct=80, proof=192)".into(),
        ));
    }
    let ivk = dfvk.fvk().vk.ivk();
    let prepared = PreparedIncomingViewingKey::new(&ivk);
    let cv = Option::from(ValueCommitment::from_bytes_not_small_order(&out.cv))
        .ok_or_else(|| SaplingError::InvalidTreeState("bad value commitment".into()))?;
    let cmu = Option::from(ExtractedNoteCommitment::from_bytes(&out.cmu))
        .ok_or_else(|| SaplingError::InvalidTreeState("bad note commitment".into()))?;
    let mut enc = [0u8; 580];
    enc.copy_from_slice(&out.enc);
    let mut oct = [0u8; 80];
    oct.copy_from_slice(&out.ct);
    let mut proof = [0u8; 192];
    proof.copy_from_slice(&out.proof);
    let od: OutputDescription<GrothProofBytes> =
        OutputDescription::from_parts(cv, cmu, EphemeralKeyBytes(out.epk), enc, oct, proof);

    Ok(
        sapling_crypto::note_encryption::try_sapling_note_decryption(&prepared, &od, zip212).map(
            |(note, addr, memo)| ReadNote {
                value: note.value().inner(),
                recipient: addr.to_bytes(),
                memo,
            },
        ),
    )
}

/// Parse a 128-byte `DiversifiableFullViewingKey` — what a watch-only wallet
/// holds. It can find and read notes but cannot spend them.
pub fn dfvk_from_bytes(bytes: &[u8; 128]) -> Result<DiversifiableFullViewingKey, SaplingError> {
    DiversifiableFullViewingKey::from_bytes(bytes)
        .ok_or_else(|| SaplingError::InvalidKey("diversifiable full viewing key".into()))
}

/// Derive a `DiversifiableFullViewingKey` from a 169-byte `ExtendedSpendingKey`
/// (`z_exportkey <zaddr> true`). Convenience for wallets that hold the spending
/// key; a viewing-only scanner should pass its DFVK bytes directly instead.
pub fn dfvk_from_extsk(extsk_bytes: &[u8]) -> Result<DiversifiableFullViewingKey, SaplingError> {
    let extsk = ExtendedSpendingKey::from_bytes(extsk_bytes)
        .map_err(|e| SaplingError::InvalidKey(format!("extended spending key: {e:?}")))?;
    Ok(extsk.to_diversifiable_full_viewing_key())
}

#[cfg(test)]
mod tree_tests {
    use super::*;

    /// A real commitment tree a VRSCTEST daemon returned from `getsaplingtree`
    /// at height 1 166 329, together with that block's `finalsaplingroot`.
    fn fixture() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/daemon/sapling_tree.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).expect("fixture")).expect("json")
    }

    /// The end-to-end check: our parse of the daemon's frontier must produce the
    /// root the daemon itself put in the block header. A frontier parsed wrongly
    /// yields a witness rooted at an anchor no node has seen — and nothing else
    /// in an offline signer would catch it.
    #[test]
    fn the_parsed_tree_reproduces_the_block_header_root() {
        let fixture = fixture();
        let tree =
            TreeStateBefore::from_hex(fixture["tree_hex"].as_str().expect("tree_hex")).unwrap();

        // `finalsaplingroot` is displayed byte-reversed, like a txid.
        let mut expected = hex::decode(
            fixture["finalsaplingroot"]
                .as_str()
                .expect("finalsaplingroot"),
        )
        .unwrap();
        expected.reverse();

        assert_eq!(tree.root().unwrap().to_vec(), expected);
    }

    #[test]
    fn the_parsed_tree_holds_every_commitment_on_the_chain() {
        let tree =
            TreeStateBefore::from_hex(fixture()["tree_hex"].as_str().expect("tree_hex")).unwrap();
        // Sapling outputs mined on VRSCTEST as of the fixture height.
        assert_eq!(tree.size().unwrap(), 3164);
    }

    #[test]
    fn an_empty_tree_round_trips() {
        let tree = TreeStateBefore::from_serialized(&[0x00, 0x00, 0x00]).unwrap();
        assert!(tree.left.is_none() && tree.right.is_none() && tree.parents.is_empty());
        assert_eq!(tree.size().unwrap(), 0);
    }

    #[test]
    fn refuses_a_truncated_tree() {
        let full = hex::decode(fixture()["tree_hex"].as_str().expect("tree_hex")).unwrap();
        for cut in [1, 20, 40, full.len() - 1] {
            assert!(
                TreeStateBefore::from_serialized(&full[..cut]).is_err(),
                "truncating to {cut} bytes parsed instead of failing"
            );
        }
    }

    #[test]
    fn refuses_trailing_bytes() {
        let mut extended = hex::decode(fixture()["tree_hex"].as_str().expect("tree_hex")).unwrap();
        extended.push(0x00);
        assert!(matches!(
            TreeStateBefore::from_serialized(&extended),
            Err(SaplingError::InvalidTreeState(_))
        ));
    }

    #[test]
    fn refuses_an_invalid_optional_node_tag() {
        assert!(matches!(
            TreeStateBefore::from_serialized(&[0x02]),
            Err(SaplingError::InvalidTreeState(_))
        ));
    }

    #[test]
    fn refuses_more_parents_than_a_sapling_tree_has_levels() {
        assert!(matches!(
            TreeStateBefore::from_serialized(&[0x00, 0x00, 0x40]),
            Err(SaplingError::InvalidTreeState(_))
        ));
    }
}

/// Build the Merkle witness for a note, returning the anchor it roots to and
/// the path itself.
///
/// The frontier before the note's block fixes everything earlier; appending the
/// block's commitments up to and including the note positions it, and appending
/// the rest of the block advances the witness to the end of that block.
///
/// `block_cmus` must be EVERY Sapling commitment in the note's block, in order —
/// not only the caller's. A missing one shifts every later position and silently
/// produces a witness for the wrong leaf.
pub(crate) fn build_witness(
    tree_before_block: &TreeStateBefore,
    block_cmus: &[[u8; 32]],
    my_cmu_index: usize,
) -> Result<(sapling_crypto::Node, sapling_crypto::MerklePath), SaplingError> {
    if my_cmu_index >= block_cmus.len() {
        return Err(SaplingError::Witness(format!(
            "my_cmu_index {my_cmu_index} is out of range for {} commitments in the block",
            block_cmus.len()
        )));
    }
    let mut tree = commitment_tree(tree_before_block)?;
    for cmu in block_cmus.iter().take(my_cmu_index + 1) {
        tree.append(node(*cmu)?)
            .map_err(|_| SaplingError::Witness("commitment tree is full".into()))?;
    }
    let mut incremental = sapling_crypto::IncrementalWitness::from_tree(tree)
        .ok_or_else(|| SaplingError::Witness("no note commitment to witness".into()))?;
    for cmu in block_cmus.iter().skip(my_cmu_index + 1) {
        incremental
            .append(node(*cmu)?)
            .map_err(|_| SaplingError::Witness("witness is full".into()))?;
    }
    let root = incremental.root();
    let path = incremental
        .path()
        .ok_or_else(|| SaplingError::Witness("witness has no path".into()))?;
    Ok((root, path))
}

/// The anchor a note's witness roots to — **without** running the prover.
///
/// Check this against a `finalsaplingroot` the chain actually has before
/// spending 30 seconds on a Groth16 proof. A frontier taken from the wrong
/// height fails nowhere else: the note decrypts, the witness builds, the proof
/// generates, and only the daemon objects, with
/// `18: bad-txns-shielded-requirements-not-met`.
///
/// Needs no proving parameters, so a watch-only wallet can verify its own
/// witness data.
pub fn witness_anchor(
    tree_before_block: &TreeStateBefore,
    block_cmus: &[[u8; 32]],
    my_cmu_index: usize,
) -> Result<[u8; 32], SaplingError> {
    Ok(build_witness(tree_before_block, block_cmus, my_cmu_index)?
        .0
        .to_bytes())
}

#[cfg(test)]
mod witness_tests {
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
                bytes.reverse(); // the daemon displays commitments reversed
                bytes
            })
            .collect()
    }

    /// The witness for a real note on VRSCTEST must root to the anchor the chain
    /// actually has — the `finalsaplingroot` in the block header.
    ///
    /// This is the whole game for spending offline. It also pins the derivation
    /// the frontier came from: a Sapling frontier holds its last two leaves in
    /// `left`/`right`, so while a note is still the second-to-last commitment on
    /// the chain, clearing those two recovers the tree as it stood before the
    /// note's block. That does NOT generalise — once anything else is shielded,
    /// the pair cascades into `parents` and the earlier state is gone for good.
    #[test]
    fn a_real_notes_witness_roots_to_the_chains_own_anchor() {
        let fixture = fixture();
        let before = TreeStateBefore::from_hex(
            fixture["frontier_before_block_1166308_hex"]
                .as_str()
                .expect("frontier"),
        )
        .expect("parse");
        assert_eq!(before.size().expect("size"), 3162);

        let cmus = wire_cmus(&fixture);
        let index = usize::try_from(fixture["my_cmu_index"].as_u64().expect("index")).unwrap();
        let anchor = witness_anchor(&before, &cmus, index).expect("anchor");

        let mut expected = hex::decode(
            fixture["finalsaplingroot"]
                .as_str()
                .expect("finalsaplingroot"),
        )
        .unwrap();
        expected.reverse();
        assert_eq!(anchor.to_vec(), expected);
    }

    /// Dropping a commitment that is not ours still breaks the witness: every
    /// later position shifts, so the path is built for the wrong leaf.
    #[test]
    fn omitting_another_partys_commitment_changes_the_anchor() {
        let fixture = fixture();
        let before = TreeStateBefore::from_hex(
            fixture["frontier_before_block_1166308_hex"]
                .as_str()
                .expect("frontier"),
        )
        .unwrap();
        let cmus = wire_cmus(&fixture);
        let full = witness_anchor(&before, &cmus, 0).unwrap();
        let partial = witness_anchor(&before, &cmus[..1], 0).unwrap();
        assert_ne!(full, partial);
    }

    #[test]
    fn a_frontier_from_the_wrong_height_changes_the_anchor() {
        let fixture = fixture();
        let correct = TreeStateBefore::from_hex(
            fixture["frontier_before_block_1166308_hex"]
                .as_str()
                .expect("frontier"),
        )
        .unwrap();
        // The tip frontier: parses fine, right size class, wrong height.
        let tip = TreeStateBefore::from_hex(fixture["tree_hex"].as_str().unwrap()).unwrap();
        let cmus = wire_cmus(&fixture);
        assert_ne!(
            witness_anchor(&correct, &cmus, 0).unwrap(),
            witness_anchor(&tip, &cmus, 0).unwrap()
        );
    }
}
