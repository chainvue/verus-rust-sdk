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
use sapling_crypto::zip32::{DiversifiableFullViewingKey, ExtendedSpendingKey};
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
    pub recipient: [u8; 43],
    /// Note nullifier — matches this note's entry in a future spend's
    /// `vShieldedSpend`; a wallet marks the note spent when it sees this
    /// nullifier in a compact block.
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

/// Derive a `DiversifiableFullViewingKey` from a 169-byte `ExtendedSpendingKey`
/// (`z_exportkey <zaddr> true`). Convenience for wallets that hold the spending
/// key; a viewing-only scanner should pass its DFVK bytes directly instead.
pub fn dfvk_from_extsk(extsk_bytes: &[u8]) -> Result<DiversifiableFullViewingKey, SaplingError> {
    let extsk = ExtendedSpendingKey::from_bytes(extsk_bytes)
        .map_err(|e| SaplingError::InvalidKey(format!("extended spending key: {e:?}")))?;
    Ok(extsk.to_diversifiable_full_viewing_key())
}
