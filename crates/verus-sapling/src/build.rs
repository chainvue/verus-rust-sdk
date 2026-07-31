//! Building shielded transactions: t→z, z→z and z→t.
//!
//! This is the proving half of the crate — the part that needs Groth16 and the
//! ~50 MB of [`SaplingParams`]. It is behind the `prover` feature for that
//! reason: a wallet that only wants to see its balance should not compile
//! bellman.
//!
//! # The two shapes
//!
//! * [`build_shield`] — t→z. Value enters the shielded pool from transparent
//!   inputs. There are no shielded spends, so the anchor is the empty tree and
//!   the only signature the shielded side needs is the binding signature.
//! * [`build_shielded_spend`] — z→z, z→t, or both at once. Spends one note into
//!   any mix of shielded and transparent outputs. There are no transparent
//!   *inputs*, so the transaction is complete the moment this returns.
//!
//! # Signing order, and why it is safe
//!
//! The ZIP-243 *shielded* sighash — what the binding signature and the
//! spend-auth signatures commit to — has **no transparent-input section**, and
//! `scriptSig` bytes never reach `hashPrevouts`, `hashSequence` or
//! `hashOutputs`. So a t→z transaction can be proven and binding-signed here
//! with empty `scriptSig`s and its transparent inputs signed afterwards, by this
//! SDK's transparent signer or by a daemon's `signrawtransaction`. Neither
//! signature invalidates the other.
//!
//! # Provenance
//!
//! Ported from `@chainvue/verus-sapling`, where all three flows were built,
//! broadcast and accepted by a Verus testnet daemon. The proving and sighash
//! logic is unchanged; what is new is the typed error surface, the shared
//! [`verus_wire::TxV4`] serializer, and returning that transaction rather than a
//! hex string.

use rand::rngs::OsRng;
use sapling_crypto::builder::{Builder, BundleType};
use sapling_crypto::bundle::{Authorized, Bundle, GrothProofBytes, OutputDescription};
use sapling_crypto::circuit::{OutputParameters, SpendParameters};
use sapling_crypto::keys::PreparedIncomingViewingKey;
use sapling_crypto::note::ExtractedNoteCommitment;
use sapling_crypto::note_encryption::{try_sapling_note_decryption, Zip212Enforcement};
use sapling_crypto::value::{NoteValue, ValueCommitment};
use sapling_crypto::zip32::ExtendedSpendingKey;
use sapling_crypto::{Anchor, MerklePath, Note, PaymentAddress};
use verus_wire::{ShieldedSpend, TxIn, TxOut, TxV4};
use zcash_note_encryption::EphemeralKeyBytes;

use crate::error::SaplingError;
use crate::params::SaplingParams;
use crate::scan::{build_witness, FullOutput, TreeStateBefore};
use crate::witness::NoteWitness;

/// Size of a Sapling memo field (ZIP-302), in bytes.
pub const MEMO_SIZE: usize = 512;

/// One shielded output: where it goes, how much, and the memo it carries.
pub struct ShieldedOutput {
    /// Raw 43-byte Sapling payment address — decode a `zs` bech32 address first
    /// if that is what you hold.
    pub recipient: [u8; 43],
    /// Value in zatoshi.
    pub value: u64,
    /// The memo field, already UTF-8-encoded and zero-padded by the caller.
    pub memo: [u8; MEMO_SIZE],
}

impl ShieldedOutput {
    /// An output with an empty (all-zero) memo.
    pub fn new(recipient: [u8; 43], value: u64) -> Self {
        Self {
            recipient,
            value,
            memo: [0u8; MEMO_SIZE],
        }
    }
}

/// A t→z build: transparent value in, shielded value out.
pub struct ShieldSpec<'a> {
    /// Transparent inputs, with empty `scriptSig`s — see the module docs on why
    /// signing them afterwards is safe.
    pub transparent_inputs: &'a [TxIn],
    /// Transparent outputs, typically just the change.
    pub transparent_outputs: &'a [TxOut],
    /// Where the shielded value goes. At least one is required.
    pub shielded_outputs: &'a [ShieldedOutput],
    /// nLockTime.
    pub lock_time: u32,
    /// Block height after which the transaction expires.
    pub expiry_height: u32,
    /// Consensus branch id — [`verus_wire::consensus::VERUS_BRANCH_ID`] on both
    /// Verus mainnet and testnet.
    pub branch_id: u32,
    /// Note-plaintext encoding. Always [`crate::VERUS_ZIP212`] on Verus.
    pub zip212: Zip212Enforcement,
}

/// The note being spent, plus everything needed to witness it.
///
/// A signing host does not need a full node: a chain scanner (lightwalletd, or
/// the daemon's `z_gettreestate`) supplies the witness inputs.
pub struct NoteToSpend<'a> {
    /// 169-byte extended spending key (`z_exportkey <zaddr> true`).
    pub extsk_bytes: &'a [u8],
    /// The output that created this note, as raw wire bytes — decrypted here to
    /// recover the note itself.
    pub output: &'a FullOutput,
    /// Commitment tree state just BEFORE the note's block
    /// (`z_gettreestate(height - 1)`).
    pub tree_before_block: &'a TreeStateBefore,
    /// Every Sapling output commitment in the note's block, in order.
    pub block_cmus: &'a [[u8; 32]],
    /// Index into `block_cmus` of this note's own commitment.
    pub my_cmu_index: usize,
    /// A witness already advanced past the note's own block.
    ///
    /// When `None`, the witness is built from the three fields above and roots
    /// to the end of the note's own block. That is fine for a note spent alone,
    /// and it is why notes from **different blocks cannot be combined** without
    /// this: a bundle carries one anchor, and two notes witnessed at their own
    /// blocks root to two different ones.
    ///
    /// Set it to a [`NoteWitness`] advanced to a
    /// common height and notes from anywhere in the chain can be spent together.
    /// The other fields are then unused for witnessing, but still describe where
    /// the note came from.
    pub advanced_witness: Option<&'a NoteWitness>,
}

/// A z→z / z→t build: one or more shielded notes in, any mix of outputs out.
pub struct SpendSpec<'a> {
    /// The notes to spend and their witness inputs.
    ///
    /// **Every note must be witnessed at the same anchor.** A Sapling bundle
    /// carries one anchor for all of its spends, so notes witnessed at different
    /// heights cannot be combined — advance them to a common tip first with
    /// [`NoteWitness`]. Mismatched anchors are
    /// refused here rather than silently taking the first, which would produce
    /// proofs against a tree the other notes are not in.
    pub notes: &'a [NoteToSpend<'a>],
    /// Shielded recipients.
    pub shielded_outputs: &'a [ShieldedOutput],
    /// Transparent recipients.
    pub transparent_outputs: &'a [TxOut],
    /// The miner fee, in zatoshi. Checked against the decrypted note value: the
    /// daemon only rejects a *negative* fee, so an accidental overshoot — a
    /// forgotten change output — is a perfectly valid transaction that donates
    /// the difference to a miner. This check is the only thing standing between
    /// a caller and that.
    pub fee: u64,
    /// Block height after which the transaction expires.
    pub expiry_height: u32,
    /// Consensus branch id.
    pub branch_id: u32,
    /// Note-plaintext encoding. Always [`crate::VERUS_ZIP212`] on Verus.
    pub zip212: Zip212Enforcement,
    /// The anchor the chain actually has, if the caller has one to check
    /// against — a `finalsaplingroot` from a block header they trust.
    ///
    /// **Supply it.** A witness built against the wrong frontier fails
    /// *nowhere* locally: the note decrypts, the witness builds, the proof
    /// generates, the transaction serializes — and the daemon then rejects it
    /// with `bad-txns-shielded-requirements-not-met`, after thirty seconds of
    /// proving. Checked here it costs a comparison, and it is checked *before*
    /// the first proof rather than after.
    ///
    /// `None` keeps the old behaviour for callers who genuinely have nothing
    /// to compare against. It is not the safe default, only the possible one.
    pub expected_anchor: Option<[u8; 32]>,
}

/// Build and prove a t→z transaction.
///
/// The returned transaction is complete on the shielded side and unsigned on the
/// transparent side; fill in the `scriptSig`s, then [`TxV4::serialize`].
///
/// Value conservation is left to the transparent side here, because a [`TxIn`]
/// does not carry the value of the output it spends — `verus-tx` is where that
/// check belongs.
pub fn build_shield(params: &SaplingParams, spec: &ShieldSpec<'_>) -> Result<TxV4, SaplingError> {
    if spec.shielded_outputs.is_empty() {
        return Err(SaplingError::NoShieldedOutput);
    }
    let mut rng = OsRng;

    // No shielded spends, so the anchor is the empty tree.
    let mut builder = Builder::new(spec.zip212, BundleType::DEFAULT, Anchor::empty_tree());
    for out in spec.shielded_outputs {
        // ovk = None: the sender keeps no outgoing-viewing linkability for a
        // shield. A wallet that wants to detect its own sends would pass Some.
        builder
            .add_output(
                None,
                payment_address(&out.recipient)?,
                NoteValue::from_raw(out.value),
                out.memo,
            )
            .map_err(|e| SaplingError::Proving(format!("add_output: {e:?}")))?;
    }

    let (bundle, _meta) = builder
        .build::<SpendParameters, OutputParameters, _, i64>(&[], &mut rng)
        .map_err(|e| SaplingError::Proving(format!("build: {e:?}")))?
        .ok_or_else(|| SaplingError::Proving("builder produced no bundle".into()))?;

    // Prove first: proving fixes the output descriptions, which feed the
    // sighash, which the binding signature then commits to.
    let proven = bundle.create_proofs(&params.spend, &params.output, &mut rng, ());

    let mut tx = TxV4 {
        inputs: spec.transparent_inputs.to_vec(),
        outputs: spec.transparent_outputs.to_vec(),
        lock_time: spec.lock_time,
        expiry_height: spec.expiry_height,
        value_balance: *proven.value_balance(),
        shielded_spends: Vec::new(),
        shielded_outputs: proven
            .shielded_outputs()
            .iter()
            .map(output_description_bytes)
            .collect(),
        binding_sig: None,
    };

    let sighash = tx.shielded_sighash(spec.branch_id);
    let authorized: Bundle<Authorized, i64> = proven
        .apply_signatures(rng, sighash, &[])
        .map_err(|e| SaplingError::Proving(format!("apply_signatures: {e:?}")))?;
    tx.binding_sig = Some(binding_sig_bytes(&authorized));
    Ok(tx)
}

/// Build, prove and fully sign a transaction that spends one shielded note.
///
/// Covers z→z, z→t and a mix of both. There are no transparent inputs, so the
/// result needs nothing further: serialize it and broadcast.
pub fn build_shielded_spend(
    params: &SaplingParams,
    spec: &SpendSpec<'_>,
) -> Result<TxV4, SaplingError> {
    let mut rng = OsRng;

    if spec.notes.is_empty() {
        return Err(SaplingError::Proving(
            "a spend needs at least one note".into(),
        ));
    }

    // Decrypt every note and witness it before building anything: a bundle
    // commits to one anchor, so a disagreement has to be caught before the first
    // proof rather than after the last.
    let mut prepared = Vec::with_capacity(spec.notes.len());
    let mut total_in: u64 = 0;
    let mut anchor: Option<Anchor> = None;
    let mut seen_commitments: Vec<[u8; 32]> = Vec::new();

    for (index, to_spend) in spec.notes.iter().enumerate() {
        let extsk = ExtendedSpendingKey::from_bytes(to_spend.extsk_bytes)
            .map_err(|e| SaplingError::InvalidKey(format!("note {index}: {e:?}")))?;
        let note = decrypt_note_to_spend(&extsk, to_spend.output, spec.zip212)?;

        // The same note twice is a double spend inside one transaction: two
        // spends with the same nullifier, which consensus rejects after the
        // proofs have been paid for.
        if seen_commitments.contains(&to_spend.output.cmu) {
            return Err(SaplingError::Proving(format!(
                "note {index} is already being spent by this transaction"
            )));
        }
        seen_commitments.push(to_spend.output.cmu);

        let (note_anchor, merkle_path) = witness(to_spend)?;
        match anchor {
            None => anchor = Some(note_anchor),
            Some(existing) if existing.to_bytes() != note_anchor.to_bytes() => {
                return Err(SaplingError::Witness(format!(
                    "note {index} is witnessed at anchor {} but note 0 at {}; \
                     advance every witness to the same height before spending",
                    hex::encode(note_anchor.to_bytes()),
                    hex::encode(existing.to_bytes())
                )));
            }
            Some(_) => {}
        }
        // Against the chain, not just against each other. Consistency among
        // the notes proves they share a tree; it does not prove it is the
        // tree consensus has.
        if let Some(expected) = spec.expected_anchor {
            if note_anchor.to_bytes() != expected {
                return Err(SaplingError::Witness(format!(
                    "note {index} witnesses to anchor {}, but the chain's root is {} — \
                     the witness is built against a frontier the chain does not have, \
                     which proves and serializes fine and is rejected on broadcast",
                    hex::encode(note_anchor.to_bytes()),
                    hex::encode(expected)
                )));
            }
        }

        total_in = total_in
            .checked_add(note.value().inner())
            .ok_or_else(|| SaplingError::Proving("the notes being spent overflow a u64".into()))?;
        prepared.push((extsk, note, merkle_path));
    }

    check_conservation(
        total_in,
        spec.shielded_outputs,
        spec.transparent_outputs,
        spec.fee,
    )?;

    let anchor = anchor.expect("checked non-empty above");
    // Outputs are keyed to the first note's outgoing viewing key, which is what
    // lets that wallet recover its own sends. Notes from different accounts in
    // one transaction would need a choice this API does not offer.
    let ovk = prepared[0].0.expsk.ovk;

    let mut builder = Builder::new(spec.zip212, BundleType::DEFAULT, anchor);
    for (extsk, note, merkle_path) in &prepared {
        let fvk = extsk.to_diversifiable_full_viewing_key().fvk().clone();
        builder
            .add_spend(fvk, note.clone(), merkle_path.clone())
            .map_err(|e| SaplingError::Proving(format!("add_spend: {e:?}")))?;
    }
    for out in spec.shielded_outputs {
        builder
            .add_output(
                Some(ovk),
                payment_address(&out.recipient)?,
                NoteValue::from_raw(out.value),
                out.memo,
            )
            .map_err(|e| SaplingError::Proving(format!("add_output: {e:?}")))?;
    }

    let spending_keys: Vec<_> = prepared.iter().map(|(extsk, _, _)| extsk.clone()).collect();
    let (bundle, _meta) = builder
        .build::<SpendParameters, OutputParameters, _, i64>(&spending_keys, &mut rng)
        .map_err(|e| SaplingError::Proving(format!("build: {e:?}")))?
        .ok_or_else(|| SaplingError::Proving("builder produced no bundle".into()))?;
    let proven = bundle.create_proofs(&params.spend, &params.output, &mut rng, ());

    let mut tx = TxV4 {
        inputs: Vec::new(),
        outputs: spec.transparent_outputs.to_vec(),
        lock_time: 0,
        expiry_height: spec.expiry_height,
        value_balance: *proven.value_balance(),
        shielded_spends: proven
            .shielded_spends()
            .iter()
            .map(|s| ShieldedSpend::unsigned(spend_body(s)))
            .collect(),
        shielded_outputs: proven
            .shielded_outputs()
            .iter()
            .map(output_description_bytes)
            .collect(),
        binding_sig: None,
    };

    let sighash = tx.shielded_sighash(spec.branch_id);
    // One spend-auth signature per spend, in the same order.
    let asks: Vec<_> = prepared
        .iter()
        .map(|(extsk, _, _)| extsk.expsk.ask.clone())
        .collect();
    let authorized: Bundle<Authorized, i64> = proven
        .apply_signatures(rng, sighash, &asks)
        .map_err(|e| SaplingError::Proving(format!("apply_signatures: {e:?}")))?;

    // Attach the signatures. The bodies do not change — and must not, since the
    // sighash just signed covers them; `ShieldedSpend` keeps the two apart so
    // this is an assignment rather than a re-serialization that could drift.
    for (spend, signed) in tx
        .shielded_spends
        .iter_mut()
        .zip(authorized.shielded_spends())
    {
        debug_assert_eq!(spend.body, spend_body(signed), "signing changed the body");
        spend.spend_auth_sig = Some(<[u8; 64]>::from(*signed.spend_auth_sig()));
    }
    tx.binding_sig = Some(binding_sig_bytes(&authorized));
    Ok(tx)
}

/// Serialize a Sapling output description in v4 wire order:
/// `cv || cmu || ephemeralKey || encCiphertext || outCiphertext || zkproof`.
fn output_description_bytes(out: &OutputDescription<GrothProofBytes>) -> Vec<u8> {
    let mut v = Vec::with_capacity(948);
    v.extend_from_slice(&out.cv().to_bytes());
    v.extend_from_slice(&out.cmu().to_bytes());
    v.extend_from_slice(&out.ephemeral_key().0);
    v.extend_from_slice(out.enc_ciphertext());
    v.extend_from_slice(out.out_ciphertext());
    v.extend_from_slice(out.zkproof());
    v
}

/// The body of a Sapling spend description: `cv || anchor || nullifier || rk ||
/// zkproof`, 320 bytes. The spend-auth signature is [`ShieldedSpend`]'s job.
fn spend_body<A>(spend: &sapling_crypto::bundle::SpendDescription<A>) -> Vec<u8>
where
    A: sapling_crypto::bundle::Authorization<SpendProof = GrothProofBytes>,
{
    let mut v = Vec::with_capacity(320);
    v.extend_from_slice(&spend.cv().to_bytes());
    v.extend_from_slice(&spend.anchor().to_bytes());
    v.extend_from_slice(&spend.nullifier().0);
    v.extend_from_slice(&<[u8; 32]>::from(*spend.rk()));
    v.extend_from_slice(spend.zkproof().as_ref());
    v
}

fn binding_sig_bytes(bundle: &Bundle<Authorized, i64>) -> [u8; 64] {
    <[u8; 64]>::from(bundle.authorization().binding_sig)
}

fn payment_address(bytes: &[u8; 43]) -> Result<PaymentAddress, SaplingError> {
    PaymentAddress::from_bytes(bytes).ok_or(SaplingError::InvalidPaymentAddress)
}

/// Recover the note to spend by decrypting the output that created it.
fn decrypt_note_to_spend(
    extsk: &ExtendedSpendingKey,
    out: &FullOutput,
    zip212: Zip212Enforcement,
) -> Result<Note, SaplingError> {
    let enc = fixed::<580>(&out.enc, "encCiphertext")?;
    let oct = fixed::<80>(&out.ct, "outCiphertext")?;
    let proof = fixed::<192>(&out.proof, "zkproof")?;
    let cv = Option::from(ValueCommitment::from_bytes_not_small_order(&out.cv))
        .ok_or_else(|| SaplingError::InvalidTreeState("bad value commitment".into()))?;
    let cmu = Option::from(ExtractedNoteCommitment::from_bytes(&out.cmu))
        .ok_or_else(|| SaplingError::InvalidTreeState("bad note commitment".into()))?;
    let od: OutputDescription<GrothProofBytes> =
        OutputDescription::from_parts(cv, cmu, EphemeralKeyBytes(out.epk), enc, oct, proof);

    let ivk = extsk.to_diversifiable_full_viewing_key().fvk().vk.ivk();
    let prepared = PreparedIncomingViewingKey::new(&ivk);
    let (note, _addr, _memo) = try_sapling_note_decryption(&prepared, &od, zip212)
        .ok_or(SaplingError::NoteNotDecryptable)?;
    Ok(note)
}

/// Every zatoshi in the note must land somewhere. See [`SpendSpec::fee`].
fn check_conservation(
    note_value: u64,
    shielded: &[ShieldedOutput],
    transparent: &[TxOut],
    fee: u64,
) -> Result<(), SaplingError> {
    let mut outputs: u64 = 0;
    for out in shielded {
        outputs = outputs
            .checked_add(out.value)
            .ok_or(SaplingError::ValueOverflow)?;
    }
    for out in transparent {
        outputs = outputs
            .checked_add(out.value)
            .ok_or(SaplingError::ValueOverflow)?;
    }
    let spent = outputs
        .checked_add(fee)
        .ok_or(SaplingError::ValueOverflow)?;
    if note_value != spent {
        return Err(SaplingError::Conservation {
            note: note_value,
            outputs,
            fee,
        });
    }
    Ok(())
}

/// Build the Merkle path proving the note is in the commitment tree, and the
/// anchor it roots to.
///
/// The tree state before the note's block fixes the frontier; appending the
/// block's commitments up to and including ours positions the note, and
/// appending the rest of the block advances the witness to the block's end.
fn witness(note: &NoteToSpend<'_>) -> Result<(Anchor, MerklePath), SaplingError> {
    if let Some(advanced) = note.advanced_witness {
        return Ok((advanced.to_anchor(), advanced.path()?));
    }
    let (root, path) = build_witness(note.tree_before_block, note.block_cmus, note.my_cmu_index)?;
    Ok((Anchor::from(root), path))
}

/// Copy a slice into a fixed-size array, erroring rather than panicking on a
/// length mismatch — this is an untrusted-input boundary.
fn fixed<const N: usize>(bytes: &[u8], field: &str) -> Result<[u8; N], SaplingError> {
    bytes.try_into().map_err(|_| {
        SaplingError::InvalidTreeState(format!("{field}: expected {N} bytes, got {}", bytes.len()))
    })
}

#[cfg(test)]
mod tests {
    fn tree_fixture() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/daemon/sapling_tree.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).expect("fixture")).expect("json")
    }

    fn fixture_cmus(fixture: &serde_json::Value) -> Vec<[u8; 32]> {
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

    fn fixture_tree(fixture: &serde_json::Value) -> crate::scan::TreeStateBefore {
        crate::scan::TreeStateBefore::from_hex(
            fixture["frontier_before_block_1166308_hex"]
                .as_str()
                .expect("frontier"),
        )
        .expect("tree")
    }

    use super::*;

    fn shielded(value: u64) -> ShieldedOutput {
        ShieldedOutput::new([0u8; 43], value)
    }

    fn transparent(value: u64) -> TxOut {
        TxOut {
            value,
            script_pubkey: Vec::new(),
        }
    }

    #[test]
    fn conservation_accepts_an_exact_split() {
        assert!(
            check_conservation(100_000, &[shielded(70_000)], &[transparent(20_000)], 10_000)
                .is_ok()
        );
    }

    /// The check that exists because the daemon does not do it: an overshoot is
    /// a VALID transaction that quietly pays the difference to a miner.
    #[test]
    fn conservation_rejects_a_forgotten_change_output() {
        match check_conservation(100_000, &[shielded(10_000)], &[], 10_000) {
            Err(SaplingError::Conservation { note, outputs, fee }) => {
                assert_eq!((note, outputs, fee), (100_000, 10_000, 10_000));
            }
            other => panic!("expected a conservation error, got {other:?}"),
        }
    }

    #[test]
    fn conservation_rejects_spending_more_than_the_note_holds() {
        assert!(matches!(
            check_conservation(100_000, &[shielded(200_000)], &[], 10_000),
            Err(SaplingError::Conservation { .. })
        ));
    }

    #[test]
    fn conservation_does_not_wrap_on_overflow() {
        assert!(matches!(
            check_conservation(0, &[shielded(u64::MAX), shielded(1)], &[], 0),
            Err(SaplingError::ValueOverflow)
        ));
    }

    #[test]
    fn a_cmu_index_past_the_end_of_the_block_is_refused() {
        let tree = TreeStateBefore {
            left: None,
            right: None,
            parents: Vec::new(),
        };
        let output = FullOutput {
            cv: [0u8; 32],
            cmu: [0u8; 32],
            epk: [0u8; 32],
            enc: Vec::new(),
            ct: Vec::new(),
            proof: Vec::new(),
        };
        let note = NoteToSpend {
            extsk_bytes: &[],
            output: &output,
            tree_before_block: &tree,
            block_cmus: &[[1u8; 32]],
            my_cmu_index: 5,
            advanced_witness: None,
        };
        assert!(matches!(witness(&note), Err(SaplingError::Witness(_))));
    }

    /// A bundle carries ONE anchor for all of its spends. Notes witnessed at
    /// their own blocks root differently, so combining them is refused before
    /// the first proof rather than after the last — proving two notes costs
    /// seconds and the daemon's only reply would be that the requirements were
    /// not met.
    #[test]
    fn notes_witnessed_at_different_anchors_are_refused() {
        let fixture = tree_fixture();
        let cmus = fixture_cmus(&fixture);
        let tree = fixture_tree(&fixture);

        // The same commitments, but one witness stops a commitment earlier, so
        // the two root to different trees.
        let (early, _) = build_witness(&tree, &cmus[..1], 0).expect("early witness");
        let (late, _) = build_witness(&tree, &cmus, 0).expect("late witness");
        assert_ne!(
            early.to_bytes(),
            late.to_bytes(),
            "the fixture must have more than one commitment for this to mean anything"
        );
    }

    #[test]
    fn a_short_ciphertext_is_an_error_not_a_panic() {
        assert!(matches!(
            fixed::<580>(&[0u8; 4], "encCiphertext"),
            Err(SaplingError::InvalidTreeState(_))
        ));
    }

    #[test]
    fn an_invalid_payment_address_is_refused() {
        // All-zero bytes are not a valid diversifier + pk_d.
        assert!(matches!(
            payment_address(&[0u8; 43]),
            Err(SaplingError::InvalidPaymentAddress)
        ));
    }
}
