//! Verus v4 (Sapling) transactions: serialization and ZIP-243 sighashes.
//!
//! Ported from the serializer in `@chainvue/verus-sapling`, whose output is
//! locked by real transactions a Verus daemon produced and accepted
//! (`fixtures/daemon/`). The byte layout is unchanged; what is new here is
//! [`TxV4::transparent_sighash`], which the shielded-only original never needed
//! because the daemon filled scriptSigs via `signrawtransaction`.

use crate::compact::{write_compact_size, write_var_slice};
use crate::consensus::{
    sighash_personal, OUTPUTS_PERSONAL, PREVOUT_PERSONAL, SAPLING_VERSION_GROUP_ID,
    SEQUENCE_PERSONAL, SHIELDED_OUTPUTS_PERSONAL, SHIELDED_SPENDS_PERSONAL, SIGHASH_ALL,
    SIGHASH_ANYONECANPAY, SIGHASH_MASK, SIGHASH_NONE, SIGHASH_SINGLE, V4_HEADER,
};
use crate::error::WireError;
use crate::hash::{blake2b_personal, sha256d};

/// A transparent input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    /// Prevout txid in INTERNAL byte order — the reverse of how RPC displays it.
    pub txid_internal: [u8; 32],
    /// Index of the output being spent.
    pub vout: u32,
    /// Sequence number. Verus wallets use `0xffffffff`.
    pub sequence: u32,
    /// The unlocking script. Empty until signed.
    pub script_sig: Vec<u8>,
}

impl TxIn {
    /// An input with no unlocking script yet — the form used while building a
    /// transaction, and the only form a shielded-only builder ever needs.
    pub fn unsigned(txid_internal: [u8; 32], vout: u32, sequence: u32) -> Self {
        Self {
            txid_internal,
            vout,
            sequence,
            script_sig: Vec::new(),
        }
    }
}

/// A transparent output: value in satoshis and a raw scriptPubKey.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    /// Value in satoshis. Integers throughout — there is no float in the value path.
    pub value: u64,
    /// Raw scriptPubKey bytes.
    pub script_pubkey: Vec<u8>,
}

/// A shielded spend description.
///
/// The signature is a separate field rather than part of `body` because a v4
/// spend description is serialized into the transaction WITH its 64-byte
/// spend-auth signature but hashed into the sighash WITHOUT it — a signature
/// cannot commit to itself. Holding one blob for both contexts means whoever
/// assembles it has to remember which form they are holding, and getting that
/// wrong yields a transaction that verifies nowhere. Here it is impossible to
/// get wrong: [`TxV4::serialize`] appends the signature, the sighash does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldedSpend {
    /// `cv || anchor || nullifier || rk || zkproof` — 320 bytes.
    pub body: Vec<u8>,
    /// The 64-byte spend-auth signature. `None` before signing.
    pub spend_auth_sig: Option<[u8; 64]>,
}

impl ShieldedSpend {
    /// An unsigned spend description — the form the sighash covers.
    pub fn unsigned(body: Vec<u8>) -> Self {
        Self {
            body,
            spend_auth_sig: None,
        }
    }
}

/// A Verus v4 (Sapling) transaction.
///
/// Shielded outputs are held as already-serialized 948-byte descriptions; they
/// are identical in both contexts. Spends are not — see [`ShieldedSpend`].
#[derive(Clone, Debug, Default)]
pub struct TxV4 {
    /// Transparent inputs.
    pub inputs: Vec<TxIn>,
    /// Transparent outputs.
    pub outputs: Vec<TxOut>,
    /// nLockTime.
    pub lock_time: u32,
    /// Block height after which the transaction expires. `0` means never.
    pub expiry_height: u32,
    /// Net value moved out of the shielded pool, in satoshis. Zero when there
    /// are no shielded parts; negative when value enters the pool (t→z).
    pub value_balance: i64,
    /// Shielded spend descriptions.
    pub shielded_spends: Vec<ShieldedSpend>,
    /// Serialized shielded output descriptions (948 bytes each).
    pub shielded_outputs: Vec<Vec<u8>>,
    /// Sapling binding signature. Required if any shielded part is present.
    pub binding_sig: Option<[u8; 64]>,
}

impl TxV4 {
    /// Whether this transaction carries any shielded component.
    pub fn is_shielded(&self) -> bool {
        !self.shielded_spends.is_empty() || !self.shielded_outputs.is_empty()
    }

    /// Serialize to the bytes a Verus daemon accepts.
    ///
    /// Errors only if shielded parts are present without a binding signature —
    /// serializing zeros there would produce a transaction the network rejects.
    pub fn serialize(&self) -> Result<Vec<u8>, WireError> {
        if self.is_shielded() && self.binding_sig.is_none() {
            return Err(WireError::MissingBindingSignature);
        }

        let mut tx = Vec::new();
        tx.extend_from_slice(&V4_HEADER.to_le_bytes());
        tx.extend_from_slice(&SAPLING_VERSION_GROUP_ID.to_le_bytes());

        write_compact_size(&mut tx, self.inputs.len() as u64);
        for input in &self.inputs {
            tx.extend_from_slice(&input.txid_internal);
            tx.extend_from_slice(&input.vout.to_le_bytes());
            write_var_slice(&mut tx, &input.script_sig);
            tx.extend_from_slice(&input.sequence.to_le_bytes());
        }

        write_compact_size(&mut tx, self.outputs.len() as u64);
        for output in &self.outputs {
            tx.extend_from_slice(&output.value.to_le_bytes());
            write_var_slice(&mut tx, &output.script_pubkey);
        }

        tx.extend_from_slice(&self.lock_time.to_le_bytes());
        tx.extend_from_slice(&self.expiry_height.to_le_bytes());
        tx.extend_from_slice(&self.value_balance.to_le_bytes());

        write_compact_size(&mut tx, self.shielded_spends.len() as u64);
        for (index, spend) in self.shielded_spends.iter().enumerate() {
            let sig = spend
                .spend_auth_sig
                .ok_or(WireError::MissingSpendAuthSignature(index))?;
            tx.extend_from_slice(&spend.body);
            tx.extend_from_slice(&sig);
        }
        write_compact_size(&mut tx, self.shielded_outputs.len() as u64);
        for output in &self.shielded_outputs {
            tx.extend_from_slice(output);
        }

        write_compact_size(&mut tx, 0); // nJoinSplit

        if self.is_shielded() {
            let sig = self.binding_sig.ok_or(WireError::MissingBindingSignature)?;
            tx.extend_from_slice(&sig);
        }
        Ok(tx)
    }

    /// Parse a serialized v4 transaction.
    ///
    /// The exact inverse of [`TxV4::serialize`]. Until this existed every
    /// serializer in this workspace was write-only, and anything that needed to
    /// *read* a transaction — completing a counterparty's offer, checking what
    /// was actually built — had to ask a daemon.
    ///
    /// # This parses hostile input
    ///
    /// A transaction to be decoded generally came from someone else: an offer to
    /// be completed, bytes from a node, a file. So every length is checked
    /// against what remains rather than trusted, nothing is allocated on the
    /// strength of a declared count, and trailing bytes are refused instead of
    /// ignored — a decoder that stops early lets two different byte strings
    /// parse to the same transaction, which is a way to be paid for something
    /// other than what was signed.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = Reader::new(bytes);

        let header = reader.u32()?;
        if header != V4_HEADER {
            return Err(WireError::UnsupportedTransactionVersion(header));
        }
        let group = reader.u32()?;
        if group != SAPLING_VERSION_GROUP_ID {
            return Err(WireError::UnsupportedVersionGroup(group));
        }

        let input_count = reader.compact_size()?;
        let mut inputs = Vec::new();
        for _ in 0..input_count {
            let txid_internal = reader.array32()?;
            let vout = reader.u32()?;
            let script_sig = reader.var_slice()?.to_vec();
            let sequence = reader.u32()?;
            inputs.push(TxIn {
                txid_internal,
                vout,
                script_sig,
                sequence,
            });
        }

        let output_count = reader.compact_size()?;
        let mut outputs = Vec::new();
        for _ in 0..output_count {
            let value = reader.u64()?;
            let script_pubkey = reader.var_slice()?.to_vec();
            outputs.push(TxOut {
                value,
                script_pubkey,
            });
        }

        let lock_time = reader.u32()?;
        let expiry_height = reader.u32()?;
        // valueBalance is signed on the wire; the wrap is the intended
        // two's-complement reinterpretation, not a lossy narrowing.
        let value_balance = reader.u64()?.cast_signed();

        let spend_count = reader.compact_size()?;
        let mut shielded_spends = Vec::new();
        for _ in 0..spend_count {
            let body = reader.take(SPEND_BODY_LEN)?.to_vec();
            let spend_auth_sig = reader.array64()?;
            shielded_spends.push(ShieldedSpend {
                body,
                spend_auth_sig: Some(spend_auth_sig),
            });
        }

        let output_desc_count = reader.compact_size()?;
        let mut shielded_outputs = Vec::new();
        for _ in 0..output_desc_count {
            shielded_outputs.push(reader.take(SHIELDED_OUTPUT_LEN)?.to_vec());
        }

        let join_splits = reader.compact_size()?;
        if join_splits != 0 {
            return Err(WireError::JoinSplitsUnsupported(join_splits));
        }

        let shielded = !shielded_spends.is_empty() || !shielded_outputs.is_empty();
        let binding_sig = if shielded {
            Some(reader.array64()?)
        } else {
            None
        };

        // Trailing bytes are a different transaction wearing this one's prefix.
        reader.expect_end()?;

        Ok(TxV4 {
            inputs,
            outputs,
            lock_time,
            expiry_height,
            value_balance,
            shielded_spends,
            shielded_outputs,
            binding_sig,
        })
    }

    /// Transaction id, in internal byte order. Use
    /// [`txid_display`](crate::hash::txid_display) for the RPC representation.
    pub fn txid(&self) -> Result<[u8; 32], WireError> {
        Ok(sha256d(&self.serialize()?))
    }

    /// ZIP-243 sighash over the whole transaction with **no transparent-input
    /// section** — what the Sapling binding signature and the shielded
    /// spend-auth signatures commit to.
    pub fn shielded_sighash(&self, branch_id: u32) -> [u8; 32] {
        // Always SIGHASH_ALL: a shielded signature has no input index to narrow
        // to, and the binding signature must cover the whole transaction.
        let mut preimage = self.sighash_prefix();
        preimage.extend_from_slice(&SIGHASH_ALL.to_le_bytes());
        blake2b_personal(&sighash_personal(branch_id), &preimage)
    }

    /// ZIP-243 sighash for one transparent input.
    ///
    /// `script_code` is the script being satisfied — for P2PKH, the prevout's
    /// scriptPubKey. `value` is that prevout's value in satoshis; committing to
    /// it is what makes Overwinter-era sighashes immune to the fee-forgery
    /// attack the legacy algorithm allowed.
    ///
    /// Only [`SIGHASH_ALL`](crate::consensus::SIGHASH_ALL) is implemented.
    pub fn transparent_sighash(
        &self,
        branch_id: u32,
        input_index: usize,
        script_code: &[u8],
        value: u64,
        hash_type: u32,
    ) -> Result<[u8; 32], WireError> {
        check_sighash_type(hash_type)?;
        // SIGHASH_SINGLE without a matching output produces a signature that
        // commits to no outputs whatsoever. ZIP-243 permits it; nothing good
        // comes of it, so it is refused rather than silently signed.
        if hash_type & SIGHASH_MASK == SIGHASH_SINGLE && input_index >= self.outputs.len() {
            return Err(WireError::SighashSingleWithoutOutput {
                index: input_index,
                outputs: self.outputs.len(),
            });
        }
        let input = self
            .inputs
            .get(input_index)
            .ok_or(WireError::InputIndexOutOfRange {
                index: input_index,
                len: self.inputs.len(),
            })?;

        let mut preimage = self.sighash_prefix_for(hash_type, input_index);
        preimage.extend_from_slice(&hash_type.to_le_bytes());
        // The transparent-input section the shielded sighash omits.
        preimage.extend_from_slice(&input.txid_internal);
        preimage.extend_from_slice(&input.vout.to_le_bytes());
        write_var_slice(&mut preimage, script_code);
        preimage.extend_from_slice(&value.to_le_bytes());
        preimage.extend_from_slice(&input.sequence.to_le_bytes());

        Ok(blake2b_personal(&sighash_personal(branch_id), &preimage))
    }

    /// The part of the ZIP-243 preimage both sighashes share, up to but not
    /// including `nHashType`.
    ///
    /// Under `SIGHASH_ALL` the prevout/sequence/output hashes are identical for
    /// both, which is why this is shared rather than duplicated. The two
    /// sighashes then diverge in exactly one place: the transparent-input
    /// section. Note the shielded hashes come *before* `lockTime`.
    fn sighash_prefix(&self) -> Vec<u8> {
        self.sighash_prefix_for(SIGHASH_ALL, 0)
    }

    /// As [`TxV4::sighash_prefix`], for a given hash type.
    ///
    /// The three hashes are blanked according to ZIP-243 section "hash type":
    /// `ANYONECANPAY` drops the other inputs, `NONE` and `SINGLE` drop or narrow
    /// the outputs. Blanked means an all-zero hash, **not** an omitted field —
    /// the preimage keeps its shape.
    fn sighash_prefix_for(&self, hash_type: u32, input_index: usize) -> Vec<u8> {
        let base = hash_type & SIGHASH_MASK;
        let anyone_can_pay = hash_type & SIGHASH_ANYONECANPAY != 0;

        let hash_prevouts = if anyone_can_pay {
            [0u8; 32]
        } else {
            let mut data = Vec::with_capacity(self.inputs.len() * 36);
            for input in &self.inputs {
                data.extend_from_slice(&input.txid_internal);
                data.extend_from_slice(&input.vout.to_le_bytes());
            }
            blake2b_personal(PREVOUT_PERSONAL, &data)
        };
        let hash_sequence = if anyone_can_pay || base == SIGHASH_SINGLE || base == SIGHASH_NONE {
            [0u8; 32]
        } else {
            let mut data = Vec::with_capacity(self.inputs.len() * 4);
            for input in &self.inputs {
                data.extend_from_slice(&input.sequence.to_le_bytes());
            }
            blake2b_personal(SEQUENCE_PERSONAL, &data)
        };
        let hash_outputs = if base == SIGHASH_SINGLE {
            match self.outputs.get(input_index) {
                Some(output) => {
                    let mut data = Vec::new();
                    data.extend_from_slice(&output.value.to_le_bytes());
                    write_var_slice(&mut data, &output.script_pubkey);
                    blake2b_personal(OUTPUTS_PERSONAL, &data)
                }
                // Refused before reaching here for a transparent signature; the
                // zero hash is what ZIP-243 specifies.
                None => [0u8; 32],
            }
        } else if base == SIGHASH_NONE {
            [0u8; 32]
        } else {
            let mut data = Vec::new();
            for output in &self.outputs {
                data.extend_from_slice(&output.value.to_le_bytes());
                write_var_slice(&mut data, &output.script_pubkey);
            }
            blake2b_personal(OUTPUTS_PERSONAL, &data)
        };
        // No JoinSplits on Verus: all-zero per ZIP-243.
        let hash_joinsplits = [0u8; 32];
        // Bodies only: the spend-auth signature is never hashed.
        let spend_bodies: Vec<&[u8]> = self
            .shielded_spends
            .iter()
            .map(|spend| spend.body.as_slice())
            .collect();
        let hash_shielded_spends = hash_descriptions(SHIELDED_SPENDS_PERSONAL, &spend_bodies);
        let output_descriptions: Vec<&[u8]> = self
            .shielded_outputs
            .iter()
            .map(|output| output.as_slice())
            .collect();
        let hash_shielded_outputs =
            hash_descriptions(SHIELDED_OUTPUTS_PERSONAL, &output_descriptions);

        let mut preimage = Vec::with_capacity(256);
        preimage.extend_from_slice(&V4_HEADER.to_le_bytes());
        preimage.extend_from_slice(&SAPLING_VERSION_GROUP_ID.to_le_bytes());
        preimage.extend_from_slice(&hash_prevouts);
        preimage.extend_from_slice(&hash_sequence);
        preimage.extend_from_slice(&hash_outputs);
        preimage.extend_from_slice(&hash_joinsplits);
        preimage.extend_from_slice(&hash_shielded_spends);
        preimage.extend_from_slice(&hash_shielded_outputs);
        preimage.extend_from_slice(&self.lock_time.to_le_bytes());
        preimage.extend_from_slice(&self.expiry_height.to_le_bytes());
        preimage.extend_from_slice(&self.value_balance.to_le_bytes());
        preimage
    }
}

/// A Sapling spend description body: `cv || anchor || nullifier || rk || proof`.
const SPEND_BODY_LEN: usize = 320;
/// A Sapling output description, whole.
const SHIELDED_OUTPUT_LEN: usize = 948;

/// A bounds-checked cursor over untrusted bytes.
///
/// Every read is checked against what remains. Nothing here allocates on the
/// strength of a length that has not been verified to exist.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self
            .at
            .checked_add(n)
            .ok_or(WireError::TruncatedTransaction)?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or(WireError::TruncatedTransaction)?;
        self.at = end;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("took four bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("took eight bytes"),
        ))
    }

    fn array32(&mut self) -> Result<[u8; 32], WireError> {
        Ok(self.take(32)?.try_into().expect("took 32 bytes"))
    }

    fn array64(&mut self) -> Result<[u8; 64], WireError> {
        Ok(self.take(64)?.try_into().expect("took 64 bytes"))
    }

    /// A compact size, refusing the non-canonical encodings.
    ///
    /// Bitcoin accepts `0xfd 0x01 0x00` for 1; Verus does not re-serialize it
    /// that way, so a transaction encoded like that would round-trip to
    /// different bytes and a different txid. Refused rather than normalised.
    fn compact_size(&mut self) -> Result<u64, WireError> {
        let first = self.take(1)?[0];
        let value = match first {
            0xfd => {
                let n = u64::from(u16::from_le_bytes(
                    self.take(2)?.try_into().expect("two bytes"),
                ));
                if n < 0xfd {
                    return Err(WireError::NonCanonicalCompactSize);
                }
                n
            }
            0xfe => {
                let n = u64::from(u32::from_le_bytes(
                    self.take(4)?.try_into().expect("four bytes"),
                ));
                if n <= u64::from(u16::MAX) {
                    return Err(WireError::NonCanonicalCompactSize);
                }
                n
            }
            0xff => {
                let n = u64::from_le_bytes(self.take(8)?.try_into().expect("eight bytes"));
                if n <= u64::from(u32::MAX) {
                    return Err(WireError::NonCanonicalCompactSize);
                }
                n
            }
            n => u64::from(n),
        };
        // A count can never exceed what is left to read, so this bounds every
        // loop above without trusting the declared number.
        if value > (self.bytes.len() - self.at) as u64 {
            return Err(WireError::TruncatedTransaction);
        }
        Ok(value)
    }

    fn var_slice(&mut self) -> Result<&'a [u8], WireError> {
        let length = self.compact_size()?;
        let length = usize::try_from(length).map_err(|_| WireError::TruncatedTransaction)?;
        self.take(length)
    }

    fn expect_end(&self) -> Result<(), WireError> {
        if self.at != self.bytes.len() {
            return Err(WireError::TrailingBytes(self.bytes.len() - self.at));
        }
        Ok(())
    }
}

/// Refuse a hash type this crate does not implement.
fn check_sighash_type(hash_type: u32) -> Result<(), WireError> {
    let base = hash_type & SIGHASH_MASK;
    let known = matches!(base, SIGHASH_ALL | SIGHASH_NONE | SIGHASH_SINGLE);
    // Only ANYONECANPAY may appear outside the base bits. Anything else is a
    // hash type nobody agreed on, and signing under it is unpredictable.
    let extra = hash_type & !(SIGHASH_MASK | SIGHASH_ANYONECANPAY);
    if !known || extra != 0 {
        return Err(WireError::UnsupportedSighashType(hash_type));
    }
    Ok(())
}

/// Hash a set of shielded descriptions, or all-zero when there are none
/// (ZIP-243 specifies the zero hash for an empty set, not the hash of nothing).
fn hash_descriptions(personal: &[u8; 16], descriptions: &[&[u8]]) -> [u8; 32] {
    if descriptions.is_empty() {
        return [0u8; 32];
    }
    let mut data = Vec::new();
    for description in descriptions {
        data.extend_from_slice(description);
    }
    blake2b_personal(personal, &data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::VERUS_BRANCH_ID;

    fn tx_with_one_input() -> TxV4 {
        TxV4 {
            inputs: vec![TxIn::unsigned([0x11; 32], 0, 0xffff_ffff)],
            outputs: vec![TxOut {
                value: 50_000_000,
                script_pubkey: vec![0x76, 0xa9, 0x14],
            }],
            ..TxV4::default()
        }
    }

    #[test]
    fn transparent_and_shielded_sighashes_differ() {
        // They share a preimage prefix; if a refactor ever made them equal, the
        // transparent-input section would have gone missing.
        let tx = tx_with_one_input();
        let transparent = tx
            .transparent_sighash(VERUS_BRANCH_ID, 0, &[0x76, 0xa9], 1_000, SIGHASH_ALL)
            .unwrap();
        assert_ne!(transparent, tx.shielded_sighash(VERUS_BRANCH_ID));
    }

    #[test]
    fn transparent_sighash_commits_to_the_input_value() {
        // The whole point of the Overwinter-era algorithm: signing a different
        // input amount must produce a different hash.
        let tx = tx_with_one_input();
        let a = tx
            .transparent_sighash(VERUS_BRANCH_ID, 0, &[0x76], 1_000, SIGHASH_ALL)
            .unwrap();
        let b = tx
            .transparent_sighash(VERUS_BRANCH_ID, 0, &[0x76], 1_001, SIGHASH_ALL)
            .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn a_wrong_branch_id_changes_the_sighash() {
        let tx = tx_with_one_input();
        assert_ne!(
            tx.shielded_sighash(VERUS_BRANCH_ID),
            tx.shielded_sighash(VERUS_BRANCH_ID + 1)
        );
    }

    /// The marketplace hash type is now implemented; this used to be refused.
    ///
    /// It needs an output at the input's index, which is the rule
    /// `SIGHASH_SINGLE` carries with it.
    #[test]
    fn accepts_the_marketplace_hash_type() {
        let tx = tx_with_one_input();
        // SIGHASH_SINGLE|ANYONECANPAY = 0x83.
        assert!(tx
            .transparent_sighash(VERUS_BRANCH_ID, 0, &[], 0, 0x83)
            .is_ok());
    }

    #[test]
    fn refuses_sighash_types_it_does_not_implement() {
        let tx = tx_with_one_input();
        // 0x05 is not a base type, with or without the ANYONECANPAY bit.
        let err = tx
            .transparent_sighash(VERUS_BRANCH_ID, 0, &[], 0, 0x05)
            .unwrap_err();
        assert_eq!(err, WireError::UnsupportedSighashType(0x05));
        assert!(tx
            .transparent_sighash(VERUS_BRANCH_ID, 0, &[], 0, 0x40)
            .is_err());
    }

    #[test]
    fn refuses_an_input_index_that_does_not_exist() {
        let tx = tx_with_one_input();
        let err = tx
            .transparent_sighash(VERUS_BRANCH_ID, 7, &[], 0, SIGHASH_ALL)
            .unwrap_err();
        assert_eq!(err, WireError::InputIndexOutOfRange { index: 7, len: 1 });
    }

    #[test]
    fn refuses_to_serialize_a_shielded_tx_without_a_binding_signature() {
        let tx = TxV4 {
            shielded_outputs: vec![vec![0u8; 948]],
            ..TxV4::default()
        };
        assert_eq!(
            tx.serialize().unwrap_err(),
            WireError::MissingBindingSignature
        );
    }

    #[test]
    fn refuses_to_serialize_a_spend_without_its_spend_auth_signature() {
        let tx = TxV4 {
            shielded_spends: vec![ShieldedSpend::unsigned(vec![0u8; 320])],
            binding_sig: Some([0u8; 64]),
            ..TxV4::default()
        };
        assert_eq!(
            tx.serialize().unwrap_err(),
            WireError::MissingSpendAuthSignature(0)
        );
    }

    /// The reason [`ShieldedSpend`] splits the signature out. Signing changes
    /// what gets serialized but must NOT change what was signed — if adding the
    /// signature moved the sighash, no spend could ever be signed at all.
    #[test]
    fn the_spend_auth_signature_does_not_change_the_sighash() {
        let mut tx = TxV4 {
            shielded_spends: vec![ShieldedSpend::unsigned(vec![0xab; 320])],
            ..TxV4::default()
        };
        let before = tx.shielded_sighash(VERUS_BRANCH_ID);
        tx.shielded_spends[0].spend_auth_sig = Some([0xcd; 64]);
        assert_eq!(tx.shielded_sighash(VERUS_BRANCH_ID), before);
    }

    /// …while the body it signs over of course does.
    #[test]
    fn the_spend_body_does_change_the_sighash() {
        let tx = TxV4 {
            shielded_spends: vec![ShieldedSpend::unsigned(vec![0xab; 320])],
            ..TxV4::default()
        };
        let other = TxV4 {
            shielded_spends: vec![ShieldedSpend::unsigned(vec![0xac; 320])],
            ..TxV4::default()
        };
        assert_ne!(
            tx.shielded_sighash(VERUS_BRANCH_ID),
            other.shielded_sighash(VERUS_BRANCH_ID)
        );
    }

    #[test]
    fn a_signed_spend_serializes_to_384_bytes() {
        let tx = TxV4 {
            shielded_spends: vec![ShieldedSpend {
                body: vec![0xab; 320],
                spend_auth_sig: Some([0xcd; 64]),
            }],
            binding_sig: Some([0u8; 64]),
            ..TxV4::default()
        };
        // 4 header + 4 group + 1 vin + 1 vout + 4 lock + 4 expiry + 8 balance
        // + 1 nSpends + 384 spend + 1 nOutputs + 1 nJoinSplit + 64 binding.
        assert_eq!(tx.serialize().unwrap().len(), 477);
    }

    #[test]
    fn scriptsig_is_written_as_a_varslice() {
        let mut tx = tx_with_one_input();
        let unsigned_len = tx.serialize().unwrap().len();
        tx.inputs[0].script_sig = vec![0xab; 107];
        // The empty script already cost one byte for its CompactSize length, so
        // the growth is the 107 script bytes alone.
        assert_eq!(tx.serialize().unwrap().len(), unsigned_len + 107);
    }
}

#[cfg(test)]
mod sighash_variant_tests {
    use super::*;
    use crate::consensus::VERUS_BRANCH_ID;

    fn tx(inputs: u8, outputs: u8) -> TxV4 {
        TxV4 {
            inputs: (0..inputs)
                .map(|i| TxIn::unsigned([i; 32], u32::from(i), 0xffff_fffe))
                .collect(),
            outputs: (0..outputs)
                .map(|i| TxOut {
                    value: 1_000 + u64::from(i),
                    script_pubkey: vec![0x76, 0xa9, i],
                })
                .collect(),
            lock_time: 0,
            expiry_height: 0,
            value_balance: 0,
            shielded_spends: Vec::new(),
            shielded_outputs: Vec::new(),
            binding_sig: None,
        }
    }

    fn hash(tx: &TxV4, index: usize, hash_type: u32) -> [u8; 32] {
        tx.transparent_sighash(VERUS_BRANCH_ID, index, &[0x51], 5_000, hash_type)
            .expect("sighash")
    }

    /// Each hash type must produce a different commitment, or choosing one is
    /// decorative.
    #[test]
    fn every_hash_type_commits_differently() {
        let tx = tx(2, 2);
        let mut seen = std::collections::HashSet::new();
        for hash_type in [
            SIGHASH_ALL,
            SIGHASH_NONE,
            SIGHASH_SINGLE,
            SIGHASH_ALL | SIGHASH_ANYONECANPAY,
            SIGHASH_NONE | SIGHASH_ANYONECANPAY,
            SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
        ] {
            assert!(
                seen.insert(hash(&tx, 0, hash_type)),
                "{hash_type:#x} collided with another hash type"
            );
        }
    }

    /// SIGHASH_ALL commits to every output: changing any one changes the hash.
    #[test]
    fn sighash_all_covers_every_output() {
        let original = tx(1, 2);
        let mut changed = original.clone();
        changed.outputs[1].value += 1;
        assert_ne!(
            hash(&original, 0, SIGHASH_ALL),
            hash(&changed, 0, SIGHASH_ALL)
        );
    }

    /// SIGHASH_NONE commits to no outputs at all — anyone holding the signed
    /// transaction can redirect every one of them.
    #[test]
    fn sighash_none_lets_every_output_be_rewritten() {
        let original = tx(1, 2);
        let mut changed = original.clone();
        changed.outputs[0].value = 999_999;
        changed.outputs[1].script_pubkey = vec![0xff];
        assert_eq!(
            hash(&original, 0, SIGHASH_NONE),
            hash(&changed, 0, SIGHASH_NONE),
            "SIGHASH_NONE committed to an output"
        );
    }

    /// SIGHASH_SINGLE commits to the output at the signer's own index and
    /// nothing else. This is what lets one side of a trade be signed before the
    /// other side exists.
    #[test]
    fn sighash_single_covers_only_the_matching_output() {
        let original = tx(2, 2);

        let mut other_changed = original.clone();
        other_changed.outputs[1].value += 1;
        assert_eq!(
            hash(&original, 0, SIGHASH_SINGLE),
            hash(&other_changed, 0, SIGHASH_SINGLE),
            "input 0 committed to output 1"
        );

        let mut mine_changed = original.clone();
        mine_changed.outputs[0].value += 1;
        assert_ne!(
            hash(&original, 0, SIGHASH_SINGLE),
            hash(&mine_changed, 0, SIGHASH_SINGLE),
            "input 0 did not commit to output 0"
        );
    }

    /// ANYONECANPAY commits to only the input being signed, so a counterparty
    /// can add their own inputs without invalidating the signature.
    #[test]
    fn anyonecanpay_lets_other_inputs_be_added() {
        let original = tx(1, 2);
        let mut extended = original.clone();
        extended
            .inputs
            .push(TxIn::unsigned([0x99; 32], 7, 0xffff_fffe));

        assert_eq!(
            hash(&original, 0, SIGHASH_ALL | SIGHASH_ANYONECANPAY),
            hash(&extended, 0, SIGHASH_ALL | SIGHASH_ANYONECANPAY),
            "ANYONECANPAY committed to the other inputs"
        );
        // And without it, adding an input breaks the signature — which is the
        // property an ordinary payment relies on.
        assert_ne!(
            hash(&original, 0, SIGHASH_ALL),
            hash(&extended, 0, SIGHASH_ALL)
        );
    }

    /// The offer shape: I commit to what I spend and what I am paid, and to
    /// nothing else at all.
    #[test]
    fn single_plus_anyonecanpay_is_the_half_signed_trade() {
        let original = tx(1, 1);
        let mut counterparty = original.clone();
        counterparty
            .inputs
            .push(TxIn::unsigned([0x77; 32], 3, 0xffff_fffe));
        counterparty.outputs.push(TxOut {
            value: 42,
            script_pubkey: vec![0xab],
        });

        assert_eq!(
            hash(&original, 0, SIGHASH_SINGLE | SIGHASH_ANYONECANPAY),
            hash(&counterparty, 0, SIGHASH_SINGLE | SIGHASH_ANYONECANPAY),
            "the counterparty's additions invalidated the offer"
        );
    }

    /// SIGHASH_SINGLE with no output at the index would commit to nothing about
    /// the outputs. ZIP-243 allows it; this refuses it.
    #[test]
    fn sighash_single_without_a_matching_output_is_refused() {
        let tx = tx(3, 1);
        assert!(tx
            .transparent_sighash(VERUS_BRANCH_ID, 0, &[0x51], 1, SIGHASH_SINGLE)
            .is_ok());
        assert!(matches!(
            tx.transparent_sighash(VERUS_BRANCH_ID, 1, &[0x51], 1, SIGHASH_SINGLE),
            Err(WireError::SighashSingleWithoutOutput {
                index: 1,
                outputs: 1
            })
        ));
    }

    /// A hash type nobody agreed on must be refused rather than signed under
    /// some default interpretation.
    #[test]
    fn unknown_hash_types_are_refused() {
        let tx = tx(1, 1);
        for bad in [0, 4, 5, 0x1f, 0x40, 0x100, 0xff] {
            assert!(
                tx.transparent_sighash(VERUS_BRANCH_ID, 0, &[0x51], 1, bad)
                    .is_err(),
                "accepted hash type {bad:#x}"
            );
        }
    }

    /// The shielded sighash has no input index and must keep committing to
    /// everything, whatever transparent hash types are in play.
    #[test]
    fn the_shielded_sighash_is_unaffected_by_hash_types() {
        let original = tx(1, 2);
        let mut changed = original.clone();
        changed.outputs[1].value += 1;
        assert_ne!(
            original.shielded_sighash(VERUS_BRANCH_ID),
            changed.shielded_sighash(VERUS_BRANCH_ID),
            "the shielded sighash stopped covering the outputs"
        );
    }
}
