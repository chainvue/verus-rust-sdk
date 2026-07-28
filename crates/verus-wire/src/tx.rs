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
    SEQUENCE_PERSONAL, SHIELDED_OUTPUTS_PERSONAL, SHIELDED_SPENDS_PERSONAL, SIGHASH_ALL, V4_HEADER,
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

    /// Transaction id, in internal byte order. Use
    /// [`txid_display`](crate::hash::txid_display) for the RPC representation.
    pub fn txid(&self) -> Result<[u8; 32], WireError> {
        Ok(sha256d(&self.serialize()?))
    }

    /// ZIP-243 sighash over the whole transaction with **no transparent-input
    /// section** — what the Sapling binding signature and the shielded
    /// spend-auth signatures commit to.
    pub fn shielded_sighash(&self, branch_id: u32) -> [u8; 32] {
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
        if hash_type != SIGHASH_ALL {
            return Err(WireError::UnsupportedSighashType(hash_type));
        }
        let input = self
            .inputs
            .get(input_index)
            .ok_or(WireError::InputIndexOutOfRange {
                index: input_index,
                len: self.inputs.len(),
            })?;

        let mut preimage = self.sighash_prefix();
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
        let hash_prevouts = {
            let mut data = Vec::with_capacity(self.inputs.len() * 36);
            for input in &self.inputs {
                data.extend_from_slice(&input.txid_internal);
                data.extend_from_slice(&input.vout.to_le_bytes());
            }
            blake2b_personal(PREVOUT_PERSONAL, &data)
        };
        let hash_sequence = {
            let mut data = Vec::with_capacity(self.inputs.len() * 4);
            for input in &self.inputs {
                data.extend_from_slice(&input.sequence.to_le_bytes());
            }
            blake2b_personal(SEQUENCE_PERSONAL, &data)
        };
        let hash_outputs = {
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

    #[test]
    fn refuses_sighash_types_it_does_not_implement() {
        let tx = tx_with_one_input();
        // SIGHASH_SINGLE|ANYONECANPAY, used by marketplace offers.
        let err = tx
            .transparent_sighash(VERUS_BRANCH_ID, 0, &[], 0, 0x83)
            .unwrap_err();
        assert_eq!(err, WireError::UnsupportedSighashType(0x83));
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
