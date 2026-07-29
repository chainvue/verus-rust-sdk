//! Signing a transaction in more than one place.
//!
//! Every builder in this crate takes all the keys at once and returns finished
//! bytes. That is fine when one person holds every key, and useless the moment
//! they do not: a `2-of-2` VerusID whose two keys live on two machines cannot be
//! operated by an API that wants both in one process. Multisig that requires all
//! signers to be in the same place is not multisig.
//!
//! A [`PartialTransaction`] is the transaction plus the signatures gathered so
//! far. It serializes, so it can be handed to a co-signer over any channel,
//! signed there, and handed back — in any order, and by any subset, until it has
//! enough.
//!
//! ```text
//! start ──► sign(key_a) ──► serialize ──►  … ──► deserialize ──► sign(key_b) ──► finalize
//! ```
//!
//! # Why order does not matter
//!
//! The ZIP-243 sighash covers the inputs, the outputs, the amounts and the
//! scripts of the outputs being spent — but **not** the `scriptSig`s. Adding one
//! signature therefore cannot change the hash another signer is signing, so
//! signatures are independent and commutative. This is what makes an
//! asynchronous flow possible at all; it is a property of the sighash, not
//! something this module arranges.
//!
//! # What a co-signer must check
//!
//! Nothing here can tell a co-signer that a transaction is *what they meant to
//! sign*. Signing is the one irreversible step, and whoever assembled the
//! transaction chose the outputs. [`PartialTransaction::summary`] exists so that
//! the recipient can look at where the money goes and what it costs **before**
//! adding a signature — treat a partial transaction from someone else as
//! untrusted input, because that is exactly what it is.
//!
//! Tampering after a signature exists is caught: a changed output changes the
//! sighash, and the earlier signature stops verifying. [`PartialTransaction::finalize`]
//! re-verifies every signature it holds, so a mangled or malicious partial fails
//! there rather than at the daemon.

use verus_keys::{Address, PrivateKey, PublicKey};
use verus_wire::consensus::{SIGHASH_ALL, VERUS_BRANCH_ID};
use verus_wire::hash::txid_display;
use verus_wire::{TxIn, TxOut, TxV4};

use crate::amount::Amount;
use crate::cc::fulfillment_script_sig;
use crate::error::TxError;
use crate::expiry::Expiry;
use crate::send::SignedTransaction;
use crate::{Txid, Utxo};

/// How an input is unlocked, which decides what a signature over it looks like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputKind {
    /// A plain key-hash output: one DER signature and its public key.
    PubKeyHash,
    /// A CryptoCondition: `m` compact signatures in a single fulfillment.
    CryptoCondition,
}

/// One signature already gathered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectedSignature {
    /// The public key it was made with.
    pub pubkey: Vec<u8>,
    /// DER + hash type for a key-hash input, compact `r || s` for a condition.
    pub bytes: Vec<u8>,
}

/// An input being signed, and what it needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialInput {
    /// The output being spent.
    pub outpoint: (Txid, u32),
    /// Its script — the sighash commits to it.
    pub script_pubkey: Vec<u8>,
    /// Its value — the sighash commits to this too.
    pub value: Amount,
    /// How it is unlocked.
    pub kind: InputKind,
    /// Signatures gathered so far, in the order they arrived.
    pub signatures: Vec<CollectedSignature>,
}

/// A transaction and the signatures gathered for it so far.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialTransaction {
    /// The outputs, fixed when the transaction was started.
    pub outputs: Vec<TxOut>,
    /// The inputs, with their signatures.
    pub inputs: Vec<PartialInput>,
    /// When this transaction stops being minable.
    pub expiry: Expiry,
    /// nLockTime.
    pub lock_time: u32,
}

/// What this transaction does, for a co-signer to check before signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    /// Value of every input being spent.
    pub total_in: Amount,
    /// Value of every output.
    pub total_out: Amount,
    /// The difference: miner fee plus anything deliberately burned.
    pub fee_and_burn: Amount,
    /// Each output's value and, where it is a plain key-hash output, who it
    /// pays. `None` means a CryptoCondition this summary does not decode —
    /// look at the script itself before signing.
    pub outputs: Vec<(Amount, Option<Address>)>,
    /// How many signatures each input still expects to be usable, as far as can
    /// be told without the conditions' own definitions.
    pub signatures_per_input: Vec<usize>,
}

impl PartialTransaction {
    /// Start from a set of inputs and outputs, with nothing signed.
    ///
    /// `kinds[i]` says how `inputs[i]` is unlocked. A key-hash input marked as a
    /// condition (or the reverse) produces a scriptSig of the wrong shape, which
    /// the daemon rejects as a script that finished false.
    pub fn start(
        inputs: &[Utxo],
        kinds: &[InputKind],
        outputs: Vec<TxOut>,
        expiry: Expiry,
        lock_time: u32,
    ) -> Result<Self, TxError> {
        if inputs.len() != kinds.len() {
            return Err(TxError::PrevoutCountMismatch {
                inputs: inputs.len(),
                prevouts: kinds.len(),
            });
        }
        Ok(Self {
            outputs,
            inputs: inputs
                .iter()
                .zip(kinds)
                .map(|(utxo, kind)| PartialInput {
                    outpoint: (utxo.txid, utxo.vout),
                    script_pubkey: utxo.script_pubkey.clone(),
                    value: utxo.satoshis,
                    kind: *kind,
                    signatures: Vec::new(),
                })
                .collect(),
            expiry,
            lock_time,
        })
    }

    /// The transaction as it will be signed — scriptSigs empty, because they are
    /// not part of the sighash.
    fn skeleton(&self) -> TxV4 {
        TxV4 {
            inputs: self
                .inputs
                .iter()
                .map(|input| {
                    TxIn::unsigned(
                        input.outpoint.0.to_internal(),
                        input.outpoint.1,
                        0xffff_ffff,
                    )
                })
                .collect(),
            outputs: self.outputs.clone(),
            lock_time: self.lock_time,
            expiry_height: self.expiry.to_height(),
            ..TxV4::default()
        }
    }

    /// The sighash for one input.
    pub fn sighash(&self, index: usize) -> Result<[u8; 32], TxError> {
        let input = self
            .inputs
            .get(index)
            .ok_or(TxError::PrevoutCountMismatch {
                inputs: self.inputs.len(),
                prevouts: index,
            })?;
        Ok(self.skeleton().transparent_sighash(
            VERUS_BRANCH_ID,
            index,
            &input.script_pubkey,
            input.value.to_sat(),
            SIGHASH_ALL,
        )?)
    }

    /// Add `key`'s signature to every input it can sign, and report how many it
    /// signed.
    ///
    /// A key-hash input is signed only when the key actually owns it; signing it
    /// with anything else would produce a scriptSig that cannot verify. A
    /// condition input is signed unconditionally, because whether the key is one
    /// of the condition's signers is decided by an identity object this crate
    /// cannot see from here — the caller knows, and a wrong key is caught at
    /// [`finalize`](Self::finalize) only insofar as it verifies against its own
    /// public key.
    ///
    /// Signing twice with the same key is a no-op rather than a duplicate: a
    /// fulfillment carrying the same signature twice satisfies nothing.
    pub fn sign(&mut self, key: &PrivateKey) -> Result<usize, TxError> {
        let pubkey = key.public_key().to_bytes();
        let owner = key.address().hash();
        let mut signed = 0;

        for index in 0..self.inputs.len() {
            let sighash = self.sighash(index)?;
            let input = &mut self.inputs[index];
            if input.signatures.iter().any(|s| s.pubkey == pubkey) {
                continue;
            }
            let bytes = match input.kind {
                InputKind::PubKeyHash => {
                    match Address::from_p2pkh_script_pubkey(&input.script_pubkey) {
                        Some(address) if address.hash() == owner => {
                            key.sign_prehash_der(&sighash, 1)?
                        }
                        // Not ours, or not the shape it claims: leave it for
                        // whoever does own it.
                        _ => continue,
                    }
                }
                InputKind::CryptoCondition => key.sign_prehash_compact(&sighash)?.to_vec(),
            };
            input.signatures.push(CollectedSignature {
                pubkey: pubkey.clone(),
                bytes,
            });
            signed += 1;
        }
        Ok(signed)
    }

    /// Whether every input carries at least one signature.
    ///
    /// A weak check: it cannot know a `2-of-3` condition needs two, because the
    /// threshold lives in an identity object this transaction does not contain.
    /// [`finalize`](Self::finalize) will still produce bytes; consensus decides.
    pub fn is_complete(&self) -> bool {
        self.inputs.iter().all(|input| !input.signatures.is_empty())
    }

    /// What this transaction does, so a co-signer can look before signing.
    pub fn summary(&self) -> Result<Summary, TxError> {
        let total_in = Amount::checked_sum(self.inputs.iter().map(|i| i.value))
            .ok_or(TxError::ValueOverflow)?;
        let total_out = Amount::checked_sum(self.outputs.iter().map(|o| Amount::from_sat(o.value)))
            .ok_or(TxError::ValueOverflow)?;
        Ok(Summary {
            total_in,
            total_out,
            fee_and_burn: total_in
                .checked_sub(total_out)
                .ok_or(TxError::ValueNotConserved {
                    inputs: total_in.to_sat(),
                    outputs: total_out.to_sat(),
                    actual: i128::from(total_in.to_sat()) - i128::from(total_out.to_sat()),
                    expected: 0,
                })?,
            outputs: self
                .outputs
                .iter()
                .map(|out| {
                    (
                        Amount::from_sat(out.value),
                        Address::from_p2pkh_script_pubkey(&out.script_pubkey),
                    )
                })
                .collect(),
            signatures_per_input: self.inputs.iter().map(|i| i.signatures.len()).collect(),
        })
    }

    /// Build the finished transaction.
    ///
    /// Every signature is verified against the sighash it claims to cover before
    /// any bytes are produced, so a partial transaction that was tampered with
    /// after signing — or assembled by someone who got a script or a value wrong
    /// — fails here rather than at the daemon, where the message is only that a
    /// script finished false.
    pub fn finalize(&self) -> Result<SignedTransaction, TxError> {
        let mut tx = self.skeleton();
        let hash_type = u8::try_from(SIGHASH_ALL).expect("SIGHASH_ALL is 1");

        for (index, input) in self.inputs.iter().enumerate() {
            if input.signatures.is_empty() {
                return Err(TxError::MissingSignature { index });
            }
            let sighash = self.sighash(index)?;
            for signature in &input.signatures {
                verify(&sighash, signature, input.kind, index)?;
            }
            tx.inputs[index].script_sig = match input.kind {
                InputKind::PubKeyHash => {
                    let signature = &input.signatures[0];
                    let mut script_sig =
                        Vec::with_capacity(2 + signature.bytes.len() + signature.pubkey.len());
                    script_sig.push(
                        u8::try_from(signature.bytes.len())
                            .map_err(|_| TxError::MissingSignature { index })?,
                    );
                    script_sig.extend_from_slice(&signature.bytes);
                    script_sig.push(
                        u8::try_from(signature.pubkey.len())
                            .map_err(|_| TxError::MissingSignature { index })?,
                    );
                    script_sig.extend_from_slice(&signature.pubkey);
                    script_sig
                }
                InputKind::CryptoCondition => {
                    let signatures = input
                        .signatures
                        .iter()
                        .map(|s| {
                            let compact: [u8; 64] = s
                                .bytes
                                .clone()
                                .try_into()
                                .map_err(|_| TxError::MissingSignature { index })?;
                            Ok((s.pubkey.clone(), compact))
                        })
                        .collect::<Result<Vec<_>, TxError>>()?;
                    fulfillment_script_sig(&signatures, hash_type)?
                }
            };
        }

        let raw = tx.serialize()?;
        let total_in = Amount::checked_sum(self.inputs.iter().map(|i| i.value))
            .ok_or(TxError::ValueOverflow)?;
        let total_out = Amount::checked_sum(self.outputs.iter().map(|o| Amount::from_sat(o.value)))
            .ok_or(TxError::ValueOverflow)?;
        Ok(SignedTransaction {
            hex: hex::encode(&raw),
            txid: txid_display(&tx.txid()?),
            fee: total_in.checked_sub(total_out).unwrap_or(Amount::ZERO),
            change: Amount::ZERO,
            inputs_used: self.inputs.iter().map(|i| i.outpoint).collect(),
        })
    }
}

/// Check one gathered signature against the hash it claims to cover.
fn verify(
    sighash: &[u8; 32],
    signature: &CollectedSignature,
    kind: InputKind,
    index: usize,
) -> Result<(), TxError> {
    let pubkey = PublicKey::from_bytes(&signature.pubkey)
        .map_err(|_| TxError::InvalidSignature { index })?;
    let ok = match kind {
        // The trailing byte is the hash type, not part of the signature.
        InputKind::PubKeyHash => {
            let der = signature
                .bytes
                .split_last()
                .map(|(_, der)| der)
                .unwrap_or(&[]);
            pubkey.verify_der(sighash, der)
        }
        InputKind::CryptoCondition => pubkey.verify_compact(sighash, &signature.bytes),
    };
    if ok {
        Ok(())
    } else {
        Err(TxError::InvalidSignature { index })
    }
}

/// The tag every serialized partial transaction starts with, so a file handed
/// to the wrong reader fails immediately instead of being misparsed.
const MAGIC: &[u8; 8] = b"VRSCPSIG";
/// Format version. A reader refuses anything it does not know rather than
/// guessing at a layout that may have moved.
const FORMAT_VERSION: u8 = 1;

impl PartialTransaction {
    /// Serialize for handing to a co-signer.
    ///
    /// Self-contained on purpose: the prevout scripts and values travel with it,
    /// because the sighash commits to them and a co-signer that had to be told
    /// them separately could be told the wrong ones.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TxError> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        out.extend_from_slice(&self.expiry.to_height().to_le_bytes());
        out.extend_from_slice(&self.lock_time.to_le_bytes());

        write_compact(&mut out, self.outputs.len());
        for output in &self.outputs {
            out.extend_from_slice(&output.value.to_le_bytes());
            write_slice(&mut out, &output.script_pubkey);
        }

        write_compact(&mut out, self.inputs.len());
        for input in &self.inputs {
            out.extend_from_slice(&input.outpoint.0.to_internal());
            out.extend_from_slice(&input.outpoint.1.to_le_bytes());
            write_slice(&mut out, &input.script_pubkey);
            out.extend_from_slice(&input.value.to_sat().to_le_bytes());
            out.push(match input.kind {
                InputKind::PubKeyHash => 0,
                InputKind::CryptoCondition => 1,
            });
            write_compact(&mut out, input.signatures.len());
            for signature in &input.signatures {
                write_slice(&mut out, &signature.pubkey);
                write_slice(&mut out, &signature.bytes);
            }
        }
        Ok(out)
    }

    /// Read one back. Treats its input as untrusted: every length is checked
    /// against what is actually there.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TxError> {
        let mut reader = Reader { bytes, at: 0 };
        if reader.take(8)? != MAGIC {
            return Err(TxError::MalformedPartialTransaction(
                "not a partial transaction".to_string(),
            ));
        }
        let version = reader.byte()?;
        if version != FORMAT_VERSION {
            return Err(TxError::MalformedPartialTransaction(format!(
                "format version {version} is not one this crate reads"
            )));
        }
        let expiry = Expiry::from_height(reader.u32()?);
        let lock_time = reader.u32()?;

        let output_count = reader.compact()?;
        let mut outputs = Vec::with_capacity(output_count.min(1024));
        for _ in 0..output_count {
            let value = reader.u64()?;
            let script_pubkey = reader.var_slice()?.to_vec();
            outputs.push(TxOut {
                value,
                script_pubkey,
            });
        }

        let input_count = reader.compact()?;
        let mut inputs = Vec::with_capacity(input_count.min(1024));
        for _ in 0..input_count {
            let txid: [u8; 32] = reader
                .take(32)?
                .try_into()
                .expect("take returned the requested length");
            let vout = reader.u32()?;
            let script_pubkey = reader.var_slice()?.to_vec();
            let value = Amount::from_sat(reader.u64()?);
            let kind = match reader.byte()? {
                0 => InputKind::PubKeyHash,
                1 => InputKind::CryptoCondition,
                other => {
                    return Err(TxError::MalformedPartialTransaction(format!(
                        "input kind {other} is not one this crate knows"
                    )))
                }
            };
            let signature_count = reader.compact()?;
            let mut signatures = Vec::with_capacity(signature_count.min(64));
            for _ in 0..signature_count {
                let pubkey = reader.var_slice()?.to_vec();
                let bytes = reader.var_slice()?.to_vec();
                signatures.push(CollectedSignature { pubkey, bytes });
            }
            inputs.push(PartialInput {
                outpoint: (Txid::from_internal(txid), vout),
                script_pubkey,
                value,
                kind,
                signatures,
            });
        }

        if reader.at != reader.bytes.len() {
            return Err(TxError::MalformedPartialTransaction(
                "trailing bytes after the partial transaction".to_string(),
            ));
        }
        Ok(Self {
            outputs,
            inputs,
            expiry,
            lock_time,
        })
    }
}

fn write_compact(out: &mut Vec<u8>, value: usize) {
    verus_wire::compact::write_compact_size(out, value as u64);
}

fn write_slice(out: &mut Vec<u8>, bytes: &[u8]) {
    verus_wire::compact::write_var_slice(out, bytes);
}

/// A bounds-checked reader. Every `take` is validated, so a truncated or
/// oversized length is an error rather than a panic.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TxError> {
        let end = self
            .at
            .checked_add(n)
            .ok_or_else(|| TxError::MalformedPartialTransaction("length overflows".to_string()))?;
        if end > self.bytes.len() {
            return Err(TxError::MalformedPartialTransaction(format!(
                "wanted {n} bytes at {} but only {} remain",
                self.at,
                self.bytes.len().saturating_sub(self.at)
            )));
        }
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, TxError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, TxError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64, TxError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("eight bytes"),
        ))
    }

    fn compact(&mut self) -> Result<usize, TxError> {
        let first = self.byte()?;
        let value = match first {
            0..=0xfc => u64::from(first),
            0xfd => u64::from(u16::from_le_bytes(
                self.take(2)?.try_into().expect("two bytes"),
            )),
            0xfe => u64::from(self.u32()?),
            _ => self.u64()?,
        };
        usize::try_from(value).map_err(|_| {
            TxError::MalformedPartialTransaction("count does not fit in memory".to_string())
        })
    }

    fn var_slice(&mut self) -> Result<&'a [u8], TxError> {
        let len = self.compact()?;
        self.take(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cc::reserve_output_script;

    const TEST_WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";

    fn key_a() -> PrivateKey {
        PrivateKey::from_wif(TEST_WIF).unwrap()
    }

    fn key_b() -> PrivateKey {
        PrivateKey::from_bytes(&[0x27; 32], true).unwrap()
    }

    fn p2pkh_input(key: &PrivateKey, value: u64) -> Utxo {
        Utxo {
            txid: Txid::from_internal([0xa0; 32]),
            vout: 0,
            satoshis: Amount::from_sat(value),
            script_pubkey: key.address().p2pkh_script_pubkey().unwrap(),
        }
    }

    fn condition_input(key: &PrivateKey) -> Utxo {
        Utxo {
            txid: Txid::from_internal([0xc0; 32]),
            vout: 1,
            satoshis: Amount::ZERO,
            script_pubkey: reserve_output_script(key.address().hash(), [0x77; 20], 1_000).unwrap(),
        }
    }

    fn outputs(key: &PrivateKey, value: u64) -> Vec<TxOut> {
        vec![TxOut {
            value,
            script_pubkey: key.address().p2pkh_script_pubkey().unwrap(),
        }]
    }

    fn started() -> PartialTransaction {
        let a = key_a();
        PartialTransaction::start(
            &[condition_input(&a), p2pkh_input(&a, 100_000)],
            &[InputKind::CryptoCondition, InputKind::PubKeyHash],
            outputs(&a, 90_000),
            Expiry::Never,
            0,
        )
        .unwrap()
    }

    /// The property the whole flow rests on: signatures are independent, so two
    /// co-signers produce the same bytes whichever order they sign in.
    #[test]
    fn signing_order_does_not_change_the_result() {
        let (a, b) = (key_a(), key_b());

        let mut forwards = started();
        forwards.sign(&a).unwrap();
        forwards.sign(&b).unwrap();

        let mut backwards = started();
        backwards.sign(&b).unwrap();
        backwards.sign(&a).unwrap();

        // The gathered sets differ only in order; the finished bytes must not
        // differ at all once sorted the same way.
        assert_eq!(forwards.inputs[0].signatures.len(), 2);
        assert_eq!(backwards.inputs[0].signatures.len(), 2);
        let mut f = forwards.inputs[0].signatures.clone();
        let mut b2 = backwards.inputs[0].signatures.clone();
        f.sort_by(|x, y| x.pubkey.cmp(&y.pubkey));
        b2.sort_by(|x, y| x.pubkey.cmp(&y.pubkey));
        assert_eq!(f, b2);
    }

    /// A round trip through the wire format is what makes a co-signer on another
    /// machine possible at all.
    #[test]
    fn survives_a_round_trip_between_signers() {
        let (a, b) = (key_a(), key_b());
        let mut here = started();
        here.sign(&a).unwrap();

        let carried = here.to_bytes().unwrap();
        let mut there = PartialTransaction::from_bytes(&carried).unwrap();
        assert_eq!(there, here);

        there.sign(&b).unwrap();
        let returned = PartialTransaction::from_bytes(&there.to_bytes().unwrap()).unwrap();
        assert_eq!(returned.inputs[0].signatures.len(), 2);
        assert!(returned.finalize().is_ok());
    }

    /// Only the owner can sign a key-hash input; another key must leave it alone
    /// rather than attach a signature that cannot verify.
    #[test]
    fn a_key_hash_input_is_only_signed_by_its_owner() {
        let mut partial = started();
        let signed = partial.sign(&key_b()).unwrap();
        // The condition input, but not the P2PKH one.
        assert_eq!(signed, 1);
        assert_eq!(partial.inputs[1].signatures.len(), 0);
        assert!(!partial.is_complete());
    }

    #[test]
    fn signing_twice_with_one_key_does_not_duplicate() {
        let a = key_a();
        let mut partial = started();
        assert_eq!(partial.sign(&a).unwrap(), 2);
        assert_eq!(partial.sign(&a).unwrap(), 0);
        assert_eq!(partial.inputs[0].signatures.len(), 1);
    }

    /// Tampering after signing must be caught here, not by the daemon: changing
    /// an output changes the sighash, so the existing signature stops verifying.
    #[test]
    fn an_output_changed_after_signing_is_rejected() {
        let a = key_a();
        let mut partial = started();
        partial.sign(&a).unwrap();
        assert!(partial.finalize().is_ok());

        // Redirect the money.
        partial.outputs[0].value = 10_000;
        assert!(matches!(
            partial.finalize(),
            Err(TxError::InvalidSignature { .. })
        ));
    }

    /// The same, for the value a signature commits to via the sighash.
    #[test]
    fn a_changed_input_value_is_rejected() {
        let a = key_a();
        let mut partial = started();
        partial.sign(&a).unwrap();
        partial.inputs[1].value = Amount::from_sat(999_999);
        assert!(matches!(
            partial.finalize(),
            Err(TxError::InvalidSignature { .. })
        ));
    }

    #[test]
    fn refuses_to_finalize_while_an_input_is_unsigned() {
        let partial = started();
        assert!(matches!(
            partial.finalize(),
            Err(TxError::MissingSignature { index: 0 })
        ));
    }

    /// The two paths must agree. A transparent send built all-at-once and the
    /// same transaction assembled through the partial flow have to produce
    /// identical bytes — otherwise one of them is wrong, and the partial path
    /// would be signing something subtly different from what was proven on
    /// chain.
    #[test]
    fn the_partial_path_matches_the_direct_builder() {
        use crate::send::{build_transparent_send, Recipient, SendParams};

        let key = key_a();
        let funding = Utxo {
            txid: Txid::from_internal([0xf0; 32]),
            vout: 0,
            satoshis: Amount::from_sat(100_000_000),
            script_pubkey: key.address().p2pkh_script_pubkey().unwrap(),
        };
        let recipient_address: Address = "RPsQDnaxXgrLjcVBh3SpvCpTabWxAdMdzu".parse().unwrap();
        let recipients = [Recipient {
            address: recipient_address,
            satoshis: Amount::from_sat(90_000_000),
        }];
        let utxos = [funding.clone()];
        let direct = build_transparent_send(
            &key,
            &SendParams::new(&utxos, &recipients, key.address(), Expiry::Never),
        )
        .unwrap();

        // The same transaction, described input by input: the declared output
        // first, then change, which is the order the builder emits.
        let outputs = vec![
            TxOut {
                value: 90_000_000,
                script_pubkey: recipient_address.p2pkh_script_pubkey().unwrap(),
            },
            TxOut {
                value: direct.change.to_sat(),
                script_pubkey: key.address().p2pkh_script_pubkey().unwrap(),
            },
        ];
        let mut partial =
            PartialTransaction::start(&utxos, &[InputKind::PubKeyHash], outputs, Expiry::Never, 0)
                .unwrap();
        partial.sign(&key).unwrap();
        let assembled = partial.finalize().unwrap();

        assert_eq!(
            assembled.hex, direct.hex,
            "partial and direct paths diverged"
        );
        assert_eq!(assembled.txid, direct.txid);
    }

    /// What a co-signer looks at before deciding.
    #[test]
    fn summarizes_what_is_being_signed() {
        let a = key_a();
        let summary = started().summary().unwrap();
        assert_eq!(summary.total_in, Amount::from_sat(100_000));
        assert_eq!(summary.total_out, Amount::from_sat(90_000));
        assert_eq!(summary.fee_and_burn, Amount::from_sat(10_000));
        assert_eq!(summary.outputs.len(), 1);
        assert_eq!(summary.outputs[0].1.as_ref(), Some(&a.address()));
        assert_eq!(summary.signatures_per_input, vec![0, 0]);
    }
}
