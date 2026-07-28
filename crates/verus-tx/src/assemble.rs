//! Assembling and signing a transaction that mixes CryptoCondition and P2PKH
//! inputs.
//!
//! Shared by the VerusID flows in [`crate::register`] and [`crate::update`],
//! which differ only in what they put in the outputs: both spend a
//! CryptoCondition output they control, fund the rest from plain P2PKH UTXOs,
//! and must conserve value exactly.

use verus_keys::{Address, PrivateKey};
use verus_wire::consensus::{SIGHASH_ALL, VERUS_BRANCH_ID};
use verus_wire::hash::txid_display;
use verus_wire::{TxIn, TxOut, TxV4};

use crate::cc::fulfillment_script_sig;
use crate::error::TxError;
use crate::fee::select_utxos;
use crate::send::{p2pkh_script_sig, SignedTransaction};
use crate::Utxo;

/// Verus rejects an expiry height at or above this. `0` means "never expires".
const EXPIRY_HEIGHT_THRESHOLD: u32 = 500_000_000;

/// The shape of a transaction to assemble.
pub(crate) struct Assembly<'a> {
    /// Inputs spent before the funding ones, in order. CryptoCondition outputs
    /// carrying no native value — currently only a name commitment.
    pub(crate) leading: &'a [Utxo],
    /// P2PKH UTXOs available to fund the transaction.
    pub(crate) funding: &'a [Utxo],
    /// The declared outputs, before change.
    pub(crate) outputs: Vec<TxOut>,
    /// Value that leaves the transaction without an output — the registration
    /// fee. Funded and conserved like any other outlay.
    pub(crate) burn: u64,
    /// Output count handed to the fee estimator.
    pub(crate) fee_output_count: u64,
    /// Where change goes.
    pub(crate) change_address: &'a Address,
    /// Expiry height.
    pub(crate) expiry_height: u32,
    /// Fee rate in satoshis per kilobyte.
    pub(crate) fee_per_kb: u64,
}

/// Select coins, assemble, check conservation, sign.
pub(crate) fn assemble(key: &PrivateKey, plan: Assembly<'_>) -> Result<SignedTransaction, TxError> {
    // A leading input carrying native value would silently fund the burn and
    // break the accounting below, which assumes their contribution is zero.
    for utxo in plan.leading {
        if utxo.satoshis != 0 {
            return Err(TxError::LeadingInputCarriesValue {
                txid: utxo.txid.to_display_hex(),
                vout: utxo.vout,
                satoshis: utxo.satoshis,
            });
        }
    }

    let selection = select_utxos(
        plan.funding,
        plan.burn,
        plan.fee_output_count,
        plan.fee_per_kb,
        // Every output here is a CryptoCondition, which the fee heuristic sizes
        // at 200 bytes rather than 34.
        true,
    )?;

    let mut outputs = plan.outputs;
    if selection.change > 0 {
        outputs.push(TxOut {
            value: selection.change,
            script_pubkey: plan.change_address.p2pkh_script_pubkey()?,
        });
    }

    let inputs: Vec<Utxo> = plan
        .leading
        .iter()
        .chain(selection.selected.iter())
        .cloned()
        .collect();

    let mut tx = TxV4 {
        inputs: inputs
            .iter()
            .map(|utxo| TxIn::unsigned(utxo.txid.to_internal(), utxo.vout, 0xffff_ffff))
            .collect(),
        outputs,
        lock_time: 0,
        expiry_height: plan.expiry_height,
        ..TxV4::default()
    };

    // Exact-integer conservation: inputs − outputs must be the miner fee plus
    // the declared burn, and nothing else.
    let inputs_total: u64 = inputs.iter().map(|u| u.satoshis).sum();
    let outputs_total: u64 = tx.outputs.iter().map(|o| o.value).sum();
    let actual = i128::from(inputs_total) - i128::from(outputs_total);
    let expected = selection.fee + plan.burn;
    if actual != i128::from(expected) {
        return Err(TxError::ValueNotConserved {
            inputs: inputs_total,
            outputs: outputs_total,
            actual,
            expected,
        });
    }

    sign_inputs(&mut tx, key, &inputs, plan.leading.len())?;

    let raw = tx.serialize()?;
    Ok(SignedTransaction {
        hex: hex::encode(&raw),
        txid: txid_display(&tx.txid()?),
        fee: expected,
        change: selection.change,
        inputs_used: inputs.iter().map(|utxo| (utxo.txid, utxo.vout)).collect(),
    })
}

/// Sign every input: the leading CryptoConditions with a fulfillment, the rest
/// as P2PKH.
///
/// The two kinds differ only in the scriptSig. The sighash is the same ZIP-243
/// preimage either way, with the prevout's own script as the script code, and it
/// commits to **every** input of the transaction — so each signature must be
/// computed against the whole transaction, not against a slice of it. Signing a
/// subset produces a different `hashPrevouts` and `hashSequence`, and the daemon
/// rejects it with `mandatory-script-verify-flag-failed`, which says only that a
/// script finished false and nothing about which one or why.
fn sign_inputs(
    tx: &mut TxV4,
    key: &PrivateKey,
    prevouts: &[Utxo],
    leading: usize,
) -> Result<(), TxError> {
    let pubkey = key.public_key().to_bytes();
    for (index, utxo) in prevouts.iter().enumerate() {
        let sighash = tx.transparent_sighash(
            VERUS_BRANCH_ID,
            index,
            &utxo.script_pubkey,
            utxo.satoshis,
            SIGHASH_ALL,
        )?;
        tx.inputs[index].script_sig = if index < leading {
            // The fulfillment states the hash type in one byte of its own,
            // unlike a P2PKH scriptSig where it trails the DER signature.
            let hash_type = u8::try_from(SIGHASH_ALL).expect("SIGHASH_ALL is 1");
            let signature = key.sign_prehash_compact(&sighash)?;
            fulfillment_script_sig(&pubkey, &signature, hash_type)?
        } else {
            p2pkh_script_sig(key, &sighash, &pubkey)?
        };
    }
    Ok(())
}

pub(crate) fn check_expiry(expiry_height: u32) -> Result<(), TxError> {
    if expiry_height >= EXPIRY_HEIGHT_THRESHOLD {
        return Err(TxError::ExpiryHeightTooLarge(expiry_height));
    }
    Ok(())
}

pub(crate) fn check_p2pkh_funding(utxos: &[Utxo]) -> Result<(), TxError> {
    for utxo in utxos {
        if Address::from_p2pkh_script_pubkey(&utxo.script_pubkey).is_none() {
            return Err(TxError::UnsupportedFundingScript {
                txid: utxo.txid.to_display_hex(),
                vout: utxo.vout,
            });
        }
    }
    Ok(())
}
