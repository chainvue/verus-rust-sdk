//! Assembling and signing a transaction that mixes CryptoCondition and P2PKH
//! inputs.
//!
//! Shared by the VerusID flows in `verus_tx::register` and `verus_tx::update`,
//! which differ only in what they put in the outputs: both spend a
//! CryptoCondition output they control, fund the rest from plain P2PKH UTXOs,
//! and must conserve value exactly.

use verus_keys::{Address, PrivateKey};
use verus_wire::consensus::{SIGHASH_ALL, VERUS_BRANCH_ID};
use verus_wire::hash::txid_display;
use verus_wire::{TxIn, TxOut, TxV4};

use crate::send::{p2pkh_script_sig, SignedTransaction};
use verus_tx_primitives::cc::fulfillment_script_sig;
use verus_tx_primitives::fee::{
    check_burn_ceiling, check_fee_ceiling, estimate_fee, select_utxos, DUST_THRESHOLD,
};
use verus_tx_primitives::Amount;
use verus_tx_primitives::Expiry;
use verus_tx_primitives::TxError;
use verus_tx_primitives::Utxo;

/// The shape of a transaction to assemble.
pub struct Assembly<'a> {
    /// Inputs spent before the funding ones, in order: CryptoCondition outputs
    /// the caller controls — a name commitment, token inputs, or (only with
    /// [`Assembly::value_bearing_leading`]) identity-held funding.
    pub leading: &'a [Utxo],
    /// P2PKH UTXOs available to fund the transaction.
    pub funding: &'a [Utxo],
    /// The declared outputs, before change.
    pub outputs: Vec<TxOut>,
    /// Value that leaves the transaction without an output — the registration
    /// fee. Funded and conserved like any other outlay.
    pub burn: Amount,
    /// Output count handed to the fee estimator.
    pub fee_output_count: u64,
    /// Where change goes.
    pub change_address: &'a Address,
    /// The change output's script, when change must not be plain P2PKH.
    ///
    /// `None` pays change to `change_address` as P2PKH, which is right for
    /// every flow that funds from a key. An identity-funded spend sets this to
    /// the identity's own payment script, so what is not spent **stays under
    /// the identity's authority** instead of quietly migrating to a bare key.
    pub change_script: Option<Vec<u8>>,
    /// Permit leading inputs to carry native value, counted exactly.
    ///
    /// Off, the historical invariant holds: a leading input with value is
    /// refused, because the accounting would otherwise let it silently fund
    /// the burn. On, that value is a *declared* funding source — and the only
    /// one: `funding` must be empty (`MixedFunding`), the leading inputs cover
    /// the declared outlay plus the miner fee, and the excess returns via
    /// `change_script`. Nothing becomes implicit — the check
    /// `inputs − outputs = fee + burn` still holds to the satoshi.
    ///
    /// This is opt-in per call site on purpose. The flows that assumed
    /// zero-value leading inputs still get the refusal; only a flow built to
    /// spend identity-held funds (a mint, an identity-funded send) asks.
    pub value_bearing_leading: bool,
    /// When the transaction stops being minable.
    pub expiry: Expiry,
    /// Fee rate in satoshis per kilobyte.
    pub fee_per_kb: u64,
}

/// Select coins, assemble, check conservation, sign.
///
/// `funding_key` signs the P2PKH inputs. `leading_keys` sign the CryptoCondition
/// ones, all of them into a single fulfillment per input — an `m-of-n` condition
/// wants `m` signatures in one scriptSig, not `m` scriptSigs.
pub fn assemble(
    funding_key: &PrivateKey,
    leading_keys: &[&PrivateKey],
    plan: Assembly<'_>,
) -> Result<SignedTransaction, TxError> {
    // Unless the caller has explicitly declared otherwise, a leading input
    // carrying native value would silently fund the burn and break the
    // accounting below, which assumes their contribution is zero.
    if !plan.value_bearing_leading {
        for utxo in plan.leading {
            if !utxo.satoshis.is_zero() {
                return Err(TxError::LeadingInputCarriesValue {
                    txid: utxo.txid.to_display_hex(),
                    vout: utxo.vout,
                    satoshis: utxo.satoshis.to_sat(),
                });
            }
        }
    }

    // A burn is caller-supplied chain policy, so a typo in it is possible and
    // conservation would certify the result regardless.
    check_burn_ceiling(plan.burn.to_sat())?;

    // Everything that has to be funded: the value the declared outputs carry
    // plus the burn. Most callers here emit only valueless CryptoConditions and
    // the outputs term is zero — a referral payout is the first that is not, and
    // omitting it under-funds the transaction by exactly the payout.
    //
    // #194: this sum used to be a raw `u64` `.sum()`, a few lines from the
    // `Amount::checked_sum` that does the same job correctly for the leading
    // inputs. Two caller-supplied output values whose total exceeds `u64::MAX`
    // wrap `declared_value` down to a plausible number, and the conservation
    // check at the end cannot see it — `outputs_total` sums the same values and
    // wraps the same way, so the difference still matches and the transaction
    // gets signed.
    let declared_value =
        Amount::checked_sum(plan.outputs.iter().map(|out| Amount::from_sat(out.value)))
            .ok_or(TxError::ValueOverflow)?
            .to_sat();
    let required = declared_value
        .checked_add(plan.burn.to_sat())
        .ok_or(TxError::ValueOverflow)?;

    // What the leading inputs bring. Zero on every historical path; with
    // `value_bearing_leading` it is a declared funding source, subtracted from
    // what the P2PKH selection must raise.
    let leading_total = Amount::checked_sum(plan.leading.iter().map(|u| u.satoshis))
        .ok_or(TxError::ValueOverflow)?
        .to_sat();

    // Value-bearing leading inputs get the same duplicate guard selection
    // gives funding: a repeated outpoint double-counts `leading_total` and
    // signs a transaction the mempool rejects.
    if plan.value_bearing_leading {
        // Identity change must carry an explicit script — P2PKH change here
        // would silently migrate identity funds to a bare key, which is the
        // exact move this design forbids. A hard error rather than an assert:
        // this routes money, and a release-mode slip must not route it wrong.
        if plan.change_script.is_none() {
            return Err(TxError::MissingChangeScript);
        }
        // And the identity funds the whole transaction alone. Mixing P2PKH
        // funding in would mean two fee computations, P2PKH surplus routed to
        // the identity's change script, and a branch no chain has accepted —
        // unrepresentable beats unproven.
        if !plan.funding.is_empty() {
            return Err(TxError::MixedFunding);
        }
        for (index, utxo) in plan.leading.iter().enumerate() {
            if plan.leading[..index]
                .iter()
                .any(|earlier| earlier.txid == utxo.txid && earlier.vout == utxo.vout)
            {
                return Err(TxError::DuplicateUtxo {
                    txid: utxo.txid.to_display_hex(),
                    vout: utxo.vout,
                });
            }
        }
    }

    // Selection, or its equivalent when the leading inputs already cover
    // everything. `fee` and `change` come out of exactly one of the branches,
    // and conservation below re-checks whichever produced them.
    let (selected, fee, change) = if leading_total >= required && plan.value_bearing_leading {
        // The leading inputs over-cover the declared outlay, so no P2PKH input
        // is needed — the miner fee and the change both come from the excess.
        // Mixing in selection here would mean two fee computations; a caller
        // whose excess cannot cover the fee is told exactly that instead.
        let excess = leading_total - required;
        let fee = estimate_fee(
            plan.leading.len() as u64,
            plan.fee_output_count,
            plan.fee_per_kb,
            true,
        )?;
        check_fee_ceiling(fee)?;
        if excess < fee {
            return Err(TxError::InsufficientFunds {
                required: required.checked_add(fee).ok_or(TxError::ValueOverflow)?,
                available: leading_total,
            });
        }
        let change = excess - fee;
        // The same dust rule as coin selection: change not worth an output
        // becomes fee, and conservation accounts for it as fee.
        if change <= DUST_THRESHOLD {
            (Vec::new(), fee + change, 0)
        } else {
            (Vec::new(), fee, change)
        }
    } else if plan.value_bearing_leading {
        // An identity-funded plan that is short. There is no P2PKH fallback —
        // MixedFunding refused that above — so answer with the identity's
        // real holdings, not selection's `available: 0`.
        let fee = estimate_fee(
            plan.leading.len() as u64,
            plan.fee_output_count,
            plan.fee_per_kb,
            true,
        )?;
        return Err(TxError::InsufficientFunds {
            required: required.checked_add(fee).ok_or(TxError::ValueOverflow)?,
            available: leading_total,
        });
    } else {
        // Only the historical paths reach this branch, and their leading
        // inputs are all valueless — the guard at the top enforced it — so
        // the full requirement is raised from P2PKH selection.
        //
        // # The fee does not count the leading inputs, and that is proven
        //
        // Selection sizes the fee from what it selects, so the leading inputs
        // are absent from the arithmetic even though they are signed and
        // broadcast like any other. That reads like an undercount, and it was
        // reported as one. It is not a mistake to correct: adding them changes
        // the bytes of **nine daemon-accepted transactions** —
        // `identity_lifecycle`'s registration, revocation, recovery, multisig
        // update, content update, and the four referral vectors — every one of
        // which was mined. Whatever a strict byte-count would say, this is
        // what the reference implementation does and what the chain took.
        //
        // It is not inconsistent with `build_token_send` counting all of its
        // inputs: there the token UTXOs go through the builder's own selection
        // loop and so land in `selected`. The distinction is which list an
        // input arrives in, and both behaviours are pinned by goldens —
        // `fixtures/transparent/vectors.json`'s token vector expects a fee of
        // 10200, which is exactly two inputs and three outputs.
        //
        // The one case this leaves open: a spend with *many* leading inputs
        // prices well under its size, and no golden covers that shape. If a
        // node ever rejects one for a low fee, the fix belongs in the builder
        // that assembles it, not here — changing this line breaks the nine.
        let selection = select_utxos(
            plan.funding,
            required,
            plan.fee_output_count,
            plan.fee_per_kb,
            // Every output here is a CryptoCondition, which the fee heuristic
            // sizes at 200 bytes rather than 34.
            true,
        )?;
        (selection.selected, selection.fee, selection.change)
    };

    let mut outputs = plan.outputs;
    if change > 0 {
        outputs.push(TxOut {
            value: change,
            script_pubkey: match &plan.change_script {
                Some(script) => script.clone(),
                None => plan.change_address.p2pkh_script_pubkey()?,
            },
        });
    }

    let inputs: Vec<Utxo> = plan
        .leading
        .iter()
        .chain(selected.iter())
        .cloned()
        .collect();

    let mut tx = TxV4 {
        inputs: inputs
            .iter()
            .map(|utxo| TxIn::unsigned(utxo.txid.to_internal(), utxo.vout, 0xffff_ffff))
            .collect(),
        outputs,
        lock_time: 0,
        expiry_height: plan.expiry.to_height(),
        ..TxV4::default()
    };

    // Exact-integer conservation: inputs − outputs must be the miner fee plus
    // the declared burn, and nothing else. This is the backstop for BOTH
    // branches above — a slip in either fee computation fails here rather than
    // signing a transaction that pays the difference to a miner.
    //
    // #194: both sides used to be raw `u64` `.sum()`s, promoted to `i128` only
    // on the next line — too late. The wrap happens inside the sum, and because
    // both sides wrap identically modulo 2^64 the difference still matches, so
    // this check certifies an overflowed transaction instead of refusing it
    // (in a debug build the same input panics in the iterator's `Sum` impl
    // rather than returning `ValueOverflow`). Summing through `Amount` puts the
    // overflow where it belongs: before the i128 difference is formed. The
    // reported fields stay `u64`, so `ValueNotConserved` is unchanged.
    let inputs_total = Amount::checked_sum(inputs.iter().map(|u| u.satoshis))
        .ok_or(TxError::ValueOverflow)?
        .to_sat();
    let outputs_total = Amount::checked_sum(tx.outputs.iter().map(|o| Amount::from_sat(o.value)))
        .ok_or(TxError::ValueOverflow)?
        .to_sat();
    let actual = i128::from(inputs_total) - i128::from(outputs_total);
    let expected = fee + plan.burn.to_sat();
    if actual != i128::from(expected) {
        return Err(TxError::ValueNotConserved {
            inputs: inputs_total,
            outputs: outputs_total,
            actual,
            expected,
        });
    }

    sign_inputs(
        &mut tx,
        funding_key,
        leading_keys,
        &inputs,
        plan.leading.len(),
    )?;

    let raw = tx.serialize()?;
    Ok(SignedTransaction {
        hex: hex::encode(&raw),
        txid: txid_display(&tx.txid()?),
        fee: Amount::from_sat(expected),
        change: Amount::from_sat(change),
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
    funding_key: &PrivateKey,
    leading_keys: &[&PrivateKey],
    prevouts: &[Utxo],
    leading: usize,
) -> Result<(), TxError> {
    if leading > 0 && leading_keys.is_empty() {
        return Err(TxError::NoSignatures);
    }
    let funding_pubkey = funding_key.public_key().to_bytes();
    for (index, utxo) in prevouts.iter().enumerate() {
        let sighash = tx.transparent_sighash(
            VERUS_BRANCH_ID,
            index,
            &utxo.script_pubkey,
            utxo.satoshis.to_sat(),
            SIGHASH_ALL,
        )?;
        tx.inputs[index].script_sig = if index < leading {
            // The fulfillment states the hash type in one byte of its own,
            // unlike a P2PKH scriptSig where it trails the DER signature.
            let hash_type = u8::try_from(SIGHASH_ALL).expect("SIGHASH_ALL is 1");
            let signatures = leading_keys
                .iter()
                .map(|key| {
                    Ok((
                        key.public_key().to_bytes(),
                        key.sign_prehash_compact(&sighash)?,
                    ))
                })
                .collect::<Result<Vec<_>, TxError>>()?;
            fulfillment_script_sig(&signatures, hash_type)?
        } else {
            p2pkh_script_sig(funding_key, &sighash, &funding_pubkey)?
        };
    }
    Ok(())
}

/// Refuse an expiry height consensus would reject.
///
/// # Errors
///
/// [`TxError::ExpiryHeightTooLarge`] if the height is at or above the
/// consensus threshold.
pub fn check_expiry(expiry: Expiry) -> Result<(), TxError> {
    expiry.check()
}

/// Refuse funding this crate cannot sign.
///
/// The builders above take arbitrary UTXOs from a caller, and only plain P2PKH
/// funding can be signed here — a CryptoCondition output needs an authority
/// this layer does not model. Refusing is the point: signing whatever decoded
/// would produce a transaction the network rejects, after the caller has
/// already committed to it.
///
/// # Errors
///
/// [`TxError::UnsupportedFundingScript`] naming the first UTXO that is not
/// P2PKH.
pub fn check_p2pkh_funding(utxos: &[Utxo]) -> Result<(), TxError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use verus_tx_primitives::cc::identity_payment_script;
    use verus_tx_primitives::Txid;

    fn key() -> PrivateKey {
        PrivateKey::from_wif("UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc").unwrap()
    }

    fn utxo(satoshis: u64, vout: u32, script_pubkey: Vec<u8>) -> Utxo {
        Utxo {
            txid: Txid::from_display_hex(
                "59a1097f1162b8dfd7037b5933d7156700bb0fe4230f14f003ba5f1c087206b3",
            )
            .unwrap(),
            vout,
            satoshis: Amount::from_sat(satoshis),
            script_pubkey,
        }
    }

    fn value_bearing_plan<'a>(
        leading: &'a [Utxo],
        funding: &'a [Utxo],
        change_address: &'a Address,
        change_script: Option<Vec<u8>>,
    ) -> Assembly<'a> {
        Assembly {
            leading,
            funding,
            outputs: Vec::new(),
            burn: Amount::ZERO,
            fee_output_count: 1,
            change_address,
            change_script,
            value_bearing_leading: true,
            expiry: Expiry::Never,
            fee_per_kb: verus_tx_primitives::fee::DEFAULT_FEE_PER_KB,
        }
    }

    /// No public builder can reach these — `identity_spend` passes no funding
    /// and the mint refuses P2PKH coins first — so the guards are pinned here,
    /// where a future in-crate call site would meet them.
    #[test]
    fn value_bearing_leading_refuses_mixed_funding_and_a_missing_change_script() {
        let identity_script = identity_payment_script([0x42; 20]).unwrap();
        let leading = [utxo(1_00000000, 0, identity_script.clone())];
        let p2pkh = [utxo(
            1_00000000,
            1,
            key().address().p2pkh_script_pubkey().unwrap(),
        )];
        let change = key().address();

        let mixed = value_bearing_plan(&leading, &p2pkh, &change, Some(identity_script.clone()));
        assert!(matches!(
            assemble(&key(), &[&key()], mixed),
            Err(TxError::MixedFunding)
        ));

        let scriptless = value_bearing_plan(&leading, &[], &change, None);
        assert!(matches!(
            assemble(&key(), &[&key()], scriptless),
            Err(TxError::MissingChangeScript)
        ));

        let duplicated = [
            utxo(1_00000000, 0, identity_script.clone()),
            utxo(1_00000000, 0, identity_script.clone()),
        ];
        let dup = value_bearing_plan(&duplicated, &[], &change, Some(identity_script));
        assert!(matches!(
            assemble(&key(), &[&key()], dup),
            Err(TxError::DuplicateUtxo { .. })
        ));
    }

    /// A short identity-funded plan answers with the identity's real holdings.
    #[test]
    fn a_short_value_bearing_plan_reports_honest_numbers() {
        let identity_script = identity_payment_script([0x42; 20]).unwrap();
        let leading = [utxo(5_000, 0, identity_script.clone())];
        let change = key().address();
        let mut plan = value_bearing_plan(&leading, &[], &change, Some(identity_script));
        plan.outputs = vec![TxOut {
            value: 50_000,
            script_pubkey: change.p2pkh_script_pubkey().unwrap(),
        }];
        match assemble(&key(), &[&key()], plan) {
            Err(TxError::InsufficientFunds {
                required,
                available,
            }) => {
                assert_eq!(available, 5_000, "what the identity actually holds");
                assert!(required > 50_000, "the outlay plus the estimated fee");
            }
            other => panic!("expected InsufficientFunds, got {other:?}"),
        }
    }

    /// #194: two caller-supplied output values whose total exceeds `u64::MAX`
    /// are refused, not wrapped.
    ///
    /// The wrap used to be invisible to every later check: `declared_value`
    /// came down to a plausible number the funding covers, and the
    /// conservation check summed the same two values the same way, so
    /// `inputs − outputs` still matched and the transaction was signed. The
    /// debug build was no better, only louder — it panicked inside `Sum`
    /// instead of returning an error, which is the divergence this pins shut.
    #[test]
    fn output_values_that_overflow_u64_are_refused() {
        // Derived from `u64::MAX` rather than pinned: the pair sums to
        // `u64::MAX + 1 + payout`, so an unchecked sum wraps to `payout`.
        let payout: u64 = 50_000;
        let offset: u64 = 1_000_000;
        let first = u64::MAX - offset;
        let second = offset + 1 + payout;
        assert!(
            first.checked_add(second).is_none(),
            "the fixture has to actually overflow u64"
        );
        assert_eq!(
            first.wrapping_add(second),
            payout,
            "and wrap to a number the funding below covers — which is why \
             nothing downstream used to catch it"
        );

        let change = key().address();
        let script = change.p2pkh_script_pubkey().unwrap();
        let funding = [utxo(1_00000000, 0, script.clone())];
        // The historical shape: no leading inputs, P2PKH funding, P2PKH
        // change. Only `value_bearing_leading` differs from the fixture.
        let mut plan = value_bearing_plan(&[], &funding, &change, None);
        plan.value_bearing_leading = false;
        plan.fee_output_count = 3;
        plan.outputs = vec![
            TxOut {
                value: first,
                script_pubkey: script.clone(),
            },
            TxOut {
                value: second,
                script_pubkey: script,
            },
        ];

        match assemble(&key(), &[], plan) {
            Err(TxError::ValueOverflow) => {}
            other => panic!("expected ValueOverflow, got {other:?}"),
        }
    }
}
