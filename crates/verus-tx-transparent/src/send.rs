//! Building and signing a transparent send.

use verus_keys::{Address, AddressKind, PrivateKey};
use verus_wire::consensus::{SIGHASH_ALL, VERUS_BRANCH_ID};
use verus_wire::hash::txid_display;
use verus_wire::{TxIn, TxOut, TxV4};

use verus_tx_primitives::cc::identity_payment_script;
use verus_tx_primitives::fee::{select_utxos, DEFAULT_FEE_PER_KB};
use verus_tx_primitives::Amount;
use verus_tx_primitives::Expiry;
use verus_tx_primitives::TxError;
use verus_tx_primitives::{Txid, Utxo};

/// Sign every transparent input of `tx` as P2PKH, in order.
///
/// `prevouts[i]` must be the output `tx.inputs[i]` spends: the sighash commits
/// to that output's script AND its value, so a mismatch produces a signature
/// that verifies nowhere.
///
/// Exposed because a shielded transaction needs this too. A t→z is proven and
/// binding-signed by `verus-sapling` with empty `scriptSig`s, then signed here —
/// safe in either order, because the shielded sighash has no transparent-input
/// section and `scriptSig` bytes never reach `hashPrevouts`, `hashSequence` or
/// `hashOutputs`.
pub fn sign_p2pkh_inputs(
    tx: &mut TxV4,
    key: &PrivateKey,
    prevouts: &[Utxo],
) -> Result<(), TxError> {
    if prevouts.len() != tx.inputs.len() {
        return Err(TxError::PrevoutCountMismatch {
            inputs: tx.inputs.len(),
            prevouts: prevouts.len(),
        });
    }
    let pubkey = key.public_key().to_bytes();
    for (index, utxo) in prevouts.iter().enumerate() {
        if Address::from_p2pkh_script_pubkey(&utxo.script_pubkey).is_none() {
            return Err(TxError::UnsupportedFundingScript {
                txid: utxo.txid.to_display_hex(),
                vout: utxo.vout,
            });
        }
        let sighash = tx.transparent_sighash(
            VERUS_BRANCH_ID,
            index,
            &utxo.script_pubkey,
            utxo.satoshis.to_sat(),
            SIGHASH_ALL,
        )?;
        tx.inputs[index].script_sig = p2pkh_script_sig(key, &sighash, &pubkey)?;
    }
    Ok(())
}

/// `PUSH(signature || hashtype) PUSH(pubkey)` — the scriptSig unlocking a P2PKH
/// output.
///
/// Both pushes are far below the 76-byte direct-push limit, so no `OP_PUSHDATA`
/// is involved.
pub(crate) fn p2pkh_script_sig(
    key: &PrivateKey,
    sighash: &[u8; 32],
    pubkey: &[u8],
) -> Result<Vec<u8>, TxError> {
    let signature = key.sign_prehash_der(sighash, 1)?;
    let mut script_sig = Vec::with_capacity(2 + signature.len() + pubkey.len());
    script_sig.push(u8::try_from(signature.len()).expect("DER signature is under 76 bytes"));
    script_sig.extend_from_slice(&signature);
    script_sig.push(u8::try_from(pubkey.len()).expect("public key is 33 or 65 bytes"));
    script_sig.extend_from_slice(pubkey);
    Ok(script_sig)
}

/// Where value is going.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipient {
    /// The `R` address being paid.
    pub address: Address,
    /// How much to pay.
    pub satoshis: Amount,
}

/// What to build.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SendParams<'a> {
    /// UTXOs available to spend. All must be plain P2PKH controlled by `key`.
    pub utxos: &'a [Utxo],
    /// Where the value is going.
    pub recipients: &'a [Recipient],
    /// Where change goes.
    pub change_address: Address,
    /// When this transaction stops being minable.
    ///
    /// Deliberately not defaulted — see [`Expiry`], where `Never` has to be
    /// written rather than fallen into.
    pub expiry: Expiry,
    /// Fee rate in satoshis per kilobyte.
    pub fee_per_kb: u64,
}

impl<'a> SendParams<'a> {
    /// Parameters with the default fee rate.
    pub fn new(
        utxos: &'a [Utxo],
        recipients: &'a [Recipient],
        change_address: Address,
        expiry: Expiry,
    ) -> Self {
        Self {
            utxos,
            recipients,
            change_address,
            expiry,
            fee_per_kb: DEFAULT_FEE_PER_KB,
        }
    }

    /// Override the fee rate.
    pub fn with_fee_per_kb(mut self, fee_per_kb: u64) -> Self {
        self.fee_per_kb = fee_per_kb;
        self
    }
}

/// A signed transaction, ready for the caller to broadcast.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTransaction {
    /// Raw transaction hex.
    pub hex: String,
    /// Transaction id in display order.
    pub txid: String,
    /// Fee paid, including any dust folded into it.
    pub fee: Amount,
    /// Change returned, or zero if it would have been dust.
    pub change: Amount,
    /// The outpoints spent, in input order.
    pub inputs_used: Vec<(Txid, u32)>,
}

/// A transparent send with its coins chosen and its outputs placed, but
/// nothing signed.
///
/// Every decision that costs money has already been made by the time this
/// exists: which UTXOs are spent, what the fee is, whether change survives the
/// dust rule, and where it goes. A signature adds no value and moves none — it
/// only proves the spend was authorised.
///
/// Which is why it is worth having on its own. [`build_transparent_send`] takes
/// a key and therefore has to run wherever the key is; producing this does not,
/// so a machine that can see the chain can plan a payment it has no power to
/// make and hand the plan to a machine that never goes online. See
/// `verus_flows::prepare_unsigned_send` and the `airgap_watch` / `airgap_sign`
/// examples for that pair.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TransparentPlan {
    /// The UTXOs to spend, in input order.
    pub selected: Vec<Utxo>,
    /// The outputs: the recipients in the caller's order, then change if any.
    pub outputs: Vec<TxOut>,
    /// The fee, including any change too small to keep.
    pub fee: Amount,
    /// Change returned, or zero when it would have been dust.
    pub change: Amount,
    /// When the transaction stops being minable.
    pub expiry: Expiry,
    /// nLockTime — always zero for a send. Carried so that nothing downstream
    /// has to hardcode a consensus field it did not choose.
    pub lock_time: u32,
}

/// Choose coins and place outputs for a transparent send, without signing.
///
/// This is [`build_transparent_send`] up to the point where a key is needed:
/// the same coin selection, the same fee, the same output order, the same
/// conservation check. The signing path calls this one, so the two cannot drift
/// into planning different transactions — which matters, because a difference
/// of one satoshi in the fee is a different change output and therefore a
/// different transaction entirely.
///
/// # Scope
///
/// Plain native transfers only: every funding UTXO must be P2PKH and every
/// recipient an `R` address. Token transfers, conversions, VerusID operations
/// and identity-held funds all need CryptoCondition outputs, which are not
/// ported yet — and this refuses them rather than producing a transaction whose
/// value it cannot account for.
///
/// # Determinism
///
/// No randomness is involved: coin selection is ordered by value, stably. The
/// same UTXO set and the same request always produce the same plan.
pub fn plan_transparent_send(params: &SendParams<'_>) -> Result<TransparentPlan, TxError> {
    if params.recipients.is_empty() {
        return Err(TxError::NoOutputs);
    }
    params.expiry.check()?;

    // Refuse anything outside the supported shape BEFORE selecting coins, so a
    // rejection cannot depend on which UTXOs happened to be chosen.
    for utxo in params.utxos {
        if Address::from_p2pkh_script_pubkey(&utxo.script_pubkey).is_none() {
            return Err(TxError::UnsupportedFundingScript {
                txid: utxo.txid.to_display_hex(),
                vout: utxo.vout,
            });
        }
    }
    let mut required_native: u64 = 0;
    // Paying a VerusID uses a CryptoCondition output, which the fee heuristic
    // sizes at 200 bytes rather than 34 — and it sizes EVERY output that way
    // once any one of them is smart, which is why this is decided up front for
    // the whole transaction rather than per output.
    let mut has_smart_outputs = false;
    for (index, recipient) in params.recipients.iter().enumerate() {
        match recipient.address.kind() {
            AddressKind::PubKeyHash => {}
            AddressKind::Identity => has_smart_outputs = true,
            _ => return Err(TxError::UnsupportedRecipient),
        }
        if recipient.satoshis.is_zero() {
            return Err(TxError::ZeroValueOutput { index });
        }
        required_native = required_native
            .checked_add(recipient.satoshis.to_sat())
            .ok_or(TxError::ValueOverflow)?;
    }

    let selection = select_utxos(
        params.utxos,
        required_native,
        params.recipients.len() as u64,
        params.fee_per_kb,
        has_smart_outputs,
    )?;

    // Declared outputs first, then change — the order the TypeScript SDK emits,
    // and therefore part of the bytes being matched.
    let mut outputs = Vec::with_capacity(params.recipients.len() + 1);
    for recipient in params.recipients {
        let script_pubkey = match recipient.address.kind() {
            AddressKind::Identity => identity_payment_script(recipient.address.hash())?,
            _ => recipient.address.p2pkh_script_pubkey()?,
        };
        outputs.push(TxOut {
            value: recipient.satoshis.to_sat(),
            script_pubkey,
        });
    }
    if selection.change > 0 {
        outputs.push(TxOut {
            value: selection.change,
            script_pubkey: params.change_address.p2pkh_script_pubkey()?,
        });
    }

    // Exact-integer conservation, checked before anything is signed or handed
    // to a co-signer. This is the real backstop: the JavaScript fork's
    // equivalent truncates input values modulo 2^32 and is blind above ~42.9
    // coins.
    let inputs_total: u64 = selection.selected.iter().map(|u| u.satoshis.to_sat()).sum();
    let outputs_total: u64 = outputs.iter().map(|o| o.value).sum();
    let actual = i128::from(inputs_total) - i128::from(outputs_total);
    if actual != i128::from(selection.fee) {
        return Err(TxError::ValueNotConserved {
            inputs: inputs_total,
            outputs: outputs_total,
            actual,
            expected: selection.fee,
        });
    }

    Ok(TransparentPlan {
        selected: selection.selected,
        outputs,
        fee: Amount::from_sat(selection.fee),
        change: Amount::from_sat(selection.change),
        expiry: params.expiry,
        lock_time: 0,
    })
}

/// Build and sign a transparent send.
///
/// Coin selection, the fee and the outputs come from
/// [`plan_transparent_send`] — see there for what is and is not supported.
/// This adds the one thing that needs a key.
///
/// # Determinism
///
/// No randomness is involved: coin selection is ordered and signing is RFC6979.
/// The same inputs always produce the same bytes, which is what allows this to
/// be tested byte-for-byte against the TypeScript SDK.
pub fn build_transparent_send(
    key: &PrivateKey,
    params: &SendParams<'_>,
) -> Result<SignedTransaction, TxError> {
    let plan = plan_transparent_send(params)?;

    let mut tx = TxV4 {
        inputs: plan
            .selected
            .iter()
            .map(|utxo| TxIn::unsigned(utxo.txid.to_internal(), utxo.vout, 0xffff_ffff))
            .collect(),
        outputs: plan.outputs,
        lock_time: plan.lock_time,
        expiry_height: plan.expiry.to_height(),
        ..TxV4::default()
    };

    sign_p2pkh_inputs(&mut tx, key, &plan.selected)?;

    let raw = tx.serialize()?;
    Ok(SignedTransaction {
        hex: hex::encode(&raw),
        txid: txid_display(&tx.txid()?),
        fee: plan.fee,
        change: plan.change,
        inputs_used: plan
            .selected
            .iter()
            .map(|utxo| (utxo.txid, utxo.vout))
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";
    const TEST_ADDRESS: &str = "RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX";
    const TEST_ADDRESS_B: &str = "RPsQDnaxXgrLjcVBh3SpvCpTabWxAdMdzu";

    fn key() -> PrivateKey {
        PrivateKey::from_wif(TEST_WIF).unwrap()
    }

    fn address(text: &str) -> Address {
        text.parse().unwrap()
    }

    fn funding(byte: u8, satoshis: u64) -> Utxo {
        Utxo {
            txid: Txid::from_internal([byte; 32]),
            vout: 0,
            satoshis: Amount::from_sat(satoshis),
            script_pubkey: address(TEST_ADDRESS).p2pkh_script_pubkey().unwrap(),
        }
    }

    fn recipients(satoshis: u64) -> Vec<Recipient> {
        vec![Recipient {
            address: address(TEST_ADDRESS_B),
            satoshis: Amount::from_sat(satoshis),
        }]
    }

    #[test]
    fn refuses_a_non_p2pkh_funding_utxo() {
        let mut utxo = funding(0xaa, 100_000_000);
        utxo.script_pubkey = vec![0x51]; // OP_TRUE — not something we can spend
        let to = recipients(1_000_000);
        let utxos = [utxo];
        let params = SendParams::new(&utxos, &to, address(TEST_ADDRESS), Expiry::Never);
        assert!(matches!(
            build_transparent_send(&key(), &params),
            Err(TxError::UnsupportedFundingScript { .. })
        ));
    }

    /// The prevout supplies the script and value the sighash commits to, so
    /// pairing the wrong one with an input signs a commitment nobody asked for.
    /// A shielded caller assembles its own `TxV4`, which is exactly where the
    /// two lists can drift apart.
    #[test]
    fn signing_refuses_a_prevout_list_that_does_not_line_up() {
        let mut tx = TxV4 {
            inputs: vec![
                TxIn::unsigned([0xaa; 32], 0, 0xffff_ffff),
                TxIn::unsigned([0xbb; 32], 0, 0xffff_ffff),
            ],
            ..TxV4::default()
        };
        let prevouts = [funding(0xaa, 100_000_000)];
        assert!(matches!(
            sign_p2pkh_inputs(&mut tx, &key(), &prevouts),
            Err(TxError::PrevoutCountMismatch {
                inputs: 2,
                prevouts: 1
            })
        ));
    }

    #[test]
    fn signing_commits_to_the_prevout_value() {
        // Two transactions identical but for the value being signed over must
        // get different signatures — the Overwinter-era fix this relies on.
        let make = |satoshis| {
            let mut tx = TxV4 {
                inputs: vec![TxIn::unsigned([0xaa; 32], 0, 0xffff_ffff)],
                ..TxV4::default()
            };
            sign_p2pkh_inputs(&mut tx, &key(), &[funding(0xaa, satoshis)]).unwrap();
            tx.inputs[0].script_sig.clone()
        };
        assert_ne!(make(100_000_000), make(100_000_001));
    }

    #[test]
    fn signing_refuses_a_non_p2pkh_prevout() {
        let mut tx = TxV4 {
            inputs: vec![TxIn::unsigned([0xaa; 32], 0, 0xffff_ffff)],
            ..TxV4::default()
        };
        let mut utxo = funding(0xaa, 100_000_000);
        utxo.script_pubkey = vec![0x51];
        assert!(matches!(
            sign_p2pkh_inputs(&mut tx, &key(), &[utxo]),
            Err(TxError::UnsupportedFundingScript { .. })
        ));
    }

    /// Paying a VerusID emits a CryptoCondition output, not P2PKH — and the
    /// fee heuristic charges for it, because every output is sized at 200 bytes
    /// once any one of them is smart.
    #[test]
    fn pays_an_identity_with_a_cryptocondition_output() {
        let identity = Address::new(AddressKind::Identity, [0x11; 20]);
        let to = vec![Recipient {
            address: identity,
            satoshis: Amount::from_sat(1_000_000),
        }];
        let utxos = [funding(0xaa, 100_000_000)];
        let params = SendParams::new(&utxos, &to, address(TEST_ADDRESS), Expiry::Never);
        let signed = build_transparent_send(&key(), &params).expect("build");

        let expected = verus_tx_primitives::cc::identity_payment_script([0x11; 20]).unwrap();
        assert!(
            signed.hex.contains(&hex::encode(&expected)),
            "the identity payment script is not in the transaction"
        );

        // At this size both land on the 10 000 floor, so the fee alone proves
        // nothing here — see the next test for where it bites.
        assert_eq!(signed.fee, Amount::from_sat(10_000));
    }

    /// The smart-output flag has to actually reach the fee estimate. One small
    /// output hides that, because the 10 000 floor swallows the difference —
    /// so this uses enough outputs to clear the floor, where 200 bytes per
    /// output instead of 34 is visible.
    #[test]
    fn identity_outputs_are_charged_at_the_smart_output_size() {
        let utxos = [funding(0xaa, 500_000_000)];
        let to_identities: Vec<Recipient> = (0..20)
            .map(|i| Recipient {
                address: Address::new(AddressKind::Identity, [i; 20]),
                satoshis: Amount::from_sat(1_000_000),
            })
            .collect();
        let to_addresses: Vec<Recipient> = (0..20)
            .map(|_| Recipient {
                address: address(TEST_ADDRESS_B),
                satoshis: Amount::from_sat(1_000_000),
            })
            .collect();

        let smart = build_transparent_send(
            &key(),
            &SendParams::new(&utxos, &to_identities, address(TEST_ADDRESS), Expiry::Never),
        )
        .expect("build");
        let native = build_transparent_send(
            &key(),
            &SendParams::new(&utxos, &to_addresses, address(TEST_ADDRESS), Expiry::Never),
        )
        .expect("build");

        assert!(
            smart.fee > native.fee,
            "CryptoCondition outputs must cost more than P2PKH ones ({} vs {})",
            smart.fee,
            native.fee
        );
        // The exact numbers, because "bigger" would pass even if the flag were
        // reaching the estimate by accident. One input, 21 outputs (20 plus
        // change), 10 000 satoshis per 1000 bytes:
        //   native  60 + 180 + 21*34  =  954 bytes -> 9 540, raised to the
        //                                            10 000 floor
        //   smart   60 + 180 + 21*200 = 4440 bytes -> 44 400, well clear of it
        assert_eq!(native.fee, Amount::from_sat(10_000));
        assert_eq!(smart.fee, Amount::from_sat(44_400));
    }

    #[test]
    fn still_refuses_a_script_hash_recipient() {
        let to = vec![Recipient {
            address: Address::new(AddressKind::ScriptHash, [0x11; 20]),
            satoshis: Amount::from_sat(1_000_000),
        }];
        let utxos = [funding(0xaa, 100_000_000)];
        let params = SendParams::new(&utxos, &to, address(TEST_ADDRESS), Expiry::Never);
        assert!(matches!(
            build_transparent_send(&key(), &params),
            Err(TxError::UnsupportedRecipient)
        ));
    }

    #[test]
    fn refuses_an_out_of_range_expiry_height() {
        let utxos = [funding(0xaa, 100_000_000)];
        let to = recipients(1_000_000);
        let mut params = SendParams::new(
            &utxos,
            &to,
            address(TEST_ADDRESS),
            Expiry::AtHeight(500_000_000),
        );
        assert!(matches!(
            build_transparent_send(&key(), &params),
            Err(TxError::ExpiryHeightTooLarge(500_000_000))
        ));
        // One below the threshold is fine.
        params.expiry = Expiry::AtHeight(499_999_999);
        assert!(build_transparent_send(&key(), &params).is_ok());
    }

    #[test]
    fn refuses_a_zero_value_output() {
        let utxos = [funding(0xaa, 100_000_000)];
        let to = recipients(0);
        let params = SendParams::new(&utxos, &to, address(TEST_ADDRESS), Expiry::Never);
        assert!(matches!(
            build_transparent_send(&key(), &params),
            Err(TxError::ZeroValueOutput { index: 0 })
        ));
    }

    #[test]
    fn refuses_to_build_with_no_outputs() {
        let utxos = [funding(0xaa, 100_000_000)];
        let params = SendParams::new(&utxos, &[], address(TEST_ADDRESS), Expiry::Never);
        assert!(matches!(
            build_transparent_send(&key(), &params),
            Err(TxError::NoOutputs)
        ));
    }

    #[test]
    fn value_is_conserved_across_a_range_of_amounts() {
        for amount in [1_000u64, 546, 50_000_000, 99_000_000] {
            let utxos = [funding(0xaa, 100_000_000)];
            let to = recipients(amount);
            let params = SendParams::new(&utxos, &to, address(TEST_ADDRESS), Expiry::Never);
            let signed = build_transparent_send(&key(), &params).unwrap();
            assert_eq!(
                100_000_000,
                amount + signed.fee.to_sat() + signed.change.to_sat()
            );
        }
    }

    #[test]
    fn is_deterministic() {
        let utxos = [funding(0xaa, 100_000_000), funding(0xbb, 20_000_000)];
        let to = recipients(50_000_000);
        let params = SendParams::new(&utxos, &to, address(TEST_ADDRESS), Expiry::Never);
        assert_eq!(
            build_transparent_send(&key(), &params).unwrap(),
            build_transparent_send(&key(), &params).unwrap()
        );
    }
}
