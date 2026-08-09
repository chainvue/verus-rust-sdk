//! Fee estimation and coin selection.
//!
//! **Ported literally** from `@chainvue/verus-sdk`'s `src/utxo/index.ts`
//! (lines 132-147 and 152-323), quirks included. Byte-for-byte agreement with
//! that implementation is this crate's correctness gate, and the fee feeds the
//! change output — so a "better" heuristic here would change transaction bytes
//! and silently break every differential vector. If the heuristic is ever
//! genuinely fixed, both sides must change in one commit and the vectors be
//! regenerated.

use crate::amount::Amount;
use crate::error::TxError;
use crate::Utxo;

/// Fixed transaction overhead, in bytes. (`TX_OVERHEAD`)
pub const TX_OVERHEAD: u64 = 60;
/// Assumed size of a signed input. (`INPUT_SIZE`)
pub const INPUT_SIZE: u64 = 180;
/// Assumed size of a P2PKH output. (`P2PKH_OUTPUT_SIZE`)
pub const P2PKH_OUTPUT_SIZE: u64 = 34;
/// Assumed size of a CryptoCondition output. (`SMART_OUTPUT_SIZE`)
///
/// Applied to EVERY output once any output is a smart one, exactly as the
/// TypeScript does — not per-output. That is why a token transfer's fee lands
/// above the floor while a native one sits on it.
pub const SMART_OUTPUT_SIZE: u64 = 200;
/// Default fee rate in satoshis per kilobyte. (`DEFAULT_FEE_PER_KB`)
pub const DEFAULT_FEE_PER_KB: u64 = 10_000;
/// Floor on the fee, regardless of size. (`MIN_FEE`)
pub const MIN_FEE: u64 = 10_000;
/// Change at or below this is not worth an output; it becomes fee.
/// (`DUST_THRESHOLD`)
pub const DUST_THRESHOLD: u64 = 546;

/// The largest miner fee this crate will sign.
///
/// One whole coin, against a floor of 10,000 satoshis — four orders of magnitude
/// of headroom, so no ordinary transaction comes near it.
///
/// **This is a backstop, not a live guard.** With the current selection the
/// derived fee is `estimate_fee` — a function of transaction size — plus at most
/// [`DUST_THRESHOLD`] of folded change, so it cannot reach this ceiling however
/// the caller funds the transaction. It is here so that a future change to the
/// heuristic cannot quietly start signing large fees; `derived_fees_stay_far_below_the_ceiling`
/// pins that reasoning. The reachable risk is the *declared* outlay, which is
/// caller-supplied — see [`MAX_DECLARED_BURN`].
pub const MAX_MINER_FEE: u64 = 100_000_000;

/// The largest declared burn this crate will sign.
///
/// A burn is value the caller deliberately destroys: the 100-coin fee of a
/// VerusID registration, which is chain policy this crate cannot look up and
/// must be told. Being told means a typo is possible, and a typo here is the one
/// with real consequences — exact conservation will certify `100_000` coins as
/// happily as `100`, because it only checks that the arithmetic agrees with
/// itself.
///
/// Ten times the largest legitimate value known today, so every real
/// registration passes and an order-of-magnitude slip does not.
pub const MAX_DECLARED_BURN: u64 = 100_000_000_000;

/// The largest burn this crate trusts a node's own report of, by default.
///
/// Distinct from [`MAX_DECLARED_BURN`], and much tighter. `MAX_DECLARED_BURN`
/// is the backstop for a fee the *caller* has already decided on and pinned —
/// it exists to catch a typo, not to doubt the number. This constant guards
/// the default path instead, where nothing decided anything: `verus-flows`
/// reads `idregistrationfees` / `currencyregistrationfee` straight off
/// whatever node answered `getcurrency`, and that fee is burned outright, with
/// no output to recover it from if the node was lying.
///
/// A real identity registration on VRSCTEST/VRSC is 100 coins; a real currency
/// launch is 200. 500 — half of [`MAX_DECLARED_BURN`] — clears both with room
/// to spare for a genuine policy change, while still refusing a node that
/// reports something like 999: comfortably inside `MAX_DECLARED_BURN`, and
/// exactly the ~10x inflation a hostile or misconfigured node can otherwise get
/// signed away for free, since exact conservation certifies it as happily as
/// the real figure. A caller who has independently confirmed that a fee above
/// this bar is genuinely correct can still get it signed — by pinning it,
/// which is then judged against `MAX_DECLARED_BURN` instead, on the theory
/// that a caller who pinned a number has taken responsibility for it.
pub const MAX_TRUSTED_NODE_FEE: u64 = 500 * crate::amount::SATS_PER_COIN;

/// Refuse a derived fee that is implausible on its face.
///
/// `pub` only because the assembler that calls it is in another crate now, and
/// `#[doc(hidden)]` because that is the only reason. Reachable as
/// `verus_tx::fee::check_fee_ceiling`, but not part of what either crate
/// promises.
#[doc(hidden)]
pub fn check_fee_ceiling(fee: u64) -> Result<(), TxError> {
    if fee > MAX_MINER_FEE {
        return Err(TxError::FeeTooLarge {
            fee,
            ceiling: MAX_MINER_FEE,
        });
    }
    Ok(())
}

/// Refuse a declared burn that is implausible on its face.
///
/// `pub` and `#[doc(hidden)]` for the same reason as
/// [`check_fee_ceiling`].
#[doc(hidden)]
pub fn check_burn_ceiling(burn: u64) -> Result<(), TxError> {
    if burn > MAX_DECLARED_BURN {
        return Err(TxError::FeeTooLarge {
            fee: burn,
            ceiling: MAX_DECLARED_BURN,
        });
    }
    Ok(())
}

/// Estimate the fee for a transaction of this shape.
///
/// The rounding is `ceil(size * fee_per_kb / 1000)`. The TypeScript writes it as
/// `(x + 999n) / 1000n`; `div_ceil` is the same value for every non-negative
/// input and cannot overflow on the way, and the differential vectors would
/// catch it if that were ever untrue. The floor is applied with a **strict** `>`
/// exactly as the TypeScript does, so the two cannot drift.
///
/// Every internal caller passes [`DEFAULT_FEE_PER_KB`], and the wasm boundary
/// caps `fee_per_kb` before it ever reaches here — but this is a public
/// function, and a direct Rust caller can hand it anything, including a value
/// chosen to make `size * fee_per_kb` wrap a `u64`. A wrap in release mode
/// would not panic; it would silently produce whatever the truncated bits
/// happen to be, which can land below [`MIN_FEE`] and turn an absurd request
/// into the *minimum* fee. So the size sum and the size/rate product are both
/// checked, and an overflow is reported as [`TxError::ValueOverflow`] instead
/// of being allowed to wrap.
pub fn estimate_fee(
    num_inputs: u64,
    num_outputs: u64,
    fee_per_kb: u64,
    has_smart_outputs: bool,
) -> Result<u64, TxError> {
    let output_size = if has_smart_outputs {
        SMART_OUTPUT_SIZE
    } else {
        P2PKH_OUTPUT_SIZE
    };
    let inputs_size = num_inputs
        .checked_mul(INPUT_SIZE)
        .ok_or(TxError::ValueOverflow)?;
    let outputs_size = num_outputs
        .checked_mul(output_size)
        .ok_or(TxError::ValueOverflow)?;
    let tx_size = TX_OVERHEAD
        .checked_add(inputs_size)
        .and_then(|size| size.checked_add(outputs_size))
        .ok_or(TxError::ValueOverflow)?;
    let fee = tx_size
        .checked_mul(fee_per_kb)
        .ok_or(TxError::ValueOverflow)?
        .div_ceil(1000);
    Ok(if fee > MIN_FEE { fee } else { MIN_FEE })
}

/// The outcome of coin selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    /// Chosen UTXOs, in the order they become inputs.
    pub selected: Vec<Utxo>,
    /// Change to return, or zero when it would be dust.
    pub change: u64,
    /// The fee, including any dust that was folded into it.
    pub fee: u64,
}

/// Choose UTXOs to cover `required_native` plus the fee.
///
/// Faithful to the TypeScript in three details that matter for byte-equality:
///
/// 1. Candidates are sorted **descending** by value. (Milestone 1 has no
///    token-carrying UTXOs, so the "pure-native first" key is constant.)
/// 2. The **initial** fee estimate counts `selected.len() + 1` inputs and
///    `num_outputs + 1` outputs, while the estimate inside the loop counts
///    `selected.len()`. That off-by-one is deliberate and reproduced.
/// 3. Change is kept only when **strictly greater** than the dust threshold;
///    exactly 546 satoshis folds into the fee.
pub fn select_utxos(
    utxos: &[Utxo],
    required_native: u64,
    num_outputs: u64,
    fee_per_kb: u64,
    has_smart_outputs: bool,
) -> Result<Selection, TxError> {
    // An outpoint can only be spent once. Unchecked, a repeat double-counts the
    // funds and surfaces much later as an opaque builder failure.
    for (index, utxo) in utxos.iter().enumerate() {
        if utxos[..index]
            .iter()
            .any(|earlier| earlier.txid == utxo.txid && earlier.vout == utxo.vout)
        {
            return Err(TxError::DuplicateUtxo {
                txid: utxo.txid.to_display_hex(),
                vout: utxo.vout,
            });
        }
    }

    let mut candidates: Vec<Utxo> = utxos.to_vec();
    // Descending by value, stably — matching JavaScript's stable sort, so UTXOs
    // of equal value keep the caller's order and selection stays reproducible.
    candidates.sort_by_key(|utxo| core::cmp::Reverse(utxo.satoshis.to_sat()));
    let mut candidates = candidates.into_iter();

    let mut selected: Vec<Utxo> = Vec::new();
    // Signed: the remainder goes negative once enough value is selected, and the
    // loop condition depends on that.
    let mut remaining_native = i128::from(required_native);
    // `num_outputs` is caller-supplied (see the doc above) and feeds a `+ 1`
    // that `estimate_fee`'s own checked arithmetic cannot see: at `u64::MAX`
    // this wraps to `0` *before* it ever reaches `checked_mul`, so an unchecked
    // version of this line would silently turn an absurd output count into a
    // plausible, wrong fee instead of the overflow it actually is.
    let change_outputs = num_outputs.checked_add(1).ok_or(TxError::ValueOverflow)?;
    let mut fee = estimate_fee(1, change_outputs, fee_per_kb, has_smart_outputs)?;

    while remaining_native + i128::from(fee) > 0 {
        let Some(next) = candidates.next() else {
            // Best-effort for the error message: on overflow this reports
            // `u64::MAX` rather than a wrapped, misleading total. Either way
            // the caller is about to see `InsufficientFunds`.
            let available = Amount::checked_sum(utxos.iter().map(|u| u.satoshis))
                .map(Amount::to_sat)
                .unwrap_or(u64::MAX);
            return Err(TxError::InsufficientFunds {
                required: required_native.saturating_add(fee),
                available,
            });
        };
        remaining_native -= i128::from(next.satoshis.to_sat());
        selected.push(next);
        fee = estimate_fee(
            selected.len() as u64,
            change_outputs,
            fee_per_kb,
            has_smart_outputs,
        )?;
    }

    let total_in = Amount::checked_sum(selected.iter().map(|u| u.satoshis))
        .ok_or(TxError::ValueOverflow)?
        .to_sat();
    // Non-negative by construction: the loop only exits once the selected value
    // covers the requirement plus the fee.
    let actual_change = total_in - required_native - fee;

    let selection = if actual_change > DUST_THRESHOLD {
        Selection {
            selected,
            change: actual_change,
            fee,
        }
    } else {
        // Dust folds into the fee rather than becoming an unspendable output.
        Selection {
            selected,
            change: 0,
            fee: fee + actual_change,
        }
    };
    // Checked after the dust fold, because that is the step that can inflate a
    // fee: a caller who funds a transaction with one enormous UTXO and asks for
    // an amount just below it turns the whole remainder into "fee".
    check_fee_ceiling(selection.fee)?;
    Ok(selection)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Txid;

    fn utxo(byte: u8, satoshis: u64) -> Utxo {
        Utxo {
            txid: Txid::from_internal([byte; 32]),
            vout: 0,
            satoshis: Amount::from_sat(satoshis),
            script_pubkey: vec![0x76, 0xa9, 0x14],
        }
    }

    #[test]
    fn matches_the_golden_transactions_fee_arithmetic() {
        // 1 input, 1 declared output (+1 for change) = 308 bytes → 3_080 sats,
        // which is below the floor, so the fee is MIN_FEE. This is the value in
        // the TypeScript SDK's golden snapshot.
        assert_eq!(
            estimate_fee(1, 2, DEFAULT_FEE_PER_KB, false).unwrap(),
            10_000
        );
    }

    #[test]
    fn smart_outputs_push_the_fee_above_the_floor() {
        // The token differential vector: 2 inputs, 1 declared output + native
        // change + token change = 3, all sized as smart outputs.
        // 60 + 2*180 + 3*200 = 1020 bytes -> 10_200 satoshis.
        assert_eq!(
            estimate_fee(2, 3, DEFAULT_FEE_PER_KB, true).unwrap(),
            10_200
        );
    }

    #[test]
    fn the_fee_floor_is_a_floor_not_a_default() {
        // A transaction large enough to exceed the floor must pay by size.
        let fee = estimate_fee(20, 20, DEFAULT_FEE_PER_KB, false).unwrap();
        let size = TX_OVERHEAD + 20 * INPUT_SIZE + 20 * P2PKH_OUTPUT_SIZE;
        assert_eq!(fee, (size * DEFAULT_FEE_PER_KB).div_ceil(1000));
        assert!(fee > MIN_FEE);
    }

    #[test]
    fn absurd_fee_per_kb_is_refused_rather_than_wrapped() {
        // Derived from the live constants rather than a hardcoded number, so
        // that changing TX_OVERHEAD/INPUT_SIZE/P2PKH_OUTPUT_SIZE can't leave
        // this test passing while it quietly stops exercising the overflow.
        //
        // `tx_size * fee_per_kb` used to be unchecked: any `fee_per_kb` over
        // `u64::MAX / tx_size` wraps the product, and after `div_ceil(1000)`
        // the wrapped result can land below MIN_FEE — the old code took the
        // `if fee > MIN_FEE` branch's `else` and quietly returned MIN_FEE for
        // a rate that should have produced an astronomical fee. The checked
        // arithmetic must refuse this instead of computing a wrong answer.
        let tx_size = TX_OVERHEAD + INPUT_SIZE + 2 * P2PKH_OUTPUT_SIZE; // 1 input, 2 outputs, matching the call below
        let wrapping_fee_per_kb = u64::MAX / tx_size + 1;
        assert!(matches!(
            estimate_fee(1, 2, wrapping_fee_per_kb, false),
            Err(TxError::ValueOverflow)
        ));
    }

    /// #166: `num_outputs + 1` used to be unchecked in `select_utxos`, one line
    /// above `estimate_fee`'s own checked arithmetic. At `u64::MAX` it wraps to
    /// `0` before `checked_mul` ever sees it, so an absurd caller-supplied
    /// output count silently turned into `Ok` at `MIN_FEE` instead of the
    /// overflow it actually is.
    #[test]
    fn absurd_num_outputs_is_refused_rather_than_wrapped() {
        let utxos = [utxo(1, 100_000_000)];
        assert!(matches!(
            select_utxos(&utxos, 1_000, u64::MAX, DEFAULT_FEE_PER_KB, false),
            Err(TxError::ValueOverflow)
        ));
    }

    /// #166: the UTXO sums in `select_utxos` used to escape `Amount` to raw
    /// `u64` and add with plain `+`/`.sum()`, exactly the operation `Amount`
    /// exists to forbid (see `amount.rs`'s module doc). This selection needs
    /// two selected UTXOs to force the loop past a single input, and their
    /// combined value to exceed `u64::MAX`, so `total_in` overflows on the
    /// success path rather than in the `available` error-reporting path.
    #[test]
    fn total_in_overflow_is_refused_rather_than_wrapped() {
        let utxos = [utxo(1, u64::MAX), utxo(2, u64::MAX)];
        assert!(matches!(
            select_utxos(&utxos, u64::MAX, 1, DEFAULT_FEE_PER_KB, false),
            Err(TxError::ValueOverflow)
        ));
    }

    #[test]
    fn selects_the_largest_utxo_first() {
        let utxos = [
            utxo(1, 10_000_000),
            utxo(2, 100_000_000),
            utxo(3, 50_000_000),
        ];
        let selection = select_utxos(&utxos, 40_000_000, 1, DEFAULT_FEE_PER_KB, false).unwrap();
        assert_eq!(selection.selected.len(), 1);
        assert_eq!(
            selection.selected[0].satoshis,
            Amount::from_sat(100_000_000)
        );
    }

    #[test]
    fn accumulates_until_the_requirement_and_fee_are_covered() {
        let utxos = [
            utxo(1, 30_000_000),
            utxo(2, 30_000_000),
            utxo(3, 30_000_000),
        ];
        let selection = select_utxos(&utxos, 65_000_000, 1, DEFAULT_FEE_PER_KB, false).unwrap();
        assert_eq!(selection.selected.len(), 3);
        let total: u64 = selection.selected.iter().map(|u| u.satoshis.to_sat()).sum();
        assert_eq!(total, 65_000_000 + selection.fee + selection.change);
    }

    #[test]
    fn dust_change_becomes_fee_rather_than_an_output() {
        // Leave exactly DUST_THRESHOLD over: strictly-greater means it folds.
        let required = 1_000_000;
        let fee = estimate_fee(1, 2, DEFAULT_FEE_PER_KB, false).unwrap();
        let utxos = [utxo(1, required + fee + DUST_THRESHOLD)];
        let selection = select_utxos(&utxos, required, 1, DEFAULT_FEE_PER_KB, false).unwrap();
        assert_eq!(selection.change, 0);
        assert_eq!(selection.fee, fee + DUST_THRESHOLD);
    }

    #[test]
    fn one_satoshi_above_dust_is_kept_as_change() {
        let required = 1_000_000;
        let fee = estimate_fee(1, 2, DEFAULT_FEE_PER_KB, false).unwrap();
        let utxos = [utxo(1, required + fee + DUST_THRESHOLD + 1)];
        let selection = select_utxos(&utxos, required, 1, DEFAULT_FEE_PER_KB, false).unwrap();
        assert_eq!(selection.change, DUST_THRESHOLD + 1);
        assert_eq!(selection.fee, fee);
    }

    /// The claim [`MAX_MINER_FEE`] rests on: a derived fee is a function of
    /// size plus at most one dust threshold, so no funding shape reaches the
    /// ceiling. If this ever fails, the ceiling stopped being a backstop and
    /// became a live guard — and the fee logic changed in a way worth reading.
    #[test]
    fn derived_fees_stay_far_below_the_ceiling() {
        for utxo_value in [1_000u64, 100_000_000, 2_100_000_000_000_000] {
            for required in [1u64, 546, 10_000] {
                if utxo_value <= required + 10_000 {
                    continue;
                }
                let utxos = [utxo(0xa1, utxo_value)];
                let selection = select_utxos(&utxos, required, 1, DEFAULT_FEE_PER_KB, false);
                if let Ok(selection) = selection {
                    assert!(
                        selection.fee
                            <= estimate_fee(1, 2, DEFAULT_FEE_PER_KB, false).unwrap()
                                + DUST_THRESHOLD,
                        "fee {} exceeded size estimate plus dust for a {utxo_value} input",
                        selection.fee
                    );
                    assert!(selection.fee < MAX_MINER_FEE);
                }
            }
        }
    }

    /// An order-of-magnitude slip on a registration fee is refused. Exact
    /// conservation would certify it, because it only checks the arithmetic
    /// agrees with itself.
    #[test]
    fn a_mistyped_burn_is_refused() {
        assert!(
            check_burn_ceiling(10_000_000_000).is_ok(),
            "a real registration"
        );
        assert!(matches!(
            check_burn_ceiling(10_000_000_000_000),
            Err(TxError::FeeTooLarge { .. })
        ));
    }

    #[test]
    fn conservation_holds_for_every_selection() {
        for required in [1u64, 546, 10_000, 1_000_000, 99_000_000] {
            let utxos = [utxo(1, 100_000_000), utxo(2, 20_000_000)];
            let selection = select_utxos(&utxos, required, 1, DEFAULT_FEE_PER_KB, false).unwrap();
            let total_in: u64 = selection.selected.iter().map(|u| u.satoshis.to_sat()).sum();
            assert_eq!(total_in, required + selection.fee + selection.change);
        }
    }

    #[test]
    fn selection_is_stable_under_input_reordering() {
        let a = [utxo(1, 10_000_000), utxo(2, 100_000_000)];
        let b = [utxo(2, 100_000_000), utxo(1, 10_000_000)];
        assert_eq!(
            select_utxos(&a, 40_000_000, 1, DEFAULT_FEE_PER_KB, false).unwrap(),
            select_utxos(&b, 40_000_000, 1, DEFAULT_FEE_PER_KB, false).unwrap()
        );
    }

    #[test]
    fn refuses_duplicate_outpoints() {
        let utxos = [utxo(1, 100_000_000), utxo(1, 100_000_000)];
        assert!(matches!(
            select_utxos(&utxos, 1_000, 1, DEFAULT_FEE_PER_KB, false),
            Err(TxError::DuplicateUtxo { .. })
        ));
    }

    #[test]
    fn reports_insufficient_funds_with_both_numbers() {
        let utxos = [utxo(1, 1_000_000)];
        let err = select_utxos(&utxos, 5_000_000, 1, DEFAULT_FEE_PER_KB, false).unwrap_err();
        match err {
            TxError::InsufficientFunds {
                required,
                available,
            } => {
                assert_eq!(available, 1_000_000);
                assert_eq!(required, 5_000_000 + MIN_FEE);
            }
            other => panic!("unexpected error: {other}"),
        }
    }
}
