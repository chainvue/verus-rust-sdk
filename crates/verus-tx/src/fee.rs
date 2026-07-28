//! Fee estimation and coin selection.
//!
//! **Ported literally** from `@chainvue/verus-sdk`'s `src/utxo/index.ts`
//! (lines 132-147 and 152-323), quirks included. Byte-for-byte agreement with
//! that implementation is this crate's correctness gate, and the fee feeds the
//! change output — so a "better" heuristic here would change transaction bytes
//! and silently break every differential vector. If the heuristic is ever
//! genuinely fixed, both sides must change in one commit and the vectors be
//! regenerated.

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

/// Estimate the fee for a transaction of this shape.
///
/// The rounding is `ceil(size * fee_per_kb / 1000)`. The TypeScript writes it as
/// `(x + 999n) / 1000n`; `div_ceil` is the same value for every non-negative
/// input and cannot overflow on the way, and the differential vectors would
/// catch it if that were ever untrue. The floor is applied with a **strict** `>`
/// exactly as the TypeScript does, so the two cannot drift.
pub fn estimate_fee(
    num_inputs: u64,
    num_outputs: u64,
    fee_per_kb: u64,
    has_smart_outputs: bool,
) -> u64 {
    let output_size = if has_smart_outputs {
        SMART_OUTPUT_SIZE
    } else {
        P2PKH_OUTPUT_SIZE
    };
    let tx_size = TX_OVERHEAD + num_inputs * INPUT_SIZE + num_outputs * output_size;
    let fee = (tx_size * fee_per_kb).div_ceil(1000);
    if fee > MIN_FEE {
        fee
    } else {
        MIN_FEE
    }
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
    candidates.sort_by_key(|utxo| core::cmp::Reverse(utxo.satoshis));
    let mut candidates = candidates.into_iter();

    let mut selected: Vec<Utxo> = Vec::new();
    // Signed: the remainder goes negative once enough value is selected, and the
    // loop condition depends on that.
    let mut remaining_native = i128::from(required_native);
    let mut fee = estimate_fee(1, num_outputs + 1, fee_per_kb, false);

    while remaining_native + i128::from(fee) > 0 {
        let Some(next) = candidates.next() else {
            let available: u64 = utxos.iter().map(|u| u.satoshis).sum();
            return Err(TxError::InsufficientFunds {
                required: required_native.saturating_add(fee),
                available,
            });
        };
        remaining_native -= i128::from(next.satoshis);
        selected.push(next);
        fee = estimate_fee(selected.len() as u64, num_outputs + 1, fee_per_kb, false);
    }

    let total_in: u64 = selected.iter().map(|u| u.satoshis).sum();
    // Non-negative by construction: the loop only exits once the selected value
    // covers the requirement plus the fee.
    let actual_change = total_in - required_native - fee;

    Ok(if actual_change > DUST_THRESHOLD {
        Selection {
            selected,
            change: actual_change,
            fee,
        }
    } else {
        Selection {
            selected,
            change: 0,
            fee: fee + actual_change,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Txid;

    fn utxo(byte: u8, satoshis: u64) -> Utxo {
        Utxo {
            txid: Txid::from_internal([byte; 32]),
            vout: 0,
            satoshis,
            script_pubkey: vec![0x76, 0xa9, 0x14],
        }
    }

    #[test]
    fn matches_the_golden_transactions_fee_arithmetic() {
        // 1 input, 1 declared output (+1 for change) = 308 bytes → 3_080 sats,
        // which is below the floor, so the fee is MIN_FEE. This is the value in
        // the TypeScript SDK's golden snapshot.
        assert_eq!(estimate_fee(1, 2, DEFAULT_FEE_PER_KB, false), 10_000);
    }

    #[test]
    fn smart_outputs_push_the_fee_above_the_floor() {
        // The token differential vector: 2 inputs, 1 declared output + native
        // change + token change = 3, all sized as smart outputs.
        // 60 + 2*180 + 3*200 = 1020 bytes -> 10_200 satoshis.
        assert_eq!(estimate_fee(2, 3, DEFAULT_FEE_PER_KB, true), 10_200);
    }

    #[test]
    fn the_fee_floor_is_a_floor_not_a_default() {
        // A transaction large enough to exceed the floor must pay by size.
        let fee = estimate_fee(20, 20, DEFAULT_FEE_PER_KB, false);
        let size = TX_OVERHEAD + 20 * INPUT_SIZE + 20 * P2PKH_OUTPUT_SIZE;
        assert_eq!(fee, (size * DEFAULT_FEE_PER_KB).div_ceil(1000));
        assert!(fee > MIN_FEE);
    }

    #[test]
    fn selects_the_largest_utxo_first() {
        let utxos = [
            utxo(1, 10_000_000),
            utxo(2, 100_000_000),
            utxo(3, 50_000_000),
        ];
        let selection = select_utxos(&utxos, 40_000_000, 1, DEFAULT_FEE_PER_KB).unwrap();
        assert_eq!(selection.selected.len(), 1);
        assert_eq!(selection.selected[0].satoshis, 100_000_000);
    }

    #[test]
    fn accumulates_until_the_requirement_and_fee_are_covered() {
        let utxos = [
            utxo(1, 30_000_000),
            utxo(2, 30_000_000),
            utxo(3, 30_000_000),
        ];
        let selection = select_utxos(&utxos, 65_000_000, 1, DEFAULT_FEE_PER_KB).unwrap();
        assert_eq!(selection.selected.len(), 3);
        let total: u64 = selection.selected.iter().map(|u| u.satoshis).sum();
        assert_eq!(total, 65_000_000 + selection.fee + selection.change);
    }

    #[test]
    fn dust_change_becomes_fee_rather_than_an_output() {
        // Leave exactly DUST_THRESHOLD over: strictly-greater means it folds.
        let required = 1_000_000;
        let fee = estimate_fee(1, 2, DEFAULT_FEE_PER_KB, false);
        let utxos = [utxo(1, required + fee + DUST_THRESHOLD)];
        let selection = select_utxos(&utxos, required, 1, DEFAULT_FEE_PER_KB).unwrap();
        assert_eq!(selection.change, 0);
        assert_eq!(selection.fee, fee + DUST_THRESHOLD);
    }

    #[test]
    fn one_satoshi_above_dust_is_kept_as_change() {
        let required = 1_000_000;
        let fee = estimate_fee(1, 2, DEFAULT_FEE_PER_KB, false);
        let utxos = [utxo(1, required + fee + DUST_THRESHOLD + 1)];
        let selection = select_utxos(&utxos, required, 1, DEFAULT_FEE_PER_KB).unwrap();
        assert_eq!(selection.change, DUST_THRESHOLD + 1);
        assert_eq!(selection.fee, fee);
    }

    #[test]
    fn conservation_holds_for_every_selection() {
        for required in [1u64, 546, 10_000, 1_000_000, 99_000_000] {
            let utxos = [utxo(1, 100_000_000), utxo(2, 20_000_000)];
            let selection = select_utxos(&utxos, required, 1, DEFAULT_FEE_PER_KB).unwrap();
            let total_in: u64 = selection.selected.iter().map(|u| u.satoshis).sum();
            assert_eq!(total_in, required + selection.fee + selection.change);
        }
    }

    #[test]
    fn selection_is_stable_under_input_reordering() {
        let a = [utxo(1, 10_000_000), utxo(2, 100_000_000)];
        let b = [utxo(2, 100_000_000), utxo(1, 10_000_000)];
        assert_eq!(
            select_utxos(&a, 40_000_000, 1, DEFAULT_FEE_PER_KB).unwrap(),
            select_utxos(&b, 40_000_000, 1, DEFAULT_FEE_PER_KB).unwrap()
        );
    }

    #[test]
    fn refuses_duplicate_outpoints() {
        let utxos = [utxo(1, 100_000_000), utxo(1, 100_000_000)];
        assert!(matches!(
            select_utxos(&utxos, 1_000, 1, DEFAULT_FEE_PER_KB),
            Err(TxError::DuplicateUtxo { .. })
        ));
    }

    #[test]
    fn reports_insufficient_funds_with_both_numbers() {
        let utxos = [utxo(1, 1_000_000)];
        let err = select_utxos(&utxos, 5_000_000, 1, DEFAULT_FEE_PER_KB).unwrap_err();
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
