//! What a set of outputs is worth, currency by currency.
//!
//! A Verus address holds more than coins. Tokens live in the *payload* of
//! CryptoCondition reserve outputs, not in their satoshi field, so a satoshi
//! count says nothing about them and "what does this address have" has as many
//! answers as there are currencies it has touched.
//!
//! This is pure decoding — the same decoder [`crate::build_token_send`] uses to
//! *select* those outputs, so a balance computed here always agrees with what a
//! transfer can actually spend. It needs no node: a caller who already has the
//! outputs already has the answer.
//!
//! # An output this crate cannot read is not zero
//!
//! [`token_balances`] is fallible, and that is the point of it. A
//! CryptoCondition whose eval code this crate does not decode may carry value it
//! cannot see, and [`crate::decode_output_script`] reports that as a *value*
//! ([`crate::OutputKind::UnsupportedCryptoCondition`]) rather than an error — so
//! skipping it is precisely how a balance silently loses a token and tells a
//! user they hold nothing when they hold something. It is refused instead, and
//! named.

use std::collections::BTreeMap;

use crate::amount::Amount;
use crate::currency::CurrencyId;
use crate::decode::{decode_output_script, OutputKind};
use crate::error::TxError;
use crate::Utxo;

/// How much of each currency a set of outputs carries.
///
/// The chain's own native value is **not** here: it has no currency id in an
/// output, and folding the two together is how double-counting starts.
pub type TokenBalances = BTreeMap<CurrencyId, Amount>;

/// Sum the token value carried by `utxos`.
///
/// Native satoshis are ignored — a reserve output carries native value *as well
/// as* its payload, and that part belongs to the native total, not to the token.
pub fn token_balances(utxos: &[Utxo]) -> Result<TokenBalances, TxError> {
    let mut held = TokenBalances::new();
    for utxo in utxos {
        let tokens = match decode_output_script(&utxo.script_pubkey)? {
            OutputKind::ReserveOutput { tokens, .. } => tokens,
            // Native value, held plainly or held for an identity; and the
            // output that *is* an identity, which is a definition rather than a
            // balance. None carries a currency payload.
            OutputKind::PubKeyHash { .. }
            | OutputKind::IdentityPayment { .. }
            | OutputKind::IdentityPrimary { .. } => continue,
            OutputKind::UnsupportedCryptoCondition { eval_code } => {
                return Err(TxError::UncountableOutput {
                    txid: utxo.txid.to_display_hex(),
                    vout: utxo.vout,
                    eval_code,
                })
            }
        };
        for (currency, amount) in tokens {
            let entry = held.entry(currency).or_insert(Amount::ZERO);
            *entry = entry
                .checked_add(Amount::from_sat(amount))
                .ok_or(TxError::ValueOverflow)?;
        }
    }
    Ok(held)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cc;
    use crate::{Destination, Txid};
    use verus_keys::{Address, AddressKind};

    const A: CurrencyId = CurrencyId::from_bytes([0xaa; 20]);
    const B: CurrencyId = CurrencyId::from_bytes([0xbb; 20]);

    fn reserve_output(currency: CurrencyId, amount: u64) -> Utxo {
        Utxo {
            txid: Txid::from_internal([0x22; 32]),
            vout: 0,
            satoshis: Amount::from_sat(10_000),
            script_pubkey: cc::reserve_output_script([0x11; 20], currency, amount).unwrap(),
        }
    }

    fn native() -> Utxo {
        Utxo {
            txid: Txid::from_internal([0x33; 32]),
            vout: 1,
            satoshis: Amount::from_sat(5_000_000),
            script_pubkey: Address::new(AddressKind::PubKeyHash, [0x11; 20])
                .p2pkh_script_pubkey()
                .unwrap(),
        }
    }

    #[test]
    fn a_native_only_address_holds_no_tokens() {
        assert!(token_balances(&[native()]).unwrap().is_empty());
    }

    #[test]
    fn balances_accumulate_across_outputs_and_currencies() {
        let held = token_balances(&[
            native(),
            reserve_output(A, 100),
            reserve_output(A, 250),
            reserve_output(B, 7),
        ])
        .unwrap();
        assert_eq!(held.get(&A), Some(&Amount::from_sat(350)));
        assert_eq!(held.get(&B), Some(&Amount::from_sat(7)));
        assert_eq!(held.len(), 2, "native value must not appear as a currency");
    }

    /// The native satoshis a reserve output also carries belong to the native
    /// total. Counting them as token value would inflate every token balance by
    /// the dust that carries it.
    #[test]
    fn the_native_value_of_a_reserve_output_is_not_token_value() {
        let utxo = reserve_output(A, 100);
        assert_eq!(utxo.satoshis, Amount::from_sat(10_000));
        assert_eq!(token_balances(&[utxo]).unwrap()[&A], Amount::from_sat(100));
    }

    /// **Why this is fallible.** The decoder reports an unreadable
    /// CryptoCondition as a value, not an error, so a `continue` here would
    /// silently drop whatever it carries.
    #[test]
    fn an_unreadable_output_is_refused_rather_than_counted_as_nothing() {
        let utxo = Utxo {
            txid: Txid::from_internal([0x55; 32]),
            vout: 3,
            satoshis: Amount::from_sat(1),
            script_pubkey: cc::cc_script(
                &cc::OptCcParams::one_of_one(0x7f, Destination::PubKeyHash([0x44; 20])),
                &cc::OptCcParams::one_of_one(0x7f, Destination::PubKeyHash([0x44; 20])),
            )
            .unwrap(),
        };
        match token_balances(&[reserve_output(A, 100), utxo]) {
            Err(TxError::UncountableOutput {
                txid,
                vout,
                eval_code,
            }) => {
                // Named, or a wallet cannot tell a user which output to look at.
                assert!(txid.starts_with("5555"), "{txid}");
                assert_eq!(vout, 3);
                assert_eq!(eval_code, 0x7f);
            }
            other => panic!("an unreadable output must not read as zero: {other:?}"),
        }
    }

    /// An identity output is not a token balance — and must not be an error
    /// either, or an address holding a VerusID could report no balance at all.
    #[test]
    fn an_identity_output_is_skipped_not_refused() {
        let utxo = Utxo {
            txid: Txid::from_internal([0x66; 32]),
            vout: 0,
            satoshis: Amount::from_sat(1_000),
            script_pubkey: crate::identity_payment_script([0x77; 20]).unwrap(),
        };
        assert!(token_balances(&[utxo]).unwrap().is_empty());
    }
}
