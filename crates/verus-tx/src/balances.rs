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
//! # What it cannot count, and what that costs
//!
//! Failing closed has a price, and it should be stated rather than discovered:
//!
//! * A **proof-of-stake coinbase** pays its first output to a stakeguard
//!   CryptoCondition (eval code 1), which this crate does not decode. A recent
//!   staker's balance is therefore *unknown*, not zero.
//! * **Tokens held by a VerusID** are reserve outputs paying an identity
//!   destination, which the decoder does not read yet. Counting an
//!   i-address's holdings fails for the same reason.
//!
//! Both refuse by name — the outpoint is in the error — so a caller who knows
//! an output is harmless can drop it and count the rest. A proof-of-work
//! coinbase, which pays P2PK, *is* counted: it provably carries no currency,
//! and refusing it would be a gap dressed as caution.
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
///
/// `utxos` must hold each outpoint at most once: this sums what it is given and
/// cannot tell a genuine second output from the same one listed twice, so a
/// caller concatenating paged results should deduplicate first.
pub fn token_balances(utxos: &[Utxo]) -> Result<TokenBalances, TxError> {
    let mut held = TokenBalances::new();
    for utxo in utxos {
        let uncountable = |reason: String| TxError::UncountableOutput {
            txid: utxo.txid.to_display_hex(),
            vout: utxo.vout,
            reason,
        };
        // Every refusal names the output. A decoder error on its own does not:
        // a wallet told "a reserve output paying an identity is not decoded
        // yet" cannot tell which of forty outputs to look at.
        let decoded = decode_output_script(&utxo.script_pubkey)
            .map_err(|error| uncountable(error.to_string()))?;
        let tokens = match decoded {
            OutputKind::ReserveOutput { tokens, .. } => tokens,
            // Native value — held plainly, paid to a public key, or held for
            // an identity — and the output that *is* an identity, which is a
            // definition rather than a balance. None carries a currency
            // payload, so none contributes to a token total.
            //
            // `PubKey` is on this list for a reason worth stating: a
            // proof-of-work coinbase pays itself P2PK, so any address that has
            // ever mined holds one. This crate cannot *spend* such an output,
            // but it can be certain no token hides in it — and refusing the
            // whole balance over an output that provably carries nothing would
            // be a gap dressed as caution.
            OutputKind::PubKeyHash { .. }
            | OutputKind::PubKey { .. }
            | OutputKind::IdentityPayment { .. }
            | OutputKind::IdentityPrimary { .. } => continue,
            OutputKind::UnsupportedCryptoCondition { eval_code } => {
                return Err(uncountable(format!(
                    "it is a CryptoCondition with eval code {eval_code}, which this crate \
                     cannot decode"
                )))
            }
        };
        for (currency, amount) in tokens {
            // A zero entry is not a holding. Recording one would make a wallet
            // list a currency the user does not have.
            if amount == 0 {
                continue;
            }
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
            Err(TxError::UncountableOutput { txid, vout, reason }) => {
                // Named, or a wallet cannot tell a user which output to look at.
                assert!(txid.starts_with("5555"), "{txid}");
                assert_eq!(vout, 3);
                assert!(
                    reason.contains("127"),
                    "the eval code must be named: {reason}"
                );
            }
            other => panic!("an unreadable output must not read as zero: {other:?}"),
        }
    }

    /// **A proof-of-work coinbase pays P2PK**, so any address that has ever
    /// mined holds one. Refusing the whole balance over an output that
    /// provably cannot carry a token would make this function useless for
    /// every miner — and it did, until the decoder learned the shape.
    ///
    /// The script is a real one: block 1170100 on VRSCTEST, coinbase vout 0.
    #[test]
    fn a_pay_to_pubkey_coinbase_output_carries_no_token_and_is_not_refused() {
        let script =
            hex::decode("2102b8f1cef8c8e81e3fd428cfdaf78e86c725c7d04e487f8b0f151d3929a19fa56eac")
                .unwrap();
        let utxo = Utxo {
            txid: Txid::from_internal([0x77; 32]),
            vout: 0,
            satoshis: Amount::from_sat(600_000_000),
            script_pubkey: script,
        };
        let held = token_balances(&[utxo, reserve_output(A, 100)])
            .expect("a miner must still be able to see their tokens");
        assert_eq!(held[&A], Amount::from_sat(100));
        assert_eq!(held.len(), 1, "a P2PK output contributes no currency");
    }

    /// **A proof-of-stake coinbase pays a stakeguard CryptoCondition**, which
    /// this crate does not decode. So a recent staker's balance is *unknown*,
    /// not zero — and the refusal has to say which output made it unknown,
    /// because that is the only way a caller can decide the output is
    /// harmless and count the rest themselves.
    ///
    /// The script is a real one: block 1170103 on VRSCTEST, coinbase vout 0.
    /// This test records a known limitation rather than approving of it; the
    /// fix is to teach the decoder eval code 1, at which point this test
    /// should change to assert the balance succeeds.
    #[test]
    fn a_stakeguard_output_is_refused_by_name_rather_than_ignored() {
        let script = hex::decode(
            "3d04030001021504d72c764548836ae9e1784b54afed2c1f1061bd532103166b7813a4855a88e9ef7\
             340a692ef3c2decedfdc2c7563ec79537e89667d935cc4c8704030101011504d72c764548836ae9e17\
             84b54afed2c1f1061bd5343010000a659dcb60845f0ea2f48a9a5513cd90ab986fd670d8644f52fcc1\
             53478260efdd114a32487649aababf8c747cb6733b6c69da63362cd6f226fead87401000000270403\
             0101012103166b7813a4855a88e9ef7340a692ef3c2decedfdc2c7563ec79537e89667d93575"
                .replace(['\n', ' '], "")
                .as_str(),
        )
        .expect("a real stakeguard script");
        let utxo = Utxo {
            txid: Txid::from_internal([0x99; 32]),
            vout: 0,
            satoshis: Amount::from_sat(600_000_000),
            script_pubkey: script,
        };
        match token_balances(&[utxo]) {
            Err(TxError::UncountableOutput { txid, vout, reason }) => {
                assert!(txid.starts_with("9999"), "{txid}");
                assert_eq!(vout, 0);
                assert!(
                    reason.contains('1'),
                    "the eval code must be named: {reason}"
                );
            }
            other => panic!("a stakeguard output must be refused, by name: {other:?}"),
        }
    }

    /// Every refusal must name the output, not only the one that has a
    /// dedicated variant. A decoder error carries no outpoint of its own, so a
    /// wallet told "a reserve output paying an identity is not decoded yet"
    /// could not say which of forty outputs to look at.
    #[test]
    fn a_decoder_failure_is_reported_against_the_output_that_caused_it() {
        let utxo = Utxo {
            txid: Txid::from_internal([0x88; 32]),
            vout: 9,
            satoshis: Amount::from_sat(1),
            // A CryptoCondition prefix with nothing decodable after it.
            script_pubkey: vec![0x4c, 0x0f, 0xcc],
        };
        match token_balances(&[utxo]) {
            Err(TxError::UncountableOutput { txid, vout, .. }) => {
                assert!(txid.starts_with("8888"), "{txid}");
                assert_eq!(vout, 9);
            }
            other => panic!("a decode failure must name its output: {other:?}"),
        }
    }

    /// Summing must not wrap. The guard is unreachable with real supplies, and
    /// pinned anyway because an unchecked add here would silently report a
    /// balance smaller than the truth.
    #[test]
    fn a_total_that_would_overflow_is_refused_rather_than_wrapped() {
        let huge = reserve_output(A, u64::MAX);
        let more = reserve_output(A, 1);
        assert!(matches!(
            token_balances(&[huge, more]),
            Err(TxError::ValueOverflow)
        ));
        // One output at the ceiling is reported, not refused.
        assert_eq!(
            token_balances(&[reserve_output(A, u64::MAX)]).unwrap()[&A],
            Amount::from_sat(u64::MAX)
        );
    }

    /// A zero-value token entry is not a holding, and printing "0 SOMETOKEN"
    /// for a currency a user does not have is noise.
    #[test]
    fn a_zero_amount_does_not_create_a_holding() {
        assert!(token_balances(&[reserve_output(A, 0)]).unwrap().is_empty());
        let held = token_balances(&[reserve_output(A, 0), reserve_output(B, 5)]).unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[&B], Amount::from_sat(5));
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
