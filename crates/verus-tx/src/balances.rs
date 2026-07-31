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
//! named: the outpoint is in the error, so a caller who knows an output is
//! harmless can drop it and count the rest.
//!
//! # …but "cannot read" is a much smaller set than it looks
//!
//! Failing closed has a price, and paying it where nothing is bought is not
//! caution, it is a gap. Three shapes this crate cannot *spend* are counted
//! anyway, because each provably holds no currency:
//!
//! * A **proof-of-work coinbase** pays P2PK. There is nowhere in that script
//!   for a payload to live.
//! * A **proof-of-stake coinbase** pays its first output to a stakeguard
//!   CryptoCondition (eval code 1). The chain's own
//!   `CScript::ReserveOutValue` reads currency out of five eval codes and
//!   stakeguard is not one of them — so it is undecodable and tokenless, and
//!   refusing it would have made a balance impossible for every staker.
//!   [`crate::may_carry_currency`] is where that list lives.
//! * The same goes for notarizations, finalizations, currency definitions and
//!   identity outputs.
//!
//! **Tokens held by a VerusID** are counted too, and that one is not a
//! proof-of-absence but a proof-of-presence: they are ordinary reserve outputs
//! whose destination happens to be an identity, and the decoder now reads the
//! destination kind instead of insisting on a key hash.
//!
//! **Several currencies in one output** are counted, and **name commitments**
//! are read rather than refused. Both were invisible until the two fixes above
//! landed — everything an ordinary address holds was being refused for other
//! reasons first, so nothing had ever reached them.
//!
//! **Reserve deposits and reserve transfers** are counted too, given `native`
//! — see below. They are the two shapes that name the chain's own currency in
//! their payload while also carrying it as satoshis, so counting them without
//! knowing which currency that is would report the same money twice.
//!
//! # What is genuinely still uncountable
//!
//! One eval code: `EVAL_CROSSCHAIN_IMPORT` (13). It holds currency, and the
//! chain itself says the amount "cannot be calculated in isolation as an
//! input" — so it is not a decoding gap that could be closed by reading harder.
//! See [`crate::may_carry_currency`].

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

/// Why a reserve deposit or transfer cannot be counted without `native`.
const NEEDS_NATIVE: &str = "it is a reserve deposit or transfer, which names the chain's own \
     currency in its payload as well as carrying it as satoshis; pass the chain's currency id as \
     `native` so that part can be left out instead of counted twice";

/// Sum the token value carried by `utxos`.
///
/// Native satoshis are ignored — a reserve output carries native value *as well
/// as* its payload, and that part belongs to the native total, not to the token.
///
/// `utxos` must hold each outpoint at most once: this sums what it is given and
/// cannot tell a genuine second output from the same one listed twice, so a
/// caller concatenating paged results should deduplicate first.
///
/// # `native`
///
/// The chain's own currency id — `VRSCTEST`'s, `VRSC`'s, or a PBaaS chain's —
/// or `None` if the caller does not know it.
///
/// Two output shapes need it and no other does. A reserve deposit and a
/// reserve transfer both name the chain's own currency **inside their
/// payload**, for the chain's accounting, while carrying that same value as
/// ordinary satoshis in the output. `CScript::ReserveOutValue` erases it
/// before returning, and so does this: counting it would report the same money
/// twice, once as native and once as a token. On both real VRSCTEST vectors
/// this crate tests against, the erase is what takes the answer to empty.
///
/// Passing `None` is not a shortcut — it refuses those two shapes by name
/// rather than guessing, which is exactly what this function did before it
/// could decode them at all. Everything else is counted either way.
///
/// [`crate::vdxf::root_namespace`] derives the id from a chain's name offline,
/// and `getcurrency` returns it.
pub fn token_balances(
    utxos: &[Utxo],
    native: Option<CurrencyId>,
) -> Result<TokenBalances, TxError> {
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
            // A commitment is one of the five kinds consensus reads currency
            // out of, so its tokens are counted rather than assumed away. In
            // practice the list is empty for every ordinary one — only the
            // advanced form carries anything.
            OutputKind::ReserveOutput { tokens, .. }
            | OutputKind::IdentityCommitment { tokens, .. } => tokens,
            // The two shapes that name the chain's own currency in their
            // payload while also carrying it as satoshis. Countable only with
            // `native` in hand; refused by name without it, which is what this
            // function did for them before it could read them at all.
            OutputKind::ReserveDeposit { tokens, .. } => {
                let Some(native) = native else {
                    return Err(uncountable(NEEDS_NATIVE.into()));
                };
                tokens
                    .into_iter()
                    .filter(|(currency, _)| *currency != native)
                    .collect()
            }
            OutputKind::ReserveTransfer { transfer, .. } => {
                let Some(native) = native else {
                    return Err(uncountable(NEEDS_NATIVE.into()));
                };
                transfer
                    .reserve_value(native)
                    .map_err(|error| uncountable(error.to_string()))?
            }
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
            // An eval code this crate cannot decode, but which the chain's own
            // `CScript::ReserveOutValue` never reads currency out of — a
            // stakeguard, a notarization, a currency definition. Undecodable
            // *and* provably tokenless, so refusing it would fail closed
            // against nothing while making a balance impossible for anyone who
            // has staked. See [`crate::may_carry_currency`].
            OutputKind::UnsupportedCryptoCondition {
                may_carry_currency: false,
                ..
            } => continue,
            OutputKind::UnsupportedCryptoCondition { eval_code, .. } => {
                return Err(uncountable(format!(
                    "it is a CryptoCondition with eval code {eval_code}, which can carry \
                     currency and which this crate cannot decode"
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
        assert!(token_balances(&[native()], None).unwrap().is_empty());
    }

    #[test]
    fn balances_accumulate_across_outputs_and_currencies() {
        let held = token_balances(
            &[
                native(),
                reserve_output(A, 100),
                reserve_output(A, 250),
                reserve_output(B, 7),
            ],
            None,
        )
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
        assert_eq!(
            token_balances(&[utxo], None).unwrap()[&A],
            Amount::from_sat(100)
        );
    }

    /// **Why this is fallible.** The decoder reports an unreadable
    /// CryptoCondition as a value, not an error, so a `continue` here would
    /// silently drop whatever it carries.
    ///
    /// Eval code 13 is `EVAL_CROSSCHAIN_IMPORT`, the last of the five the
    /// chain's own `CScript::ReserveOutValue` reads currency out of that this
    /// crate still does not decode. That is what makes it the right shape for
    /// this test: an output that genuinely could be hiding a token.
    ///
    /// It used to be eval 11. Eval 11 became decodable, and the test had to
    /// move rather than be deleted — the property is "an undecoded
    /// currency-bearing shape refuses the balance", and it stays true as long
    /// as any such shape is left.
    #[test]
    fn an_unreadable_output_that_could_hold_currency_is_refused_not_counted_as_nothing() {
        let utxo = Utxo {
            txid: Txid::from_internal([0x55; 32]),
            vout: 3,
            satoshis: Amount::from_sat(1),
            script_pubkey: cc::cc_script(
                &cc::OptCcParams::one_of_one(
                    crate::currency_launch::EVAL_CROSSCHAIN_IMPORT,
                    Destination::PubKeyHash([0x44; 20]),
                ),
                &cc::OptCcParams::one_of_one(
                    crate::currency_launch::EVAL_CROSSCHAIN_IMPORT,
                    Destination::PubKeyHash([0x44; 20]),
                ),
            )
            .unwrap(),
        };
        match token_balances(&[reserve_output(A, 100), utxo], None) {
            Err(TxError::UncountableOutput { txid, vout, reason }) => {
                // Named, or a wallet cannot tell a user which output to look at.
                assert!(txid.starts_with("5555"), "{txid}");
                assert_eq!(vout, 3);
                assert!(
                    reason.contains("13"),
                    "the eval code must be named: {reason}"
                );
            }
            other => panic!("an unreadable output must not read as zero: {other:?}"),
        }
    }

    /// And the refusal must be **narrow**. Every eval code the chain never
    /// reads currency out of has to be countable, or the balance is refused
    /// for a notarization, a currency definition, an identity reservation —
    /// shapes an ordinary address meets all the time.
    ///
    /// Pinned against [`crate::may_carry_currency`] directly rather than
    /// against a list copied into the test: two copies of the list would agree
    /// with each other and with nothing else.
    #[test]
    fn only_the_eval_codes_that_can_hold_currency_refuse_a_balance() {
        let mut refused = Vec::new();
        for eval_code in 1..=0x1au8 {
            let script = cc::cc_script(
                &cc::OptCcParams::one_of_one(eval_code, Destination::PubKeyHash([0x44; 20])),
                &cc::OptCcParams::one_of_one(eval_code, Destination::PubKeyHash([0x44; 20])),
            )
            .unwrap();
            // Identity outputs (14) and plain reserve outputs (9) decode into
            // their own kinds and are not what this is about.
            if !matches!(
                decode_output_script(&script),
                Ok(OutputKind::UnsupportedCryptoCondition { .. })
            ) {
                continue;
            }
            let utxo = Utxo {
                txid: Txid::from_internal([0x66; 32]),
                vout: 0,
                satoshis: Amount::from_sat(1),
                script_pubkey: script,
            };
            let counted = token_balances(&[utxo], None).is_ok();
            assert_eq!(
                counted,
                !crate::may_carry_currency(eval_code),
                "eval code {eval_code} is counted={counted} but may_carry_currency says otherwise"
            );
            if !counted {
                refused.push(eval_code);
            }
        }
        assert!(
            !refused.is_empty(),
            "nothing was refused, so this test proves nothing"
        );
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
        let held = token_balances(&[utxo, reserve_output(A, 100)], None)
            .expect("a miner must still be able to see their tokens");
        assert_eq!(held[&A], Amount::from_sat(100));
        assert_eq!(held.len(), 1, "a P2PK output contributes no currency");
    }

    /// **A proof-of-stake coinbase pays a stakeguard CryptoCondition**, and
    /// this crate still cannot decode its payload — but it does not have to.
    /// `CScript::ReserveOutValue` never reads currency out of eval code 1, so
    /// the output is provably tokenless and counting it as zero loses nothing.
    ///
    /// This test used to assert the opposite: that a staker got a refusal
    /// naming the output. That was honest but it was also a wall — an address
    /// that had staked once could not be given a balance at all. The refusal
    /// is now narrowed to the eval codes that could actually be hiding
    /// something, which is what `only_the_eval_codes_that_can_hold_currency…`
    /// above pins.
    ///
    /// The script is a real one: block 1170103 on VRSCTEST, coinbase vout 0.
    #[test]
    fn a_stakeguard_output_is_counted_as_tokenless_rather_than_refusing_the_balance() {
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
        // Decoded, but only as far as its eval code — the payload is still
        // opaque, which is the whole point: countable without being readable.
        assert_eq!(
            decode_output_script(&utxo.script_pubkey).unwrap(),
            OutputKind::UnsupportedCryptoCondition {
                eval_code: 1,
                may_carry_currency: false,
            }
        );

        let held = token_balances(&[utxo, reserve_output(A, 100)], None)
            .expect("a staker must still be able to see their tokens");
        assert_eq!(held[&A], Amount::from_sat(100));
        assert_eq!(
            held.len(),
            1,
            "a stakeguard output contributes no currency of its own"
        );
    }

    /// **Tokens held by a VerusID.** A reserve output whose destination is an
    /// identity is what a mint pays and what an identity-owned balance is made
    /// of. The decoder used to refuse it — `a reserve output paying
    /// Identity(…) is not decoded yet` — which made an i-address's holdings
    /// uncountable even though the payload was in plain sight and the
    /// encoder in `cc.rs` had been writing that exact shape all along.
    #[test]
    fn a_reserve_output_held_by_an_identity_is_counted() {
        let identity = [0x5a; 20];
        let script =
            cc::reserve_output_script_to(Destination::Identity(identity), A, 250_000_000).unwrap();
        assert_eq!(
            decode_output_script(&script).unwrap(),
            OutputKind::ReserveOutput {
                destination: Destination::Identity(identity),
                tokens: vec![(A, 250_000_000)],
            },
            "the destination kind must survive decoding, or the output names an \
             R address nobody controls"
        );

        let utxo = Utxo {
            txid: Txid::from_internal([0xab; 32]),
            vout: 1,
            satoshis: Amount::from_sat(0),
            script_pubkey: script,
        };
        assert_eq!(
            token_balances(&[utxo], None).expect("an identity's tokens are countable")[&A],
            Amount::from_sat(250_000_000)
        );
    }

    /// Every refusal must name the output, not only the one that has a
    /// dedicated variant. A decoder error carries no outpoint of its own, so a
    /// wallet told "unsupported TokenOutput version 2147483649" could not say
    /// which of forty outputs to go and look at.
    #[test]
    fn a_decoder_failure_is_reported_against_the_output_that_caused_it() {
        let utxo = Utxo {
            txid: Txid::from_internal([0x88; 32]),
            vout: 9,
            satoshis: Amount::from_sat(1),
            // A CryptoCondition prefix with nothing decodable after it.
            script_pubkey: vec![0x4c, 0x0f, 0xcc],
        };
        match token_balances(&[utxo], None) {
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
            token_balances(&[huge, more], None),
            Err(TxError::ValueOverflow)
        ));
        // One output at the ceiling is reported, not refused.
        assert_eq!(
            token_balances(&[reserve_output(A, u64::MAX)], None).unwrap()[&A],
            Amount::from_sat(u64::MAX)
        );
    }

    /// A zero-value token entry is not a holding, and printing "0 SOMETOKEN"
    /// for a currency a user does not have is noise.
    #[test]
    fn a_zero_amount_does_not_create_a_holding() {
        assert!(token_balances(&[reserve_output(A, 0)], None)
            .unwrap()
            .is_empty());
        let held = token_balances(&[reserve_output(A, 0), reserve_output(B, 5)], None).unwrap();
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
        assert!(token_balances(&[utxo], None).unwrap().is_empty());
    }
}
