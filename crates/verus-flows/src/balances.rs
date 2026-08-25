//! What an address holds, currency by currency — and what it is called.
//!
//! The counting itself is [`verus_tx::token_balances`], which is pure decoding
//! and needs no node. What this module adds is the two things that only make
//! sense with a chain in front of you: the split between spendable and immature
//! outputs, and friendly names.
//!
//! # Why this reads the outputs instead of asking
//!
//! `getaddressbalance` answers the question directly: it returns a
//! `currencybalance` map keyed by currency i-address, and
//! [`verus_rpc::AddressBalance`] models it. That is one request and it is the
//! obvious thing to reach for.
//!
//! It is not what [`Funding::token_balances`] uses, and the reason is not
//! distrust of any particular node. It is that deriving the figure from the
//! UTXOs costs **nothing extra** — [`crate::spendable`] has already fetched
//! them — so the cheaper-but-trusting option is not actually cheaper. What that
//! buys is a balance computed from the very outputs a transfer would spend, by
//! the same decoder that selects them: a number that agrees with what you can
//! actually spend, rather than one that agrees with what a server said.
//!
//! It also sidesteps two mismatches that make the node's figure awkward to use
//! as-is. `currencybalance` counts immature coinbase, so it is a holdings
//! figure and not a spendable one; and it repeats the chain's own currency
//! alongside the native `balance`, so a caller who sums the map double-counts.

use std::collections::BTreeMap;

use verus_rpc::{AddressUtxo, ChainReader};
use verus_tx::{token_balances, CurrencyId, TokenBalances, Utxo};

use crate::error::FlowError;
use crate::funding::Funding;

/// Count the tokens in outputs a node reported.
fn balances_of(
    found: &[AddressUtxo],
    native: Option<CurrencyId>,
) -> Result<TokenBalances, FlowError> {
    let utxos: Vec<Utxo> = found.iter().map(|f| f.utxo.clone()).collect();
    Ok(token_balances(&utxos, native)?)
}

/// The chain's own currency id.
///
/// One request, and worth making once and keeping: it never changes for a
/// given chain. [`Funding::token_balances`] needs it to tell the chain's own
/// currency apart from a token when an output names both, and a wallet
/// otherwise has no offline way to know which id that is.
///
/// Derived from the chain's name rather than read from `getcurrency`, because
/// a root chain's currency id *is* the id of its name — the same derivation
/// [`verus_tx::vdxf::root_namespace`] does offline. The request here is only
/// to learn which chain the node is on.
pub fn native_currency(reader: &impl ChainReader) -> Result<CurrencyId, FlowError> {
    let info = reader.chain_info()?;
    Ok(verus_tx::root_namespace(&info.name)?)
}

impl Funding {
    /// Tokens this address can spend right now.
    ///
    /// The token counterpart of [`Funding::total`], and kept apart from
    /// [`Funding::immature_token_balances`] for the same reason the native
    /// figures are: "you have 500 but can spend 20" is a fact a wallet has to
    /// be able to explain.
    ///
    /// Costs nothing — the outputs are already in hand.
    ///
    /// `native` is the chain's own currency id, from [`native_currency`], and
    /// `None` is a legitimate answer meaning "I do not know it". It is needed
    /// only for reserve deposits and transfers, which name the chain's own
    /// currency in their payload as well as carrying it as satoshis; without
    /// it those two are refused by name rather than double-counted. Nothing an
    /// ordinary address holds is affected either way.
    pub fn token_balances(&self, native: Option<CurrencyId>) -> Result<TokenBalances, FlowError> {
        balances_of(&self.other, native)
    }

    /// Tokens held in outputs that are **not currently spendable**.
    ///
    /// Named for coinbase maturity because that is the usual cause, but the
    /// bucket is wider than that: [`crate::spendable`] routes any output the
    /// node reports as unspendable here, whatever its age or script. So a
    /// token can legitimately appear, and a wallet showing only
    /// [`Funding::token_balances`] would be understating what its user owns.
    ///
    /// Note this can *fail* rather than come back empty, and an error here
    /// means "unknown", never zero. That is why it is a separate call from the
    /// spendable figure rather than folded into it: one bucket being
    /// uncountable must not take the other down with it.
    ///
    /// Coinbase outputs are the ones most likely to be unusual, and both usual
    /// shapes are fine — a proof-of-work coinbase pays P2PK and a
    /// proof-of-stake coinbase pays a stakeguard CryptoCondition, and neither
    /// can carry currency. See [`verus_tx::may_carry_currency`] for what is
    /// left that cannot be counted.
    pub fn immature_token_balances(
        &self,
        native: Option<CurrencyId>,
    ) -> Result<TokenBalances, FlowError> {
        balances_of(&self.immature, native)
    }
}

/// What [`currency_names`] found: the names it could read, and one reason for
/// each currency it could not.
///
/// A name for the pair, not a wrapper around it: this is the tuple, and
/// `let (names, _) = …` still compiles and still throws the failures away.
/// The alias exists so the signature stays readable and so this doc comment
/// has somewhere to live. What keeps a caller honest is the second half being
/// named in the return type at all, not the alias.
pub type CurrencyNames = (BTreeMap<CurrencyId, String>, Vec<(CurrencyId, FlowError)>);

/// Friendly names for currency ids, and a reason for each one that is missing.
///
/// Deliberately **not** folded into [`Funding::token_balances`]: this is one
/// request per currency, and a balance should not secretly cost a round trip
/// per token a user happens to hold. Call it when there is something to
/// display, and cache what it returns — a currency's name is fixed when it is
/// registered and cannot change, so the cache never needs invalidating.
///
/// # Why a second list rather than a failed lookup
///
/// A name is a per-currency answer, so a per-currency failure has to cost one
/// name and not the map. This used to abort on the first one it could not
/// read, which meant a wallet holding five tokens lost all five names because
/// of a fee field on one of them.
///
/// Aborting was not paranoia, though, and the rule behind it still holds: an
/// internal error, a bad parameter or a rate limit is **not** a statement about
/// the currency, and reading one as "unnamed" leaves a token showing as a bare
/// `i` address with nothing to say why. The second list keeps that rule and
/// serves it better than the abort did — the caller now learns *which* currency
/// it is missing and *what went wrong*, so it can show the names it has, say
/// why the rest are absent, and know not to write "this currency has no name"
/// into a cache that is never invalidated. One network blip no longer looks
/// like an address holding nothing but nameless currencies.
///
/// So exactly one answer is still left out in silence: the node saying it does
/// not know the currency. That one *is* a statement about the currency, and
/// there is nothing to report beyond the id the caller already has.
///
/// A node that answers about a **different** currency than the one asked for is
/// the opposite — a statement about the node — and goes in the error list.
/// Dropping it silently would let a confused or hostile node suppress a name
/// with nobody able to see that it had.
///
/// # The outer `Result`
///
/// It carries one thing and one thing only:
/// [`RpcError::AnswerNeeded`](verus_rpc::RpcError::AnswerNeeded), the sentinel
/// [`crate::drive`] uses to mean "stop, I still need an answer". That is not a
/// failure of this lookup, and no other error can come back this way. Folding
/// it into the per-currency list instead would tell a driver the work had
/// finished, and the caller would get an empty map for ever.
///
/// # Trust
///
/// The names come from the node and are displayed to a user. Verus names
/// permit far more than they look like they do, so treat a name as untrusted
/// display text: escape it, constrain it to one line, and do not let it
/// impersonate an address or a number. The id in the key is the part that
/// cannot lie, and this checks the node's answer against it.
pub fn currency_names(
    reader: &impl ChainReader,
    currencies: impl IntoIterator<Item = CurrencyId>,
) -> Result<CurrencyNames, FlowError> {
    // Every lookup is issued before any is inspected. The currencies are known
    // from the argument and none depends on another, so a `?`-shaped loop
    // would ask for them one at a time — and against the driver in
    // [`crate::drive`] that is one network round trip *per currency*. A wallet
    // naming sixteen tokens would exhaust the round budget and fail, which is
    // neither a bug in the driver nor in this function. Collect, then fold.
    let asked: Vec<(CurrencyId, String, Result<_, verus_rpc::RpcError>)> = currencies
        .into_iter()
        .map(|currency| {
            let address =
                verus_keys::Address::new(verus_keys::AddressKind::Identity, currency.to_bytes())
                    .to_string();
            let answer = reader.currency(&address);
            (currency, address, answer)
        })
        .collect();

    let mut names = BTreeMap::new();
    let mut unreadable = Vec::new();
    for (currency, address, answer) in asked {
        match answer {
            Ok(policy) if policy.currency_id == address => {
                names.insert(currency, policy.name);
            }
            // Free consistency check: a node that answers about a different
            // currency than the one asked for is confused or hostile, and
            // either way its answer is not a name for this token. Reported
            // rather than dropped, because a name withheld by a hostile node
            // must not be indistinguishable from a name that was never
            // registered. Spelled the way `history` spells the same shape of
            // disagreement: the node pointed somewhere other than where it was
            // asked to look.
            Ok(policy) => unreadable.push((
                currency,
                FlowError::Rpc(verus_rpc::RpcError::Unexpected(format!(
                    "asked getcurrency about {address} but the answer describes {} — refusing \
                     to use it as that currency's name",
                    policy.currency_id
                ))),
            )),
            // The node answered, and its answer was "no such currency".
            // `getcurrency` spells that `-8` ("Invalid currency or currency
            // not found"); `-5` is the identity code, tolerated alongside it
            // because `crate::error::absent_is_none` reads it the same way for
            // identities and a node reusing it here would mean the same thing.
            // Everything else the node could say is a statement about the
            // node, and lands in `unreadable` with its reason attached.
            //
            // Matched on the code alone. `-8` is generic in the bitcoind
            // lineage this inherits from, so in principle it could arrive
            // meaning something else — but `getcurrency` answers a malformed
            // argument with `-1` and a help string (`fixtures/rpc/err_badparam.json`),
            // and the argument here is an i-address this function builds
            // itself, so there is no caller input that could provoke one.
            Err(verus_rpc::RpcError::Node { code: -8 | -5, .. }) => {}
            // Not an outcome for this currency at all: the driver's "ask me
            // again once you have fetched what I recorded". Every lookup was
            // already issued above, so the record is complete and stopping
            // here costs nothing.
            Err(error @ verus_rpc::RpcError::AnswerNeeded) => return Err(error.into()),
            Err(error) => unreadable.push((currency, error.into())),
        }
    }
    Ok((names, unreadable))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spendable;
    use crate::testing::ScriptedReader;
    use verus_tx::Amount;

    const ADDRESS: &str = "RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX";

    /// `ScriptedReader::with_reserve_utxo` builds this currency.
    const TOKEN: CurrencyId = CurrencyId::from_bytes([0x22; 20]);

    /// A second currency, so a *mixed* answer can be asserted.
    const OTHER: CurrencyId = CurrencyId::from_bytes([0x33; 20]);

    /// The i-address `currency_names` looks a currency up by.
    fn i_address(currency: CurrencyId) -> String {
        verus_keys::Address::new(verus_keys::AddressKind::Identity, currency.to_bytes()).to_string()
    }

    /// **The method must read the outputs that hold tokens.** Reading the
    /// wrong set — `immature` rather than `other` — returns an empty map for
    /// every real address, and nothing else in the workspace notices.
    #[test]
    fn spendable_tokens_come_from_the_outputs_that_hold_them() {
        let node = ScriptedReader::new(1_000)
            .with_utxo(ADDRESS, 900, 5_000_000)
            .with_reserve_utxo(ADDRESS, 900);
        let funding = spendable(&node, ADDRESS).unwrap();

        assert_eq!(funding.utxos.len(), 1, "the native output funds a send");
        assert_eq!(funding.other.len(), 1, "the reserve output does not");

        let held = funding.token_balances(None).unwrap();
        assert_eq!(
            held.get(&TOKEN),
            Some(&Amount::from_sat(1_000_000)),
            "the token the address holds must be counted"
        );
        assert!(
            funding.immature_token_balances(None).unwrap().is_empty(),
            "nothing here is immature"
        );
    }

    /// And the two buckets must not be the same bucket: a token in an
    /// unspendable output is reported by the immature method and *not* by the
    /// spendable one, or "you have 500 but can spend 20" cannot be said.
    #[test]
    fn an_unspendable_token_is_reported_separately_and_not_as_spendable() {
        let node = ScriptedReader::new(1_000)
            .with_utxo(ADDRESS, 990, 5_000_000)
            .with_reserve_utxo(ADDRESS, 990)
            .with_coinbase_at(990);
        let funding = spendable(&node, ADDRESS).unwrap();

        assert!(
            funding.token_balances(None).unwrap().is_empty(),
            "an immature token is not spendable"
        );
        assert_eq!(
            funding.immature_token_balances(None).unwrap().get(&TOKEN),
            Some(&Amount::from_sat(1_000_000)),
            "and it must still be reported somewhere, or it vanishes"
        );
    }

    /// **A staker must get a balance.** A proof-of-stake coinbase pays its
    /// first output to a stakeguard CryptoCondition, and this used to make the
    /// whole set uncountable — so an address that had staked once got an error
    /// where it wanted a number, in the immature bucket where a fresh stake
    /// always lands.
    ///
    /// The script is a real one: block 1170103 on VRSCTEST, coinbase vout 0.
    #[test]
    fn a_stakers_immature_coinbase_does_not_make_their_tokens_uncountable() {
        let stakeguard = hex::decode(
            "3d04030001021504d72c764548836ae9e1784b54afed2c1f1061bd532103166b7813a4855a88e9ef7\
             340a692ef3c2decedfdc2c7563ec79537e89667d935cc4c8704030101011504d72c764548836ae9e17\
             84b54afed2c1f1061bd5343010000a659dcb60845f0ea2f48a9a5513cd90ab986fd670d8644f52fcc1\
             53478260efdd114a32487649aababf8c747cb6733b6c69da63362cd6f226fead87401000000270403\
             0101012103166b7813a4855a88e9ef7340a692ef3c2decedfdc2c7563ec79537e89667d93575"
                .replace(['\n', ' '], "")
                .as_str(),
        )
        .expect("a real stakeguard script");
        let node = ScriptedReader::new(1_000)
            .with_script_utxo(ADDRESS, 990, 600_000_000, stakeguard)
            .with_reserve_utxo(ADDRESS, 990)
            .with_coinbase_at(990);
        let funding = spendable(&node, ADDRESS).unwrap();

        assert_eq!(
            funding
                .immature_token_balances(None)
                .expect("a staker's holdings must be countable")
                .get(&TOKEN),
            Some(&Amount::from_sat(1_000_000)),
            "the stakeguard output must not take the token count down with it"
        );
    }

    /// **A VerusID's holdings.** `getaddressutxos` answers for an i-address,
    /// and what comes back is reserve outputs paying that identity. Reading
    /// them is the whole reason a wallet can show what an identity owns.
    #[test]
    fn tokens_held_by_an_identity_are_reported() {
        let identity = verus_keys::Address::new(verus_keys::AddressKind::Identity, [0x5a; 20]);
        let script = verus_tx::cc::reserve_output_script_to(
            verus_tx::Destination::Identity([0x5a; 20]),
            TOKEN,
            4_200_000,
        )
        .expect("reserve script");
        let node =
            ScriptedReader::new(1_000).with_script_utxo(&identity.to_string(), 900, 0, script);
        let funding = spendable(&node, &identity.to_string()).unwrap();

        assert_eq!(
            funding.token_balances(None).expect("countable").get(&TOKEN),
            Some(&Amount::from_sat(4_200_000))
        );
    }

    #[test]
    fn an_address_with_no_tokens_reports_none() {
        let node = ScriptedReader::new(1_000).with_utxo(ADDRESS, 900, 5_000_000);
        let funding = spendable(&node, ADDRESS).unwrap();
        assert!(funding.token_balances(None).unwrap().is_empty());
    }

    /// A name is looked up by the currency's own i-address and must be the
    /// name, not the id echoed back.
    #[test]
    fn a_name_is_resolved_for_the_currency_that_was_asked_about() {
        let id = i_address(TOKEN);
        let node = ScriptedReader::new(1_000).with_policy(verus_rpc::CurrencyPolicy {
            currency_id: id.clone(),
            name: "sometoken".into(),
            ..policy()
        });
        let (names, unreadable) = currency_names(&node, [TOKEN]).unwrap();
        assert_eq!(names.get(&TOKEN).map(String::as_str), Some("sometoken"));
        assert_ne!(names[&TOKEN], id, "the id is not a name");
        assert!(unreadable.is_empty(), "nothing failed: {unreadable:?}");
    }

    /// **The amplifier this shape exists to remove.** One currency that cannot
    /// be read costs exactly one name; every other name still comes back. The
    /// old signature returned `Err` here, so a wallet holding two tokens got
    /// zero names because of a fee field on one of them — and holding five, it
    /// lost five.
    #[test]
    fn an_unreadable_currency_costs_its_own_name_and_no_other() {
        let readable = i_address(TOKEN);
        let node = ScriptedReader::new(1_000)
            .with_policy_for(
                &readable,
                verus_rpc::CurrencyPolicy {
                    currency_id: readable.clone(),
                    name: "sometoken".into(),
                    ..policy()
                },
            )
            // The real trigger: a currency whose fee fields the daemon reports
            // in a shape that cannot be read exactly.
            .with_currency_failure(
                &i_address(OTHER),
                verus_rpc::RpcError::LossyNumber {
                    field: "idregistrationfees",
                    value: "1e-8".into(),
                },
            );

        let (names, unreadable) = currency_names(&node, [TOKEN, OTHER]).unwrap();

        assert_eq!(
            names.get(&TOKEN).map(String::as_str),
            Some("sometoken"),
            "the readable currency must keep its name"
        );
        assert!(
            !names.contains_key(&OTHER),
            "and the unreadable one must not acquire one"
        );
        assert_eq!(
            unreadable.len(),
            1,
            "exactly one lookup failed: {unreadable:?}"
        );
        assert_eq!(unreadable[0].0, OTHER, "and it must say which one");
        assert!(
            matches!(
                unreadable[0].1,
                FlowError::Rpc(verus_rpc::RpcError::LossyNumber { .. })
            ),
            "the reason must survive intact, or the caller cannot say why the \
             name is missing: {:?}",
            unreadable[0].1
        );
    }

    /// A currency the node says it does not have is left out **in silence** —
    /// no entry in the error list. That answer is a statement about the
    /// currency, and there is nothing to report beyond the id the caller
    /// already holds. `-8` is what `getcurrency` actually sends.
    #[test]
    fn a_currency_the_node_does_not_know_is_left_out_without_a_reason() {
        for code in [-8, -5] {
            let node = ScriptedReader::new(1_000).with_currency_failure(
                &i_address(TOKEN),
                verus_rpc::RpcError::Node {
                    code,
                    message: "Invalid currency or currency not found".into(),
                },
            );
            let (names, unreadable) = currency_names(&node, [TOKEN]).unwrap();
            assert!(names.is_empty(), "{code} names nothing");
            assert!(
                unreadable.is_empty(),
                "{code} is an answer about the currency, not a failure: {unreadable:?}"
            );
        }
    }

    /// The driver's sentinel is **not** a per-currency outcome. It has to come
    /// back through the outer `Result`, or [`crate::drive::advance`] sees an
    /// `Ok` with an empty map, marks the operation finished, and never fetches
    /// the answers it recorded — a caller left with no names for ever.
    #[test]
    fn an_answer_still_needed_is_not_reported_as_a_currencys_failure() {
        let node = ScriptedReader::new(1_000)
            .with_currency_failure(&i_address(TOKEN), verus_rpc::RpcError::AnswerNeeded);

        assert!(
            matches!(
                currency_names(&node, [TOKEN]),
                Err(FlowError::Rpc(verus_rpc::RpcError::AnswerNeeded))
            ),
            "the sentinel must escape rather than be collected"
        );
    }

    /// A node that answers about a different currency than the one asked for
    /// is confused or hostile; either way its answer is not this token's name.
    /// It is reported rather than dropped, or such a node could suppress a
    /// name and look exactly like a currency that never had one.
    #[test]
    fn an_answer_about_a_different_currency_is_reported_not_used_as_a_name() {
        let node = ScriptedReader::new(1_000).with_policy(verus_rpc::CurrencyPolicy {
            currency_id: verus_keys::Address::new(verus_keys::AddressKind::Identity, [0x99; 20])
                .to_string(),
            name: "somethingelse".into(),
            ..policy()
        });

        let (names, unreadable) = currency_names(&node, [TOKEN]).unwrap();

        assert!(names.is_empty(), "the wrong currency's name is not a name");
        assert_eq!(
            unreadable.len(),
            1,
            "and the caller must be told: {unreadable:?}"
        );
        assert_eq!(unreadable[0].0, TOKEN);
        let said = unreadable[0].1.to_string();
        assert!(
            said.contains(&i_address(TOKEN))
                && said.contains(&i_address(CurrencyId::from_bytes([0x99; 20]))),
            "the message names what was asked and what came back: {said}"
        );
    }

    fn policy() -> verus_rpc::CurrencyPolicy {
        verus_rpc::CurrencyPolicy {
            currency_id: String::new(),
            name: String::new(),
            id_registration_fee: Amount::ZERO,
            id_referral_levels: 0,
            id_import_fee: Amount::ZERO,
            currency_registration_fee: Amount::ZERO,
            proof_protocol: 1,
        }
    }
}
