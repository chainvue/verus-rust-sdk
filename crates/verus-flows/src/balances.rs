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
fn balances_of(found: &[AddressUtxo]) -> Result<TokenBalances, FlowError> {
    let utxos: Vec<Utxo> = found.iter().map(|f| f.utxo.clone()).collect();
    Ok(token_balances(&utxos)?)
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
    pub fn token_balances(&self) -> Result<TokenBalances, FlowError> {
        balances_of(&self.other)
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
    pub fn immature_token_balances(&self) -> Result<TokenBalances, FlowError> {
        balances_of(&self.immature)
    }
}

/// Friendly names for currency ids.
///
/// Deliberately **not** folded into [`Funding::token_balances`]: this is one
/// request per currency, and a balance should not secretly cost a round trip
/// per token a user happens to hold. Call it when there is something to
/// display, and cache what it returns — a currency's name is fixed when it is
/// registered and cannot change, so the cache never needs invalidating.
///
/// A currency the **node** says it does not know is left out rather than
/// failing the lookup: a missing name is a display problem, and it must not
/// stop a wallet reporting a balance it already knows.
///
/// A node that could not be *reached*, though, is an error. The two used to be
/// treated alike, and that is worse than it sounds given the advice to cache:
/// one network blip would have written "this currency has no name" into a
/// cache that is never invalidated, and an unreachable node would have been
/// indistinguishable from an address holding nothing but unknown currencies.
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
) -> Result<BTreeMap<CurrencyId, String>, FlowError> {
    let mut names = BTreeMap::new();
    for currency in currencies {
        let address =
            verus_keys::Address::new(verus_keys::AddressKind::Identity, currency.to_bytes())
                .to_string();
        match reader.currency(&address) {
            Ok(policy) => {
                // Free consistency check: a node that answers about a
                // different currency than the one asked for is confused or
                // hostile, and either way its answer is not a name for this
                // token.
                if policy.currency_id == address {
                    names.insert(currency, policy.name);
                }
            }
            // The node answered, and its answer was "no such currency".
            Err(verus_rpc::RpcError::Node { .. }) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(names)
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

        let held = funding.token_balances().unwrap();
        assert_eq!(
            held.get(&TOKEN),
            Some(&Amount::from_sat(1_000_000)),
            "the token the address holds must be counted"
        );
        assert!(
            funding.immature_token_balances().unwrap().is_empty(),
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
            funding.token_balances().unwrap().is_empty(),
            "an immature token is not spendable"
        );
        assert_eq!(
            funding.immature_token_balances().unwrap().get(&TOKEN),
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
                .immature_token_balances()
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
            funding.token_balances().expect("countable").get(&TOKEN),
            Some(&Amount::from_sat(4_200_000))
        );
    }

    #[test]
    fn an_address_with_no_tokens_reports_none() {
        let node = ScriptedReader::new(1_000).with_utxo(ADDRESS, 900, 5_000_000);
        let funding = spendable(&node, ADDRESS).unwrap();
        assert!(funding.token_balances().unwrap().is_empty());
    }

    /// A name is looked up by the currency's own i-address and must be the
    /// name, not the id echoed back.
    #[test]
    fn a_name_is_resolved_for_the_currency_that_was_asked_about() {
        let id = verus_keys::Address::new(verus_keys::AddressKind::Identity, TOKEN.to_bytes())
            .to_string();
        let node = ScriptedReader::new(1_000).with_policy(verus_rpc::CurrencyPolicy {
            currency_id: id.clone(),
            name: "sometoken".into(),
            ..policy()
        });
        let names = currency_names(&node, [TOKEN]).unwrap();
        assert_eq!(names.get(&TOKEN).map(String::as_str), Some("sometoken"));
        assert_ne!(names[&TOKEN], id, "the id is not a name");
    }

    /// A node that answers about a different currency than the one asked for
    /// is confused or hostile; either way its answer is not this token's name.
    #[test]
    fn an_answer_about_a_different_currency_is_not_used_as_a_name() {
        let node = ScriptedReader::new(1_000).with_policy(verus_rpc::CurrencyPolicy {
            currency_id: verus_keys::Address::new(verus_keys::AddressKind::Identity, [0x99; 20])
                .to_string(),
            name: "somethingelse".into(),
            ..policy()
        });
        assert!(currency_names(&node, [TOKEN]).unwrap().is_empty());
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
