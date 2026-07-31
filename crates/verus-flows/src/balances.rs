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

    /// Tokens held in outputs that are not yet spendable.
    ///
    /// Expected to be empty, and checked anyway. Only coinbase outputs can be
    /// immature and coinbase outputs are native, so a token appearing here
    /// would mean an assumption in [`crate::spendable`] had stopped holding —
    /// which is exactly the moment a wallet should not be quietly reporting a
    /// smaller balance than the chain shows.
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
/// A currency the node will not resolve is left out rather than failing the
/// lookup: a missing *name* is a display problem, and it must not stop a wallet
/// reporting a balance it already knows.
pub fn currency_names(
    reader: &impl ChainReader,
    currencies: impl IntoIterator<Item = CurrencyId>,
) -> BTreeMap<CurrencyId, String> {
    let mut names = BTreeMap::new();
    for currency in currencies {
        let address =
            verus_keys::Address::new(verus_keys::AddressKind::Identity, currency.to_bytes())
                .to_string();
        if let Ok(policy) = reader.currency(&address) {
            names.insert(currency, policy.name);
        }
    }
    names
}
