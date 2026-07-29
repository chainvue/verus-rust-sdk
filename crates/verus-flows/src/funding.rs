//! Finding coins that can actually be spent right now.
//!
//! `getaddressutxos` reports what an address owns. That is not the same as what
//! it can spend: a coinbase output needs 100 confirmations, and one that has not
//! matured builds and signs perfectly before the daemon answers
//! `bad-txns-premature-spend-of-coinbase`. The whole cost of that mistake lands
//! after the work is done.
//!
//! # Only the young are suspect
//!
//! Telling a coinbase from an ordinary output needs the transaction that created
//! it, which is a round trip each. Doing that for every UTXO would make funding
//! a wallet with a hundred outputs a hundred requests.
//!
//! It is also unnecessary. An output with 100 or more confirmations is spendable
//! *whether or not* it is a coinbase, so its origin does not matter. Only
//! outputs younger than that can be immature, and there are rarely many. So this
//! checks exactly those and leaves the rest alone.

use verus_rpc::{AddressUtxo, ChainReader, COINBASE_MATURITY};
use verus_tx::{Amount, Utxo};

use crate::error::FlowError;

/// Spendable coins at an address, and the height they were assessed at.
#[derive(Clone, Debug)]
pub struct Funding {
    /// Outputs that can be spent now, ready for a builder.
    pub utxos: Vec<Utxo>,
    /// The chain tip this was decided against.
    pub tip: u32,
    /// The sum of [`Funding::utxos`].
    pub total: Amount,
    /// Outputs excluded because they are coinbase and not yet mature.
    ///
    /// Reported rather than silently dropped: "you have 500 but can spend 20"
    /// is a fact a wallet needs to be able to explain to a user.
    pub immature: Vec<AddressUtxo>,
}

impl Funding {
    /// The value sitting in immature coinbase outputs.
    pub fn immature_total(&self) -> Amount {
        Amount::checked_sum(self.immature.iter().map(|found| found.utxo.satoshis))
            .unwrap_or(Amount::ZERO)
    }
}

/// Gather what `address` can spend at the current tip.
///
/// Costs two requests, plus one per output younger than
/// [`COINBASE_MATURITY`] — see the module docs for why that is the right
/// number and not one per output.
pub fn spendable(reader: &impl ChainReader, address: &str) -> Result<Funding, FlowError> {
    let tip = reader.block_count()?;
    let found = reader.address_utxos(&[address])?;

    // Only an output that could still be immature is worth a round trip.
    let mut coinbase_heights = Vec::new();
    for utxo in &found {
        if utxo.confirmations(tip) >= COINBASE_MATURITY {
            continue;
        }
        if is_coinbase(reader, &utxo.utxo.txid.to_display_hex())? {
            coinbase_heights.push(utxo.height);
        }
    }

    let utxos = verus_rpc::spendable_at(&found, tip, &coinbase_heights);
    let spendable_outpoints: Vec<_> = utxos.iter().map(|u| (u.txid, u.vout)).collect();
    let immature = found
        .into_iter()
        .filter(|found| !spendable_outpoints.contains(&(found.utxo.txid, found.utxo.vout)))
        .collect();

    let total = Amount::checked_sum(utxos.iter().map(|u| u.satoshis)).ok_or_else(|| {
        FlowError::NotReady("the address holds more than can be represented".into())
    })?;

    Ok(Funding {
        utxos,
        tip,
        total,
        immature,
    })
}

/// Whether a transaction is a coinbase.
///
/// A coinbase has exactly one input and that input has a `coinbase` field
/// instead of an outpoint. Checked positively — an unrecognised shape is
/// treated as *not* coinbase, because the alternative is refusing to spend
/// ordinary money whenever a daemon changes how it prints an input.
fn is_coinbase(reader: &impl ChainReader, txid: &str) -> Result<bool, FlowError> {
    let tx = reader.raw_transaction(txid)?;
    Ok(tx["vin"]
        .as_array()
        .and_then(|vin| vin.first())
        .is_some_and(|input| input.get("coinbase").is_some()))
}

/// Refuse early when there is plainly not enough to work with.
///
/// The builder would refuse too, but only after selecting and estimating. This
/// produces the message a user can act on, and names the immature portion when
/// that is what makes the difference.
pub fn require(funding: &Funding, needed: Amount, address: &str) -> Result<(), FlowError> {
    if funding.total >= needed {
        return Ok(());
    }
    Err(FlowError::InsufficientFunds {
        needed,
        available: funding.total,
        address: address.to_string(),
        utxos: funding.utxos.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::ScriptedReader;

    #[test]
    fn sums_what_can_be_spent() {
        let reader = ScriptedReader::new(1_000)
            .with_utxo("R1", 100, 5_000_000)
            .with_utxo("R1", 200, 3_000_000);
        let funding = spendable(&reader, "R1").unwrap();
        assert_eq!(funding.utxos.len(), 2);
        assert_eq!(funding.total.to_sat(), 8_000_000);
        assert_eq!(funding.tip, 1_000);
        assert!(funding.immature.is_empty());
    }

    /// The case this module exists for. The coins are there; they cannot be
    /// spent; and a wallet has to be able to say which is which.
    #[test]
    fn an_immature_coinbase_is_excluded_and_reported() {
        let reader = ScriptedReader::new(1_000)
            .with_utxo("R1", 950, 5_000_000)
            .with_coinbase_at(950)
            .with_utxo("R1", 100, 3_000_000);

        let funding = spendable(&reader, "R1").unwrap();
        assert_eq!(funding.utxos.len(), 1);
        assert_eq!(funding.total.to_sat(), 3_000_000);
        assert_eq!(funding.immature.len(), 1);
        assert_eq!(funding.immature_total().to_sat(), 5_000_000);
    }

    /// A coinbase past maturity is ordinary money.
    #[test]
    fn a_mature_coinbase_is_spendable() {
        let reader = ScriptedReader::new(2_000)
            .with_utxo("R1", 950, 5_000_000)
            .with_coinbase_at(950);
        let funding = spendable(&reader, "R1").unwrap();
        assert_eq!(funding.utxos.len(), 1);
        assert!(funding.immature.is_empty());
    }

    /// The optimisation that keeps funding cheap: an old output is spendable
    /// whether or not it is a coinbase, so its origin is never looked up.
    #[test]
    fn old_outputs_cost_no_extra_requests() {
        let reader = ScriptedReader::new(100_000)
            .with_utxo("R1", 10, 1)
            .with_utxo("R1", 20, 1)
            .with_utxo("R1", 30, 1);
        let funding = spendable(&reader, "R1").unwrap();
        assert_eq!(funding.utxos.len(), 3);
        // getblockcount + getaddressutxos, and nothing per output.
        assert_eq!(reader.requests(), 2);
    }

    /// Only the young ones are looked up, and only they.
    #[test]
    fn only_young_outputs_are_looked_up() {
        let reader = ScriptedReader::new(1_000)
            .with_utxo("R1", 10, 1)
            .with_utxo("R1", 950, 1)
            .with_utxo("R1", 960, 1);
        spendable(&reader, "R1").unwrap();
        // Two lookups: 950 and 960 are within 100 of the tip, 10 is not.
        assert_eq!(reader.requests(), 4);
    }

    #[test]
    fn refuses_when_there_is_not_enough() {
        let reader = ScriptedReader::new(1_000).with_utxo("R1", 100, 1_000);
        let funding = spendable(&reader, "R1").unwrap();
        assert!(require(&funding, Amount::from_sat(500), "R1").is_ok());
        match require(&funding, Amount::from_sat(5_000), "R1") {
            Err(FlowError::InsufficientFunds {
                needed, available, ..
            }) => {
                assert_eq!(needed.to_sat(), 5_000);
                assert_eq!(available.to_sat(), 1_000);
            }
            other => panic!("expected InsufficientFunds, got {other:?}"),
        }
    }
}
