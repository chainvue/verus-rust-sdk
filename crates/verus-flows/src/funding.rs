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
    /// Outputs that are not plain P2PKH — reserve outputs holding tokens,
    /// identity outputs, anything CryptoCondition.
    ///
    /// Kept out of [`Funding::utxos`] because the native builders refuse them,
    /// and rightly: a reserve output's value is in its payload, not its satoshis,
    /// so spending one as ordinary funding would destroy whatever it carries.
    /// A wallet that holds a single token would otherwise be unable to make an
    /// ordinary payment at all.
    ///
    /// Handed back rather than dropped, because a token transfer needs exactly
    /// these — see `verus_tx::token` and `verus_flows::convert`.
    pub other: Vec<AddressUtxo>,
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
    let coinbase_heights = probe_coinbase_heights(reader, &found, tip)?;
    let mature = verus_rpc::spendable_at(&found, tip, &coinbase_heights);
    let mature_outpoints: Vec<_> = mature.iter().map(|u| (u.txid, u.vout)).collect();

    // A native builder can only spend P2PKH. Everything else is separated here
    // rather than refused later by the builder, which cannot tell a caller
    // which of their outputs was the problem.
    let (utxos, other): (Vec<Utxo>, Vec<Utxo>) = mature
        .into_iter()
        .partition(|utxo| is_p2pkh(&utxo.script_pubkey));
    let other_outpoints: Vec<_> = other.iter().map(|u| (u.txid, u.vout)).collect();

    let mut immature = Vec::new();
    let mut non_native = Vec::new();
    for utxo in found {
        let outpoint = (utxo.utxo.txid, utxo.utxo.vout);
        if other_outpoints.contains(&outpoint) {
            non_native.push(utxo);
        } else if !mature_outpoints.contains(&outpoint) {
            immature.push(utxo);
        }
    }

    let total = Amount::checked_sum(utxos.iter().map(|u| u.satoshis)).ok_or_else(|| {
        FlowError::NotReady("the address holds more than can be represented".into())
    })?;

    Ok(Funding {
        utxos,
        tip,
        total,
        immature,
        other: non_native,
    })
}

/// The heights of the coinbase outputs in `found` that could still be
/// immature. Only an output younger than [`COINBASE_MATURITY`] is worth the
/// round trip — shared by [`spendable`] and [`identity_held`] so their
/// maturity rules cannot drift apart.
fn probe_coinbase_heights(
    reader: &impl ChainReader,
    found: &[AddressUtxo],
    tip: u32,
) -> Result<Vec<u32>, FlowError> {
    let mut heights = Vec::new();
    for utxo in found {
        if utxo.confirmations(tip) >= COINBASE_MATURITY {
            continue;
        }
        if is_coinbase(reader, &utxo.utxo.txid.to_display_hex())? {
            heights.push(utxo.height);
        }
    }
    Ok(heights)
}

/// `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`, and nothing else.
fn is_p2pkh(script: &[u8]) -> bool {
    script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
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

/// Gather the outputs a VerusID holds — the standard pay-to-identity outputs
/// for `identity`, mature and ready to fund an identity-authorised spend or a
/// mint.
///
/// `identity` is the `i` address. Only outputs whose script is *exactly* the
/// identity's payment script are returned: the identity's own identity output
/// (the one carrying its definition), tokens it holds, and anything else
/// CryptoCondition are all excluded, because the identity-funded builders
/// refuse them and rightly so.
pub fn identity_held(reader: &impl ChainReader, identity: &str) -> Result<Vec<Utxo>, FlowError> {
    let address: verus_keys::Address = identity
        .parse()
        .map_err(|e| FlowError::NoSuchIdentity(format!("{identity}: {e}")))?;
    let expected = verus_tx::identity_payment_script(address.hash())?;
    let tip = reader.block_count()?;
    let found = reader.address_utxos(&[identity])?;

    // Coinbase maturity applies here exactly as in `spendable` — an identity
    // that stakes is paid in coinbase outputs carrying this very script, and
    // an identity spend consumes EVERY output it is handed, so one immature
    // output would poison the whole spend for a hundred blocks with an error
    // that names nothing.
    let coinbase_heights = probe_coinbase_heights(reader, &found, tip)?;

    Ok(verus_rpc::spendable_at(&found, tip, &coinbase_heights)
        .into_iter()
        .filter(|utxo| utxo.script_pubkey == expected)
        .collect())
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

    /// The bug this separation exists for: a wallet holding one token could not
    /// make an ordinary payment, because the reserve output was handed to a
    /// native builder that correctly refused it.
    #[test]
    fn a_token_output_does_not_break_a_native_send() {
        let address = "R1";
        let reader = ScriptedReader::new(1_000)
            .with_utxo(address, 100, 5_000_000)
            .with_reserve_utxo(address, 200);

        let funding = spendable(&reader, address).unwrap();
        assert_eq!(funding.utxos.len(), 1, "the reserve output was left in");
        assert_eq!(funding.total.to_sat(), 5_000_000);
        assert_eq!(funding.other.len(), 1, "the reserve output was dropped");
        assert!(funding.immature.is_empty());
    }

    /// A reserve output's value is in its payload, so it must not be counted as
    /// native funds either.
    #[test]
    fn a_token_output_is_not_counted_as_native_value() {
        let reader = ScriptedReader::new(1_000).with_reserve_utxo("R1", 200);
        let funding = spendable(&reader, "R1").unwrap();
        assert_eq!(funding.total.to_sat(), 0);
        assert!(funding.utxos.is_empty());
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
