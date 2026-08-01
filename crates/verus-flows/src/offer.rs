//! Finding an offer, and reading it against the chain before completing it.
//!
//! [`browse`] lists what is standing against a currency or an identity. Until
//! it existed, making and taking an offer both worked and there was no way to
//! *discover* one — an application could complete a trade it had been handed
//! but could not show anyone what was for sale.
//!
//! `verus_tx::take_offer` builds what a maker asked for. It cannot check any of
//! it: the value a maker is giving lives in an *outpoint*, not in the offer, so
//! the taker had to pass `offered_value` in by hand and hope. This module looks
//! it up.
//!
//! # What this does and does not protect against
//!
//! Worth being precise, because it is easy to oversell.
//!
//! Consensus already prevents the theft case. If the funding outpoint is gone,
//! or holds less than the offer implies, the completed transaction is rejected
//! or never relays — the taker loses effort, not funds. So this is **not**
//! anti-fraud machinery.
//!
//! What it does buy:
//!
//! * **The taker sees the trade before signing it.** [`inspect`] returns what
//!   is really on offer and what is really demanded, both read from the chain
//!   rather than from the maker's message.
//! * **`offered_value` stops being a guess.** [`take`] uses the value it read,
//!   so a caller cannot transpose a digit and hand the difference to a miner.
//!   That one is a real fund-loss bug, and it is the caller's own to make.
//! * **Failure moves earlier and gets a reason.** "That outpoint is not an offer
//!   funding output" beats a broadcast rejection with no explanation.
//!
//! # Why "is it still unspent" is not answered
//!
//! `getspentinfo` is served by the public node and cannot answer: it returns
//! `-5` for spent and unspent outpoints alike, because the node runs without
//! `spentindex`. Probed 2026-07-30 against `api.verustest.net`.
//!
//! So a spent-check would have to come from the address index, and this module
//! does not pretend to have one. [`OfferTerms::confirmations`] tells you the
//! funding transaction exists and is mined, which is strictly less than "its
//! output is still there" — the difference is stated rather than glossed.

use verus_keys::PrivateKey;
use verus_rpc::{Broadcaster, ChainReader, OfferListing};
use verus_tx::offer::{offer_funding_script, take_offer, TakeParams, OFFER_HASH_TYPE};
use verus_tx::{Amount, CurrencyId, Txid, Utxo};
use verus_wire::hash::txid_display;
use verus_wire::TxV4;

use crate::broadcast::Unsent;

use crate::error::FlowError;

/// What a maker is asking to be paid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Demand {
    /// Native coins.
    Native {
        /// How much.
        amount: Amount,
        /// The address the maker wants paying.
        recipient: [u8; 20],
    },
    /// A token, as a reserve output.
    Token {
        /// Which token.
        currency: CurrencyId,
        /// How much.
        amount: Amount,
        /// The address the maker wants paying.
        recipient: [u8; 20],
    },
}

/// An offer, checked against the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferTerms {
    /// The outpoint the offer spends.
    pub funding_txid: Txid,
    /// Index of that output.
    pub funding_vout: u32,
    /// What the funding output really holds, read from the chain — **not** from
    /// the maker's word.
    pub offered: Amount,
    /// The address that controls the funding output: the maker.
    pub control: [u8; 20],
    /// What the maker wants in return.
    pub demand: Demand,
    /// Height after which the offer can no longer be completed.
    pub expiry_height: u32,
    /// Confirmations on the funding *transaction*.
    ///
    /// Not proof the output is unspent — see the module docs. Zero means it is
    /// in the mempool, which is a reason to wait.
    pub confirmations: u32,
}

impl OfferTerms {
    /// Whether the offer can still be completed at `tip`.
    #[must_use]
    pub fn is_live_at(&self, tip: u32) -> bool {
        self.expiry_height == 0 || tip < self.expiry_height
    }
}

/// Read an offer and check it against the chain.
///
/// Refuses anything that is not a well-formed offer over a genuine funding
/// output — including one that spends an ordinary coin, which would mean the
/// maker's signature covers something other than what the offer claims.
pub fn inspect(reader: &impl ChainReader, offer_hex: &str) -> Result<OfferTerms, FlowError> {
    let bytes =
        hex::decode(offer_hex).map_err(|e| FlowError::Offer(format!("offer is not hex: {e}")))?;
    let offer = TxV4::deserialize(&bytes).map_err(|e| FlowError::Offer(format!("offer: {e}")))?;

    if offer.inputs.len() != 1 || offer.outputs.len() != 1 {
        return Err(FlowError::Offer(format!(
            "an offer has one input and one output, this has {} and {}",
            offer.inputs.len(),
            offer.outputs.len()
        )));
    }

    // The hash type lives in the fulfillment. Anything but SIGHASH_SINGLE |
    // ANYONECANPAY means the maker signed more than their own side, and
    // appending to it would void their signature.
    let fulfillment = &offer.inputs[0].script_sig;
    let hash_type = fulfillment
        .iter()
        .position(|b| *b == 0x01)
        .and_then(|start| fulfillment.get(start + 1).copied())
        .ok_or_else(|| FlowError::Offer("the offer input has no fulfillment".into()))?;
    if u32::from(hash_type) != OFFER_HASH_TYPE {
        return Err(FlowError::Offer(format!(
            "the offer is signed under hash type {hash_type:#x}, not {OFFER_HASH_TYPE:#x}"
        )));
    }

    let funding_txid = Txid::from_internal(offer.inputs[0].txid_internal);
    let funding_vout = offer.inputs[0].vout;

    let raw = reader.raw_transaction(&funding_txid.to_display_hex())?;
    let vout = raw["vout"]
        .as_array()
        .and_then(|outs| outs.get(usize::try_from(funding_vout).unwrap_or(usize::MAX)))
        .ok_or_else(|| {
            FlowError::Offer(format!(
                "the funding transaction has no output {funding_vout}"
            ))
        })?;

    let script = hex::decode(
        vout["scriptPubKey"]["hex"]
            .as_str()
            .ok_or_else(|| FlowError::Offer("the funding output has no script".into()))?,
    )
    .map_err(|e| FlowError::Offer(format!("the funding output's script is not hex: {e}")))?;

    // An offer funding script is completely determined by the 20-byte hash it
    // is locked to, so extracting that hash and rebuilding is a total check —
    // no field can differ without the comparison failing. `decode_output_script`
    // is not enough here: it reports eval code 17, which a name commitment also
    // uses.
    let rebuilt = script
        .get(7..27)
        .and_then(|slice| <[u8; 20]>::try_from(slice).ok())
        .map(|control| (control, offer_funding_script(control)));
    let control = match rebuilt {
        Some((control, Ok(expected))) if expected == script => control,
        // A script too short to hold a destination and one that holds a
        // different structure are the same answer to the caller: whatever this
        // outpoint is, it is not backing an offer.
        _ => {
            return Err(FlowError::Offer(
                "the outpoint this offer spends is not an offer funding output; the maker's \
                 signature covers something other than what the offer claims"
                    .into(),
            ))
        }
    };

    let offered = read_satoshis(vout)?;

    let demand = match verus_tx::decode_output_script(&offer.outputs[0].script_pubkey)
        .map_err(|e| FlowError::Offer(format!("the offer's demand: {e}")))?
    {
        verus_tx::OutputKind::PubKeyHash { hash } => Demand::Native {
            amount: Amount::from_sat(offer.outputs[0].value),
            recipient: hash,
        },
        verus_tx::OutputKind::ReserveOutput {
            destination,
            tokens,
        } => {
            let (currency, amount) = tokens.first().copied().ok_or_else(|| {
                FlowError::Offer("the offer demands a token output holding nothing".into())
            })?;
            if tokens.len() > 1 {
                return Err(FlowError::Offer(
                    "the offer demands several tokens in one output, which taking does not fund"
                        .into(),
                ));
            }
            // The demand must be reproduced as an output the taker pays, and
            // `Demand::Token` names its recipient by key hash. A demand paid to
            // an identity or a script is a shape this flow cannot rebuild yet —
            // refused rather than paid to the wrong `R` address, which is what
            // reading the hash out of any destination kind would do.
            let verus_tx::Destination::PubKeyHash(recipient) = destination else {
                return Err(FlowError::Offer(format!(
                    "the offer demands a token paid to {destination:?}, and taking one only \
                     funds a demand paid to a transparent address"
                )));
            };
            Demand::Token {
                currency,
                amount: Amount::from_sat(amount),
                recipient,
            }
        }
        other => {
            return Err(FlowError::Offer(format!(
                "the offer demands an output this crate cannot pay: {other:?}"
            )))
        }
    };

    Ok(OfferTerms {
        funding_txid,
        funding_vout,
        offered,
        control,
        demand,
        expiry_height: offer.expiry_height,
        confirmations: raw["confirmations"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0),
    })
}

/// A satoshi amount from a daemon `vout`.
///
/// Prefers the integer `valueSat`; falls back to the decimal `value`, read from
/// its original text rather than through `f64`. A float would round, and this is
/// the number the taker is deciding on.
fn read_satoshis(vout: &serde_json::Value) -> Result<Amount, FlowError> {
    if let Some(sats) = vout["valueSat"].as_u64() {
        return Ok(Amount::from_sat(sats));
    }
    let text = vout["value"].to_string();
    Amount::from_coins_str(text.trim_matches('"'))
        .map_err(|e| FlowError::Offer(format!("the funding output's value: {e}")))
}

/// An offer completed — broadcast by [`take`], still unsent from
/// [`prepare_take`].
#[derive(Debug, Clone)]
pub struct Taken {
    /// The terms as they were read from the chain.
    pub terms: OfferTerms,
    /// The completed transaction's id, computed locally from its bytes.
    pub txid: String,
}

/// What a taker supplies. The offered value is deliberately absent — it comes
/// from the chain, which is the whole point of this module.
#[derive(Debug, Clone)]
pub struct Taking<'a> {
    /// The maker's half-signed offer.
    pub offer_hex: &'a str,
    /// The taker's coins: native for the fee, plus reserve outputs if the
    /// maker asked to be paid in a token.
    pub utxos: &'a [Utxo],
    /// Where the offered funds go.
    pub recipient: [u8; 20],
    /// Where the taker's change goes.
    pub change_address: verus_keys::Address,
    /// The miner fee, in satoshis. Paid by the taker.
    pub fee: u64,
}

impl<'a> Taking<'a> {
    /// What a taker supplies to complete an offer.
    pub fn new(
        offer_hex: &'a str,
        utxos: &'a [Utxo],
        recipient: [u8; 20],
        change_address: verus_keys::Address,
        fee: u64,
    ) -> Self {
        Self {
            offer_hex,
            utxos,
            recipient,
            change_address,
            fee,
        }
    }
}

/// Complete an offer, paying what the chain says it demands.
///
/// Unlike `verus_tx::take_offer`, the offered value is the one [`inspect`] read
/// from the funding outpoint — a caller cannot mistype it and hand the
/// difference to a miner.
///
/// Refuses an offer that has already expired at the current tip, which would
/// otherwise be built, signed and rejected.
pub fn take(
    reader: &impl ChainReader,
    broadcaster: &impl Broadcaster,
    key: &PrivateKey,
    params: &Taking<'_>,
) -> Result<Taken, FlowError> {
    prepare_take(reader, key, params)?.broadcast(broadcaster)
}

/// Complete an offer without sending it.
///
/// The read-only half of [`take`], including the expiry refusal.
///
/// Unlike [`browse`], the order of the two reads here is not load-bearing: the
/// terms and the tip are both read before anything is signed, and the offer is
/// judged against that tip either way.
pub fn prepare_take(
    reader: &impl ChainReader,
    key: &PrivateKey,
    params: &Taking<'_>,
) -> Result<Unsent<Taken>, FlowError> {
    let Taking {
        offer_hex,
        utxos,
        recipient,
        change_address,
        fee,
    } = *params;
    // Issued together, unwrapped after — see [`crate::drive`].
    let terms = inspect(reader, offer_hex);
    let tip = reader.block_count();
    let (terms, tip) = (terms?, tip?);

    if !terms.is_live_at(tip) {
        return Err(FlowError::Offer(format!(
            "this offer expired at height {}, and the chain is at {tip}",
            terms.expiry_height
        )));
    }

    let raw = take_offer(
        key,
        &TakeParams::new(
            offer_hex,
            utxos,
            recipient,
            change_address,
            terms.offered,
            fee,
        ),
    )?;

    // The txid is computed here, from the bytes we are about to send, so
    // `broadcast` can refuse a node that answers about a different transaction.
    let completed =
        TxV4::deserialize(&raw).map_err(|e| FlowError::Offer(format!("completed offer: {e}")))?;
    let local_txid = txid_display(
        &completed
            .txid()
            .map_err(|e| FlowError::Offer(format!("completed offer txid: {e}")))?,
    );

    Ok(Unsent {
        hex: hex::encode(&raw),
        txid: local_txid.clone(),
        outcome: Taken {
            terms,
            txid: local_txid,
        },
    })
}

/// A listing, read against a particular tip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    /// The offer as the node reports it.
    pub listing: OfferListing,
    /// Whether it could still be completed at the tip this was read against.
    ///
    /// **Usually true — and that is a measurement, not an assumption.** Every
    /// offer the two public nodes returned was live when checked: 54 of 54 on
    /// VRSCTEST and 1843 of 1843 on VRSC. So the daemon appears to drop expired
    /// offers before answering, and this flag does little work today.
    ///
    /// It earns its place for the reason that is not about the node's
    /// filtering. This records the offer against **a** tip, and the chain moves
    /// afterwards: an offer expiring a block from now is listed as live and is
    /// dead by the time a taker has finished signing. Keeping the judgement
    /// separate from the data means [`verus_rpc::OfferListing::is_live_at`] can
    /// answer it again later, against a newer tip, without refetching the list.
    pub live: bool,
}

/// Every offer standing against a currency or an identity.
///
/// The half of the marketplace that was missing. Making and taking an offer
/// have both been proven on chain; without this an application could complete a
/// trade it had been handed, but could not show anyone what was for sale.
///
/// `is_currency` says how to read `target`, and getting it wrong fails
/// **quietly**: a currency asked about as an identity comes back empty, which
/// is indistinguishable from a currency nobody is trading. A plain name is only
/// ever taken as an identity — pass an `i` address for a currency.
///
/// `with_offer_bytes` asks for each maker's signed half-transaction, which is
/// what [`inspect`] takes. Without it a listing is something to display; with
/// it, it is something that can be checked against the chain and completed. It
/// makes the reply substantially larger, so it is a choice rather than a
/// default.
///
/// Costs two requests: the offers, then the tip.
///
/// That order is not incidental. A block landing between the two calls makes
/// the tip *newer* than the listings, so an offer that expired in the gap is
/// judged dead rather than alive. The other order fails the other way, and
/// optimistic is the wrong direction for the one question this answers.
///
/// # What this does not tell you
///
/// [`Listing::live`] rules out an offer that has expired. It says nothing about
/// whether the maker's funding output is **still unspent** — the same limit
/// [`inspect`] has, and for the same reason: `getspentinfo` cannot answer it on
/// a node without `spentindex`. An offer can be live, well-formed, and already
/// taken by somebody else.
pub fn browse(
    reader: &impl ChainReader,
    target: &str,
    is_currency: bool,
    with_offer_bytes: bool,
) -> Result<Vec<Listing>, FlowError> {
    let listings = reader.offers(target, is_currency, with_offer_bytes)?;
    let tip = reader.block_count()?;
    Ok(listings
        .into_iter()
        .map(|listing| Listing {
            live: listing.is_live_at(tip),
            listing,
        })
        .collect())
}

#[cfg(test)]
mod browse_tests {
    use super::*;
    use crate::testing::ScriptedReader;
    use std::collections::BTreeMap;
    use verus_rpc::OfferSide;

    fn listing(expiry: u32) -> OfferListing {
        OfferListing {
            offering: OfferSide::Currencies(BTreeMap::from([(
                "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq".to_string(),
                Amount::from_sat(1_000_000_000),
            )])),
            accepting: OfferSide::Identity {
                identity_id: "iSb6MzpWJU7nWkFnzQB1uyoLWvmRMwyWs3".to_string(),
                name: "OnyxSpark".to_string(),
                system_id: "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq".to_string(),
            },
            block_expiry: expiry,
            funding_txid: Txid::from_internal([0x0a; 32]),
            raw_offer: None,
            price: "0.025".to_string(),
            bucket: "currency_x_for_ids".to_string(),
        }
    }

    /// The tip decides, not the node: an offer that expires at exactly the
    /// current height can no longer be completed, because any transaction
    /// taking it lands at a later one.
    #[test]
    fn expiry_is_judged_against_the_tip() {
        let reader = ScriptedReader::new(1_170_800).with_offers(vec![
            listing(1_170_799),
            listing(1_170_800),
            listing(1_170_801),
            listing(0),
        ]);

        let live: Vec<bool> = browse(&reader, "iJhCez", true, false)
            .unwrap()
            .iter()
            .map(|l| l.live)
            .collect();
        assert_eq!(live, vec![false, false, true, true], "0 means no expiry");
    }

    /// The same listing is live now and dead later, without asking again.
    /// That is the case the flag exists for — the public nodes were observed
    /// returning no expired offers at all, so the node's own filtering is not
    /// what makes this useful.
    #[test]
    fn a_listing_can_be_rechecked_against_a_later_tip() {
        let reader = ScriptedReader::new(1_170_800).with_offers(vec![listing(1_170_900)]);
        let found = browse(&reader, "iJhCez", true, false).unwrap();

        assert!(found[0].live);
        assert!(!found[0].listing.is_live_at(1_170_900));
    }

    /// An empty answer is a legitimate outcome, and it is also what asking
    /// about a currency as an identity produces. The flow does not invent a
    /// distinction the node does not draw.
    #[test]
    fn nothing_for_sale_is_an_empty_list_not_an_error() {
        let reader = ScriptedReader::new(1_170_800);
        assert!(browse(&reader, "iJhCez", true, false).unwrap().is_empty());
    }
}
