//! Reading an offer against the chain before completing it.
//!
//! The offer is funded through the SDK and broadcast to the scripted chain, so
//! the funding output the inspection reads back is a real one this workspace
//! produced — not a hand-written fixture that could agree with a wrong parser.

use verus_flows::testing::ScriptedReader;
use verus_flows::{offer as flow, Demand, FlowError};
use verus_keys::PrivateKey;
use verus_tx::offer::{fund_offer, make_offer, offer_funding_script, OfferParams, Wanted};
use verus_tx::{Amount, CurrencyId, Expiry, Txid, Utxo};

fn maker() -> PrivateKey {
    PrivateKey::from_bytes(&[0x41; 32], true).unwrap()
}

const TIP: u32 = 1_167_900;

/// Fund an offer on the scripted chain and return the funding UTXO.
fn funded(reader: &ScriptedReader, amount: u64) -> Utxo {
    let coins = [Utxo {
        txid: Txid::from_internal([0xc0; 32]),
        vout: 0,
        satoshis: Amount::from_sat(amount + 1_00000000),
        script_pubkey: maker().address().p2pkh_script_pubkey().unwrap(),
    }];
    let funding = fund_offer(
        &maker(),
        &coins,
        Amount::from_sat(amount),
        &maker().address(),
        Expiry::AtHeight(TIP + 100),
        100_000,
    )
    .unwrap();

    // The scripted node learns the transaction, so its outputs can be read back
    // exactly as a daemon would serve them.
    use verus_rpc::Broadcaster;
    reader.send_raw_transaction(&funding.hex).unwrap();

    Utxo {
        txid: Txid::from_display_hex(&funding.txid).unwrap(),
        vout: 0,
        satoshis: Amount::from_sat(amount),
        script_pubkey: offer_funding_script(maker().address().hash()).unwrap(),
    }
}

fn native_offer(reader: &ScriptedReader, offered: u64, wanted: u64) -> String {
    let funding = funded(reader, offered);
    make_offer(
        &maker(),
        &OfferParams::new(
            &funding,
            Wanted::Native {
                amount: Amount::from_sat(wanted),
                recipient: maker().address().hash(),
            },
            Expiry::AtHeight(TIP + 50),
        ),
    )
    .unwrap()
    .hex
}

/// The value comes from the chain, not from whatever the caller believed.
#[test]
fn the_offered_value_is_read_from_the_funding_outpoint() {
    let reader = ScriptedReader::new(TIP);
    let offer = native_offer(&reader, 7_00000000, 2_00000000);

    let terms = flow::inspect(&reader, &offer).unwrap();

    assert_eq!(terms.offered, Amount::from_sat(7_00000000));
    assert_eq!(terms.control, maker().address().hash());
    assert_eq!(
        terms.demand,
        Demand::Native {
            amount: Amount::from_sat(2_00000000),
            recipient: maker().address().hash(),
        }
    );
    assert_eq!(terms.expiry_height, TIP + 50);
}

/// A daemon reports `value` in coins. Reading it as satoshis would be wrong by
/// a factor of 100,000,000 — and would still parse, still build, and quietly
/// hand the difference to a miner.
#[test]
fn the_value_is_not_off_by_a_factor_of_a_hundred_million() {
    let reader = ScriptedReader::new(TIP);
    let offer = native_offer(&reader, 3_00000000, 1_00000000);

    let terms = flow::inspect(&reader, &offer).unwrap();
    assert_eq!(terms.offered, Amount::from_sat(3_00000000));
    assert_ne!(terms.offered, Amount::from_sat(3));
}

/// A token demand is read back as a token, with its currency and amount.
#[test]
fn a_token_demand_is_reported_as_one() {
    let reader = ScriptedReader::new(TIP);
    let funding = funded(&reader, 5_00000000);
    let currency = CurrencyId::from_bytes([0x2b; 20]);
    let offer = make_offer(
        &maker(),
        &OfferParams::new(
            &funding,
            Wanted::Token {
                currency,
                amount: Amount::from_sat(9_00000000),
                recipient: maker().address().hash(),
            },
            Expiry::AtHeight(TIP + 50),
        ),
    )
    .unwrap()
    .hex;

    let terms = flow::inspect(&reader, &offer).unwrap();
    assert_eq!(
        terms.demand,
        Demand::Token {
            currency,
            amount: Amount::from_sat(9_00000000),
            recipient: maker().address().hash(),
        }
    );
    // The offered side is still native, and still read from the chain.
    assert_eq!(terms.offered, Amount::from_sat(5_00000000));
}

/// An "offer" whose input spends an ordinary coin is not an offer.
///
/// The maker's signature would then cover something other than an offer funding
/// output, and the shape of the trade is not what it appears to be. Refusing
/// here beats discovering it at broadcast.
#[test]
fn an_offer_over_something_that_is_not_a_funding_output_is_refused() {
    let reader = ScriptedReader::new(TIP);

    // Build the offer over a plain P2PKH coin by lying to `make_offer` about
    // what the funding script is — the chain will disagree.
    let plain = Utxo {
        txid: Txid::from_internal([0xc0; 32]),
        vout: 0,
        satoshis: Amount::from_sat(4_00000000),
        script_pubkey: maker().address().p2pkh_script_pubkey().unwrap(),
    };
    let coins = [Utxo {
        satoshis: Amount::from_sat(9_00000000),
        ..plain.clone()
    }];
    // Put a plain send on the chain so the outpoint resolves to a P2PKH output.
    let sent = verus_tx::build_transparent_send(
        &maker(),
        &verus_tx::SendParams::new(
            &coins,
            &[verus_tx::Recipient {
                address: maker().address(),
                satoshis: Amount::from_sat(4_00000000),
            }],
            maker().address(),
            Expiry::AtHeight(TIP + 100),
        ),
    )
    .unwrap();
    use verus_rpc::Broadcaster;
    reader.send_raw_transaction(&sent.hex).unwrap();

    let pretend = Utxo {
        txid: Txid::from_display_hex(&sent.txid).unwrap(),
        vout: 0,
        satoshis: Amount::from_sat(4_00000000),
        // `make_offer` checks the script it is given, so it has to be told this
        // is a funding output; the chain is what catches the lie.
        script_pubkey: offer_funding_script(maker().address().hash()).unwrap(),
    };
    let offer = make_offer(
        &maker(),
        &OfferParams::new(
            &pretend,
            Wanted::Native {
                amount: Amount::from_sat(1_00000000),
                recipient: maker().address().hash(),
            },
            Expiry::AtHeight(TIP + 50),
        ),
    )
    .unwrap()
    .hex;

    let err = flow::inspect(&reader, &offer).unwrap_err();
    match err {
        FlowError::Offer(ref text) => {
            assert!(text.contains("not an offer funding output"), "{text}");
        }
        other => panic!("expected an offer error, got {other:?}"),
    }
}

#[test]
fn an_expired_offer_is_refused_before_it_is_built() {
    let reader = ScriptedReader::new(TIP);
    let offer = native_offer(&reader, 3_00000000, 1_00000000);
    let terms = flow::inspect(&reader, &offer).unwrap();

    assert!(terms.is_live_at(TIP));
    assert!(!terms.is_live_at(terms.expiry_height));
    assert!(!terms.is_live_at(terms.expiry_height + 1));
}

#[test]
fn malformed_offers_are_refused_without_touching_the_chain() {
    let reader = ScriptedReader::new(TIP);

    assert!(matches!(
        flow::inspect(&reader, "not hex").unwrap_err(),
        FlowError::Offer(_)
    ));
    assert!(matches!(
        flow::inspect(&reader, "00ff").unwrap_err(),
        FlowError::Offer(_)
    ));
    assert_eq!(reader.requests(), 0, "a bad offer must cost no lookups");
}
