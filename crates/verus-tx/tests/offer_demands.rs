//! What `take_offer` accepts as a maker's demand, and what it refuses.
//!
//! Offline, one test per output shape. The live swap test proves the
//! mechanism end to end but exercises exactly one shape — a native demand to
//! a key hash — so every other branch of the demand match was unexercised,
//! and both of its bugs shipped that way:
//!
//! * it once matched `_ => Vec::new()`, so an output it could not decode
//!   silently became "no token demand" and the token accounting was skipped —
//!   a free trade for the taker's counterparty;
//! * fixing that, it then refused everything but a bare key hash, which broke
//!   the ordinary daemon shape of demanding native payment to an i-address.
//!
//! One shape per test, each asserting the branch it names.

use verus_keys::PrivateKey;
use verus_tx::offer::{
    make_offer, offer_funding_script, take_offer, OfferParams, TakeParams, Wanted,
};
use verus_tx::{Amount, CurrencyId, Expiry, Txid, Utxo};
use verus_wire::{TxOut, TxV4};

const MAKER_WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";

fn maker() -> PrivateKey {
    PrivateKey::from_wif(MAKER_WIF).unwrap()
}

fn taker() -> PrivateKey {
    PrivateKey::from_bytes(&[0x5b; 32], true).unwrap()
}

fn offered() -> Amount {
    Amount::from_sat(1_00000000)
}

/// The maker's funding output: what the offer spends.
fn funding() -> Utxo {
    Utxo {
        txid: Txid::from_internal([0x71; 32]),
        vout: 0,
        satoshis: offered(),
        script_pubkey: offer_funding_script(maker().address().hash()).unwrap(),
    }
}

/// The taker's coins.
fn taker_utxos() -> Vec<Utxo> {
    vec![Utxo {
        txid: Txid::from_internal([0x72; 32]),
        vout: 1,
        satoshis: Amount::from_sat(5_00000000),
        script_pubkey: taker().address().p2pkh_script_pubkey().unwrap(),
    }]
}

/// A signed offer demanding `wanted`.
fn offer_demanding(wanted: Wanted) -> String {
    let funding = funding();
    make_offer(&maker(), &OfferParams::new(&funding, wanted, Expiry::Never))
        .expect("make the offer")
        .hex
}

/// Replace the offer's single output with `script`, keeping the maker's
/// signature — enough to drive `take_offer`'s demand match, which reads the
/// output before it ever checks a signature.
fn offer_with_demand_script(script: Vec<u8>, value: u64) -> String {
    let hex = offer_demanding(Wanted::Native {
        amount: Amount::from_sat(1_20000000),
        recipient: maker().address().hash(),
    });
    let mut tx = TxV4::deserialize(&hex::decode(&hex).unwrap()).unwrap();
    tx.outputs[0] = TxOut {
        value,
        script_pubkey: script,
    };
    hex::encode(tx.serialize().unwrap())
}

fn take(offer: &str) -> Result<Vec<u8>, verus_tx::TxError> {
    let utxos = taker_utxos();
    take_offer(
        &taker(),
        &TakeParams::new(
            offer,
            &utxos,
            taker().address().hash(),
            taker().address(),
            offered(),
            20_000,
        ),
    )
}

/// The shape the live test covers, pinned offline so the others have a
/// baseline: native payment to a key hash, no token demand.
#[test]
fn a_native_demand_to_a_key_hash_is_taken() {
    let offer = offer_demanding(Wanted::Native {
        amount: Amount::from_sat(1_20000000),
        recipient: maker().address().hash(),
    });
    take(&offer).expect("a plain native demand is takeable");
}

/// **The regression this file exists for.** A daemon `makeoffer` demanding
/// native payment to the maker's i-address decodes as `IdentityPayment` —
/// native value only, no eval payload, as fully understood as a key hash.
/// Refusing it broke interop with the daemon's own mechanism.
#[test]
fn a_native_demand_to_an_identity_is_taken() {
    let script = verus_tx::identity_payment_script([0x33; 20]).unwrap();
    let offer = offer_with_demand_script(script, 1_20000000);
    take(&offer).expect("paying an identity is an ordinary native demand");
}

/// A token demand must actually reach the token accounting — not be silently
/// treated as "nothing demanded". The taker here funds no tokens at all, so
/// an honest accounting must refuse for want of them; if the demand were
/// dropped the take would succeed and the maker would be paid nothing.
#[test]
fn a_token_demand_is_accounted_rather_than_skipped() {
    let offer = offer_demanding(Wanted::Token {
        currency: CurrencyId::from_bytes([0x2b; 20]),
        amount: Amount::from_sat(500_00000000),
        recipient: maker().address().hash(),
    });
    match take(&offer) {
        // The refusal must NAME the shortfall and the currency — that is the
        // evidence the demand reached the accounting rather than being
        // dropped. A bare "invalid offer" would not distinguish the two.
        Err(verus_tx::TxError::InvalidOffer(message)) => {
            assert!(
                message.contains("short by 50000000000"),
                "the shortfall was not accounted: {message}"
            );
            assert!(
                message.contains("2b2b2b2b"),
                "the demanded currency was not named: {message}"
            );
        }
        Ok(_) => panic!("the token demand was silently dropped — this is the free-trade bug"),
        Err(other) => panic!("expected a named token shortfall, got {other:?}"),
    }
}

/// An output whose eval code this crate cannot decode may carry value it
/// cannot see. It must be refused, never reclassified as native-only.
#[test]
fn an_undecodable_demand_is_refused_not_treated_as_native() {
    // A CryptoCondition with an eval code this crate does not decode.
    let script = verus_tx::cc::cc_script(
        &verus_tx::cc::OptCcParams::one_of_one(0x7f, verus_tx::Destination::PubKeyHash([0x44; 20])),
        &verus_tx::cc::OptCcParams::one_of_one(0x7f, verus_tx::Destination::PubKeyHash([0x44; 20])),
    )
    .expect("build an unsupported cc output");
    let offer = offer_with_demand_script(script, 1_20000000);
    match take(&offer) {
        Err(verus_tx::TxError::InvalidOffer(_)) => {}
        Ok(_) => panic!("an unaccountable demand was taken as if it were native"),
        Err(other) => panic!("expected InvalidOffer, got {other:?}"),
    }
}

/// An output that HOLDS an identity is not a payment at all.
#[test]
fn an_identity_primary_demand_is_refused() {
    let identity = verus_tx::identity::Identity {
        version: 3,
        flags: 0,
        primary_addresses: vec![verus_tx::Destination::PubKeyHash([0x55; 20])],
        min_sigs: 1,
        parent: [0x66; 20],
        name: "notademand".into(),
        content_multimap: Vec::new(),
        content_map: Vec::new(),
        revocation_authority: [0x66; 20],
        recovery_authority: [0x66; 20],
        private_addresses: Vec::new(),
        system_id: [0x66; 20],
        unlock_after: 0,
    };
    let script = verus_tx::identity_primary_script(
        [0x77; 20],
        identity.to_bytes().unwrap(),
        identity.revocation_authority,
        identity.recovery_authority,
    )
    .unwrap();
    let offer = offer_with_demand_script(script, 0);
    assert!(
        matches!(take(&offer), Err(verus_tx::TxError::InvalidOffer(_))),
        "an identity output is not a demand shape"
    );
}
