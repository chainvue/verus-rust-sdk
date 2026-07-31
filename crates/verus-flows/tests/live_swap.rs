//! A complete marketplace order settled on VRSCTEST, through the public node.
//!
//! Two independent keys, two independent signatures, one transaction. The maker
//! signs an input under `SIGHASH_SINGLE | ANYONECANPAY` paired with the output
//! they want; the taker appends their own side and signs it under
//! `SIGHASH_ALL`. Neither ever holds the other's key, and nothing is escrowed.
//!
//! **Opt-in, and it spends real testnet coins:**
//!
//! ```sh
//! export VERUS_LIVE_KEY=<maker WIF>
//! export VERUS_LIVE_TAKER_KEY=<taker WIF>
//! VERUS_LIVE_SWAP=1 cargo test -p verus-flows --test live_swap -- --nocapture --test-threads=1
//! ```
//!
//! Two orders are settled here, and the second is the one that matters:
//!
//!   * `two_parties_settle_a_marketplace_order` — both legs native. The
//!     simplest form of the mechanism.
//!   * `two_parties_settle_a_token_demand` — the maker wants a **token**, so
//!     the taker pays from a reserve input, unlocks it with a CryptoCondition
//!     fulfillment rather than a P2PKH `scriptSig`, and takes the surplus back
//!     as token change. That composition had no oracle behind it at all: the
//!     TypeScript SDK has no offers, so there are no bytes to be identical to,
//!     and the settled order above was native legs only.

use std::str::FromStr;

use verus_flows::{spendable, Broadcaster, ChainReader, HttpTransport, RpcClient};
use verus_keys::{Address, PrivateKey};
use verus_tx::offer::{fund_offer, make_offer, take_offer, OfferParams, TakeParams, Wanted};
use verus_tx::CurrencyId;
use verus_tx::{
    decode_output_script, Amount, Expiry, OutputKind, Txid, Utxo, DEFAULT_EXPIRY_BLOCKS,
};
use verus_wire::TxV4;

const ENDPOINT: &str = "https://api.verustest.net";
const FEE_PER_KB: u64 = 100_000;

fn client() -> RpcClient<HttpTransport> {
    RpcClient::new(HttpTransport::new(ENDPOINT).expect("https"))
}

fn keys() -> Option<(PrivateKey, PrivateKey)> {
    if std::env::var("VERUS_LIVE_SWAP").is_err() {
        eprintln!("skipping: set VERUS_LIVE_SWAP=1, VERUS_LIVE_KEY and VERUS_LIVE_TAKER_KEY");
        return None;
    }
    let maker = PrivateKey::from_wif(&std::env::var("VERUS_LIVE_KEY").expect("VERUS_LIVE_KEY"))
        .expect("maker WIF");
    let taker =
        PrivateKey::from_wif(&std::env::var("VERUS_LIVE_TAKER_KEY").expect("VERUS_LIVE_TAKER_KEY"))
            .expect("taker WIF");
    Some((maker, taker))
}

/// Wait for a transaction to confirm, or give up.
fn await_confirmation(client: &RpcClient<HttpTransport>, txid: &str) {
    for _ in 0..40 {
        if let Ok(Some(confirmations)) = client.confirmations(txid) {
            if confirmations > 0 {
                eprintln!("    confirmed ({confirmations})");
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(15));
    }
    panic!("{txid} never confirmed");
}

#[test]
fn two_parties_settle_a_marketplace_order() {
    let Some((maker, taker)) = keys() else { return };
    let client = client();

    let maker_address = maker.address();
    let taker_address = taker.address();
    eprintln!("maker {maker_address}\ntaker {taker_address}");

    let offered = Amount::from_sat(1_00000000); // the maker gives 1 VRSCTEST
    let wanted = Amount::from_sat(1_20000000); // and wants 1.2 back

    // --- step 1: the maker moves funds into an output an offer can be signed over
    let tip = client.block_count().expect("tip");
    let maker_funds = spendable(&client, &maker_address.to_string()).expect("maker funds");
    let funding_tx = fund_offer(
        &maker,
        &maker_funds.utxos,
        offered,
        &maker_address,
        Expiry::within(tip, DEFAULT_EXPIRY_BLOCKS),
        FEE_PER_KB,
    )
    .expect("fund the offer");

    eprintln!("  funding {}", funding_tx.txid);
    client
        .send_raw_transaction(&funding_tx.hex)
        .expect("broadcast the funding transaction");
    await_confirmation(&client, &funding_tx.txid);

    // Output 0 of that transaction is the offer's backing.
    let funding = Utxo {
        txid: Txid::from_display_hex(&funding_tx.txid).expect("txid"),
        vout: 0,
        satoshis: offered,
        script_pubkey: verus_tx::offer::offer_funding_script(maker_address.hash()).expect("script"),
    };

    // --- step 2: the maker signs the offer. Nothing is broadcast.
    let tip = client.block_count().expect("tip");
    let offer = make_offer(
        &maker,
        &OfferParams::new(
            &funding,
            Wanted::Native {
                amount: wanted,
                recipient: maker_address.hash(),
            },
            Expiry::within(tip, 200),
        ),
    )
    .expect("make the offer");
    eprintln!(
        "  offer signed: give {}, want {}",
        offered.to_coins_string(),
        wanted.to_coins_string()
    );

    // --- step 3: the taker completes it, with their own coins and their own key
    let taker_funds = spendable(&client, &taker_address.to_string()).expect("taker funds");
    assert!(
        taker_funds.total >= wanted,
        "the taker holds {} but the offer asks {}",
        taker_funds.total.to_coins_string(),
        wanted.to_coins_string()
    );

    let completed = take_offer(
        &taker,
        &TakeParams::new(
            &offer.hex,
            &taker_funds.utxos,
            taker_address.hash(),
            taker_address,
            offered,
            20_000,
        ),
    )
    .expect("take the offer");
    let completed_hex = hex::encode(&completed);

    // The maker's side must have survived completion untouched.
    let original = TxV4::deserialize(&hex::decode(&offer.hex).unwrap()).unwrap();
    let final_tx = TxV4::deserialize(&completed).unwrap();
    assert_eq!(final_tx.inputs[0], original.inputs[0]);
    assert_eq!(final_tx.outputs[0], original.outputs[0]);
    eprintln!(
        "  completed: {} inputs, {} outputs",
        final_tx.inputs.len(),
        final_tx.outputs.len()
    );

    // --- step 4: the network settles it
    let txid = client
        .send_raw_transaction(&completed_hex)
        .expect("the network must accept an order this SDK settled");
    eprintln!("  SETTLED {txid}");
    await_confirmation(&client, &txid);
}

/// The token this trade is denominated in: `sdkcuralpha`, a `proofprotocol` 2
/// token this SDK launched. Any token the taker holds would do; this one is
/// pinned so a run is reproducible.
const TOKEN: &str = "i7UCaJkKRFXBCK4S1AMrkfKTnPwdLc7dV7";

/// How much of it the maker asks for. Small on purpose — the point is the
/// mechanism, and a surplus is what forces the token-change output to exist.
const TOKEN_WANTED: u64 = 1_00000000;

/// The token a reserve output carries, if it carries any.
fn token_in(utxo: &Utxo, currency: CurrencyId) -> Option<Amount> {
    match decode_output_script(&utxo.script_pubkey).ok()? {
        OutputKind::ReserveOutput { tokens, .. } => tokens
            .into_iter()
            .find(|(held, _)| *held == currency)
            .map(|(_, amount)| Amount::from_sat(amount)),
        _ => None,
    }
}

/// A maker who wants a token, and a taker who pays it from a reserve output.
///
/// This is the last composition in `PROVEN.md` that was verified against
/// nothing but our own reasoning, and it is also the one where being wrong
/// costs the *counterparty*: the taker signs a half-transaction that someone
/// else completes, and a reserve input signed the ordinary P2PKH way produces
/// bytes the daemon rejects — or worse, conserves tokens incorrectly.
///
/// Three things are exercised here that the native order does not touch:
/// funding a demand from reserve inputs, unlocking one with a CryptoCondition
/// fulfillment, and returning the surplus as token change.
#[test]
fn two_parties_settle_a_token_demand() {
    let Some((maker, taker)) = keys() else { return };
    let client = client();

    let currency = CurrencyId::from_bytes(Address::from_str(TOKEN).expect("token address").hash());
    let wanted = Amount::from_sat(TOKEN_WANTED);
    let offered = Amount::from_sat(50000000); // the maker gives 0.5 VRSCTEST

    let maker_address = maker.address();
    let taker_address = taker.address();
    eprintln!("maker {maker_address}\ntaker {taker_address}\ntoken {TOKEN}");

    // --- step 0: check both sides can do their part BEFORE anything is spent.
    //
    // The native order broadcasts its funding transaction first and discovers a
    // shortfall afterwards. Here the taker's side involves a token that may
    // simply not be there, and finding that out after the maker has already
    // paid a miner fee is a worse way to learn it.
    let taker_funds = spendable(&client, &taker_address.to_string()).expect("taker funds");
    let reserves: Vec<Utxo> = taker_funds
        .other
        .iter()
        .map(|found| found.utxo.clone())
        .filter(|utxo| token_in(utxo, currency).is_some())
        .collect();
    let held = Amount::checked_sum(reserves.iter().filter_map(|u| token_in(u, currency)))
        .expect("token total");
    assert!(
        held >= wanted,
        "the taker holds {} of {TOKEN} but the offer asks {}",
        held.to_coins_string(),
        wanted.to_coins_string(),
    );
    assert!(
        held > wanted,
        "pick an amount below what the taker holds: paying it all leaves no \
         token change, and the change output is half of what this test proves",
    );
    eprintln!(
        "  taker holds {} across {} reserve output(s)",
        held.to_coins_string(),
        reserves.len(),
    );

    // --- step 1: the maker moves native funds into an output an offer can sign over
    let tip = client.block_count().expect("tip");
    let maker_funds = spendable(&client, &maker_address.to_string()).expect("maker funds");
    let funding_tx = fund_offer(
        &maker,
        &maker_funds.utxos,
        offered,
        &maker_address,
        Expiry::within(tip, DEFAULT_EXPIRY_BLOCKS),
        FEE_PER_KB,
    )
    .expect("fund the offer");

    eprintln!("  funding {}", funding_tx.txid);
    client
        .send_raw_transaction(&funding_tx.hex)
        .expect("broadcast the funding transaction");
    await_confirmation(&client, &funding_tx.txid);

    let funding = Utxo {
        txid: Txid::from_display_hex(&funding_tx.txid).expect("txid"),
        vout: 0,
        satoshis: offered,
        script_pubkey: verus_tx::offer::offer_funding_script(maker_address.hash()).expect("script"),
    };

    // --- step 2: the maker signs an offer whose demand is a token
    let tip = client.block_count().expect("tip");
    let offer = make_offer(
        &maker,
        &OfferParams::new(
            &funding,
            Wanted::Token {
                currency,
                amount: wanted,
                recipient: maker_address.hash(),
            },
            Expiry::within(tip, 200),
        ),
    )
    .expect("make the offer");
    eprintln!(
        "  offer signed: give {} VRSCTEST, want {} of the token",
        offered.to_coins_string(),
        wanted.to_coins_string(),
    );

    // --- step 3: the taker pays it. Reserve inputs for the token, P2PKH for
    // the miner fee — `take_offer` selects from one list and has to tell them
    // apart itself.
    let mut funding_inputs = taker_funds.utxos.clone();
    funding_inputs.extend(reserves);

    let completed = take_offer(
        &taker,
        &TakeParams::new(
            &offer.hex,
            &funding_inputs,
            taker_address.hash(),
            taker_address,
            offered,
            20_000,
        ),
    )
    .expect("take the token offer");

    // The maker's half must have survived completion untouched: their signature
    // covers input 0 paired with output 0, and altering either voids it.
    let original = TxV4::deserialize(&hex::decode(&offer.hex).unwrap()).unwrap();
    let final_tx = TxV4::deserialize(&completed).unwrap();
    assert_eq!(final_tx.inputs[0], original.inputs[0]);
    assert_eq!(final_tx.outputs[0], original.outputs[0]);

    // Tokens must be conserved: what the maker is paid plus what comes back as
    // change equals what was spent. A transaction that fails this burns the
    // difference, and the daemon will not always say so.
    let paid_out = Amount::checked_sum(final_tx.outputs.iter().filter_map(|out| {
        token_in(
            &Utxo {
                txid: funding.txid,
                vout: 0,
                satoshis: Amount::ZERO,
                script_pubkey: out.script_pubkey.clone(),
            },
            currency,
        )
    }))
    .expect("token outputs");
    assert_eq!(
        paid_out, held,
        "tokens in must equal tokens out; the difference would be burned",
    );
    eprintln!(
        "  completed: {} inputs, {} outputs, {} of the token accounted for",
        final_tx.inputs.len(),
        final_tx.outputs.len(),
        paid_out.to_coins_string(),
    );

    // --- step 4: the network settles it
    let txid = client
        .send_raw_transaction(&hex::encode(&completed))
        .expect("the network must accept a token demand this SDK settled");
    eprintln!("  SETTLED {txid}");
    await_confirmation(&client, &txid);
}
