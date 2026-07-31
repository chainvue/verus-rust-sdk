//! Who a reserve output pays, and what that does and does not decide.
//!
//! A reserve output's destination decides **who can spend it**. It does not
//! decide **what it holds** — the token payload sits in the params chunk either
//! way. The decoder used to conflate the two: anything but a bare key hash was
//! refused outright with `a reserve output paying Identity(…) is not decoded
//! yet`, which meant an address's tokens became unreadable the moment a VerusID
//! held them. That is the ordinary shape for a minted currency, so "not decoded
//! yet" was quietly the common case.
//!
//! Separating the two questions is only safe if the *spending* half is still
//! enforced. Before, it was enforced by accident: the decode failed, so nothing
//! downstream had to think about it. Now it has to be enforced on purpose, and
//! this file pins both halves together — read it, refuse to spend it — because
//! the failure mode of getting only the first half right is a transaction that
//! nobody on earth can sign.

use verus_keys::{Address, AddressKind, PrivateKey};
use verus_tx::cc::reserve_output_script_to;
use verus_tx::{
    build_token_send, decode_output_script, token_balances, Amount, CurrencyId, Destination,
    Expiry, OutputKind, TokenRecipient, TokenSendParams, TxError, Txid, Utxo,
};

const CURRENCY: CurrencyId = CurrencyId::from_bytes([0x33; 20]);
const IDENTITY: [u8; 20] = [0x5a; 20];

fn key() -> PrivateKey {
    PrivateKey::from_bytes(&[0x11; 32], true).expect("valid key")
}

fn utxo(destination: Destination, amount: u64, vout: u32) -> Utxo {
    Utxo {
        txid: Txid::from_internal([0xcd; 32]),
        vout,
        satoshis: Amount::from_sat(0),
        script_pubkey: reserve_output_script_to(destination, CURRENCY, amount).expect("script"),
    }
}

/// Native coin to pay a fee with, so a refusal is about the token input and
/// not about an unfundable transaction.
fn native(satoshis: u64) -> Utxo {
    Utxo {
        txid: Txid::from_internal([0xef; 32]),
        vout: 0,
        satoshis: Amount::from_sat(satoshis),
        script_pubkey: key().address().p2pkh_script_pubkey().expect("p2pkh script"),
    }
}

/// Every destination kind survives decoding, including the two this crate has
/// no way to spend. Losing the kind would be worse than refusing: an identity
/// hash rendered as an `R` address names an address nobody controls.
#[test]
fn every_destination_kind_decodes_and_keeps_its_kind() {
    for destination in [
        Destination::PubKeyHash([0x11; 20]),
        Destination::Identity(IDENTITY),
        Destination::ScriptHash([0x22; 20]),
        Destination::PubKey(vec![0x02; 33]),
    ] {
        let script = reserve_output_script_to(destination.clone(), CURRENCY, 700).expect("script");
        assert_eq!(
            decode_output_script(&script).expect("decodes"),
            OutputKind::ReserveOutput {
                destination: destination.clone(),
                tokens: vec![(CURRENCY, 700)],
            },
            "{destination:?} did not round trip"
        );
    }
}

/// The point of reading them: an identity's holdings are countable.
#[test]
fn tokens_held_by_an_identity_are_counted() {
    let held = token_balances(&[utxo(Destination::Identity(IDENTITY), 900, 0)]).expect("countable");
    assert_eq!(held[&CURRENCY], Amount::from_sat(900));
}

/// And the half that used to be free. An identity's tokens are spendable only
/// with the identity's authority; this crate signs with a transparent key, so
/// selecting one as funding must fail loudly rather than build a transaction
/// with an unsatisfiable input.
#[test]
fn an_identity_held_token_is_refused_as_funding() {
    let utxos = [
        native(1_000_000),
        utxo(Destination::Identity(IDENTITY), 900, 1),
    ];
    let recipients = [TokenRecipient {
        address: key().address(),
        currency: CURRENCY,
        amount: Amount::from_sat(100),
    }];
    let params = TokenSendParams::new(&utxos, &recipients, key().address(), Expiry::Never);

    match build_token_send(&key(), &params) {
        Err(TxError::IdentityHeldFunding {
            txid,
            vout,
            identity,
        }) => {
            assert_eq!(vout, 1, "the refusal must name the output: {txid}");
            assert_eq!(identity, hex::encode(IDENTITY));
        }
        other => panic!("an identity-held token must not be selected as funding: {other:?}"),
    }
}

/// Same for the two kinds this crate has no signing path for at all. A script
/// hash needs a redeem script and a bare public key needs a different
/// scriptSig shape; both would produce inputs the network rejects.
#[test]
fn a_script_hash_or_public_key_reserve_output_is_refused_as_funding() {
    for (index, destination) in [
        Destination::ScriptHash([0x22; 20]),
        Destination::PubKey(vec![0x02; 33]),
    ]
    .into_iter()
    .enumerate()
    {
        let vout = u32::try_from(index).expect("fits") + 1;
        let utxos = [native(1_000_000), utxo(destination.clone(), 900, vout)];
        let recipients = [TokenRecipient {
            address: key().address(),
            currency: CURRENCY,
            amount: Amount::from_sat(100),
        }];
        let params = TokenSendParams::new(&utxos, &recipients, key().address(), Expiry::Never);

        match build_token_send(&key(), &params) {
            Err(TxError::UnsupportedFundingScript { vout: named, .. }) => {
                assert_eq!(named, vout, "{destination:?} named the wrong output");
            }
            other => panic!("{destination:?} must be refused as funding: {other:?}"),
        }
    }
}

/// The ordinary case still works, so the guards above are not simply refusing
/// everything.
#[test]
fn a_key_hash_reserve_output_still_funds_a_send() {
    let hash = key().address().hash();
    let utxos = [
        native(1_000_000),
        utxo(Destination::PubKeyHash(hash), 900, 1),
    ];
    let recipients = [TokenRecipient {
        address: Address::new(AddressKind::PubKeyHash, [0x77; 20]),
        currency: CURRENCY,
        amount: Amount::from_sat(100),
    }];
    let params = TokenSendParams::new(&utxos, &recipients, key().address(), Expiry::Never);
    build_token_send(&key(), &params).expect("an ordinary token send still builds");
}
