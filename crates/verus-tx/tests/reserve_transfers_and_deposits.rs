//! The last two currency-bearing shapes: eval 8 and eval 11.
//!
//! Both are real VRSCTEST scripts, and both are checked against what the daemon
//! reports for the same bytes. The transfer is the more delicate of the two: its
//! payload is seven fields deep and the destination sits in the middle, so a
//! misread of the destination does not fail where it happens — it fails several
//! fields later, on a "currency id" that is really the tail of an address.
//!
//! # The thing worth understanding about these two
//!
//! Both name the **chain's own currency** inside their payload, and both carry
//! that same value as ordinary satoshis in the output. `ReserveOutValue` erases
//! it before returning, and so does [`verus_tx::token_balances`]. On both of
//! these vectors the erase is what takes the answer to empty — which means a
//! decoder that reported the payload as a token balance would not be slightly
//! wrong, it would report the whole output twice.

use verus_keys::Address;
use verus_tx::{
    decode_output_script, root_namespace, token_balances, Amount, CurrencyId, Destination,
    OutputKind, Txid, Utxo,
};

/// Output 1 of `18273a8f0722753c3103d7fd253c32985ee5047b97aea85f271d822a0a974bf3`,
/// block 1170450 — a reserve-to-reserve conversion.
const TRANSFER: &str = "1a040300010114cb8a0f7f651b484a81e2312c3438deb601e27368cc4ca4040308010114\
                        cb8a0f7f651b484a81e2312c3438deb601e273684c8801a6ef9ea235635e328124ff3429\
                        db9f9e91b64e2d81b4e1318703a6ef9ea235635e328124ff3429db9f9e91b64e2d809b2a\
                        42144fad5a983b2b714651afe2e40a9e0a7d498bfdd7011602143d74453766227cfd9c04\
                        49e83184ae4912b0d5cb6d4a9a7ef695f4f2a35a49c9f232beb5cc9b964ac0bfd996f371\
                        6d9d397db9b1070756b4d8ac9a5a75";

/// The output's own satoshi value, from `getrawtransaction`.
const TRANSFER_VALUE: u64 = 5_095_259;

/// Output 0 of `1b6817f2b573afefbed5d3eb7c10576765a4a9eb86ea256baffcb2aebb3633dc`,
/// block 1170449.
const DEPOSIT: &str = "2704030001012103b99d7cb946c5b1f8a54cde49b8d7e0a2a15a22639feb798009f82b519\
                       526c050cc4c5504030b01012103b99d7cb946c5b1f8a54cde49b8d7e0a2a15a22639feb79\
                       8009f82b519526c0502d01a6ef9ea235635e328124ff3429db9f9e91b64e2d81b5fd5f6d4\
                       a9a7ef695f4f2a35a49c9f232beb5cc9b964a75";

const DEPOSIT_VALUE: u64 = 5_095_263;

fn script(padded: &str) -> Vec<u8> {
    hex::decode(padded.replace([' ', '\n'], "")).expect("a real script")
}

fn currency(address: &str) -> CurrencyId {
    CurrencyId::from_bytes(address.parse::<Address>().expect("i-address").hash())
}

fn key_hash(address: &str) -> Destination {
    Destination::PubKeyHash(address.parse::<Address>().expect("R address").hash())
}

fn native() -> CurrencyId {
    root_namespace("VRSCTEST").expect("root")
}

fn utxo(script_pubkey: Vec<u8>, satoshis: u64, vout: u32) -> Utxo {
    Utxo {
        txid: Txid::from_internal([0x31; 32]),
        vout,
        satoshis: Amount::from_sat(satoshis),
        script_pubkey,
    }
}

/// Every field, against the daemon's `reservetransfer` object for the same
/// output. The two currency slots are the trap: for a reserve-to-reserve
/// conversion the daemon prints the serialized `destCurrencyID` as `via` and
/// the *second* reserve as `destinationcurrencyid`, which is the opposite way
/// round from the bytes.
#[test]
fn a_real_reserve_transfer_decodes_field_for_field() {
    let decoded = decode_output_script(&script(TRANSFER)).expect("decodes");
    let OutputKind::ReserveTransfer {
        destination,
        transfer,
    } = decoded
    else {
        panic!("expected a reserve transfer, got {decoded:?}");
    };

    // Paid to the protocol's transfer address, not to a recipient.
    assert_eq!(destination, key_hash("RTqQe58LSj2yr5CrwYFwcsAQ1edQwmrkUU"));

    assert_eq!(transfer.flags, 1027, "VALID | CONVERT | RESERVE_TO_RESERVE");
    assert_eq!(
        transfer.tokens,
        vec![(currency("iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq"), 5_075_249)]
    );
    assert_eq!(
        transfer.fee_currency,
        currency("iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq")
    );
    assert_eq!(transfer.fees, 20_010);

    assert_eq!(
        transfer.destination.recipient,
        key_hash("RGYV8WX9ykrCUZz9VgPAdaRV1aqGDnhz5j")
    );
    assert_eq!(
        transfer.destination.auxiliary,
        vec![key_hash("REt8apovRu1QQrFoUn2uDYsT4oLjh1WCcs")],
        "the refund address"
    );
    assert!(transfer.destination.gateway.is_none(), "no bridge leg");

    // Serialized order, which the daemon labels `via`.
    assert_eq!(
        transfer.destination_currency,
        currency("iDSQTXbRNjSfXvQf9q9rHZy51x3CNSypBM")
    );
    // And what the daemon labels `destinationcurrencyid`.
    assert_eq!(
        transfer.second_reserve,
        Some(currency("iM3gzspfspD8SqsNpHSaVJA2BZQrbTc7TL"))
    );
    assert_eq!(transfer.destination_system, None, "not cross-system");
}

/// What the output *holds*, which is not what its payload lists.
///
/// `TotalCurrencyOut` is the transferred amount plus the fee, and the erase of
/// the chain's own currency then takes it to nothing — because every satoshi of
/// it is already in the output's value field. The arithmetic is checked against
/// that field rather than asserted: 5,075,249 + 20,010 is exactly the
/// 5,095,259 the output carries.
#[test]
fn a_reserve_transfers_value_is_its_satoshis_and_not_a_token() {
    let decoded = decode_output_script(&script(TRANSFER)).expect("decodes");
    let OutputKind::ReserveTransfer { transfer, .. } = decoded else {
        panic!("expected a reserve transfer");
    };

    assert_eq!(
        transfer.tokens[0].1 + transfer.fees,
        TRANSFER_VALUE,
        "amount plus fee is the output's satoshi value, which is why the erase is right"
    );

    assert!(
        transfer
            .reserve_value(native())
            .expect("computable")
            .is_empty(),
        "every currency here is the chain's own"
    );
    assert!(
        token_balances(&[utxo(script(TRANSFER), TRANSFER_VALUE, 1)], Some(native()))
            .expect("countable")
            .is_empty()
    );
}

/// And the same for a deposit, whose payload is a token output followed by the
/// currency whose reserves it holds.
#[test]
fn a_real_reserve_deposit_decodes_and_counts_as_nothing() {
    let decoded = decode_output_script(&script(DEPOSIT)).expect("decodes");
    let OutputKind::ReserveDeposit {
        controlling_currency,
        tokens,
        ..
    } = decoded
    else {
        panic!("expected a reserve deposit, got {decoded:?}");
    };

    assert_eq!(
        controlling_currency,
        currency("iDSQTXbRNjSfXvQf9q9rHZy51x3CNSypBM")
    );
    assert_eq!(
        tokens,
        vec![(
            currency("iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq"),
            DEPOSIT_VALUE
        )],
        "the payload names the chain's own currency, for the same value the output carries"
    );

    assert!(
        token_balances(&[utxo(script(DEPOSIT), DEPOSIT_VALUE, 0)], Some(native()))
            .expect("countable")
            .is_empty()
    );
}

/// Without `native` neither can be counted, and the refusal has to say so
/// rather than guess. This is the behaviour these two had before they could be
/// decoded at all, preserved exactly.
#[test]
fn neither_is_counted_without_the_chains_own_currency() {
    for (label, hex, value) in [
        ("transfer", TRANSFER, TRANSFER_VALUE),
        ("deposit", DEPOSIT, DEPOSIT_VALUE),
    ] {
        match token_balances(&[utxo(script(hex), value, 0)], None) {
            Err(verus_tx::TxError::UncountableOutput { reason, txid, .. }) => {
                assert!(txid.starts_with("3131"), "{label}: {txid}");
                assert!(
                    reason.contains("native"),
                    "{label}: the refusal must say what is missing: {reason}"
                );
            }
            other => panic!("{label} must be refused without `native`: {other:?}"),
        }
    }
}

/// A wrong `native` must not silently produce a wrong answer — it produces a
/// *different* one, and this pins which. Told the chain is something else, the
/// erase does not fire and the payload's own currency shows up as a token.
/// That is the double count the parameter exists to prevent, made visible.
#[test]
fn the_wrong_native_currency_is_what_double_counting_looks_like() {
    let wrong = currency("iM3gzspfspD8SqsNpHSaVJA2BZQrbTc7TL");
    let held = token_balances(&[utxo(script(DEPOSIT), DEPOSIT_VALUE, 0)], Some(wrong))
        .expect("still countable");
    assert_eq!(
        held[&currency("iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq")],
        Amount::from_sat(DEPOSIT_VALUE),
        "the output's satoshis reappear as a token, which is exactly the bug"
    );
}

/// Encoder and decoder must agree, on the shapes this crate itself writes.
///
/// The golden vectors already prove the encoder matches the daemon; this proves
/// the reader is the same reader, so a change to either side that breaks the
/// pair fails here rather than on chain.
#[test]
fn what_this_crate_writes_it_can_read_back() {
    use verus_tx::convert::{ConversionKind, ReserveTransfer, TransferDestination};

    let source = currency("iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq");
    let fractional = currency("iDSQTXbRNjSfXvQf9q9rHZy51x3CNSypBM");
    let recipient = key_hash("RGYV8WX9ykrCUZz9VgPAdaRV1aqGDnhz5j");

    for kind in [
        ConversionKind::IntoFractional { fractional },
        ConversionKind::Burn,
        ConversionKind::ReserveToReserve {
            via: fractional,
            target: currency("iM3gzspfspD8SqsNpHSaVJA2BZQrbTc7TL"),
        },
    ] {
        let built = ReserveTransfer {
            source,
            amount: Amount::from_sat(123_456),
            kind: kind.clone(),
            fee_currency: source,
            fee: Amount::from_sat(20_010),
            destination: TransferDestination::converting(recipient.clone()),
        };
        let script = built.to_script().expect("script");

        let OutputKind::ReserveTransfer { transfer, .. } =
            decode_output_script(&script).expect("decodes")
        else {
            panic!("{kind:?} did not decode as a reserve transfer");
        };
        assert_eq!(transfer.tokens, vec![(source, 123_456)], "{kind:?}");
        assert_eq!(transfer.fees, 20_010, "{kind:?}");
        assert_eq!(transfer.destination.recipient, recipient, "{kind:?}");
        assert_eq!(
            transfer.destination.auxiliary,
            vec![recipient.clone()],
            "{kind:?}"
        );
    }
}

/// A destination type this crate cannot read is refused rather than reported as
/// the wrong party. The daemon defines several — full identities, currency
/// registrations, Ethereum addresses — each with its own body format.
#[test]
fn an_unknown_destination_type_is_refused() {
    // Type 9 is DEST_ETH, whose body is 20 bytes but means something else.
    let mut payload = script(TRANSFER);
    let position = payload
        .windows(2)
        .position(|w| w == [0x42, 0x14])
        .expect("the destination type byte and its length");
    payload[position] = 9;
    assert!(
        decode_output_script(&payload).is_err(),
        "an Ethereum destination must not be read as an R address"
    );
}
