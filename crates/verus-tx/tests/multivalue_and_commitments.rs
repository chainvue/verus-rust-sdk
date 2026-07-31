//! The two output shapes that were refused once everything else was countable.
//!
//! Both were invisible until [`verus_tx::token_balances`] stopped refusing
//! stakers and identity-held tokens — they were behind an earlier refusal, so
//! nothing had ever reached them. Running a balance for a real VRSCTEST
//! staker's identity surfaced both in one go.
//!
//! Both vectors here are **real on-chain scripts**, and both are checked
//! against what the daemon says the same bytes mean. That matters more than
//! usual: the failure mode of misreading a currency map is not an exception,
//! it is a balance in a currency that does not exist, reported confidently.

use std::collections::BTreeMap;

use verus_keys::{Address, AddressKind};
use verus_tx::{
    data_key, decode_output_script, root_namespace, token_balances, Amount, CurrencyId,
    Destination, OutputKind, TxError, Txid, Utxo, ADVANCED_COMMITMENT_KEY,
};

/// Output 10 of `9d0859212eb5dd5bbcd5d8a171e8e0080e16d5629ed84bd596573aae9b086443`
/// on VRSCTEST — a reserve output held by `i4hbUHjZ32qWJdWNiMM2dsdz26E4xpFqSs`
/// carrying nine currencies at once, in the `VERSION_MULTIVALUE` encoding.
const MULTIVALUE: &str = "1b040300010115040d70e777403b2fa1e52b09853be00beb8ac88762cc4d2001040309\
                          010115040d70e777403b2fa1e52b09853be00beb8ac887624d020186fefeff01094\
                          4a25b3d593e0bb4f0b700b98d3c625c891a61bf00076b7a070700004aa2555d465e\
                          133e03c7e084177b21d3237371710048c66fefa00a006ac68d215ec4da6375ca23b\
                          89f211c810881b83a0048c66fefa00a0074c096ce2c9a09f237b0b512cfe3e71579\
                          ab03b70048c66fefa00a0084d881e355c1c87dd84baa2e068dc3829e140d3c00785\
                          62014b10000c0bfd996f3716d9d397db9b1070756b4d8ac9a5a0088e1b24c090100\
                          ca1753f4d2f16990d8db6e7972525daf603609640048c66fefa00a00d173589004f\
                          1ddb99fcd6952f84c148d45407309000814fd1d000000e5548cd120855cfb556307\
                          543f86d63d0fec02b500f47cab871a000075";

/// Output 0 of `3a6f6a02f2fb74dc16a5e9d49cb02966100a72656acd30d9c28d5eae554edaca`
/// on VRSCTEST — an ordinary name commitment, which the daemon reports with an
/// empty `currencyvalues`.
const COMMITMENT: &str = "1b040300010115040d70e777403b2fa1e52b09853be00beb8ac88762cc3c04031101\
                          0115040d70e777403b2fa1e52b09853be00beb8ac8876220089ce908e263013785c\
                          59404a6b88c47e30e52e32dedde094f8c5ade74ebb9ed75";

/// `getrawtransaction` verbosity 1, `reserveoutput.currencyvalues`, converted
/// from coins to satoshis. Nine entries, and every one has to match — a
/// misread of the amount width would shift the whole map, not lose one entry.
const DAEMON_VALUES: &[(&str, u64)] = &[
    ("i9jRsqnfMnQmGc3LJnMt9Z6T4CoDkv6Q9o", 7_728_700_000_000),
    ("iAH9uQ4GnREmbpVKd1fU9zrePte3odZGFd", 2_991_700_000_000_000),
    ("iDD6uzji8SpCvHs3hgq9Z4tKqr9CKrL73S", 2_991_700_000_000_000),
    ("iE7rXeqXV6ec93heNqZ35xcswZ8yzHoQQw", 2_991_700_000_000_000),
    ("iFawzbS99RqGs7J2TNxME1TmmayBGuRkA2", 194_700_000_000_000),
    ("iM3gzspfspD8SqsNpHSaVJA2BZQrbTc7TL", 291_700_000_000_000),
    ("iMu5sgTiGcaWryiwGwNTWcHxQo589xMXK8", 2_991_700_000_000_000),
    ("iNZzqYdmfCPCcVSTBjbPT8Q7rqeFohxATu", 128_800_000_000),
    ("iQP7TeWNDNsF7aaaCkQzNyS4jDjdKncNWf", 29_170_000_000_000),
];

/// The identity that holds both outputs.
const HOLDER: &str = "i4hbUHjZ32qWJdWNiMM2dsdz26E4xpFqSs";

fn script(hex_with_indent: &str) -> Vec<u8> {
    hex::decode(hex_with_indent.replace([' ', '\n'], "")).expect("a real script")
}

fn identity(address: &str) -> Destination {
    Destination::Identity(address.parse::<Address>().expect("i-address").hash())
}

fn utxo(script_pubkey: Vec<u8>, vout: u32) -> Utxo {
    Utxo {
        txid: Txid::from_internal([0x42; 32]),
        vout,
        satoshis: Amount::ZERO,
        script_pubkey,
    }
}

/// The whole point: nine currencies out of one output, agreeing with the
/// daemon entry for entry.
#[test]
fn a_multi_currency_reserve_output_reads_exactly_what_the_daemon_reports() {
    let decoded = decode_output_script(&script(MULTIVALUE)).expect("decodes");
    let OutputKind::ReserveOutput {
        destination,
        tokens,
    } = decoded
    else {
        panic!("expected a reserve output, got {decoded:?}");
    };
    assert_eq!(destination, identity(HOLDER));

    let read: BTreeMap<String, u64> = tokens
        .iter()
        .map(|(currency, amount)| {
            (
                Address::new(AddressKind::Identity, currency.to_bytes()).to_string(),
                *amount,
            )
        })
        .collect();
    let expected: BTreeMap<String, u64> = DAEMON_VALUES
        .iter()
        .map(|(id, amount)| ((*id).to_string(), *amount))
        .collect();
    assert_eq!(read, expected);
}

/// And it must reach a balance, which is what failed before: this address got
/// `unsupported TokenOutput version 2147483649` instead of a number.
#[test]
fn a_multi_currency_output_is_countable() {
    let held = token_balances(&[utxo(script(MULTIVALUE), 10)]).expect("countable");
    assert_eq!(held.len(), DAEMON_VALUES.len());
    for (id, amount) in DAEMON_VALUES {
        let currency = CurrencyId::from_bytes(id.parse::<Address>().expect("i-address").hash());
        assert_eq!(held[&currency], Amount::from_sat(*amount), "{id}");
    }
}

/// An ordinary name commitment: a 32-byte hash and nothing else. It reaches a
/// balance now instead of refusing one, and it reports no currency because it
/// *has* none — read, not assumed.
#[test]
fn an_ordinary_name_commitment_decodes_and_holds_nothing() {
    let decoded = decode_output_script(&script(COMMITMENT)).expect("decodes");
    let OutputKind::IdentityCommitment {
        destination,
        commitment,
        tokens,
    } = decoded
    else {
        panic!("expected a name commitment, got {decoded:?}");
    };
    assert_eq!(destination, identity(HOLDER));
    assert_eq!(
        hex::encode(commitment),
        "089ce908e263013785c59404a6b88c47e30e52e32dedde094f8c5ade74ebb9ed",
        "the daemon prints this reversed; these are the bytes in the script"
    );
    assert!(tokens.is_empty(), "the daemon reports currencyvalues: {{}}");

    assert!(token_balances(&[utxo(script(COMMITMENT), 0)])
        .expect("countable")
        .is_empty());
}

/// The sentinel that decides whether a commitment carries currency, re-derived
/// rather than trusted. A wrong transcription would read every advanced
/// commitment as an ordinary one and lose whatever it holds — silently, since
/// the ordinary form is the one that parses cleanly.
#[test]
fn the_advanced_commitment_key_is_the_one_the_daemon_issues() {
    let derived = data_key(
        "system.identity.advancedcommitmenthash",
        root_namespace("vrsc").expect("root"),
        "VRSCTEST",
    )
    .expect("derives");
    assert_eq!(derived, ADVANCED_COMMITMENT_KEY);
    assert_eq!(
        Address::new(AddressKind::Identity, derived).to_string(),
        // `getvdxfid "vrsc::system.identity.advancedcommitmenthash"`.
        "i74sHfYTqdfd5ZSmQSLHug4GuX2XHKwA7Y"
    );
}

/// The advanced form, built by hand because no such output exists on VRSCTEST
/// to copy. Its shape is fully determined by `CCommitmentHash::SerializationOp`
/// — hash, then a `CTokenOutput` if and only if the hash starts with the key —
/// so the thing worth pinning is that the branch is actually taken.
#[test]
fn an_advanced_commitment_carries_its_token_output() {
    let currency = CurrencyId::from_bytes([0x33; 20]);
    let mut payload = [0u8; 32];
    payload[..20].copy_from_slice(&ADVANCED_COMMITMENT_KEY);
    payload[20..].copy_from_slice(&[0xab; 12]);

    let mut vdata = payload.to_vec();
    // A single-value CTokenOutput: version 1, currency, VARINT amount. The
    // amount bytes are lifted from the golden reserve output rather than
    // hand-derived — VARINT is not CompactSize and writing one from memory is
    // how you get a test that agrees with your mistake.
    vdata.push(1);
    vdata.extend_from_slice(&currency.to_bytes());
    vdata.extend_from_slice(&[0x92, 0x88, 0xb3, 0x00]); // 40_000_000

    let script = verus_tx::cc::cc_script(
        &verus_tx::cc::OptCcParams::one_of_one(0, Destination::PubKeyHash([0x11; 20])),
        &verus_tx::cc::OptCcParams {
            vdata: vec![vdata],
            ..verus_tx::cc::OptCcParams::one_of_one(17, Destination::PubKeyHash([0x11; 20]))
        },
    )
    .expect("script");

    match decode_output_script(&script).expect("decodes") {
        OutputKind::IdentityCommitment {
            commitment, tokens, ..
        } => {
            assert_eq!(commitment, payload);
            assert_eq!(tokens, vec![(currency, 40_000_000)]);
        }
        other => panic!("expected an advanced commitment, got {other:?}"),
    }
    assert_eq!(
        token_balances(&[utxo(script, 0)]).expect("countable")[&currency],
        Amount::from_sat(40_000_000)
    );
}

/// Data after the hash **without** the sentinel is refused rather than read as
/// a token output. Guessing here would invent a balance out of whatever bytes
/// happened to follow.
#[test]
fn a_commitment_with_unexplained_trailing_data_is_refused() {
    let mut vdata = vec![0x77; 32];
    vdata.extend_from_slice(&[1, 0x33]);
    let script = verus_tx::cc::cc_script(
        &verus_tx::cc::OptCcParams::one_of_one(0, Destination::PubKeyHash([0x11; 20])),
        &verus_tx::cc::OptCcParams {
            vdata: vec![vdata],
            ..verus_tx::cc::OptCcParams::one_of_one(17, Destination::PubKeyHash([0x11; 20]))
        },
    )
    .expect("script");
    assert!(matches!(
        decode_output_script(&script),
        Err(TxError::MalformedCryptoCondition(_))
    ));
}

/// A currency map is caller-supplied bytes. Three ways it can lie, all of
/// which must be errors rather than a number.
#[test]
fn a_hostile_currency_map_is_refused_rather_than_believed() {
    let holder = Destination::PubKeyHash([0x11; 20]);
    let build = |map: Vec<u8>| {
        let mut vdata = vec![0x86, 0xfe, 0xfe, 0xff, 0x01]; // VERSION_MULTIVALUE | 1
        vdata.extend_from_slice(&map);
        verus_tx::cc::cc_script(
            &verus_tx::cc::OptCcParams::one_of_one(0, holder.clone()),
            &verus_tx::cc::OptCcParams {
                vdata: vec![vdata],
                ..verus_tx::cc::OptCcParams::one_of_one(9, holder.clone())
            },
        )
        .expect("script")
    };

    // A count far larger than the bytes that follow. Must not allocate for it.
    let mut huge = vec![0xff];
    huge.extend_from_slice(&u64::MAX.to_le_bytes());
    assert!(decode_output_script(&build(huge)).is_err(), "absurd count");

    // A negative amount. `CAmount` is signed; this crate's `Amount` is not,
    // and reinterpreting it as a huge positive number is the worst answer.
    let mut negative = vec![0x01];
    negative.extend_from_slice(&[0x33; 20]);
    negative.extend_from_slice(&(-1i64).to_le_bytes());
    match decode_output_script(&build(negative)) {
        Err(TxError::MalformedCryptoCondition(reason)) => {
            assert!(reason.contains("negative"), "{reason}");
        }
        other => panic!("a negative amount must be refused: {other:?}"),
    }

    // A non-canonical CompactSize: `fd 01 00` for 1. Two byte strings must not
    // decode to the same output.
    let mut sloppy = vec![0xfd, 0x01, 0x00];
    sloppy.extend_from_slice(&[0x33; 20]);
    sloppy.extend_from_slice(&1i64.to_le_bytes());
    assert!(
        decode_output_script(&build(sloppy)).is_err(),
        "non-canonical CompactSize"
    );
}
