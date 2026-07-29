//! Golden bytes for every VerusID operation, so a refactor cannot change them
//! silently.
//!
//! # Why these exist
//!
//! Each operation below was proven by a transaction a Verus daemon accepted on
//! VRSCTEST — the txid is recorded with each case. That evidence is real but it
//! is also spent: nothing in the repository would notice if a refactor changed
//! the bytes tomorrow, and the next signal would be a rejected broadcast, after
//! a fee had been paid and, for a registration, after a name commitment had been
//! consumed.
//!
//! These pin the bytes instead. They are built from fixed synthetic inputs with
//! the public test key, so they need no network, no funds and no secrets — RFC
//! 6979 signing makes them exactly reproducible. They do **not** re-prove
//! consensus agreement; they prove the code still produces what consensus
//! already accepted.
//!
//! # When one of these fails
//!
//! Assume the change is wrong until shown otherwise. Every byte here encodes
//! something a daemon checks: an eval code, a serialization layout, an output
//! ordering, a fee split. If a change is deliberate, the new bytes need a fresh
//! daemon acceptance before the golden is updated — not the other way round.

use verus_keys::{Address, PrivateKey};
use verus_tx::cc::Destination;
use verus_tx::identity::{Identity, FLAG_REVOKED};
use verus_tx::register::{
    build_identity_registration, build_name_commitment, identity_id, CommitmentParams,
    NameReservation, ParentCurrencyFee, RegistrationParams,
};
use verus_tx::revoke::{
    build_identity_recovery, build_identity_revocation, RecoveryParams, RevocationParams,
};
use verus_tx::update::{build_identity_update, UpdateParams};
use verus_tx::CurrencyId;
use verus_tx::{Amount, Expiry, Txid, Utxo};

/// The public test key used across this repository. It holds nothing.
const TEST_WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";
/// A second key, for the multisig cases.
const CO_SIGNER: [u8; 32] = [0x27; 32];
/// `VRSCTEST`, the system every case here parents to.
const VRSCTEST: &str = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";
/// A fixed salt. Real registrations must use a CSPRNG; a golden must not.
const SALT: [u8; 32] = [0x5a; 32];

fn key() -> PrivateKey {
    PrivateKey::from_wif(TEST_WIF).unwrap()
}

fn co_signer() -> PrivateKey {
    PrivateKey::from_bytes(&CO_SIGNER, true).unwrap()
}

fn chain() -> [u8; 20] {
    VRSCTEST.parse::<Address>().unwrap().hash()
}

fn funding(satoshis: u64) -> Utxo {
    Utxo {
        txid: Txid::from_internal([0xf0; 32]),
        vout: 0,
        satoshis: Amount::from_sat(satoshis),
        script_pubkey: key().address().p2pkh_script_pubkey().unwrap(),
    }
}

fn reservation(name: &str, parent: [u8; 20], referral: Option<[u8; 20]>) -> NameReservation {
    NameReservation::new(name, parent, referral, SALT).unwrap()
}

/// The commitment output for `reservation`, as step 2 would spend it.
fn commitment_utxo(reservation: &NameReservation) -> Utxo {
    Utxo {
        txid: Txid::from_internal([0xc0; 32]),
        vout: 0,
        satoshis: Amount::ZERO,
        script_pubkey: verus_tx::register::commitment_script(
            &reservation.commitment_hash().unwrap(),
            key().address().hash(),
        )
        .unwrap(),
    }
}

fn identity(
    name: &str,
    primaries: Vec<Destination>,
    min_sigs: u32,
    authority: [u8; 20],
) -> Identity {
    Identity {
        version: 3,
        flags: 0,
        primary_addresses: primaries,
        min_sigs,
        parent: chain(),
        name: name.to_string(),
        content_multimap: Vec::new(),
        content_map: Vec::new(),
        revocation_authority: authority,
        recovery_authority: authority,
        private_addresses: Vec::new(),
        system_id: chain(),
        unlock_after: 0,
    }
}

fn identity_utxo(identity: &Identity) -> Utxo {
    Utxo {
        txid: Txid::from_internal([0x1d; 32]),
        vout: 0,
        satoshis: Amount::ZERO,
        script_pubkey: verus_tx::identity_primary_script(
            identity_id(&identity.name, Some(identity.parent)),
            identity.to_bytes().unwrap(),
            identity.revocation_authority,
            identity.recovery_authority,
        )
        .unwrap(),
    }
}

/// Compare against the golden, printing the actual bytes when it differs so a
/// deliberate change can be inspected before being accepted.
fn assert_golden(name: &str, actual: &str, expected: &str) {
    assert_eq!(
        actual, expected,
        "\n{name}: transaction bytes changed.\n\
         If this was deliberate, the new bytes need a daemon to accept them \
         before this golden is updated.\nactual: {actual}\n"
    );
}

/// Step 1 of registration. Proven on chain as
/// fbfbd336f856b6f32c1414adfb4fb67fb289246e292cae4968c557e60fdbdfdb.
#[test]
fn name_commitment() {
    let reservation = reservation("rustsdk", chain(), None);
    let utxos = [funding(150_000_000_000)];
    let signed = build_name_commitment(
        &key(),
        &CommitmentParams::new(&utxos, &reservation, key().address(), Expiry::Never),
    )
    .unwrap();
    assert_golden("name_commitment", &signed.hex, GOLDEN_COMMITMENT);
}

/// Step 2, unreferred. Proven on chain as
/// c5587f4cac06ba48892aa8a5aa90d3b80e9317a5b364a8479f5b96626214fd8f, which
/// created rustsdk.VRSCTEST@ at block 1166555.
#[test]
fn registration() {
    let reservation = reservation("rustsdk", chain(), None);
    let commitment = commitment_utxo(&reservation);
    let utxos = [funding(150_000_000_000)];
    let primaries = [key().address()];
    let registered = build_identity_registration(
        &key(),
        &RegistrationParams::new(
            &commitment,
            &reservation,
            &utxos,
            &primaries,
            chain(),
            100_00000000,
            key().address(),
            Expiry::Never,
        )
        .with_referrals(3, &[]),
    )
    .unwrap();
    assert_golden(
        "registration",
        &registered.transaction.hex,
        GOLDEN_REGISTRATION,
    );
}

/// A referral pays the referrer fee/(levels+2) and costs the registrant
/// fee*(levels+1)/(levels+2). Proven on chain as
/// 0463960881f979b99c9228f368f29d1a81ccbe153c6ab617a98686eb226b13c0, which paid
/// 20 VRSCTEST to rustsdk@ at block 1167099.
#[test]
fn referred_registration() {
    let referrer = identity_id("rustsdk", Some(chain()));
    let reservation = reservation("rustref02", chain(), Some(referrer));
    let commitment = commitment_utxo(&reservation);
    let utxos = [funding(150_000_000_000)];
    let primaries = [key().address()];
    let registered = build_identity_registration(
        &key(),
        &RegistrationParams::new(
            &commitment,
            &reservation,
            &utxos,
            &primaries,
            chain(),
            100_00000000,
            key().address(),
            Expiry::Never,
        )
        .with_referrals(3, &[]),
    )
    .unwrap();
    assert_golden(
        "referred_registration",
        &registered.transaction.hex,
        GOLDEN_REFERRED,
    );
}

/// A referrer who was **itself** referred is paid too, one output per level up
/// the chain. Confirmed against a `registeridentity` the daemon built on
/// VRSCTEST for a name referred by `rustref02@`, which `rustsdk@` had referred:
/// two 20.0 payouts, 40 burned, and a registrant outlay of 80 — the same 80 as
/// a depth-1 referral, because the outlay does not depend on the depth. What
/// changes is the split between referrers and the burn.
#[test]
fn referral_chain_pays_every_level() {
    let direct = identity_id("rustref02", Some(chain()));
    let indirect = identity_id("rustsdk", Some(chain()));
    let reservation = reservation("rustdepth01", chain(), Some(direct));
    let commitment = commitment_utxo(&reservation);
    let utxos = [funding(150_000_000_000)];
    let primaries = [key().address()];
    // Nearest referrer first, then up. The SDK cannot walk this itself: each
    // link lives in the previous referrer's on-chain identity.
    let chain_up = [direct, indirect];
    let registered = build_identity_registration(
        &key(),
        &RegistrationParams::new(
            &commitment,
            &reservation,
            &utxos,
            &primaries,
            chain(),
            100_00000000,
            key().address(),
            Expiry::Never,
        )
        .with_referrals(3, &chain_up),
    )
    .unwrap();

    // 80 outlay: 40 to the two referrers, 40 burned. The fee this reports is the
    // burn plus the miner fee, the payouts being outputs in their own right.
    let miner_fee = registered.transaction.fee.to_sat() - 40_00000000;
    assert!(miner_fee < 100_000, "miner fee {miner_fee} is implausible");
    assert_golden(
        "referral_chain_pays_every_level",
        &registered.transaction.hex,
        GOLDEN_REFERRAL_DEPTH,
    );
}

/// A sub-identity pays its fee in the PARENT's currency and burns the parent's
/// import fee natively. Proven on chain as
/// 4e746e10d67c9815e46b9bdb0ac3ec7fd41d432fa76b1f9895ce66ec7b560b45, which
/// created rustsub02.ownora-nft@ at block 1167146.
#[test]
fn sub_identity_registration() {
    // A stand-in parent currency; the layout does not depend on which.
    let parent = [0x9a; 20];
    let reservation = reservation("rustsub02", parent, None);
    let commitment = commitment_utxo(&reservation);
    let utxos = [funding(150_000_000_000)];
    let token = Utxo {
        txid: Txid::from_internal([0x70; 32]),
        vout: 0,
        satoshis: Amount::ZERO,
        script_pubkey: verus_tx::cc::reserve_output_script(
            key().address().hash(),
            CurrencyId::of_identity(parent),
            3_00000000,
        )
        .unwrap(),
    };
    let token_funding = [token];
    let primaries = [key().address()];
    let registered = build_identity_registration(
        &key(),
        &RegistrationParams::new(
            &commitment,
            &reservation,
            &utxos,
            &primaries,
            chain(),
            0,
            key().address(),
            Expiry::Never,
        )
        .with_parent_currency(ParentCurrencyFee {
            fee: 1_00000000,
            native_import_fee: 2_000_000,
            token_funding: &token_funding,
            proof_protocol: 2,
        }),
    )
    .unwrap();
    assert_golden(
        "sub_identity_registration",
        &registered.transaction.hex,
        GOLDEN_SUB_ID,
    );
}

/// Publishing content. Proven on chain as
/// bea8a8462ac2ee34272f29ebe034fd7f5a43529ac023c17440db5e41b4f00767 at block
/// 1166566.
#[test]
fn update_publishing_content() {
    let current = identity(
        "rustsdk",
        vec![Destination::PubKeyHash(key().address().hash())],
        1,
        identity_id("rustsdk", Some(chain())),
    );
    let held = identity_utxo(&current);
    let mut proposed = current.clone();
    proposed.content_map = vec![([0x11; 20], [0x22; 32])];
    let utxos = [funding(140_000_000_000)];
    let signed = build_identity_update(
        &key(),
        &[&key()],
        &UpdateParams::new(&held, &proposed, &utxos, key().address(), Expiry::Never),
    )
    .unwrap();
    assert_golden("update_publishing_content", &signed.hex, GOLDEN_UPDATE);
}

/// An m-of-n condition takes m signatures in ONE fulfillment. Proven on chain as
/// 9ff188d8fabbb338d11ed1405345783265a02c3afc8b5705ccd9d35e0d802303 at block
/// 1166732.
#[test]
fn multisig_update() {
    let current = identity(
        "rustmulti",
        vec![
            Destination::PubKeyHash(key().address().hash()),
            Destination::PubKeyHash(co_signer().address().hash()),
        ],
        2,
        identity_id("rustmulti", Some(chain())),
    );
    let held = identity_utxo(&current);
    let mut proposed = current.clone();
    proposed.content_map = vec![([0x33; 20], [0x44; 32])];
    let utxos = [funding(130_000_000_000)];
    let signed = build_identity_update(
        &key(),
        &[&key(), &co_signer()],
        &UpdateParams::new(&held, &proposed, &utxos, key().address(), Expiry::Never),
    )
    .unwrap();
    assert_golden("multisig_update", &signed.hex, GOLDEN_MULTISIG_UPDATE);
}

/// Revocation sets FLAG_REVOKED and changes nothing else. Proven on chain as
/// 0acf6faf864c6b7d4e846073ae4bbca7858719955c98d86bb0877345ce546342 at block
/// 1167197.
#[test]
fn revocation() {
    // Recovery must point at another identity or revocation is refused.
    let current = identity(
        "rustrevoke01",
        vec![Destination::PubKeyHash(key().address().hash())],
        1,
        identity_id("rustsdk", Some(chain())),
    );
    let held = identity_utxo(&current);
    let utxos = [funding(112_000_000_000)];
    let signed = build_identity_revocation(
        &key(),
        &[&key()],
        &RevocationParams::new(&held, &utxos, key().address(), Expiry::Never),
    )
    .unwrap();
    assert_golden("revocation", &signed.hex, GOLDEN_REVOCATION);
}

/// Recovery clears the flag and may replace the primary addresses — the point of
/// it. Proven on chain as
/// 088db56d780cb943f888f0bd98329764ee4e1f6467c18f2d506cc94f12e9179d at block
/// 1167199, which brought the identity back under a different key.
#[test]
fn recovery() {
    let mut revoked = identity(
        "rustrevoke01",
        vec![Destination::PubKeyHash(key().address().hash())],
        1,
        identity_id("rustsdk", Some(chain())),
    );
    revoked.flags |= FLAG_REVOKED;
    let held = identity_utxo(&revoked);

    let mut recovered = revoked.clone();
    recovered.flags &= !FLAG_REVOKED;
    recovered.primary_addresses = vec![Destination::PubKeyHash(co_signer().address().hash())];

    let utxos = [funding(112_000_000_000)];
    let signed = build_identity_recovery(
        &key(),
        &[&key()],
        &RecoveryParams::new(&held, &recovered, &utxos, key().address(), Expiry::Never),
    )
    .unwrap();
    assert_golden("recovery", &signed.hex, GOLDEN_RECOVERY);
}

const GOLDEN_COMMITMENT: &str = "0400008085202f8901f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0000000006b483045022100b59ab0ac362cecac4989ecee5fef681dc654cf5f2266f758f267be07e1fb804b02201ff2c2c262a3ff70b3863ee9b49f1e2bde2077fe0a2a4cd025a25c4355e973b10121026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57beaffffffff020000000000000000591a040300010114aabfb6281561808fe200ab7e186f0e3e0e82b381cc3b040311010114aabfb6281561808fe200ab7e186f0e3e0e82b38120b084c5925513c3966c01e796b9e21d04764c490796e1253fc83965bda8afea0475f034b2ec220000001976a914aabfb6281561808fe200ab7e186f0e3e0e82b38188ac00000000000000000000000000000000000000";
const GOLDEN_REGISTRATION: &str = "0400008085202f8902c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000694c670101010121026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57bea400b8c4cf8396d8a38b9117a413eaaf75dd68023754fc6d41a266d157b54e477fe63898f192d939041825a97713453afa1842f1bb795f55579ed982b1112891152fffffffff0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0000000006a473044022032234e6ec1800a95ce02c88c89ce097773cb8decec86b0d1571ed044d560f69f02204398390013d9faf24a4b88c3cfa0c23d9d1915dba07275408483b8116979813b0121026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57beaffffffff030000000000000000fd22014704030001031504dc27511804e5a909774a66ddd4b0b477e6b267a61504dc27511804e5a909774a66ddd4b0b477e6b267a61504dc27511804e5a909774a66ddd4b0b477e6b267a6cc4cd604030e01011504dc27511804e5a909774a66ddd4b0b477e6b267a64c8103000000000000000114aabfb6281561808fe200ab7e186f0e3e0e82b38101000000a6ef9ea235635e328124ff3429db9f9e91b64e2d077275737473646b0000dc27511804e5a909774a66ddd4b0b477e6b267a6dc27511804e5a909774a66ddd4b0b477e6b267a600a6ef9ea235635e328124ff3429db9f9e91b64e2d000000001b04030f01011504dc27511804e5a909774a66ddd4b0b477e6b267a61b04031001011504dc27511804e5a909774a66ddd4b0b477e6b267a6750000000000000000911b04030001011504dc27511804e5a909774a66ddd4b0b477e6b267a6cc4c7104030a01011504dc27511804e5a909774a66ddd4b0b477e6b267a64c5401000000077275737473646ba6ef9ea235635e328124ff3429db9f9e91b64e2d00000000000000000000000000000000000000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a75604fa698200000001976a914aabfb6281561808fe200ab7e186f0e3e0e82b38188ac00000000000000000000000000000000000000";
const GOLDEN_REFERRED: &str = "0400008085202f8902c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000694c670101010121026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57bea407fc35ece4d27f1c8eb4d113f857945385eb7b108e9d08e929ea97688eb9b50161dfecd470a6b4fff3759821232016b9d1bc4d8570f7309256f248a2c9bd02575fffffffff0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0000000006b483045022100bc537b512dd1bc8f97c4554c630c759e1160e19c365321bd36cd0c49ac90c0fa022011c135b9339923029dfa159ee48dfd4a21bac9590d3b3c651cf4bf06de4104370121026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57beaffffffff040000000000000000fd24014704030001031504085db662d299655dbb094771a54b110b399796d21504085db662d299655dbb094771a54b110b399796d21504085db662d299655dbb094771a54b110b399796d2cc4cd804030e01011504085db662d299655dbb094771a54b110b399796d24c8303000000000000000114aabfb6281561808fe200ab7e186f0e3e0e82b38101000000a6ef9ea235635e328124ff3429db9f9e91b64e2d097275737472656630320000085db662d299655dbb094771a54b110b399796d2085db662d299655dbb094771a54b110b399796d200a6ef9ea235635e328124ff3429db9f9e91b64e2d000000001b04030f01011504085db662d299655dbb094771a54b110b399796d21b04031001011504085db662d299655dbb094771a54b110b399796d275009435770000000024050403000000cc1b04030001011504dc27511804e5a909774a66ddd4b0b477e6b267a6750000000000000000931b04030001011504085db662d299655dbb094771a54b110b399796d2cc4c7304030a01011504085db662d299655dbb094771a54b110b399796d24c560100000009727573747265663032a6ef9ea235635e328124ff3429db9f9e91b64e2ddc27511804e5a909774a66ddd4b0b477e6b267a65a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a7590dbdb0f210000001976a914aabfb6281561808fe200ab7e186f0e3e0e82b38188ac00000000000000000000000000000000000000";
const GOLDEN_REFERRAL_DEPTH: &str = "0400008085202f8902c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000694c670101010121026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57bea40d25a36634c9f9259f8f579332fb31eca94fad7a9dc95232d3538a87376fb97cd38af1c9abfc4b73f066595b10a0557b898ede90ca1881e35975824909cf2f21bfffffffff0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0000000006a4730440220085c754dafe9a2011e54351f0f1cffc6807c18c067e28b39ee42eec4bf00bf4e02202014a246009144d2eb1d90d07b6560f38da7fd87f49fba93622d751657e01b5f0121026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57beaffffffff050000000000000000fd26014704030001031504c9cd75ff2bc1f6e9d377dc8dc139a296aedea9a11504c9cd75ff2bc1f6e9d377dc8dc139a296aedea9a11504c9cd75ff2bc1f6e9d377dc8dc139a296aedea9a1cc4cda04030e01011504c9cd75ff2bc1f6e9d377dc8dc139a296aedea9a14c8503000000000000000114aabfb6281561808fe200ab7e186f0e3e0e82b38101000000a6ef9ea235635e328124ff3429db9f9e91b64e2d0b72757374646570746830310000c9cd75ff2bc1f6e9d377dc8dc139a296aedea9a1c9cd75ff2bc1f6e9d377dc8dc139a296aedea9a100a6ef9ea235635e328124ff3429db9f9e91b64e2d000000001b04030f01011504c9cd75ff2bc1f6e9d377dc8dc139a296aedea9a11b04031001011504c9cd75ff2bc1f6e9d377dc8dc139a296aedea9a175009435770000000024050403000000cc1b04030001011504085db662d299655dbb094771a54b110b399796d275009435770000000024050403000000cc1b04030001011504dc27511804e5a909774a66ddd4b0b477e6b267a6750000000000000000951b04030001011504c9cd75ff2bc1f6e9d377dc8dc139a296aedea9a1cc4c7504030a01011504c9cd75ff2bc1f6e9d377dc8dc139a296aedea9a14c58010000000b7275737464657074683031a6ef9ea235635e328124ff3429db9f9e91b64e2d085db662d299655dbb094771a54b110b399796d25a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a75c0d3db0f210000001976a914aabfb6281561808fe200ab7e186f0e3e0e82b38188ac00000000000000000000000000000000000000";
const GOLDEN_SUB_ID: &str = "0400008085202f8903c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000694c670101010121026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57bea40376f380d80079ce9680dff271a0f0ad581227a7504a20476ac1fac9a1ed469ac7656870da666db3a7cd8c091241cf14e8321224cef9604f684321aa8a7857a7effffffff707070707070707070707070707070707070707070707070707070707070707000000000694c670101010121026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57bea40192629ef75b31e9e45998a9caea9ad80d2416d215b540abbcfd73e574df0710801a5742666676c023e73c4c7b0b85386f9268983c10410465d1ad560877294f0fffffffff0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0000000006b483045022100c6353d02e2125bec188f00c0fee8f36c89fa724772acbcedfb7e8394ae432d2302206f414713c4bd0750812c91db061116534d799c88008f246199dc4a54d6ec288e0121026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57beaffffffff050000000000000000fd240147040300010315049fad1f23199c4b15ca00d5db2462e1f9f9f3cb2815049fad1f23199c4b15ca00d5db2462e1f9f9f3cb2815049fad1f23199c4b15ca00d5db2462e1f9f9f3cb28cc4cd804030e010115049fad1f23199c4b15ca00d5db2462e1f9f9f3cb284c8303000000000000000114aabfb6281561808fe200ab7e186f0e3e0e82b381010000009a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a0972757374737562303200009fad1f23199c4b15ca00d5db2462e1f9f9f3cb289fad1f23199c4b15ca00d5db2462e1f9f9f3cb2800a6ef9ea235635e328124ff3429db9f9e91b64e2d000000001b04030f010115049fad1f23199c4b15ca00d5db2462e1f9f9f3cb281b040310010115049fad1f23199c4b15ca00d5db2462e1f9f9f3cb28750000000000000000541b040300010115049a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9acc35040309010115049a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a19019a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9aaed6c100750000000000000000931b040300010115049fad1f23199c4b15ca00d5db2462e1f9f9f3cb28cc4c7304030a010115049fad1f23199c4b15ca00d5db2462e1f9f9f3cb284c5601000000097275737473756230329a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a00000000000000000000000000000000000000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a750000000000000000521a040300010114aabfb6281561808fe200ab7e186f0e3e0e82b381cc34040309010114aabfb6281561808fe200ab7e186f0e3e0e82b38119019a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9adeae830075e0ae93ec220000001976a914aabfb6281561808fe200ab7e186f0e3e0e82b38188ac00000000000000000000000000000000000000";
const GOLDEN_UPDATE: &str = "0400008085202f89021d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d00000000694c670101010121026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57bea409bf032b8ee93ec4e5a60ef55e92e74998df6542e9b6db7008af8b73b373a534311cc1ddd77db60e40d43bb5df62cc38e1372aef6ab481fb37445a139bebd90edfffffffff0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0000000006a4730440220067433d2e07150d3b0e8225f1ce2dfae1b5a751dec83e3016464ceff0025aadf02206594d2214c6fdcf93748c9f5415f59edfd8f56900d13c7cfaecd14c632452dda0121026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57beaffffffff020000000000000000fd57014704030001031504dc27511804e5a909774a66ddd4b0b477e6b267a61504dc27511804e5a909774a66ddd4b0b477e6b267a61504dc27511804e5a909774a66ddd4b0b477e6b267a6cc4d0a0104030e01011504dc27511804e5a909774a66ddd4b0b477e6b267a64cb503000000000000000114aabfb6281561808fe200ab7e186f0e3e0e82b38101000000a6ef9ea235635e328124ff3429db9f9e91b64e2d077275737473646b000111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222dc27511804e5a909774a66ddd4b0b477e6b267a6dc27511804e5a909774a66ddd4b0b477e6b267a600a6ef9ea235635e328124ff3429db9f9e91b64e2d000000001b04030f01011504dc27511804e5a909774a66ddd4b0b477e6b267a61b04031001011504dc27511804e5a909774a66ddd4b0b477e6b267a675f050a698200000001976a914aabfb6281561808fe200ab7e186f0e3e0e82b38188ac00000000000000000000000000000000000000";
const GOLDEN_MULTISIG_UPDATE: &str = "0400008085202f89021d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d00000000cd4ccb0101020121026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57bea407a3eae6c944e5a2686d57b92d44f11fb4d3606103df5775c8d0453e219b3c6ed5e42696d59452638bc7ec44aeeccab6b46c8a07133f50eb8174eedae920f5b2f01210216345bf831164a03758eaea5e8b66fee2be7710b8f190ee880249032a29ed66e4060e16493b5142868d835d0593b87f3491486067112a1d688ef396021028f5c7b3fbdc7c5c7209007dbc939e762cfa21e27f41606a993ffea252eb6fdbfb20ebafffffffff0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0000000006a4730440220575a5ce8a5ef2ab75a8880d73a59424c1f6280d37fc4210a76d9475abf14797c022044c0602d4335415ae9cfb5a47ee7fab85b3b025ba686e9dfb6921af710f269710121026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57beaffffffff020000000000000000fd6e01470403000103150401b12d9cf8cc63af6680890d115a001df7d68660150401b12d9cf8cc63af6680890d115a001df7d68660150401b12d9cf8cc63af6680890d115a001df7d68660cc4d210104030e0101150401b12d9cf8cc63af6680890d115a001df7d686604ccc03000000000000000214aabfb6281561808fe200ab7e186f0e3e0e82b381147e28fa4c1fcf53426593d0b88a1ce45ff6d625d302000000a6ef9ea235635e328124ff3429db9f9e91b64e2d09727573746d756c746900013333333333333333333333333333333333333333444444444444444444444444444444444444444444444444444444444444444401b12d9cf8cc63af6680890d115a001df7d6866001b12d9cf8cc63af6680890d115a001df7d6866000a6ef9ea235635e328124ff3429db9f9e91b64e2d000000001b04030f0101150401b12d9cf8cc63af6680890d115a001df7d686601b0403100101150401b12d9cf8cc63af6680890d115a001df7d6866075f06c9a441e0000001976a914aabfb6281561808fe200ab7e186f0e3e0e82b38188ac00000000000000000000000000000000000000";
const GOLDEN_REVOCATION: &str = "0400008085202f89021d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d00000000694c670101010121026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57bea409b347479363b83074aa6fa60f3f96ac36c51affaecb9809924c7b659626e042b25c9da16b1befc99c67108ed75aa86520a1c5f506560c0ba8f53f10e0214b1d1fffffffff0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0000000006b48304502210085c3ec527ac92c8fa1d1ce4863ae2ed09e08df7839342e8d449a1ba2f6ec92fd022007ca1e6a21208af97cdf1337b962633ae20c596d8ee2c977fd213f2babd324e00121026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57beaffffffff020000000000000000fd27014704030001031504071b7b0c54b501dfbbe4793071c433a129a9a0541504dc27511804e5a909774a66ddd4b0b477e6b267a61504dc27511804e5a909774a66ddd4b0b477e6b267a6cc4cdb04030e01011504071b7b0c54b501dfbbe4793071c433a129a9a0544c8603000000008000000114aabfb6281561808fe200ab7e186f0e3e0e82b38101000000a6ef9ea235635e328124ff3429db9f9e91b64e2d0c727573747265766f6b6530310000dc27511804e5a909774a66ddd4b0b477e6b267a6dc27511804e5a909774a66ddd4b0b477e6b267a600a6ef9ea235635e328124ff3429db9f9e91b64e2d000000001b04030f01011504dc27511804e5a909774a66ddd4b0b477e6b267a61b04031001011504dc27511804e5a909774a66ddd4b0b477e6b267a675f038b8131a0000001976a914aabfb6281561808fe200ab7e186f0e3e0e82b38188ac00000000000000000000000000000000000000";
const GOLDEN_RECOVERY: &str = "0400008085202f89021d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d00000000694c670101010121026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57bea40cc7a2f1018cf3061110af15899a97e5dc169f6482f1764788b44b75acc65960b720a783a91053ce7eb84e795cc0fcae61ab65ac290eab7044b185fa0ff605560fffffffff0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0000000006b483045022100a51e2dcef4de871b42f6a527526c89a2bf9df6c9363084ae5ee170ff2e70081202205d2662211ab5720bbc5a89bad248f8752e0da1d8da1584d5a1acb8388bf728530121026449e0864fc9eef8a9fc0badbfef45c7ebb03e6cb650db83412cb7ddcee57beaffffffff020000000000000000fd27014704030001031504071b7b0c54b501dfbbe4793071c433a129a9a0541504dc27511804e5a909774a66ddd4b0b477e6b267a61504dc27511804e5a909774a66ddd4b0b477e6b267a6cc4cdb04030e01011504071b7b0c54b501dfbbe4793071c433a129a9a0544c86030000000000000001147e28fa4c1fcf53426593d0b88a1ce45ff6d625d301000000a6ef9ea235635e328124ff3429db9f9e91b64e2d0c727573747265766f6b6530310000dc27511804e5a909774a66ddd4b0b477e6b267a6dc27511804e5a909774a66ddd4b0b477e6b267a600a6ef9ea235635e328124ff3429db9f9e91b64e2d000000001b04030f01011504dc27511804e5a909774a66ddd4b0b477e6b267a61b04031001011504dc27511804e5a909774a66ddd4b0b477e6b267a675f038b8131a0000001976a914aabfb6281561808fe200ab7e186f0e3e0e82b38188ac00000000000000000000000000000000000000";
