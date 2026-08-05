//! The registration salt must come from a real entropy source.
//!
//! # What breaks if it does not
//!
//! Registering a VerusID is commit/reveal: a first transaction publishes
//! `hash(name, salt, …)` and a second, later, reveals the name. The salt is the
//! only thing standing between those two — it is what stops an observer from
//! learning which name is being claimed before the claim is complete.
//!
//! Make the salt predictable and that mapping becomes a table anyone can
//! precompute. Someone watching the mempool reads the commitment, works out the
//! name, and registers it first. What is lost is the name **and** the
//! registration fee, which is burned rather than paid to an output — over 100
//! VRSCTEST for a root identity, and the chain does not give it back.
//!
//! # The regression this actually guards against
//!
//! Not an attacker against today's code: `random_salt` calls `OsRng`. The
//! realistic way this breaks is a later change that makes the salt deterministic
//! *on purpose* — someone wants a reproducible test, stubs the source, and it
//! ships. That is how this class of bug has entered real wallets, and without
//! this file the whole suite stays green while it happens.
//!
//! # What it can and cannot detect
//!
//! It detects gross failure: a constant, a fixed byte pattern, a source that
//! only varies part of the output, or a generator seeded the same way in every
//! process. It cannot detect a subtly biased or deliberately backdoored
//! generator — no statistical test over a few dozen samples can, and claiming
//! otherwise would make this file worse than useless. Regression detection is
//! the job; entropy validation is not something a test suite can do.

use std::collections::HashSet;
use std::process::Command;

use verus_flows::testing::ScriptedReader;
use verus_flows::{prepare_registration, RegistrationOptions};
use verus_keys::PrivateKey;
use verus_rpc::CurrencyPolicy;
use verus_tx::Amount;

/// The public test key used across this repository. It holds nothing.
const TEST_WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";

/// Set in the child process, which prints one salt and stops. See
/// [`a_second_process_draws_a_different_salt`].
const PROBE: &str = "VERUS_SALT_PROBE";

fn key() -> PrivateKey {
    PrivateKey::from_wif(TEST_WIF).expect("the test WIF parses")
}

fn chain() -> ScriptedReader {
    ScriptedReader::new(1_000)
        .with_policy(CurrencyPolicy {
            currency_id: "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq".into(),
            name: "VRSCTEST".into(),
            id_registration_fee: Amount::from_sat(100_00000000),
            id_referral_levels: 3,
            id_import_fee: Amount::from_sat(2_000_000),
            currency_registration_fee: Amount::from_sat(200_00000000),
            proof_protocol: 1,
        })
        .with_utxo(&key().address().to_string(), 500, 200_00000000)
}

/// One salt, drawn through the public API rather than by calling the private
/// generator — so this tests the path a wallet actually takes.
fn draw_one() -> [u8; 32] {
    prepare_registration(
        &chain(),
        &key(),
        "salttest",
        &RegistrationOptions::default(),
    )
    .expect("the scripted chain funds a registration")
    .reservation
    .salt
}

/// How many samples. Large enough that the per-bit check below cannot fire by
/// chance — see the calculation there — and small enough to stay instant.
const SAMPLES: usize = 64;

#[test]
fn every_salt_differs_from_every_other() {
    let salts: HashSet<[u8; 32]> = (0..SAMPLES).map(|_| draw_one()).collect();
    assert_eq!(
        salts.len(),
        SAMPLES,
        "a repeated salt in {SAMPLES} draws: the source is not random"
    );
}

#[test]
fn no_salt_is_a_fixed_pattern() {
    for salt in (0..SAMPLES).map(|_| draw_one()) {
        assert_ne!(salt, [0x00; 32], "an all-zero salt is a stubbed generator");
        assert_ne!(salt, [0xff; 32], "an all-ones salt is a stubbed generator");
        assert!(
            salt.iter().collect::<HashSet<_>>().len() > 1,
            "every byte of the salt is identical: {}",
            hex::encode(salt)
        );
    }
}

/// Every one of the 256 bits must take both values across the samples.
///
/// This is the check that catches a *partial* source — a generator that varies
/// four bytes and leaves twenty-eight constant would pass both tests above,
/// while leaving the salt trivially searchable.
///
/// It cannot fire by accident. For one bit position to be constant across 64
/// independent draws has probability `2 · 2⁻⁶⁴`; across all 256 positions that
/// is about `2.8 · 10⁻¹⁷`, which is a false failure roughly once every hundred
/// million years of running this suite once a second.
#[test]
fn every_bit_position_varies() {
    let salts: Vec<[u8; 32]> = (0..SAMPLES).map(|_| draw_one()).collect();

    for byte in 0..32 {
        for bit in 0..8 {
            let mask = 1u8 << bit;
            let ones = salts.iter().filter(|s| s[byte] & mask != 0).count();
            assert!(
                ones > 0 && ones < SAMPLES,
                "bit {bit} of byte {byte} was always {} across {SAMPLES} salts: \
                 the generator does not fill the whole salt",
                u8::from(ones > 0)
            );
        }
    }
}

/// A fresh process must not draw the salt a previous one drew.
///
/// The three tests above all run inside one process, and every one of them
/// passes against `StdRng::seed_from_u64(0)` — a generator whose output is
/// distinct, well spread, and **identical on every machine, every run**. That is
/// not a contrived failure: seeding a PRNG with a constant is the ordinary way
/// somebody makes a test reproducible, and it is exactly the shape of the bug
/// this file exists for.
///
/// Catching it needs a second process, because "reproducible" means reproducible
/// *across* processes. So this one re-executes the test binary with [`PROBE`]
/// set, which makes it print a salt and stop, and checks the child disagreed
/// with the parent.
#[test]
fn a_second_process_draws_a_different_salt() {
    if std::env::var(PROBE).is_ok() {
        println!("SALT {}", hex::encode(draw_one()));
        return;
    }

    let exe = std::env::current_exe().expect("the test binary knows its own path");
    let output = Command::new(exe)
        .args([
            "--exact",
            "a_second_process_draws_a_different_salt",
            "--nocapture",
        ])
        .env(PROBE, "1")
        .output()
        .expect("the test binary re-executes");
    assert!(
        output.status.success(),
        "the child failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let child = stdout
        .lines()
        .find_map(|line| line.strip_prefix("SALT "))
        .unwrap_or_else(|| panic!("the child printed no salt:\n{stdout}"));

    assert_ne!(
        child,
        hex::encode(draw_one()),
        "two processes drew the same salt: the generator is seeded deterministically"
    );
}
