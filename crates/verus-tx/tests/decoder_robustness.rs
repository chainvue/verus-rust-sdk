//! The decoders must never panic on hostile input.
//!
//! [`decode_output_script`] and [`Identity::from_bytes`] are the only functions
//! in this crate that read bytes **other people wrote**. A wallet calls them on
//! every output it sees while scanning the chain, including outputs crafted by
//! whoever wanted to, so a panic there is not a bug that shows up in a test — it
//! is a wallet that dies while listing its own balance, at a time an attacker
//! chooses.
//!
//! Returning an error is always acceptable. Panicking never is.
//!
//! # Why this and not `cargo fuzz`
//!
//! A libFuzzer harness needs nightly, so CI would not run it and it would rot.
//! This runs on stable, in CI, on every change, and is deterministic — a failure
//! reproduces exactly instead of only on the machine that found it. It is a
//! weaker search than coverage-guided fuzzing, so it is a floor rather than a
//! ceiling: a real `cargo fuzz` target over the same two entry points is worth
//! adding for long soak runs.
//!
//! The corpus is built from *valid* scripts, then damaged. Random bytes alone
//! mostly bounce off the first length check; mutating real structures is what
//! reaches the parsing deeper in, where the length arithmetic lives.

use std::panic::{catch_unwind, AssertUnwindSafe};

use verus_keys::{Address, PrivateKey};
use verus_tx::cc::{reserve_output_script, Destination};
use verus_tx::identity::Identity;
use verus_tx::register::{commitment_script, identity_id, NameReservation};
use verus_tx::CurrencyId;
use verus_tx::{decode_output_script, identity_payment_script, identity_primary_script};

const TEST_WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";
const VRSCTEST: &str = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";

/// xorshift64*, so a failure is reproducible from its seed alone.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        // The modulus is already below `bound`, which came from a usize, so the
        // narrowing is exact on any pointer width.
        usize::try_from(self.next() % bound as u64).expect("modulus is below a usize bound")
    }

    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }
}

fn key() -> PrivateKey {
    PrivateKey::from_wif(TEST_WIF).unwrap()
}

fn chain() -> [u8; 20] {
    VRSCTEST.parse::<Address>().unwrap().hash()
}

fn sample_identity() -> Identity {
    Identity {
        version: 3,
        flags: 0,
        primary_addresses: vec![
            Destination::PubKeyHash(key().address().hash()),
            Destination::PubKeyHash([0x99; 20]),
        ],
        min_sigs: 2,
        parent: chain(),
        name: "robustness".to_string(),
        content_multimap: vec![([0x01; 20], vec![vec![0xab; 12], vec![]])],
        content_map: vec![([0x02; 20], [0x03; 32])],
        revocation_authority: [0x04; 20],
        recovery_authority: [0x05; 20],
        private_addresses: vec![[0x06; 43]],
        system_id: chain(),
        unlock_after: 12345,
    }
}

/// Every shape of output this crate knows how to build.
fn valid_scripts() -> Vec<Vec<u8>> {
    let identity = sample_identity();
    let id = identity_id(&identity.name, Some(identity.parent));
    let reservation = NameReservation::new("robustness", chain(), None, [0x5a; 32]).unwrap();
    vec![
        key().address().p2pkh_script_pubkey().unwrap(),
        identity_payment_script(id).unwrap(),
        reserve_output_script(
            key().address().hash(),
            CurrencyId::from_bytes([0x77; 20]),
            42_000_000,
        )
        .unwrap(),
        identity_primary_script(
            id,
            identity.to_bytes().unwrap(),
            identity.revocation_authority,
            identity.recovery_authority,
        )
        .unwrap(),
        commitment_script(
            &reservation.commitment_hash().unwrap(),
            key().address().hash(),
        )
        .unwrap(),
    ]
}

/// Damage `bytes` in one of the ways a parser is most likely to mishandle.
fn mutate(rng: &mut Rng, bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    if out.is_empty() {
        return out;
    }
    match rng.below(6) {
        // Flip a byte — including, sometimes, a length prefix.
        0 => {
            let at = rng.below(out.len());
            out[at] ^= 1 << rng.below(8);
        }
        // Truncate: the classic way to walk a reader off the end.
        1 => out.truncate(rng.below(out.len())),
        // Overstate a length so the payload claims more than exists.
        2 => {
            let at = rng.below(out.len());
            out[at] = 0xff;
        }
        // Splice in random bytes.
        3 => {
            let at = rng.below(out.len());
            let len = rng.below(16);
            for _ in 0..len {
                out.insert(at, rng.byte());
            }
        }
        // Remove a run.
        4 => {
            let at = rng.below(out.len());
            let len = rng.below(out.len() - at).max(1);
            out.drain(at..at + len);
        }
        // Extend with trailing junk, which must not be silently accepted.
        _ => {
            for _ in 0..rng.below(32) {
                out.push(rng.byte());
            }
        }
    }
    out
}

/// Run `f` and report the input that made it panic, so the failure is
/// actionable rather than a bare backtrace.
fn must_not_panic<T>(label: &str, input: &[u8], f: impl FnOnce() -> T) {
    if catch_unwind(AssertUnwindSafe(f)).is_err() {
        panic!(
            "{label} panicked on {} bytes: {}",
            input.len(),
            hex::encode(input)
        );
    }
}

/// The harness must be able to fail.
///
/// Every test here passed on its first run, which is the expected outcome for
/// decoders written to reject rather than assume — but it is also what a net
/// with a hole in it looks like. This proves the hole is not there: a function
/// that panics is reported, not swallowed.
#[test]
fn the_harness_detects_a_panic() {
    let caught = catch_unwind(AssertUnwindSafe(|| {
        must_not_panic("deliberate", &[0xde, 0xad], || panic!("boom"));
    }));
    assert!(caught.is_err(), "must_not_panic swallowed a panic");
}

#[test]
fn decoding_a_mutated_output_script_never_panics() {
    let corpus = valid_scripts();
    let mut rng = Rng(0x5eed_1234_5678_9abc);
    for round in 0..40_000 {
        let base = &corpus[round % corpus.len()];
        let candidate = mutate(&mut rng, base);
        must_not_panic("decode_output_script", &candidate, || {
            let _ = decode_output_script(&candidate);
        });
    }
}

#[test]
fn decoding_arbitrary_bytes_as_a_script_never_panics() {
    let mut rng = Rng(0x0bad_c0de_0bad_c0de);
    for _ in 0..40_000 {
        let len = rng.below(300);
        let candidate: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        must_not_panic("decode_output_script", &candidate, || {
            let _ = decode_output_script(&candidate);
        });
    }
}

#[test]
fn reading_a_mutated_identity_never_panics() {
    let encoded = sample_identity().to_bytes().unwrap();
    let mut rng = Rng(0xfeed_face_dead_beef);
    for _ in 0..40_000 {
        let candidate = mutate(&mut rng, &encoded);
        must_not_panic("Identity::from_bytes", &candidate, || {
            let _ = Identity::from_bytes(&candidate);
        });
    }
}

#[test]
fn reading_arbitrary_bytes_as_an_identity_never_panics() {
    let mut rng = Rng(0x1234_5678_9abc_def0);
    for _ in 0..40_000 {
        let len = rng.below(400);
        let candidate: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        must_not_panic("Identity::from_bytes", &candidate, || {
            let _ = Identity::from_bytes(&candidate);
        });
    }
}

/// A decoder that accepts damaged input is as dangerous as one that panics: it
/// reports a balance or an authority that the bytes do not say. Whatever
/// survives mutation must re-encode to exactly the bytes it was read from.
#[test]
fn an_identity_that_parses_round_trips_exactly() {
    let encoded = sample_identity().to_bytes().unwrap();
    let mut rng = Rng(0xabcd_ef01_2345_6789);
    let mut parsed = 0u32;
    for _ in 0..40_000 {
        let candidate = mutate(&mut rng, &encoded);
        if let Ok(identity) = Identity::from_bytes(&candidate) {
            parsed += 1;
            let reencoded = identity.to_bytes().expect("a parsed identity re-encodes");
            assert_eq!(
                hex::encode(&reencoded),
                hex::encode(&candidate),
                "identity parsed from bytes it does not reproduce"
            );
        }
    }
    // If nothing parsed, the test proved nothing.
    assert!(
        parsed > 0,
        "no mutated identity parsed; the corpus is wrong"
    );
}
