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
//! # This and `cargo fuzz`, not this instead of it
//!
//! There is a libFuzzer harness now — `fuzz/fuzz_targets/output_script.rs` —
//! and CI runs a smoke pass over it. This file used to say such a target
//! "would rot" because it needs nightly; that is handled by giving it its own
//! workspace and its own job.
//!
//! Both are worth keeping, and the overflow test at the bottom of this file is
//! the evidence. The fuzzer found a panic in about a second that the mutation
//! search below never reached, because this corpus is built from
//! `reserve_output_script` and `commitment_script` and so never constructs a
//! well-formed `EVAL_RESERVE_TRANSFER`. Coverage-guided mutation goes where a
//! fixed corpus does not.
//!
//! What this has and the fuzzer does not: it runs on stable, on every change,
//! and it is deterministic — a failure here reproduces exactly, rather than
//! only on the machine that happened to find it.
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
use verus_tx::{
    decode_output_script, identity_payment_script, identity_primary_script, OutputKind,
};

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

/// A small identity: one primary address, no content, no private addresses, a
/// short name. On its own its payload sits comfortably under the 255-byte
/// `OP_PUSHDATA1` ceiling — the baseline every variant in [`identity_corpus`]
/// is built from, so each one isolates a single feature crossing it.
fn minimal_identity() -> Identity {
    Identity {
        version: 3,
        flags: 0,
        primary_addresses: vec![Destination::PubKeyHash(key().address().hash())],
        min_sigs: 1,
        parent: chain(),
        name: "id".to_string(),
        content_multimap: Vec::new(),
        content_map: Vec::new(),
        revocation_authority: [0x04; 20],
        recovery_authority: [0x05; 20],
        private_addresses: Vec::new(),
        system_id: chain(),
        unlock_after: 0,
    }
}

/// The identity shapes the auditor measured as failing to decode (H1): the
/// encoder (`cc.rs` `push_data`) reaches for `OP_PUSHDATA2` the moment the
/// payload passes 255 bytes, and the decoder only understood `OP_PUSHDATA1`.
/// Each variant changes exactly one thing from [`minimal_identity`] so the
/// corpus proves the fix covers each trigger independently, not just their sum.
fn identity_corpus() -> Vec<Identity> {
    let base = minimal_identity();

    let mut three_primaries = base.clone();
    three_primaries.primary_addresses = vec![
        Destination::PubKeyHash(key().address().hash()),
        Destination::PubKeyHash([0x99; 20]),
        Destination::PubKeyHash([0x88; 20]),
    ];
    three_primaries.min_sigs = 2;

    let mut with_private_address = base.clone();
    with_private_address.private_addresses = vec![[0x06; 43]];

    let mut with_content_map_entry = base.clone();
    with_content_map_entry.content_map = vec![([0x02; 20], [0x03; 32])];

    let mut long_name = base.clone();
    long_name.name = "a".repeat(50);

    vec![
        base,
        three_primaries,
        with_private_address,
        with_content_map_entry,
        long_name,
    ]
}

/// Encode an identity into the output script that would actually hold it on
/// chain, via the real encoder — never hand-rolled bytes.
fn identity_script(identity: &Identity) -> Vec<u8> {
    let id = identity_id(&identity.name, Some(identity.parent));
    identity_primary_script(
        id,
        identity.to_bytes().unwrap(),
        identity.revocation_authority,
        identity.recovery_authority,
    )
    .unwrap()
}

/// Every shape of output this crate knows how to build.
fn valid_scripts() -> Vec<Vec<u8>> {
    let identity = sample_identity();
    let id = identity_id(&identity.name, Some(identity.parent));
    let reservation = NameReservation::new("robustness", chain(), None, [0x5a; 32]).unwrap();
    let mut scripts = vec![
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
    ];
    scripts.extend(identity_corpus().iter().map(identity_script));
    scripts
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
    assert!(
        catch_unwind(AssertUnwindSafe(f)).is_ok(),
        "{label} panicked on {} bytes: {}",
        input.len(),
        hex::encode(input)
    );
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

/// Every mutation test below only asserts "must not panic" — a `Vec` of
/// scripts a decoder is *supposed* to accept, with nothing ever checking that
/// it actually does. That blind spot is why H1 (the decoder could not read
/// `OP_PUSHDATA2`, which its own encoder writes for any identity payload past
/// 255 bytes) survived: `valid_scripts()` already contained a script that
/// size before this test existed, and nothing here noticed it failed to
/// decode.
#[test]
fn every_unmutated_valid_script_decodes_successfully() {
    for (index, script) in valid_scripts().into_iter().enumerate() {
        let result = decode_output_script(&script);
        assert!(
            result.is_ok(),
            "corpus entry {index} ({} bytes) failed to decode: {result:?}",
            script.len()
        );
    }
}

/// An identity that decodes must decode to exactly the identity that was
/// encoded, not merely "successfully to something". Covers the shapes that
/// motivated the `OP_PUSHDATA2` fix: three primary addresses, a private (z)
/// address, a `content_map` entry, and a name at the 50-character mark.
#[test]
fn an_identity_round_trips_through_the_real_encoder_and_decoder() {
    for identity in identity_corpus() {
        let script = identity_script(&identity);
        match decode_output_script(&script) {
            Ok(OutputKind::IdentityPrimary { identity: decoded }) => {
                assert_eq!(
                    *decoded, identity,
                    "identity {:?} did not round-trip through decode_output_script",
                    identity.name
                );
            }
            other => panic!(
                "identity {:?} ({} byte payload) did not decode as IdentityPrimary: {other:?}",
                identity.name,
                script.len()
            ),
        }
    }
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

/// A `CompactSize` length prefix that overflows `offset + length`.
///
/// Found by `fuzz/fuzz_targets/output_script.rs` in about a second, and *not*
/// found by the mutation search above — which is the point of keeping both.
/// That search builds its corpus from `reserve_output_script` and
/// `commitment_script`, so it never produced a well-formed enough
/// `EVAL_RESERVE_TRANSFER` to reach `TransferDestination::deserialize`, where
/// the arithmetic lived. Coverage-guided mutation walked in.
///
/// The bytes are the artifact libFuzzer wrote, unedited. Before the fix this
/// panicked with "attempt to add with overflow" at `convert.rs:315` — in a
/// debug build, which is what `cargo test` is, and what a consumer runs while
/// developing. In release the addition wrapped, `get` saw a backwards range,
/// and it refused correctly by accident.
#[test]
fn a_length_prefix_that_overflows_the_offset_is_refused() {
    let script = hex::decode(
        "1a040300010114258a0f7f651b48ae81e2312c3438deb601e27368cc4c8f040308010114cb8a0f7f\
         651b484a81e2312c3438deb601e273684c7301a6ef9ea25e8163353224ff3429db9f9e91813ef10e\
         47ac626d3c87257308b7d25a204c011699143ef1810262ffffffffffffffffffffff1a5a204ce908\
         e3e5c373389fa7684c7301a6ef9ea25e8163353224ff3429db9f9e9181d25a204ce908e3e5c37338\
         9fa7ae5d4b22a87ffc204a74ff75",
    )
    .expect("the artifact is hex");

    // Any `Err` is fine. A panic is not, and neither is an `Ok` — this script
    // does not describe a coherent output.
    let decoded = catch_unwind(AssertUnwindSafe(|| decode_output_script(&script)));
    match decoded {
        Ok(Ok(kind)) => panic!("a script with an overflowing length prefix decoded as {kind:?}"),
        Ok(Err(_)) => {}
        Err(_) => panic!("a script with an overflowing length prefix panicked"),
    }
}
