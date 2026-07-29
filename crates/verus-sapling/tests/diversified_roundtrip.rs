//! A note received at a diversified address must also be *spendable*.
//!
//! Receiving is the easy half and the unit tests cover it: one incoming viewing
//! key finds notes to every diversified address. The half worth proving is the
//! other one. If the spend path assumed the default diversifier anywhere — when
//! recovering the note, deriving the nullifier, or building the proof — then
//! handing out diversified addresses would be a trap that accepts money and
//! cannot release it, and nothing about receiving would reveal it.
//!
//! So this builds a real proven t→z to a **non-default** address and then spends
//! that note back out, through the real Groth16 prover.
//!
//! **Opt-in**, because it needs the ~50 MB Sapling parameters and takes seconds:
//!
//! ```sh
//! VERUS_SAPLING_PARAMS="$HOME/Library/Application Support/ZcashParams" \
//!   cargo test -p verus-sapling --test diversified_roundtrip -- --nocapture
//! ```
//!
//! Skips when that is unset, so CI stays free of a 50 MB download.

use verus_sapling::build::{
    build_shield, build_shielded_spend, NoteToSpend, ShieldSpec, ShieldedOutput, SpendSpec,
};
use verus_sapling::derive::{derive_account, COIN_TYPE_MAINNET};
use verus_sapling::diversified::{addresses, index_of};
use verus_sapling::params::SaplingParams;
use verus_sapling::scan::{dfvk_from_extsk, read_note, FullOutput, TreeStateBefore};
use verus_sapling::VERUS_ZIP212;
use verus_wire::consensus::VERUS_BRANCH_ID;
use verus_wire::{TxIn, TxOut};

/// Load the proving parameters, or `None` if the caller did not ask for this.
fn params() -> Option<SaplingParams> {
    let dir = std::env::var("VERUS_SAPLING_PARAMS").ok().or_else(|| {
        eprintln!("skipping: set VERUS_SAPLING_PARAMS to the directory holding sapling-*.params");
        None
    })?;
    let spend = format!("{dir}/sapling-spend.params");
    let output = format!("{dir}/sapling-output.params");
    Some(SaplingParams::from_files(&spend, &output).expect("read sapling parameters"))
}

/// Pull a shielded output back off a built transaction, in the shape the spend
/// path consumes.
fn full_output(tx: &verus_wire::TxV4, index: usize) -> FullOutput {
    let raw = &tx.shielded_outputs[index];
    // A Sapling OutputDescription on the wire:
    //   cv(32) cmu(32) epk(32) enc(580) out(80) proof(192)
    let mut at = 0;
    let mut take = |n: usize| {
        let slice = raw[at..at + n].to_vec();
        at += n;
        slice
    };
    let cv: [u8; 32] = take(32).try_into().unwrap();
    let cmu: [u8; 32] = take(32).try_into().unwrap();
    let epk: [u8; 32] = take(32).try_into().unwrap();
    FullOutput {
        cv,
        cmu,
        epk,
        enc: take(580),
        ct: take(80),
        proof: take(192),
    }
}

#[test]
fn a_note_received_at_a_diversified_address_can_be_spent() {
    let Some(params) = params() else { return };

    let account = derive_account(&[7u8; 64], COIN_TYPE_MAINNET, 0).expect("derive");
    let dfvk = dfvk_from_extsk(&account.extsk).expect("dfvk");

    // The 8th usable address, chosen so it is emphatically not the default.
    let (index, recipient) = addresses(&dfvk, 0).nth(7).expect("an address");
    assert_ne!(
        recipient, account.address,
        "the test needs a non-default address to mean anything"
    );
    eprintln!("paying diversifier index {index}");

    // --- receive: a proven t→z to that address ---
    let value = 500_000u64;
    let shield = build_shield(
        &params,
        &ShieldSpec {
            transparent_inputs: &[TxIn::unsigned([0x11; 32], 0, 0xffff_ffff)],
            transparent_outputs: &[],
            shielded_outputs: &[ShieldedOutput::new(recipient, value)],
            lock_time: 0,
            expiry_height: 0,
            branch_id: VERUS_BRANCH_ID,
            zip212: VERUS_ZIP212,
        },
    )
    .expect("build the shield");

    // A bundle with one real output is padded with a **dummy** one, so that
    // an observer cannot infer the recipient count. Two outputs for one
    // payment is correct, and it is why the real note has to be located by
    // trial decryption rather than by index — the same reason
    // `NoteWitness::new` warns against assuming index 0.
    assert_eq!(
        shield.shielded_outputs.len(),
        2,
        "expected the real output plus a privacy dummy"
    );

    let outputs: Vec<FullOutput> = (0..shield.shielded_outputs.len())
        .map(|i| full_output(&shield, i))
        .collect();
    let (position, read) = outputs
        .iter()
        .enumerate()
        .find_map(|(i, output)| {
            read_note(&dfvk, output, VERUS_ZIP212)
                .expect("decrypt")
                .map(|note| (i, note))
        })
        .expect("one of the outputs is ours");
    let output = &outputs[position];
    eprintln!("the real note is output {position} of {}", outputs.len());

    // The dummy must NOT decrypt to us — otherwise it is not a dummy.
    assert_eq!(
        outputs
            .iter()
            .filter(|o| read_note(&dfvk, o, VERUS_ZIP212)
                .expect("decrypt")
                .is_some())
            .count(),
        1,
        "more than one output decrypted; the padding is not a dummy"
    );

    assert_eq!(read.value, value);
    assert_eq!(read.recipient, recipient);
    assert_eq!(index_of(&dfvk, &read.recipient).unwrap(), Some(index));
    eprintln!("received {value} at index {index}, decrypted and attributed");

    // --- spend it: the half that would silently be broken ---
    let empty_tree = TreeStateBefore {
        left: None,
        right: None,
        parents: Vec::new(),
    };
    let fee = 10_000u64;
    let spend = build_shielded_spend(
        &params,
        &SpendSpec {
            notes: &[NoteToSpend {
                extsk_bytes: &account.extsk,
                output,
                tree_before_block: &empty_tree,
                // Every commitment in the block, in order — the dummy included,
                // because the tree does not know which outputs were dummies.
                block_cmus: &outputs.iter().map(|o| o.cmu).collect::<Vec<_>>(),
                my_cmu_index: position,
                advanced_witness: None,
            }],
            shielded_outputs: &[],
            transparent_outputs: &[TxOut {
                value: value - fee,
                script_pubkey: vec![0x76, 0xa9, 0x14],
            }],
            fee,
            expiry_height: 0,
            branch_id: VERUS_BRANCH_ID,
            zip212: VERUS_ZIP212,
        },
    )
    .expect("a note at a diversified address must be spendable");

    assert_eq!(spend.shielded_spends.len(), 1, "the note was not spent");
    // valueBalance is what leaves the shielded pool: the whole note.
    assert_eq!(spend.value_balance, i64::try_from(value).unwrap());
    assert!(spend.serialize().is_ok(), "the spend does not serialize");

    eprintln!(
        "spent it: 1 shielded spend, valueBalance {}, {} bytes",
        spend.value_balance,
        spend.serialize().unwrap().len()
    );
}

/// Two different diversified addresses, both spendable, in one transaction.
///
/// A wallet handing out a fresh address per payment accumulates notes across
/// many diversifiers and eventually has to combine them. If anything keyed off
/// "the" diversifier, one note would work and two would not.
#[test]
fn notes_at_two_different_diversifiers_spend_together() {
    let Some(params) = params() else { return };

    let account = derive_account(&[7u8; 64], COIN_TYPE_MAINNET, 0).expect("derive");
    let dfvk = dfvk_from_extsk(&account.extsk).expect("dfvk");

    let picks: Vec<_> = addresses(&dfvk, 0).take(6).collect();
    let (first_index, first) = picks[2];
    let (second_index, second) = picks[5];
    assert_ne!(first, second);

    // Both notes must land in the same block to share an anchor, so they are
    // built as two outputs of one transaction.
    let shield = build_shield(
        &params,
        &ShieldSpec {
            transparent_inputs: &[TxIn::unsigned([0x22; 32], 0, 0xffff_ffff)],
            transparent_outputs: &[],
            shielded_outputs: &[
                ShieldedOutput::new(first, 300_000),
                ShieldedOutput::new(second, 200_000),
            ],
            lock_time: 0,
            expiry_height: 0,
            branch_id: VERUS_BRANCH_ID,
            zip212: VERUS_ZIP212,
        },
    )
    .expect("build the shield");
    assert_eq!(shield.shielded_outputs.len(), 2);

    // The builder shuffles outputs, so find each note rather than assuming an
    // order — the same reason `NoteWitness::new` warns against assuming index 0.
    let outputs: Vec<FullOutput> = (0..2).map(|i| full_output(&shield, i)).collect();
    let cmus: Vec<[u8; 32]> = outputs.iter().map(|o| o.cmu).collect();

    let mut total = 0u64;
    let mut seen = Vec::new();
    for output in &outputs {
        let read = read_note(&dfvk, output, VERUS_ZIP212)
            .expect("decrypt")
            .expect("ours");
        total += read.value;
        seen.push(index_of(&dfvk, &read.recipient).unwrap().expect("an index"));
    }
    seen.sort_unstable();
    assert_eq!(seen, {
        let mut want = [first_index, second_index];
        want.sort_unstable();
        want.to_vec()
    });
    assert_eq!(total, 500_000);

    let empty_tree = TreeStateBefore {
        left: None,
        right: None,
        parents: Vec::new(),
    };
    let fee = 10_000u64;
    let notes: Vec<NoteToSpend> = outputs
        .iter()
        .enumerate()
        .map(|(i, output)| NoteToSpend {
            extsk_bytes: &account.extsk,
            output,
            tree_before_block: &empty_tree,
            block_cmus: &cmus,
            my_cmu_index: i,
            advanced_witness: None,
        })
        .collect();

    let spend = build_shielded_spend(
        &params,
        &SpendSpec {
            notes: &notes,
            shielded_outputs: &[],
            transparent_outputs: &[TxOut {
                value: total - fee,
                script_pubkey: vec![0x76, 0xa9, 0x14],
            }],
            fee,
            expiry_height: 0,
            branch_id: VERUS_BRANCH_ID,
            zip212: VERUS_ZIP212,
        },
    )
    .expect("two diversifiers must spend together");

    assert_eq!(spend.shielded_spends.len(), 2);
    assert_eq!(spend.value_balance, i64::try_from(total).unwrap());
    eprintln!("spent notes at indices {seen:?} together, valueBalance {total}");
}
