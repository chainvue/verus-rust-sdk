//! Prove a shield, spend the note it created, and verify every proof and
//! signature — offline, with no daemon and no chain.
//!
//! This is the gate the unit tests cannot be: it needs the ~50 MB Sapling
//! parameters and roughly half a minute of Groth16 proving, so it runs by hand
//! rather than in CI.
//!
//! ```sh
//! cargo run --release -p verus-sapling --features prover --example prove_and_verify
//! ```
//!
//! # What it actually establishes
//!
//! The round trip is self-contained: it shields to an address it derives, then
//! spends the very note that shield created, using that output's own commitment
//! as the whole tree. Every proof and signature is then checked with
//! `SaplingVerificationContext` — the same verifier a consensus node runs.
//!
//! `final_check` returning true means the binding signature verifies **under the
//! sighash [`verus_wire::TxV4`] computed**, and `check_spend` means the
//! spend-auth signature does too. That sighash is separately pinned against
//! three real daemon-produced transactions in `verus-wire`'s
//! `daemon_vectors.rs`, so the two together chain our builder to bytes a Verus
//! daemon actually accepted.
//!
//! What it does NOT establish is chain validity: the anchor here roots a tree
//! containing one note, which no real chain ever had. Only a funded broadcast
//! proves that, and that is a separate, manual exercise.

use bellman::groth16::Proof;
use bls12_381::Bls12;
use group::GroupEncoding;
use sapling_crypto::circuit::{PreparedOutputVerifyingKey, PreparedSpendVerifyingKey};
use sapling_crypto::note::ExtractedNoteCommitment;
use sapling_crypto::value::ValueCommitment;
use sapling_crypto::SaplingVerificationContext;
use verus_sapling::build::{
    build_shield, build_shielded_spend, NoteToSpend, ShieldSpec, ShieldedOutput, SpendSpec,
};
use verus_sapling::derive::{derive_account, COIN_TYPE_MAINNET};
use verus_sapling::params::SaplingParams;
use verus_sapling::scan::{dfvk_from_extsk, read_note, FullOutput, TreeStateBefore};
use verus_sapling::VERUS_ZIP212;
use verus_wire::consensus::VERUS_BRANCH_ID;
use verus_wire::{ShieldedSpend, TxIn, TxOut};

/// A shielded output description on the wire, field by field.
struct Description {
    cv: [u8; 32],
    cmu: [u8; 32],
    epk: [u8; 32],
    enc: Vec<u8>,
    ct: Vec<u8>,
    proof: Vec<u8>,
}

impl From<&Description> for FullOutput {
    fn from(d: &Description) -> Self {
        FullOutput {
            cv: d.cv,
            cmu: d.cmu,
            epk: d.epk,
            enc: d.enc.clone(),
            ct: d.ct.clone(),
            proof: d.proof.clone(),
        }
    }
}

impl Description {
    fn parse(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 948, "a v4 output description is 948 bytes");
        Self {
            cv: bytes[0..32].try_into().unwrap(),
            cmu: bytes[32..64].try_into().unwrap(),
            epk: bytes[64..96].try_into().unwrap(),
            enc: bytes[96..676].to_vec(),
            ct: bytes[676..756].to_vec(),
            proof: bytes[756..948].to_vec(),
        }
    }
}

/// Written into the shielded change note and read back at the end.
const MEMO: &[u8] = b"verus-rust-sdk round trip";

fn params_dir() -> String {
    std::env::var("VERUS_SAPLING_PARAMS").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/Library/Application Support/ZcashParams")
    })
}

fn main() {
    let dir = params_dir();
    eprintln!("loading Sapling parameters from {dir} …");
    let params = SaplingParams::from_files(
        format!("{dir}/sapling-spend.params"),
        format!("{dir}/sapling-output.params"),
    )
    .unwrap_or_else(|e| {
        eprintln!("{e}");
        eprintln!("set VERUS_SAPLING_PARAMS to the directory holding them.");
        std::process::exit(1);
    });
    let spend_vk = params.spend.prepared_verifying_key();
    let output_vk = params.output.prepared_verifying_key();

    // A throwaway account. Deterministic so a failure is reproducible.
    let account = derive_account(&[7u8; 64], COIN_TYPE_MAINNET, 0).expect("derive");

    // ---- t→z: 1.0 VRSC into the shielded pool, 0.0001 to the miner ----
    let shielded_outputs = [ShieldedOutput::new(account.address, 100_000_000)];
    let shield = build_shield(
        &params,
        &ShieldSpec {
            transparent_inputs: &[TxIn::unsigned([0x11; 32], 0, 0xffff_ffff)],
            transparent_outputs: &[],
            shielded_outputs: &shielded_outputs,
            lock_time: 0,
            expiry_height: 1_200_000,
            branch_id: VERUS_BRANCH_ID,
            zip212: VERUS_ZIP212,
        },
    )
    .expect("build the shield");

    let shield_sighash = shield.shielded_sighash(VERUS_BRANCH_ID);
    println!("t→z");
    println!("  valueBalance : {}", shield.value_balance);
    println!("  sighash      : {}", hex::encode(shield_sighash));
    println!(
        "  size         : {} bytes",
        shield.serialize().unwrap().len()
    );

    // The Sapling builder pads a bundle to two outputs — a lone output would
    // leak that the transaction has exactly one recipient. Both count toward the
    // value-commitment sum, so `final_check` fails unless BOTH are accumulated.
    let created: Vec<Description> = shield
        .shielded_outputs
        .iter()
        .map(|o| Description::parse(o))
        .collect();
    println!(
        "  outputs      : {} (one real, the rest padding)",
        created.len()
    );

    let mut ctx = SaplingVerificationContext::new();
    for (i, d) in created.iter().enumerate() {
        check_output(&mut ctx, d, &output_vk, &format!("t→z output {i} proof"));
    }
    let ok = ctx.final_check(
        shield.value_balance,
        &shield_sighash,
        redjubjub::Signature::from(shield.binding_sig.expect("binding sig")),
    );
    report("t→z binding signature", ok);

    // Which of those outputs is ours? Only trial decryption can say — exactly
    // what a wallet does when it sees the transaction on chain.
    let dfvk = dfvk_from_extsk(&account.extsk).expect("dfvk");
    let outputs: Vec<FullOutput> = created.iter().map(FullOutput::from).collect();
    let mine = outputs
        .iter()
        .position(|o| {
            read_note(&dfvk, o, VERUS_ZIP212)
                .expect("well-formed output")
                .is_some_and(|n| n.value == 100_000_000)
        })
        .expect("one of the outputs must decrypt to our note");
    println!("  our note     : output {mine}");

    // ---- z→z + z→t: spend that note into BOTH pools at once ----
    // 0.5 stays shielded (with a memo), 0.4 goes transparent, 0.1 to the miner.
    // The note's block contained just this one transaction's outputs, and the
    // tree before that block was empty — the whole chain history the witness
    // needs, in two values.
    let block_cmus: Vec<[u8; 32]> = created.iter().map(|d| d.cmu).collect();
    let empty_tree = TreeStateBefore {
        left: None,
        right: None,
        parents: Vec::new(),
    };
    let mut memo = [0u8; 512];
    memo[..MEMO.len()].copy_from_slice(MEMO);
    let shielded_change = [ShieldedOutput {
        recipient: account.address,
        value: 50_000_000,
        memo,
    }];
    let transparent_outputs = [TxOut {
        value: 40_000_000,
        // A P2PKH script paying an arbitrary hash; nothing here spends it.
        script_pubkey: [&[0x76, 0xa9, 0x14][..], &[0x22; 20], &[0x88, 0xac]].concat(),
    }];
    let spend = build_shielded_spend(
        &params,
        &SpendSpec {
            note: NoteToSpend {
                extsk_bytes: &account.extsk,
                output: &outputs[mine],
                tree_before_block: &empty_tree,
                block_cmus: &block_cmus,
                my_cmu_index: mine,
            },
            shielded_outputs: &shielded_change,
            transparent_outputs: &transparent_outputs,
            fee: 10_000_000,
            expiry_height: 1_200_000,
            branch_id: VERUS_BRANCH_ID,
            zip212: VERUS_ZIP212,
        },
    )
    .expect("build the shielded spend");

    let spend_sighash = spend.shielded_sighash(VERUS_BRANCH_ID);
    println!("z→z + z→t");
    println!("  valueBalance : {}", spend.value_balance);
    println!("  sighash      : {}", hex::encode(spend_sighash));
    println!(
        "  size         : {} bytes",
        spend.serialize().unwrap().len()
    );

    let mut ctx = SaplingVerificationContext::new();
    check_spend(
        &mut ctx,
        &spend.shielded_spends[0],
        &spend_sighash,
        &spend_vk,
    );
    for (i, out) in spend.shielded_outputs.iter().enumerate() {
        check_output(
            &mut ctx,
            &Description::parse(out),
            &output_vk,
            &format!("shielded output {i} proof"),
        );
    }
    let ok = ctx.final_check(
        spend.value_balance,
        &spend_sighash,
        redjubjub::Signature::from(spend.binding_sig.expect("binding sig")),
    );
    report("binding signature", ok);

    // The memo only survives a correct note-encryption path, so reading it back
    // proves more than the proofs do.
    let spent_outputs: Vec<FullOutput> = spend
        .shielded_outputs
        .iter()
        .map(|o| FullOutput::from(&Description::parse(o)))
        .collect();
    let change = spent_outputs
        .iter()
        .find_map(|o| read_note(&dfvk, o, VERUS_ZIP212).expect("well-formed output"))
        .expect("our shielded change must decrypt");
    assert_eq!(change.value, 50_000_000, "change value");
    assert_eq!(&change.memo[..MEMO.len()], MEMO, "memo round trip");
    println!(
        "  shielded change: {} zatoshi, memo {:?}",
        change.value,
        String::from_utf8_lossy(MEMO)
    );

    println!("\nEvery proof and signature verified against our own sighash.");
}

/// A spend description body: `cv(32) anchor(32) nullifier(32) rk(32)
/// proof(192)`, plus the spend-auth signature `TxV4` keeps beside it.
fn check_spend(
    ctx: &mut SaplingVerificationContext,
    spend: &ShieldedSpend,
    sighash: &[u8; 32],
    vk: &PreparedSpendVerifyingKey,
) {
    let bytes = &spend.body;
    assert_eq!(bytes.len(), 320, "a spend description body is 320 bytes");
    let cv = ValueCommitment::from_bytes_not_small_order(&bytes[0..32].try_into().unwrap())
        .expect("value commitment");
    let anchor =
        bls12_381::Scalar::from_bytes(&bytes[32..64].try_into().unwrap()).expect("anchor scalar");
    let nullifier: [u8; 32] = bytes[64..96].try_into().unwrap();
    let rk = redjubjub::VerificationKey::try_from(<[u8; 32]>::try_from(&bytes[96..128]).unwrap())
        .expect("rk");
    let proof = Proof::<Bls12>::read(&bytes[128..320]).expect("spend proof");
    let auth_sig =
        redjubjub::Signature::from(spend.spend_auth_sig.expect("the spend must be signed"));

    let ok = ctx.check_spend(&cv, anchor, &nullifier, rk, sighash, auth_sig, proof, vk);
    report("spend proof and spend-auth signature", ok);
}

fn check_output(
    ctx: &mut SaplingVerificationContext,
    d: &Description,
    vk: &PreparedOutputVerifyingKey,
    label: &str,
) {
    let cv = ValueCommitment::from_bytes_not_small_order(&d.cv).expect("value commitment");
    let cmu = Option::from(ExtractedNoteCommitment::from_bytes(&d.cmu)).expect("note commitment");
    let epk = jubjub::ExtendedPoint::from_bytes(&d.epk).expect("ephemeral key");
    let proof = Proof::<Bls12>::read(&d.proof[..]).expect("output proof");
    report(label, ctx.check_output(&cv, cmu, epk, proof, vk));
}

/// Exit non-zero on any failure: an example that prints "false" and returns 0 is
/// a gate that passes when it should not.
fn report(what: &str, ok: bool) {
    println!("  {:<44} {}", what, if ok { "ok" } else { "FAILED" });
    if !ok {
        eprintln!("\n{what} did not verify.");
        std::process::exit(1);
    }
}
