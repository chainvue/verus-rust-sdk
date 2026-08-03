//! Proving and signing a shielded spend.
//!
//! The pieces this composes were each proven separately and left unjoined.
//! `verus_sapling::build_shielded_spend` has produced z→z, z→t and multi-note
//! spends the network accepted; [`witness_note`](super::witness_note) assembles
//! everything it takes as input. What was missing is the part a wallet cannot
//! write for itself without re-deriving every trap below.
//!
//! Everything that can be got wrong *cheaply* lives one module over, in
//! [`planning`](super::planning) — selection, witnessing and the anchor check
//! against consensus all run without the prover, and [`prepare_spend`] runs
//! them before the first proof.
//!
//! # There is no fee estimator here
//!
//! [`SpendRequest::fee`] is required, and nothing in this crate will guess it.
//! `estimatefee` prices a transaction by its serialized size against a
//! transparent fee-per-kilobyte, and a shielded transaction's size is dominated
//! by Groth16 proofs — a spend description is 384 bytes of which the caller
//! chose none. Applying the transparent heuristic would produce a confidently
//! wrong number, and the failure is asymmetric: `build_shielded_spend` refuses
//! an overshoot, but only because a bundle that overshoots is otherwise a
//! perfectly valid transaction that hands the difference to a miner.
//!
//! # A note is worth what it is worth
//!
//! Shielded value cannot be split at the input. A note enters a spend whole, and
//! anything above the outputs and the fee has to come back as change — to an
//! address the spender controls, in the same bundle. That is why
//! [`SpendRequest::change_address`] exists, and why leaving it unset defaults to
//! the address the largest selected note was already paid to rather than to
//! nothing.

use verus_keys::{Address, AddressKind};
use verus_light::{LightClient, LightTransport};
use verus_rpc::{Broadcaster, ChainReader};
use verus_sapling::build::{
    build_shielded_spend, NoteToSpend, ShieldedOutput, SpendSpec, MEMO_SIZE,
};
use verus_sapling::params::SaplingParams;
use verus_sapling::scan::DetectedNote;
use verus_sapling::VERUS_ZIP212;
use verus_tx::{identity_payment_script, Expiry, DEFAULT_EXPIRY_BLOCKS};
use verus_wire::consensus::VERUS_BRANCH_ID;
use verus_wire::hash::txid_display;
use verus_wire::TxOut;

use crate::broadcast::Unsent;
use crate::error::FlowError;

use super::planning::{plan_spend, SpendPlan};

/// One shielded recipient.
pub struct ShieldedRecipient {
    /// Raw 43-byte Sapling payment address. Decode a `zs…` string with
    /// [`verus_sapling::zaddr::decode`] first.
    pub address: [u8; 43],
    /// Value in zatoshi.
    pub amount: u64,
    /// The ZIP-302 memo, already encoded and zero-padded.
    pub memo: [u8; MEMO_SIZE],
}

impl ShieldedRecipient {
    /// A recipient with an empty memo.
    #[must_use]
    pub fn new(address: [u8; 43], amount: u64) -> Self {
        Self {
            address,
            amount,
            memo: [0u8; MEMO_SIZE],
        }
    }

    /// A recipient carrying a UTF-8 memo.
    ///
    /// # Errors
    ///
    /// [`FlowError::Shielded`] if the text does not fit in [`MEMO_SIZE`] bytes.
    /// Truncating instead would silently deliver half a message.
    pub fn with_memo(address: [u8; 43], amount: u64, text: &str) -> Result<Self, FlowError> {
        let bytes = text.as_bytes();
        if bytes.len() > MEMO_SIZE {
            return Err(FlowError::Shielded(format!(
                "a memo is at most {MEMO_SIZE} bytes, this one is {}",
                bytes.len()
            )));
        }
        let mut memo = [0u8; MEMO_SIZE];
        memo[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            address,
            amount,
            memo,
        })
    }
}

/// One transparent recipient of a shielded spend.
pub struct TransparentRecipient {
    /// An `R` address or a VerusID — both are paid correctly, and they are not
    /// the same script. See [`transparent_script`].
    pub address: Address,
    /// Value in satoshis.
    pub amount: u64,
}

/// What a spend is being asked to do.
///
/// `notes` are the wallet's own — this crate does not scan on your behalf here,
/// for the same reason [`send_token`](crate::send_token) does not discover token
/// outputs: a wallet already tracks its notes, and pretending to a lookup would
/// mean rescanning the chain on every payment. Get them from
/// [`scan`](super::scan) and [`ScanResult::unspent`](super::ScanResult::unspent)
/// — **`unspent`, not `notes`**, or the spend is built from money already gone.
pub struct SpendRequest<'a> {
    /// The 169-byte extended spending key that owns every note in `notes`.
    pub extsk: &'a [u8],
    /// Candidate notes, unspent. A subset is selected; see [`select_notes`](super::select_notes).
    pub notes: &'a [DetectedNote],
    /// Shielded recipients.
    pub shielded_to: &'a [ShieldedRecipient],
    /// Transparent recipients.
    pub transparent_to: &'a [TransparentRecipient],
    /// The miner fee, in zatoshi. Required — see the module docs on why nothing
    /// here will estimate it.
    pub fee: u64,
    /// Where surplus value returns.
    ///
    /// `None` sends it back to the address the largest selected note was paid
    /// to, which the spending key demonstrably controls. Set it to use a fresh
    /// diversified address instead.
    pub change_address: Option<[u8; 43]>,
    /// The height every note is witnessed to.
    ///
    /// `None` uses the light server's tip. A bundle carries one anchor, so this
    /// is shared by every selected note and must not be below any of their
    /// heights.
    pub anchor_height: Option<u64>,
    /// When the transaction stops being minable.
    ///
    /// `None` is [`DEFAULT_EXPIRY_BLOCKS`] past the **chain tip**, as the
    /// [`ChainReader`] reports it — the same policy [`send`](fn@crate::send)
    /// applies, and for the same reason: a spend that does not confirm should
    /// die rather than land months later against notes the wallet has since
    /// spent elsewhere.
    ///
    /// Not past the anchor. A caller pinning a deliberately deep anchor would
    /// otherwise get an expiry already behind the chain. And not from the light
    /// server's tip either — see [`SpendPlan::tip`](crate::SpendPlan#structfield.tip).
    pub expiry: Option<Expiry>,
}

/// A shielded spend, built and signed.
///
/// There are no transparent *inputs* in a shielded spend, so these bytes are
/// complete the moment they are produced — nothing further to sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldedSpent {
    /// The transaction id, computed locally from `hex`.
    pub txid: String,
    /// The raw bytes.
    pub hex: String,
    /// Fee paid, as asked for.
    pub fee: u64,
    /// Value returned to `change_address`, zero when the notes covered the
    /// outputs exactly.
    pub change: u64,
    /// The anchor every spend proof was built against, checked against the
    /// chain's own `finalsaplingroot` before proving.
    pub anchor: [u8; 32],
    /// The height that anchor came from.
    pub anchor_height: u64,
    /// The nullifiers this transaction publishes — one per note spent.
    ///
    /// A wallet marks these notes spent on seeing them in a block. Recorded
    /// here so it need not re-derive them, and so a spend that is broadcast and
    /// then lost track of can still be reconciled.
    pub nullifiers: Vec<[u8; 32]>,
}

/// Spend shielded notes and hand the bytes to a node.
///
/// # Errors
///
/// Everything [`prepare_spend`] can report, plus
/// [`FlowError::BroadcastUncertain`] — **do not simply retry**, read
/// [`crate::broadcast`](mod@crate::broadcast).
pub fn spend<T: LightTransport>(
    light: &LightClient<T>,
    reader: &impl ChainReader,
    broadcaster: &impl Broadcaster,
    params: &SaplingParams,
    request: &SpendRequest<'_>,
) -> Result<ShieldedSpent, FlowError> {
    prepare_spend(light, reader, params, request)?.broadcast(broadcaster)
}

/// Build a shielded spend without sending it.
///
/// Takes no [`Broadcaster`], so it cannot broadcast — the same split every
/// write flow in this crate uses, enforced by the signature rather than by
/// remembering. Proving is expensive enough that a caller may well want to
/// inspect the result before committing to it.
///
/// # What it does, in order
///
/// 1. Selects notes ([`select_notes`](super::select_notes)) covering the outputs plus the fee.
/// 2. Witnesses each one to a shared anchor height through the light server.
/// 3. Checks every witness produced the *same* anchor.
/// 4. Checks that anchor against the block header's `finalsaplingroot`, read
///    from the [`ChainReader`] — a source the light server does not control.
/// 5. Only then proves.
///
/// # Errors
///
/// [`FlowError::InsufficientFunds`] if the notes cannot cover the outputs and
/// the fee, [`FlowError::Shielded`] for every way the anchor, the witnesses or
/// the request itself cannot be trusted, and [`FlowError::Tx`] / the sapling
/// error surface for a build that fails.
pub fn prepare_spend<T: LightTransport>(
    light: &LightClient<T>,
    reader: &impl ChainReader,
    params: &SaplingParams,
    request: &SpendRequest<'_>,
) -> Result<Unsent<ShieldedSpent>, FlowError> {
    // Select, witness, and check the anchor against the chain — all of it
    // before the first proof, and none of it needing the prover.
    let plan = plan_spend(
        light,
        reader,
        request.notes,
        cost_of(request)?,
        request.anchor_height,
    )?;
    prove_spend(params, &plan, request)
}

/// Prove and sign a spend against a plan that has already been made.
///
/// The half of [`prepare_spend`] that costs money. Separate because
/// [`plan_spend`] is cheap and this is not: an interface that wants to show a
/// user what is about to happen — which notes, what change, which anchor — can
/// plan, display, and only then prove, without fetching everything twice.
///
/// # Errors
///
/// [`FlowError::Shielded`] if the plan does not account for this request. That
/// is checked rather than assumed: a plan whose notes are worth a different
/// total would otherwise produce a transaction whose change output silently
/// absorbs the difference, or one that pays a miner the lot.
///
/// The check is on the **total**, which is what conservation depends on. It
/// does not — and cannot — tell a plan made for outputs 90 + fee 10 from one
/// made for outputs 10 + fee 90: both spend the same notes and both conserve.
pub fn prove_spend(
    params: &SaplingParams,
    plan: &SpendPlan,
    request: &SpendRequest<'_>,
) -> Result<Unsent<ShieldedSpent>, FlowError> {
    check_plan_covers(plan.total_in, plan.change, cost_of(request)?)?;
    if plan.notes.is_empty() {
        return Err(FlowError::Shielded(
            "a spend needs at least one note".into(),
        ));
    }

    let mut shielded: Vec<ShieldedOutput> = request
        .shielded_to
        .iter()
        .map(|to| ShieldedOutput {
            recipient: to.address,
            value: to.amount,
            memo: to.memo,
        })
        .collect();
    if plan.change > 0 {
        shielded.push(ShieldedOutput::new(
            change_address(request, plan)?,
            plan.change,
        ));
    }

    let transparent = request
        .transparent_to
        .iter()
        .map(|to| {
            Ok(TxOut {
                value: to.amount,
                script_pubkey: transparent_script(&to.address)?,
            })
        })
        .collect::<Result<Vec<_>, FlowError>>()?;

    // From the chain tip, not from the anchor. A caller pinning a deliberately
    // deep anchor for reorg safety would otherwise get an expiry *behind* the
    // tip — a transaction born unminable, discovered only after paying for the
    // proof, which is the exact failure class the anchor check exists to
    // pre-empt.
    let expiry = match request.expiry {
        Some(expiry) => expiry,
        None => Expiry::within(height_u32(plan.tip)?, DEFAULT_EXPIRY_BLOCKS),
    };
    expiry.check()?;

    let notes: Vec<NoteToSpend<'_>> = plan
        .notes
        .iter()
        .map(|note| note.to_spend(request.extsk))
        .collect();

    let tx = build_shielded_spend(
        params,
        &SpendSpec {
            notes: &notes,
            shielded_outputs: &shielded,
            transparent_outputs: &transparent,
            fee: request.fee,
            expiry_height: expiry.to_height(),
            branch_id: VERUS_BRANCH_ID,
            zip212: VERUS_ZIP212,
            // Belt and braces: `plan_spend` already compared this against the
            // chain, and the builder refuses again before its first proof.
            expected_anchor: Some(plan.anchor),
        },
    )
    .map_err(|e| FlowError::Shielded(format!("building the spend: {e}")))?;

    let raw = tx
        .serialize()
        .map_err(|e| FlowError::Shielded(format!("serializing the spend: {e}")))?;
    let txid = txid_display(
        &tx.txid()
            .map_err(|e| FlowError::Shielded(format!("computing the txid: {e}")))?,
    );
    let hex = hex::encode(&raw);

    Ok(Unsent {
        hex: hex.clone(),
        txid: txid.clone(),
        outcome: ShieldedSpent {
            txid,
            hex,
            fee: request.fee,
            change: plan.change,
            anchor: plan.anchor,
            anchor_height: plan.anchor_height,
            nullifiers: plan.notes.iter().map(|n| n.note.nullifier).collect(),
        },
    })
}

/// The plan's notes must be worth exactly what the spend costs plus what it
/// returns as change.
///
/// Split out from [`prove_spend`] so it can be tested without the ~50 MB of
/// Sapling parameters that function's signature demands — the guard runs long
/// before any of them are touched, and a cheap check reachable only through an
/// expensive call is a check that does not get tested.
fn check_plan_covers(total_in: u64, change: u64, needed: u64) -> Result<(), FlowError> {
    if change.checked_add(needed) == Some(total_in) {
        return Ok(());
    }
    Err(FlowError::Shielded(format!(
        "this plan spends notes worth {total_in} zatoshi against {needed} of outputs and fee \
         with {change} as change, which does not balance; it was made for a different request"
    )))
}

/// What the transaction must cover: every output, plus the fee.
///
/// One function because computing it in two places is how a plan and a proof
/// come to disagree about the change.
fn cost_of(request: &SpendRequest<'_>) -> Result<u64, FlowError> {
    if request.shielded_to.is_empty() && request.transparent_to.is_empty() {
        return Err(FlowError::Shielded(
            "a spend with no recipients would pay its whole value to a miner".into(),
        ));
    }
    total_out(request)?.checked_add(request.fee).ok_or_else(|| {
        FlowError::Shielded("the outputs and the fee together overflow a u64".into())
    })
}

/// Total value leaving the shielded pool, outputs only.
fn total_out(request: &SpendRequest<'_>) -> Result<u64, FlowError> {
    let mut total: u64 = 0;
    for amount in request
        .shielded_to
        .iter()
        .map(|to| to.amount)
        .chain(request.transparent_to.iter().map(|to| to.amount))
    {
        total = total
            .checked_add(amount)
            .ok_or_else(|| FlowError::Shielded("the outputs overflow a u64".into()))?;
    }
    Ok(total)
}

/// Where change goes: what the caller asked for, or the largest note's own
/// address.
fn change_address(request: &SpendRequest<'_>, plan: &SpendPlan) -> Result<[u8; 43], FlowError> {
    match request.change_address {
        Some(address) => Ok(address),
        // `select_notes` returns largest-first, so this is the biggest note —
        // and an address this key was already paid at, so demonstrably one it
        // controls.
        None => plan
            .notes
            .first()
            .map(|note| note.note.recipient)
            .ok_or_else(|| FlowError::Shielded("no note to take a change address from".into())),
    }
}

/// The output script paying a transparent recipient.
///
/// A VerusID is **not** a P2PKH output with a different hash in it: it is a
/// CryptoCondition whose destination carries an identity type byte. Writing one
/// as a bare 20-byte hash produces a script paying a transparent address that
/// merely shares the identity's hash — spendable by nobody. That is the same
/// dispatch `verus_tx::build_transparent_send` makes, applied here because a
/// shielded spend builds its transparent outputs itself.
///
/// # Errors
///
/// [`FlowError::Shielded`] for a script-hash address, which this crate does not
/// build outputs for; [`FlowError::Tx`] if the script cannot be built.
pub fn transparent_script(address: &Address) -> Result<Vec<u8>, FlowError> {
    match address.kind() {
        AddressKind::Identity => Ok(identity_payment_script(address.hash())?),
        AddressKind::PubKeyHash => Ok(address.p2pkh_script_pubkey()?),
        AddressKind::ScriptHash => Err(FlowError::Shielded(format!(
            "{address} is a script hash; this crate does not build P2SH outputs for a shielded \
             spend, and paying it as a key hash would be spendable by nobody"
        ))),
    }
}

/// A height as consensus counts them.
fn height_u32(height: u64) -> Result<u32, FlowError> {
    u32::try_from(height)
        .map_err(|_| FlowError::Shielded(format!("block height {height} does not fit in 32 bits")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plan's notes must be worth exactly the spend plus the change.
    ///
    /// This is the guard that stops a plan made for one request being proved
    /// against another, and it runs before the ~50 MB of Sapling parameters
    /// `prove_spend` demands are touched — which is why it is a separate
    /// function, and why it is testable at all.
    #[test]
    fn a_plan_that_balances_is_accepted_and_one_that_does_not_is_refused() {
        // 100 in, 90 spent, 10 back.
        check_plan_covers(100, 10, 90).expect("balances");
        // The change-free case the live z→t used.
        check_plan_covers(4_970_000, 0, 4_970_000).expect("balances exactly");

        // A plan for a cheaper request: 10 zatoshi would go to the miner.
        assert!(check_plan_covers(100, 10, 80).is_err());
        // A plan for a dearer one: the notes do not cover it.
        assert!(check_plan_covers(100, 10, 100).is_err());
    }

    /// Overflow must refuse rather than wrap into a plan that appears to
    /// balance. `change + needed` is caller-influenced on both terms.
    #[test]
    fn a_change_and_cost_that_wrap_do_not_look_balanced() {
        assert!(check_plan_covers(0, u64::MAX, 1).is_err());
        assert!(check_plan_covers(u64::MAX, u64::MAX, u64::MAX).is_err());
    }

    /// The message has to name all three numbers: "does not balance" alone
    /// leaves a wallet author nothing to compare.
    #[test]
    fn the_refusal_names_what_disagreed() {
        let message = match check_plan_covers(100, 10, 80) {
            Err(FlowError::Shielded(message)) => message,
            other => panic!("expected a refusal, got {other:?}"),
        };
        for number in ["100", "10", "80"] {
            assert!(message.contains(number), "{number} missing from: {message}");
        }
        // And no run of stray whitespace from a broken line continuation.
        assert!(!message.contains("  "), "{message}");
    }

    #[test]
    fn an_identity_is_paid_as_a_cryptocondition_not_as_a_key_hash() {
        // A real VRSCTEST identity — the one paid by the on-chain
        // pay-to-identity proof in `PROVEN.md`.
        let identity: Address = "i8jHXEEYEQ7KEoYe6eKXBib8cUBZ6vjWSd".parse().expect("i");
        let script = transparent_script(&identity).expect("a script");
        assert_eq!(
            script,
            identity_payment_script(identity.hash()).expect("a script")
        );
        // Not a P2PKH script: those open `OP_DUP OP_HASH160`. Writing the
        // identity's 20 bytes into one of those pays an address that merely
        // shares the hash, and is spendable by nobody.
        assert_ne!(&script[..2], &[0x76, 0xa9]);
        // `verus-keys` refuses that mistake outright, which is why this
        // function has to dispatch rather than reach for the P2PKH script
        // every time.
        assert!(identity.p2pkh_script_pubkey().is_err());
    }

    #[test]
    fn a_key_hash_is_paid_as_p2pkh() {
        let address: Address = "RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX".parse().expect("R");
        assert_eq!(
            transparent_script(&address).expect("a script"),
            address.p2pkh_script_pubkey().expect("a script")
        );
    }
}
