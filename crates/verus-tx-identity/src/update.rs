//! Updating a VerusID.
//!
//! An update spends the output that currently holds the identity and publishes a
//! new one in its place. There is no partial update at the protocol level: the
//! new output carries the **whole** identity object, so every field the caller
//! does not deliberately change must be carried over unchanged from the chain's
//! current copy.
//!
//! An update may carry auxiliary transparent outputs alongside the identity —
//! see [`UpdateParams::additional_outputs`]. When present, they occupy the
//! start of the `vout` array; the identity primary follows, and change (if
//! any) trails.
//!
//! That is why this takes an [`Identity`] rather than a set of edits. The
//! intended flow is: read the current identity out of its output with
//! [`verus_tx_protocol::decode_output_script`], change what you mean to change, and hand the
//! whole thing back. An identity assembled from scratch will silently drop
//! whatever the chain already published — including, if you are careless with
//! `primary_addresses` or `min_sigs`, the authority to update it ever again.
//!
//! # Authority
//!
//! The identity output is a CryptoCondition whose master condition is `1-of-3`
//! over the identity, its revocation authority and its recovery authority. This
//! module signs as the identity: the keys must be `min_sigs` of the identity's
//! own `primary_addresses`, and they all go into a single fulfillment.
//! Revocation and recovery are different operations with different eval codes
//! and are not implemented here.
//!
//! The threshold that matters is the one on the **output being spent**, not the
//! one being published: raising `min_sigs` still only needs the old threshold to
//! authorise, and takes effect from the next update onward.
//!
//! Changing any of the four authority fields is refused unless
//! [`UpdateParams::allow_authority_change`] is set — see that field for why.
//!
//! # Who may change which authority
//!
//! Consensus validates the three conditions of that `1-of-3` **separately**,
//! each one guarding its own fields. From `ValidateIdentityPrimary`,
//! `ValidateIdentityRevoke` and `ValidateIdentityRecover` in VerusCoin's
//! `src/pbaas/identity.cpp`, read at `master` on 2026-08-05:
//!
//! | changing | needs the … condition satisfied | refusal, as consensus names it internally |
//! |---|---|---|
//! | `primary_addresses`, `min_sigs` | primary | `Unauthorized identity modification` |
//! | `revocation_authority` | revocation | `Unauthorized modification of revocation information` |
//! | `recovery_authority` | recovery | `Unauthorized modification of recovery information` |
//!
//! So an authority is **not** frozen at registration, and it is **not** freely
//! editable either. Which of the two applies depends on where it currently
//! points:
//!
//! * A **freshly registered identity is all three authorities at once**, so the
//!   same `primary_addresses` satisfy all three conditions. It can point
//!   revocation and recovery elsewhere in an ordinary update — a self-authority
//!   identity is not stuck with that shape.
//! * Once an authority points at **another** identity, the primary keys alone
//!   can no longer move it. Only the authority currently named can, and it
//!   cannot be taken back by the identity. That is the direction with no undo,
//!   and the reason [`UpdateParams::allow_authority_change`] is off by default.
//!
//! Both halves are proven on VRSCTEST rather than argued from the source above.
//! `vdxf1171008.VRSCTEST@`, its own recovery authority since registration, moved
//! that authority to `VRSCTEST@` with nothing but its own primary keys at block
//! 1177036 (`e3994443922e3a2e01e42b5a830ac48314d3fae60d4cb8c3859db2a4b8f9058a`).
//! The same run then tried to move it back with the same keys and was refused.
//! See `crates/verus-flows/tests/live_authority.rs`.
//!
//! The refusal names nothing — `mandatory-script-verify-flag-failed`, the
//! generic "a script finished false". Consensus does not report *which*
//! condition went unsatisfied, so a caller who is wrong about which authority
//! they hold learns only that something failed. That is why
//! [`UpdateParams::allow_authority_change`] refuses by default instead of
//! letting the daemon be the first thing to say no.
//!
//! Both thresholds are proven on VRSCTEST: `rustsdk@` (`1-of-1`) updated at
//! block 1166566, and `rustmulti@` (`2-of-2`) at block 1166732 with both
//! signatures in one fulfillment
//! (`9ff188d8fabbb338d11ed1405345783265a02c3afc8b5705ccd9d35e0d802303`).

use verus_keys::{Address, PrivateKey};

use crate::register::identity_id;
use verus_tx_primitives::cc::{identity_primary_script, Destination};
use verus_tx_primitives::fee::{DEFAULT_FEE_PER_KB, SMART_OUTPUT_SIZE};
use verus_tx_primitives::Amount;
use verus_tx_primitives::Expiry;
use verus_tx_primitives::TxError;
use verus_tx_primitives::Utxo;
use verus_tx_protocol::decode::{decode_output_script, OutputKind};
use verus_tx_protocol::identity::{Identity, FLAG_LOCKED, MAX_UNLOCK_DELAY};
use verus_tx_transparent::assemble::{assemble, check_expiry, check_p2pkh_funding, Assembly};
use verus_tx_transparent::SignedTransaction;
use verus_wire::TxOut;

/// What to update, and what to fund it with.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct UpdateParams<'a> {
    /// The output currently holding the identity — what `getidentity` reports as
    /// its `txid`/`vout`. It carries no native value.
    pub identity_output: &'a Utxo,
    /// The identity as it should read AFTER the update, stated in full.
    pub identity: &'a Identity,
    /// P2PKH UTXOs to pay the miner fee from.
    pub utxos: &'a [Utxo],
    /// Where change goes.
    pub change_address: Address,
    /// When this transaction stops being minable. See [`Expiry`].
    pub expiry: Expiry,
    /// Fee rate in satoshis per kilobyte.
    pub fee_per_kb: u64,
    /// Permit changing who controls the identity.
    ///
    /// Off by default, and worth leaving off. An update that alters
    /// `primary_addresses`, `min_sigs`, or either authority is the one mistake
    /// with no remedy: publish a threshold nobody can meet, or addresses nobody
    /// holds, and the identity can never be updated again — not by the holder,
    /// not by the recovery authority, not by anyone. Changing content carries no
    /// such risk, which is why it does not need this.
    ///
    /// The check compares against the identity **as the chain currently has
    /// it**, decoded from the output being spent, not against anything the
    /// caller supplies.
    ///
    /// Setting this does not mean consensus will accept the result: each
    /// authority field is guarded by its own spend condition, and the identity's
    /// primary keys satisfy the revocation and recovery ones only while the
    /// identity is still its own authority. See [the module docs](self#who-may-change-which-authority).
    pub allow_authority_change: bool,
    /// The chain tip, if known, so the timelock rules can be checked in full.
    ///
    /// Consensus decides whether an identity is locked *right now* partly from
    /// whether its unlock height has passed, which cannot be known offline. With
    /// this set, [`build_identity_update`] applies every timelock rule; without
    /// it, the one rule that needs the height — an identity part-way through a
    /// countdown — goes unchecked and is left to the daemon, which will report
    /// only that a script finished false.
    ///
    /// [`crate::update`]'s flow counterpart in `verus-flows` always sets it,
    /// because it has already read the tip to compute the expiry.
    pub tip: Option<u32>,
    /// Extra transparent outputs to emit before the identity primary, in the
    /// caller-supplied order.
    ///
    /// Empty on every historical path. The one caller that needs this is a
    /// content-multimap encryptor that pairs a `flags:13` cmm entry with one or
    /// more `EVAL_NOTARY_EVIDENCE` data-deposit outputs the entry points at by
    /// vout index: the pointer is baked in at encrypt time, so the position
    /// each output lands at has to be fixed and knowable up front.
    ///
    /// # Vout layout
    ///
    /// The final `vout` array is
    /// `[additional_outputs.., identity_primary, (change if any)]`. Aux outputs
    /// occupy indices `0..N`, the identity primary lands at `N`, and change
    /// (when it appears) at `N + 1`.
    ///
    /// Aux at the front rather than after the identity has two consequences.
    /// The ergonomic one is that the caller's baked-in index is `0` and does
    /// not depend on how many outputs the builder emits alongside — a later
    /// addition to that layout cannot silently shift the pointer. The
    /// stronger one is a consensus alignment: on a tokenized-control
    /// identity, `ValidateIdentityRevoke` and `ValidateIdentityRecover`
    /// (VerusCoin `src/pbaas/identity.cpp`, `master@d1df9b7`, lines 3119 and
    /// 3265) reserve the slot at `idIndex + 1` for the control token. Aux
    /// after the identity would have collided with that slot on those two
    /// spend paths.
    ///
    /// # The cross-field contract
    ///
    /// The invariant that matters — *the vout index baked into the cmm entry
    /// points at the evidence output that belongs to it* — spans two fields
    /// of this struct: [`Self::identity`]'s `content_multimap`, which the
    /// caller mutates, and [`Self::additional_outputs`]. Nothing here
    /// correlates them, and consensus does not check the index either
    /// (`CUTXORef` with a null txid means "this transaction"; see
    /// `IsOnSameTransaction` in VerusCoin `src/primitives/transaction.h`,
    /// resolved as `tx.vout[output.n]` at read time). A mismatch is a valid,
    /// mined transaction whose data is silently unretrievable. The contract
    /// is: this builder guarantees the order (aux first, in the order given);
    /// the caller guarantees the index (indices `0..additional_outputs.len()`
    /// baked into the cmm entry are the ones the corresponding aux outputs
    /// land at).
    ///
    /// # Requirements the daemon places on the scripts
    ///
    /// This crate does not model `EVAL_NOTARY_EVIDENCE`, and nothing here
    /// inspects the bytes — caller-supplied `script_pubkey` values are
    /// emitted verbatim, in the order given. Consensus rejects a malformed
    /// script at broadcast (or, worse, mines a transaction whose payload is
    /// unreadable), which is where any check here would need to re-run
    /// anyway. What the daemon requires, transcribed from
    /// `master@d1df9b7`:
    ///
    /// * The evidence type must be `TYPE_IMPORT_PROOF`, not
    ///   `TYPE_NOTARY_EVIDENCE`. `PreCheckNotaryEvidence` in
    ///   `src/pbaas/notarization.cpp:11113` rejects the latter on any
    ///   transaction that does not reference a real notarization output. The
    ///   daemon's own `updateidentity` (`src/rpc/pbaasrpc.cpp`) uses
    ///   `TYPE_IMPORT_PROOF` for data deposits.
    /// * Each output must be the canonical 1-of-1 to the eval's well-known
    ///   pubkey (`IsEvalPKOut`), and `::AsVector(evidence) == p.vData[0]`
    ///   must hold exactly.
    /// * A payload split into chunks must occupy **contiguous** vouts with
    ///   correct internal `md.index` values. `PreCheckNotaryEvidence`
    ///   recomputes `multiStart = outNum - md.index` and requires the vout
    ///   at `multiStart` to be a chunk whose `index == 0`.
    /// * No aux output may be an `EVAL_IDENTITY_PRIMARY`. A second one for
    ///   the same ID invalidates the transaction in the `CIdentity(tx, ...)`
    ///   constructor (`src/pbaas/identity.cpp:42`); one for a different ID
    ///   fails `PrecheckIdentityPrimary`.
    ///
    /// # Fee accounting
    ///
    /// `build_identity_update` pads its `fee_output_count` with each aux
    /// script's excess bytes over `SMART_OUTPUT_SIZE`. Scripts at or under
    /// that threshold contribute zero, which keeps every historical golden
    /// byte-identical. The pad covers the offline estimator's undercount
    /// only. The daemon's `GetMinRelayFeeByOutputs` (`reserves.cpp:7896`)
    /// adds further charges — per vout beyond three, per 128 bytes of
    /// content multimap, and for evidence storage bytes on a transaction
    /// flagged `IS_EVIDENCE_STORAGE | IS_HIGH_FEE` (`reserves.cpp:3469`) —
    /// which are not modelled here. Underpayment against that policy is
    /// soft: the free-transaction rate limiter, not a reject.
    pub additional_outputs: Vec<TxOut>,
}

impl<'a> UpdateParams<'a> {
    /// Parameters with the default fee rate and authority changes refused.
    pub fn new(
        identity_output: &'a Utxo,
        identity: &'a Identity,
        utxos: &'a [Utxo],
        change_address: Address,
        expiry: Expiry,
    ) -> Self {
        Self {
            identity_output,
            identity,
            utxos,
            change_address,
            expiry,
            fee_per_kb: DEFAULT_FEE_PER_KB,
            allow_authority_change: false,
            tip: None,
            additional_outputs: Vec::new(),
        }
    }

    /// Tell the builder the current height, enabling the full timelock check.
    #[must_use]
    pub fn at_tip(mut self, tip: u32) -> Self {
        self.tip = Some(tip);
        self
    }

    /// Override the fee rate.
    pub fn with_fee_per_kb(mut self, fee_per_kb: u64) -> Self {
        self.fee_per_kb = fee_per_kb;
        self
    }

    /// Permit changing who controls the identity.
    ///
    /// Read [`UpdateParams::allow_authority_change`] before calling this: it is
    /// the one VerusID mistake with no remedy.
    pub fn allowing_authority_change(mut self) -> Self {
        self.allow_authority_change = true;
        self
    }

    /// Emit these transparent outputs before the identity primary.
    ///
    /// See [`UpdateParams::additional_outputs`] for the vout layout and why
    /// the caller-controlled position is `0`.
    #[must_use]
    pub fn with_additional_outputs(mut self, outputs: Vec<TxOut>) -> Self {
        self.additional_outputs = outputs;
        self
    }
}

/// Build and sign an identity update.
///
/// `funding_key` pays the miner fee from `params.utxos`. `identity_keys` satisfy
/// the identity's own condition and must be `min_sigs` of its
/// `primary_addresses` — for the ordinary `1-of-1` identity both are the same
/// key, passed twice.
///
/// A key the identity does not list produces a transaction the daemon rejects at
/// script verification, reporting only that a script finished false, so it is
/// refused here instead.
pub fn build_identity_update(
    funding_key: &PrivateKey,
    identity_keys: &[&PrivateKey],
    params: &UpdateParams<'_>,
) -> Result<SignedTransaction, TxError> {
    check_expiry(params.expiry)?;
    check_p2pkh_funding(params.utxos)?;

    let identity = params.identity;
    let id = identity_id(&identity.name, Some(identity.parent));

    // The chain's copy is the authority on what is being spent and on who may
    // spend it. Everything below compares against this, never against the
    // caller's proposed identity — a caller who got the authority wrong would
    // otherwise be checked against their own mistake.
    let current = match decode_output_script(&params.identity_output.script_pubkey)? {
        OutputKind::IdentityPrimary { identity } => *identity,
        _ => return Err(TxError::IdentityOutputMismatch),
    };
    if identity_id(&current.name, Some(current.parent)) != id {
        return Err(TxError::IdentityOutputMismatch);
    }

    if !params.allow_authority_change {
        check_authority_unchanged(&current, identity)?;
    }
    check_timelock(&current, identity, params.expiry.to_height(), params.tip)?;

    // Satisfying the condition takes min_sigs signatures — the CURRENT
    // threshold, since that is what the output being spent commits to. An
    // update that raises the threshold still only needs the old one.
    if identity_keys.len() < current.min_sigs as usize {
        return Err(TxError::NotEnoughSigners {
            supplied: identity_keys.len(),
            required: current.min_sigs,
        });
    }
    for key in identity_keys {
        let signer = Destination::PubKeyHash(key.address().hash());
        if !current.primary_addresses.contains(&signer) {
            return Err(TxError::NotAPrimaryAddress {
                address: key.address().to_string(),
            });
        }
    }

    let script_pubkey = identity_primary_script(
        id,
        identity.to_bytes()?,
        identity.revocation_authority,
        identity.recovery_authority,
        identity.has_tokenized_control(),
    )?;

    // Aux outputs come first, then the identity primary. Fixing the layout
    // this way lets a caller whose payload commits to a vout index — the
    // `flags:13` cmm case — bake in `0` and stay right regardless of what
    // this builder emits alongside.
    let mut outputs = params.additional_outputs.clone();
    outputs.push(TxOut {
        value: 0,
        script_pubkey,
    });

    // `estimate_fee` prices every output as `SMART_OUTPUT_SIZE` (200 bytes)
    // and never inspects `script_pubkey.len()`, so an aux output the caller
    // supplied — the payload this field exists to carry — is systematically
    // underpriced above that size. A 10 KB notary-evidence deposit priced
    // as 200 bytes sits in the mempool under the free-tx rate limiter and
    // never mines. Pad the count with the aux scripts' excess bytes,
    // expressed in the unit the estimator already uses, so a caller-side
    // fee change stays inside this crate and does not touch the shared
    // heuristic in `fee.rs` — its byte-parity with the TypeScript SDK is
    // the differential-vector correctness gate. The identity primary and
    // change already fit in one unit; scripts at or under 200 bytes
    // contribute zero, so every historical path stays byte-identical.
    let mut fee_output_count: u64 = outputs
        .len()
        .checked_add(1)
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(TxError::ValueOverflow)?;
    for aux in &params.additional_outputs {
        let len = u64::try_from(aux.script_pubkey.len()).map_err(|_| TxError::ValueOverflow)?;
        let pad = len
            .saturating_sub(SMART_OUTPUT_SIZE)
            .div_ceil(SMART_OUTPUT_SIZE);
        fee_output_count = fee_output_count
            .checked_add(pad)
            .ok_or(TxError::ValueOverflow)?;
    }

    assemble(
        funding_key,
        identity_keys,
        Assembly {
            leading: core::slice::from_ref(params.identity_output),
            funding: params.utxos,
            outputs,
            burn: Amount::ZERO,
            // Every declared output plus a change slot.
            fee_output_count,
            change_address: &params.change_address,
            change_script: None,
            value_bearing_leading: false,
            expiry: params.expiry,
            fee_per_kb: params.fee_per_kb,
        },
    )
}

/// Refuse an update the chain's timelock rules would reject.
///
/// A transcription of the timelock half of `CIdentity::IsInvalidMutation`
/// (VerusCoin `src/pbaas/identity.cpp`, read at `master` on 2026-08-05). Every
/// input it needs is already here, so these are refusals the caller can read
/// rather than the anonymous `mandatory-script-verify-flag-failed` the daemon
/// answers with once the fee is spent.
///
/// # The rules, and the one that surprises everyone
///
/// * **No instant unlock.** A locked identity cannot come out locked-false in
///   the same update, unless that update also revokes it.
/// * **An unlock only ever moves later.** Neither a longer delay nor a re-lock
///   may bring the unlock height forward.
/// * **A delay is capped** at [`MAX_UNLOCK_DELAY`].
/// * **Starting the countdown is measured from `nExpiryHeight`**, not from the
///   tip: leaving a delay of `d` requires publishing an unlock height of at
///   least `d + expiry`. This is the one a caller cannot work out alone, since
///   the expiry belongs to the transaction being built.
///
/// Measured against VRSCTEST on 2026-08-05 rather than left as a reading of the
/// source: from the flagged-locked state, `tip + delay` was refused and
/// `delay + expiry` accepted, and from a running countdown an earlier unlock and
/// an instant one were both refused while a later one was accepted. The rule is
/// a floor, not a pin. See `PROVEN.md`.
///
/// # Stale unlock heights
///
/// `unlock_after` keeps its value once a countdown elapses; nothing clears it.
/// So an identity that has ever been unlocked rests at flag-clear with a
/// non-zero height in the past, and every later update carries that height
/// through untouched. Consensus judges this by
/// `newIdentity.IsLocked(height)` alone — false for an elapsed height, so the
/// floor never applies. Anything stricter here refuses ordinary updates to an
/// ordinary identity, which is what it did until 2026-08-05.
///
/// # What is not checked, and where this is deliberately stricter
///
/// `IdentityLockOverride` — a chain-level override consensus consults — has no
/// offline equivalent, so an identity it exempts is judged locked here.
///
/// Without a tip, "counting down" cannot be told from "elapsed", so *setting* a
/// new absolute height is judged a live countdown and held to the floor. With a
/// tip, one case stays stricter than consensus on purpose: setting a height that
/// is already in the past. Consensus shrugs — the identity is unlocked either
/// way — while this refuses it, because a caller asking for it has almost
/// certainly computed the wrong number.
///
/// Both divergences are in the same safe direction: this refuses something the
/// chain would have allowed, rather than passing something it would reject.
fn check_timelock(
    current: &Identity,
    proposed: &Identity,
    expiry_height: u32,
    tip: Option<u32>,
) -> Result<(), TxError> {
    let refuse = |reason: String| Err(TxError::TimelockRefused { reason });

    // "Locked" has two senses and both matter. The flag alone means locked and
    // *not* counting down; the height comparison catches an identity part-way
    // through a countdown, and is the only part that needs the tip.
    let flagged = |id: &Identity| id.flags & FLAG_LOCKED != 0;
    let locked_now = |id: &Identity| match tip {
        _ if id.is_revoked() => false,
        Some(height) => flagged(id) || id.unlock_after >= height,
        // Without the tip, only the unambiguous half is known.
        None => flagged(id),
    };

    if locked_now(current) && !proposed.is_revoked() {
        if !locked_now(proposed) {
            return refuse(format!(
                "the identity is locked and this update would leave it unlocked; only a \
                 revocation may do that in one step (unlock_after {} -> {})",
                current.unlock_after, proposed.unlock_after
            ));
        }
        if flagged(current) {
            if flagged(proposed) {
                if proposed.unlock_after < current.unlock_after {
                    return refuse(format!(
                        "a locked identity's delay may only grow: {} -> {}",
                        current.unlock_after, proposed.unlock_after
                    ));
                }
            } else {
                // Starting the countdown. The floor is the delay plus this
                // transaction's own expiry height, with one escape for delays
                // that were set above the cap before it applied.
                let floor = current.unlock_after.saturating_add(expiry_height);
                let escape = current.unlock_after > MAX_UNLOCK_DELAY
                    && proposed.unlock_after == MAX_UNLOCK_DELAY.saturating_add(expiry_height);
                if proposed.unlock_after < floor && !escape {
                    return refuse(format!(
                        "starting the countdown needs an unlock height of at least {floor} \
                         (delay {} + this transaction's expiry {expiry_height}), not {}",
                        current.unlock_after, proposed.unlock_after
                    ));
                }
            }
        } else if flagged(proposed) {
            if expiry_height.saturating_add(proposed.unlock_after) < current.unlock_after {
                return refuse(format!(
                    "re-locking may not bring the unlock forward: {} + delay {} is before the \
                     current unlock height {}",
                    expiry_height, proposed.unlock_after, current.unlock_after
                ));
            }
        } else if proposed.unlock_after < current.unlock_after {
            return refuse(format!(
                "an unlock height may only move later: {} -> {}",
                current.unlock_after, proposed.unlock_after
            ));
        }
    } else if locked_now(proposed)
        // Consensus stops at `locked_now(proposed)`. The rest is this crate
        // covering the tipless case, where "counting down" and "elapsed" cannot
        // be told apart: an absolute height being *set* is then treated as a
        // live countdown. It must not fire on a height being carried through
        // unchanged, which is the resting state of every identity that has ever
        // been unlocked — see the note on stale heights below.
        || (!flagged(proposed)
            && proposed.unlock_after != 0
            && proposed.unlock_after != current.unlock_after)
    {
        if flagged(proposed) {
            if proposed.unlock_after > MAX_UNLOCK_DELAY {
                return refuse(format!(
                    "a lock delay of {} exceeds the maximum of {MAX_UNLOCK_DELAY}",
                    proposed.unlock_after
                ));
            }
        } else if proposed.unlock_after <= expiry_height {
            return refuse(format!(
                "an unlock height of {} is not past this transaction's expiry {expiry_height}, \
                 so the identity would be unlocked before it could be mined",
                proposed.unlock_after
            ));
        }
    }
    Ok(())
}

/// Refuse an update that moves control of the identity.
///
/// These four fields decide who may ever update, revoke or recover it. Content
/// is not checked: changing it is the normal reason to update at all.
fn check_authority_unchanged(current: &Identity, proposed: &Identity) -> Result<(), TxError> {
    let changed = |field: &str| {
        Err(TxError::AuthorityChangeRefused {
            field: field.to_string(),
        })
    };
    if current.primary_addresses != proposed.primary_addresses {
        return changed("primary_addresses");
    }
    if current.min_sigs != proposed.min_sigs {
        return changed("min_sigs");
    }
    if current.revocation_authority != proposed.revocation_authority {
        return changed("revocation_authority");
    }
    if current.recovery_authority != proposed.recovery_authority {
        return changed("recovery_authority");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use verus_tx_primitives::fee::DUST_THRESHOLD;
    use verus_tx_primitives::Txid;
    use verus_wire::TxV4;

    const TEST_WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";
    const VRSCTEST: &str = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";

    fn key() -> PrivateKey {
        PrivateKey::from_wif(TEST_WIF).unwrap()
    }

    /// A second, unrelated key — the co-signer of a multisig identity.
    fn other_key() -> PrivateKey {
        PrivateKey::from_bytes(&[0x27; 32], true).unwrap()
    }

    fn parent() -> [u8; 20] {
        VRSCTEST.parse::<Address>().unwrap().hash()
    }

    fn identity(primaries: Vec<Destination>, min_sigs: u32) -> Identity {
        Identity {
            version: 3,
            flags: 0,
            primary_addresses: primaries,
            min_sigs,
            parent: parent(),
            name: "rustsdk".to_string(),
            content_multimap: Vec::new(),
            content_map: Vec::new(),
            revocation_authority: identity_id("rustsdk", Some(parent())),
            recovery_authority: identity_id("rustsdk", Some(parent())),
            private_addresses: Vec::new(),
            system_id: parent(),
            unlock_after: 0,
        }
    }

    /// A single-signature identity controlled by `key()`.
    fn simple_identity() -> Identity {
        identity(vec![Destination::PubKeyHash(key().address().hash())], 1)
    }

    /// The output the chain currently holds this identity in.
    fn identity_utxo(identity: &Identity) -> Utxo {
        Utxo {
            txid: Txid::from_internal([0xaa; 32]),
            vout: 0,
            satoshis: Amount::from_sat(0),
            script_pubkey: identity_primary_script(
                identity_id(&identity.name, Some(identity.parent)),
                identity.to_bytes().unwrap(),
                identity.revocation_authority,
                identity.recovery_authority,
                identity.has_tokenized_control(),
            )
            .unwrap(),
        }
    }

    fn funding(key: &PrivateKey) -> Vec<Utxo> {
        vec![Utxo {
            txid: Txid::from_internal([0xbb; 32]),
            vout: 0,
            satoshis: Amount::from_sat(100_000_000),
            script_pubkey: key.address().p2pkh_script_pubkey().unwrap(),
        }]
    }

    /// Publishing content is the ordinary case and needs no opt-in.
    #[test]
    fn builds_an_update_spending_the_identity_output() {
        let key = key();
        let current = simple_identity();
        let held = identity_utxo(&current);
        let mut proposed = current.clone();
        proposed.content_map = vec![([0x01; 20], [0x02; 32])];
        let utxos = funding(&key);
        let params = UpdateParams::new(&held, &proposed, &utxos, key.address(), Expiry::Never);
        let signed = build_identity_update(&key, &[&key], &params).unwrap();
        assert_eq!(signed.inputs_used[0], (held.txid, held.vout));
        assert_eq!(signed.inputs_used.len(), 2);
    }

    /// Signing with a key the identity does not list would fail at script
    /// verification with an error that names neither the input nor the cause.
    #[test]
    fn refuses_a_key_that_is_not_a_primary_address() {
        let key = key();
        let current = identity(vec![Destination::PubKeyHash([0x99; 20])], 1);
        let held = identity_utxo(&current);
        let utxos = funding(&key);
        let params = UpdateParams::new(&held, &current, &utxos, key.address(), Expiry::Never);
        assert!(matches!(
            build_identity_update(&key, &[&key], &params),
            Err(TxError::NotAPrimaryAddress { .. })
        ));
    }

    /// A 2-of-2 identity signs with both keys, in one fulfillment.
    #[test]
    fn signs_a_multisig_identity_with_every_key() {
        let key = key();
        let other = other_key();
        let current = identity(
            vec![
                Destination::PubKeyHash(key.address().hash()),
                Destination::PubKeyHash(other.address().hash()),
            ],
            2,
        );
        let held = identity_utxo(&current);
        let utxos = funding(&key);
        let params = UpdateParams::new(&held, &current, &utxos, key.address(), Expiry::Never);
        let signed = build_identity_update(&key, &[&key, &other], &params).unwrap();

        // The fulfillment on input 0 carries a count of 2. Its layout is
        // version, hash type, count — after the outer push opcode.
        let raw = hex::decode(&signed.hex).unwrap();
        let fulfillment_count = raw
            .windows(3)
            .find(|w| w[0] == 1 && w[1] == 1 && (w[2] == 1 || w[2] == 2))
            .map(|w| w[2])
            .expect("a fulfillment header");
        assert_eq!(fulfillment_count, 2);
    }

    /// One signature cannot satisfy a 2-of-2 condition. Catching it here beats
    /// broadcasting a transaction that can never verify.
    #[test]
    fn refuses_fewer_keys_than_the_threshold() {
        let key = key();
        let other = other_key();
        let current = identity(
            vec![
                Destination::PubKeyHash(key.address().hash()),
                Destination::PubKeyHash(other.address().hash()),
            ],
            2,
        );
        let held = identity_utxo(&current);
        let utxos = funding(&key);
        let params = UpdateParams::new(&held, &current, &utxos, key.address(), Expiry::Never);
        assert!(matches!(
            build_identity_update(&key, &[&key], &params),
            Err(TxError::NotEnoughSigners {
                supplied: 1,
                required: 2
            })
        ));
    }

    /// The threshold that authorises is the one on the output being spent, not
    /// the one being published — so raising it needs only the old threshold.
    #[test]
    fn raising_the_threshold_authorises_against_the_old_one() {
        let key = key();
        let other = other_key();
        let current = simple_identity();
        let held = identity_utxo(&current);
        let mut proposed = current.clone();
        proposed
            .primary_addresses
            .push(Destination::PubKeyHash(other.address().hash()));
        proposed.min_sigs = 2;
        let utxos = funding(&key);
        let params = UpdateParams {
            allow_authority_change: true,
            ..UpdateParams::new(&held, &proposed, &utxos, key.address(), Expiry::Never)
        };
        // One key, because the CURRENT identity is 1-of-1.
        assert!(build_identity_update(&key, &[&key], &params).is_ok());
    }

    /// Each authority field is refused on its own, and named in the error.
    #[test]
    fn refuses_authority_changes_by_default() {
        let key = key();
        let current = simple_identity();
        let held = identity_utxo(&current);
        let utxos = funding(&key);

        let mut primaries = current.clone();
        primaries.primary_addresses = vec![Destination::PubKeyHash([0x99; 20])];
        let mut sigs = current.clone();
        sigs.min_sigs = 2;
        let mut revocation = current.clone();
        revocation.revocation_authority = [0x99; 20];
        let mut recovery = current.clone();
        recovery.recovery_authority = [0x99; 20];

        for (proposed, expected) in [
            (primaries, "primary_addresses"),
            (sigs, "min_sigs"),
            (revocation, "revocation_authority"),
            (recovery, "recovery_authority"),
        ] {
            let params = UpdateParams::new(&held, &proposed, &utxos, key.address(), Expiry::Never);
            match build_identity_update(&key, &[&key], &params) {
                Err(TxError::AuthorityChangeRefused { field }) => assert_eq!(field, expected),
                other => panic!("{expected} should have been refused, got {other:?}"),
            }
        }
    }

    /// Aux outputs land at the start of the vout array, in the order given,
    /// with the identity primary after them. The `flags:13` cmm encryptor
    /// commits to those indices at encrypt time — a rearrangement here would
    /// silently point the ciphertext reference at the wrong output.
    #[test]
    fn additional_outputs_precede_the_identity_primary() {
        let key = key();
        let current = simple_identity();
        let held = identity_utxo(&current);
        let utxos = funding(&key);
        let aux0 = TxOut {
            value: 0,
            script_pubkey: vec![0xaa; 24],
        };
        let aux1 = TxOut {
            value: 0,
            script_pubkey: vec![0xbb; 32],
        };
        let params = UpdateParams::new(&held, &current, &utxos, key.address(), Expiry::Never)
            .with_additional_outputs(vec![aux0.clone(), aux1.clone()]);
        let signed = build_identity_update(&key, &[&key], &params).unwrap();
        let tx = TxV4::deserialize(&hex::decode(&signed.hex).unwrap()).unwrap();

        // The aux outputs occupy indices 0..N verbatim.
        assert_eq!(tx.outputs[0].script_pubkey, aux0.script_pubkey);
        assert_eq!(tx.outputs[0].value, 0);
        assert_eq!(tx.outputs[1].script_pubkey, aux1.script_pubkey);
        assert_eq!(tx.outputs[1].value, 0);

        // The identity primary follows, carrying zero native value.
        let id = identity_id(&current.name, Some(current.parent));
        let expected_identity_script = identity_primary_script(
            id,
            current.to_bytes().unwrap(),
            current.revocation_authority,
            current.recovery_authority,
            current.has_tokenized_control(),
        )
        .unwrap();
        assert_eq!(tx.outputs[2].script_pubkey, expected_identity_script);
        assert_eq!(tx.outputs[2].value, 0);

        // What follows the identity is change: P2PKH, back to the funding
        // key's address. Its presence confirms the fee estimator sized the
        // change slot despite the extra outputs — an under-sized estimate
        // would have merged change into fee at the dust threshold.
        assert_eq!(tx.outputs.len(), 4);
        assert_eq!(
            tx.outputs[3].script_pubkey,
            key.address().p2pkh_script_pubkey().unwrap()
        );
    }

    /// A large aux script pays a fee proportional to its bytes, not to the
    /// flat `SMART_OUTPUT_SIZE` the estimator prices every output at.
    /// Without the caller-side padding in `build_identity_update`, a 4 KB
    /// evidence deposit would price the same as a 32-byte push and the
    /// transaction would sit in the mempool.
    #[test]
    fn a_large_aux_script_is_priced_by_its_bytes() {
        let key = key();
        let current = simple_identity();
        let held = identity_utxo(&current);
        let utxos = funding(&key);

        let small = TxOut {
            value: 0,
            script_pubkey: vec![0xaa; 32],
        };
        let large = TxOut {
            value: 0,
            script_pubkey: vec![0xbb; 4096],
        };

        let small_signed = build_identity_update(
            &key,
            &[&key],
            &UpdateParams::new(&held, &current, &utxos, key.address(), Expiry::Never)
                .with_additional_outputs(vec![small]),
        )
        .unwrap();
        let large_signed = build_identity_update(
            &key,
            &[&key],
            &UpdateParams::new(&held, &current, &utxos, key.address(), Expiry::Never)
                .with_additional_outputs(vec![large]),
        )
        .unwrap();

        // Materiality: 4 KB adds ceil((4096 - 200) / 200) = 20 pad units at
        // 200 bytes each, which at `DEFAULT_FEE_PER_KB = 10_000` is at
        // least 40_000 additional sat over the small-script build's fee.
        assert!(
            large_signed.fee.to_sat() >= small_signed.fee.to_sat() + 40_000,
            "expected the 4 KB build's fee to be at least 40_000 sat above the 32-byte \
             build's, got small={} large={}",
            small_signed.fee.to_sat(),
            large_signed.fee.to_sat()
        );
    }

    /// An aux output that carries native value is funded from the P2PKH
    /// UTXOs alongside the fee, and the change slot picks up whatever is
    /// left. `assemble` already sums `plan.outputs[].value` into its
    /// `required` amount (`assemble.rs:101`); nothing in the prior test
    /// covered a caller taking that path.
    #[test]
    fn an_aux_output_value_is_funded_from_the_utxos() {
        let key = key();
        let current = simple_identity();
        let held = identity_utxo(&current);
        let utxos = funding(&key);
        let funding_total: u64 = utxos.iter().map(|u| u.satoshis.to_sat()).sum();

        let aux_value: u64 = 1_000_000;
        let aux = TxOut {
            value: aux_value,
            script_pubkey: vec![0xcc; 32],
        };
        let params = UpdateParams::new(&held, &current, &utxos, key.address(), Expiry::Never)
            .with_additional_outputs(vec![aux]);
        let signed = build_identity_update(&key, &[&key], &params).unwrap();

        // Exact conservation: funding_total = aux_value + change + fee.
        assert_eq!(
            signed.change.to_sat() + aux_value + signed.fee.to_sat(),
            funding_total,
        );

        // And the change output actually carries that amount, at the tail
        // of the vout array — aux at 0, identity at 1, change at 2.
        let tx = TxV4::deserialize(&hex::decode(&signed.hex).unwrap()).unwrap();
        assert_eq!(tx.outputs.len(), 3);
        assert_eq!(tx.outputs[0].value, aux_value);
        assert_eq!(tx.outputs[2].value, signed.change.to_sat());
    }

    /// When the leftover after aux value and fee would be dust, `assemble`
    /// folds it into the fee rather than emitting an unspendable output.
    /// The existing ordering test asserts the change slot is present as its
    /// fee-sanity proxy, so the no-change shape is otherwise unexercised.
    #[test]
    fn aux_values_that_leave_dust_fold_change_into_fee() {
        let key = key();
        let current = simple_identity();
        let held = identity_utxo(&current);
        let utxos = funding(&key);
        let funding_total: u64 = utxos.iter().map(|u| u.satoshis.to_sat()).sum();

        // Compute the fee this build will estimate so aux value can be
        // sized to leave change at (or under) DUST_THRESHOLD. One aux
        // (32 B, no padding), one identity, one change slot →
        // fee_output_count = 3; select_utxos adds +1 → change_outputs = 4;
        // estimate_fee(1 input, 4 outputs, 10_000, smart) = 10_400.
        // Leave 500 sat over the fee — below DUST_THRESHOLD, folded in.
        let target_dust: u64 = 500;
        assert!(target_dust <= DUST_THRESHOLD);
        let estimated_fee: u64 = 10_400;
        let aux_value: u64 = funding_total - estimated_fee - target_dust;
        let aux = TxOut {
            value: aux_value,
            script_pubkey: vec![0xdd; 32],
        };
        let params = UpdateParams::new(&held, &current, &utxos, key.address(), Expiry::Never)
            .with_additional_outputs(vec![aux]);
        let signed = build_identity_update(&key, &[&key], &params).unwrap();

        // No change output; only aux and identity primary remain.
        let tx = TxV4::deserialize(&hex::decode(&signed.hex).unwrap()).unwrap();
        assert_eq!(
            tx.outputs.len(),
            2,
            "the dust change was folded into the fee"
        );
        assert_eq!(signed.change.to_sat(), 0);
        // The fee absorbed the dust: fee = estimate + target_dust.
        assert_eq!(signed.fee.to_sat(), estimated_fee + target_dust);
        // Conservation still exact.
        assert_eq!(aux_value + signed.fee.to_sat(), funding_total);
    }

    /// The fee grows with the number of aux outputs — the estimator is fed
    /// a count that includes them. Without this the current ordering test
    /// would pass a regression that fed the wrong count, because
    /// `MIN_FEE = 10_000` floors a four-output transaction and the
    /// change-output presence check would still hold.
    #[test]
    fn the_fee_grows_with_the_number_of_additional_outputs() {
        let key = key();
        let current = simple_identity();
        let held = identity_utxo(&current);
        let utxos = funding(&key);

        let no_aux = build_identity_update(
            &key,
            &[&key],
            &UpdateParams::new(&held, &current, &utxos, key.address(), Expiry::Never),
        )
        .unwrap();

        let five_aux: Vec<TxOut> = (0u8..5)
            .map(|i| TxOut {
                value: 0,
                script_pubkey: vec![0xee ^ i; 32],
            })
            .collect();
        let with_aux = build_identity_update(
            &key,
            &[&key],
            &UpdateParams::new(&held, &current, &utxos, key.address(), Expiry::Never)
                .with_additional_outputs(five_aux),
        )
        .unwrap();

        // Five extra 200-byte output slots (32-byte scripts, no padding —
        // the estimator prices them at SMART_OUTPUT_SIZE) add 1000 bytes
        // of estimated size, worth 10_000 sat at DEFAULT_FEE_PER_KB.
        // Pin at "materially above" rather than an exact target so a
        // downstream constant tweak does not turn this into a byte-parity
        // check on the estimator itself.
        assert!(
            with_aux.fee.to_sat() >= no_aux.fee.to_sat() + 8_000,
            "expected 5 aux outputs to add at least 8_000 sat of fee over the no-aux \
             build, got no_aux={} with_aux={}",
            no_aux.fee.to_sat(),
            with_aux.fee.to_sat()
        );
    }

    /// Content changes are not authority changes and need no opt-in.
    #[test]
    fn content_changes_are_not_authority_changes() {
        let key = key();
        let current = simple_identity();
        let held = identity_utxo(&current);
        let mut proposed = current.clone();
        proposed.content_multimap = vec![([0x03; 20], vec![vec![0x04; 8]])];
        let utxos = funding(&key);
        let params = UpdateParams::new(&held, &proposed, &utxos, key.address(), Expiry::Never);
        assert!(build_identity_update(&key, &[&key], &params).is_ok());
    }

    /// Spending an output that holds a different identity — an update to
    /// `rustsdk` aimed at the output holding `someoneelse`. It would sign and
    /// serialize perfectly well, and be caught only by the daemon.
    #[test]
    fn refuses_an_output_that_holds_another_identity() {
        let key = key();
        let mut someone_else = simple_identity();
        someone_else.name = "someoneelse".to_string();
        let held = identity_utxo(&someone_else);
        let utxos = funding(&key);
        let ours = simple_identity();
        let params = UpdateParams::new(&held, &ours, &utxos, key.address(), Expiry::Never);
        assert!(matches!(
            build_identity_update(&key, &[&key], &params),
            Err(TxError::IdentityOutputMismatch)
        ));
    }

    /// An output that is not an identity at all.
    #[test]
    fn refuses_an_output_that_is_not_an_identity() {
        let key = key();
        let current = simple_identity();
        let held = Utxo {
            script_pubkey: key.address().p2pkh_script_pubkey().unwrap(),
            ..identity_utxo(&current)
        };
        let utxos = funding(&key);
        let params = UpdateParams::new(&held, &current, &utxos, key.address(), Expiry::Never);
        assert!(matches!(
            build_identity_update(&key, &[&key], &params),
            Err(TxError::IdentityOutputMismatch)
        ));
    }
}
