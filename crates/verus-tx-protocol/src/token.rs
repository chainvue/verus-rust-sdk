//! Sending tokens.
//!
//! A token send differs from a native one in three ways, and all three change
//! the bytes:
//!
//! 1. **Selection is two-phase.** Token-bearing UTXOs are chosen first, for the
//!    token; then native UTXOs cover the fee. A token-bearing UTXO pulled in for
//!    its native value must have its tokens returned as change, or that value is
//!    burned.
//! 2. **Outputs are CryptoConditions**, so every output is fee-estimated at
//!    `SMART_OUTPUT_SIZE` rather than `P2PKH_OUTPUT_SIZE` — which is why a token
//!    transfer's fee sits above the floor where a native one sits on it.
//! 3. **Token change is its own output**, emitted before the native change.
//!
//! Ported from `@chainvue/verus-sdk`'s two-phase `selectUtxos`
//! (`src/utxo/index.ts:194-299`) and pinned byte-for-byte against it.

use verus_keys::{Address, AddressKind, PrivateKey};
use verus_wire::consensus::{SIGHASH_ALL, VERUS_BRANCH_ID};
use verus_wire::hash::txid_display;
use verus_wire::{TxIn, TxOut, TxV4};

use crate::decode::{decode_output_script, OutputKind};
use verus_tx_primitives::cc::{
    fulfillment_script_sig, reserve_output_script, reserve_output_script_to,
};
use verus_tx_primitives::fee::{estimate_fee, DEFAULT_FEE_PER_KB, DUST_THRESHOLD};
use verus_tx_primitives::Amount;
use verus_tx_primitives::CurrencyId;
use verus_tx_primitives::Expiry;
use verus_tx_primitives::TxError;
use verus_tx_primitives::Utxo;
use verus_tx_transparent::SignedTransaction;

/// Refuse a reserve output no transparent key in this crate can sign for.
///
/// The decoder reads every destination kind now, because what an output
/// *holds* does not depend on who can spend it. Selecting one as funding does:
/// every signing path here produces a P2PKH-shaped fulfillment, so a reserve
/// output paying an identity, a script hash or a bare public key has to be
/// refused here rather than built into a transaction nobody can satisfy.
///
/// # Errors
///
/// [`TxError::IdentityHeldFunding`] for an identity-held output, and
/// [`TxError::UnsupportedFundingScript`] for a script hash or bare public key.
///
/// Before the decoder learned those shapes this was enforced by accident —
/// `decode_output_script` failed outright — which is exactly the kind of guard
/// that disappears silently when the thing failing by accident starts working.
pub fn reject_unspendable_reserve(
    utxo: &Utxo,
    destination: &verus_tx_primitives::cc::Destination,
) -> Result<(), TxError> {
    match destination {
        verus_tx_primitives::cc::Destination::PubKeyHash(_) => Ok(()),
        verus_tx_primitives::cc::Destination::Identity(identity) => {
            Err(TxError::IdentityHeldFunding {
                txid: utxo.txid.to_display_hex(),
                vout: utxo.vout,
                identity: hex::encode(identity),
            })
        }
        verus_tx_primitives::cc::Destination::PubKey(_)
        | verus_tx_primitives::cc::Destination::ScriptHash(_) => {
            Err(TxError::UnsupportedFundingScript {
                txid: utxo.txid.to_display_hex(),
                vout: utxo.vout,
            })
        }
    }
}

/// Where token value is going.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenRecipient {
    /// The `R` address being paid.
    pub address: Address,
    /// Which token.
    pub currency: CurrencyId,
    /// How much, in the token's smallest unit.
    pub amount: Amount,
}

/// What to build.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct TokenSendParams<'a> {
    /// UTXOs available: token-bearing reserve outputs and native P2PKH.
    pub utxos: &'a [Utxo],
    /// Where the tokens are going.
    pub recipients: &'a [TokenRecipient],
    /// Where both token and native change return.
    pub change_address: Address,
    /// When this transaction stops being minable. See [`Expiry`].
    pub expiry: Expiry,
    /// Fee rate in satoshis per kilobyte.
    pub fee_per_kb: u64,
}

impl<'a> TokenSendParams<'a> {
    /// Parameters with the default fee rate.
    pub fn new(
        utxos: &'a [Utxo],
        recipients: &'a [TokenRecipient],
        change_address: Address,
        expiry: Expiry,
    ) -> Self {
        Self {
            utxos,
            recipients,
            change_address,
            expiry,
            fee_per_kb: DEFAULT_FEE_PER_KB,
        }
    }

    /// Override the fee rate.
    pub fn with_fee_per_kb(mut self, fee_per_kb: u64) -> Self {
        self.fee_per_kb = fee_per_kb;
        self
    }
}

/// A UTXO with its script already decoded.
struct Decoded<'a> {
    utxo: &'a Utxo,
    tokens: Vec<(CurrencyId, u64)>,
    /// CryptoCondition outputs are unlocked by a fulfillment, not a P2PKH
    /// scriptSig — signing them the wrong way produces a transaction the daemon
    /// rejects at broadcast.
    is_cryptocondition: bool,
}

impl Decoded<'_> {
    fn carries_tokens(&self) -> bool {
        self.tokens.iter().any(|(_, amount)| *amount > 0)
    }
}

/// Running balance per currency, in insertion order.
///
/// **Order is observable**: it decides the order token change outputs are
/// emitted, and therefore the transaction bytes. A `HashMap` here would produce
/// a valid but different transaction, nondeterministically — hence a `Vec`.
#[derive(Default)]
pub struct Balances(Vec<(CurrencyId, i128)>);

impl Balances {
    /// Record `amount` of `currency` being supplied by an input.
    pub fn sub(&mut self, currency: CurrencyId, amount: u64) {
        match self.0.iter_mut().find(|(id, _)| *id == currency) {
            Some((_, balance)) => *balance -= i128::from(amount),
            None => self.0.push((currency, -i128::from(amount))),
        }
    }

    /// Record `amount` of `currency` that the outputs demand.
    pub fn add_required(&mut self, currency: CurrencyId, amount: u64) {
        match self.0.iter_mut().find(|(id, _)| *id == currency) {
            Some((_, balance)) => *balance += i128::from(amount),
            None => self.0.push((currency, i128::from(amount))),
        }
    }

    /// Whether the outputs still demand more of `currency` than inputs supply.
    pub fn still_needed(&self, currency: CurrencyId) -> bool {
        self.0
            .iter()
            .any(|(id, balance)| *id == currency && *balance > 0)
    }

    /// Currencies the inputs do not cover, and by how much.
    pub fn shortfalls(&self) -> Vec<(CurrencyId, i128)> {
        self.0
            .iter()
            .filter(|(_, balance)| *balance > 0)
            .copied()
            .collect()
    }

    /// Currencies with a surplus — these become change outputs, in order.
    pub fn change(&self) -> Vec<(CurrencyId, u64)> {
        self.0
            .iter()
            .filter(|(_, balance)| *balance < 0)
            .map(|(id, balance)| {
                (
                    *id,
                    u64::try_from(-*balance).expect("a surplus fits u64: it came from u64 inputs"),
                )
            })
            .collect()
    }
}

/// Build and sign a token transfer.
///
/// # Scope
///
/// Plain token transfers: reserve outputs to `R` addresses. Conversions,
/// cross-chain exports, mint and burn all set additional fields on the output
/// and are **refused** rather than approximated.
pub fn build_token_send(
    key: &PrivateKey,
    params: &TokenSendParams<'_>,
) -> Result<SignedTransaction, TxError> {
    if params.recipients.is_empty() {
        return Err(TxError::NoOutputs);
    }
    params.expiry.check()?;
    if params.change_address.kind() != AddressKind::PubKeyHash {
        return Err(TxError::UnsupportedRecipient);
    }

    // Decode every UTXO up front. An unreadable CryptoCondition fails here, not
    // silently as "native only" — see `decode`.
    let decoded: Vec<Decoded<'_>> = params
        .utxos
        .iter()
        .map(|utxo| {
            let (tokens, is_cryptocondition) = match decode_output_script(&utxo.script_pubkey)? {
                OutputKind::PubKeyHash { .. } => (Vec::new(), false),
                OutputKind::ReserveOutput {
                    tokens,
                    destination,
                } => {
                    reject_unspendable_reserve(utxo, &destination)?;
                    (tokens, true)
                }
                // Native value, but not value this crate can sign for: the
                // scriptSig for a P2PK input is a bare signature, and every
                // signing path here builds the P2PKH form. Refused rather than
                // selected, so the failure is "cannot spend this output"
                // instead of a transaction the network rejects.
                OutputKind::PubKey { .. } => {
                    return Err(TxError::UnsupportedFundingScript {
                        txid: utxo.txid.to_display_hex(),
                        vout: utxo.vout,
                    })
                }
                // Identity-held funds are spendable only with the identity's
                // authority, not this key's. Building a spend would produce a
                // transaction nobody can satisfy.
                OutputKind::IdentityPayment { identity } => {
                    return Err(TxError::IdentityHeldFunding {
                        txid: utxo.txid.to_display_hex(),
                        vout: utxo.vout,
                        identity: hex::encode(identity),
                    })
                }
                OutputKind::IdentityPrimary { .. } => {
                    return Err(TxError::UnsupportedFundingEval {
                        txid: utxo.txid.to_display_hex(),
                        vout: utxo.vout,
                        eval_code: crate::identity::EVAL_IDENTITY_PRIMARY,
                    })
                }
                // A name commitment exists to be spent by the registration
                // that completes it, which takes it as a named input rather
                // than picking it up as funding. Selecting one here would
                // reserve a name and then destroy the reservation.
                OutputKind::IdentityCommitment { .. } => {
                    return Err(TxError::UnsupportedFundingEval {
                        txid: utxo.txid.to_display_hex(),
                        vout: utxo.vout,
                        eval_code: verus_tx_primitives::cc::EVAL_IDENTITY_COMMITMENT,
                    })
                }
                // Neither belongs to whoever is signing. A reserve deposit is
                // held by a currency's own condition, and a transfer is paid to
                // the protocol's transfer address and consumed by the next
                // import. Decoding them made them visible here; it did not make
                // them spendable.
                OutputKind::ReserveDeposit { .. } => {
                    return Err(TxError::UnsupportedFundingEval {
                        txid: utxo.txid.to_display_hex(),
                        vout: utxo.vout,
                        eval_code: verus_tx_primitives::cc::EVAL_RESERVE_DEPOSIT,
                    })
                }
                OutputKind::ReserveTransfer { .. } => {
                    return Err(TxError::UnsupportedFundingEval {
                        txid: utxo.txid.to_display_hex(),
                        vout: utxo.vout,
                        eval_code: crate::convert::EVAL_RESERVE_TRANSFER,
                    })
                }
                OutputKind::UnsupportedCryptoCondition { eval_code, .. } => {
                    return Err(TxError::UnsupportedFundingEval {
                        txid: utxo.txid.to_display_hex(),
                        vout: utxo.vout,
                        eval_code,
                    })
                }
            };
            Ok(Decoded {
                utxo,
                tokens,
                is_cryptocondition,
            })
        })
        .collect::<Result<_, _>>()?;

    let mut balances = Balances::default();
    for recipient in params.recipients {
        // An `i…` recipient is an ordinary token payment, not an exotic one:
        // tokens held by a VerusID are a normal shape, spendable by that
        // identity's authority. `destination_for` refuses a script hash, which
        // no template here writes.
        //
        // This is NOT the same question as whether such an output can FUND a
        // transaction — see `reject_unspendable_reserve`, which refuses exactly
        // the identity-held output this may now create, because every signing
        // path in this crate produces a P2PKH-shaped fulfillment. Paying one is
        // supported; spending one is not.
        // Called for its refusal, here rather than at the output loop below, so
        // a bad recipient is reported before any balance accounting runs and
        // the error names the recipient rather than a shortfall.
        crate::convert::destination_for(&recipient.address)?;
        if recipient.amount.is_zero() {
            return Err(TxError::ZeroValueOutput { index: 0 });
        }
        balances.add_required(recipient.currency, recipient.amount.to_sat());
    }

    // Phase 1: take UTXOs carrying a currency we still need, in caller order.
    let mut selected: Vec<&Decoded<'_>> = Vec::new();
    let mut remaining_native: i128 = 0;
    for candidate in &decoded {
        let useful = candidate
            .tokens
            .iter()
            .any(|(id, amount)| *amount > 0 && balances.still_needed(*id));
        if !useful {
            continue;
        }
        for (id, amount) in &candidate.tokens {
            balances.sub(*id, *amount);
        }
        remaining_native -= i128::from(candidate.utxo.satoshis.to_sat());
        selected.push(candidate);
    }

    let shortfalls = balances.shortfalls();
    if let Some((currency, missing)) = shortfalls.first() {
        return Err(TxError::InsufficientTokens {
            currency: currency.to_string(),
            missing: u64::try_from(*missing).unwrap_or(u64::MAX),
        });
    }

    // Phase 2: native UTXOs for the fee. Pure-native first so token-bearing
    // outputs are only spent when they must be, then descending by value.
    let mut candidates: Vec<&Decoded<'_>> = decoded
        .iter()
        .filter(|d| !selected.iter().any(|s| std::ptr::eq(*s, *d)))
        .collect();
    candidates.sort_by_key(|d| {
        (
            d.carries_tokens(),
            core::cmp::Reverse(d.utxo.satoshis.to_sat()),
        )
    });
    let mut candidates = candidates.into_iter();

    let declared_outputs = params.recipients.len() as u64;
    // `declared_outputs` and the change count are both caller-influenced.
    // Unchecked, `+ 1` here wraps to `0` before `estimate_fee`'s own
    // `checked_mul` can see it, turning an absurd output count into a
    // plausible, wrong fee instead of the overflow it actually is — the same
    // pattern fixed in `verus-tx-primitives::fee::select_utxos` (#166).
    let total_outputs = |balances: &Balances| -> Result<u64, TxError> {
        declared_outputs
            .checked_add(1)
            .and_then(|n| n.checked_add(balances.change().len() as u64))
            .ok_or(TxError::ValueOverflow)
    };
    let mut fee = estimate_fee(
        selected.len() as u64 + 1,
        total_outputs(&balances)?,
        params.fee_per_kb,
        true,
    )?;

    while remaining_native + i128::from(fee) > 0 {
        let Some(next) = candidates.next() else {
            // #199: this sum used to be a raw `u64` `.sum()`, so a UTXO set
            // whose native total exceeds `u64::MAX` reported a wrapped — and
            // therefore misleading — `available` (and panicked in a debug
            // build). It stays best-effort rather than a hard `ValueOverflow`:
            // the failure here is that the candidates ran out before the fee
            // was covered, not the arithmetic, and `u64::MAX` is the honest
            // "more than everything". Matches #194's handling in
            // `build_identity_spend` and #166's `available` in
            // `fee.rs::select_utxos`.
            let available = Amount::checked_sum(params.utxos.iter().map(|u| u.satoshis))
                .map(Amount::to_sat)
                .unwrap_or(u64::MAX);
            return Err(TxError::InsufficientFunds {
                required: fee,
                available,
            });
        };
        remaining_native -= i128::from(next.utxo.satoshis.to_sat());
        // Tokens on a UTXO pulled in for its native value become change, or they
        // would be spent with no output to receive them.
        for (id, amount) in &next.tokens {
            balances.sub(*id, *amount);
        }
        selected.push(next);
        fee = estimate_fee(
            selected.len() as u64,
            total_outputs(&balances)?,
            params.fee_per_kb,
            true,
        )?;
    }

    // #199: `total_native_in` used to be a raw `u64` `.sum()` and the change a
    // raw subtraction below it. Selected UTXOs whose native total exceeds
    // `u64::MAX` wrap the total down to a plausible number, `actual_change` is
    // derived from the wrapped total, and the conservation check at the end
    // cannot see it: it compares `total_native_in` against outputs that were
    // sized from the same wrap, so the difference still matches the fee and the
    // transaction gets signed. Unlike a wrap that only misreports a number,
    // this one loses real value — everything the wrap dropped is handed to the
    // miner. A debug build does not wrap, it panics in the iterator's `Sum`
    // impl, so neither build returns the `ValueOverflow` the API promises.
    //
    // Summing through `Amount` puts the overflow before anything is derived
    // from it. The subtraction is checked too: it can only underflow
    // downstream of that wrap, but the guard belongs here rather than resting
    // on the loop invariant three blocks above.
    let total_native_in = Amount::checked_sum(selected.iter().map(|d| d.utxo.satoshis))
        .ok_or(TxError::ValueOverflow)?
        .to_sat();
    let actual_change = total_native_in
        .checked_sub(fee)
        .ok_or(TxError::ValueOverflow)?;
    let (native_change, fee) = if actual_change > DUST_THRESHOLD {
        (actual_change, fee)
    } else {
        // Dust change is dropped into the fee rather than emitted as an output
        // nobody can economically spend.
        (
            0,
            fee.checked_add(actual_change)
                .ok_or(TxError::ValueOverflow)?,
        )
    };

    // Outputs: declared, then token change, then native change.
    let change_hash = params.change_address.hash();
    let mut outputs = Vec::new();
    for recipient in params.recipients {
        outputs.push(TxOut {
            value: 0, // the value is the token inside the payload
            script_pubkey: reserve_output_script_to(
                crate::convert::destination_for(&recipient.address)?,
                recipient.currency,
                recipient.amount.to_sat(),
            )?,
        });
    }
    for (currency, amount) in balances.change() {
        outputs.push(TxOut {
            value: 0,
            script_pubkey: reserve_output_script(change_hash, currency, amount)?,
        });
    }
    if native_change > 0 {
        outputs.push(TxOut {
            value: native_change,
            script_pubkey: params.change_address.p2pkh_script_pubkey()?,
        });
    }

    let mut tx = TxV4 {
        inputs: selected
            .iter()
            .map(|d| TxIn::unsigned(d.utxo.txid.to_internal(), d.utxo.vout, 0xffff_ffff))
            .collect(),
        outputs,
        lock_time: 0,
        expiry_height: params.expiry.to_height(),
        ..TxV4::default()
    };

    // #199: summed through `Amount` for the same reason as `total_native_in`
    // above — a check that exists to catch a wrap must not be able to wrap
    // itself. At most one output here carries a non-zero value today, so this
    // is the backstop and not the defect.
    let outputs_total = Amount::checked_sum(tx.outputs.iter().map(|o| Amount::from_sat(o.value)))
        .ok_or(TxError::ValueOverflow)?
        .to_sat();
    let actual = i128::from(total_native_in) - i128::from(outputs_total);
    if actual != i128::from(fee) {
        return Err(TxError::ValueNotConserved {
            inputs: total_native_in,
            outputs: outputs_total,
            actual,
            expected: fee,
        });
    }

    let pubkey = key.public_key().to_bytes();
    let mut script_sigs = Vec::with_capacity(tx.inputs.len());
    for (index, entry) in selected.iter().enumerate() {
        let utxo = entry.utxo;
        let sighash = tx.transparent_sighash(
            VERUS_BRANCH_ID,
            index,
            &utxo.script_pubkey,
            utxo.satoshis.to_sat(),
            SIGHASH_ALL,
        )?;
        script_sigs.push(if entry.is_cryptocondition {
            // Compact r || s, not DER: the CryptoCondition fulfillment carries
            // the raw 64 bytes and holds the hash type in its own field.
            let signature = key.sign_prehash(&sighash)?;
            let compact: [u8; 64] = signature.to_bytes().into();
            fulfillment_script_sig(&[(pubkey.clone(), compact)], 1)?
        } else {
            let signature = key.sign_prehash_der(&sighash, 1)?;
            let mut script_sig = Vec::with_capacity(2 + signature.len() + pubkey.len());
            script_sig
                .push(u8::try_from(signature.len()).expect("DER signature is under 76 bytes"));
            script_sig.extend_from_slice(&signature);
            script_sig.push(u8::try_from(pubkey.len()).expect("public key is 33 or 65 bytes"));
            script_sig.extend_from_slice(&pubkey);
            script_sig
        });
    }
    for (input, script_sig) in tx.inputs.iter_mut().zip(script_sigs) {
        input.script_sig = script_sig;
    }

    let raw = tx.serialize()?;
    Ok(SignedTransaction {
        hex: hex::encode(&raw),
        txid: txid_display(&tx.txid()?),
        fee: Amount::from_sat(fee),
        change: Amount::from_sat(native_change),
        inputs_used: selected
            .iter()
            .map(|d| (d.utxo.txid, d.utxo.vout))
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use verus_tx_primitives::cc::Destination;
    use verus_tx_primitives::Txid;

    const CURRENCY: CurrencyId = CurrencyId::from_bytes([0x33; 20]);

    fn key() -> PrivateKey {
        PrivateKey::from_bytes(&[0x11; 32], true).expect("valid key")
    }

    /// A reserve output holding `tokens` of [`CURRENCY`] and `satoshis` of
    /// native value, paying the key this module signs with.
    fn token_utxo(vout: u32, satoshis: u64, tokens: u64) -> Utxo {
        Utxo {
            txid: Txid::from_internal([0xcd; 32]),
            vout,
            satoshis: Amount::from_sat(satoshis),
            script_pubkey: reserve_output_script(key().address().hash(), CURRENCY, tokens)
                .expect("reserve output script"),
        }
    }

    /// A plain P2PKH output of the signing key's, to pay the miner fee from.
    fn native_utxo(vout: u32, satoshis: u64) -> Utxo {
        Utxo {
            txid: Txid::from_internal([0xab; 32]),
            vout,
            satoshis: Amount::from_sat(satoshis),
            script_pubkey: key().address().p2pkh_script_pubkey().expect("p2pkh script"),
        }
    }

    fn recipient(amount: u64) -> TokenRecipient {
        TokenRecipient {
            address: key().address(),
            currency: CURRENCY,
            amount: Amount::from_sat(amount),
        }
    }

    /// The sum `total_native_in` used to be, over the same UTXOs the tests
    /// below hand to `build_token_send` — kept so they can show what it
    /// produced instead of asserting it from memory.
    ///
    /// The wrap is spelled out with `wrapping_add` because the original
    /// `.sum()` does not wrap in a debug build, it panics; that divergence
    /// between profiles is half of what #199 is about.
    fn unchecked_native_total(utxos: &[Utxo]) -> u64 {
        utxos
            .iter()
            .map(|u| u.satoshis.to_sat())
            .fold(0u64, u64::wrapping_add)
    }

    /// A VerusID is an ordinary token recipient.
    ///
    /// Tokens held by an identity are a normal on-chain shape — the same one
    /// `cc::reserve_output_script_to` already writes for a sub-identity's
    /// registration fee — and a wallet paying `name@` is the common case, not
    /// an exotic one. It was refused here for no reason the code stated.
    #[test]
    fn a_verusid_is_an_ordinary_token_recipient() {
        let identity = [0x77; 20];
        let signed = build_token_send(
            &key(),
            &TokenSendParams::new(
                &[token_utxo(0, 100_000_000, 500), native_utxo(1, 100_000_000)],
                &[TokenRecipient {
                    address: Address::new(AddressKind::Identity, identity),
                    currency: CURRENCY,
                    amount: Amount::from_sat(200),
                }],
                key().address(),
                Expiry::from_height(1_170_000),
            ),
        )
        .expect("paying an identity a token is supported");

        // The output has to name the IDENTITY, not a key hash. Writing an
        // identity's hash as a key hash produces an output nobody can spend,
        // which is the failure this test exists to rule out.
        let expected =
            reserve_output_script_to(Destination::Identity(identity), CURRENCY, 200).unwrap();
        let tx = verus_wire::TxV4::deserialize(&hex::decode(&signed.hex).unwrap()).unwrap();
        assert!(
            tx.outputs.iter().any(|o| o.script_pubkey == expected),
            "no output pays the identity",
        );
    }

    /// Paying an identity and SPENDING what an identity holds are different
    /// questions, and only the first is supported.
    ///
    /// Every signing path in this crate produces a P2PKH-shaped fulfillment, so
    /// an identity-held output cannot be funding — `reject_unspendable_reserve`
    /// says so. Relaxing the recipient rule must not relax that one, and this
    /// is the test that would notice if it ever did.
    #[test]
    fn an_identity_held_output_is_still_refused_as_funding() {
        let identity = [0x77; 20];
        let held = Utxo {
            txid: Txid::from_internal([0xef; 32]),
            vout: 0,
            satoshis: Amount::from_sat(0),
            script_pubkey: reserve_output_script_to(Destination::Identity(identity), CURRENCY, 500)
                .unwrap(),
        };
        let error = build_token_send(
            &key(),
            &TokenSendParams::new(
                &[held, native_utxo(1, 100_000_000)],
                &[recipient(200)],
                key().address(),
                Expiry::from_height(1_170_000),
            ),
        )
        .expect_err("an identity-held output cannot fund a P2PKH-signed spend");
        assert!(
            matches!(error, TxError::IdentityHeldFunding { .. }),
            "{error:?}",
        );
    }

    /// A script hash stays refused. No template here writes one, and guessing
    /// an untested encoding for money is not worth the convenience.
    #[test]
    fn a_script_hash_recipient_is_still_refused() {
        let error = build_token_send(
            &key(),
            &TokenSendParams::new(
                &[token_utxo(0, 100_000_000, 500), native_utxo(1, 100_000_000)],
                &[TokenRecipient {
                    address: Address::new(AddressKind::ScriptHash, [0x99; 20]),
                    currency: CURRENCY,
                    amount: Amount::from_sat(200),
                }],
                key().address(),
                Expiry::from_height(1_170_000),
            ),
        )
        .expect_err("a script hash is not a supported recipient");
        assert!(matches!(error, TxError::UnsupportedRecipient), "{error:?}");
    }

    /// #199: a selected UTXO set whose native total exceeds `u64::MAX` is
    /// refused, not wrapped into a transaction that hands the difference to a
    /// miner.
    ///
    /// The wrap used to be invisible to every later check. `total_native_in`
    /// came down to a plausible number, `actual_change` was derived from it,
    /// and the conservation check compared that same wrapped total against
    /// outputs sized from it — so the difference still matched the fee and the
    /// transaction was signed. Unlike a wrap that only misreports a number,
    /// this one loses real value: everything the wrap dropped is paid to the
    /// miner. The debug build was no better, only louder — it panicked inside
    /// `Sum` instead of returning an error.
    #[test]
    fn a_native_input_total_that_overflows_u64_is_refused() {
        // Derived from `u64::MAX` rather than pinned: the first two sum to
        // exactly `u64::MAX + 1`, so an unchecked total wraps down to the
        // third UTXO's value alone.
        let offset: u64 = 1_000_000;
        let (first, second) = (u64::MAX - offset, offset + 1);
        let funded: u64 = 1_00000000;
        let tokens_each: u64 = 1_000_000;

        let utxos = [
            token_utxo(0, first, tokens_each),
            token_utxo(1, second, tokens_each),
            token_utxo(2, funded, tokens_each),
        ];
        assert!(
            first.checked_add(second).is_none(),
            "the fixture has to actually overflow u64"
        );
        assert_eq!(
            unchecked_native_total(&utxos),
            funded,
            "and wrap to a total the transaction's own funding covers — which \
             is why nothing downstream used to catch it"
        );

        // More than any two UTXOs hold, so phase 1 has to take all three and
        // still emits token change.
        let recipients = [recipient(tokens_each * 2 + 1)];
        let params = TokenSendParams::new(&utxos, &recipients, key().address(), Expiry::Never);
        match build_token_send(&key(), &params) {
            Err(TxError::ValueOverflow) => {}
            other => panic!("expected ValueOverflow, got {other:?}"),
        }
    }

    /// #199: the same overflow with nothing left over is an overflow, not a
    /// conservation failure.
    ///
    /// Two UTXOs summing to exactly `2^64` wrap `total_native_in` to `0`, and
    /// the release build then underflowed `total_native_in - fee` into a huge
    /// change output. That was refused — but as `ValueNotConserved`, blaming
    /// conservation for an arithmetic overflow and reporting `inputs: 0` for a
    /// set holding more than `u64::MAX`. Catching the wrap in the sum names
    /// the actual failure.
    #[test]
    fn an_input_total_that_wraps_to_zero_is_reported_as_an_overflow() {
        let offset: u64 = 1_000_000;
        let (first, second) = (u64::MAX - offset, offset + 1);
        let tokens_each: u64 = 1_000_000;

        let utxos = [
            token_utxo(0, first, tokens_each),
            token_utxo(1, second, tokens_each),
        ];
        assert!(
            first.checked_add(second).is_none(),
            "the fixture has to actually overflow u64"
        );
        assert_eq!(
            unchecked_native_total(&utxos),
            0,
            "and wrap to nothing, which is what the fee was subtracted from"
        );

        let recipients = [recipient(tokens_each * 2)];
        let params = TokenSendParams::new(&utxos, &recipients, key().address(), Expiry::Never);
        match build_token_send(&key(), &params) {
            Err(TxError::ValueOverflow) => {}
            other => panic!("expected ValueOverflow, got {other:?}"),
        }
    }

    /// #199: the `InsufficientFunds` report still names what the UTXOs
    /// actually hold.
    ///
    /// That sum was rewritten to saturate rather than wrap, but it cannot
    /// overflow through this API: the branch is only taken once every UTXO has
    /// been selected, and the loop guard above it means the native total is
    /// below the fee to get there. So this pins the ordinary report instead —
    /// the saturating rewrite must not have changed it.
    #[test]
    fn running_out_of_funding_still_reports_what_the_utxos_hold() {
        let dust: u64 = 1;
        let tokens: u64 = 1_000_000;

        let utxos = [token_utxo(0, dust, tokens)];
        let recipients = [recipient(tokens)];
        let params = TokenSendParams::new(&utxos, &recipients, key().address(), Expiry::Never);
        match build_token_send(&key(), &params) {
            Err(TxError::InsufficientFunds {
                required,
                available,
            }) => {
                assert_eq!(available, dust, "the exact total, not saturated");
                assert!(required > available, "otherwise it would not have failed");
            }
            other => panic!("expected InsufficientFunds, got {other:?}"),
        }
    }
}
