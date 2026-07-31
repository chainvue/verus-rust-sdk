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

use crate::amount::Amount;
use crate::cc::{fulfillment_script_sig, reserve_output_script};
use crate::currency::CurrencyId;
use crate::decode::{decode_output_script, OutputKind};
use crate::error::TxError;
use crate::expiry::Expiry;
use crate::fee::{estimate_fee, DEFAULT_FEE_PER_KB, DUST_THRESHOLD};
use crate::send::SignedTransaction;
use crate::Utxo;

/// Refuse a reserve output no transparent key in this crate can sign for.
///
/// The decoder reads every destination kind now, because what an output
/// *holds* does not depend on who can spend it. Selecting one as funding does:
/// every signing path here produces a P2PKH-shaped fulfillment, so a reserve
/// output paying an identity, a script hash or a bare public key has to be
/// refused here rather than built into a transaction nobody can satisfy.
///
/// Before the decoder learned those shapes this was enforced by accident —
/// `decode_output_script` failed outright — which is exactly the kind of guard
/// that disappears silently when the thing failing by accident starts working.
pub(crate) fn reject_unspendable_reserve(
    utxo: &Utxo,
    destination: &crate::cc::Destination,
) -> Result<(), TxError> {
    match destination {
        crate::cc::Destination::PubKeyHash(_) => Ok(()),
        crate::cc::Destination::Identity(identity) => Err(TxError::IdentityHeldFunding {
            txid: utxo.txid.to_display_hex(),
            vout: utxo.vout,
            identity: hex::encode(identity),
        }),
        crate::cc::Destination::PubKey(_) | crate::cc::Destination::ScriptHash(_) => {
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
pub(crate) struct Balances(Vec<(CurrencyId, i128)>);

impl Balances {
    pub(crate) fn sub(&mut self, currency: CurrencyId, amount: u64) {
        match self.0.iter_mut().find(|(id, _)| *id == currency) {
            Some((_, balance)) => *balance -= i128::from(amount),
            None => self.0.push((currency, -i128::from(amount))),
        }
    }

    pub(crate) fn add_required(&mut self, currency: CurrencyId, amount: u64) {
        match self.0.iter_mut().find(|(id, _)| *id == currency) {
            Some((_, balance)) => *balance += i128::from(amount),
            None => self.0.push((currency, i128::from(amount))),
        }
    }

    pub(crate) fn still_needed(&self, currency: CurrencyId) -> bool {
        self.0
            .iter()
            .any(|(id, balance)| *id == currency && *balance > 0)
    }

    pub(crate) fn shortfalls(&self) -> Vec<(CurrencyId, i128)> {
        self.0
            .iter()
            .filter(|(_, balance)| *balance > 0)
            .copied()
            .collect()
    }

    /// Currencies with a surplus — these become change outputs, in order.
    pub(crate) fn change(&self) -> Vec<(CurrencyId, u64)> {
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
                        eval_code: crate::register::EVAL_IDENTITY_COMMITMENT,
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
        if recipient.address.kind() != AddressKind::PubKeyHash {
            return Err(TxError::UnsupportedRecipient);
        }
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
    let mut fee = estimate_fee(
        selected.len() as u64 + 1,
        declared_outputs + 1 + balances.change().len() as u64,
        params.fee_per_kb,
        true,
    );

    while remaining_native + i128::from(fee) > 0 {
        let Some(next) = candidates.next() else {
            let available: u64 = params.utxos.iter().map(|u| u.satoshis.to_sat()).sum();
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
            declared_outputs + 1 + balances.change().len() as u64,
            params.fee_per_kb,
            true,
        );
    }

    let total_native_in: u64 = selected.iter().map(|d| d.utxo.satoshis.to_sat()).sum();
    let actual_change = total_native_in - fee;
    let (native_change, fee) = if actual_change > DUST_THRESHOLD {
        (actual_change, fee)
    } else {
        (0, fee + actual_change)
    };

    // Outputs: declared, then token change, then native change.
    let change_hash = params.change_address.hash();
    let mut outputs = Vec::new();
    for recipient in params.recipients {
        outputs.push(TxOut {
            value: 0, // the value is the token inside the payload
            script_pubkey: reserve_output_script(
                recipient.address.hash(),
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

    let outputs_total: u64 = tx.outputs.iter().map(|o| o.value).sum();
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
