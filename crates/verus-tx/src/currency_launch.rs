//! The other six outputs of a `definecurrency` transaction.
//!
//! A launch carries seven, in this order and no other:
//!
//! ```text
//! 0  identity update      EVAL_IDENTITY_PRIMARY        re-issues the defining ID with FLAG_ACTIVE_CURRENCY
//! 1  currency definition  EVAL_CURRENCY_DEFINITION     see `currency_definition`
//! 2  cross-chain import   EVAL_CROSSCHAIN_IMPORT       same-chain definition import stub
//! 3  notarization         EVAL_ACCEPTEDNOTARIZATION    definition stub + the initial currency state
//! 4  cross-chain export   EVAL_CROSSCHAIN_EXPORT       definition export stub
//! 5  reserve deposit      EVAL_RESERVE_DEPOSIT         holds the launch fee's import share
//! 6  change               identity CC output           returns funds to the defining identity
//! ```
//!
//! # Why this can be built offline at all
//!
//! For a same-chain token or basket the notarization is a **stub**: fixed
//! version and flags, null previous references, empty state maps. It does not
//! depend on live notarization state. Only the tip height enters outputs 2–4;
//! everything else is a function of the definition. That is what makes a launch
//! buildable without a full node, and it is worth stating because it is not true
//! of a PBaaS chain launch — which is why those are refused.
//!
//! # Ported, not reverse-engineered
//!
//! The layout comes from `@chainvue/verus-sdk`'s `src/currency/outputs.ts`, which
//! is byte-locked against live `definecurrency` output across tokens and
//! fractional baskets. Several values here would be unguessable: the daemon's
//! fixed destination pubkeys, the flag combinations, and the pre-launch
//! conversion price.
//!
//! Two details that are easy to get wrong and fail only at the daemon:
//!
//! * **The import output pays a key *hash*, not a pubkey.** Every other CC
//!   output here uses `TYPE_PK` with the raw key; the import uses `TYPE_PKH`.
//! * **`CReserveDeposit` encodes its amounts as `VARINT`**, where the currency
//!   state and the export use fixed-width `int64`. Three encodings again, and
//!   again chosen per field.

use crate::amount::Amount;
use crate::cc::{cc_script, identity_primary_script, var_int, Destination, OptCcParams, EVAL_NONE};
use crate::currency::CurrencyId;
use crate::currency_definition::{
    currency_definition_script, option, CurrencyDefinition, EVAL_CURRENCY_DEFINITION,
};
use crate::error::TxError;
use crate::identity::{Identity, FLAG_ACTIVE_CURRENCY, FLAG_TOKENIZED_CONTROL};
use crate::register::identity_id;
use verus_wire::compact::write_compact_size;
use verus_wire::TxOut;

/// One satoshi-scaled unit — `SATOSHIDEN`.
const SATOSHIDEN: u128 = 100_000_000;

/// `EVAL_CROSSCHAIN_IMPORT`.
pub const EVAL_CROSSCHAIN_IMPORT: u8 = 13;
/// `EVAL_ACCEPTEDNOTARIZATION`.
pub const EVAL_ACCEPTEDNOTARIZATION: u8 = 5;
/// `EVAL_CROSSCHAIN_EXPORT`.
pub const EVAL_CROSSCHAIN_EXPORT: u8 = 12;
/// `EVAL_RESERVE_DEPOSIT`.
pub const EVAL_RESERVE_DEPOSIT: u8 = 11;

/// The daemon's fixed destination pubkey for accepted-notarization outputs.
const NOTARIZATION_PUBKEY: &str =
    "02d85f078815b7a52faa92639c3691d2a640e26c4e06de54dd1490f0e93bcc11c3";
/// The daemon's fixed destination pubkey for cross-chain export outputs.
const EXPORT_PUBKEY: &str = "02cbfe54fb371cfc89d35b46cafcad6ac3b7dc9b40546b0f30b2b29a4865ed3b4a";
/// The daemon's fixed destination pubkey for reserve deposit outputs.
const RESERVE_DEPOSIT_PUBKEY: &str =
    "03b99d7cb946c5b1f8a54cde49b8d7e0a2a15a22639feb798009f82b519526c050";
/// Hash160 of the cross-chain import pubkey.
///
/// The import output's destination is this key *hash*, not the key — the one
/// output of the seven that differs, and a mismatch fails only at the daemon.
const IMPORT_KEYHASH: [u8; 20] = [
    0x6e, 0x4a, 0xe3, 0x5c, 0xca, 0x12, 0x2e, 0xb6, 0x5e, 0x73, 0xab, 0xd4, 0xc9, 0x56, 0x94, 0x0e,
    0xf2, 0x5a, 0x3e, 0xab,
];

/// What the definition alone cannot supply.
#[derive(Clone, Debug)]
pub struct LaunchContext {
    /// The defining identity, as the chain currently holds it.
    ///
    /// Its address is the new currency's id, and it must not already have
    /// [`FLAG_ACTIVE_CURRENCY`] — an identity may define a currency exactly once.
    pub identity: Identity,
    /// The identity's 20-byte address.
    pub identity_address: [u8; 20],
    /// Current chain tip. Embedded in outputs 2–4.
    pub height: u32,
    /// The chain's currency launch fee, in native satoshis.
    ///
    /// Read it from `getcurrency` on the parent rather than assuming: it is 200
    /// native for a standard token or basket and 0.02 for an NFT, and a wrong
    /// value produces a definition the daemon rejects.
    pub launch_fee: Amount,
}

/// The seven output scripts, in the order they must appear.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchOutputs {
    /// Outputs 0 through 6.
    pub outputs: Vec<TxOut>,
}

impl LaunchOutputs {
    /// The reserve deposit's value — the import share of the launch fee, which
    /// the transaction has to fund on top of the miner fee.
    #[must_use]
    pub fn reserve_deposit_value(&self) -> Amount {
        Amount::from_sat(self.outputs[5].value)
    }
}

fn push_u16_le(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_i32_le(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_i64_le(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_varint(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&var_int(value));
}

/// `CCurrencyValueMap`: a compact-size count, then `(uint160, int64)` pairs.
fn push_currency_value_map(out: &mut Vec<u8>, entries: &[([u8; 20], u64)]) -> Result<(), TxError> {
    write_compact_size(out, entries.len() as u64);
    for (currency, amount) in entries {
        out.extend_from_slice(currency);
        push_i64_le(
            out,
            i64::try_from(*amount).map_err(|_| TxError::ValueOverflow)?,
        );
    }
    Ok(())
}

/// A vector of `n` zero `int64`s.
fn push_zero_amounts(out: &mut Vec<u8>, n: usize) {
    write_compact_size(out, n as u64);
    for _ in 0..n {
        push_i64_le(out, 0);
    }
}

fn pubkey(hex_str: &str) -> Result<Destination, TxError> {
    let bytes = hex::decode(hex_str).map_err(|e| {
        TxError::InvalidCurrencyDefinition(format!("a fixed pubkey is not hex: {e}"))
    })?;
    Ok(Destination::PubKey(bytes))
}

/// Wrap a payload in the CC output shape every launch output shares.
fn wrap(eval_code: u8, payload: Vec<u8>, destination: Destination) -> Result<Vec<u8>, TxError> {
    let master = OptCcParams::one_of_one(EVAL_NONE, destination.clone());
    let params = OptCcParams {
        vdata: vec![payload],
        ..OptCcParams::one_of_one(eval_code, destination)
    };
    cc_script(&master, &params)
}

/// Output 2: `CCrossChainImport`, a same-chain definition import stub.
fn serialize_import(system: [u8; 20], currency: [u8; 20], height: u32) -> Result<Vec<u8>, TxError> {
    let mut out = Vec::new();
    push_u16_le(&mut out, 1); // version
    push_u16_le(&mut out, 0x0009); // DEFINITION_IMPORT | SAME_CHAIN
    out.extend_from_slice(&system);
    push_u32_le(&mut out, height);
    out.extend_from_slice(&currency);
    push_currency_value_map(&mut out, &[])?; // importValue
    push_currency_value_map(&mut out, &[])?; // totalReserveOutMap
    push_i32_le(&mut out, 0); // numOutputs
    out.extend_from_slice(&[0u8; 32]); // hashReserveTransfers
    out.extend_from_slice(&[0u8; 32]); // exportTxId
                                       // exportTxOutNum points at output 4 of this same transaction — the export.
    push_i32_le(&mut out, 4);
    Ok(out)
}

/// The `CCoinbaseCurrencyState` the definition notarization carries.
///
/// The one computed value in the whole launch: for a fresh fractional currency
/// the pre-launch conversion price is the Bancor price with reserves replaced by
/// `SATOSHIDEN`, floored — `SATOSHIDEN^3 / (initial_supply * weight)`. It uses
/// the definition's **normalized** weights, and is byte-exact against the daemon
/// for even and uneven splits.
fn serialize_currency_state(
    currency: [u8; 20],
    reserves: &[CurrencyId],
    weights: &[i32],
    fractional: bool,
    initial_supply: Amount,
    token_supply: Amount,
) -> Result<Vec<u8>, TxError> {
    let n = reserves.len();
    let supply = if fractional {
        initial_supply
    } else {
        token_supply
    };
    // One weight per currency: the definition's for a basket, all zero for a
    // currency-mapped token whose definition carries none.
    let state_weights: Vec<i32> = if weights.len() == n {
        weights.to_vec()
    } else {
        vec![0; n]
    };

    let mut out = Vec::new();
    push_u16_le(&mut out, 1); // version
    push_u16_le(&mut out, if fractional { 0x0003 } else { 0x0002 }); // PRELAUNCH [| FRACTIONAL]
    out.extend_from_slice(&currency);

    write_compact_size(&mut out, n as u64);
    for reserve in reserves {
        out.extend_from_slice(&reserve.to_bytes());
    }
    write_compact_size(&mut out, n as u64);
    for weight in &state_weights {
        push_i32_le(&mut out, *weight);
    }
    push_zero_amounts(&mut out, n); // reserves — nothing preconverted yet

    push_varint(
        &mut out,
        if fractional {
            initial_supply.to_sat()
        } else {
            0
        },
    );
    push_varint(&mut out, 0); // emitted
    push_varint(&mut out, supply.to_sat());

    // The CCoinbaseCurrencyState extension, all zero at definition.
    push_i64_le(&mut out, 0); // primaryCurrencyOut
    push_i64_le(&mut out, 0); // preConvertedOut
    push_i64_le(&mut out, 0); // primaryCurrencyFees
    push_i64_le(&mut out, 0); // primaryCurrencyConversionFees
    push_zero_amounts(&mut out, n); // reserveIn
    push_zero_amounts(&mut out, n); // primaryCurrencyIn
    push_zero_amounts(&mut out, n); // reserveOut

    write_compact_size(&mut out, n as u64);
    for weight in &state_weights {
        let price = if fractional && initial_supply.to_sat() > 0 && *weight > 0 {
            let denominator = u128::from(initial_supply.to_sat())
                * u128::try_from(*weight).expect("a positive weight");
            let price = SATOSHIDEN * SATOSHIDEN * SATOSHIDEN / denominator;
            i64::try_from(price).map_err(|_| TxError::ValueOverflow)?
        } else {
            0
        };
        push_i64_le(&mut out, price);
    }
    push_zero_amounts(&mut out, n); // viaConversionPrice
    push_zero_amounts(&mut out, n); // fees

    write_compact_size(&mut out, n as u64); // priorWeights
    for _ in 0..n {
        push_i32_le(&mut out, 0);
    }
    push_zero_amounts(&mut out, n); // conversionFees
    Ok(out)
}

/// Output 3 body: `CPBaaSNotarization`, a definition stub.
fn serialize_notarization(currency: [u8; 20], state: &[u8], height: u32) -> Vec<u8> {
    let mut out = Vec::new();
    push_varint(&mut out, 2); // VERSION_CURRENT on VRSC and VRSCTEST
    push_varint(&mut out, 0x83); // DEF_NOTARIZATION | PRE_LAUNCH | SAME_CHAIN
    out.extend_from_slice(&[0x00, 0x00]); // proposer: empty CTransferDestination
    out.extend_from_slice(&currency);
    out.extend_from_slice(state);
    push_u32_le(&mut out, height);
    out.extend_from_slice(&[0u8; 32]); // prevNotarization.hash
    push_u32_le(&mut out, 0xffff_ffff); // prevNotarization.n
    out.extend_from_slice(&[0u8; 32]); // hashPrevCrossNotarization
    push_u32_le(&mut out, 0); // prevHeight
    write_compact_size(&mut out, 0); // currencyStates
    write_compact_size(&mut out, 0); // proofRoots
    write_compact_size(&mut out, 0); // nodes
    out
}

/// Output 4: `CCrossChainExport`, a same-chain definition export stub.
fn serialize_export(
    system: [u8; 20],
    currency: [u8; 20],
    height: u32,
    fee: &[([u8; 20], u64)],
) -> Result<Vec<u8>, TxError> {
    let mut out = Vec::new();
    push_u16_le(&mut out, 1); // version
    push_u16_le(&mut out, 0x0041); // DEFINITION_EXPORT | PRELAUNCH
    out.extend_from_slice(&system);
    out.extend_from_slice(&[0u8; 32]); // hashReserveTransfers
    out.extend_from_slice(&system); // destSystemID — the same chain
    out.extend_from_slice(&currency);
    out.extend_from_slice(&[0x00, 0x00]); // exporter: empty CTransferDestination
    push_i32_le(&mut out, -1); // firstInput
    push_i32_le(&mut out, 0); // numInputs
    push_varint(&mut out, 0); // sourceHeightStart
    push_varint(&mut out, u64::from(height)); // sourceHeightEnd
    push_currency_value_map(&mut out, fee)?; // totalFees
    push_currency_value_map(&mut out, fee)?; // totalAmounts
    push_currency_value_map(&mut out, &[])?; // totalBurned
    write_compact_size(&mut out, 0); // reserveTransfers
    Ok(out)
}

/// Output 5 body: `CReserveDeposit`.
///
/// Its amounts are `VARINT`, unlike the `int64` the state and export use.
fn serialize_reserve_deposit(system: [u8; 20], controlling: [u8; 20], amount: u64) -> Vec<u8> {
    let mut out = Vec::new();
    push_varint(&mut out, 1); // version
    out.extend_from_slice(&system);
    push_varint(&mut out, amount);
    out.extend_from_slice(&controlling);
    out
}

/// Output 6: change, as a CC output the defining identity can spend.
///
/// Hand-assembled to match the daemon exactly: the master params are `m=0, n=0`
/// with no destination, which no helper here produces because nothing else wants
/// it.
fn identity_change_script(identity: [u8; 20]) -> Vec<u8> {
    let master: [u8; 5] = [0x04, 0x03, 0x00, 0x00, 0x00]; // v3, eval 0, m=0, n=0
    let mut params = vec![0x04, 0x03, 0x00, 0x01, 0x01]; // v3, eval 0, m=1, n=1
    params.push(0x15); // push 21 bytes
    params.push(0x04); // DEST_ID
    params.extend_from_slice(&identity);

    let mut script = Vec::new();
    script.push(u8::try_from(master.len()).expect("five bytes"));
    script.extend_from_slice(&master);
    script.push(0xcc); // OP_CHECKCRYPTOCONDITION
    script.push(u8::try_from(params.len()).expect("under 76 bytes"));
    script.extend_from_slice(&params);
    script.push(0x75); // OP_DROP
    script
}

/// Build all seven output scripts of a `definecurrency` transaction.
///
/// Refuses, rather than building something the daemon will reject opaquely:
///
/// * an identity that already has an active currency — one per identity, ever,
/// * a name and parent that do not derive the defining identity's own address,
/// * a `start_block` at or below the tip, which would clear the launch instantly,
/// * a zero launch fee.
pub fn build_launch_outputs(
    definition: &CurrencyDefinition,
    context: &LaunchContext,
) -> Result<LaunchOutputs, TxError> {
    // A currency can be defined once per identity, and the daemon says so only
    // after the transaction is signed and submitted.
    if context.identity.flags & FLAG_ACTIVE_CURRENCY != 0 {
        return Err(TxError::InvalidCurrencyDefinition(
            "this identity already has an active currency; a currency can be defined only once \
             per identity"
                .into(),
        ));
    }

    // The new currency's id IS the defining identity's address, and outputs 2–5
    // all reference it. A typo in the name or the wrong parent builds a
    // transaction that signs cleanly and is rejected with nothing to go on.
    let derived = identity_id(&definition.name, Some(definition.parent.to_bytes()));
    if derived != context.identity_address {
        return Err(TxError::InvalidCurrencyDefinition(format!(
            "currency {:?} under {} derives identity {}, but the defining identity is {}",
            definition.name,
            definition.parent,
            hex::encode(derived),
            hex::encode(context.identity_address)
        )));
    }

    // The daemon never emits a start block at or below the tip. One would clear
    // the launch immediately — for a preconvert basket that is an instant
    // launch-failure and refund.
    if definition.start_block <= u64::from(context.height) {
        return Err(TxError::InvalidCurrencyDefinition(format!(
            "start_block {} must be above the current height {}",
            definition.start_block, context.height
        )));
    }
    if context.launch_fee == Amount::ZERO {
        return Err(TxError::InvalidCurrencyDefinition(
            "the launch fee must be positive; read it from getcurrency on the parent".into(),
        ));
    }

    let system = definition.system_id.to_bytes();
    let currency = context.identity_address;
    let fractional = definition.is_fractional();

    // The ceiling half of the launch fee funds the reserve deposit, and the
    // import and export threads carry the same figure as their fee. Ceiling, not
    // floor, so an odd fee still matches consensus.
    let fee = context.launch_fee.to_sat();
    let import_fee = fee - fee / 2;
    let fee_entry = [(system, import_fee)];

    // A fractional currency's supply waits for preconversions; a token's is the
    // sum of what it preallocates.
    let token_supply = Amount::checked_sum(definition.preallocations.iter().map(|p| p.amount))
        .ok_or(TxError::ValueOverflow)?;

    let mut identity = context.identity.clone();
    identity.flags |= FLAG_ACTIVE_CURRENCY;
    if definition.options & option::NFT_TOKEN != 0 {
        identity.flags |= FLAG_TOKENIZED_CONTROL;
    }

    let state = serialize_currency_state(
        currency,
        &definition.currencies,
        &definition.weights,
        fractional,
        definition.initial_supply,
        token_supply,
    )?;

    let outputs = vec![
        TxOut {
            value: 0,
            script_pubkey: identity_primary_script(
                context.identity_address,
                identity.to_bytes()?,
                identity.revocation_authority,
                identity.recovery_authority,
            )?,
        },
        TxOut {
            value: 0,
            script_pubkey: currency_definition_script(definition)?,
        },
        TxOut {
            value: 0,
            script_pubkey: wrap(
                EVAL_CROSSCHAIN_IMPORT,
                serialize_import(system, currency, context.height)?,
                // The one output that pays a key hash rather than a pubkey.
                Destination::PubKeyHash(IMPORT_KEYHASH),
            )?,
        },
        TxOut {
            value: 0,
            script_pubkey: wrap(
                EVAL_ACCEPTEDNOTARIZATION,
                serialize_notarization(currency, &state, context.height),
                pubkey(NOTARIZATION_PUBKEY)?,
            )?,
        },
        TxOut {
            value: 0,
            script_pubkey: wrap(
                EVAL_CROSSCHAIN_EXPORT,
                serialize_export(system, currency, context.height, &fee_entry)?,
                pubkey(EXPORT_PUBKEY)?,
            )?,
        },
        TxOut {
            value: import_fee,
            script_pubkey: wrap(
                EVAL_RESERVE_DEPOSIT,
                serialize_reserve_deposit(system, currency, import_fee),
                pubkey(RESERVE_DEPOSIT_PUBKEY)?,
            )?,
        },
        TxOut {
            value: 0,
            script_pubkey: identity_change_script(currency),
        },
    ];

    debug_assert_eq!(EVAL_CURRENCY_DEFINITION, 2, "output 1 is the definition");
    Ok(LaunchOutputs { outputs })
}
