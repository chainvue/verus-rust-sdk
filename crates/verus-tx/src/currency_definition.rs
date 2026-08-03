//! Serializing a currency definition — `CCurrencyDefinition` — into the output
//! script a `definecurrency` transaction carries.
//!
//! # Where this layout came from
//!
//! Three earlier PRs mapped it by differential analysis: 25 permutation vectors
//! captured from `verusd` (free, because `definecurrency` builds a transaction
//! and does **not** broadcast), then diffed a field at a time. That settled the
//! header, the fee fields, and the finding that a definition uses **three
//! different amount encodings chosen per field**.
//!
//! It could not settle two things, and I said so rather than guessing: the order
//! of the interleaved amount vectors, and some bytes that are zero in every
//! vector and therefore invisible. Black-box probing cannot distinguish two
//! empty lists from one, and a wrong guess about money-carrying fields is not
//! the kind of thing to ship.
//!
//! Both are now resolved from `@chainvue/verus-sdk`'s `src/currency/definition.ts`,
//! which mirrors `CCurrencyDefinition::SerializationOp` (VerusCoin
//! `src/pbaas/crosschainrpc.h`) and is itself byte-locked against on-chain
//! definitions. The answers: `gatewayConverterIssuance` — an `int64`, zero for
//! everything here — sits between the preallocations and the currency list, and
//! the invisible empty lists are `conversions` and `preconverted`.
//!
//! Everything derived by probing was confirmed, which is why those PRs were
//! worth keeping rather than discarding.
//!
//! # The three encodings
//!
//! | encoding | fields |
//! |---|---|
//! | `VARINT` (satoshi, base-128 with the minus-one adjustment) | `start_block`, `end_block`, `prelaunch_discount`, `min_notaries_confirm`, the three fee fields |
//! | little-endian `int32` | `weights`, `prelaunch_carveout`, the two protocol ids |
//! | little-endian `int64` | `initial_supply`, preallocation amounts, and every amount vector |
//!
//! Picking one for the whole object produces wrong money **without failing to
//! parse**, so the distinction is load-bearing rather than cosmetic.
//!
//! # `preconverted` mirrors `initial_contributions`
//!
//! Found while byte-locking the vectors, and not visible in any RPC output: the
//! daemon never echoes `preconverted` in its JSON view of a definition, yet
//! every captured script carries it, always equal to `initial_contributions`. A
//! contribution made at definition time is already converted, so the two start
//! life the same.
//!
//! The field stays separate here because the wire has two of them, but a caller
//! building a fractional basket almost certainly wants them equal — see
//! [`CurrencyDefinition::with_contributions`].
//!
//! # Scope
//!
//! Simple tokens and fractional reserve baskets. PBaaS chains and gateways are
//! refused: their serialization carries extra trailing fields this does not
//! write, and a definition that is short by a field is not a definition.
//!
//! For a non-gateway, non-PBaaS currency the C++ writes its five trailing fee
//! fields into a **shadowed local stream**, so they never reach the wire — a
//! token or basket definition ends at `id_import_fees`. That is a genuine
//! quirk of the source, not an omission here.

use crate::amount::Amount;
use crate::cc::{cc_script, var_int, Destination, OptCcParams, EVAL_NONE};
use crate::currency::CurrencyId;
use crate::error::TxError;
use verus_wire::compact::write_compact_size;

pub use crate::cc::EVAL_CURRENCY_DEFINITION;

/// `CCurrencyDefinition::VERSION_CURRENT`.
pub const CURRENCY_DEFINITION_VERSION: u32 = 1;

/// The longest a currency name may be on the wire.
const MAX_NAME_LEN: usize = 64;

/// Currency option bits — `CCurrencyDefinition::ECurrencyOptions`.
pub mod option {
    /// A fractional reserve basket.
    pub const FRACTIONAL: u32 = 0x1;
    /// Only identities may hold it.
    pub const ID_RESTRICTED: u32 = 0x2;
    /// Identities may stake it.
    pub const ID_STAKING: u32 = 0x4;
    /// Sub-identity registrations pay referrals.
    pub const ID_REFERRALS: u32 = 0x8;
    /// A referral is mandatory.
    pub const ID_REFERRALREQUIRED: u32 = 0x10;
    /// A token rather than an independent chain. Set for everything this
    /// module builds.
    pub const TOKEN: u32 = 0x20;
    /// Single-currency basket.
    pub const SINGLECURRENCY: u32 = 0x40;
    /// A gateway — refused here.
    pub const GATEWAY: u32 = 0x80;
    /// An independent PBaaS chain — refused here.
    pub const PBAAS: u32 = 0x100;
    /// A gateway's converter currency — refused here.
    pub const GATEWAY_CONVERTER: u32 = 0x200;
    /// Gateway name controller.
    pub const GATEWAY_NAMECONTROLLER: u32 = 0x400;
    /// An NFT.
    pub const NFT_TOKEN: u32 = 0x800;
    /// Identities may not be registered under it.
    pub const NO_IDS: u32 = 0x1000;
}

/// One preallocation: an identity and what it receives at launch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preallocation {
    /// The recipient identity's 20-byte hash.
    pub recipient: [u8; 20],
    /// How much it receives.
    pub amount: Amount,
}

/// A currency definition, ready to serialize.
///
/// Built by hand rather than through a builder: every field is a consensus
/// value, and a defaulted one that should have been set is a currency launched
/// wrong and unfixable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrencyDefinition {
    /// Structure version. [`CURRENCY_DEFINITION_VERSION`].
    pub version: u32,
    /// Option bits — see [`option`].
    pub options: u32,
    /// The parent currency this is defined under.
    pub parent: CurrencyId,
    /// The name, at most 64 bytes.
    pub name: String,
    /// The system the launch happens on.
    pub launch_system_id: CurrencyId,
    /// The system that hosts it.
    pub system_id: CurrencyId,
    /// `ENotarizationProtocol`.
    pub notarization_protocol: i32,
    /// `EProofProtocol`.
    pub proof_protocol: i32,
    /// Block the currency starts at.
    pub start_block: u64,
    /// Block it ends at; zero for never.
    pub end_block: u64,
    /// Initial supply.
    pub initial_supply: Amount,
    /// Who gets what before anyone converts.
    pub preallocations: Vec<Preallocation>,
    /// Gateway converter issuance. Zero for everything this module builds —
    /// present because the wire has a field for it, between the preallocations
    /// and the currency list.
    pub gateway_converter_issuance: Amount,
    /// Reserve currencies. Empty for a simple token.
    pub currencies: Vec<CurrencyId>,
    /// Reserve weights, as `int32` satoshi-scaled ratios.
    pub weights: Vec<i32>,
    /// Conversion rates.
    pub conversions: Vec<Amount>,
    /// Minimum preconversion per reserve.
    pub min_preconversion: Vec<Amount>,
    /// Maximum preconversion per reserve.
    pub max_preconversion: Vec<Amount>,
    /// Initial contributions per reserve.
    pub initial_contributions: Vec<Amount>,
    /// Amount already preconverted per reserve.
    pub preconverted: Vec<Amount>,
    /// Pre-launch discount, satoshi-scaled.
    pub prelaunch_discount: u64,
    /// Pre-launch carve-out, satoshi-scaled. `int32` on the wire, not `int64`.
    pub prelaunch_carveout: i32,
    /// Notaries, for a notary-confirmed currency.
    pub notaries: Vec<CurrencyId>,
    /// How many notaries must confirm.
    pub min_notaries_confirm: u64,
    /// Fee to register a sub-identity.
    pub id_registration_fees: u64,
    /// How many referral levels pay out.
    pub id_referral_levels: u64,
    /// Fee to import an identity.
    pub id_import_fees: u64,
}

impl CurrencyDefinition {
    /// A simple token under `parent`, with sensible protocol defaults.
    ///
    /// Amounts and fees still have to be set: there is no safe default for
    /// money.
    #[must_use]
    pub fn token(parent: CurrencyId, name: impl Into<String>, start_block: u64) -> Self {
        Self {
            version: CURRENCY_DEFINITION_VERSION,
            options: option::TOKEN,
            parent,
            name: name.into(),
            launch_system_id: parent,
            system_id: parent,
            notarization_protocol: 1,
            proof_protocol: 1,
            start_block,
            end_block: 0,
            initial_supply: Amount::ZERO,
            preallocations: Vec::new(),
            gateway_converter_issuance: Amount::ZERO,
            currencies: Vec::new(),
            weights: Vec::new(),
            conversions: Vec::new(),
            min_preconversion: Vec::new(),
            max_preconversion: Vec::new(),
            initial_contributions: Vec::new(),
            preconverted: Vec::new(),
            prelaunch_discount: 0,
            prelaunch_carveout: 0,
            notaries: Vec::new(),
            min_notaries_confirm: 0,
            id_registration_fees: 0,
            id_referral_levels: 0,
            id_import_fees: 0,
        }
    }

    /// Set the initial contributions, and `preconverted` to match.
    ///
    /// The daemon initialises the two equal at definition time, and nothing in
    /// its RPC output reveals the second field, so setting one without the other
    /// is almost always a mistake. Do it by hand only when you know why.
    #[must_use]
    pub fn with_contributions(mut self, contributions: Vec<Amount>) -> Self {
        self.preconverted = contributions.clone();
        self.initial_contributions = contributions;
        self
    }

    /// Whether this is a fractional basket.
    #[must_use]
    pub fn is_fractional(&self) -> bool {
        self.options & option::FRACTIONAL != 0
    }
}

/// The daemon's hardcoded destination for `EVAL_CURRENCY_DEFINITION` outputs —
/// `PBaaSDefinitionPubKey` in `src/cc/CCcustom.cpp`.
///
/// Chain-independent: identical on VRSC and VRSCTEST, which is what makes
/// embedding it safe rather than something to derive.
const CURRENCY_DEFINITION_PUBKEY: [u8; 33] = [
    0x02, 0xa0, 0xde, 0x91, 0x74, 0x0d, 0x3d, 0x5a, 0x3a, 0x4a, 0x79, 0x90, 0xae, 0x22, 0x31, 0x51,
    0x33, 0xd0, 0x2f, 0x33, 0x71, 0x6b, 0x33, 0x9e, 0xbc, 0xe8, 0x86, 0x62, 0xd0, 0x12, 0x22, 0x4e,
    0xf5,
];

fn push_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_i32_le(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_i64_le(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_amount_le(out: &mut Vec<u8>, amount: Amount) -> Result<(), TxError> {
    let sats = i64::try_from(amount.to_sat()).map_err(|_| TxError::ValueOverflow)?;
    push_i64_le(out, sats);
    Ok(())
}

fn push_varint(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&var_int(value));
}

fn push_amount_vector(out: &mut Vec<u8>, values: &[Amount]) -> Result<(), TxError> {
    write_compact_size(out, values.len() as u64);
    for value in values {
        push_amount_le(out, *value)?;
    }
    Ok(())
}

fn push_currency_vector(out: &mut Vec<u8>, values: &[CurrencyId]) {
    write_compact_size(out, values.len() as u64);
    for value in values {
        out.extend_from_slice(&value.to_bytes());
    }
}

/// Serialize a definition to the blob carried as `vdata[0]`.
///
/// This is `CCurrencyDefinition::AsVector()`.
pub fn serialize_definition(def: &CurrencyDefinition) -> Result<Vec<u8>, TxError> {
    // Refused rather than approximated: a gateway or PBaaS definition carries
    // trailing fields this does not write, and a definition short by a field
    // describes a different currency.
    let unsupported = option::GATEWAY | option::PBAAS | option::GATEWAY_CONVERTER;
    if def.options & unsupported != 0 {
        return Err(TxError::InvalidCurrencyDefinition(
            "gateway and PBaaS definitions carry extra trailing fields this does not encode".into(),
        ));
    }
    let name_bytes = def.name.as_bytes();
    if name_bytes.len() > MAX_NAME_LEN {
        return Err(TxError::InvalidCurrencyDefinition(format!(
            "name is {} bytes, at most {MAX_NAME_LEN} are allowed",
            name_bytes.len()
        )));
    }
    // Every per-reserve vector is indexed by the same reserve list. A short one
    // silently shifts which currency an amount belongs to.
    let reserves = def.currencies.len();
    for (label, len) in [
        ("weights", def.weights.len()),
        ("conversions", def.conversions.len()),
        ("min_preconversion", def.min_preconversion.len()),
        ("max_preconversion", def.max_preconversion.len()),
        ("initial_contributions", def.initial_contributions.len()),
        ("preconverted", def.preconverted.len()),
    ] {
        if len != 0 && len != reserves {
            return Err(TxError::InvalidCurrencyDefinition(format!(
                "{label} has {len} entries but there are {reserves} reserve currencies; \
                 an amount would be attributed to the wrong currency"
            )));
        }
    }

    let mut out = Vec::new();
    push_u32_le(&mut out, def.version);
    push_u32_le(&mut out, def.options);
    out.extend_from_slice(&def.parent.to_bytes());
    write_compact_size(&mut out, name_bytes.len() as u64);
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(&def.launch_system_id.to_bytes());
    out.extend_from_slice(&def.system_id.to_bytes());
    push_i32_le(&mut out, def.notarization_protocol);
    push_i32_le(&mut out, def.proof_protocol);
    // nativeCurrencyID: a null CTransferDestination — type 0, empty payload.
    out.extend_from_slice(&[0x00, 0x00]);
    // gatewayID: a null uint160.
    out.extend_from_slice(&[0u8; 20]);
    push_varint(&mut out, def.start_block);
    push_varint(&mut out, def.end_block);
    push_amount_le(&mut out, def.initial_supply)?;

    write_compact_size(&mut out, def.preallocations.len() as u64);
    for preallocation in &def.preallocations {
        out.extend_from_slice(&preallocation.recipient);
        push_amount_le(&mut out, preallocation.amount)?;
    }

    push_amount_le(&mut out, def.gateway_converter_issuance)?;
    push_currency_vector(&mut out, &def.currencies);

    write_compact_size(&mut out, def.weights.len() as u64);
    for weight in &def.weights {
        push_i32_le(&mut out, *weight);
    }

    push_amount_vector(&mut out, &def.conversions)?;
    push_amount_vector(&mut out, &def.min_preconversion)?;
    push_amount_vector(&mut out, &def.max_preconversion)?;
    push_amount_vector(&mut out, &def.initial_contributions)?;
    push_amount_vector(&mut out, &def.preconverted)?;

    push_varint(&mut out, def.prelaunch_discount);
    push_i32_le(&mut out, def.prelaunch_carveout);
    push_currency_vector(&mut out, &def.notaries);
    push_varint(&mut out, def.min_notaries_confirm);
    push_varint(&mut out, def.id_registration_fees);
    push_varint(&mut out, def.id_referral_levels);
    push_varint(&mut out, def.id_import_fees);

    Ok(out)
}

/// The complete `EVAL_CURRENCY_DEFINITION` output script.
///
/// A 1-of-1 CryptoCondition to the daemon's fixed definition pubkey, carrying
/// the serialized definition as its only `vdata` entry.
pub fn currency_definition_script(def: &CurrencyDefinition) -> Result<Vec<u8>, TxError> {
    let destination = Destination::PubKey(CURRENCY_DEFINITION_PUBKEY.to_vec());
    let master = OptCcParams::one_of_one(EVAL_NONE, destination.clone());
    let params = OptCcParams {
        vdata: vec![serialize_definition(def)?],
        ..OptCcParams::one_of_one(EVAL_CURRENCY_DEFINITION, destination)
    };
    cc_script(&master, &params)
}
