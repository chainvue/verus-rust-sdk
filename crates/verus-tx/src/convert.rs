//! Conversions and burns: `CReserveTransfer` outputs.
//!
//! Everything this crate built before moved value that already existed. A
//! conversion asks the chain to *change what the value is*: native coins into a
//! fractional currency, a fractional back into one of its reserves, one reserve
//! into another through a shared fractional, or a token out of existence.
//!
//! # The output does not pay the recipient
//!
//! That is the thing to understand before reading anything else. A reserve
//! transfer pays a **protocol address**, and the real recipient is named inside
//! the payload:
//!
//! ```text
//! PUSH(master: EVAL_NONE, dest = RESERVE_TRANSFER_ADDRESS)
//! OP_CHECKCRYPTOCONDITION
//! PUSH(params: EVAL_RESERVE_TRANSFER, dest = RESERVE_TRANSFER_ADDRESS,
//!      vdata = [ CReserveTransfer ])
//! OP_DROP
//! ```
//!
//! The chain's import machinery picks the output up, performs the conversion at
//! the price prevailing when it is imported, and pays out. So a conversion is a
//! *request*, not a transfer, and the amount received is not known when it is
//! signed — see "the price is not agreed" below.
//!
//! # The amount is a request, and the price is not agreed
//!
//! There is no slippage bound in this structure. The conversion executes at
//! whatever the reserve ratios are when it is imported, which is at least one
//! block later and possibly many. A caller who needs a bound has to decide
//! before signing, from [`estimateconversion`], and accept that the answer can
//! move. Nothing in the transaction enforces it.
//!
//! # Reproduced from the daemon
//!
//! Every flag combination and layout here was taken from `sendcurrency` output
//! templates on VRSCTEST, and the scripts this module builds are compared
//! byte-for-byte against them in the tests. The flags are not guesses:
//!
//! | operation | flags | meaning |
//! |---|---|---|
//! | reserve → fractional | 3 | `VALID \| CONVERT` |
//! | fractional → reserve | 515 | `VALID \| CONVERT \| IMPORT_TO_SOURCE` |
//! | reserve → reserve (`via`) | 1027 | `VALID \| CONVERT \| RESERVE_TO_RESERVE` |
//! | burn | 641 | `VALID \| BURN_CHANGE_PRICE \| IMPORT_TO_SOURCE` |
//!
//! [`estimateconversion`]: https://api.verus.services

use verus_keys::{Address, PrivateKey};
use verus_wire::TxOut;

use crate::amount::Amount;
use crate::assemble::{assemble, Assembly};
use crate::cc::{cc_script, token_output, Destination, OptCcParams, EVAL_NONE};
use crate::currency::CurrencyId;
use crate::error::TxError;
use crate::expiry::Expiry;
use crate::fee::DEFAULT_FEE_PER_KB;
use crate::send::SignedTransaction;
use crate::Utxo;

/// `EVAL_RESERVE_TRANSFER` — an output requesting a conversion, export or burn.
pub const EVAL_RESERVE_TRANSFER: u8 = 8;

/// The address every reserve transfer is paid to.
///
/// Not the recipient, and not derived from anything: it is a protocol constant,
/// the same on mainnet and testnet. Verified rather than assumed — the address
/// has received 84,248,804 VRSC on mainnet and 3,678,445 VRSCTEST on testnet, so
/// it is plainly the same well-known destination on both.
///
/// It is `RTqQe58LSj2yr5CrwYFwcsAQ1edQwmrkUU`.
pub const RESERVE_TRANSFER_ADDRESS: [u8; 20] = [
    0xcb, 0x8a, 0x0f, 0x7f, 0x65, 0x1b, 0x48, 0x4a, 0x81, 0xe2, 0x31, 0x2c, 0x34, 0x38, 0xde, 0xb6,
    0x01, 0xe2, 0x73, 0x68,
];

/// The transfer is well formed. Always set.
pub const RT_VALID: u64 = 1;
/// Convert the value rather than simply moving it.
pub const RT_CONVERT: u64 = 2;
/// Convert at the **launch** price rather than the market one.
///
/// Only valid before the destination currency's `start_block`. A preconversion
/// is not a trade against a live reserve — the currency has no reserves yet — it
/// is a commitment made at the launch ratio, refunded in full if the launch
/// fails its minimums.
pub const RT_PRECONVERT: u64 = 4;
/// Create new supply of a centralized currency.
///
/// Only its controlling identity may do this, and only for a currency whose
/// `proofprotocol` is 2 (`CHAINID`) — a fractional basket cannot be minted, its
/// supply comes from conversions.
pub const RT_MINT_CURRENCY: u64 = 32;
/// Destroy the value, reducing supply and moving the fractional's price.
pub const RT_BURN_CHANGE_PRICE: u64 = 128;
/// The destination currency is the *source* of the conversion — set when
/// converting a fractional back into one of its reserves.
pub const RT_IMPORT_TO_SOURCE: u64 = 512;
/// Convert between two reserves through a shared fractional.
pub const RT_RESERVE_TO_RESERVE: u64 = 1024;

/// Where a converted amount is delivered.
///
/// A reserve transfer can name auxiliary destinations alongside the primary one.
/// The daemon attaches one — the same address again — on a conversion and none
/// on a burn, which is reproduced here rather than rationalised.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferDestination {
    /// Who receives the converted value.
    pub recipient: Destination,
    /// Additional destinations, serialized after the primary one.
    pub auxiliary: Vec<Destination>,
}

impl TransferDestination {
    /// A conversion's destination, in the shape the daemon writes: the recipient
    /// listed once as the primary and once as an auxiliary.
    pub fn converting(recipient: Destination) -> Self {
        Self {
            recipient: recipient.clone(),
            auxiliary: vec![recipient],
        }
    }

    /// A converting destination whose refund goes somewhere else.
    ///
    /// The auxiliary destination is the **refund address**: where the value
    /// returns if the conversion cannot be completed. For an ordinary conversion
    /// that is a rare case; for a
    /// [`Preconvert`](crate::convert::ConversionKind::Preconvert) it is the
    /// normal one — a launch that misses its `min_preconversion` refunds every
    /// contribution, and this is where yours goes.
    ///
    /// [`converting`](Self::converting) names the recipient for both, which is
    /// correct only when they are the same party. The daemon uses the *sender*
    /// as the auxiliary, so a payment to somebody else refunds to you, not to
    /// them.
    pub fn converting_with_refund(recipient: Destination, refund: Destination) -> Self {
        Self {
            recipient,
            auxiliary: vec![refund],
        }
    }

    /// A destination with no auxiliaries, which is what a burn carries.
    pub fn plain(recipient: Destination) -> Self {
        Self {
            recipient,
            auxiliary: Vec::new(),
        }
    }

    /// The type byte: the destination kind, with bit 6 set when auxiliaries
    /// follow.
    fn type_byte(&self) -> u8 {
        let base = destination_type(&self.recipient);
        if self.auxiliary.is_empty() {
            base
        } else {
            base | FLAG_DEST_AUX
        }
    }

    fn serialize(&self) -> Result<Vec<u8>, TxError> {
        let mut out = crate::cc::var_int(u64::from(self.type_byte()));
        let body = destination_bytes(&self.recipient);
        write_compact_size(&mut out, body.len() as u64);
        out.extend_from_slice(&body);

        if !self.auxiliary.is_empty() {
            write_compact_size(&mut out, self.auxiliary.len() as u64);
            for aux in &self.auxiliary {
                // Each auxiliary is itself a serialized destination, length
                // prefixed: type, then its own length-prefixed body.
                let mut inner = crate::cc::var_int(u64::from(destination_type(aux)));
                let aux_body = destination_bytes(aux);
                write_compact_size(&mut inner, aux_body.len() as u64);
                inner.extend_from_slice(&aux_body);
                write_compact_size(&mut out, inner.len() as u64);
                out.extend_from_slice(&inner);
            }
        }
        Ok(out)
    }
}

/// Set on a destination type when auxiliary destinations follow.
const FLAG_DEST_AUX: u8 = 64;

fn destination_type(destination: &Destination) -> u8 {
    match destination {
        Destination::PubKey(_) => 1,
        Destination::PubKeyHash(_) => 2,
        Destination::ScriptHash(_) => 3,
        Destination::Identity(_) => 4,
    }
}

fn destination_bytes(destination: &Destination) -> Vec<u8> {
    match destination {
        Destination::PubKey(key) => key.clone(),
        Destination::PubKeyHash(hash)
        | Destination::ScriptHash(hash)
        | Destination::Identity(hash) => hash.to_vec(),
    }
}

/// Bitcoin-style compact size, used for the *lengths* inside a transfer
/// destination — not for the amounts, which use the Satoshi VARINT.
fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    // Each branch is guarded by the bound above it, so every conversion is
    // exact; `try_from` says so to the compiler rather than to a reader.
    if let Ok(small) = u8::try_from(n) {
        if small < 0xfd {
            out.push(small);
            return;
        }
    }
    if let Ok(medium) = u16::try_from(n) {
        out.push(0xfd);
        out.extend_from_slice(&medium.to_le_bytes());
    } else if let Ok(large) = u32::try_from(n) {
        out.push(0xfe);
        out.extend_from_slice(&large.to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// What a reserve transfer is asking the chain to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConversionKind {
    /// A reserve into the fractional currency that holds it.
    ///
    /// `into` is the fractional.
    IntoFractional {
        /// The fractional currency being bought.
        fractional: CurrencyId,
    },
    /// A fractional currency back into one of its reserves.
    ///
    /// `reserve` must actually be a reserve of the currency being spent, which
    /// this crate cannot check — the chain rejects it if not.
    IntoReserve {
        /// The reserve currency being bought.
        reserve: CurrencyId,
    },
    /// One reserve into another, through a fractional that holds both.
    ReserveToReserve {
        /// The fractional to route through.
        via: CurrencyId,
        /// The reserve currency being bought.
        target: CurrencyId,
    },
    /// A reserve into a currency that has not launched yet, at the launch price.
    ///
    /// Valid **only** while the destination is pre-launch: after `start_block`
    /// the chain rejects it, and before it a plain conversion is rejected in
    /// turn, because there are no reserves to price against. The two are not
    /// interchangeable at any height.
    ///
    /// If the launch fails to meet its `min_preconversion`, every preconversion
    /// is refunded — which is why this is safe to make early and why the amount
    /// must respect `max_preconversion`.
    Preconvert {
        /// The launching currency being bought.
        fractional: CurrencyId,
    },
    /// Create new supply of a centralized currency.
    ///
    /// Signed by the currency's **controlling identity** — the one the currency
    /// is named after — and valid only for a currency whose `proofprotocol` is
    /// 2 (`CHAINID`). A fractional basket is refused by the chain: its supply
    /// comes from conversions, not from an issuer's say-so.
    ///
    /// Unlike a conversion this carries **no auxiliary destination**. There is
    /// nothing to refund — the value did not exist before.
    Mint {
        /// The currency to create.
        currency: CurrencyId,
    },
    /// Destroy the value.
    ///
    /// The currency must be a token. Burning reduces supply, which moves a
    /// fractional's price — there is no undo, and no output pays anything back.
    Burn,
}

impl ConversionKind {
    /// The flags the daemon sets for this operation.
    fn flags(&self) -> u64 {
        match self {
            ConversionKind::IntoFractional { .. } => RT_VALID | RT_CONVERT,
            ConversionKind::Preconvert { .. } => RT_VALID | RT_CONVERT | RT_PRECONVERT,
            ConversionKind::Mint { .. } => RT_VALID | RT_MINT_CURRENCY,
            ConversionKind::IntoReserve { .. } => RT_VALID | RT_CONVERT | RT_IMPORT_TO_SOURCE,
            ConversionKind::ReserveToReserve { .. } => {
                RT_VALID | RT_CONVERT | RT_RESERVE_TO_RESERVE
            }
            ConversionKind::Burn => RT_VALID | RT_BURN_CHANGE_PRICE | RT_IMPORT_TO_SOURCE,
        }
    }

    /// The destination currency written into the payload.
    ///
    /// For a burn this is the currency being destroyed, which reads oddly until
    /// you notice a burn is an "import to source" like a fractional-to-reserve
    /// conversion — the value goes back where it came from and stops there.
    fn destination_currency(&self, source: CurrencyId) -> CurrencyId {
        match self {
            ConversionKind::IntoFractional { fractional }
            | ConversionKind::Preconvert { fractional } => *fractional,
            ConversionKind::IntoReserve { reserve } => *reserve,
            ConversionKind::ReserveToReserve { via, .. } => *via,
            ConversionKind::Mint { currency } => *currency,
            ConversionKind::Burn => source,
        }
    }

    /// The second currency, present only for a reserve-to-reserve conversion.
    fn second_reserve(&self) -> Option<CurrencyId> {
        match self {
            ConversionKind::ReserveToReserve { target, .. } => Some(*target),
            _ => None,
        }
    }
}

/// A conversion request, before it becomes a script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReserveTransfer {
    /// The currency being spent.
    pub source: CurrencyId,
    /// How much of it, in its smallest unit.
    pub amount: Amount,
    /// What to do with it.
    pub kind: ConversionKind,
    /// The currency the fee is paid in.
    pub fee_currency: CurrencyId,
    /// The conversion fee.
    ///
    /// **Chain policy, not a constant.** Read it from `estimateconversion`
    /// rather than hard-coding: the daemon charged 0.0002001 for a conversion
    /// and 0.0002 for a burn on VRSCTEST, and neither figure is guaranteed to
    /// hold on another chain or after a parameter change.
    pub fee: Amount,
    /// Where the converted value is delivered.
    pub destination: TransferDestination,
}

impl ReserveTransfer {
    /// Serialize the `CReserveTransfer` payload.
    pub fn to_payload(&self) -> Result<Vec<u8>, TxError> {
        let mut out = token_output(self.source, self.amount.to_sat());
        out.extend_from_slice(&crate::cc::var_int(self.kind.flags()));
        out.extend_from_slice(&self.fee_currency.to_bytes());
        out.extend_from_slice(&crate::cc::var_int(self.fee.to_sat()));
        out.extend_from_slice(&self.destination.serialize()?);
        out.extend_from_slice(&self.kind.destination_currency(self.source).to_bytes());
        if let Some(second) = self.kind.second_reserve() {
            out.extend_from_slice(&second.to_bytes());
        }
        Ok(out)
    }

    /// The complete `scriptPubKey` for this conversion.
    pub fn to_script(&self) -> Result<Vec<u8>, TxError> {
        let holder = Destination::PubKeyHash(RESERVE_TRANSFER_ADDRESS);
        let master = OptCcParams::one_of_one(EVAL_NONE, holder.clone());
        let params = OptCcParams {
            vdata: vec![self.to_payload()?],
            ..OptCcParams::one_of_one(EVAL_RESERVE_TRANSFER, holder)
        };
        cc_script(&master, &params)
    }

    /// The **native** value this output must carry.
    ///
    /// When the source currency is the chain's own, the conversion is funded by
    /// the output's native value: amount plus fee. When it is a token, the value
    /// travels in the payload and the native value is the fee only.
    ///
    /// Getting this backwards produces a transaction whose value does not
    /// conserve, which the daemon rejects — or, worse, one that quietly hands
    /// the difference to a miner.
    pub fn native_value(&self, chain_currency: CurrencyId) -> Result<Amount, TxError> {
        // A mint does not spend its amount — it creates it. The output carries
        // the fee and nothing else, however the value slot is filled in.
        // Funding the amount natively would ask a caller to hold what they are
        // about to issue, which is the opposite of what minting is for, and the
        // daemon's own template carries exactly the fee.
        if matches!(self.kind, ConversionKind::Mint { .. }) {
            return if self.fee_currency == chain_currency {
                Ok(self.fee)
            } else {
                Ok(Amount::ZERO)
            };
        }
        if self.source == chain_currency {
            self.amount
                .checked_add(self.fee)
                .ok_or(TxError::ValueOverflow)
        } else if self.fee_currency == chain_currency {
            Ok(self.fee)
        } else {
            Ok(Amount::ZERO)
        }
    }
}

/// Convert `amount` of `source` into another currency.
///
/// Returns the `scriptPubKey` and the native value the output must carry. The
/// caller assembles them into a transaction — see `verus_flows::convert` for the
/// version that funds and broadcasts it.
///
/// # Errors
///
/// Refuses a zero amount, and refuses converting a currency into itself, which
/// the chain would reject after the fee had been paid.
pub fn build_conversion(
    source: CurrencyId,
    amount: Amount,
    kind: ConversionKind,
    recipient: Address,
    fee_currency: CurrencyId,
    fee: Amount,
) -> Result<ReserveTransfer, TxError> {
    if amount == Amount::ZERO {
        return Err(TxError::InvalidConversion(
            "a conversion of zero would pay a fee to do nothing".into(),
        ));
    }
    let target = kind.destination_currency(source);
    if target == source && !matches!(kind, ConversionKind::Burn) {
        return Err(TxError::InvalidConversion(format!(
            "{source:?} cannot be converted into itself"
        )));
    }
    if let ConversionKind::ReserveToReserve { via, target } = &kind {
        if via == target {
            return Err(TxError::InvalidConversion(
                "the currency routed through cannot also be the target".into(),
            ));
        }
        if *target == source {
            return Err(TxError::InvalidConversion(
                "the target reserve is the source currency".into(),
            ));
        }
    }

    // The auxiliary destination is the refund address, so it exists only where
    // there is something to refund. A burn destroys the value deliberately and a
    // mint creates value that did not exist, so both carry a plain destination —
    // the daemon's own templates for each have the bare type byte, not the
    // aux-flagged one.
    let destination = match kind {
        ConversionKind::Burn | ConversionKind::Mint { .. } => {
            TransferDestination::plain(Destination::PubKeyHash(recipient.hash()))
        }
        _ => TransferDestination::converting(Destination::PubKeyHash(recipient.hash())),
    };

    Ok(ReserveTransfer {
        source,
        amount,
        kind,
        fee_currency,
        fee,
        destination,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VRSCTEST: [u8; 20] = hex20("a6ef9ea235635e328124ff3429db9f9e91b64e2d");
    const SHYLOCK: [u8; 20] = hex20("e908e3e5c373389fa7ae5d4b22a87ffc204a74ff");
    const SDKDISCOUNT: [u8; 20] = hex20("29c5b458d298301d3da78b1dd9b000c679c2a7c6");
    const TARGET_RESERVE: [u8; 20] = hex20("6c4d1ff569d46ff39270b2b7059cbeaf44d8203f");
    const RECIPIENT: &str = "RJGYC29RTSGQbWMrstQziJxfQaiDCjm5iP";

    const fn hex20(text: &str) -> [u8; 20] {
        let bytes = text.as_bytes();
        let mut out = [0u8; 20];
        let mut i = 0;
        while i < 20 {
            out[i] = nibble(bytes[i * 2]) * 16 + nibble(bytes[i * 2 + 1]);
            i += 1;
        }
        out
    }
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => 0,
        }
    }

    fn recipient() -> Address {
        RECIPIENT.parse().unwrap()
    }

    /// The scripts `sendcurrency` produced on VRSCTEST, with a `returntxtemplate`
    /// so nothing was spent. Reproducing these byte-for-byte is what says this
    /// module is right rather than merely self-consistent.
    ///
    /// Captured 2026-07-29 against verusd 1.2.17-2; see
    /// `fixtures/daemon/reserve_transfers.json`.
    #[test]
    fn a_reserve_into_a_fractional_matches_the_daemon() {
        let transfer = build_conversion(
            CurrencyId::from_bytes(VRSCTEST),
            Amount::from_sat(1_50000000),
            ConversionKind::IntoFractional {
                fractional: CurrencyId::from_bytes(SHYLOCK),
            },
            recipient(),
            CurrencyId::from_bytes(VRSCTEST),
            Amount::from_sat(20_010),
        )
        .unwrap();

        assert_eq!(
            hex::encode(transfer.to_script().unwrap()),
            "1a040300010114cb8a0f7f651b484a81e2312c3438deb601e27368cc4c8f\
             040308010114cb8a0f7f651b484a81e2312c3438deb601e273684c7301a6\
             ef9ea235635e328124ff3429db9f9e91b64e2dc6c2a20003a6ef9ea23563\
             5e328124ff3429db9f9e91b64e2d809b2a42146299813ef10e47ac626d3c\
             87257308b7d25a204c011602146299813ef10e47ac626d3c87257308b7d2\
             5a204ce908e3e5c373389fa7ae5d4b22a87ffc204a74ff75"
                .replace(['\n', ' '], "")
        );
        // The whole amount plus the fee leaves natively: the source is the
        // chain's own currency.
        assert_eq!(
            transfer
                .native_value(CurrencyId::from_bytes(VRSCTEST))
                .unwrap()
                .to_sat(),
            1_50020010
        );
    }

    #[test]
    fn a_fractional_into_a_reserve_matches_the_daemon() {
        let transfer = build_conversion(
            CurrencyId::from_bytes(SHYLOCK),
            Amount::from_sat(1_00000000),
            ConversionKind::IntoReserve {
                reserve: CurrencyId::from_bytes(VRSCTEST),
            },
            recipient(),
            CurrencyId::from_bytes(VRSCTEST),
            Amount::from_sat(20_010),
        )
        .unwrap();

        assert_eq!(
            hex::encode(transfer.to_script().unwrap()),
            "1a040300010114cb8a0f7f651b484a81e2312c3438deb601e27368cc4c90\
             040308010114cb8a0f7f651b484a81e2312c3438deb601e273684c7401e9\
             08e3e5c373389fa7ae5d4b22a87ffc204a74ffaed6c1008303a6ef9ea235\
             635e328124ff3429db9f9e91b64e2d809b2a42146299813ef10e47ac626d\
             3c87257308b7d25a204c011602146299813ef10e47ac626d3c87257308b7\
             d25a204ca6ef9ea235635e328124ff3429db9f9e91b64e2d75"
                .replace(['\n', ' '], "")
        );
        // A token source: only the fee is native.
        assert_eq!(
            transfer
                .native_value(CurrencyId::from_bytes(VRSCTEST))
                .unwrap()
                .to_sat(),
            20_010
        );
    }

    #[test]
    fn a_burn_matches_the_daemon() {
        let transfer = build_conversion(
            CurrencyId::from_bytes(SHYLOCK),
            Amount::from_sat(1_00000000),
            ConversionKind::Burn,
            recipient(),
            CurrencyId::from_bytes(VRSCTEST),
            Amount::from_sat(20_000),
        )
        .unwrap();

        assert_eq!(
            hex::encode(transfer.to_script().unwrap()),
            "1a040300010114cb8a0f7f651b484a81e2312c3438deb601e27368cc4c78\
             040308010114cb8a0f7f651b484a81e2312c3438deb601e273684c5c01e9\
             08e3e5c373389fa7ae5d4b22a87ffc204a74ffaed6c1008401a6ef9ea235\
             635e328124ff3429db9f9e91b64e2d809b2002146299813ef10e47ac626d\
             3c87257308b7d25a204ce908e3e5c373389fa7ae5d4b22a87ffc204a74ff75"
                .replace(['\n', ' '], "")
        );
    }

    #[test]
    fn a_reserve_to_reserve_conversion_matches_the_daemon() {
        let transfer = build_conversion(
            CurrencyId::from_bytes(VRSCTEST),
            Amount::from_sat(1_00000000),
            ConversionKind::ReserveToReserve {
                via: CurrencyId::from_bytes(SDKDISCOUNT),
                target: CurrencyId::from_bytes(TARGET_RESERVE),
            },
            recipient(),
            CurrencyId::from_bytes(VRSCTEST),
            Amount::from_sat(20_010),
        )
        .unwrap();

        assert_eq!(
            hex::encode(transfer.to_script().unwrap()),
            "1a040300010114cb8a0f7f651b484a81e2312c3438deb601e27368cc4ca4\
             040308010114cb8a0f7f651b484a81e2312c3438deb601e273684c8801a6\
             ef9ea235635e328124ff3429db9f9e91b64e2daed6c1008703a6ef9ea235\
             635e328124ff3429db9f9e91b64e2d809b2a42146299813ef10e47ac626d\
             3c87257308b7d25a204c011602146299813ef10e47ac626d3c87257308b7\
             d25a204c29c5b458d298301d3da78b1dd9b000c679c2a7c66c4d1ff569d4\
             6ff39270b2b7059cbeaf44d8203f75"
                .replace(['\n', ' '], "")
        );
    }

    /// The flag values are the whole protocol contract here. A wrong one asks
    /// the chain for a different operation, and the fee is spent finding out.
    #[test]
    fn each_operation_sets_the_flags_the_daemon_sets() {
        assert_eq!(
            ConversionKind::IntoFractional {
                fractional: CurrencyId::from_bytes(SHYLOCK)
            }
            .flags(),
            3
        );
        assert_eq!(
            ConversionKind::IntoReserve {
                reserve: CurrencyId::from_bytes(VRSCTEST)
            }
            .flags(),
            515
        );
        assert_eq!(
            ConversionKind::ReserveToReserve {
                via: CurrencyId::from_bytes(SDKDISCOUNT),
                target: CurrencyId::from_bytes(TARGET_RESERVE),
            }
            .flags(),
            1027
        );
        assert_eq!(ConversionKind::Burn.flags(), 641);
    }

    /// A burn carries no auxiliary destination and a conversion carries one.
    /// Both were taken from the daemon; neither is a preference.
    #[test]
    fn a_burn_has_no_auxiliary_destination() {
        let burn = build_conversion(
            CurrencyId::from_bytes(SHYLOCK),
            Amount::from_sat(1),
            ConversionKind::Burn,
            recipient(),
            CurrencyId::from_bytes(VRSCTEST),
            Amount::from_sat(1),
        )
        .unwrap();
        assert!(burn.destination.auxiliary.is_empty());
        assert_eq!(burn.destination.type_byte(), 2);

        let convert = build_conversion(
            CurrencyId::from_bytes(VRSCTEST),
            Amount::from_sat(1),
            ConversionKind::IntoFractional {
                fractional: CurrencyId::from_bytes(SHYLOCK),
            },
            recipient(),
            CurrencyId::from_bytes(VRSCTEST),
            Amount::from_sat(1),
        )
        .unwrap();
        assert_eq!(convert.destination.auxiliary.len(), 1);
        assert_eq!(convert.destination.type_byte(), 66);
    }

    /// Converting a currency into itself is rejected by the chain — after the
    /// fee is gone. Refusing locally is free.
    #[test]
    fn a_currency_cannot_be_converted_into_itself() {
        assert!(build_conversion(
            CurrencyId::from_bytes(SHYLOCK),
            Amount::from_sat(1),
            ConversionKind::IntoFractional {
                fractional: CurrencyId::from_bytes(SHYLOCK)
            },
            recipient(),
            CurrencyId::from_bytes(VRSCTEST),
            Amount::from_sat(1),
        )
        .is_err());
    }

    /// A zero conversion pays a fee to accomplish nothing.
    #[test]
    fn a_zero_conversion_is_refused() {
        assert!(build_conversion(
            CurrencyId::from_bytes(VRSCTEST),
            Amount::ZERO,
            ConversionKind::IntoFractional {
                fractional: CurrencyId::from_bytes(SHYLOCK)
            },
            recipient(),
            CurrencyId::from_bytes(VRSCTEST),
            Amount::from_sat(1),
        )
        .is_err());
    }

    /// A route that goes through the currency it is trying to reach, or starts
    /// where it means to end, is a caller mistake worth catching.
    #[test]
    fn a_nonsensical_route_is_refused() {
        let via = CurrencyId::from_bytes(SDKDISCOUNT);
        assert!(build_conversion(
            CurrencyId::from_bytes(VRSCTEST),
            Amount::from_sat(1),
            ConversionKind::ReserveToReserve { via, target: via },
            recipient(),
            CurrencyId::from_bytes(VRSCTEST),
            Amount::from_sat(1),
        )
        .is_err());
        assert!(build_conversion(
            CurrencyId::from_bytes(VRSCTEST),
            Amount::from_sat(1),
            ConversionKind::ReserveToReserve {
                via,
                target: CurrencyId::from_bytes(VRSCTEST),
            },
            recipient(),
            CurrencyId::from_bytes(VRSCTEST),
            Amount::from_sat(1),
        )
        .is_err());
    }

    /// A token conversion must not claim native value it does not move, and a
    /// native one must claim all of it. This is the check that stops a
    /// transaction silently donating the difference to a miner.
    #[test]
    fn native_value_follows_the_source_currency() {
        let chain = CurrencyId::from_bytes(VRSCTEST);
        let native_source = build_conversion(
            chain,
            Amount::from_sat(500),
            ConversionKind::IntoFractional {
                fractional: CurrencyId::from_bytes(SHYLOCK),
            },
            recipient(),
            chain,
            Amount::from_sat(7),
        )
        .unwrap();
        assert_eq!(native_source.native_value(chain).unwrap().to_sat(), 507);

        let token_source = build_conversion(
            CurrencyId::from_bytes(SHYLOCK),
            Amount::from_sat(500),
            ConversionKind::IntoReserve { reserve: chain },
            recipient(),
            chain,
            Amount::from_sat(7),
        )
        .unwrap();
        assert_eq!(token_source.native_value(chain).unwrap().to_sat(), 7);

        // A fee in some third currency leaves nothing native at all.
        let all_token = build_conversion(
            CurrencyId::from_bytes(SHYLOCK),
            Amount::from_sat(500),
            ConversionKind::IntoReserve { reserve: chain },
            recipient(),
            CurrencyId::from_bytes(SDKDISCOUNT),
            Amount::from_sat(7),
        )
        .unwrap();
        assert_eq!(all_token.native_value(chain).unwrap().to_sat(), 0);
    }
}

/// What to build for a conversion.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ConversionParams<'a> {
    /// The conversion request itself.
    pub transfer: &'a ReserveTransfer,
    /// P2PKH UTXOs funding the native side: the amount when the source is the
    /// chain's own currency, the fee otherwise, plus the miner fee.
    pub utxos: &'a [Utxo],
    /// Token-bearing inputs, when the source currency is a token.
    ///
    /// Every one is spent whole and the surplus returns as token change, so a
    /// token left out is a token burned — the same rule as a sub-identity
    /// registration.
    pub token_funding: &'a [Utxo],
    /// Outputs held by the minted currency's controlling identity, for a mint.
    ///
    /// Consensus requires that a mint be *spent by* the currency id: at least
    /// one input of the transaction must spend a CryptoCondition output whose
    /// scriptSig fulfillment carries the identity's primary-key signatures
    /// meeting its `minsigs` (`CheckIdentitySpends`, `pbaas.cpp`). A P2PKH
    /// input can never satisfy that — its scriptSig has no fulfillment — so a
    /// mint funded only from plain coins builds, signs, and is then rejected
    /// with nothing but `bad-txns-failed-precheck`. Discovered the hard way;
    /// pinned from the daemon's source afterwards.
    ///
    /// Each output here must pay the controlling identity itself (the standard
    /// pay-to-identity script), is spent whole, and the surplus returns **to
    /// the identity**, not to the change address — money under an identity's
    /// authority should not quietly migrate to a bare key.
    pub identity_funding: &'a [Utxo],
    /// The chain's own currency, which decides whether the source is native.
    pub chain_currency: CurrencyId,
    /// Where change goes.
    pub change_address: Address,
    /// When the transaction stops being minable.
    pub expiry: Expiry,
    /// Fee rate in satoshis per kilobyte.
    pub fee_per_kb: u64,
}

impl<'a> ConversionParams<'a> {
    /// A conversion funded entirely from native coins.
    pub fn new(
        transfer: &'a ReserveTransfer,
        utxos: &'a [Utxo],
        chain_currency: CurrencyId,
        change_address: Address,
        expiry: Expiry,
    ) -> Self {
        Self {
            transfer,
            utxos,
            token_funding: &[],
            identity_funding: &[],
            chain_currency,
            change_address,
            expiry,
            fee_per_kb: DEFAULT_FEE_PER_KB,
        }
    }

    /// Token inputs, for converting or burning a token.
    pub fn with_token_funding(mut self, token_funding: &'a [Utxo]) -> Self {
        self.token_funding = token_funding;
        self
    }

    /// Identity-held inputs, for a mint. See [`ConversionParams::identity_funding`].
    pub fn with_identity_funding(mut self, identity_funding: &'a [Utxo]) -> Self {
        self.identity_funding = identity_funding;
        self
    }

    /// Override the fee rate.
    pub fn with_fee_per_kb(mut self, fee_per_kb: u64) -> Self {
        self.fee_per_kb = fee_per_kb;
        self
    }
}

/// Build and sign a conversion.
///
/// The token side is conserved the same way a sub-identity registration
/// conserves it: every token input is spent whole, the conversion consumes what
/// it needs, and the remainder comes back as token change. A missing change
/// output destroys the surplus, so it is computed here rather than left to the
/// caller.
pub fn build_conversion_transaction(
    key: &PrivateKey,
    params: &ConversionParams<'_>,
) -> Result<SignedTransaction, TxError> {
    params.expiry.check()?;

    let transfer = params.transfer;
    let native = transfer.native_value(params.chain_currency)?;
    let mut outputs = vec![TxOut {
        value: native.to_sat(),
        script_pubkey: transfer.to_script()?,
    }];

    // A mint is authorised by WHAT IT SPENDS, so its input side is checked
    // first — before the token accounting below could fail with a message
    // about token balances when the real mistake is the mint's shape. See
    // `ConversionParams::identity_funding`.
    let source_is_native = transfer.source == params.chain_currency;
    let is_mint = matches!(transfer.kind, ConversionKind::Mint { .. });
    if is_mint && !source_is_native {
        // The daemon's own template names the SYSTEM currency in the source
        // slot. A token source would route through the token-change accounting
        // below, whose inputs a mint never spends — a signed transaction with
        // an unbacked change output, rejected on chain.
        return Err(TxError::InvalidConversion(
            "a mint's transfer names the chain's own currency as its source".into(),
        ));
    }
    if is_mint && params.identity_funding.is_empty() {
        return Err(TxError::InvalidConversion(
            "a mint must spend an output held by the currency's controlling identity; \
             fund it with identity_funding, not plain coins"
                .into(),
        ));
    }
    if is_mint && !params.utxos.is_empty() {
        // Mixing key-held coins into an identity-authorised spend is refused
        // rather than half-supported: the identity covers the whole outlay on
        // every proven path, and P2PKH surplus routed to the identity's change
        // script would migrate plain-key money under the identity silently.
        return Err(TxError::InvalidConversion(
            "a mint is funded by the identity alone; do not supply P2PKH utxos".into(),
        ));
    }

    if !params.identity_funding.is_empty() {
        let ConversionKind::Mint { currency } = transfer.kind else {
            // Checked up here with the other input-side refusals — below the
            // token accounting, its message would be masked by a token-balance
            // error that is not the caller's real mistake.
            return Err(TxError::InvalidConversion(
                "identity funding is only used for a mint".into(),
            ));
        };
        let identity_script = crate::cc::identity_payment_script(currency.to_bytes())?;
        for utxo in params.identity_funding {
            if utxo.script_pubkey != identity_script {
                return Err(TxError::InvalidConversion(format!(
                    "identity funding {}:{} does not pay the controlling identity of the \
                     currency being minted",
                    utxo.txid.to_display_hex(),
                    utxo.vout
                )));
            }
        }
    }

    // Token change, when the source is a token.
    if !source_is_native {
        let mut held: u64 = 0;
        for utxo in params.token_funding {
            match crate::decode::decode_output_script(&utxo.script_pubkey)? {
                crate::decode::OutputKind::ReserveOutput { tokens, .. } => {
                    // A reserve output can carry several currencies. Only the
                    // one being converted counts towards the amount; the others
                    // still have to come back as change, so a multi-currency
                    // input is refused rather than silently destroying them.
                    if tokens.len() != 1 || tokens[0].0 != transfer.source {
                        return Err(TxError::InvalidConversion(
                            "a token input does not carry exactly the currency being converted"
                                .into(),
                        ));
                    }
                    held = held
                        .checked_add(tokens[0].1)
                        .ok_or(TxError::ValueOverflow)?;
                }
                _ => {
                    return Err(TxError::InvalidConversion(
                        "a token input is not a reserve output".into(),
                    ))
                }
            }
        }
        let needed = transfer.amount.to_sat();
        let change = held
            .checked_sub(needed)
            .ok_or_else(|| TxError::InsufficientTokens {
                currency: hex::encode(transfer.source.to_bytes()),
                missing: needed.saturating_sub(held),
            })?;
        if change > 0 {
            outputs.push(TxOut {
                value: 0,
                script_pubkey: crate::cc::reserve_output_script(
                    params.change_address.hash(),
                    transfer.source,
                    change,
                )?,
            });
        }
    } else if !params.token_funding.is_empty() {
        return Err(TxError::InvalidConversion(
            "a native conversion needs no token inputs".into(),
        ));
    }

    let output_count = outputs.len() as u64 + 1;
    let (leading, change_script) = if is_mint {
        // Whatever the identity outputs carry beyond the fee returns to the
        // identity itself, not to a bare key.
        let ConversionKind::Mint { currency } = transfer.kind else {
            unreachable!("is_mint checked above");
        };
        (
            params.identity_funding,
            Some(crate::cc::identity_payment_script(currency.to_bytes())?),
        )
    } else {
        (params.token_funding, None)
    };
    assemble(
        key,
        &[key],
        Assembly {
            leading,
            funding: params.utxos,
            outputs,
            burn: Amount::ZERO,
            fee_output_count: output_count,
            change_address: &params.change_address,
            change_script,
            value_bearing_leading: is_mint,
            expiry: params.expiry,
            fee_per_kb: params.fee_per_kb,
        },
    )
}

#[cfg(test)]
mod preconvert_tests {
    use super::*;

    fn hash(text: &str) -> [u8; 20] {
        text.parse::<Address>().expect("address").hash()
    }

    /// The daemon's own preconvert, reproduced byte for byte.
    ///
    /// Captured from `sendcurrency … "preconvert": true` with `returntx` on
    /// VRSCTEST, 2026-07-30, against a currency this SDK had just launched.
    #[test]
    fn a_preconvert_matches_the_daemon() {
        let vrsctest = CurrencyId::from_bytes(hash("iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq"));
        let launching = CurrencyId::from_bytes(hash("iRRhsKoiBuMoyANFcQ2NMLJXDgfSHjgffS"));

        let transfer = ReserveTransfer {
            source: vrsctest,
            amount: Amount::from_coins_str("5.0").unwrap(),
            fee_currency: vrsctest,
            fee: Amount::from_coins_str("0.0002").unwrap(),
            // Sent FROM one address TO another: the auxiliary is the sender,
            // which is where a failed launch refunds to.
            destination: TransferDestination::converting_with_refund(
                Destination::PubKeyHash(hash("RWoj68ERmYHEhrkhFc1GgaxJGnS4z6XBQG")),
                Destination::PubKeyHash(hash("RWKve6J7EB8YiFegJ4KGvuuzZwyt8URkUb")),
            ),
            kind: ConversionKind::Preconvert {
                fractional: launching,
            },
        };

        assert_eq!(
            hex::encode(transfer.to_script().unwrap()),
            "1a040300010114cb8a0f7f651b484a81e2312c3438deb601e27368cc4c90040308010114cb8a0f7\
             f651b484a81e2312c3438deb601e273684c7401a6ef9ea235635e328124ff3429db9f9e91b64e2d8\
             0edb4c90007a6ef9ea235635e328124ff3429db9f9e91b64e2d809b204214ec2101af4bbb81466ce\
             a147744865262182d594401160214e6df008745f81e609c87bfc8d6f071c9ccd79f20f0ca3af64b0\
             622d96024557f92ecc5f2e676048075"
                .replace(['\n', ' '], "")
        );
        // The output carries the amount plus the fee, natively.
        assert_eq!(
            transfer.native_value(vrsctest).unwrap(),
            Amount::from_coins_str("5.0002").unwrap()
        );
    }

    /// The daemon's own mint, reproduced byte for byte.
    ///
    /// Captured from `sendcurrency "sdkcuralpha@" … "mintnew": true` with
    /// `returntx` on VRSCTEST, 2026-07-30.
    ///
    /// Two things worth reading off it. The destination carries **no auxiliary**
    /// — a conversion refunds if it cannot complete, and there is nothing to
    /// refund on a mint. And the payload's value slot names the *system*
    /// currency while the destination names what is being created, which reads
    /// oddly and is what the daemon emits.
    #[test]
    fn a_mint_matches_the_daemon() {
        let vrsctest = CurrencyId::from_bytes(hash("iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq"));
        let token = CurrencyId::from_bytes(hash("i7UCaJkKRFXBCK4S1AMrkfKTnPwdLc7dV7"));

        let transfer = ReserveTransfer {
            source: vrsctest,
            amount: Amount::from_coins_str("1.0").unwrap(),
            fee_currency: vrsctest,
            fee: Amount::from_coins_str("0.0002").unwrap(),
            destination: TransferDestination::plain(Destination::PubKeyHash(hash(
                "RWoj68ERmYHEhrkhFc1GgaxJGnS4z6XBQG",
            ))),
            kind: ConversionKind::Mint { currency: token },
        };

        assert_eq!(
            hex::encode(transfer.to_script().unwrap()),
            "1a040300010114cb8a0f7f651b484a81e2312c3438deb601e27368cc4c77040308010114cb8a0f7             f651b484a81e2312c3438deb601e273684c5b01a6ef9ea235635e328124ff3429db9f9e91b64e2da             ed6c10021a6ef9ea235635e328124ff3429db9f9e91b64e2d809b200214ec2101af4bbb81466cea1             47744865262182d59442bd0c2dcf49d034269ad0cd786c01bdd4bc2f9d675"
                .replace(['\n', ' '], "")
        );
    }

    /// Mint is `VALID | MINT_CURRENCY` — no CONVERT bit, because nothing is
    /// being converted.
    #[test]
    fn minting_does_not_set_the_convert_flag() {
        let token = CurrencyId::from_bytes([0x22; 20]);
        let flags = ConversionKind::Mint { currency: token }.flags();

        assert_eq!(flags, RT_VALID | RT_MINT_CURRENCY);
        assert_eq!(flags & RT_CONVERT, 0);
        assert_eq!(flags, 33);
    }

    /// A mint's output carries the fee, not the amount.
    ///
    /// Funding the amount natively would ask an issuer to already hold what
    /// they are about to create. The daemon's template carries 0.0002 for a
    /// 1.0 mint, and this is what that means in the builder.
    #[test]
    fn a_mint_funds_only_its_fee() {
        let vrsctest = CurrencyId::from_bytes(hash("iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq"));
        let token = CurrencyId::from_bytes([0x22; 20]);
        let fee = Amount::from_coins_str("0.0002").unwrap();

        let mint = ReserveTransfer {
            source: vrsctest,
            amount: Amount::from_coins_str("500.0").unwrap(),
            fee_currency: vrsctest,
            fee,
            destination: TransferDestination::plain(Destination::PubKeyHash([0x33; 20])),
            kind: ConversionKind::Mint { currency: token },
        };
        assert_eq!(mint.native_value(vrsctest).unwrap(), fee);

        // The same shape as a conversion would fund the amount as well, which
        // is the difference this guards.
        let converting = ReserveTransfer {
            kind: ConversionKind::IntoFractional { fractional: token },
            ..mint.clone()
        };
        assert_eq!(
            converting.native_value(vrsctest).unwrap(),
            Amount::from_coins_str("500.0002").unwrap()
        );
    }

    /// A preconvert is `VALID | CONVERT | PRECONVERT`, and the bit that makes it
    /// one is the third.
    #[test]
    fn the_preconvert_flag_is_the_only_difference_from_a_conversion() {
        let target = CurrencyId::from_bytes([0x11; 20]);
        let plain = ConversionKind::IntoFractional { fractional: target }.flags();
        let pre = ConversionKind::Preconvert { fractional: target }.flags();

        assert_eq!(plain, RT_VALID | RT_CONVERT);
        assert_eq!(pre, RT_VALID | RT_CONVERT | RT_PRECONVERT);
        assert_eq!(pre ^ plain, RT_PRECONVERT);
    }

    /// The refund address is a distinct field, and `converting` collapses it
    /// onto the recipient — right only when they are the same party.
    #[test]
    fn the_refund_address_is_not_always_the_recipient() {
        let payee = Destination::PubKeyHash([0xaa; 20]);
        let me = Destination::PubKeyHash([0xbb; 20]);

        let collapsed = TransferDestination::converting(payee.clone());
        assert_eq!(collapsed.auxiliary, vec![payee.clone()]);

        let explicit = TransferDestination::converting_with_refund(payee.clone(), me.clone());
        assert_eq!(explicit.recipient, payee);
        assert_eq!(explicit.auxiliary, vec![me]);
        assert_ne!(
            explicit.serialize().unwrap(),
            collapsed.serialize().unwrap(),
            "paying someone else must not refund to them"
        );
    }
}

#[cfg(test)]
mod mint_destination_tests {
    use super::*;

    /// A mint built through [`build_conversion`] must carry a **plain**
    /// destination.
    ///
    /// This is the gap the unit tests missed: `a_mint_matches_the_daemon`
    /// constructs the transfer by hand with `plain`, so it passed while
    /// `build_conversion` — the path every flow actually takes — still attached
    /// an auxiliary. The chain rejected it with `bad-txns-failed-precheck` and
    /// the diff was a single type byte: 0x42 where the daemon writes 0x02.
    #[test]
    fn a_built_mint_has_no_auxiliary_destination() {
        let source = CurrencyId::from_bytes([0x11; 20]);
        let token = CurrencyId::from_bytes([0x22; 20]);
        let recipient: Address = "RJGYC29RTSGQbWMrstQziJxfQaiDCjm5iP".parse().unwrap();

        let mint = build_conversion(
            source,
            Amount::from_sat(1),
            ConversionKind::Mint { currency: token },
            recipient,
            source,
            Amount::from_sat(1),
        )
        .unwrap();
        assert!(
            mint.destination.auxiliary.is_empty(),
            "a mint has nothing to refund, so it carries no auxiliary destination"
        );

        // A conversion through the same path still has one.
        let converting = build_conversion(
            source,
            Amount::from_sat(1),
            ConversionKind::IntoFractional { fractional: token },
            recipient,
            source,
            Amount::from_sat(1),
        )
        .unwrap();
        assert_eq!(converting.destination.auxiliary.len(), 1);
    }
}

#[cfg(test)]
mod mint_funding_tests {
    use super::*;
    use crate::cc::identity_payment_script;
    use crate::Txid;
    use verus_wire::TxV4;

    const TEST_WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";

    fn key() -> PrivateKey {
        PrivateKey::from_wif(TEST_WIF).unwrap()
    }

    fn chain() -> CurrencyId {
        CurrencyId::from_bytes([0x11; 20])
    }

    fn token() -> CurrencyId {
        CurrencyId::from_bytes([0x22; 20])
    }

    fn mint_transfer() -> ReserveTransfer {
        build_conversion(
            chain(),
            Amount::from_coins_str("500").unwrap(),
            ConversionKind::Mint { currency: token() },
            key().address(),
            chain(),
            Amount::from_sat(20_000),
        )
        .unwrap()
    }

    fn identity_held(satoshis: u64) -> Utxo {
        Utxo {
            txid: Txid::from_display_hex(
                "59a1097f1162b8dfd7037b5933d7156700bb0fe4230f14f003ba5f1c087206b3",
            )
            .unwrap(),
            vout: 0,
            satoshis: Amount::from_sat(satoshis),
            script_pubkey: identity_payment_script(token().to_bytes()).unwrap(),
        }
    }

    /// The whole mint transaction, built through the path callers take.
    ///
    /// Input 0 spends the identity-held output with a fulfillment; output 0
    /// is the reserve transfer carrying only the fee; the surplus returns to
    /// the identity, not to a bare key. This is the shape `CheckIdentitySpends`
    /// accepts and a P2PKH-funded mint cannot produce.
    #[test]
    fn a_mint_spends_the_identity_and_returns_change_to_it() {
        let transfer = mint_transfer();
        let funding = [identity_held(10_00000000)];
        let params = ConversionParams::new(&transfer, &[], chain(), key().address(), Expiry::Never)
            .with_identity_funding(&funding);
        let signed = build_conversion_transaction(&key(), &params).unwrap();

        let tx = TxV4::deserialize(&hex::decode(&signed.hex).unwrap()).unwrap();
        assert_eq!(tx.inputs.len(), 1, "only the identity output is spent");
        assert_eq!(tx.outputs.len(), 2, "transfer plus identity change");

        // Output 0 is the transfer itself, byte-identical to the encoder.
        assert_eq!(tx.outputs[0].script_pubkey, transfer.to_script().unwrap());
        assert_eq!(tx.outputs[0].value, 20_000, "a mint carries only its fee");

        // Change returns to the identity's own script.
        assert_eq!(
            tx.outputs[1].script_pubkey,
            identity_payment_script(token().to_bytes()).unwrap()
        );

        // Exact conservation: what the identity held minus what the outputs
        // carry is the miner fee, nothing else.
        let outputs: u64 = tx.outputs.iter().map(|o| o.value).sum();
        assert_eq!(10_00000000 - outputs, signed.fee.to_sat());

        // The input is a fulfillment stating SIGHASH_ALL for itself — the two
        // properties `CheckIdentitySpends` requires of the scriptSig.
        let data = match tx.inputs[0].script_sig.as_slice() {
            [0x4c, _, rest @ ..] => rest,
            [op, rest @ ..] if *op < 0x4c => rest,
            other => panic!("not a single push: {other:02x?}"),
        };
        assert_eq!(data[0], 1, "SmartTransactionSignatures v1");
        assert_eq!(data[1], 0x01, "SIGHASH_ALL, stated inline");
    }

    /// A mint funded only from plain coins is refused before signing.
    ///
    /// It would build, sign, and be rejected with nothing but
    /// `bad-txns-failed-precheck` — which is exactly how this requirement was
    /// discovered. The refusal names the cure.
    #[test]
    fn a_mint_without_identity_funding_is_refused() {
        let transfer = mint_transfer();
        let plain = [Utxo {
            txid: Txid::from_display_hex(
                "59a1097f1162b8dfd7037b5933d7156700bb0fe4230f14f003ba5f1c087206b3",
            )
            .unwrap(),
            vout: 1,
            satoshis: Amount::from_sat(10_00000000),
            script_pubkey: key().address().p2pkh_script_pubkey().unwrap(),
        }];
        let params =
            ConversionParams::new(&transfer, &plain, chain(), key().address(), Expiry::Never);
        assert!(matches!(
            build_conversion_transaction(&key(), &params),
            Err(TxError::InvalidConversion(reason))
                if reason.contains("controlling identity")
        ));
    }

    /// Identity funding on anything but a mint is refused — no other flow is
    /// proven to need it, and accepting it silently would spend identity funds
    /// where plain coins were meant.
    #[test]
    fn identity_funding_on_a_conversion_is_refused() {
        let transfer = build_conversion(
            chain(),
            Amount::from_sat(1_00000000),
            ConversionKind::IntoFractional {
                fractional: token(),
            },
            key().address(),
            chain(),
            Amount::from_sat(20_000),
        )
        .unwrap();
        let funding = [identity_held(10_00000000)];
        let params = ConversionParams::new(&transfer, &[], chain(), key().address(), Expiry::Never)
            .with_identity_funding(&funding);
        assert!(matches!(
            build_conversion_transaction(&key(), &params),
            Err(TxError::InvalidConversion(reason)) if reason.contains("only used for a mint")
        ));
    }

    /// Funding that does not pay the minted currency's controlling identity is
    /// refused — the wrong identity's money must not be spendable by a typo.
    #[test]
    fn identity_funding_for_the_wrong_identity_is_refused() {
        let transfer = mint_transfer();
        let mut wrong = identity_held(10_00000000);
        wrong.script_pubkey = identity_payment_script([0x99; 20]).unwrap();
        let funding = [wrong];
        let params = ConversionParams::new(&transfer, &[], chain(), key().address(), Expiry::Never)
            .with_identity_funding(&funding);
        assert!(matches!(
            build_conversion_transaction(&key(), &params),
            Err(TxError::InvalidConversion(reason))
                if reason.contains("does not pay the controlling identity")
        ));
    }

    /// The identity must cover the transfer fee plus the miner fee; short by
    /// any amount is a named refusal, not a transaction.
    #[test]
    fn a_mint_the_identity_cannot_pay_for_is_refused() {
        let transfer = mint_transfer();
        let funding = [identity_held(20_000)]; // exactly the transfer fee, nothing for the miner
        let params = ConversionParams::new(&transfer, &[], chain(), key().address(), Expiry::Never)
            .with_identity_funding(&funding);
        assert!(matches!(
            build_conversion_transaction(&key(), &params),
            Err(TxError::InsufficientFunds { .. })
        ));
    }
}
