//! VerusPay invoices: the object behind every "pay me" link and QR code.
//!
//! Ported from `VerusPayInvoice` and `VerusPayInvoiceDetails` in the TypeScript
//! SDK (`src/vdxf/classes/payment/`). An invoice says *what is being asked for*
//! — how much, in which currency, to which destination, until when — and
//! nothing about how it gets paid. Deciding whether to pay one, and selecting
//! the coins to pay it with, belongs to the wallet.
//!
//! Two directions, and the type serves both. A wallet **reads** a merchant's
//! deeplink or QR code rather than making a user retype an address and an
//! amount, which is how an amount gets typed wrong. A wallet **writes** one from
//! its Receive screen rather than inventing a second format the phones cannot
//! scan.
//!
//! ```text
//! VdxfObject {
//!     key      veruspay.vrsc::invoice
//!     version  3 | 4, with 0x80000000 ORed in when signed
//!     data     [ system_id ‖ signing_id ‖ signature ]  -- signed only
//!              VerusPayInvoiceDetails
//! }
//! ```
//!
//! # The four things that are easy to get wrong
//!
//! **The URI scheme is not `verus://`.** It is the lowercased vdxfid of
//! `vrsc::applications.wallet`, and the payload is a **path segment**, not a
//! query parameter. Verus Mobile routes `verus:` and `verus0:` to a different
//! parser entirely, so a link built as `verus://x-callback-url/…` is rejected
//! outright. [`VerusPayInvoice::to_wallet_deeplink_uri`] therefore takes no
//! scheme argument and this module exposes no way to build any other one; the
//! scheme is derived from [`keys::WALLET_VDXF_KEY`] at the single place it is
//! written, and [`wallet_deeplink_scheme`] is there for a wallet that has to
//! register it with an operating system.
//!
//! **Signing is a version bit, not a field.** `setSigned()` ORs `0x80000000`
//! into the version, so a signed v4 invoice's frame version reads
//! `2147483652`. A reader that compares that to 4 without masking rejects a
//! perfectly good invoice. Here the bit is not a number a caller handles at
//! all: it is [`VerusPayInvoice::signature`] being `Some`, and
//! [`VerusPayInvoice::serialized_version`] is what puts it back on the wire.
//!
//! **A signed invoice's payload is not just the details.** It prepends the
//! system id, the signing id and a nested signature object, and — unlike the
//! login-consent and provisioning messages, which write theirs *with* its key —
//! an invoice writes the signature object **without** its key. Twenty bytes of
//! difference, in a position where getting it wrong reads a version out of the
//! middle of a hash.
//!
//! **Flags suppress fields; they do not zero them.** `acceptsAnyAmount` means
//! the amount is *absent from the bytes*, not that it is zero, and the same goes
//! for `acceptsAnyDestination`. That is why [`RequestedAmount`] and
//! [`InvoiceDestination`] are enums rather than `Option`s carrying a separate
//! flag word: the flags this module writes are computed from the data
//! ([`VerusPayInvoiceDetails::flags`]) and cannot contradict it.
//!
//! # Signed does not mean verified
//!
//! [`VerusPayInvoice::signature`] being `Some` says an invoice *carries* a
//! signature, never that anyone checked it. Checking it needs the signing
//! identity **as it stood at the signature's height**, which needs a node, so it
//! lives with the login flow in `verus-flows` rather than here. What this module
//! provides is the exact input to that check:
//! [`VerusPayInvoice::details_hash`], which is `getDetailsHash` — and the type
//! distinction itself, so that a caller cannot lose track of which kind it is
//! holding and render an unsigned invoice as though somebody vouched for it.

use verus_keys::{Address, AddressKind};
use verus_tx_primitives::cc::{var_int, Destination};
use verus_tx_primitives::{CurrencyId, TxError};
use verus_wire::compact::write_compact_size;
use verus_wire::hash::sha256;

use crate::convert::TransferDestination;
use crate::decode::{read_compact_size, read_var_int};
use crate::vdxf::keys;
use crate::vdxf::object::{compact_size_length, DEFAULT_VERSION};
use crate::vdxf::{Hash160, VdxfObject};

/// `VERUSPAY_VALID`. Always set; an invoice without it is not one.
pub const FLAG_VALID: u64 = 1;
/// `VERUSPAY_ACCEPTS_CONVERSION`. Appends `maxestimatedslippage`.
pub const FLAG_ACCEPTS_CONVERSION: u64 = 2;
/// `VERUSPAY_ACCEPTS_NON_VERUS_SYSTEMS`. Appends the counted system array.
pub const FLAG_ACCEPTS_NON_VERUS_SYSTEMS: u64 = 4;
/// `VERUSPAY_EXPIRES`. Appends `expiryheight` — **before** the slippage, even
/// though this is the higher bit. Field order is not flag order.
pub const FLAG_EXPIRES: u64 = 8;
/// `VERUSPAY_ACCEPTS_ANY_DESTINATION`. Suppresses the destination field.
pub const FLAG_ACCEPTS_ANY_DESTINATION: u64 = 16;
/// `VERUSPAY_ACCEPTS_ANY_AMOUNT`. Suppresses the amount field.
pub const FLAG_ACCEPTS_ANY_AMOUNT: u64 = 32;
/// `VERUSPAY_EXCLUDES_VERUS_BLOCKCHAIN`. Gates no field.
pub const FLAG_EXCLUDES_VERUS_BLOCKCHAIN: u64 = 64;
/// `VERUSPAY_IS_TESTNET`. Gates no field.
pub const FLAG_IS_TESTNET: u64 = 128;
/// `VERUSPAY_IS_PRECONVERT`. Gates no field. **v4 only** — `setFlags` silently
/// drops it on v3.
pub const FLAG_IS_PRECONVERT: u64 = 256;
/// `VERUSPAY_DESTINATION_IS_SAPLING_PAYMENT_ADDRESS`. Swaps the destination
/// field's shape. **v4 only.**
pub const FLAG_DESTINATION_IS_SAPLING_PAYMENT_ADDRESS: u64 = 512;
/// `VERUSPAY_IS_TAGGED`. Appends a `CompactXAddressObject`. **v4 only**, and
/// **not implemented here** — see [`VerusPayInvoiceDetails::deserialize`].
pub const FLAG_IS_TAGGED: u64 = 1024;

/// `VERUSPAY_VERSION_SIGNED`, which is also `VERUSPAY_VERSION_MASK`.
///
/// The bit `setSigned()` ORs into the version. Exposed because a caller reading
/// a raw [`VdxfObject::version`] off the wire needs it to mask, and inventing
/// the constant a second time is how the mask gets forgotten.
pub const VERSION_SIGNED_BIT: u64 = 0x8000_0000;

/// Every flag bit this module knows how to write or read.
const KNOWN_FLAGS: u64 = FLAG_VALID
    | FLAG_ACCEPTS_CONVERSION
    | FLAG_ACCEPTS_NON_VERUS_SYSTEMS
    | FLAG_EXPIRES
    | FLAG_ACCEPTS_ANY_DESTINATION
    | FLAG_ACCEPTS_ANY_AMOUNT
    | FLAG_EXCLUDES_VERUS_BLOCKCHAIN
    | FLAG_IS_TESTNET
    | FLAG_IS_PRECONVERT
    | FLAG_DESTINATION_IS_SAPLING_PAYMENT_ADDRESS
    | FLAG_IS_TAGGED;

/// The bits `setFlags` refuses to set below v4.
const V4_ONLY_FLAGS: u64 =
    FLAG_IS_PRECONVERT | FLAG_DESTINATION_IS_SAPLING_PAYMENT_ADDRESS | FLAG_IS_TAGGED;

/// A raw Sapling payment address is eleven bytes of diversifier and thirty-two
/// of `pk_d`.
const SAPLING_ADDRESS_LEN: usize = 43;

fn bad(detail: &str) -> TxError {
    TxError::MalformedVdxfObject(detail.to_string())
}

/// Which invoice version, and therefore which integer encoding.
///
/// The version changes the *encoding* rather than the fields: v3 writes its
/// variable-length integers as Satoshi VARINTs (seven bits a byte, MSB
/// continuation) and v4 as Bitcoin CompactSizes. The same logical invoice is a
/// different byte string under each wherever a value reaches `0x80`, which is
/// why every serialization entry point here is told which one to use rather than
/// assuming.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerusPayVersion {
    /// `VERUSPAY_VERSION_3`. Variable-length integers are Satoshi VARINTs.
    V3,
    /// `VERUSPAY_VERSION_4`. Variable-length integers are CompactSizes, and the
    /// preconvert, Sapling-destination and tagged flags become available.
    V4,
}

impl VerusPayVersion {
    /// `VERUSPAY_VERSION_CURRENT`: what a new invoice is written as.
    pub const CURRENT: Self = Self::V4;

    /// The number this version is on the wire, without the signed bit.
    pub fn number(self) -> u64 {
        match self {
            Self::V3 => 3,
            Self::V4 => 4,
        }
    }

    /// The version a number names, **with the signed bit already masked off**.
    ///
    /// # Errors
    ///
    /// Anything outside
    /// `VERUSPAY_VERSION_FIRSTVALID..=VERUSPAY_VERSION_LASTVALID`. Pass a raw
    /// frame version here and a signed invoice is rejected as version
    /// 2147483652 — [`VerusPayInvoice::from_vdxf_object`] does the masking, and
    /// is the way in.
    pub fn from_number(number: u64) -> Result<Self, TxError> {
        match number {
            3 => Ok(Self::V3),
            4 => Ok(Self::V4),
            other => Err(bad(&format!(
                "VerusPay invoice version {other} is outside the supported range 3..=4 \
                 (a signed invoice's version carries {VERSION_SIGNED_BIT:#x} and must be \
                 masked off first)"
            ))),
        }
    }

    /// Whether the v4-only flags are available. `isGTEV4()`.
    fn is_gte_v4(self) -> bool {
        self >= Self::V4
    }

    /// `writeVarUInt`: a VARINT on v3, a CompactSize on v4.
    fn write_var_uint(self, out: &mut Vec<u8>, value: u64) {
        if self.is_gte_v4() {
            write_compact_size(out, value);
        } else {
            out.extend_from_slice(&var_int(value));
        }
    }

    /// `getVarUIntEncodingLength`.
    fn var_uint_length(self, value: u64) -> usize {
        if self.is_gte_v4() {
            compact_size_length(value)
        } else {
            var_int(value).len()
        }
    }

    /// `readVarUInt`.
    fn read_var_uint(self, bytes: &[u8], offset: &mut usize) -> Result<u64, TxError> {
        if self.is_gte_v4() {
            read_compact_size(bytes, offset)
        } else {
            read_var_int(bytes, offset)
        }
    }
}

/// How much an invoice asks for.
///
/// Not an `Option<u64>`, because the two cases are not "a value or nothing":
/// `Any` sets `VERUSPAY_ACCEPTS_ANY_AMOUNT` and the amount is then **absent
/// from the wire entirely**, which is a different byte string from an amount of
/// zero and a different thing to show a user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestedAmount {
    /// Exactly this many of the smallest unit of the requested currency.
    ///
    /// Satoshis — an integer, never a float. One hundred coins is
    /// `Exact(10_000_000_000)`, which is already past the range an `f64`
    /// represents exactly once a few more digits arrive.
    Exact(u64),
    /// Whatever the payer decides to send.
    Any,
}

/// A raw Sapling payment address, as an invoice carries it.
///
/// Forty-three bytes — eleven of diversifier, thirty-two of `pk_d` — written
/// **raw**: no type byte and no length prefix, unlike the
/// [`TransferDestination`] that occupies the same field position otherwise.
///
/// Kept as bytes rather than as a `zs…` string because the bech32 codec lives in
/// `verus-sapling`, and this crate does not depend on the shielded stack to read
/// a payment request. `verus_sapling::zaddr::{encode, decode}` is the pair that
/// converts, and both crates agree that a raw address is these forty-three
/// bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SaplingDestination([u8; SAPLING_ADDRESS_LEN]);

impl SaplingDestination {
    /// From the raw forty-three bytes.
    pub const fn from_bytes(bytes: [u8; SAPLING_ADDRESS_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw forty-three bytes, ready for `verus_sapling::zaddr::encode`.
    pub const fn to_bytes(self) -> [u8; SAPLING_ADDRESS_LEN] {
        self.0
    }

    /// The eleven-byte diversifier.
    pub fn diversifier(&self) -> &[u8; 11] {
        self.0[..11].try_into().expect("the first eleven of 43")
    }

    /// The thirty-two-byte `pk_d`.
    pub fn pk_d(&self) -> &[u8; 32] {
        self.0[11..].try_into().expect("the last thirty-two of 43")
    }
}

/// Where an invoice asks to be paid.
///
/// The three cases are three different byte layouts in one field position, and
/// which one is on the wire is decided by the flag word rather than by anything
/// self-describing in the bytes — so this enum is the flag, not a companion to
/// it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvoiceDestination {
    /// A transparent destination: a `CTransferDestination`, the same structure a
    /// reserve transfer carries.
    Transparent(TransferDestination),
    /// A shielded destination. Sets
    /// `VERUSPAY_DESTINATION_IS_SAPLING_PAYMENT_ADDRESS`, and is **v4 only** —
    /// serializing one under v3 is refused rather than silently written as a
    /// transparent destination.
    Sapling(SaplingDestination),
    /// The payer's own address. Sets `VERUSPAY_ACCEPTS_ANY_DESTINATION`, and the
    /// destination is then absent from the wire.
    Any,
}

impl InvoiceDestination {
    /// The address the primary recipient is spelled as, where there is one.
    ///
    /// # Why this is not ambiguous, when upstream's `Hash160` is
    ///
    /// A twenty-byte hash on the wire does not say which base58 version byte it
    /// renders under — upstream's `Hash160.fromBuffer` hardcodes the `i` version
    /// and each payload type re-stamps it afterwards. Here the field layout
    /// settles it with no re-stamping needed: a transparent destination carries
    /// a **type byte**, and [`Destination`] preserves it, so a key hash comes
    /// back as `Destination::PubKeyHash` and renders as an `R` address while an
    /// identity renders as an `i` address. There is nothing to guess.
    ///
    /// `None` for [`InvoiceDestination::Any`] (there is no destination), for
    /// [`InvoiceDestination::Sapling`] (which is a `zs…` address and not a
    /// base58 one — use [`SaplingDestination::to_bytes`] with
    /// `verus_sapling::zaddr::encode`), and for a raw-public-key recipient,
    /// which names no address of its own.
    pub fn recipient_address(&self) -> Option<Address> {
        let Self::Transparent(destination) = self else {
            return None;
        };
        match &destination.recipient {
            Destination::PubKeyHash(hash) => Some(Address::new(AddressKind::PubKeyHash, *hash)),
            Destination::ScriptHash(hash) => Some(Address::new(AddressKind::ScriptHash, *hash)),
            Destination::Identity(hash) => Some(Address::new(AddressKind::Identity, *hash)),
            Destination::PubKey(_) => None,
        }
    }
}

/// What is being asked for: the invoice's payload.
///
/// `VerusPayInvoiceDetails`. Every optional field is optional *on the wire* as
/// well — the flag word that gates it is computed from this structure by
/// [`VerusPayInvoiceDetails::flags`] rather than stored beside it, so a flag can
/// never disagree with the data it describes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerusPayInvoiceDetails {
    /// How much, in the smallest unit of [`Self::requested_currency`].
    pub amount: RequestedAmount,
    /// Where the value is to be delivered.
    pub destination: InvoiceDestination,
    /// The currency being asked for.
    pub requested_currency: CurrencyId,
    /// The block height past which this invoice is no longer valid.
    ///
    /// `Some` sets `VERUSPAY_EXPIRES`. Checking it is the payer's job and needs
    /// a chain height; nothing in this crate can do it.
    pub expiry_height: Option<u64>,
    /// The worst conversion slippage the merchant will accept, in satoshis.
    ///
    /// `Some` sets `VERUSPAY_ACCEPTS_CONVERSION`, which is what says the payer
    /// may pay in a currency other than the one requested.
    pub max_estimated_slippage: Option<u64>,
    /// Systems other than Verus this invoice may be paid from, **in order**.
    ///
    /// Non-empty sets `VERUSPAY_ACCEPTS_NON_VERUS_SYSTEMS`. A `Vec` and not a
    /// set: the order is on the wire, so re-sorting it changes the bytes.
    pub accepted_systems: Vec<CurrencyId>,
    /// `VERUSPAY_EXCLUDES_VERUS_BLOCKCHAIN`. Gates no field.
    pub excludes_verus_blockchain: bool,
    /// `VERUSPAY_IS_TESTNET`. Gates no field, and nothing checks it against the
    /// chain the payer is on — it is the merchant's claim about which network
    /// this invoice is for.
    pub is_testnet: bool,
    /// `VERUSPAY_IS_PRECONVERT`: the payment is a contribution to a currency
    /// launch rather than a conversion. Gates no field, and is **v4 only**.
    pub is_preconvert: bool,
}

impl VerusPayInvoiceDetails {
    /// The simplest invoice there is: this much of this currency, to here.
    ///
    /// Everything else off. Named rather than left to a struct literal because
    /// there are nine fields and six of them are "no" for the common case.
    pub fn new(
        amount: RequestedAmount,
        destination: InvoiceDestination,
        requested_currency: CurrencyId,
    ) -> Self {
        Self {
            amount,
            destination,
            requested_currency,
            expiry_height: None,
            max_estimated_slippage: None,
            accepted_systems: Vec::new(),
            excludes_verus_blockchain: false,
            is_testnet: false,
            is_preconvert: false,
        }
    }

    /// The flag word these details serialize under.
    ///
    /// Derived, never stored. `VERUSPAY_VALID` is always set — upstream's
    /// constructor starts the word at 1 and never clears it — and the v4-only
    /// bits are reported only for v4, matching `isPreconvert()` and friends,
    /// which are all `isGTEV4() && bit`.
    ///
    /// # Errors
    ///
    /// A v4-only property asked for under v3. `setFlags` drops those silently;
    /// dropping them here would mean writing an invoice that says something
    /// other than what the caller asked for, and for the Sapling case it would
    /// mean writing a shielded address into a field a reader parses as a
    /// transparent one.
    pub fn flags(&self, version: VerusPayVersion) -> Result<u64, TxError> {
        let mut flags = FLAG_VALID;
        if self.max_estimated_slippage.is_some() {
            flags |= FLAG_ACCEPTS_CONVERSION;
        }
        if !self.accepted_systems.is_empty() {
            flags |= FLAG_ACCEPTS_NON_VERUS_SYSTEMS;
        }
        if self.expiry_height.is_some() {
            flags |= FLAG_EXPIRES;
        }
        if matches!(self.destination, InvoiceDestination::Any) {
            flags |= FLAG_ACCEPTS_ANY_DESTINATION;
        }
        if matches!(self.amount, RequestedAmount::Any) {
            flags |= FLAG_ACCEPTS_ANY_AMOUNT;
        }
        if self.excludes_verus_blockchain {
            flags |= FLAG_EXCLUDES_VERUS_BLOCKCHAIN;
        }
        if self.is_testnet {
            flags |= FLAG_IS_TESTNET;
        }
        if self.is_preconvert {
            flags |= FLAG_IS_PRECONVERT;
        }
        if matches!(self.destination, InvoiceDestination::Sapling(_)) {
            flags |= FLAG_DESTINATION_IS_SAPLING_PAYMENT_ADDRESS;
        }
        if !version.is_gte_v4() && flags & V4_ONLY_FLAGS != 0 {
            return Err(bad(&format!(
                "a v{} invoice cannot carry the v4-only flags {:#x}; \
                 upstream's setFlags drops them silently and this refuses instead",
                version.number(),
                flags & V4_ONLY_FLAGS
            )));
        }
        Ok(flags)
    }

    /// How many bytes [`Self::serialize`] writes. `getByteLength()`.
    ///
    /// # Errors
    ///
    /// Everything [`Self::flags`] refuses, plus a transparent destination this
    /// crate cannot encode.
    pub fn byte_length(&self, version: VerusPayVersion) -> Result<usize, TxError> {
        let flags = self.flags(version)?;
        let mut length = version.var_uint_length(flags);
        if let RequestedAmount::Exact(amount) = self.amount {
            length += version.var_uint_length(amount);
        }
        match &self.destination {
            InvoiceDestination::Transparent(destination) => {
                length += destination.serialize()?.len();
            }
            InvoiceDestination::Sapling(_) => length += SAPLING_ADDRESS_LEN,
            InvoiceDestination::Any => {}
        }
        length += 20;
        if let Some(height) = self.expiry_height {
            length += version.var_uint_length(height);
        }
        if let Some(slippage) = self.max_estimated_slippage {
            length += version.var_uint_length(slippage);
        }
        if !self.accepted_systems.is_empty() {
            length += compact_size_length(self.accepted_systems.len() as u64);
            length += 20 * self.accepted_systems.len();
        }
        Ok(length)
    }

    /// The bytes these details occupy. `toBuffer()`.
    ///
    /// Field order is **not** flag order: the expiry height is written before
    /// the slippage even though `VERUSPAY_EXPIRES` (8) is the higher bit.
    ///
    /// # Errors
    ///
    /// Everything [`Self::flags`] refuses, plus a transparent destination this
    /// crate cannot encode.
    pub fn serialize(&self, version: VerusPayVersion) -> Result<Vec<u8>, TxError> {
        let flags = self.flags(version)?;
        let mut out = Vec::with_capacity(self.byte_length(version)?);

        version.write_var_uint(&mut out, flags);

        // Suppressed, not zeroed: the field is absent when the flag is set.
        if let RequestedAmount::Exact(amount) = self.amount {
            version.write_var_uint(&mut out, amount);
        }
        match &self.destination {
            InvoiceDestination::Transparent(destination) => {
                out.extend_from_slice(&destination.serialize()?);
            }
            InvoiceDestination::Sapling(sapling) => out.extend_from_slice(&sapling.0),
            InvoiceDestination::Any => {}
        }

        out.extend_from_slice(&self.requested_currency.to_bytes());

        if let Some(height) = self.expiry_height {
            version.write_var_uint(&mut out, height);
        }
        if let Some(slippage) = self.max_estimated_slippage {
            version.write_var_uint(&mut out, slippage);
        }
        if !self.accepted_systems.is_empty() {
            write_compact_size(&mut out, self.accepted_systems.len() as u64);
            for system in &self.accepted_systems {
                out.extend_from_slice(&system.to_bytes());
            }
        }
        Ok(out)
    }

    /// `sha256(toBuffer())`. `toSha256()`, and the details hash of an *unsigned*
    /// invoice.
    ///
    /// # Errors
    ///
    /// Everything [`Self::serialize`] refuses.
    pub fn sha256(&self, version: VerusPayVersion) -> Result<[u8; 32], TxError> {
        Ok(sha256(&self.serialize(version)?))
    }

    /// Read details back, advancing `offset`. `fromBuffer()`.
    ///
    /// # Errors
    ///
    /// A buffer that ends early, a non-canonical CompactSize, a flag word with a
    /// bit this module does not know, an invoice whose `VERUSPAY_VALID` bit is
    /// clear, a v3 invoice carrying v4-only flags, an invoice naming two
    /// destinations at once, and a tagged invoice.
    ///
    /// # Why an unknown flag is refused rather than carried
    ///
    /// The flag word is not stored on this type — it is recomputed from the
    /// fields by [`Self::flags`]. A bit this module did not set would therefore
    /// be dropped on the way back out, and an invoice that re-serializes to
    /// different bytes than it arrived as is an invoice whose signature no
    /// longer covers it. Refusing keeps "what was read writes back identically"
    /// true for everything this type accepts, which
    /// `never_panics_on_bytes_a_stranger_chose` asserts as a property rather
    /// than only on the fixtures.
    ///
    /// # `isTagged` is refused, not ignored
    ///
    /// `VERUSPAY_IS_TAGGED` appends a `CompactXAddressObject`, and an
    /// x-address has no `verus_keys::AddressKind` variant to become — widening
    /// that public enum is a decision of its own rather than a side effect of
    /// this port. The bytes after the tag cannot be skipped without parsing it,
    /// so a tagged invoice is a typed error here rather than a partial answer.
    /// [`FLAG_IS_TAGGED`] stays public so a caller can recognise one.
    pub fn deserialize(
        bytes: &[u8],
        offset: &mut usize,
        version: VerusPayVersion,
    ) -> Result<Self, TxError> {
        let flags = version.read_var_uint(bytes, offset)?;
        if flags & !KNOWN_FLAGS != 0 {
            return Err(bad(&format!(
                "a VerusPay invoice's flags {flags:#x} carry {:#x}, which is not a flag this \
                 crate knows",
                flags & !KNOWN_FLAGS
            )));
        }
        if flags & FLAG_VALID == 0 {
            return Err(bad(
                "a VerusPay invoice's flags do not carry VERUSPAY_VALID",
            ));
        }
        if !version.is_gte_v4() && flags & V4_ONLY_FLAGS != 0 {
            return Err(bad(&format!(
                "a v{} invoice carries the v4-only flags {:#x}, which upstream reads as unset \
                 while still writing them back",
                version.number(),
                flags & V4_ONLY_FLAGS
            )));
        }
        // Both destination flags at once. Upstream reads this as "any
        // destination" and ignores the Sapling bit — but it keeps the word and
        // writes it back, and this type does not keep it, so the invoice would
        // come back one bit lighter and a signature over it would stop
        // verifying. Refused for the same reason an unknown bit is.
        if flags & FLAG_ACCEPTS_ANY_DESTINATION != 0
            && flags & FLAG_DESTINATION_IS_SAPLING_PAYMENT_ADDRESS != 0
        {
            return Err(bad(
                "a VerusPay invoice sets both VERUSPAY_ACCEPTS_ANY_DESTINATION and \
                 VERUSPAY_DESTINATION_IS_SAPLING_PAYMENT_ADDRESS, which name two different \
                 destinations",
            ));
        }
        if flags & FLAG_IS_TAGGED != 0 {
            return Err(bad(
                "a tagged VerusPay invoice carries an x-address, which this crate does not model",
            ));
        }

        let amount = if flags & FLAG_ACCEPTS_ANY_AMOUNT != 0 {
            RequestedAmount::Any
        } else {
            RequestedAmount::Exact(version.read_var_uint(bytes, offset)?)
        };

        let destination = if flags & FLAG_ACCEPTS_ANY_DESTINATION != 0 {
            InvoiceDestination::Any
        } else if flags & FLAG_DESTINATION_IS_SAPLING_PAYMENT_ADDRESS != 0 {
            let raw: [u8; SAPLING_ADDRESS_LEN] = bytes
                .get(*offset..*offset + SAPLING_ADDRESS_LEN)
                .and_then(|slice| slice.try_into().ok())
                .ok_or_else(|| bad("an invoice ended before its Sapling destination"))?;
            *offset += SAPLING_ADDRESS_LEN;
            InvoiceDestination::Sapling(SaplingDestination(raw))
        } else {
            InvoiceDestination::Transparent(TransferDestination::deserialize(bytes, offset)?)
        };

        let requested_currency = read_currency(bytes, offset, "requested currency")?;

        let expiry_height = if flags & FLAG_EXPIRES != 0 {
            Some(version.read_var_uint(bytes, offset)?)
        } else {
            None
        };
        let max_estimated_slippage = if flags & FLAG_ACCEPTS_CONVERSION != 0 {
            Some(version.read_var_uint(bytes, offset)?)
        } else {
            None
        };

        let mut accepted_systems = Vec::new();
        if flags & FLAG_ACCEPTS_NON_VERUS_SYSTEMS != 0 {
            let count = read_compact_size(bytes, offset)?;
            // Bounded by what is actually left, so nothing is allocated on a
            // count a stranger chose.
            let remaining = bytes.len().saturating_sub(*offset);
            let count = usize::try_from(count)
                .ok()
                .filter(|count| count.saturating_mul(20) <= remaining)
                .ok_or_else(|| {
                    bad("an invoice claims more accepted systems than its bytes can hold")
                })?;
            accepted_systems.reserve_exact(count);
            for _ in 0..count {
                accepted_systems.push(read_currency(bytes, offset, "accepted system")?);
            }
            // The flag says the array is present; an empty one would come back
            // with the flag cleared and re-serialize a byte shorter. Refused for
            // the same reason an unknown bit is.
            if accepted_systems.is_empty() {
                return Err(bad(
                    "an invoice sets VERUSPAY_ACCEPTS_NON_VERUS_SYSTEMS and lists no systems",
                ));
            }
        }

        Ok(Self {
            amount,
            destination,
            requested_currency,
            expiry_height,
            max_estimated_slippage,
            accepted_systems,
            excludes_verus_blockchain: flags & FLAG_EXCLUDES_VERUS_BLOCKCHAIN != 0,
            is_testnet: flags & FLAG_IS_TESTNET != 0,
            is_preconvert: flags & FLAG_IS_PRECONVERT != 0,
        })
    }
}

/// Twenty raw bytes as a currency id, which is how every id inside an invoice's
/// details is written.
fn read_currency(bytes: &[u8], offset: &mut usize, what: &str) -> Result<CurrencyId, TxError> {
    let raw: [u8; 20] = bytes
        .get(*offset..*offset + 20)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| bad(&format!("an invoice ended before its {what} id")))?;
    *offset += 20;
    Ok(CurrencyId::from_bytes(raw))
}

/// Which arrangement of the signed details hash to compute.
///
/// The two are different hashes of the same invoice, and both are reachable from
/// a wallet: version 1 puts the Verus data-signature prefix first, version 2
/// puts it after the signing id. A verifier that tries only the default cannot
/// check an older signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureVersion {
    /// Prefix, system id, height, signing id, details hash.
    V1,
    /// System id, height, signing id, prefix, details hash. The default
    /// upstream.
    V2,
}

/// The signature a VerusPay invoice carries, and who made it.
///
/// Present only on a signed invoice, which is the whole reason
/// [`VerusPayInvoice::signature`] is an `Option` and not a bool beside a
/// possibly-empty buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvoiceSignature {
    /// The system the signature was made on — the chain whose height the
    /// signature counts against.
    pub system_id: CurrencyId,
    /// The identity that signed. An `i` address.
    pub signing_id: CurrencyId,
    /// The `CIdentitySignature`, as bytes.
    ///
    /// Opaque here on purpose: parsing it is
    /// `verus_tx_identity::signature::IdentitySignature::from_bytes`, and
    /// *verifying* it needs that identity as it stood at the signature's own
    /// height, which needs a node. Upstream carries the same bytes as standard
    /// base64 — the padded `+/` alphabet, which is **not** the `base64url` a
    /// deeplink uses.
    pub signature: Vec<u8>,
}

impl InvoiceSignature {
    /// The bytes this occupies at the head of a signed invoice's payload:
    /// two raw [`Hash160`]s and the signature as a nested [`VdxfObject`]
    /// **without its key**.
    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.byte_length());
        out.extend_from_slice(&Hash160::of(self.system_id.to_bytes(), false).serialize());
        out.extend_from_slice(&Hash160::of(self.signing_id.to_bytes(), false).serialize());
        out.extend_from_slice(&self.signature_object().serialize(false));
        out
    }

    /// `getByteLength()` for the same three fields.
    fn byte_length(&self) -> usize {
        20 + 20 + self.signature_object().byte_length(false)
    }

    /// The nested object the signature rides in.
    ///
    /// Its key is `IDENTITY_AUTH_SIG_VDXF_KEY` and is **not serialized** — a
    /// signed invoice constructs its `VerusIDSignature` with
    /// `serializekey = false`, where a login-consent or provisioning message
    /// constructs the identical object with it `true`. The key is carried here
    /// anyway so the object is well formed and so the asymmetry is visible at
    /// the one place it matters.
    fn signature_object(&self) -> VdxfObject {
        VdxfObject::new(
            keys::IDENTITY_AUTH_SIG_VDXF_KEY,
            DEFAULT_VERSION,
            self.signature.clone(),
        )
    }

    /// Read the signed prefix back, advancing `offset`.
    fn deserialize(bytes: &[u8], offset: &mut usize) -> Result<Self, TxError> {
        let system_id = read_currency(bytes, offset, "signature system")?;
        let signing_id = read_currency(bytes, offset, "signing identity")?;
        // `Some(key)` because an invoice's signature object does not carry one.
        // Passing `None` here would read the version out of the middle of the
        // signature.
        let object =
            VdxfObject::deserialize(bytes, offset, Some(keys::IDENTITY_AUTH_SIG_VDXF_KEY))?;
        if object.version() != DEFAULT_VERSION {
            return Err(bad(&format!(
                "an invoice's signature object is version {} and not the {DEFAULT_VERSION} \
                 every VerusIDSignature is written as",
                object.version()
            )));
        }
        Ok(Self {
            system_id,
            signing_id,
            signature: object.data().to_vec(),
        })
    }
}

/// A VerusPay invoice: what is being asked for, and optionally who vouches for
/// it.
///
/// `VerusPayInvoice`. Construct one with [`VerusPayInvoice::unsigned`] or
/// [`VerusPayInvoice::signed`] — which of the two is on the wire is a *version
/// bit*, so it is not a field a caller sets and cannot be set inconsistently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerusPayInvoice {
    version: VerusPayVersion,
    signature: Option<InvoiceSignature>,
    details: VerusPayInvoiceDetails,
}

impl VerusPayInvoice {
    /// An invoice nobody has vouched for.
    ///
    /// Accepted by Verus Mobile and displayed as unverified, which is the
    /// behaviour this SDK must not be looser than. A caller that renders this
    /// the same as a signed one is telling a user something untrue, which is why
    /// [`Self::signature`] is on the type rather than discovered later.
    pub fn unsigned(version: VerusPayVersion, details: VerusPayInvoiceDetails) -> Self {
        Self {
            version,
            signature: None,
            details,
        }
    }

    /// An invoice carrying an identity's signature over its details.
    ///
    /// Carrying one is not the same as it being **valid** — see the module docs.
    pub fn signed(
        version: VerusPayVersion,
        details: VerusPayInvoiceDetails,
        signature: InvoiceSignature,
    ) -> Self {
        Self {
            version,
            signature: Some(signature),
            details,
        }
    }

    /// Which invoice version this is — with no signed bit in it, ever.
    pub fn version(&self) -> VerusPayVersion {
        self.version
    }

    /// What is being asked for.
    pub fn details(&self) -> &VerusPayInvoiceDetails {
        &self.details
    }

    /// Who signed, and with what — `None` when nobody did.
    pub fn signature(&self) -> Option<&InvoiceSignature> {
        self.signature.as_ref()
    }

    /// Whether this invoice carries a signature at all. `isSigned()`.
    ///
    /// **Not** whether the signature is good. See the module docs.
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// The number that goes in the frame's version field: the invoice version
    /// with [`VERSION_SIGNED_BIT`] ORed in when signed.
    ///
    /// `2147483651` and `2147483652` are the two signed spellings, and they are
    /// the reason [`VerusPayVersion::from_number`] insists on a masked value.
    pub fn serialized_version(&self) -> u64 {
        let mut version = self.version.number();
        if self.is_signed() {
            version |= VERSION_SIGNED_BIT;
        }
        version
    }

    /// The payload bytes: the signed prefix, when there is one, then the
    /// details. `toDataBuffer()`.
    ///
    /// # Errors
    ///
    /// Everything [`VerusPayInvoiceDetails::serialize`] refuses.
    pub fn to_data_buffer(&self) -> Result<Vec<u8>, TxError> {
        let mut out = Vec::with_capacity(self.data_byte_length()?);
        if let Some(signature) = &self.signature {
            out.extend_from_slice(&signature.serialize());
        }
        out.extend_from_slice(&self.details.serialize(self.version)?);
        Ok(out)
    }

    /// How long [`Self::to_data_buffer`] is. `dataByteLength()`.
    ///
    /// # Errors
    ///
    /// Everything [`VerusPayInvoiceDetails::byte_length`] refuses.
    pub fn data_byte_length(&self) -> Result<usize, TxError> {
        let signed = self
            .signature
            .as_ref()
            .map_or(0, InvoiceSignature::byte_length);
        Ok(signed + self.details.byte_length(self.version)?)
    }

    /// This invoice in the VDXF frame it travels in.
    ///
    /// The key is always [`keys::VERUSPAY_INVOICE_VDXF_KEY`]; there is no way to
    /// address an invoice as something else.
    ///
    /// # Errors
    ///
    /// Everything [`Self::to_data_buffer`] refuses.
    pub fn to_vdxf_object(&self) -> Result<VdxfObject, TxError> {
        Ok(VdxfObject::new(
            keys::VERUSPAY_INVOICE_VDXF_KEY,
            self.serialized_version(),
            self.to_data_buffer()?,
        ))
    }

    /// Read an invoice out of its frame.
    ///
    /// # Errors
    ///
    /// A frame addressed by a key that is not the invoice key, a version outside
    /// 3..=4 once the signed bit is masked off, and everything
    /// [`VerusPayInvoiceDetails::deserialize`] refuses — plus trailing bytes,
    /// because an invoice is the whole payload and anything left over means this
    /// is not the object it claims to be.
    pub fn from_vdxf_object(object: &VdxfObject) -> Result<Self, TxError> {
        if object.key() != keys::VERUSPAY_INVOICE_VDXF_KEY {
            return Err(bad(&format!(
                "a VerusPay invoice is addressed by {}, and this object is addressed by {}",
                Address::new(AddressKind::Identity, keys::VERUSPAY_INVOICE_VDXF_KEY),
                object.key_address()
            )));
        }
        // Mask first. Comparing the raw version to 4 rejects every signed
        // invoice there is.
        let raw = object.version();
        let version = VerusPayVersion::from_number(raw & !VERSION_SIGNED_BIT)?;
        let is_signed = raw & VERSION_SIGNED_BIT != 0;

        let data = object.data();
        let mut offset = 0;
        let signature = if is_signed {
            Some(InvoiceSignature::deserialize(data, &mut offset)?)
        } else {
            None
        };
        let details = VerusPayInvoiceDetails::deserialize(data, &mut offset, version)?;
        if offset != data.len() {
            return Err(bad(&format!(
                "{} trailing bytes after a VerusPay invoice's details",
                data.len() - offset
            )));
        }
        Ok(Self {
            version,
            signature,
            details,
        })
    }

    /// The hash a signature over this invoice covers. `getDetailsHash()`.
    ///
    /// For an **unsigned** invoice this is just `sha256(details)` and neither
    /// argument is used — which is upstream's behaviour, and is why this returns
    /// a hash rather than refusing: `getDetailsHash` is also how an unsigned
    /// invoice is identified.
    ///
    /// For a **signed** one it commits to the system, the height and the signing
    /// identity as well, so a signature cannot be replayed onto another chain or
    /// another identity. `signed_block_height` is the height the signature was
    /// made at, which the `CIdentitySignature` inside
    /// [`InvoiceSignature::signature`] carries.
    ///
    /// # Errors
    ///
    /// Everything [`VerusPayInvoiceDetails::serialize`] refuses.
    pub fn details_hash(
        &self,
        signed_block_height: u32,
        signature_version: SignatureVersion,
    ) -> Result<[u8; 32], TxError> {
        let details = self.details.sha256(self.version)?;
        let Some(signature) = &self.signature else {
            return Ok(details);
        };
        let height = signed_block_height.to_le_bytes();
        let mut preimage = Vec::with_capacity(SIGNATURE_PREFIX.len() + 76);
        match signature_version {
            SignatureVersion::V1 => {
                preimage.extend_from_slice(SIGNATURE_PREFIX);
                preimage.extend_from_slice(&signature.system_id.to_bytes());
                preimage.extend_from_slice(&height);
                preimage.extend_from_slice(&signature.signing_id.to_bytes());
            }
            SignatureVersion::V2 => {
                preimage.extend_from_slice(&signature.system_id.to_bytes());
                preimage.extend_from_slice(&height);
                preimage.extend_from_slice(&signature.signing_id.to_bytes());
                preimage.extend_from_slice(SIGNATURE_PREFIX);
            }
        }
        preimage.extend_from_slice(&details);
        Ok(sha256(&preimage))
    }

    /// The text a QR code carries: the whole frame, key included, as base64url.
    ///
    /// `toQrString()`.
    ///
    /// # Errors
    ///
    /// Everything [`Self::to_vdxf_object`] refuses.
    pub fn to_qr_string(&self) -> Result<String, TxError> {
        Ok(self.to_vdxf_object()?.to_base64url(true))
    }

    /// Read an invoice out of a scanned QR code.
    ///
    /// # Errors
    ///
    /// Everything [`crate::base64url::decode`], [`VdxfObject::from_base64url`]
    /// and [`Self::from_vdxf_object`] refuse.
    pub fn from_qr_string(text: &str) -> Result<Self, TxError> {
        Self::from_vdxf_object(&VdxfObject::from_base64url(text, None)?)
    }

    /// The deeplink a wallet is handed.
    ///
    /// `toWalletDeeplinkUri()`:
    ///
    /// ```text
    /// i5jtwbp6zymeay9llnraglgjqgdrffsau4://x-callback-url/iEETy7La3FTN2Sd2hNRgepek5S8x8eeUeQ/<base64url>
    /// ```
    ///
    /// The scheme is [`wallet_deeplink_scheme`] and is not a parameter — see the
    /// module docs for why `verus://` here is a link no wallet will open. The
    /// payload is a **path segment**, and it omits the twenty-byte key because
    /// the path already names it.
    ///
    /// Nothing is percent-encoded, because upstream percent-encodes nothing and
    /// a wallet matching on the literal path would not find an encoded one.
    /// base64url's alphabet is URI-safe as it stands, which is what makes that
    /// safe rather than merely compatible.
    ///
    /// # Errors
    ///
    /// Everything [`Self::to_vdxf_object`] refuses.
    pub fn to_wallet_deeplink_uri(&self) -> Result<String, TxError> {
        let payload = self.to_vdxf_object()?.to_base64url(false);
        Ok(format!(
            "{}://x-callback-url/{}/{payload}",
            wallet_deeplink_scheme(),
            Address::new(AddressKind::Identity, keys::VERUSPAY_INVOICE_VDXF_KEY),
        ))
    }

    /// Read an invoice out of a deeplink.
    ///
    /// # Errors
    ///
    /// A URI whose scheme, `x-callback-url` host or invoice-key path segment is
    /// not the one [`Self::to_wallet_deeplink_uri`] writes — upstream splits on
    /// the key and takes whatever follows, which accepts `verus://…` and worse;
    /// this insists on the whole prefix, because a link that a real wallet would
    /// refuse must not parse here into something a caller then displays. Plus
    /// everything [`Self::from_qr_string`] refuses.
    pub fn from_wallet_deeplink_uri(uri: &str) -> Result<Self, TxError> {
        let prefix = format!(
            "{}://x-callback-url/{}/",
            wallet_deeplink_scheme(),
            Address::new(AddressKind::Identity, keys::VERUSPAY_INVOICE_VDXF_KEY),
        );
        let payload = uri.strip_prefix(&prefix).ok_or_else(|| {
            bad(&format!(
                "a VerusPay deeplink begins {prefix:?}; this one does not"
            ))
        })?;
        // The payload is the last path segment and the whole of it. `base64url`
        // refuses every character that could start another segment, a query or
        // a fragment, so anything after the invoice is a rejection rather than
        // two URIs decoding to one invoice.
        let object = VdxfObject::from_base64url(payload, Some(keys::VERUSPAY_INVOICE_VDXF_KEY))?;
        Self::from_vdxf_object(&object)
    }
}

/// `VERUS_DATA_SIGNATURE_PREFIX`: the domain separator, length-prefixed.
///
/// `compactSize(19) ‖ "Verus signed data:\n"`. The same nineteen bytes
/// `verus_tx_identity::signature::SIGNATURE_PREFIX` holds, written here with the
/// CompactSize upstream bakes into the constant.
const SIGNATURE_PREFIX: &[u8] = b"\x13Verus signed data:\n";

/// The URI scheme a VerusPay deeplink travels under.
///
/// The lowercased vdxfid of `vrsc::applications.wallet`,
/// `i5jtwbp6zymeay9llnraglgjqgdrffsau4`. Derived from
/// [`keys::WALLET_VDXF_KEY`] rather than written down, so there is one place it
/// can be wrong.
///
/// Exposed for the one thing a caller legitimately needs it for: registering the
/// scheme with an operating system. Building a URI is
/// [`VerusPayInvoice::to_wallet_deeplink_uri`]'s job, and it takes no scheme
/// argument — `verus://x-callback-url/…` is a link Verus Mobile routes to a
/// different parser and rejects, so this SDK offers no way to compose one.
pub fn wallet_deeplink_scheme() -> String {
    Address::new(AddressKind::Identity, keys::WALLET_VDXF_KEY)
        .to_string()
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq` — VRSCTEST, the currency every
    /// fixture invoice asks for.
    fn vrsctest() -> CurrencyId {
        CurrencyId::from_bytes(
            "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq"
                .parse::<Address>()
                .expect("a literal this file controls")
                .hash(),
        )
    }

    fn pkh(address: &str) -> InvoiceDestination {
        InvoiceDestination::Transparent(TransferDestination::plain(Destination::PubKeyHash(
            address
                .parse::<Address>()
                .expect("a literal this file controls")
                .hash(),
        )))
    }

    fn basic() -> VerusPayInvoiceDetails {
        VerusPayInvoiceDetails::new(
            RequestedAmount::Exact(10_000_000_000),
            pkh("R9J8E2no2HVjQmzX6Ntes2ShSGcn7WiRcx"),
            vrsctest(),
        )
    }

    /// The scheme trap, asserted against the literal a wallet has to match on.
    #[test]
    fn the_deeplink_scheme_is_the_wallet_vdxfid_and_not_verus() {
        assert_eq!(
            wallet_deeplink_scheme(),
            "i5jtwbp6zymeay9llnraglgjqgdrffsau4"
        );
        let uri = VerusPayInvoice::unsigned(VerusPayVersion::V4, basic())
            .to_wallet_deeplink_uri()
            .unwrap();
        assert!(uri.starts_with("i5jtwbp6zymeay9llnraglgjqgdrffsau4://x-callback-url/"));
        assert!(!uri.starts_with("verus"));
        // A path segment, not a query parameter: no `?`, no `=`, nothing
        // percent-encoded.
        let (_, payload) = uri.rsplit_once('/').expect("a final path segment");
        assert!(!uri.contains('?'), "the payload is not a query parameter");
        assert!(!payload.contains('%'), "nothing is percent-encoded");
    }

    /// The same URI, refused when its scheme is the one Verus Mobile routes
    /// elsewhere.
    #[test]
    fn a_verus_scheme_deeplink_is_refused() {
        let invoice = VerusPayInvoice::unsigned(VerusPayVersion::V4, basic());
        let real = invoice.to_wallet_deeplink_uri().unwrap();
        assert_eq!(
            VerusPayInvoice::from_wallet_deeplink_uri(&real).unwrap(),
            invoice
        );

        let key = Address::new(AddressKind::Identity, keys::VERUSPAY_INVOICE_VDXF_KEY);
        let payload = real.rsplit_once('/').expect("a payload").1;
        for wrong in [
            format!("verus://x-callback-url/{key}/{payload}"),
            format!("verus0://x-callback-url/{key}/{payload}"),
            // Right scheme, wrong object: a login-consent key in the path.
            format!(
                "{}://x-callback-url/{}/{payload}",
                wallet_deeplink_scheme(),
                Address::new(AddressKind::Identity, keys::LOGIN_CONSENT_REQUEST_VDXF_KEY)
            ),
            // Right prefix, payload in a query parameter instead of the path.
            format!(
                "{}://x-callback-url/{key}/?{key}={payload}",
                wallet_deeplink_scheme()
            ),
        ] {
            assert!(
                VerusPayInvoice::from_wallet_deeplink_uri(&wrong).is_err(),
                "{wrong} must be refused"
            );
        }
    }

    /// The signed bit is not a version number, and masking is not optional.
    #[test]
    fn the_signed_bit_is_the_top_of_the_version_and_never_a_field() {
        let unsigned = VerusPayInvoice::unsigned(VerusPayVersion::V4, basic());
        assert_eq!(unsigned.serialized_version(), 4);
        assert!(!unsigned.is_signed());

        let signed = VerusPayInvoice::signed(
            VerusPayVersion::V4,
            basic(),
            InvoiceSignature {
                system_id: vrsctest(),
                signing_id: vrsctest(),
                signature: vec![0xab; 72],
            },
        );
        assert_eq!(signed.serialized_version(), 2_147_483_652);
        assert_eq!(signed.version(), VerusPayVersion::V4);

        // The mask, stated as the thing a reader must do.
        assert!(VerusPayVersion::from_number(signed.serialized_version()).is_err());
        assert_eq!(
            VerusPayVersion::from_number(signed.serialized_version() & !VERSION_SIGNED_BIT)
                .unwrap(),
            VerusPayVersion::V4
        );
        // And that `from_vdxf_object` does it, which is the only way in.
        let object = signed.to_vdxf_object().unwrap();
        assert_eq!(object.version(), 2_147_483_652);
        assert_eq!(VerusPayInvoice::from_vdxf_object(&object).unwrap(), signed);
    }

    /// A signed invoice's payload is the details plus a prefix, and the prefix
    /// is two raw hashes then a keyless signature object: a version byte and a
    /// length byte, no twenty-byte key.
    #[test]
    fn a_signed_payload_prepends_two_hashes_and_a_keyless_signature_object() {
        let signature = InvoiceSignature {
            system_id: vrsctest(),
            signing_id: vrsctest(),
            signature: vec![0xab; 72],
        };
        let signed = VerusPayInvoice::signed(VerusPayVersion::V4, basic(), signature);
        let data = signed.to_data_buffer().unwrap();
        let details = basic().serialize(VerusPayVersion::V4).unwrap();

        assert!(data.ends_with(&details));
        // 20 + 20 + varint(1) + compactSize(72) + 72.
        assert_eq!(data.len() - details.len(), 20 + 20 + 1 + 1 + 72);
        assert_eq!(&data[..20], &vrsctest().to_bytes());
        // The key is NOT there: byte 40 is the signature object's version.
        assert_eq!(
            data[40], 1,
            "the signature object's version, not a key byte"
        );
        assert_eq!(data[41], 72, "the signature's CompactSize length");
        assert_eq!(signed.data_byte_length().unwrap(), data.len());
    }

    /// Flags are computed from the data, so they cannot contradict it.
    #[test]
    fn flags_are_derived_and_v4_only_bits_are_refused_on_v3() {
        let mut details = basic();
        assert_eq!(details.flags(VerusPayVersion::V3).unwrap(), FLAG_VALID);

        details.expiry_height = Some(2_000_000);
        details.max_estimated_slippage = Some(40_000_000);
        assert_eq!(
            details.flags(VerusPayVersion::V3).unwrap(),
            FLAG_VALID | FLAG_EXPIRES | FLAG_ACCEPTS_CONVERSION
        );

        details.amount = RequestedAmount::Any;
        details.destination = InvoiceDestination::Any;
        assert_eq!(
            details.flags(VerusPayVersion::V3).unwrap() & FLAG_ACCEPTS_ANY_AMOUNT,
            FLAG_ACCEPTS_ANY_AMOUNT
        );

        // The v4-only bits: silently dropped upstream, refused here.
        let mut preconvert = basic();
        preconvert.is_preconvert = true;
        assert!(preconvert.flags(VerusPayVersion::V3).is_err());
        assert_eq!(
            preconvert.flags(VerusPayVersion::V4).unwrap(),
            FLAG_VALID | FLAG_IS_PRECONVERT
        );

        let mut shielded = basic();
        shielded.destination = InvoiceDestination::Sapling(SaplingDestination::from_bytes([7; 43]));
        assert!(shielded.serialize(VerusPayVersion::V3).is_err());
        assert!(shielded.serialize(VerusPayVersion::V4).is_ok());
    }

    /// An amount of `Any` suppresses the field rather than writing a zero — the
    /// two are different byte strings and mean different things.
    #[test]
    fn any_amount_removes_the_field_rather_than_zeroing_it() {
        let mut any = basic();
        any.amount = RequestedAmount::Any;
        any.destination = InvoiceDestination::Any;

        let mut zeroed = basic();
        zeroed.amount = RequestedAmount::Exact(0);
        zeroed.destination = InvoiceDestination::Any;

        let any_bytes = any.serialize(VerusPayVersion::V4).unwrap();
        let zero_bytes = zeroed.serialize(VerusPayVersion::V4).unwrap();
        assert_ne!(any_bytes, zero_bytes);
        assert_eq!(zero_bytes.len(), any_bytes.len() + 1, "the zero byte");
        // 21 bytes: a one-byte flag word and the currency id.
        assert_eq!(any_bytes.len(), 21);
    }

    /// The type byte settles what upstream's `Hash160` cannot: a key hash is an
    /// `R` address and an identity is an `i` address, with nothing re-stamped
    /// afterwards.
    #[test]
    fn a_destinations_address_version_comes_from_its_type_byte() {
        let key_hash = pkh("R9J8E2no2HVjQmzX6Ntes2ShSGcn7WiRcx");
        assert_eq!(
            key_hash.recipient_address().map(|a| a.to_string()),
            Some("R9J8E2no2HVjQmzX6Ntes2ShSGcn7WiRcx".to_string())
        );

        let identity = InvoiceDestination::Transparent(TransferDestination::plain(
            Destination::Identity(vrsctest().to_bytes()),
        ));
        assert_eq!(
            identity.recipient_address().map(|a| a.to_string()),
            Some("iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq".to_string())
        );

        // And it survives the wire, which is the half that matters: nothing in
        // the twenty bytes says `R` or `i`, so this is the type byte talking.
        for destination in [key_hash, identity] {
            let mut details = basic();
            let expected = destination.recipient_address();
            details.destination = destination;
            let bytes = details.serialize(VerusPayVersion::V4).unwrap();
            let mut offset = 0;
            let read =
                VerusPayInvoiceDetails::deserialize(&bytes, &mut offset, VerusPayVersion::V4)
                    .unwrap();
            assert_eq!(read.destination.recipient_address(), expected);
        }

        assert_eq!(InvoiceDestination::Any.recipient_address(), None);
        assert_eq!(
            InvoiceDestination::Sapling(SaplingDestination::from_bytes([3; 43]))
                .recipient_address(),
            None
        );
    }

    /// Bytes nothing upstream writes are refused rather than half-read.
    #[test]
    fn refuses_flag_words_it_cannot_write_back_identically() {
        let version = VerusPayVersion::V4;
        let currency = vrsctest().to_bytes();
        let suppressed = FLAG_ACCEPTS_ANY_AMOUNT | FLAG_ACCEPTS_ANY_DESTINATION;

        let details_with = |flags: u64, tail: &[u8]| {
            let mut bytes = Vec::new();
            write_compact_size(&mut bytes, flags);
            bytes.extend_from_slice(tail);
            bytes
        };
        let refused = |flags: u64, tail: &[u8]| {
            let bytes = details_with(flags, tail);
            let mut offset = 0;
            VerusPayInvoiceDetails::deserialize(&bytes, &mut offset, version).is_err()
        };

        // The baseline: the same shape, accepted.
        assert!(!refused(FLAG_VALID | suppressed, &currency));

        // An unknown bit: dropped on the way back out, so the invoice would
        // re-serialize to different bytes than it arrived as.
        assert!(refused(FLAG_VALID | 0x8000 | suppressed, &currency));
        // VERUSPAY_VALID clear.
        assert!(refused(suppressed, &currency));
        // Tagged: the x-address this crate deliberately does not model.
        assert!(refused(FLAG_VALID | FLAG_IS_TAGGED | suppressed, &currency));
        // Both destination flags at once: two different destinations named in
        // one word, and a bit this type cannot carry back out.
        assert!(refused(
            FLAG_VALID | suppressed | FLAG_DESTINATION_IS_SAPLING_PAYMENT_ADDRESS,
            &currency
        ));
        // A truncated currency id.
        assert!(refused(FLAG_VALID | suppressed, &currency[..19]));

        // An accepted-systems array longer than the bytes behind it: nothing is
        // allocated on it.
        let mut bytes = Vec::new();
        write_compact_size(
            &mut bytes,
            FLAG_VALID | FLAG_ACCEPTS_NON_VERUS_SYSTEMS | suppressed,
        );
        bytes.extend_from_slice(&currency);
        write_compact_size(&mut bytes, u64::from(u32::MAX) + 1);
        let mut offset = 0;
        assert!(VerusPayInvoiceDetails::deserialize(&bytes, &mut offset, version).is_err());

        // And the same flag with a count of zero, which would come back with
        // the flag cleared.
        let mut bytes = Vec::new();
        write_compact_size(
            &mut bytes,
            FLAG_VALID | FLAG_ACCEPTS_NON_VERUS_SYSTEMS | suppressed,
        );
        bytes.extend_from_slice(&currency);
        write_compact_size(&mut bytes, 0);
        let mut offset = 0;
        assert!(VerusPayInvoiceDetails::deserialize(&bytes, &mut offset, version).is_err());
    }

    /// An invoice is the whole payload; a frame with bytes left over is not one.
    #[test]
    fn refuses_a_frame_that_is_not_an_invoice() {
        let invoice = VerusPayInvoice::unsigned(VerusPayVersion::V4, basic());
        let object = invoice.to_vdxf_object().unwrap();

        // Wrong key.
        let elsewhere = VdxfObject::new(
            keys::LOGIN_CONSENT_REQUEST_VDXF_KEY,
            object.version(),
            object.data().to_vec(),
        );
        assert!(VerusPayInvoice::from_vdxf_object(&elsewhere).is_err());

        // Unsupported version.
        let old = VdxfObject::new(object.key(), 2, object.data().to_vec());
        assert!(VerusPayInvoice::from_vdxf_object(&old).is_err());

        // Trailing bytes.
        let mut data = object.data().to_vec();
        data.push(0);
        let padded = VdxfObject::new(object.key(), object.version(), data);
        assert!(VerusPayInvoice::from_vdxf_object(&padded).is_err());
    }

    /// The prefix constant, spelled out rather than trusted.
    #[test]
    fn the_signature_prefix_is_the_length_prefixed_domain_separator() {
        assert_eq!(SIGNATURE_PREFIX[0], 19);
        assert_eq!(&SIGNATURE_PREFIX[1..], b"Verus signed data:\n");
        assert_eq!(SIGNATURE_PREFIX.len(), 20);
    }

    /// An unsigned invoice's details hash ignores both arguments, because
    /// upstream's does.
    #[test]
    fn an_unsigned_details_hash_is_just_the_details_sha256() {
        let invoice = VerusPayInvoice::unsigned(VerusPayVersion::V4, basic());
        let plain = basic().sha256(VerusPayVersion::V4).unwrap();
        assert_eq!(
            invoice.details_hash(0, SignatureVersion::V2).unwrap(),
            plain
        );
        assert_eq!(
            invoice.details_hash(999_999, SignatureVersion::V1).unwrap(),
            plain
        );
    }

    /// Bytes a stranger chose are an `Err`, never a panic, and never an
    /// allocation on a declared count — and whatever does parse, writes back.
    ///
    /// A deeplink was validated by nobody at all: it is a string off a QR code
    /// or out of an `openURL`. So this parser is held to the same rule
    /// `base64url` and `VdxfObject` are, and by the same shape of test rather
    /// than by assertion. Both versions are swept, because the two integer
    /// encodings read a different number of bytes from the same buffer.
    ///
    /// The round-trip half is what makes the refusals above worth their
    /// strictness: it asserts as a *property* that anything read out of a whole
    /// buffer re-serializes to that buffer, which is what keeps a signature over
    /// an invoice covering the invoice after a parse.
    #[test]
    fn never_panics_on_bytes_a_stranger_chose() {
        // Every one- and two-byte buffer. One byte is a bare flag word and two
        // is a flag word and the first byte of whatever it gated, so this sweeps
        // the shortest path through every branch the flags select.
        for first in 0..=0xffu8 {
            for version in [VerusPayVersion::V3, VerusPayVersion::V4] {
                let _ = VerusPayInvoiceDetails::deserialize(&[first], &mut 0, version);
                for second in 0..=0xffu8 {
                    let _ = VerusPayInvoiceDetails::deserialize(&[first, second], &mut 0, version);
                }
            }
        }

        // Longer buffers from a pool weighted towards the bytes that mean
        // something here: the CompactSize escapes, the VARINT continuation bit,
        // the destination type bytes, and the flag values that turn a field on.
        const POOL: &[u8; 16] = &[
            0x00, 0x01, 0x02, 0x04, 0x0f, 0x1f, 0x80, 0xfd, 0xfe, 0xff, 0x7f, 0x14, 0x20, 0x31,
            0x02, 0x04,
        ];
        let mut state: u32 = 0x9e37_79b9;
        let mut buffer = Vec::with_capacity(64);
        for round in 0..8000u32 {
            buffer.clear();
            let length = (round % 61) as usize + 1;
            for _ in 0..length {
                // A plain xorshift, inline for the reason `base64url`'s is: a
                // test's sequence generator is not worth a dependency.
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                buffer.push(POOL[(state % 16) as usize]);
            }
            for version in [VerusPayVersion::V3, VerusPayVersion::V4] {
                let mut offset = 0;
                if let Ok(details) =
                    VerusPayInvoiceDetails::deserialize(&buffer, &mut offset, version)
                {
                    if offset == buffer.len() {
                        assert_eq!(
                            details.serialize(version).ok().as_deref(),
                            Some(buffer.as_slice()),
                            "read {} and wrote something else",
                            hex::encode(&buffer)
                        );
                    }
                }
            }
            // And through the whole frame, which is the shape that actually
            // arrives: an attacker controls the version field too, so the signed
            // branch is reachable from here.
            for version in [
                3,
                4,
                3 | VERSION_SIGNED_BIT,
                4 | VERSION_SIGNED_BIT,
                0,
                u64::MAX,
            ] {
                let object =
                    VdxfObject::new(keys::VERUSPAY_INVOICE_VDXF_KEY, version, buffer.clone());
                let _ = VerusPayInvoice::from_vdxf_object(&object);
            }
            // And through the two text front doors, where the bytes are not even
            // known to be bytes yet.
            let _ = VerusPayInvoice::from_qr_string(&hex::encode(&buffer));
            let _ = VerusPayInvoice::from_wallet_deeplink_uri(&hex::encode(&buffer));
        }
    }
}
