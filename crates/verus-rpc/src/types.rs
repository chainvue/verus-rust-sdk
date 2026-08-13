//! What a node's answers look like once they are typed.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::value::RawValue;
use verus_tx::{Amount, Txid, Utxo};

use crate::error::RpcError;
use crate::json;

/// A satoshi amount that can be negative.
///
/// [`Amount`] is unsigned by design and stays that way: a transaction output
/// cannot hold a negative value, and making the type able to express one would
/// weaken every builder that takes it.
///
/// A *delta* is the one thing on this side of the wire that genuinely is signed.
/// `getaddressdeltas` reports the same output twice over its lifetime — once
/// positive when it is created, once negative when it is spent — and the sign is
/// the entire content of the second entry. Reading it as a magnitude turns money
/// leaving an address into money arriving at it, which is a wallet showing a
/// payment backwards.
///
/// So it is a separate type rather than an `i64` field, and there is deliberately
/// no `From<SignedAmount> for Amount`: crossing back to unsigned is a decision
/// about what to do with the sign, and [`SignedAmount::magnitude`] makes the
/// caller take it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct SignedAmount(i64);

impl SignedAmount {
    /// No movement.
    pub const ZERO: Self = Self(0);

    /// From a signed satoshi count.
    pub const fn from_sat(satoshis: i64) -> Self {
        Self(satoshis)
    }

    /// The signed satoshi count.
    pub const fn to_sat(self) -> i64 {
        self.0
    }

    /// Money left the address.
    pub const fn is_negative(self) -> bool {
        self.0 < 0
    }

    /// Money arrived at the address.
    pub const fn is_positive(self) -> bool {
        self.0 > 0
    }

    /// The size of the movement, without its direction.
    ///
    /// `i64::MIN` has no positive counterpart, so `unsigned_abs` gives its
    /// magnitude as `2^63` rather than wrapping or panicking. No reader in this
    /// crate can produce that value: the ceiling on a currency amount is
    /// `i64::MAX` satoshis, one below it, and the native ceiling is far lower
    /// still. `unsigned_abs` is what makes that a bound rather than a hope.
    pub const fn magnitude(self) -> Amount {
        Amount::from_sat(self.0.unsigned_abs())
    }

    /// Add another movement, refusing to wrap.
    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }

    /// The amount as a decimal coin string, sign included.
    pub fn to_coins_string(self) -> String {
        let magnitude = self.magnitude().to_coins_string();
        if self.is_negative() {
            format!("-{magnitude}")
        } else {
            magnitude
        }
    }
}

impl std::fmt::Display for SignedAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_coins_string())
    }
}

/// One movement of value at one address, as `getaddressdeltas` reports it.
///
/// **Two deltas per output over its life**, not one: a positive entry in the
/// block that created it and a negative entry in the block that spent it. A
/// transaction that pays an address and takes change back therefore contributes
/// several rows, which is why `verus_flows::history` exists to fold them into
/// per-transaction entries rather than showing them raw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressDelta {
    /// The address this movement belongs to.
    pub address: String,
    /// The transaction that caused it.
    pub txid: Txid,
    /// Block it was mined in.
    pub height: u32,
    /// The block's timestamp, as the daemon reports it.
    ///
    /// A miner-chosen field, only loosely monotonic. Fine for display, not a
    /// source of ordering — sort by `(height, block_index, index)` for that.
    pub block_time: i64,
    /// Position of the transaction within its block.
    pub block_index: u32,
    /// Position of the input or output within the transaction.
    pub index: u32,
    /// Native value moved, negative when spending.
    ///
    /// **Zero for a token-only output.** A reserve output carries no native
    /// value, so a wallet that reads only this field shows a token transfer as
    /// nothing happening — see [`AddressDelta::currency_values`].
    pub satoshis: SignedAmount,
    /// Per-currency value moved, keyed by currency i-address, negative when
    /// spending.
    ///
    /// Includes the chain's own currency, duplicating
    /// [`AddressDelta::satoshis`]. Summing this map *and* that field
    /// double-counts the native leg.
    pub currency_values: BTreeMap<String, SignedAmount>,
    /// Whether this row is an input being spent rather than an output created.
    pub spending: bool,
}

/// One movement of value at an address that is **in the mempool, not yet
/// mined**.
///
/// The present-tense companion to [`AddressDelta`]: the same "what moved at this
/// address", on the other side of the confirmation line. A wallet needs both,
/// because a UTXO set and a delta list agree that an unconfirmed payment does
/// not exist — so an address that has just been paid reports a balance of zero,
/// which is the one answer a wallet must not give while money is demonstrably on
/// its way.
///
/// # What is missing compared to a mined delta, and what is added
///
/// No `height`, `block_index` or `block_time`: nothing here is in a block. In
/// their place is [`MempoolDelta::timestamp`], and — on spend rows —
/// [`MempoolDelta::spends`], which names the output being consumed. A mined
/// delta does not carry that, because for a confirmed spend the prevout can be
/// found on the chain.
///
/// # None of this is settled
///
/// A row here is a statement about **one node's** mempool at one instant. The
/// transaction may be mined, may be evicted, may be replaced, and a second node
/// may never have seen it. Show it as pending; do not let it decide what can be
/// spent. [`crate::ChainReader::address_utxos`] answers that question and
/// deliberately excludes everything here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MempoolDelta {
    /// The address this movement belongs to.
    pub address: String,
    /// The unconfirmed transaction that causes it.
    pub txid: Txid,
    /// Position of the input or output within that transaction.
    ///
    /// Inputs and outputs are numbered separately, so this is unique only
    /// alongside [`MempoolDelta::spending`] — a receive at output 0 and a spend
    /// at input 0 both report `0`.
    pub index: u32,
    /// Native value moved, negative when spending.
    ///
    /// **Zero for a token-only output**, exactly as [`AddressDelta::satoshis`]
    /// is: the value of a reserve output lives in its payload. See
    /// [`MempoolDelta::currency_values`].
    pub satoshis: SignedAmount,
    /// Per-currency value moved, keyed by currency i-address, negative when
    /// spending.
    ///
    /// Includes the chain's own currency, duplicating
    /// [`MempoolDelta::satoshis`]. Summing this map *and* that field
    /// double-counts the native leg.
    ///
    /// The daemon sends this **without being asked**. Its `verbosity` option
    /// reads as though it were the switch for per-currency data; measured
    /// against `api.verustest.net` on 2026-08-05 these values are in the plain
    /// reply, and what `verbosity: 1` adds is something else — see
    /// [`crate::ChainReader::address_mempool`].
    pub currency_values: BTreeMap<String, SignedAmount>,
    /// Whether this row is an input being spent rather than an output created.
    pub spending: bool,
    /// The output being spent, when this row is a spend.
    ///
    /// `Some` exactly when [`MempoolDelta::spending`] is true. A reply where the
    /// two disagree is refused rather than reconciled: a spend whose prevout
    /// went missing would read as a receipt, and be counted as incoming money.
    pub spends: Option<(Txid, u32)>,
    /// When the transaction entered **this node's** mempool, in seconds.
    ///
    /// Node-local, not consensus data: a second node reports a different value
    /// for the same transaction, and a node that has just restarted reports when
    /// it re-learned of it. Fine for display, not a source of ordering, and
    /// never a basis for deciding something has taken too long.
    pub timestamp: i64,
}

/// One side of an offer — what is being given, or what is wanted for it.
///
/// The two sides have the same shape and either can be either kind, which is
/// what makes an identity sale and a token trade the same mechanism.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OfferSide {
    /// Currency, possibly several at once.
    ///
    /// Keyed by currency i-address. More than one entry is ordinary on
    /// mainnet — an offer of a token usually carries a little of the native
    /// currency alongside it, because the output has to pay its own way.
    Currencies(BTreeMap<String, Amount>),
    /// A VerusID itself, changing hands.
    Identity {
        /// The identity's `i` address.
        identity_id: String,
        /// Its name, without the parent.
        name: String,
        /// The system it lives on.
        system_id: String,
    },
}

/// One offer standing on the marketplace, as `getoffers` lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferListing {
    /// What the maker is giving.
    pub offering: OfferSide,
    /// What the maker wants for it.
    pub accepting: OfferSide,
    /// Height after which the offer can no longer be completed.
    pub block_expiry: u32,
    /// The outpoint's transaction the offer spends — **not** the id of the
    /// offer transaction itself.
    ///
    /// The daemon calls this field `txid`, which reads as "this offer's
    /// transaction" and is the wrong thing to fetch. It is the *funding*
    /// transaction: the one holding the output the maker has signed away.
    ///
    /// Established by parsing `tx` from the same reply and comparing — the
    /// first input's prevout is exactly this value, while hashing `tx` gives
    /// something else entirely. Renamed here so the mistake is harder to make.
    ///
    /// The funding *vout* is not listed. It is in [`OfferListing::raw_offer`],
    /// which is one reason to ask for it.
    pub funding_txid: Txid,
    /// The maker's signed half-transaction, when it was asked for.
    ///
    /// `Some` only when `with_tx` was set. This is what turns browsing into
    /// something actionable: it is the input `verus_flows::offer::inspect`
    /// takes, so a listing can be checked against the chain and then completed
    /// without a further round trip to find it.
    pub raw_offer: Option<String>,
    /// The daemon's own price for the offer, **verbatim**.
    ///
    /// Deliberately text and not an [`Amount`], for two reasons — neither of
    /// them "an amount could not hold it". Most of these values would parse
    /// exactly; `3.9e-7` and `1e-8` are 39 and 1 satoshis and this crate reads
    /// both.
    ///
    /// The first reason is that a price is not an amount of anything. It is a
    /// **ratio** between the two sides, so giving it a money type invites it
    /// into arithmetic where every other operand is denominated in something.
    ///
    /// The second is that it is already rounded before it arrives. The daemon
    /// divides in `double` and prints the result: one listing in this crate's
    /// own fixtures offers 0.0001 for 258, whose true ratio is 3.8759…e-7 and
    /// which is printed as `3.9e-07`. Reading that into an exact type would
    /// dress a rounded figure as a precise one — and ratios below satoshi
    /// resolution are perfectly constructible, so the exact reader would also
    /// refuse listings the daemon is happy to advertise.
    ///
    /// Fine for display and for ordering a list. For anything that decides what
    /// to pay, compute from [`OfferListing::offering`] and
    /// [`OfferListing::accepting`], which are exact.
    pub price: String,
    /// The daemon's grouping key for this listing, verbatim — for example
    /// `ids_for_currency_<id>`.
    ///
    /// Kept because it is the only place the *direction* of a bucket is
    /// recorded, and dropping it would merge listings that the daemon
    /// deliberately separated.
    pub bucket: String,
}

impl OfferListing {
    /// Whether the offer can still be completed at `tip`.
    ///
    /// Zero means no expiry, matching
    /// [`verus_flows::offer::OfferTerms`](https://docs.rs/verus-flows).
    #[must_use]
    pub fn is_live_at(&self, tip: u32) -> bool {
        self.block_expiry == 0 || tip < self.block_expiry
    }
}

/// A currency as `listcurrencies` summarises it.
///
/// Only the fields every currency has are typed. Across the 290 currencies on
/// VRSCTEST a definition can carry any of some **46** different keys — weights,
/// preallocations, carveouts, notaries, gateway plumbing — of which 16 appear
/// on all of them and the rest depend on what kind of currency it is. That
/// count is a snapshot and drifts upward as new currency kinds appear, which is
/// itself the argument. Typing
/// the long tail would produce a struct that is mostly `Option::None` and that
/// breaks whenever a new currency kind appears, so the whole definition is kept
/// alongside as [`CurrencySummary::definition`], the same arrangement
/// [`IdentityRecord`] uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrencySummary {
    /// The currency's own `i` address.
    pub currency_id: String,
    /// Its name, unqualified.
    pub name: String,
    /// The name with its parents, dotted — `Bridge.vETH`, `mobile.Kaiju`.
    ///
    /// **No trailing `@`**, unlike an identity's. That suffix is the identity
    /// convention and copying it here was wrong: none of the 290 currency names
    /// on VRSCTEST carries one.
    pub fully_qualified_name: String,
    /// The currency this one was defined under.
    ///
    /// `None` for a root chain, which is defined under nothing — the single
    /// currency on VRSCTEST without this field is VRSCTEST itself.
    pub parent: Option<String>,
    /// The system the currency lives on.
    pub system_id: String,
    /// Height the currency starts at.
    pub start_block: u32,
    /// Height it ends at, or zero for never.
    pub end_block: u32,
    /// The options bitfield — what kind of currency this is.
    pub options: u32,
    /// How a sub-identity under this currency proves itself, which decides the
    /// shape of the fee output its registration must carry.
    pub proof_protocol: u32,
    /// The definition in full, for the fields not typed here.
    pub definition: serde_json::Value,
}

/// A basket that can convert one currency into another.
///
/// Answers the routing question a conversion needs and had no way to ask: given
/// a currency, which markets hold it, and what else is in them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrencyConverter {
    /// The converter's `i` address.
    pub converter_id: String,
    /// Its fully qualified name.
    pub name: String,
    /// Height the reported state was taken at.
    pub height: u32,
    /// The reserve currencies it holds, by `i` address.
    ///
    /// **Not the whole set this converter trades.** A fractional currency
    /// converts between its reserves *and itself*, so its own id is routable
    /// too and does not appear here. `getcurrencyconverters ["vlotto"]` returns
    /// vlotto, whose reserves are `[VRSCTEST]` — a caller filtering on this
    /// field alone would discard the very converter it just asked for.
    ///
    /// Use [`CurrencyConverter::trades`] rather than testing this directly.
    pub reserves: Vec<String>,
    /// The converter's definition in full.
    pub definition: serde_json::Value,
    /// `lastnotarization` — the reserve depths and prices as of
    /// [`CurrencyConverter::height`].
    ///
    /// The definition above is static; this is what actually moves, and what a
    /// router prices against. Left as JSON for the same reason the definition
    /// is: its shape depends on the kind of currency.
    ///
    /// `Null` if the entry carried none.
    pub last_notarization: serde_json::Value,
}

impl CurrencyConverter {
    /// Whether this converter can convert `currency` at all.
    ///
    /// The predicate is `currency ∈ reserves ∪ {converter_id}`, and the second
    /// half is the part that is easy to miss — see
    /// [`CurrencyConverter::reserves`].
    #[must_use]
    pub fn trades(&self, currency: &str) -> bool {
        self.converter_id == currency || self.reserves.iter().any(|held| held == currency)
    }

    /// Whether this converter can route directly between two currencies.
    #[must_use]
    pub fn routes(&self, from: &str, to: &str) -> bool {
        self.trades(from) && self.trades(to)
    }
}

/// One value published under a VDXF key.
///
/// The daemon renders a value one of two ways, and which one depends on whether
/// it recognises the key. That is not a quirk to normalise away: the two carry
/// different amounts of information, and collapsing them would either lose the
/// structure or invent one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContentValue {
    /// Hex on the wire — the raw VDXF-encoded bytes.
    ///
    /// What you get for a key the daemon does not recognise, which is every key
    /// an application defines for itself.
    Bytes(Vec<u8>),
    /// The daemon recognised the key and rendered the value structured.
    ///
    /// Kept as JSON. Re-encoding it to bytes would mean implementing the VDXF
    /// type system, and reading it as bytes is not possible — the daemon has
    /// already decoded it and the original is not in the reply.
    Structured(serde_json::Value),
}

impl ContentValue {
    /// The raw bytes, when there are any.
    ///
    /// `None` for a structured value: there are no bytes in the reply to give.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            ContentValue::Bytes(bytes) => Some(bytes),
            ContentValue::Structured(_) => None,
        }
    }
}

/// A VerusID together with the data published on it.
///
/// `getidentity` returns the identity; this returns it with its content maps
/// filled in, which is what an application storing data on an identity needs to
/// read back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityContent {
    /// The identity itself, as [`ChainReader::identity`](crate::ChainReader)
    /// would return it.
    pub identity: IdentityRecord,
    /// `contentmap` — 20-byte VDXF key to a single 32-byte value, both hex.
    ///
    /// The older and narrower of the two maps: one hash per key, so it holds a
    /// reference to content rather than content.
    pub content_map: BTreeMap<String, String>,
    /// `contentmultimap` — a VDXF key to any number of values.
    ///
    /// **Keyed by `i` address, not hex**, unlike
    /// [`IdentityContent::content_map`] in the same object. The two maps
    /// genuinely disagree about how to spell the same kind of value, so a
    /// derived key compared against the wrong rendering finds nothing.
    ///
    /// A value is VDXF-typed data whose encoding depends on its key — and a
    /// VDXF key is a **one-way hash of a name**, so for a key you did not
    /// create there is no way back to the name and therefore nothing that says
    /// how to read the value. Only its creator knows, and only publishing the
    /// name shares that.
    ///
    /// `vrsc@` and `Verus Coin Foundation@` both publish under
    /// `iSJ38vYX7qoCtotc9wBHb1vZdR3oTgoHCX`, whose name cannot be recovered
    /// from the key. Handing the value back untouched is the honest answer, not
    /// a placeholder; `verus_flows::vdxf` builds on that.
    ///
    /// See [`ContentValue`] for why a value is not simply bytes.
    ///
    /// Empty for an identity older than version 3, which has no such field at
    /// all.
    pub content_multimap: BTreeMap<String, Vec<ContentValue>>,
}

/// Confirmations a coinbase output needs before it can be spent.
///
/// A wallet that ignores this selects an immature coinbase and the daemon
/// answers `bad-txns-premature-spend-of-coinbase` at broadcast — after the
/// transaction is built and signed.
pub const COINBASE_MATURITY: u32 = 100;

/// An unspent output as a node reports it.
///
/// Deliberately **not** a bare [`Utxo`]: that type carries no height, and
/// without a height there is no way to tell a spendable coinbase from one that
/// is still maturing. Convert with [`spendable_at`], which decides
/// that question from the tip rather than trusting the node's own opinion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressUtxo {
    /// The outpoint, value and script, ready for a builder.
    pub utxo: Utxo,
    /// The address this was found under.
    pub address: String,
    /// The block it was mined in.
    pub height: u32,
    /// The node's own opinion of spendability. Recorded, not relied on.
    pub is_spendable: bool,
}

impl AddressUtxo {
    /// How many confirmations this has at `tip`.
    pub fn confirmations(&self, tip: u32) -> u32 {
        tip.saturating_sub(self.height).saturating_add(1)
    }
}

/// Keep only what can actually be spent at `tip`.
///
/// Applies coinbase maturity **and** the node's `is_spendable`, keeping the
/// stricter of the two. A wallet should call this rather than filtering by hand:
/// forgetting it produces a transaction that builds, signs and is then rejected.
pub fn spendable_at(utxos: &[AddressUtxo], tip: u32, coinbase_heights: &[u32]) -> Vec<Utxo> {
    utxos
        .iter()
        .filter(|found| found.is_spendable)
        .filter(|found| {
            !coinbase_heights.contains(&found.height)
                || found.confirmations(tip) >= COINBASE_MATURITY
        })
        .map(|found| found.utxo.clone())
        .collect()
}

/// What a node says about the chain it is on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainInfo {
    /// Chain name — `VRSC` or `VRSCTEST`.
    pub name: String,
    /// The chain's own currency id.
    pub chain_id: String,
    /// Height of the node's best block.
    pub blocks: u32,
    /// Longest chain the node has seen. Below `blocks` means it is still syncing.
    pub longest_chain: u32,
    /// Daemon version string.
    pub version: String,
}

/// The registration policy of one currency.
///
/// Both fields are per-currency, not per-chain: VRSCTEST charges 100 with 3
/// referral levels, while `ownora-nft` charges 1.0 and permits no referrals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrencyPolicy {
    /// The currency's own id.
    pub currency_id: String,
    /// Friendly name.
    pub name: String,
    /// `idregistrationfees`, reported by the daemon in **coins** and converted
    /// here exactly.
    pub id_registration_fee: Amount,
    /// `idreferrallevels` — how many referrers get paid.
    pub id_referral_levels: u32,
    /// `idimportfees`, burned natively by a sub-identity registration.
    ///
    /// **Also what an NFT launch is charged**, in place of
    /// [`currency_registration_fee`](Self::currency_registration_fee) —
    /// consensus picks between the two on the definition's `NFT_TOKEN` bit
    /// (`CCurrencyDefinition::GetCurrencyImportFee`). 0.02 against 200 on
    /// VRSCTEST, so reading the wrong one is off by four orders of magnitude.
    pub id_import_fee: Amount,
    /// `currencyregistrationfee` — what it costs to define a currency under
    /// this one.
    ///
    /// The figure a launch is built against, and the one value in it there is no
    /// safe default for: half becomes the reserve deposit and half is consumed
    /// by consensus, so a wrong number produces a transaction the daemon
    /// rejects. 200 native on VRSCTEST at the time of writing, but read it
    /// rather than assume it — it is chain policy and can change.
    ///
    /// **Not what an NFT pays** — that is
    /// [`id_import_fee`](Self::id_import_fee). `flows::prepare_launch` picks
    /// between them for you.
    ///
    /// Absent from a currency whose definition does not carry one, in which case
    /// this is zero.
    pub currency_registration_fee: Amount,
    /// Which fee-output shape a sub-identity under this parent needs.
    pub proof_protocol: u32,
}

/// What an address holds, in both forms the daemon reports it.
///
/// `getaddressbalance` answers with the **same** native balance twice:
/// `balance` in satoshis, and an entry under `currencybalance` for the chain's
/// own currency in coins. Reading the wrong one is a factor of 1e8, so both are
/// parsed exactly, by two readers that share no code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressBalance {
    /// Native balance, from the satoshi field.
    pub balance: Amount,
    /// Native lifetime received, from the satoshi field.
    pub received: Amount,
    /// Per-currency balances, keyed by currency i-address. Reported in coins,
    /// converted exactly. Includes the chain's own currency, which duplicates
    /// [`AddressBalance::balance`].
    pub currency_balance: BTreeMap<String, Amount>,
}

/// What a conversion is expected to yield.
///
/// **An estimate, and nothing more.** A conversion executes at the price
/// prevailing when it is imported, which is at least a block after it is signed.
/// Nothing in the transaction enforces this figure — see
/// [`verus_tx::convert`](https://docs.rs/verus-tx) on why there is no slippage
/// bound in the protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversionEstimate {
    /// How much of the destination currency the node expects to be produced.
    pub estimated_out: Amount,
    /// The conversion fee the node calculated, when it reported one.
    pub fee: Option<Amount>,
}

/// A VerusID as a node reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityRecord {
    /// `name.parent@`.
    pub fully_qualified_name: String,
    /// The identity's `i` address.
    pub identity_address: String,
    /// `active` or `revoked`.
    pub status: String,
    /// The transaction holding the identity, and which output.
    pub outpoint: (Txid, u32),
    /// Height that transaction was mined at.
    pub block_height: u32,
    /// The raw identity object, for callers that need every field.
    pub identity: serde_json::Value,
}

impl IdentityRecord {
    /// Whether the identity is revoked.
    pub fn is_revoked(&self) -> bool {
        self.status == "revoked"
    }
}

/// One identity found by [`crate::ChainReader::identities_with_address`].
///
/// # Why this is not an [`IdentityRecord`]
///
/// `getidentitieswithaddress` answers with the identity objects themselves —
/// the same shape as `getidentity`'s **inner** `identity` field — rather than
/// with the envelope around them. Three fields an [`IdentityRecord`] promises
/// are simply not in the reply: `fullyqualifiedname`, `status`, and
/// `blockheight`. Filling them in would mean inventing two of them, and an
/// invented `fullyqualifiedname` is the field a person reads to decide which
/// identity they are looking at.
///
/// So this type carries what the reply carries. For the full envelope, and for
/// the consensus-accurate view before anything is signed, ask
/// [`crate::ChainReader::identity`] about [`IdentityAtAddress::identity_address`]
/// — which is the identifier to prefer for anything destructive anyway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityAtAddress {
    /// The identity's own `i` address.
    pub identity_address: String,
    /// The **name component only**, without the parent and without the `@`.
    ///
    /// `vdxf1171008`, not `vdxf1171008.VRSCTEST@`. Qualifying it needs the
    /// parent's name, and [`IdentityAtAddress::parent`] is an i-address — so
    /// that is another request, and the caller decides whether to spend it.
    pub name: String,
    /// The parent currency's i-address. All-zero-ish roots have none.
    pub parent: String,
    /// Raw identity flags. Interpreted for you by
    /// [`IdentityAtAddress::is_revoked`]; `verus_tx::identity` names the bits.
    pub flags: u32,
    /// The identity's `unlock_after` field, whose meaning **depends on
    /// `flags`** — an absolute height when unlocked, a relative delay when
    /// locked. `verus_tx::identity::Timelock` is what reads it correctly; do
    /// not compare it against a block height without checking the flag first.
    pub timelock: u32,
    /// The output currently holding the identity, which moves with every
    /// update.
    pub outpoint: (Txid, u32),
    /// The whole object, for the fields not lifted above.
    pub identity: serde_json::Value,
}

impl IdentityAtAddress {
    /// Whether the identity is revoked.
    ///
    /// Read off the flag rather than off a `status` string, because this reply
    /// has no status string. Same answer, different source.
    pub fn is_revoked(&self) -> bool {
        self.flags & verus_tx::identity::FLAG_REVOKED != 0
    }
}

// ---- deserialization ----

#[derive(Deserialize)]
pub(crate) struct RawAddressUtxo<'a> {
    pub address: String,
    pub txid: String,
    #[serde(rename = "outputIndex")]
    pub output_index: u32,
    pub script: String,
    #[serde(borrow)]
    pub satoshis: &'a RawValue,
    pub height: u32,
    #[serde(default)]
    pub isspendable: u8,
}

impl RawAddressUtxo<'_> {
    pub(crate) fn into_typed(self) -> Result<AddressUtxo, RpcError> {
        Ok(AddressUtxo {
            utxo: Utxo {
                txid: Txid::from_display_hex(&self.txid)
                    .map_err(|e| RpcError::OutOfRange(format!("txid: {e}")))?,
                vout: self.output_index,
                satoshis: json::satoshis(self.satoshis, "satoshis")?,
                script_pubkey: hex_bytes(&self.script, "script")?,
            },
            address: self.address,
            height: self.height,
            is_spendable: self.isspendable != 0,
        })
    }
}

#[derive(Deserialize)]
pub(crate) struct RawAddressBalance<'a> {
    #[serde(borrow)]
    pub balance: &'a RawValue,
    #[serde(borrow)]
    pub received: &'a RawValue,
    #[serde(borrow, default)]
    pub currencybalance: BTreeMap<String, &'a RawValue>,
}

impl RawAddressBalance<'_> {
    pub(crate) fn into_typed(self) -> Result<AddressBalance, RpcError> {
        let mut currency_balance = BTreeMap::new();
        for (currency, raw) in self.currencybalance {
            // Coins here, satoshis above, in the same reply.
            currency_balance.insert(currency, json::currency_coins(raw, "currencybalance")?);
        }
        Ok(AddressBalance {
            balance: json::satoshis(self.balance, "balance")?,
            received: json::satoshis(self.received, "received")?,
            currency_balance,
        })
    }
}

#[derive(Deserialize)]
pub(crate) struct RawAddressDelta<'a> {
    pub address: String,
    pub txid: String,
    pub height: u32,
    #[serde(default)]
    pub blocktime: i64,
    #[serde(default)]
    pub blockindex: u32,
    #[serde(default)]
    pub index: u32,
    #[serde(borrow)]
    pub satoshis: &'a RawValue,
    #[serde(borrow, default)]
    pub currencyvalues: BTreeMap<String, &'a RawValue>,
    #[serde(default)]
    pub spending: bool,
}

impl RawAddressDelta<'_> {
    pub(crate) fn into_typed(self) -> Result<AddressDelta, RpcError> {
        let mut currency_values = BTreeMap::new();
        for (currency, raw) in self.currencyvalues {
            // Coins here, satoshis below, in the same row — the same split
            // `getaddressbalance` has, and signed on both sides.
            currency_values.insert(
                currency,
                json::signed_currency_coins(raw, "currencyvalues")?,
            );
        }
        Ok(AddressDelta {
            address: self.address,
            txid: Txid::from_display_hex(&self.txid)
                .map_err(|e| RpcError::OutOfRange(format!("txid: {e}")))?,
            height: self.height,
            block_time: self.blocktime,
            block_index: self.blockindex,
            index: self.index,
            satoshis: json::signed_satoshis(self.satoshis, "satoshis")?,
            currency_values,
            spending: self.spending,
        })
    }
}

/// A `getaddressmempool` row, still as JSON.
///
/// Deliberately its own type rather than `RawAddressDelta` with more `default`
/// attributes. The two replies overlap but differ in what is *required*: a
/// mined delta must carry a height, and a mempool row must not. Reading one
/// through the other's decoder would silently accept a mined delta here with
/// `height` dropped on the floor.
#[derive(Deserialize)]
pub(crate) struct RawMempoolDelta<'a> {
    pub address: String,
    pub txid: String,
    #[serde(default)]
    pub index: u32,
    #[serde(borrow)]
    pub satoshis: &'a RawValue,
    #[serde(borrow, default)]
    pub currencyvalues: BTreeMap<String, &'a RawValue>,
    #[serde(default)]
    pub spending: bool,
    /// Present on spend rows only.
    #[serde(default)]
    pub prevtxid: Option<String>,
    /// Present on spend rows only.
    #[serde(default)]
    pub prevout: Option<u32>,
    #[serde(default)]
    pub timestamp: i64,
}

impl RawMempoolDelta<'_> {
    pub(crate) fn into_typed(self) -> Result<MempoolDelta, RpcError> {
        let mut currency_values = BTreeMap::new();
        for (currency, raw) in self.currencyvalues {
            currency_values.insert(
                currency,
                json::signed_currency_coins(raw, "currencyvalues")?,
            );
        }

        // `spending` and the prevout must agree. Neither is derived from the
        // other, because the disagreement is the interesting case: a spend
        // whose `prevtxid` went missing would otherwise decode as a receipt,
        // and a caller summing positive rows would count money leaving the
        // address as money arriving at it.
        let spends = match (self.spending, self.prevtxid, self.prevout) {
            (true, Some(txid), Some(vout)) => Some((
                Txid::from_display_hex(&txid)
                    .map_err(|e| RpcError::OutOfRange(format!("prevtxid: {e}")))?,
                vout,
            )),
            (false, None, None) => None,
            (spending, txid, vout) => {
                return Err(RpcError::Unexpected(format!(
                    "getaddressmempool row for {} says spending={spending} but \
                     prevtxid={} and prevout={}",
                    self.address,
                    txid.map_or("absent".into(), |t| t),
                    vout.map_or("absent".to_string(), |v| v.to_string()),
                )))
            }
        };

        Ok(MempoolDelta {
            address: self.address,
            txid: Txid::from_display_hex(&self.txid)
                .map_err(|e| RpcError::OutOfRange(format!("txid: {e}")))?,
            index: self.index,
            satoshis: json::signed_satoshis(self.satoshis, "satoshis")?,
            currency_values,
            spending: self.spending,
            spends,
            timestamp: self.timestamp,
        })
    }
}

/// One side of an offer, still as JSON.
///
/// Read as a plain map rather than a struct with `#[serde(flatten)]` for the
/// currency entries, and that is forced rather than chosen: `flatten` buffers
/// through serde's internal `Content`, which cannot yield a `RawValue`. Since
/// keeping the original token text is the whole reason money is read through
/// `RawValue` here, the map is what there is to work with.
///
/// Which kind of side it is shows in the keys. An identity side carries
/// `identityid`; anything else is `<currency i-address>: <coins>` throughout.
#[derive(Deserialize)]
pub(crate) struct RawOfferSide<'a>(#[serde(borrow)] BTreeMap<String, &'a RawValue>);

impl RawOfferSide<'_> {
    fn into_typed(self, field: &'static str) -> Result<OfferSide, RpcError> {
        // A JSON string is **decoded**, not merely unquoted. `RawValue::get()`
        // hands back verbatim wire text, so `⌐` stays as those six literal
        // characters unless something actually parses it — and identity names
        // are user-chosen, so escapes are ordinary rather than exotic. One of
        // this crate's own mainnet fixtures lists an identity named `(⌐■_■)`,
        // which arrives as `"(⌐■_■)"`: unquoting alone gives a
        // 21-character string that matches nothing, least of all the same name
        // read back through `getidentity`.
        //
        // Required, not defaulted. A side that says it is an identity and then
        // does not name one is a malformed answer, and inventing an empty
        // string for it hands the caller an id it may go on to look up.
        let text = |key: &'static str| -> Result<String, RpcError> {
            let raw = self.0.get(key).ok_or_else(|| {
                RpcError::Unexpected(format!("an offer's {field} side has no {key}"))
            })?;
            serde_json::from_str::<String>(raw.get()).map_err(|_| {
                RpcError::Unexpected(format!(
                    "an offer's {field} side has a {key} that is not a string: {}",
                    raw.get()
                ))
            })
        };

        if self.0.contains_key("identityid") {
            return Ok(OfferSide::Identity {
                identity_id: text("identityid")?,
                name: text("name")?,
                system_id: text("systemid")?,
            });
        }

        let mut currencies = BTreeMap::new();
        for (currency, raw) in &self.0 {
            // Every remaining key is taken to be a currency, so it has to look
            // like one. Without this a stray numeric field the daemon might add
            // later — a height, a count — would silently become a holding of
            // some phantom currency and be added to a total. The identity side
            // proves that non-currency keys share this namespace.
            if !is_i_address(currency) {
                return Err(RpcError::Unexpected(format!(
                    "an offer's {field} side has {currency}, which is not a currency address"
                )));
            }
            currencies.insert(currency.clone(), json::currency_coins(raw, field)?);
        }
        if currencies.is_empty() {
            return Err(RpcError::Unexpected(format!(
                "an offer's {field} side names neither an identity nor any currency"
            )));
        }
        Ok(OfferSide::Currencies(currencies))
    }
}

/// Whether a key is shaped like the `i` address of a currency.
///
/// A cheap shape test, not a checksum: enough to keep a field that is plainly
/// not a currency from being read as one.
fn is_i_address(text: &str) -> bool {
    text.len() == 34
        && text.starts_with('i')
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() && !b"0OIl".contains(&b))
}

#[derive(Deserialize)]
pub(crate) struct RawOfferBody<'a> {
    #[serde(borrow)]
    pub offer: RawOfferSide<'a>,
    #[serde(borrow)]
    pub accept: RawOfferSide<'a>,
    // Required rather than defaulted. Zero means "never expires", so a reply
    // that simply omitted the field would read as an offer that stands
    // forever — failing open on the one question this type is asked.
    pub blockexpiry: u32,
    pub txid: String,
    #[serde(default)]
    pub tx: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct RawOfferEntry<'a> {
    #[serde(borrow)]
    pub offer: RawOfferBody<'a>,
    #[serde(borrow)]
    pub price: &'a RawValue,
}

impl RawOfferEntry<'_> {
    pub(crate) fn into_typed(self, bucket: &str) -> Result<OfferListing, RpcError> {
        Ok(OfferListing {
            offering: self.offer.offer.into_typed("offer")?,
            accepting: self.offer.accept.into_typed("accept")?,
            block_expiry: self.offer.blockexpiry,
            funding_txid: Txid::from_display_hex(&self.offer.txid)
                .map_err(|e| RpcError::OutOfRange(format!("offer txid: {e}")))?,
            raw_offer: self.offer.tx,
            // Verbatim, and never through `Amount` — see `OfferListing::price`.
            price: json::unquote(self.price.get()).to_string(),
            bucket: bucket.to_string(),
        })
    }
}

#[derive(Deserialize)]
pub(crate) struct RawCurrencyEntry {
    pub currencydefinition: serde_json::Value,
}

impl RawCurrencyEntry {
    pub(crate) fn into_typed(self) -> Result<CurrencySummary, RpcError> {
        summary_from_definition(self.currencydefinition)
    }
}

/// One currency definition, typed.
///
/// Shared by the two RPCs that carry the same object in different wrappers:
/// `listcurrencies` nests it under `currencydefinition`, `getcurrency` returns
/// it bare. Parsing them through one function is what keeps a single-currency
/// read from drifting away from the whole-chain one — the two answered
/// differently would be worse than either being wrong.
pub(crate) fn summary_from_definition(
    definition: serde_json::Value,
) -> Result<CurrencySummary, RpcError> {
    let text = |key: &str| -> Result<String, RpcError> {
        definition
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| RpcError::Unexpected(format!("a currency definition has no {key}")))
    };
    // Required, not defaulted — the opposite of what a "sensible default"
    // instinct suggests, and for a concrete reason. All four of these are
    // present, integral and within `u32` on every one of the 290
    // currencies, so `unwrap_or(0)` could never fire on an honest reply;
    // it could only turn a missing, negative or oversized value into a
    // convincing zero. And zero is never neutral here: `proofprotocol` is
    // 1, 2 or 3 and decides the fee-output shape a sub-identity
    // registration must carry, `options` decides what kind of currency
    // this is, and an `endblock` of zero means "never ends".
    let number = |key: &'static str| -> Result<u32, RpcError> {
        definition
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| {
                RpcError::Unexpected(format!("a currency definition has no usable {key}"))
            })
    };

    Ok(CurrencySummary {
        currency_id: text("currencyid")?,
        name: text("name")?,
        fully_qualified_name: text("fullyqualifiedname")?,
        // Absent on a root chain, and that is the one case where absence
        // means something rather than being a gap in the reply.
        parent: definition
            .get("parent")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        system_id: text("systemid")?,
        start_block: number("startblock")?,
        end_block: number("endblock")?,
        options: number("options")?,
        proof_protocol: number("proofprotocol")?,
        definition,
    })
}

/// One converter, whose definition hides behind a **key that is its own id**.
///
/// The entry carries four fields with names and one whose name is data — the
/// same shape `getoffers` uses for its buckets — so the definition is found by
/// elimination.
///
/// # Elimination alone is not safe, so it checks itself
///
/// "The key that is not one of these four" quietly assumes the daemon will
/// never add a fifth named field. If it ever does, elimination picks that
/// instead, and the failure is silent in a way that matters: `serde_json`'s map
/// is a `BTreeMap`, so iteration is lexicographic and any new lowercase key
/// sorting before `i` wins. What comes out is a converter whose id is a field
/// name and whose reserve list is empty — and a router built on it then answers
/// "no route" for every currency on the chain, with nothing raised anywhere.
///
/// The reply already carries the detector: a real definition has a
/// `currencyid` equal to the key it sits under, on all 26 live entries. Testing
/// it makes the elimination self-verifying instead of a bet on a future field
/// list.
///
/// The remaining fields are required for the same reason `RawCurrencyEntry`
/// requires its own: a converter with a fabricated height, an empty name or no
/// reserves looks like an answer and is not one.
pub(crate) fn converter_from_entry(
    entry: serde_json::Value,
) -> Result<CurrencyConverter, RpcError> {
    const KNOWN: [&str; 4] = ["fullyqualifiedname", "height", "lastnotarization", "output"];

    let serde_json::Value::Object(mut object) = entry else {
        return Err(RpcError::Unexpected(
            "a converter entry is not an object".into(),
        ));
    };

    let converter_id = object
        .keys()
        .find(|key| !KNOWN.contains(&key.as_str()))
        .ok_or_else(|| {
            RpcError::Unexpected(
                "a converter entry carries no definition under its own currency id".into(),
            )
        })?
        .clone();
    let definition = object
        .remove(&converter_id)
        .expect("the key came from `find` over this same map, unmodified since");

    if definition.get("currencyid").and_then(|v| v.as_str()) != Some(converter_id.as_str()) {
        return Err(RpcError::Unexpected(format!(
            "a converter entry holds {converter_id} where its definition was expected; the reply \
             shape has changed and a definition can no longer be found by elimination"
        )));
    }

    let reserves: Vec<String> = definition
        .get("currencies")
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .ok_or_else(|| {
            RpcError::Unexpected(format!(
                "converter {converter_id} lists no reserve currencies"
            ))
        })?;

    let name = object
        .get("fullyqualifiedname")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            RpcError::Unexpected(format!(
                "converter {converter_id} has no fullyqualifiedname"
            ))
        })?
        .to_string();

    let height = object
        .get("height")
        .and_then(serde_json::Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| RpcError::Unexpected(format!("converter {converter_id} has no height")))?;

    // The reserve depths and prices — what a router actually prices against.
    // The definition is the static half; this is the half that moves, and
    // dropping it would leave the recorded height describing a state the caller
    // no longer has.
    let last_notarization = object.remove("lastnotarization").unwrap_or_default();

    Ok(CurrencyConverter {
        converter_id,
        name,
        height,
        reserves,
        definition,
        last_notarization,
    })
}

#[derive(Deserialize)]
pub(crate) struct RawChainInfo {
    pub name: String,
    pub chainid: String,
    pub blocks: u32,
    pub longestchain: u32,
    #[serde(rename = "VRSCversion")]
    pub version: String,
}

#[derive(Deserialize)]
pub(crate) struct RawCurrency<'a> {
    pub currencyid: String,
    pub name: String,
    #[serde(borrow)]
    pub idregistrationfees: &'a RawValue,
    pub idreferrallevels: u32,
    #[serde(borrow)]
    pub idimportfees: &'a RawValue,
    #[serde(borrow, default)]
    pub currencyregistrationfee: Option<&'a RawValue>,
    #[serde(default)]
    pub proofprotocol: u32,
}

impl RawCurrency<'_> {
    pub(crate) fn into_typed(self) -> Result<CurrencyPolicy, RpcError> {
        Ok(CurrencyPolicy {
            currency_id: self.currencyid,
            name: self.name,
            // Coins, not satoshis — see `json`.
            // The three identity/currency fees deliberately take the NATIVE
            // ceiling, not the per-currency one, even though a fee under a
            // token parent is denominated in that token. It is a sanity bar on
            // a number that gets burned, and a fee of a billion units is not a
            // fee — the flows refuse anything over 500 coins on the default
            // path anyway. Chosen, not overlooked: `currencybalance` and
            // `estimatedcurrencyout` below are the per-currency amounts.
            id_registration_fee: json::coins(self.idregistrationfees, "idregistrationfees")?,
            id_referral_levels: self.idreferrallevels,
            id_import_fee: json::coins(self.idimportfees, "idimportfees")?,
            currency_registration_fee: match self.currencyregistrationfee {
                Some(raw) => json::coins(raw, "currencyregistrationfee")?,
                None => Amount::ZERO,
            },
            proof_protocol: self.proofprotocol,
        })
    }
}

#[derive(Deserialize)]
pub(crate) struct RawConversionEstimate<'a> {
    #[serde(borrow)]
    pub estimatedcurrencyout: &'a RawValue,
}

impl RawConversionEstimate<'_> {
    pub(crate) fn into_typed(self) -> Result<ConversionEstimate, RpcError> {
        Ok(ConversionEstimate {
            // Coins, like every other human-facing amount the daemon prints.
            estimated_out: json::currency_coins(self.estimatedcurrencyout, "estimatedcurrencyout")?,
            fee: None,
        })
    }
}

#[derive(Deserialize)]
pub(crate) struct RawIdentity {
    pub fullyqualifiedname: String,
    pub status: String,
    pub txid: String,
    pub vout: u32,
    pub blockheight: u32,
    pub identity: serde_json::Value,
}

impl RawIdentity {
    pub(crate) fn into_typed(self) -> Result<IdentityRecord, RpcError> {
        // `unwrap_or_default` here would turn "the daemon didn't say" into an
        // empty string that reads exactly like a real identity address to
        // anything that string-compares it rather than parsing it — see the
        // `contentmap` reasoning in `identity_content` for the general shape
        // of the mistake. An honest daemon always sends this field, so its
        // absence is the reply itself being wrong, not a value to paper over.
        let identity_address = self
            .identity
            .get("identityaddress")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::Unexpected("identity has no identityaddress".to_string()))?
            .to_string();
        Ok(IdentityRecord {
            fully_qualified_name: self.fullyqualifiedname,
            identity_address,
            status: self.status,
            outpoint: (
                Txid::from_display_hex(&self.txid)
                    .map_err(|e| RpcError::OutOfRange(format!("txid: {e}")))?,
                self.vout,
            ),
            block_height: self.blockheight,
            identity: self.identity,
        })
    }
}

/// One element of `getidentitieswithaddress`'s reply.
///
/// The identity object itself, plus the `txout` that holds it. Deserialized
/// permissively — every field this does not name stays in `rest` — because the
/// daemon adds fields to identity objects across versions and a strict struct
/// would refuse a reply that is merely newer than this crate.
#[derive(Deserialize)]
pub(crate) struct RawIdentityAtAddress {
    pub identityaddress: String,
    pub name: String,
    #[serde(default)]
    pub parent: String,
    #[serde(default)]
    pub flags: u32,
    #[serde(default)]
    pub timelock: u32,
    pub txout: RawTxOut,
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

/// `getidentitieswithaddress` spells the outpoint differently from
/// `getidentity`: nested under `txout`, and `voutnum` rather than `vout`.
#[derive(Deserialize)]
pub(crate) struct RawTxOut {
    pub txid: String,
    pub voutnum: u32,
}

impl RawIdentityAtAddress {
    pub(crate) fn into_typed(self) -> Result<IdentityAtAddress, RpcError> {
        let outpoint = (
            Txid::from_display_hex(&self.txout.txid)
                .map_err(|e| RpcError::OutOfRange(format!("txout.txid: {e}")))?,
            self.txout.voutnum,
        );

        // Rebuilt rather than kept alongside, so `identity` is the whole object
        // exactly as `getidentity`'s inner field would be — which is what
        // `content_multimap` and `Timelock` both expect to be handed.
        let mut identity = self.rest;
        identity.insert(
            "identityaddress".into(),
            self.identityaddress.clone().into(),
        );
        identity.insert("name".into(), self.name.clone().into());
        identity.insert("parent".into(), self.parent.clone().into());
        identity.insert("flags".into(), self.flags.into());
        identity.insert("timelock".into(), self.timelock.into());

        Ok(IdentityAtAddress {
            identity_address: self.identityaddress,
            name: self.name,
            parent: self.parent,
            flags: self.flags,
            timelock: self.timelock,
            outpoint,
            identity: serde_json::Value::Object(identity),
        })
    }
}

fn hex_bytes(text: &str, field: &'static str) -> Result<Vec<u8>, RpcError> {
    hex::decode(text).map_err(|e| RpcError::OutOfRange(format!("{field}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at_height(height: u32) -> AddressUtxo {
        AddressUtxo {
            utxo: Utxo {
                txid: Txid::from_internal([0xaa; 32]),
                vout: 0,
                satoshis: Amount::from_sat(1_000),
                script_pubkey: vec![0x76],
            },
            address: "R…".to_string(),
            height,
            is_spendable: true,
        }
    }

    #[test]
    fn confirmations_count_the_block_itself() {
        assert_eq!(at_height(100).confirmations(100), 1);
        assert_eq!(at_height(100).confirmations(109), 10);
    }

    /// An immature coinbase builds, signs, and is rejected at broadcast. Filter
    /// it out rather than discovering that.
    #[test]
    fn an_immature_coinbase_is_not_spendable() {
        let utxos = [at_height(1_000)];
        // 50 confirmations, coinbase needs 100.
        assert!(spendable_at(&utxos, 1_049, &[1_000]).is_empty());
        assert_eq!(spendable_at(&utxos, 1_099, &[1_000]).len(), 1);
    }

    /// An ordinary output at the same height is spendable immediately.
    #[test]
    fn a_non_coinbase_output_is_spendable_at_once() {
        let utxos = [at_height(1_000)];
        assert_eq!(spendable_at(&utxos, 1_000, &[]).len(), 1);
    }

    #[test]
    fn the_nodes_unspendable_flag_is_honoured() {
        let mut utxo = at_height(1_000);
        utxo.is_spendable = false;
        assert!(spendable_at(&[utxo], 2_000, &[]).is_empty());
    }
}
