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
        let identity_address = self
            .identity
            .get("identityaddress")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
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
