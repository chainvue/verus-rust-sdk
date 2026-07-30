//! What a node's answers look like once they are typed.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::value::RawValue;
use verus_tx::{Amount, Txid, Utxo};

use crate::error::RpcError;
use crate::json;

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
            currency_balance.insert(currency, json::coins(raw, "currencybalance")?);
        }
        Ok(AddressBalance {
            balance: json::satoshis(self.balance, "balance")?,
            received: json::satoshis(self.received, "received")?,
            currency_balance,
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
            estimated_out: json::coins(self.estimatedcurrencyout, "estimatedcurrencyout")?,
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
