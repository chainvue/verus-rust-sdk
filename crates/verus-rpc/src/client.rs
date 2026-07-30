//! The client, and the split between asking and telling.

use serde_json::json;
use verus_tx::Amount;

use crate::envelope::{parse, request, result_of};
use crate::error::RpcError;
use crate::method::Method;
use crate::transport::Transport;
use crate::types::{
    AddressBalance, AddressUtxo, ChainInfo, ConversionEstimate, CurrencyPolicy, IdentityRecord,
    RawAddressBalance, RawAddressUtxo, RawChainInfo, RawConversionEstimate, RawCurrency,
    RawIdentity,
};

/// Asking a node questions.
///
/// Everything here is read-only. A function taking `&impl ChainReader` and
/// nothing else **cannot broadcast** — that is a signature rather than a
/// comment, and it makes a dry-run mode compiler-enforced.
///
/// # Implementing this yourself
///
/// Deliberately not sealed. Implementing it does not let anything new reach a
/// node — it lets you *supply answers*, and what this crate can send is governed
/// by [`RequestBody`](crate::RequestBody) and its private method enum, neither
/// of which this trait touches. Sealing it would only block the useful cases: a
/// reader backed by your own indexer, one that caches, one that asks three nodes
/// and compares, or a scripted one in a test.
///
/// What you take on is that callers believe your answers. A reader that
/// under-reports UTXOs makes spending fail; one that misreports chain policy can
/// cost a name-commitment fee. The same is true of any node, which is why
/// [the crate docs](crate) treat answers as untrusted regardless of where they
/// came from.
pub trait ChainReader {
    /// Name, chain id, height and version.
    fn chain_info(&self) -> Result<ChainInfo, RpcError>;
    /// Height of the best block.
    fn block_count(&self) -> Result<u32, RpcError>;
    /// Hash of the best block. Used to notice a reorg under a pending operation.
    fn best_block_hash(&self) -> Result<String, RpcError>;
    /// Hash of the block at `height`.
    ///
    /// The other half of reorg detection: a pending operation records the hash
    /// at the height it saw, and a different hash later at that same height
    /// means the chain moved underneath it.
    fn block_hash(&self, height: u32) -> Result<String, RpcError>;
    /// A block, by height or by hash.
    ///
    /// Carries the block's transaction ids and its `finalsaplingroot`, which
    /// together are what a shielded witness would be built from.
    ///
    /// **Always sent with exactly one argument, and that is not cosmetic.** The
    /// allowlist in front of `api.verustest.net` is arity-sensitive: this method
    /// with a verbosity argument is refused as `-32601`, which reads as "the
    /// node does not have it". It does. Adding a second parameter here would
    /// break the call against public infrastructure while working perfectly
    /// against a local daemon.
    fn block(&self, height_or_hash: &str) -> Result<serde_json::Value, RpcError>;
    /// Unspent outputs at these addresses.
    ///
    /// Asking about several addresses in one call tells the node they belong
    /// together, irreversibly and in its logs. Ask separately when that linkage
    /// matters more than the round trip.
    fn address_utxos(&self, addresses: &[&str]) -> Result<Vec<AddressUtxo>, RpcError>;
    /// What these addresses hold, native and per-currency.
    ///
    /// Cheaper than [`ChainReader::address_utxos`] when only a total is wanted,
    /// and it is the total *including* immature coinbase — a balance is not the
    /// spendable amount. Select from UTXOs for that.
    fn address_balance(&self, addresses: &[&str]) -> Result<AddressBalance, RpcError>;
    /// Registration policy for a currency: the fee, referral levels and
    /// proofprotocol a registration under it needs.
    fn currency(&self, name_or_id: &str) -> Result<CurrencyPolicy, RpcError>;
    /// What a conversion is expected to yield.
    ///
    /// Ask before signing, and treat the answer as advisory: the conversion runs
    /// at the price when it is imported, and no part of the transaction commits
    /// to this number.
    fn estimate_conversion(
        &self,
        from: &str,
        to: &str,
        amount: &str,
        via: Option<&str>,
    ) -> Result<ConversionEstimate, RpcError>;
    /// The current reserves, weights and prices of a fractional currency.
    fn currency_state(&self, name_or_id: &str) -> Result<serde_json::Value, RpcError>;
    /// A VerusID, including the output that holds it.
    fn identity(&self, name_or_id: &str) -> Result<IdentityRecord, RpcError>;
    /// A VerusID **as it stood at `height`**.
    ///
    /// An identity's controlling addresses can change, so verifying a signature
    /// against today's identity answers a different question from verifying it
    /// against the identity that existed when the signature was made. A signed
    /// message carries the height for exactly this reason.
    ///
    /// Sent as two arguments and no more: the allowlist in front of
    /// `api.verustest.net` is arity-sensitive, and a third argument is refused
    /// as `-32601` — see [the crate docs](crate).
    fn identity_at(&self, name_or_id: &str, height: u32) -> Result<IdentityRecord, RpcError>;
    /// The VDXF key a content name resolves to.
    ///
    /// Returns the 20-byte key, in the order a content map stores it.
    ///
    /// **This needs a node, and that is a real limitation.** The derivation is
    /// public and deterministic — and since `verus_tx::vdxf` it IS computable
    /// offline, ported from the daemon's own derivation. This remains as the
    /// oracle: the live suite locks the local derivation against it, and a
    /// caller who wants the node's opinion can still ask.
    ///
    /// Two things to know about the answer:
    ///
    /// * A **bare** name resolves against the node's own chain, so `"profile"`
    ///   means different keys on VRSC and VRSCTEST. A `vrsc::`-qualified name
    ///   names its namespace and gives the same key everywhere — prefer it.
    /// * The daemon prints `hash160result` byte-**reversed** relative to the
    ///   `vdxfid` address, the same convention as a txid. This returns the key
    ///   in `vdxfid` order.
    fn vdxf_id(&self, name: &str) -> Result<[u8; 20], RpcError>;
    /// Ask the node whether a signed message checks out.
    ///
    /// **A cross-check, not the primary path.** `verus_tx::signature` verifies
    /// locally, which needs no network and cannot be lied to; this asks a third
    /// party the same question. Useful to confirm interoperability, or as a
    /// second opinion when a local check fails unexpectedly.
    ///
    /// Read-only, and no key is involved: verification uses public data.
    fn verify_message(
        &self,
        identity: &str,
        signature: &str,
        message: &str,
    ) -> Result<bool, RpcError>;
    /// A transaction, decoded, as JSON.
    fn raw_transaction(&self, txid: &str) -> Result<serde_json::Value, RpcError>;
    /// Parse a transaction the node has never seen, without submitting it.
    ///
    /// A read, despite taking a transaction: the node only decodes the bytes —
    /// it does not check that the inputs exist, does not relay, and does not
    /// keep it. The way to look at what a builder produced before committing to
    /// broadcasting it.
    ///
    /// It does reveal the transaction to that node ahead of time, which for a
    /// public endpoint means before it is on chain.
    fn decode_raw_transaction(&self, hex: &str) -> Result<serde_json::Value, RpcError>;
    /// How many confirmations a transaction has, or `None` if the node has
    /// never seen it.
    fn confirmations(&self, txid: &str) -> Result<Option<u32>, RpcError>;
}

/// Handing a node bytes that were already signed.
///
/// The only capability in this crate that changes anything anywhere. Not sealed,
/// for the reasons given on [`ChainReader`] — a queue, a relay of your own, or a
/// test double are all legitimate.
pub trait Broadcaster {
    /// Submit a signed transaction and return its id.
    ///
    /// **Never retry this automatically.** A transport failure is ambiguous —
    /// the node may well have accepted and relayed it — so a blind resend risks
    /// a second broadcast of a transaction that is already propagating. On a
    /// transport failure, re-read with [`ChainReader::confirmations`] and decide.
    fn send_raw_transaction(&self, hex: &str) -> Result<String, RpcError>;
}

/// A Verus daemon reached over JSON-RPC.
///
/// Read the crate docs for what this deliberately cannot do.
pub struct RpcClient<T> {
    transport: T,
}

impl<T: Transport> RpcClient<T> {
    /// Wrap a transport.
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// The transport underneath.
    ///
    /// For a caller that needs to inspect its own implementation — a request
    /// counter, a rate limiter, a recorded log. It does not widen what can be
    /// sent: a [`crate::RequestBody`] still cannot be composed from outside.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Send one request and hand back the parsed result.
    ///
    /// Private, and takes a [`Method`] rather than a string, so the set of
    /// requests this crate can emit is the set of variants of that enum.
    fn call<R>(&self, method: Method, params: serde_json::Value) -> Result<R, RpcError>
    where
        R: serde::de::DeserializeOwned,
    {
        let body = self.transport.post(&request(method, params)?)?;
        let result = result_of(&body, method)?;
        parse(result, method.name())
    }

    /// As [`RpcClient::call`], but keeping the raw text so money fields can be
    /// read from their original tokens.
    fn call_raw(&self, method: Method, params: serde_json::Value) -> Result<String, RpcError> {
        self.transport.post(&request(method, params)?)
    }
}

impl<T: Transport> ChainReader for RpcClient<T> {
    fn chain_info(&self) -> Result<ChainInfo, RpcError> {
        let raw: RawChainInfo = self.call(Method::GetInfo, json!([]))?;
        Ok(ChainInfo {
            name: raw.name,
            chain_id: raw.chainid,
            blocks: raw.blocks,
            longest_chain: raw.longestchain,
            version: raw.version,
        })
    }

    fn block_count(&self) -> Result<u32, RpcError> {
        self.call(Method::GetBlockCount, json!([]))
    }

    fn best_block_hash(&self) -> Result<String, RpcError> {
        let hash: String = self.call(Method::GetBestBlockHash, json!([]))?;
        check_hash(&hash, "getbestblockhash")
    }

    fn block_hash(&self, height: u32) -> Result<String, RpcError> {
        let hash: String = self.call(Method::GetBlockHash, json!([height]))?;
        check_hash(&hash, "getblockhash")
    }

    fn block(&self, height_or_hash: &str) -> Result<serde_json::Value, RpcError> {
        // A height is sent as a number and a hash as a string; the daemon
        // accepts either, but not a height quoted as a string.
        let key = match height_or_hash.parse::<u64>() {
            Ok(height) => json!(height),
            Err(_) => json!(height_or_hash),
        };
        self.call(Method::GetBlock, json!([key]))
    }

    fn address_utxos(&self, addresses: &[&str]) -> Result<Vec<AddressUtxo>, RpcError> {
        let body = self.call_raw(Method::GetAddressUtxos, json!([{ "addresses": addresses }]))?;
        let result = result_of(&body, Method::GetAddressUtxos)?;
        let raw: Vec<RawAddressUtxo<'_>> = serde_json::from_str(result.get())
            .map_err(|e| RpcError::Unexpected(format!("getaddressutxos: {e}")))?;

        let found: Vec<AddressUtxo> = raw
            .into_iter()
            .map(RawAddressUtxo::into_typed)
            .collect::<Result<_, _>>()?;

        // A node could answer with an output belonging to some other address.
        // The sighash commits to the script, so a substituted one only produces
        // a rejected transaction — but failing here names the cause.
        for utxo in &found {
            if !addresses.contains(&utxo.address.as_str()) {
                return Err(RpcError::Unexpected(format!(
                    "node returned an output for {}, which was not asked about",
                    utxo.address
                )));
            }
        }
        Ok(found)
    }

    fn address_balance(&self, addresses: &[&str]) -> Result<AddressBalance, RpcError> {
        let body = self.call_raw(
            Method::GetAddressBalance,
            json!([{ "addresses": addresses }]),
        )?;
        let result = result_of(&body, Method::GetAddressBalance)?;
        let raw: RawAddressBalance<'_> = serde_json::from_str(result.get())
            .map_err(|e| RpcError::Unexpected(format!("getaddressbalance: {e}")))?;
        raw.into_typed()
    }

    fn currency(&self, name_or_id: &str) -> Result<CurrencyPolicy, RpcError> {
        let body = self.call_raw(Method::GetCurrency, json!([name_or_id]))?;
        let result = result_of(&body, Method::GetCurrency)?;
        let raw: RawCurrency<'_> = serde_json::from_str(result.get())
            .map_err(|e| RpcError::Unexpected(format!("getcurrency: {e}")))?;
        raw.into_typed()
    }

    fn estimate_conversion(
        &self,
        from: &str,
        to: &str,
        amount: &str,
        via: Option<&str>,
    ) -> Result<ConversionEstimate, RpcError> {
        // The amount is passed as the caller's exact decimal text, not a float
        // built from it — the same reason money is read back through `json`.
        let amount: serde_json::Value =
            serde_json::from_str(amount).map_err(|_| RpcError::LossyNumber {
                field: "amount",
                value: amount.to_string(),
            })?;
        let mut request = json!({ "currency": from, "convertto": to, "amount": amount });
        if let Some(via) = via {
            request["via"] = json!(via);
        }
        let body = self.call_raw(Method::EstimateConversion, json!([request]))?;
        let result = result_of(&body, Method::EstimateConversion)?;
        let raw: RawConversionEstimate<'_> = serde_json::from_str(result.get())
            .map_err(|e| RpcError::Unexpected(format!("estimateconversion: {e}")))?;
        raw.into_typed()
    }

    fn currency_state(&self, name_or_id: &str) -> Result<serde_json::Value, RpcError> {
        self.call(Method::GetCurrencyState, json!([name_or_id]))
    }

    fn identity(&self, name_or_id: &str) -> Result<IdentityRecord, RpcError> {
        let raw: RawIdentity = self.call(Method::GetIdentity, json!([name_or_id]))?;
        raw.into_typed()
    }

    fn identity_at(&self, name_or_id: &str, height: u32) -> Result<IdentityRecord, RpcError> {
        let raw: RawIdentity = self.call(Method::GetIdentity, json!([name_or_id, height]))?;
        raw.into_typed()
    }

    fn vdxf_id(&self, name: &str) -> Result<[u8; 20], RpcError> {
        let answer: serde_json::Value = self.call(Method::GetVdxfId, json!([name]))?;
        let printed = answer["hash160result"]
            .as_str()
            .ok_or_else(|| RpcError::Unexpected("getvdxfid returned no hash160result".into()))?;
        let mut bytes: [u8; 20] = hex::decode(printed)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| {
                RpcError::Unexpected(format!("getvdxfid returned {printed:?}, not 20 bytes"))
            })?;
        // Printed in display order, like a txid. Reversed here so the caller
        // gets what a content map actually holds.
        bytes.reverse();
        Ok(bytes)
    }

    fn verify_message(
        &self,
        identity: &str,
        signature: &str,
        message: &str,
    ) -> Result<bool, RpcError> {
        self.call(Method::VerifyMessage, json!([identity, signature, message]))
    }

    fn raw_transaction(&self, txid: &str) -> Result<serde_json::Value, RpcError> {
        self.call(Method::GetRawTransaction, json!([txid, 1]))
    }

    fn decode_raw_transaction(&self, hex: &str) -> Result<serde_json::Value, RpcError> {
        self.call(Method::DecodeRawTransaction, json!([hex]))
    }

    fn confirmations(&self, txid: &str) -> Result<Option<u32>, RpcError> {
        match self.raw_transaction(txid) {
            Ok(tx) => Ok(Some(
                tx.get("confirmations")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|n| u32::try_from(n).ok())
                    .unwrap_or(0),
            )),
            // The node has never seen it. That is an answer, not a failure.
            Err(RpcError::Node { code: -5, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl<T: Transport> Broadcaster for RpcClient<T> {
    fn send_raw_transaction(&self, hex: &str) -> Result<String, RpcError> {
        let txid: String = self.call(Method::SendRawTransaction, json!([hex]))?;
        // A broadcast's return value is the handle the caller uses to ask
        // whether the payment landed. Accepting anything string-shaped means a
        // node can hand back a txid that will never be found, and the caller
        // polls a payment that looks permanently unconfirmed instead of
        // reporting a broken node.
        check_hash(&txid, "sendrawtransaction")
    }
}

/// A 32-byte hash, as a daemon prints one.
///
/// Not decoded into a [`verus_tx::Txid`]: callers hand these straight back to
/// the node as strings, and re-encoding would only add a place to get the byte
/// order wrong. Checked, not merely accepted.
fn check_hash(hash: &str, what: &'static str) -> Result<String, RpcError> {
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(RpcError::Unexpected(format!(
            "{what} returned {hash:?}, which is not a 32-byte hash"
        )));
    }
    Ok(hash.to_string())
}

/// The fee a registration under this currency costs, split the way consensus
/// splits it.
///
/// A convenience over [`ChainReader::currency`], kept here rather than in a flow
/// so a caller can see the numbers before committing to anything.
pub fn registration_cost(policy: &CurrencyPolicy, referred: bool) -> (Amount, Amount) {
    let fees = verus_tx::register::registration_fees(
        policy.id_registration_fee,
        policy.id_referral_levels,
        referred,
    );
    (fees.outlay, fees.referral_amount)
}
