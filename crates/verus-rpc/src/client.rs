//! The client, and the split between asking and telling.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::json;
use serde_json::value::RawValue;
use verus_tx::Amount;

use crate::envelope::{parse, request, result_of};
use crate::error::RpcError;
use crate::json;
use crate::method::Method;
use crate::transport::Transport;
use crate::types::{
    AddressBalance, AddressDelta, AddressUtxo, ChainInfo, ConversionEstimate, CurrencyPolicy,
    IdentityRecord, OfferListing, RawAddressBalance, RawAddressDelta, RawAddressUtxo, RawChainInfo,
    RawConversionEstimate, RawCurrency, RawIdentity, RawOfferEntry,
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
    /// Every movement of value at these addresses.
    ///
    /// This is what a transaction list is built from, and it is the one thing
    /// [`ChainReader::address_utxos`] cannot give you: a UTXO set is the
    /// present tense. An output that was received and later spent has no UTXO
    /// at all, so a wallet showing only unspent outputs shows a history with
    /// every completed payment missing.
    ///
    /// Ordering is the daemon's: ascending **within** each address, with the
    /// addresses concatenated. It is deliberately not described as oldest-first
    /// overall, because for more than one address it is not. Sort, or use
    /// `verus_flows::history`, which does.
    ///
    /// `range` bounds the search to `(start, end)` heights inclusive, and both
    /// must be **greater than zero** — the daemon answers `-5, "Start and end
    /// is expected to be greater than zero"` otherwise. `None` asks for the
    /// whole chain, which on a busy address is a large reply; the transport's
    /// size ceiling applies, so page with explicit ranges rather than
    /// discovering it.
    ///
    /// **Two rows per output over its lifetime**, positive when created and
    /// negative when spent, and a token output reports `satoshis` of zero with
    /// the value in `currency_values`. Both are why `verus_flows::history`
    /// exists rather than a caller folding these by hand.
    ///
    /// Needs the node's address index. A node without one answers with an
    /// error rather than an empty list.
    fn address_deltas(
        &self,
        addresses: &[&str],
        range: Option<(u32, u32)>,
    ) -> Result<Vec<AddressDelta>, RpcError>;
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
    /// The transaction that first created this identity — its registration.
    ///
    /// **Not the same as [`ChainReader::identity`]'s outpoint**, which tracks
    /// the identity's *current* output and moves with every update. Only the
    /// first one carries the registration's referral payouts, which is why
    /// this exists: consensus determines the referral chain a new registration
    /// must pay by walking its referrer's registration transaction, so a
    /// referred registration cannot be built correctly without it.
    fn identity_registration(&self, name_or_id: &str) -> Result<String, RpcError>;

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
    /// Offers standing against a currency or an identity.
    ///
    /// The half of the marketplace this SDK could not reach. `make_offer` and
    /// `take_offer` have worked since the swap settled on chain, but there was
    /// no way to *find* an offer — so an application could complete a trade it
    /// had been handed and could not show a user what was for sale.
    ///
    /// `is_currency` says how to read `currency_or_id`, and getting it wrong is
    /// not a near miss: a currency's i-address asked for as an identity comes
    /// back as an empty result rather than an error, which reads exactly like
    /// "nothing is for sale". A **name** is only ever accepted as an identity —
    /// `"VRSC"` is refused with `-8`, `"iJhCez…"` with `is_currency` works.
    ///
    /// `with_tx` adds the maker's signed half-transaction to each listing. It
    /// costs a much larger reply and is what makes a listing actionable:
    /// `verus_flows::offer::inspect` takes exactly those bytes.
    ///
    /// Listings arrive grouped by direction, and the grouping is kept on each
    /// listing rather than flattened away — see [`OfferListing::bucket`].
    fn offers(
        &self,
        currency_or_id: &str,
        is_currency: bool,
        with_tx: bool,
    ) -> Result<Vec<OfferListing>, RpcError>;
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
    ///
    /// Generic over `P` rather than fixed to `serde_json::Value`, so a caller
    /// with an exact decimal amount can hand over a `RawValue` and have it
    /// serialize verbatim — see [`crate::envelope::request`].
    fn call<R, P: Serialize>(&self, method: Method, params: P) -> Result<R, RpcError>
    where
        R: serde::de::DeserializeOwned,
    {
        let body = self.transport.post(&request(method, params)?)?;
        let result = result_of(&body, method)?;
        parse(result, method.name())
    }

    /// As [`RpcClient::call`], but keeping the raw text so money fields can be
    /// read from their original tokens.
    fn call_raw<P: Serialize>(&self, method: Method, params: P) -> Result<String, RpcError> {
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
        //
        // A node could also repeat the same outpoint — once legitimately and
        // once more, whether from a buggy index or a deliberate attempt to
        // inflate what a caller thinks it can spend. Coin selection would
        // count that value twice; catching it here names the outpoint instead
        // of surfacing as an opaque `DuplicateUtxo` from the builder.
        let mut seen = std::collections::HashSet::with_capacity(found.len());
        for utxo in &found {
            if !addresses.contains(&utxo.address.as_str()) {
                return Err(RpcError::Unexpected(format!(
                    "node returned an output for {}, which was not asked about",
                    utxo.address
                )));
            }
            if !seen.insert((utxo.utxo.txid, utxo.utxo.vout)) {
                return Err(RpcError::Unexpected(format!(
                    "node returned the outpoint {}:{} more than once",
                    utxo.utxo.txid.to_display_hex(),
                    utxo.utxo.vout
                )));
            }
        }
        Ok(found)
    }

    fn address_deltas(
        &self,
        addresses: &[&str],
        range: Option<(u32, u32)>,
    ) -> Result<Vec<AddressDelta>, RpcError> {
        let params = match range {
            Some((start, end)) => {
                json!([{ "addresses": addresses, "start": start, "end": end }])
            }
            // Omitted rather than sent as 0/0. The daemon *refuses* a zero
            // bound outright — `-5, "Start and end is expected to be greater
            // than zero"`, confirmed against `api.verustest.net` — so an
            // absent range is the only way to ask for the whole chain.
            None => json!([{ "addresses": addresses }]),
        };
        let body = self.call_raw(Method::GetAddressDeltas, params)?;
        let result = result_of(&body, Method::GetAddressDeltas)?;
        let raw: Vec<RawAddressDelta<'_>> = serde_json::from_str(result.get())
            .map_err(|e| RpcError::Unexpected(format!("getaddressdeltas: {e}")))?;

        let deltas: Vec<AddressDelta> = raw
            .into_iter()
            .map(RawAddressDelta::into_typed)
            .collect::<Result<_, _>>()?;

        // Same check as `address_utxos`, and it matters more here: a delta for
        // an address nobody asked about would be folded into a balance-like
        // total by any caller summing these, with nothing downstream to catch
        // it. A transaction is not being built, so no sighash rejects it later.
        //
        // The repeat check is the same idea: a row duplicated by a buggy index
        // or a hostile one inflates every total folded from these.
        //
        // **The address is part of the key, and leaving it out was a bug.** The
        // daemon's index is keyed per address, so uniqueness only holds within
        // one. A single output can be indexed under several addresses at once —
        // a CryptoCondition output with more than one destination, or an
        // identity's `i` address alongside a primary `R` address — and asking
        // about two of them returns two rows agreeing on `(txid, spending,
        // index)` and differing only here. Keyed without the address, a wallet
        // that owns such an output could never fetch its history at all.
        //
        // What was actually checked against the live index is narrower than the
        // earlier comment claimed: 87 rows over three addresses that share no
        // output, so 87 distinct triples. That shows those addresses do not
        // collide; it says nothing about addresses that do.
        let mut seen = std::collections::HashSet::with_capacity(deltas.len());
        for delta in &deltas {
            if !addresses.contains(&delta.address.as_str()) {
                return Err(RpcError::Unexpected(format!(
                    "node returned a delta for {}, which was not asked about",
                    delta.address
                )));
            }
            if !seen.insert((
                delta.address.as_str(),
                delta.txid,
                delta.spending,
                delta.index,
            )) {
                return Err(RpcError::Unexpected(format!(
                    "node returned the delta {}:{} ({}) for {} more than once",
                    delta.txid.to_display_hex(),
                    delta.index,
                    if delta.spending { "spend" } else { "receive" },
                    delta.address
                )));
            }
        }
        Ok(deltas)
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
        // The comment this replaced claimed the amount was "not a float built
        // from JSON" — that was wrong. `serde_json::Value` without the
        // `arbitrary_precision` feature stores any number with a decimal point
        // as `f64`, so parsing the caller's text into a `Value` and handing it
        // to `json!` *was* the float path this workspace bans:
        // `100000000.00000001` round-tripped to `100000000.0`, silently
        // dropping a satoshi, and `-5`, `1e30`, `"abc"` and `{"a":1}` all
        // parsed as *some* `Value` and passed through unvalidated.
        //
        // Fixed the way every other money field in this crate is read: keep
        // the caller's token text as a `RawValue` and validate it exactly
        // through `json::coins`, which parses via `Amount::from_coins_str` and
        // refuses negative, exponent, sub-satoshi and out-of-range input.
        //
        // `currency_coins`, not `coins`: this amount is denominated in `from`,
        // which is whatever currency the caller is converting OUT of, not the
        // chain's own. Bounding it at the native ceiling would refuse an
        // ordinary two-billion-unit amount of a large-supply token that the
        // daemon would price happily — the same over-refusal the two ceilings
        // exist to separate, and easy to miss because the reply side
        // (`estimatedcurrencyout`) needs the identical treatment. The validated amount is re-emitted through
        // `Amount::to_coins_string()` — proven to round-trip exactly by
        // `verus_tx::amount`'s own test — as a `RawValue`, so what reaches the
        // wire is that exact decimal text and never a `serde_json::Number`.
        let raw_input =
            RawValue::from_string(amount.to_string()).map_err(|_| RpcError::LossyNumber {
                field: "amount",
                value: amount.to_string(),
            })?;
        let exact = json::currency_coins(&raw_input, "amount")?;
        let raw_amount = RawValue::from_string(exact.to_coins_string())
            .expect("Amount::to_coins_string always produces a valid JSON number");

        #[derive(Serialize)]
        struct EstimateConversionParams<'a> {
            currency: &'a str,
            convertto: &'a str,
            amount: &'a RawValue,
            #[serde(skip_serializing_if = "Option::is_none")]
            via: Option<&'a str>,
        }
        let params = [EstimateConversionParams {
            currency: from,
            convertto: to,
            amount: &raw_amount,
            via,
        }];

        let body = self.call_raw(Method::EstimateConversion, params)?;
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

    fn identity_registration(&self, name_or_id: &str) -> Result<String, RpcError> {
        let answer: serde_json::Value =
            self.call(Method::GetIdentityHistory, json!([name_or_id]))?;
        // `history` is ordered oldest first; entry zero is the registration.
        let txid = answer["history"][0]["output"]["txid"]
            .as_str()
            .ok_or_else(|| {
                RpcError::Unexpected(format!(
                    "getidentityhistory for {name_or_id} has no first output"
                ))
            })?;
        check_hash(txid, "getidentityhistory")
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

    fn offers(
        &self,
        currency_or_id: &str,
        is_currency: bool,
        with_tx: bool,
    ) -> Result<Vec<OfferListing>, RpcError> {
        // Three arguments, and the allowlist in front of `api.verustest.net`
        // serves all three — unlike `getblock`, where a second argument is
        // refused. Checked rather than assumed, because that trap has cost this
        // project a wrong availability table once already.
        let body = self.call_raw(
            Method::GetOffers,
            json!([currency_or_id, is_currency, with_tx]),
        )?;
        let result = result_of(&body, Method::GetOffers)?;

        // The reply is an object whose *keys are data*: one bucket per
        // direction, named after the currencies involved. There is no fixed set
        // of them, so it is read as a map and the key carried through.
        let buckets: BTreeMap<String, Vec<RawOfferEntry<'_>>> = serde_json::from_str(result.get())
            .map_err(|e| RpcError::Unexpected(format!("getoffers: {e}")))?;

        // Same posture as the other readers: a repeated row inflates whatever
        // is folded from the answer. Here that is a marketplace listing, so a
        // funding outpoint appearing twice within one bucket shows the same
        // offer twice and makes a thin market look deep.
        //
        // Keyed per bucket, because the buckets are directions: one outpoint
        // legitimately appears in both the currency-for-identity and
        // identity-for-currency views of the same trade.
        let mut listings = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (bucket, entries) in buckets {
            for entry in entries {
                let listing = entry.into_typed(&bucket)?;
                if !seen.insert((bucket.clone(), listing.funding_txid)) {
                    return Err(RpcError::Unexpected(format!(
                        "node listed the offer funded by {} twice under {bucket}",
                        listing.funding_txid.to_display_hex()
                    )));
                }
                listings.push(listing);
            }
        }
        Ok(listings)
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
    // Lowercased for the same reason `verus_light::LightClient::txid_from_reply`
    // is: hex case carries no information, but a caller compares this against
    // a hash from elsewhere with `==` — a reorg check against a stored block
    // hash, a caller matching a broadcast's txid against its own record — and
    // a node that happens to answer in uppercase would otherwise fail that
    // comparison against every other source, which normalises to lowercase.
    Ok(hash.to_ascii_lowercase())
}

/// The fee a registration under this currency costs, split the way consensus
/// splits it.
///
/// A convenience over [`ChainReader::currency`], kept here rather than in a flow
/// so a caller can see the numbers before committing to anything.
///
/// # When the node's numbers are not believable
///
/// `idreferrallevels` comes from the node. If it is implausible enough that
/// the split cannot be computed honestly, this reports the **unreferred**
/// outcome — the whole fee burned, nobody paid — rather than a wrapped or
/// invented figure. That is deliberately the conservative direction for a
/// preview: it can only overstate what the caller pays.
///
/// Note the asymmetry it creates. A registration attempted with those same
/// numbers does not degrade — it is *refused* before anything is broadcast.
/// So a preview showing the full fee where a referral was expected means the
/// node reported something the SDK will not act on; treat it as a signal to
/// check the node, not as a quote to accept.
pub fn registration_cost(policy: &CurrencyPolicy, referred: bool) -> (Amount, Amount) {
    let fees = verus_tx::register::registration_fees(
        policy.id_registration_fee,
        policy.id_referral_levels,
        referred,
    );
    (fees.outlay, fees.referral_amount)
}
