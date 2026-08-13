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
    converter_from_entry, AddressBalance, AddressDelta, AddressUtxo, ChainInfo, ContentValue,
    ConversionEstimate, CurrencyConverter, CurrencyPolicy, CurrencySummary, IdentityAtAddress,
    IdentityContent, IdentityRecord, MempoolDelta, OfferListing, RawAddressBalance,
    RawAddressDelta, RawAddressUtxo, RawChainInfo, RawConversionEstimate, RawCurrency,
    RawCurrencyEntry, RawIdentity, RawIdentityAtAddress, RawMempoolDelta, RawOfferEntry,
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
    /// Transaction ids the node currently holds in its mempool.
    ///
    /// The one thing a UTXO set and a delta list both leave out: a payment that
    /// has been broadcast and not yet mined. Without it, a wallet can only
    /// learn that its own outgoing transaction is alive by polling
    /// [`ChainReader::confirmations`] for each txid it is waiting on — one
    /// request per transaction, forever, against a node that could have
    /// answered once.
    ///
    /// **Asked with no arguments first.** `getrawmempool` takes an optional
    /// verbosity flag, and `api.verustest.net` refuses the method outright when
    /// one is present — the same arity-sensitive proxy that refuses `getblock`
    /// with a verbosity argument, pointing the other way. Only if that is
    /// refused as `-32601` is `[false]` tried, which is the same question: a
    /// Verus daemon answers `getrawmempool` and `getrawmempool false`
    /// identically (measured 2026-08-03). The ids are what a wallet needs
    /// anyway; the *verbose* form's fee and dependency data is a different
    /// question and is not asked here.
    ///
    /// Ids are lowercased and checked, and a repeated one is refused — see
    /// [the crate docs](crate) on treating a node's answers as untrusted.
    ///
    /// An empty list is a real answer: it means nothing is pending, not that
    /// the node declined.
    fn mempool(&self) -> Result<Vec<String>, RpcError>;
    /// A block, by height or by hash.
    ///
    /// Carries the block's transaction ids and its `finalsaplingroot`, which
    /// together are what a shielded witness would be built from.
    ///
    /// **Sent with exactly one argument first, and that is not cosmetic.** The
    /// allowlist in front of `api.verustest.net` is arity-sensitive: this
    /// method with a verbosity argument is refused as `-32601`, which reads as
    /// "the node does not have it". It does. Leading with two parameters would
    /// break the call against public infrastructure while working perfectly
    /// against a local daemon.
    ///
    /// A `[height_or_hash, 1]` form is sent **only after** the one-argument
    /// call has been refused as `-32601`, so the call that works against public
    /// infrastructure is byte-for-byte what it always was. Verbosity 1 is the
    /// daemon's own default for this method, so the fallback is the same
    /// question: `getblock <h>` and `getblock <h> 1` were measured
    /// byte-identical against a VRSCTEST daemon on 2026-08-03. Verbosity **0**
    /// is a different question — it answers with the block as hex — and is
    /// deliberately never sent.
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
    /// Movements at these addresses that are in the mempool and not yet mined.
    ///
    /// The present-tense companion to [`ChainReader::address_deltas`]: the same
    /// question on the other side of the confirmation line. Every other address
    /// read here is about settled state —
    /// [`address_utxos`](ChainReader::address_utxos) and
    /// [`address_balance`](ChainReader::address_balance) exclude the mempool,
    /// and `address_deltas` reports only what is mined — so without this a
    /// wallet answers "0" for an address that has demonstrably just been paid,
    /// for as long as it takes to mine a block.
    ///
    /// The alternative is [`mempool`](ChainReader::mempool) followed by one
    /// [`raw_transaction`](ChainReader::raw_transaction) per txid, scanning
    /// outputs: O(mempool) round trips to learn about one address. This is one.
    ///
    /// # None of it is settled
    ///
    /// Answers describe **one node's** mempool at one instant. A transaction
    /// here may be mined, evicted or never seen by a second node. Show it as
    /// pending; do not let it decide what can be spent — `address_utxos` is
    /// still the answer to that, and still excludes all of this. Nothing in
    /// `verus-flows` funds a transaction from these rows.
    ///
    /// # Sent with one argument, and `verbosity` is deliberately not among them
    ///
    /// One positional object. A second positional argument is refused as
    /// `-32601` by the proxy in front of `api.verustest.net` — the same
    /// arity-sensitivity that makes [`block`](ChainReader::block) and
    /// [`mempool`](ChainReader::mempool) ask the way they do, measured again for
    /// this method on 2026-08-05.
    ///
    /// The daemon's help describes a `verbosity` option as adding "output
    /// information for spends, including all reserve amounts and destinations",
    /// which reads as though it were the switch for per-currency values. It is
    /// not: `currencyvalues` arrives in the plain reply, measured against a live
    /// pending transaction on 2026-08-05 and recorded in
    /// `fixtures/rpc/getaddressmempool_vrsctest.json`. What `verbosity: 1` adds
    /// is a `sent` object on spend rows, naming the *other* addresses a spent
    /// output paid. That is information about someone else's outputs, it is not
    /// needed to see that money is moving, and asking for it would make every
    /// reply larger and the request one option further from the shape that is
    /// known to pass the proxy. So it is not sent.
    ///
    /// # Needs the node's address index
    ///
    /// Like every other address method here. A node without one answers with an
    /// error rather than an empty list — and an empty list is a real answer,
    /// meaning nothing is pending for these addresses.
    fn address_mempool(&self, addresses: &[&str]) -> Result<Vec<MempoolDelta>, RpcError>;
    /// What these addresses hold, native and per-currency.
    ///
    /// Cheaper than [`ChainReader::address_utxos`] when only a total is wanted,
    /// and it is the total *including* immature coinbase — a balance is not the
    /// spendable amount. Select from UTXOs for that.
    ///
    /// **Excludes the mempool.** An address that has just been paid still
    /// reports the old figure; see [`ChainReader::address_mempool`].
    fn address_balance(&self, addresses: &[&str]) -> Result<AddressBalance, RpcError>;
    /// Registration policy for a currency: the fee, referral levels and
    /// proofprotocol a registration under it needs.
    ///
    /// This is the *policy* view — what it costs to register under this
    /// currency. For what the currency **is**, see
    /// [`ChainReader::currency_definition`].
    fn currency(&self, name_or_id: &str) -> Result<CurrencyPolicy, RpcError>;
    /// What a currency is: its kind, its lifetime, and its definition in full.
    ///
    /// The same [`CurrencySummary`] [`ChainReader::list_currencies`] yields per
    /// entry, for one currency and one request. Both parse the same object
    /// through the same function; `listcurrencies` merely nests it under
    /// `currencydefinition` while `getcurrency` returns it bare.
    ///
    /// # Why this exists next to `list_currencies`
    ///
    /// Until 2026-08-06 the only route to `options`, `proof_protocol` and the
    /// raw definition was `list_currencies`, which returns every currency on the
    /// chain. Measured against `api.verustest.net`:
    ///
    /// | | bytes |
    /// |---|---|
    /// | `getcurrency VRSCTEST` | 2,018 |
    /// | `listcurrencies` | 464,365 |
    ///
    /// 230× for one lookup, growing with the chain rather than with the
    /// question — so a wallet that had just launched a currency could not say
    /// what it launched without pulling half a megabyte.
    fn currency_definition(&self, name_or_id: &str) -> Result<CurrencySummary, RpcError>;
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
    /// Every currency the chain knows about.
    ///
    /// One large reply — 290 currencies on VRSCTEST — and no pagination, so
    /// fetch it once and keep it rather than calling it per lookup.
    fn list_currencies(&self) -> Result<Vec<CurrencySummary>, RpcError>;
    /// Which fractional currencies can convert **all** of these.
    ///
    /// The routing question a conversion needs and could not ask. A conversion
    /// runs through a fractional currency holding both sides; naming one
    /// currency lists every market it trades in, and naming two narrows that to
    /// the markets that can route between them directly.
    ///
    /// **A converter trades its own currency as well as its reserves**, and the
    /// answers reflect that: `["vlotto"]` returns vlotto itself, whose
    /// `reserves` are `[VRSCTEST]` and do not mention vlotto. So test
    /// membership with [`CurrencyConverter::trades`], not against
    /// [`CurrencyConverter::reserves`] — the latter discards exactly that case.
    ///
    /// An empty list is a real answer: two currencies sharing no market give
    /// one. An **unrecognised** currency does not — that is `-32602, "Invalid
    /// first currency"` — so a typo cannot be mistaken for a thin market.
    fn currency_converters(&self, currencies: &[&str]) -> Result<Vec<CurrencyConverter>, RpcError>;
    /// The fee per kilobyte the node suggests for confirmation within `blocks`.
    ///
    /// `None` when the node will not estimate — it answers a **negative** value
    /// for that, which is why this is not simply an amount. Too little recent
    /// traffic is the usual cause, and on a quiet chain it is not unusual.
    ///
    /// Advisory. Nothing about it is consensus, and both public endpoints
    /// currently answer the relay-fee floor of 0.000001 for every horizon
    /// asked. Treat it as a floor to stay above, not a price to pay.
    ///
    /// Sent with exactly one argument: the allowlist refuses two as `-32601`,
    /// and none is a `-1` usage error.
    fn estimate_fee(&self, blocks: u32) -> Result<Option<Amount>, RpcError>;
    /// A VerusID, including the output that holds it.
    fn identity(&self, name_or_id: &str) -> Result<IdentityRecord, RpcError>;
    /// Every identity that lists `address` among its **primary addresses**.
    ///
    /// The one identity read that does not start from the identity. A wallet
    /// holds keys, not names, and without this it cannot answer "which
    /// identities do I control" — only "tell me about this one", which requires
    /// already knowing the answer.
    ///
    /// Scoped on purpose. This is not a way to enumerate identities in general:
    /// the caller nominates an address, and the daemon answers about that
    /// address alone.
    ///
    /// # What comes back, and what does not
    ///
    /// [`IdentityAtAddress`], not [`IdentityRecord`] — the reply is the
    /// identity objects themselves rather than the envelope, so it carries no
    /// fully-qualified name, no status string and no block height. See that
    /// type for why inventing them would be worse than not having them.
    ///
    /// An empty list is a real answer: an address that controls nothing gives
    /// one.
    ///
    /// # `unspent: true`, deliberately
    ///
    /// The daemon defaults this to **false**, which searches the whole history:
    /// an identity that listed `address` in some earlier version comes back
    /// even though its current version does not, and the `txout` it comes back
    /// with is that earlier, already-spent output.
    ///
    /// Both halves of that are wrong for a caller asking what it controls. The
    /// first shows an identity somebody no longer has any key for. The second is
    /// worse: an identity update has to spend the output currently holding the
    /// identity, so building one against a superseded outpoint produces a
    /// transaction the chain rejects — after it has been signed.
    ///
    /// So this asks the present-tense question, which is the only one whose
    /// answer is safe to act on. The historical search is a different question
    /// and would be a different method.
    ///
    /// Sent as one object argument, matching the daemon's own usage message.
    /// The allowlist in front of `api.verustest.net` serves it — verified
    /// 2026-08-13, where the bare call answers `-1` (usage) rather than
    /// `-32601` (absent).
    fn identities_with_address(&self, address: &str) -> Result<Vec<IdentityAtAddress>, RpcError>;
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
    /// Every value an identity has **ever** published, accumulated.
    ///
    /// **Not its current content**, and the difference is not a nuance. The
    /// reply carries `fromheight` and `toheight`, and with no range given the
    /// daemon accumulates across the whole chain: a key written twice comes
    /// back with *both* values, oldest first, even though only one of them is
    /// on the identity now.
    ///
    /// Proven on chain rather than read off the docs. `vdxf1171008.VRSCTEST@`
    /// had one key published and then republished by a second update touching
    /// a different key; `getidentity` shows that key with one value and this
    /// method shows it with two.
    ///
    /// So this answers "what has this identity published over time", which is
    /// an audit question. For "what does it hold now" — which is what an
    /// application reading back its own data wants — use
    /// [`ChainReader::identity`] and [`content_multimap`].
    fn identity_content(&self, name_or_id: &str) -> Result<IdentityContent, RpcError>;
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

    /// Take the transport back.
    ///
    /// For a driver that hands a [`Cassette`](crate::Cassette) to an operation
    /// and needs it back afterwards to fill in what was missing. The client is
    /// a thin wrapper, so nothing is lost by unwrapping it between rounds.
    pub fn into_transport(self) -> T {
        self.transport
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

    /// Call `method`, trying each argument list in turn until one is not
    /// refused as not-found.
    ///
    /// # Why this exists
    ///
    /// A public endpoint is usually a filtering proxy, and the filter can be
    /// sensitive to the **number of arguments** rather than the method name.
    /// So `-32601` is evidence about one *call*, not about the node.
    ///
    /// That is not hypothetical and it is not only `getblock`. Measured against
    /// `api.verustest.net` on 2026-08-03:
    ///
    /// ```text
    /// getrawmempool []       -> {"result":[]}
    /// getrawmempool [false]  -> {"error":{"code":-32601,"message":"Method not found"}}
    /// ```
    ///
    /// A client that asked the second way and stopped would record a node that
    /// serves the mempool as one that does not.
    ///
    /// So a method with more than one plausible argument list asks each of them
    /// before concluding anything, and [`RpcError::MethodUnavailable`] then
    /// means "refused at every arity this crate knows how to ask" instead of
    /// "refused once".
    ///
    /// # What it does not do
    ///
    /// Only `-32601` advances to the next arity. Every other outcome is
    /// returned immediately, which matters most for
    /// [`RpcError::AnswerNeeded`](crate::RpcError::AnswerNeeded): under a
    /// [`Cassette`](crate::Cassette) an unanswered request must stop the
    /// operation, not provoke a second question in the same round. The retry
    /// then happens across rounds instead, and costs an extra one only when the
    /// first arity really was refused.
    ///
    /// # What may be listed as an alternative arity
    ///
    /// Not merely a *plausible* second argument list — an **equivalent
    /// question**. `getblock <h>` and `getblock <h> 1` are equivalent (verbosity
    /// 1 is the default, and the two were measured byte-identical against a
    /// VRSCTEST daemon on 2026-08-03); `getblock <h> 0` is not, because it
    /// answers with hex. `getrawtransaction [txid]` is a plausible alternative
    /// to `[txid, 1]` and is likewise **not** equivalent, for the same reason.
    ///
    /// Getting that wrong would hand a caller a different shape than it parses,
    /// only on nodes where the preferred arity happens to be filtered — which
    /// is the hardest possible place to notice it.
    ///
    /// `arities` must not be empty; the first entry is the preferred form.
    fn call_probing<R>(&self, method: Method, arities: &[serde_json::Value]) -> Result<R, RpcError>
    where
        R: serde::de::DeserializeOwned,
    {
        let mut last = RpcError::Unexpected(format!(
            "{} was called with no argument list to try",
            method.name()
        ));
        for params in arities {
            match self.call(method, params) {
                Err(refused @ RpcError::MethodUnavailable { .. }) => last = refused,
                outcome => return outcome,
            }
        }
        Err(last)
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

    fn mempool(&self) -> Result<Vec<String>, RpcError> {
        // `[]` first because it is what works against the public endpoint; the
        // explicit `[false]` is there for a node whose filter wants the
        // argument present. See `call_probing`.
        let raw: Vec<String> =
            self.call_probing(Method::GetRawMempool, &[json!([]), json!([false])])?;

        // Checked and lowercased like every other hash this client returns, and
        // for the reason `check_hash` gives: the whole point of this method is
        // `pending.contains(&txid)` against a txid from somewhere else —
        // `send_raw_transaction`'s answer, or one computed locally — and both
        // of those normalise to lowercase. A node answering in uppercase would
        // otherwise report a mempool that never matches anything.
        let ids = raw
            .iter()
            .map(|id| check_hash(id, "getrawmempool"))
            .collect::<Result<Vec<_>, _>>()?;
        // A repeated id is a node contradicting itself about a set. Refused
        // rather than deduplicated, which is what this client does everywhere
        // else it is handed a list that is supposed to be one.
        refuse_repeats(&ids, |id| id, "getrawmempool")?;
        Ok(ids)
    }

    fn block(&self, height_or_hash: &str) -> Result<serde_json::Value, RpcError> {
        // A height is sent as a number and a hash as a string; the daemon
        // accepts either, but not a height quoted as a string.
        let key = match height_or_hash.parse::<u64>() {
            Ok(height) => json!(height),
            Err(_) => json!(height_or_hash),
        };
        // One argument is the form the public endpoint serves, and adding a
        // verbosity argument to it is what makes that endpoint answer -32601.
        // The two-argument form is tried only after the one-argument form has
        // already been refused, so the working call is never made worse.
        //
        // Verbosity 1 is `getblock`'s own default, so the fallback asks the
        // same question. Measured rather than assumed, against a VRSCTEST
        // daemon on 2026-08-03:
        //
        //     verus -chain=VRSCTEST getblock 1173695     |
        //     verus -chain=VRSCTEST getblock 1173695 1   | byte-identical
        //     verus -chain=VRSCTEST getblock 1173695 0   | the block as hex
        //
        // which is why 0 is not in this list.
        self.call_probing(Method::GetBlock, &[json!([key.clone()]), json!([key, 1])])
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

    fn address_mempool(&self, addresses: &[&str]) -> Result<Vec<MempoolDelta>, RpcError> {
        // One positional object, no `verbosity`. See the trait method's docs
        // for why both halves of that are deliberate.
        let body = self.call_raw(
            Method::GetAddressMempool,
            json!([{ "addresses": addresses }]),
        )?;
        let result = result_of(&body, Method::GetAddressMempool)?;
        let raw: Vec<RawMempoolDelta<'_>> = serde_json::from_str(result.get())
            .map_err(|e| RpcError::Unexpected(format!("getaddressmempool: {e}")))?;

        let rows: Vec<MempoolDelta> = raw
            .into_iter()
            .map(RawMempoolDelta::into_typed)
            .collect::<Result<_, _>>()?;

        // The same two checks `address_deltas` makes, for the same reasons: a
        // row about an address nobody asked for, or one delivered twice, is
        // folded straight into a caller's "incoming" total with nothing
        // downstream to catch it. Here that total is what a user is shown as
        // money on its way, so an inflated one is a lie about their balance.
        //
        // The key includes `spending` because `index` numbers inputs and
        // outputs separately: a receive at output 0 and a spend at input 0
        // legitimately share an index in the same transaction, and both appear
        // in the live fixture this was written against.
        let mut seen = std::collections::HashSet::with_capacity(rows.len());
        for row in &rows {
            if !addresses.contains(&row.address.as_str()) {
                return Err(RpcError::Unexpected(format!(
                    "node returned a mempool delta for {}, which was not asked about",
                    row.address
                )));
            }
            if !seen.insert((row.address.as_str(), row.txid, row.spending, row.index)) {
                return Err(RpcError::Unexpected(format!(
                    "node returned the mempool delta {}:{} ({}) for {} more than once",
                    row.txid.to_display_hex(),
                    row.index,
                    if row.spending { "spend" } else { "receive" },
                    row.address
                )));
            }
        }
        Ok(rows)
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

    fn currency_definition(&self, name_or_id: &str) -> Result<CurrencySummary, RpcError> {
        // `getcurrency` returns the definition bare, where `listcurrencies`
        // nests it — so this hands the whole result to the shared parser.
        let definition: serde_json::Value = self.call(Method::GetCurrency, json!([name_or_id]))?;
        crate::types::summary_from_definition(definition)
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

    fn list_currencies(&self) -> Result<Vec<CurrencySummary>, RpcError> {
        let entries: Vec<RawCurrencyEntry> = self.call(Method::ListCurrencies, json!([]))?;
        let currencies: Vec<CurrencySummary> = entries
            .into_iter()
            .map(RawCurrencyEntry::into_typed)
            .collect::<Result<_, _>>()?;
        refuse_repeats(&currencies, |c| &c.currency_id, "listcurrencies")?;
        Ok(currencies)
    }

    fn currency_converters(&self, currencies: &[&str]) -> Result<Vec<CurrencyConverter>, RpcError> {
        let entries: Vec<serde_json::Value> =
            self.call(Method::GetCurrencyConverters, json!(currencies))?;
        let converters: Vec<CurrencyConverter> = entries
            .into_iter()
            .map(converter_from_entry)
            .collect::<Result<_, _>>()?;
        refuse_repeats(&converters, |c| &c.converter_id, "getcurrencyconverters")?;
        Ok(converters)
    }

    fn estimate_fee(&self, blocks: u32) -> Result<Option<Amount>, RpcError> {
        let body = self.call_raw(Method::EstimateFee, json!([blocks]))?;
        let result = result_of(&body, Method::EstimateFee)?;

        // A negative answer means "I will not estimate", not a negative fee.
        // It has to be recognised before the money reader sees it, because
        // that reader refuses a negative amount — correctly — and would turn a
        // legitimate "no opinion" into a parse failure.
        // `unquote` first: this crate tolerates a quoted number everywhere
        // else, and checking the bare token would let `"-1"` past to become a
        // `LossyNumber` — fail-closed, but reported as a malformed reply
        // rather than as the node declining to answer.
        if json::unquote(result.get()).trim_start().starts_with('-') {
            return Ok(None);
        }
        json::native_coins_lenient(result, "estimatefee").map(Some)
    }

    fn identity(&self, name_or_id: &str) -> Result<IdentityRecord, RpcError> {
        let raw: RawIdentity = self.call(Method::GetIdentity, json!([name_or_id]))?;
        raw.into_typed()
    }

    fn identities_with_address(&self, address: &str) -> Result<Vec<IdentityAtAddress>, RpcError> {
        let raw: Vec<RawIdentityAtAddress> = self.call(
            Method::GetIdentitiesWithAddress,
            json!([{ "address": address, "unspent": true }]),
        )?;
        raw.into_iter()
            .map(RawIdentityAtAddress::into_typed)
            .collect()
    }

    fn identity_content(&self, name_or_id: &str) -> Result<IdentityContent, RpcError> {
        let raw: RawIdentity = self.call(Method::GetIdentityContent, json!([name_or_id]))?;
        let identity = raw.into_typed()?;

        // Each value has to actually be the 32-byte hash the type promises. The
        // tempting `as_str().unwrap_or_default()` turns anything else into an
        // empty string, and to an application reading back its own stored data
        // that is indistinguishable from having published nothing — the one
        // reading worse than an error.
        let mut content_map = BTreeMap::new();
        if let Some(map) = identity
            .identity
            .get("contentmap")
            .and_then(|v| v.as_object())
        {
            for (key, value) in map {
                let hex = value.as_str().ok_or_else(|| {
                    RpcError::Unexpected(format!("contentmap entry {key} is not a string"))
                })?;
                if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(RpcError::Unexpected(format!(
                        "contentmap entry {key} is {hex:?}, not a 32-byte hash"
                    )));
                }
                content_map.insert(key.clone(), hex.to_string());
            }
        }

        // Every value published across the range this reply covers — which is
        // the whole chain unless the daemon was told otherwise, and is not the
        // same as the identity's current content. See the method's docs.
        let content_multimap = content_multimap(&identity.identity)?;

        Ok(IdentityContent {
            identity,
            content_map,
            content_multimap,
        })
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

/// The `contentmultimap` of an identity object, typed.
///
/// Takes the `identity` field of a `getidentity` or `getidentitycontent` reply.
/// Public because **which** of those you pass changes what you get, and that
/// difference is not cosmetic — see [`ChainReader::identity_content`].
///
/// Empty when the identity carries no multimap, which is every identity older
/// than version 3.
pub fn content_multimap(
    identity: &serde_json::Value,
) -> Result<BTreeMap<String, Vec<ContentValue>>, RpcError> {
    let mut multimap = BTreeMap::new();
    let Some(raw) = identity.get("contentmultimap") else {
        return Ok(multimap);
    };
    let map = raw.as_object().ok_or_else(|| {
        RpcError::Unexpected(format!(
            "contentmultimap is {raw}, not a map of keys to values"
        ))
    })?;
    for (key, value) in map {
        multimap.insert(key.clone(), content_values(key, value)?);
    }
    Ok(multimap)
}

/// Read the values published under one VDXF key.
///
/// See the call site for the three shapes and where they come from.
fn content_values(key: &str, value: &serde_json::Value) -> Result<Vec<ContentValue>, RpcError> {
    let one = |item: &serde_json::Value| -> Result<ContentValue, RpcError> {
        match item {
            serde_json::Value::String(hex) => {
                hex::decode(hex).map(ContentValue::Bytes).map_err(|_| {
                    RpcError::Unexpected(format!(
                        "contentmultimap entry {key} holds {hex:?}, which is not hex"
                    ))
                })
            }
            serde_json::Value::Object(_) => Ok(ContentValue::Structured(item.clone())),
            other => Err(RpcError::Unexpected(format!(
                "contentmultimap entry {key} holds {other}, which is neither hex nor an object"
            ))),
        }
    };

    match value {
        serde_json::Value::Array(items) => items.iter().map(one).collect(),
        // A single value need not be wrapped in a list on the wire; it is one
        // here, so a caller has one shape to handle rather than two.
        single => Ok(vec![one(single)?]),
    }
}

/// Refuse a list that names the same thing twice.
///
/// The same posture the UTXO, delta and offer readers take: a repeat inflates
/// whatever is folded from the answer, and here it would put one currency in a
/// list twice — a wallet showing a duplicate, or a router weighing one market
/// as two.
fn refuse_repeats<T>(
    items: &[T],
    id: impl Fn(&T) -> &String,
    what: &'static str,
) -> Result<(), RpcError> {
    let mut seen = std::collections::HashSet::with_capacity(items.len());
    for item in items {
        if !seen.insert(id(item)) {
            return Err(RpcError::Unexpected(format!(
                "{what} named {} more than once",
                id(item)
            )));
        }
    }
    Ok(())
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
