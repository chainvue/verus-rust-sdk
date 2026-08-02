//! Whole operations in the browser: the module asks the questions, the page
//! fetches the answers.
//!
//! Everything else in this crate builds and signs from data the application
//! already gathered. These bindings are the other half — the SDK's own flows,
//! the ones that know which coins are actually spendable and what a transaction
//! should expire at, running unchanged in WebAssembly.
//!
//! # Why this is not `async`
//!
//! `verus-flows` is written as straight-line Rust against a **synchronous**
//! reader, and a browser has no synchronous `fetch`. The way out is not an
//! async duplicate of every flow; it is to stop the flow doing its own I/O.
//!
//! An [`Answers`] holds what is known so far. A `plan…` call runs the operation
//! against it, **performing no I/O at all**, and returns either the finished
//! result or the exact JSON-RPC bodies it still needs. The page posts those,
//! records the replies, and calls again. Each call re-runs the operation from
//! the beginning against a cache that has grown, so the code that decides what
//! to sign is the same code a native caller runs — not a translation of it.
//!
//! ```js
//! import init, { Key, Answers, parseCoins } from "@chainvue/verus-wasm";
//! await init();
//!
//! const post = (body) =>
//!   fetch(NODE, { method: "POST", body }).then((r) => r.text());
//!
//! const key = Key.fromWif(wif);
//! const answers = new Answers();
//! for (;;) {
//!   const step = key.planSend({ to: "RQr2…", satoshis: parseCoins("1.5") }, answers);
//!   if (step.kind === "ready") {
//!     await post(JSON.stringify({ method: "sendrawtransaction", params: [step.value.hex] }));
//!     break;
//!   }
//!   await Promise.all(step.ask.map(async (body) => answers.record(body, await post(body))));
//! }
//! answers.free();
//! key.free();
//! ```
//!
//! # What a `plan…` call will never do
//!
//! **Broadcast.** Not "does not currently"; cannot. The flows were split so
//! that the re-runnable half takes no broadcaster, and re-running is exactly
//! what happens here — a send that went out once per round would send a
//! different transaction each time. So `step.value.hex` comes back and
//! the page posts it, once, deliberately, outside the loop.
//!
//! # If that post fails, do not plan again
//!
//! The one thing the SDK cannot do for you, because the POST is yours.
//!
//! A failed `sendrawtransaction` is **ambiguous**: the request may never have
//! arrived, or may have arrived, been accepted and relayed to the whole network
//! before the connection dropped. From the page the two look identical.
//!
//! The wrong recovery is to run the loop again. A fresh plan re-reads the UTXO
//! set; if the first transaction did land and has not yet confirmed, the coins
//! still look unspent, and the second plan spends them again — a **second
//! payment**, not a retry.
//!
//! The right recovery is one read and, at most, the *same bytes*:
//!
//! ```js
//! try {
//!   await post(sendRawTransaction(step.value.hex));
//! } catch (networkFailure) {
//!   const seen = await post(getRawTransaction(step.value.txid));
//!   // Absent? It never arrived, and re-posting the identical hex is safe.
//!   // Present? It is already on the network. Nothing to do.
//!   if (!JSON.parse(seen).result) await post(sendRawTransaction(step.value.hex));
//! }
//! ```
//!
//! A node that *answers* and refuses is different, and not ambiguous: it
//! understood the transaction and said no. Re-posting it unchanged will fail
//! the same way.
//!
//! # `ask` is posted verbatim
//!
//! The strings in `step.ask` are complete JSON-RPC request bodies. Post them as
//! they are; do not parse, re-encode or reorder them. They are also the keys
//! [`Answers::record`] is looked up by, so a body that comes back changed is a
//! body that was never asked — the round would repeat and the loop would run to
//! the round cap.
//!
//! They are independent of one another within a round: an operation that needed
//! one answer to form the next question would have stopped at the first. So
//! fetch them concurrently.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;

use verus_flows::drive::{advance, Step};
use verus_rpc::{Cassette, ChainReader, RpcClient};

use crate::dto::{self, Shape};
use crate::error::{WasmError, WasmResult};
use crate::keys::Key;
use crate::types::{
    CommitmentStatusStepValue, ContentRequestValue, ContentStepValue, HistoryRequestValue,
    HistoryStepValue, JsText, LoginRequestValue, LoginStepValue, OfferTermsRequestValue,
    OfferTermsStepValue, OffersRequestValue, OffersStepValue, PendingRequestValue,
    PlanBurnRequestValue, PlanConvertRequestValue, PlanMintRequestValue, PlanPublishRequestValue,
    PlanRegistrationRequestValue, PlanSendFromIdentityRequestValue, PlanSendRequestValue,
    PlanSendTokenRequestValue, RegisteredStepValue, RegistrationStepValue, SpendableRequestValue,
    SpendableStepValue, TakeOfferRequestValue, TakeOfferStepValue, TransactionStepValue,
    UpdateStepValue, VerifyLoginRequestValue, VerifyLoginStepValue,
};

/// What a driven operation knows so far, carried between rounds.
///
/// # Make a new one for every operation
///
/// **An `Answers` is a frozen view of the chain, not a connection.** Nothing in
/// it expires. A second operation planned against one that has already finished
/// is planned against the *first* operation's tip and the first operation's
/// UTXO set, however long ago that was — quietly, and with no error, because a
/// cached answer is indistinguishable from a fresh one. A wallet that keeps one
/// around and reuses it will eventually build a payment from coins it has
/// already spent.
///
/// Within one operation that same property is exactly what is wanted: every
/// round sees the same chain, so a plan cannot be built half from one view and
/// half from another.
///
/// So: `new Answers()`, drive one operation to `"ready"`, `free()`.
///
/// # The round cap
///
/// It counts rounds and gives up after sixteen. An operation that asks for
/// something new every round is a bug, and without the cap it presents as a tab
/// that fetches forever. The count is per `Answers`, which is a second reason
/// not to share one: a reused handle carries its predecessor's rounds and hits
/// the cap early.
///
/// Call `free()` when the operation is done, as with [`Key`].
#[wasm_bindgen]
#[derive(Default)]
pub struct Answers {
    inner: verus_flows::drive::Answers,
}

#[wasm_bindgen]
impl Answers {
    /// Nothing known yet.
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new() -> Answers {
        Answers::default()
    }

    /// Record the reply to one of the bodies from a step's `ask`.
    ///
    /// `body` is the key and must be passed back **unchanged**. `reply` is the
    /// node's response text, verbatim — including an error envelope, which is a
    /// real answer to some questions: a flow asking whether a name is taken
    /// needs the daemon's `-5` in order to conclude that it is not.
    pub fn record(&mut self, body: JsText, reply: JsText) -> WasmResult<()> {
        let body = dto::text("body", body.as_ref())?;
        let reply = dto::text("reply", reply.as_ref())?;
        self.inner.record(body, reply).map_err(WasmError::from)
    }

    /// How many rounds have run.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn rounds(&self) -> usize {
        self.inner.rounds()
    }

    /// How many answers are held.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn known(&self) -> usize {
        self.inner.known()
    }
}

/// What to pay, and to whom.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanSendRequest {
    /// Where the value is going. An `R…` or an `i…` address.
    pub to: String,
    /// How much, in satoshis, as a decimal string.
    pub satoshis: String,
}

impl PlanSendRequest {
    /// The keys a `PlanSendRequest` object may carry.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[("to", None), ("satoshis", None)],
    };
}

/// One round of any plan: what it still needs, or what it produced.
///
/// One shape for every `plan…` call rather than one per flow. The alternative
/// was a `SendStep`, a `HistoryStep`, a `LoginStep` and so on — identical but
/// for the payload's name, which is a lot of surface for a page to learn and a
/// lot of declarations to keep in step with the Rust.
///
/// `value` is present exactly when `kind` is `"ready"`, and `ask` is empty
/// exactly then. TypeScript sees it generically as `PlanStep<T>`.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanStep<T> {
    /// `"ask"` or `"ready"`.
    pub kind: String,
    /// JSON-RPC bodies to post verbatim. Empty when `kind` is `"ready"`.
    pub ask: Vec<String>,
    /// What the operation produced. Present only when `kind` is `"ready"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<T>,
}

impl<T> PlanStep<T> {
    /// Convert a driver step, mapping the finished value on the way.
    fn of<U>(step: Step<U>, ready: impl FnOnce(U) -> T) -> Self {
        match step {
            Step::Ask(ask) => Self {
                kind: "ask".into(),
                ask,
                value: None,
            },
            Step::Ready(value) => Self {
                kind: "ready".into(),
                ask: Vec::new(),
                value: Some(ready(value)),
            },
        }
    }
}

/// A transaction a flow built and signed, ready to post.
///
/// Deliberately not [`JsSignedTransaction`](crate::dto::JsSignedTransaction),
/// which the direct builders return: that one lists the outpoints it spent, and
/// a flow's result does not carry them. Reporting an empty list would be a
/// silent lie about which coins are now committed.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsPlannedTransaction {
    /// The raw transaction, hex — what `sendrawtransaction` takes.
    pub hex: String,
    /// Its txid in display order, computed from `hex` before anything is sent.
    pub txid: String,
    /// The miner fee paid, in satoshis, including any dust folded into it.
    pub fee: String,
    /// Change returned, in satoshis; `"0"` if it would have been dust.
    pub change: String,
}

impl From<verus_flows::Sent> for JsPlannedTransaction {
    fn from(sent: verus_flows::Sent) -> Self {
        Self {
            hex: sent.hex,
            txid: sent.txid,
            fee: dto::sats_string(sent.fee),
            change: dto::sats_string(sent.change),
        }
    }
}

/// An identity update a flow built and signed, ready to post.
///
/// A [`JsPlannedTransaction`] plus what the update will change. Storing data on
/// an identity costs a miner fee like any other transaction, and a wallet
/// asking a user to approve it should be able to say how much.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsPlannedUpdate {
    /// The raw transaction, hex — what `sendrawtransaction` takes.
    pub hex: String,
    /// Its txid in display order, computed from `hex` before anything is sent.
    pub txid: String,
    /// The miner fee, in satoshis, paid from the funding address.
    pub fee: String,
    /// Change returned to the funding address, in satoshis; `"0"` if it would
    /// have been dust.
    pub change: String,
    /// The key that will be written, as it appears in `contentmultimap`.
    pub key: String,
    /// How many values will stand under it. Zero means the key is removed.
    pub values: usize,
}

/// Which addresses to read, and over what stretch of chain.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryRequest {
    /// The addresses to report on. A node sees every one of them.
    pub addresses: Vec<String>,
    /// First block to search, inclusive. Omit both bounds for the whole chain,
    /// which on a busy address is a large reply — page with explicit ranges
    /// rather than finding the transport's size ceiling.
    #[serde(default)]
    pub start_height: Option<u32>,
    /// Last block to search, inclusive.
    #[serde(default)]
    pub end_height: Option<u32>,
}

impl HistoryRequest {
    /// The keys a `HistoryRequest` object may carry.
    ///
    /// `addresses` is a leaf: an array of strings, with no object inside for a
    /// stray key to hide in.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[
            ("addresses", None),
            ("startHeight", None),
            ("endHeight", None),
        ],
    };
}

/// One transaction that touched the addresses asked about.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsHistoryEntry {
    /// The transaction, in display order.
    pub txid: String,
    /// Block it was mined in.
    pub height: u32,
    /// Position within that block.
    pub block_index: u32,
    /// The block's timestamp as the daemon reports it, in seconds.
    ///
    /// A plain `number`, unlike every amount here: a Unix timestamp is far
    /// inside what a float64 holds exactly, so the reason money is a string
    /// does not apply. Miner-chosen and only loosely monotonic — fine to
    /// display, not a source of ordering. These entries are sorted by height.
    pub block_time: i64,
    /// Net native value in satoshis, as a decimal string, negative when more
    /// left than arrived.
    ///
    /// **`"0"` does not mean nothing happened.** A token-only transfer moves no
    /// native value at all; read `netCurrencies` too.
    pub net_native: String,
    /// Net movement per currency, keyed by `i…` address, **excluding** the
    /// chain's own currency. Amounts are decimal strings in the currency's
    /// smallest unit.
    ///
    /// Currencies that net to exactly zero are absent rather than `"0"`: a
    /// transaction that spent a 5-token output and took 5 back as change did
    /// not move that token, and listing it invites a phantom line in a wallet.
    pub net_currencies: BTreeMap<String, String>,
    /// Whether any output belonging to these addresses was spent here.
    ///
    /// Distinct from a negative net: a self-transfer spends an output and
    /// returns the value, netting to just the fee.
    pub spent_something: bool,
}

impl From<verus_flows::history::HistoryEntry> for JsHistoryEntry {
    fn from(entry: verus_flows::history::HistoryEntry) -> Self {
        Self {
            txid: entry.txid.to_display_hex(),
            height: entry.height,
            block_index: entry.block_index,
            block_time: entry.block_time,
            net_native: entry.net_native.to_sat().to_string(),
            net_currencies: entry
                .net_currencies
                .into_iter()
                .map(|(currency, amount)| (currency, amount.to_sat().to_string()))
                .collect(),
            spent_something: entry.spent_something,
        }
    }
}

/// What a login challenge commits to.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoginRequest {
    /// Who is asking. Included in the signed text so a signature made for one
    /// site cannot be replayed at another.
    pub audience: String,
    /// Random and single-use. 32 bytes of entropy, hex or base64, is ample.
    pub challenge: String,
}

impl LoginRequest {
    /// The keys a `LoginRequest` object may carry.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[("audience", None), ("challenge", None)],
    };

    fn to_flow(&self) -> verus_flows::LoginRequest {
        verus_flows::LoginRequest {
            audience: self.audience.clone(),
            challenge: self.challenge.clone(),
        }
    }
}

/// What to verify, and how strict to be about its age.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifyLoginRequest {
    /// The identity that supposedly signed — a name or an `i…` address.
    pub identity: String,
    /// The signature it presented, base64.
    pub signature: String,
    /// The challenge it was given. Must be the one this server issued.
    pub audience: String,
    /// The challenge nonce.
    pub challenge: String,
    /// How old the signature's height may be, in blocks. Roughly a block a
    /// minute on Verus, so 60 is an hour. Omit for that default.
    #[serde(default)]
    pub max_age_blocks: Option<u32>,
    /// How far ahead of the tip a signature may be stamped. Omit for 2.
    #[serde(default)]
    pub max_future_blocks: Option<u32>,
}

impl VerifyLoginRequest {
    /// The keys a `VerifyLoginRequest` object may carry.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[
            ("identity", None),
            ("signature", None),
            ("audience", None),
            ("challenge", None),
            ("maxAgeBlocks", None),
            ("maxFutureBlocks", None),
        ],
    };
}

/// Who signed in, and under what authority.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsLoggedIn {
    /// The fully qualified name, e.g. `alice.VRSCTEST@`.
    pub name: String,
    /// The identity's `i…` address. **This is the identifier to key a session
    /// on** — a name can be transferred, an `i` address cannot.
    pub identity_address: String,
    /// The height the signature was stamped with.
    pub signed_at: u32,
    /// The addresses that actually signed, and were authorised to at that
    /// height rather than at the tip.
    pub signers: Vec<String>,
}

impl From<verus_flows::LoggedIn> for JsLoggedIn {
    fn from(logged_in: verus_flows::LoggedIn) -> Self {
        Self {
            name: logged_in.name,
            identity_address: logged_in.identity_address,
            signed_at: logged_in.signed_at,
            signers: logged_in.signers.iter().map(ToString::to_string).collect(),
        }
    }
}

/// Whose coins to look at.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpendableRequest {
    /// The address to assess. A node sees it.
    pub address: String,
}

impl SpendableRequest {
    /// The keys a `SpendableRequest` object may carry.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[("address", None)],
    };
}

/// What an address can actually spend right now.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsFunding {
    /// The chain tip this was decided against. Everything below is a statement
    /// about that height, not about now.
    pub tip: u32,
    /// Total spendable, in satoshis, as a decimal string.
    pub total: String,
    /// The outputs a builder can use.
    pub utxos: Vec<crate::dto::JsUtxo>,
    /// Native value that exists but cannot be spent **yet** — mostly immature
    /// coinbases.
    ///
    /// Part of the gap between a balance and what a payment can use, **not all
    /// of it**: the outputs counted in `other` carry native value too, and it
    /// is in neither this figure nor `total`. So `total + notYetSpendable` can
    /// still fall short of what `getaddressbalance` reports, and by design —
    /// the remainder is locked in outputs a native send must not touch.
    pub not_yet_spendable: String,
    /// How many outputs are not plain P2PKH: reserve outputs holding tokens,
    /// identity outputs, anything CryptoCondition. Excluded from `utxos`
    /// because the native builders refuse them — a reserve output's value is in
    /// its payload, so spending one as ordinary funding destroys what it
    /// carries.
    ///
    /// A **count**, not the outputs. Spending a token means naming the outputs
    /// that hold it, and this flow cannot identify them: `getaddressutxos`
    /// reports a reserve output's native value, not which token it carries or
    /// how much, so recognising them means decoding each script. A wallet that
    /// tracks its own token outputs already knows them and passes them to the
    /// token send; this number is here so a balance screen can say "and 3
    /// outputs this cannot spend" rather than silently omitting them.
    pub other: usize,
}

impl From<verus_flows::Funding> for JsFunding {
    fn from(funding: verus_flows::Funding) -> Self {
        Self {
            tip: funding.tip,
            total: dto::sats_string(funding.total),
            not_yet_spendable: dto::sats_string(funding.immature_total()),
            other: funding.other.len(),
            utxos: funding
                .utxos
                .into_iter()
                .map(|utxo| crate::dto::JsUtxo {
                    txid: utxo.txid.to_display_hex(),
                    vout: utxo.vout,
                    satoshis: dto::sats_string(utxo.satoshis),
                    script_pubkey: hex::encode(&utxo.script_pubkey),
                })
                .collect(),
        }
    }
}

/// Which identity's stored data to read.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentRequest {
    /// The identity holding it — a name or an `i…` address.
    pub identity: String,
}

impl ContentRequest {
    /// The keys a `ContentRequest` object may carry.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[("identity", None)],
    };
}

/// One value stored under a VDXF key.
///
/// A multimap value is VDXF-typed data whose encoding depends on its key, and
/// **a VDXF key is a one-way hash of a name**: for a key you did not create
/// there is no way to recover the name, and so no way to know how to read the
/// bytes. So this hands them over and stops. For your own keys that costs
/// nothing — you chose the encoding.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsContentValue {
    /// The raw bytes as hex, for a key the daemon does not recognise — which
    /// is every key an application defines for itself. Absent when the daemon
    /// recognised the key and decoded it, because the original bytes are then
    /// not in the reply at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
    /// The daemon's decoded rendering, when it had one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured: Option<serde_json::Value>,
}

impl From<verus_rpc::ContentValue> for JsContentValue {
    fn from(value: verus_rpc::ContentValue) -> Self {
        match value {
            verus_rpc::ContentValue::Bytes(bytes) => Self {
                hex: Some(hex::encode(bytes)),
                structured: None,
            },
            verus_rpc::ContentValue::Structured(json) => Self {
                hex: None,
                structured: Some(json),
            },
        }
    }
}

/// Plan a transaction history read.
///
/// Costs one round: the chain's own currency id and the address deltas are
/// asked for together, because neither needs the other.
///
/// # Errors
///
/// Throws if the request is malformed, if a recorded reply cannot be
/// understood, or if the operation is still asking after sixteen rounds.
#[wasm_bindgen(js_name = planHistory)]
pub fn plan_history(
    request: HistoryRequestValue,
    answers: &mut Answers,
) -> WasmResult<HistoryStepValue> {
    let request: HistoryRequest = dto::from_js(request.into(), &HistoryRequest::SHAPE)?;
    let addresses: Vec<&str> = request.addresses.iter().map(String::as_str).collect();
    let range = match (request.start_height, request.end_height) {
        (Some(start), Some(end)) => Some((start, end)),
        (None, None) => None,
        _ => {
            return Err(WasmError::new(
                "InvalidArgument",
                "a height range needs both startHeight and endHeight, or neither",
            ))
        }
    };

    let step = advance(&mut answers.inner, |client: &RpcClient<Cassette>| {
        verus_flows::history::history(client, &addresses, range)
    })
    .map_err(WasmError::from)?;

    let step = PlanStep::of(step, |entries: Vec<verus_flows::HistoryEntry>| {
        entries
            .into_iter()
            .map(JsHistoryEntry::from)
            .collect::<Vec<_>>()
    });
    Ok(crate::to_js(&step)?.unchecked_into())
}

/// What token to move, and which outputs hold it.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanSendTokenRequest {
    /// The token's currency id — an `i…` address. For a tokenised identity,
    /// that is the identity's own `i` address.
    pub currency: String,
    /// Where the tokens are going.
    pub to: String,
    /// How much, in the token's smallest unit, as a decimal string.
    pub amount: String,
    /// The outputs holding the token.
    ///
    /// **Not discovered for you**, and that is honest rather than lazy:
    /// `getaddressutxos` reports a reserve output's native value, not which
    /// token it carries or how much, so recognising them means decoding each
    /// script. A wallet that tracks its own token outputs already knows them.
    /// The native coins for the miner fee *are* found automatically.
    pub token_utxos: Vec<crate::dto::JsUtxo>,
}

impl PlanSendTokenRequest {
    /// The keys a `PlanSendTokenRequest` object may carry.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[
            ("currency", None),
            ("to", None),
            ("amount", None),
            ("tokenUtxos", Some(&crate::dto::JsUtxo::SHAPE)),
        ],
    };
}

/// A payment out of funds a VerusID holds.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanSendFromIdentityRequest {
    /// The identity paying — a name or an `i…` address.
    pub identity: String,
    /// Where the value is going.
    pub to: String,
    /// How much, in satoshis, as a decimal string.
    pub satoshis: String,
}

impl PlanSendFromIdentityRequest {
    /// The keys a `PlanSendFromIdentityRequest` object may carry.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[("identity", None), ("to", None), ("satoshis", None)],
    };
}

/// What to store on a VerusID, and under which key.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanPublishRequest {
    /// The identity to write to — a name or an `i…` address.
    pub identity: String,
    /// The VDXF key, as a `contentmultimap` spells it: an `i…` address.
    /// Derive it with `vdxfKey`.
    pub key: String,
    /// The values to store, each as hex.
    ///
    /// **Replaces whatever stood under the key** — there is no append, because
    /// an update restates the whole identity. Read first if you mean to add.
    /// An empty list removes the key.
    pub values: Vec<String>,
}

impl PlanPublishRequest {
    /// The keys a `PlanPublishRequest` object may carry.
    ///
    /// `values` is a leaf: an array of strings, with no object inside for a
    /// stray key to hide in.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[("identity", None), ("key", None), ("values", None)],
    };
}

/// Read an absolute fee, refusing one that cannot have been meant.
///
/// Every fee a caller names outright goes through here. There are four of them
/// now — the taker's, and the three conversion plans — and each is the kind of
/// field where a transposed digit is paid rather than caught.
fn checked_fee(text: &str) -> WasmResult<verus_tx::Amount> {
    let fee = dto::sats(text)?;
    if fee.to_sat() > MAX_ABSOLUTE_FEE {
        return Err(WasmError::new(
            "FeeTooLarge",
            format!(
                "a fee of {} coins is almost certainly a unit mistake; the ceiling here is {}",
                fee.to_coins_string(),
                verus_tx::Amount::from_sat(MAX_ABSOLUTE_FEE).to_coins_string()
            ),
        ));
    }
    Ok(fee)
}

/// The largest fee a plan will accept where the caller names one outright.
///
/// Not always a *miner* fee: for the three conversion plans this bounds the
/// **reserve transfer** fee, which the miner fee is computed separately from.
/// The units are the same — native satoshis — so one ceiling covers both.
///
/// One coin, which is orders of magnitude above any real fee on this chain: the
/// conversion fee observed from the daemon is 0.0002001. Not a consensus rule
/// and not advice — a bar below which a number cannot be a mistake and above
/// which it almost certainly is.
const MAX_ABSOLUTE_FEE: u64 = verus_tx::SATS_PER_COIN;

/// What to convert, into what, and on whose terms.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanConvertRequest {
    /// The currency being spent, as an `i…` address.
    pub from: String,
    /// How much of it, in satoshis, as a decimal string.
    pub amount: String,
    /// Which kind of conversion. One of `"intoFractional"`, `"intoReserve"`,
    /// `"reserveToReserve"`, `"preconvert"`.
    ///
    /// Minting and burning are **not** here. They have their own bindings
    /// because they are not conversions in the sense this is: a burn destroys
    /// value and cannot be undone, and a mint needs a controlling identity's
    /// authority. Neither should be reachable by changing a string.
    pub kind: String,
    /// The currency being bought — the fractional, the reserve, or the target.
    pub into: String,
    /// The fractional to route through. **Only** for `"reserveToReserve"`, and
    /// refused for every other kind rather than ignored.
    #[serde(default)]
    pub via: Option<String>,
    /// Where the result should land — an `R…` address.
    pub recipient: String,
    /// The conversion fee, in satoshis, as a decimal string.
    pub fee: String,
    /// The least you are willing to accept, in satoshis.
    ///
    /// **Nothing enforces this on chain**, and that is not a limitation of this
    /// SDK — the protocol has no slippage bound. A conversion is a request at
    /// an unknown price: the chain performs it when it *imports* the output, a
    /// block later at best, at whatever the reserve ratios are then.
    ///
    /// What this does is refuse before signing if the node's own estimate has
    /// already fallen below it. That is the only price check that exists.
    #[serde(default)]
    pub min_expected: Option<String>,
    /// Outputs carrying the source currency, when it is a token.
    ///
    /// Leave empty when converting the chain's own currency. As with a token
    /// send, every token input is spent whole and the surplus returns as
    /// change.
    #[serde(default)]
    pub token_funding: Vec<crate::dto::JsUtxo>,
}

impl PlanConvertRequest {
    /// The keys a `PlanConvertRequest` object may carry.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[
            ("from", None),
            ("amount", None),
            ("kind", None),
            ("into", None),
            ("via", None),
            ("recipient", None),
            ("fee", None),
            ("minExpected", None),
            ("tokenFunding", Some(&crate::dto::JsUtxo::SHAPE)),
        ],
    };

    /// The kind, with `into` and `via` resolved against it.
    ///
    /// The kind is a string beside two currency fields rather than a tagged
    /// union, because the request sanitizer declares a fixed set of keys and
    /// cannot vary them per variant — and losing the sanitizer here would be a
    /// far worse trade than a slightly flatter shape.
    ///
    /// What that costs is a combination the shape permits and the meaning does
    /// not: `via` alongside a kind that does not route. Refused by name rather
    /// than ignored, because a caller who set it believed it did something.
    fn conversion_kind(&self) -> WasmResult<verus_tx::convert::ConversionKind> {
        use verus_tx::convert::ConversionKind;
        let into = dto::currency("into", &self.into)?;

        let routed = matches!(self.kind.as_str(), "reserveToReserve");
        match (&self.via, routed) {
            (Some(_), false) => {
                return Err(WasmError::new(
                    "InvalidArgument",
                    format!(
                        "via is only used by a reserveToReserve conversion, and kind is {:?}",
                        self.kind
                    ),
                ))
            }
            (None, true) => {
                return Err(WasmError::new(
                    "InvalidArgument",
                    "a reserveToReserve conversion needs `via`: the fractional holding both \
                     reserves, which is what makes the route exist",
                ))
            }
            _ => {}
        }

        Ok(match self.kind.as_str() {
            "intoFractional" => ConversionKind::IntoFractional { fractional: into },
            "intoReserve" => ConversionKind::IntoReserve { reserve: into },
            "reserveToReserve" => ConversionKind::ReserveToReserve {
                via: dto::currency("via", self.via.as_deref().unwrap_or_default())?,
                target: into,
            },
            "preconvert" => ConversionKind::Preconvert { fractional: into },
            "mint" | "burn" => {
                return Err(WasmError::new(
                    "InvalidArgument",
                    format!(
                        "{:?} is not a conversion; use planMint or planBurn, which exist \
                         separately because a burn cannot be undone and a mint needs an \
                         identity's authority",
                        self.kind
                    ),
                ))
            }
            other => {
                return Err(WasmError::new(
                    "InvalidArgument",
                    format!(
                        "unknown conversion kind {other:?}; expected intoFractional, \
                         intoReserve, reserveToReserve or preconvert"
                    ),
                ))
            }
        })
    }
}

/// What to destroy.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanBurnRequest {
    /// The token's currency id, as an `i…` address.
    pub currency: String,
    /// How much to destroy, in satoshis, as a decimal string.
    pub amount: String,
    /// The conversion fee, in satoshis, as a decimal string.
    pub fee: String,
    /// Outputs carrying the token.
    #[serde(default)]
    pub token_funding: Vec<crate::dto::JsUtxo>,
}

impl PlanBurnRequest {
    /// The keys a `PlanBurnRequest` object may carry.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[
            ("currency", None),
            ("amount", None),
            ("fee", None),
            ("tokenFunding", Some(&crate::dto::JsUtxo::SHAPE)),
        ],
    };
}

/// What to mint, and to whom.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanMintRequest {
    /// The token's `i…` address — which is **also** the id of the identity
    /// that controls it, and that coincidence is the whole mechanism.
    pub currency: String,
    /// How much new supply, in satoshis, as a decimal string.
    pub amount: String,
    /// Where it lands — an `R…` address.
    pub recipient: String,
    /// The conversion fee, in satoshis, as a decimal string.
    pub fee: String,
}

impl PlanMintRequest {
    /// The keys a `PlanMintRequest` object may carry.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[
            ("currency", None),
            ("amount", None),
            ("recipient", None),
            ("fee", None),
        ],
    };
}

/// A registration in progress, as JavaScript holds it.
///
/// # Persist this before broadcasting anything
///
/// `pending` carries the reservation's **salt**, and the salt is the one value
/// in the whole registration that cannot be recovered from the chain. Lose it
/// after the commitment is broadcast and the commitment fee is gone with no way
/// to redeem it. Write it somewhere durable before you post the commitment, not
/// after.
///
/// Treat it as opaque and hand it back unchanged. It is JSON so it can be
/// stored, not so it can be edited.
///
/// # The ordering guarantee, and what it costs at this boundary
///
/// In Rust the two steps are different *types*: a commitment that has not
/// confirmed cannot be handed to the registration step, because it does not
/// type-check. A JSON blob crossing into JavaScript has no such property, so
/// the guarantee becomes a runtime one — `state` records which step this is at,
/// and `planRegistrationComplete` refuses a value that is not `"readyToRegister"`.
///
/// That is a real weakening and worth naming: the mistake it prevents costs a
/// commitment fee, and here it is caught by a check rather than by the compiler.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsPending {
    /// Which step this is at: `"awaitingCommitment"` or `"readyToRegister"`.
    pub state: String,
    /// The name being claimed, without the parent.
    pub name: String,
    /// What the registration will cost, in satoshis, as a decimal string.
    ///
    /// Read from chain policy when the plan was made. A node that misreports it
    /// is the one failure with teeth here, because it is discovered *after* the
    /// commitment is spent — `pinFee` is the escape hatch.
    pub registration_fee: String,
    /// The commitment transaction, hex. Post this for step one.
    pub commitment_hex: String,
    /// Its txid.
    pub commitment_txid: String,
    /// The flow's own state, including the salt. Opaque; hand it back unchanged.
    pub pending: serde_json::Value,
}

/// What to claim, and under what terms.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanRegistrationRequest {
    /// The name to claim, without the parent.
    pub name: String,
    /// The addresses that will control the identity. Empty means this key's own.
    #[serde(default)]
    pub primary_addresses: Vec<String>,
    /// How many of them must sign. Omit for one.
    #[serde(default)]
    pub min_sigs: Option<u32>,
    /// An identity to credit as referrer, which reduces the fee.
    #[serde(default)]
    pub referral: Option<String>,
    /// Override the registration fee read from chain policy, in satoshis.
    ///
    /// The node reports this figure and it is spent before it can be checked
    /// against anything, so a wrong one is discovered after the commitment.
    /// Pin it when you know better.
    #[serde(default)]
    pub pin_fee: Option<String>,
    /// The reservation salt, 32 bytes as hex.
    ///
    /// Omit and one is drawn here. Supply one and the registration becomes
    /// **reproducible**: the same name, key and salt always give the same
    /// commitment, so a page can re-derive it after losing its state rather
    /// than losing the fee. Whatever you choose, it must be unpredictable —
    /// the salt is what stops somebody else seeing your name before you claim
    /// it.
    #[serde(default)]
    pub salt: Option<String>,
}

impl PlanRegistrationRequest {
    /// The keys a `PlanRegistrationRequest` object may carry.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[
            ("name", None),
            ("primaryAddresses", None),
            ("minSigs", None),
            ("referral", None),
            ("pinFee", None),
            ("salt", None),
        ],
    };
}

/// A registration in progress, handed back for the next step.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingRequest {
    /// The value a previous step returned, unchanged.
    pub pending: JsPending,
}

impl PendingRequest {
    /// The keys a `PendingRequest` object may carry.
    ///
    /// `pending` is declared as a leaf: its contents are this crate's own
    /// serialization handed back verbatim, not a shape a caller composes, so
    /// sanitising inside it would refuse fields the SDK itself wrote.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[("pending", None)],
    };
}

/// Where a commitment stands.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub enum JsCommitmentStatus {
    /// Accepted but not yet mined. Poll again.
    Waiting {
        /// How many confirmations it has. Zero means it is in the mempool.
        confirmations: u32,
    },
    /// Confirmed. `pending` has moved to `"readyToRegister"`.
    Ready {
        /// The value to hand to `planRegistrationComplete`.
        pending: JsPending,
    },
    /// The chain moved under this registration, so what was read before is
    /// suspect. Start again rather than spending against a view that is gone.
    Reorged {
        /// What was noticed.
        detail: String,
    },
    /// The node has never seen the commitment. It may never have been posted,
    /// or it may have been dropped from the mempool.
    ///
    /// The default only because a drift check needs one, and this is the
    /// variant that claims least.
    #[default]
    Gone,
}

/// A registration transaction, built and signed. **Not broadcast.**
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsRegistered {
    /// The raw transaction, hex — what `sendrawtransaction` takes.
    pub hex: String,
    /// Its txid in display order, computed before anything is sent.
    pub txid: String,
    /// The name claimed, without the parent.
    pub name: String,
    /// The identity's `i` address — computable before the identity exists.
    pub identity_address: String,
    /// What the registration cost, in satoshis, as a decimal string.
    pub fee_paid: String,
}

/// What is standing on the marketplace against a currency or an identity.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OffersRequest {
    /// What to look for offers against.
    pub target: String,
    /// How to read `target`.
    ///
    /// Getting this wrong fails **quietly**: a currency asked about as an
    /// identity comes back empty, which is indistinguishable from a currency
    /// nobody is trading. A plain name is only ever an identity — pass an `i`
    /// address for a currency.
    pub is_currency: bool,
    /// Ask for each maker's signed half-transaction as well.
    ///
    /// Without it a listing is something to display; with it, it is something
    /// `planOfferTerms` can check against the chain and `planTakeOffer` can
    /// complete. It makes the reply substantially larger, so it is a choice.
    #[serde(default)]
    pub with_offer_bytes: bool,
}

impl OffersRequest {
    /// The keys an `OffersRequest` object may carry.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[
            ("target", None),
            ("isCurrency", None),
            ("withOfferBytes", None),
        ],
    };
}

/// One side of an offer — what is given, or what is wanted for it.
///
/// The two sides have the same shape and either can be either kind, which is
/// what makes an identity sale and a token trade the same mechanism.
// `rename_all` on an enum renames the **variants**; the fields inside them need
// `rename_all_fields`. Without it `identity_id` reaches JavaScript in snake
// case while every other field in the API is camel — and nothing but the union
// drift test would have said so.
#[derive(Clone, Debug, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub enum JsOfferSide {
    /// Currency, possibly several at once. More than one is ordinary: an offer
    /// of a token usually carries a little native currency alongside it,
    /// because the output has to pay its own way.
    Currencies {
        /// Keyed by currency `i` address; amounts in satoshis, decimal strings.
        amounts: BTreeMap<String, String>,
    },
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

impl Default for JsOfferSide {
    fn default() -> Self {
        Self::Currencies {
            amounts: BTreeMap::new(),
        }
    }
}

impl From<verus_rpc::OfferSide> for JsOfferSide {
    fn from(side: verus_rpc::OfferSide) -> Self {
        match side {
            verus_rpc::OfferSide::Currencies(amounts) => Self::Currencies {
                amounts: amounts
                    .into_iter()
                    .map(|(currency, amount)| (currency, dto::sats_string(amount)))
                    .collect(),
            },
            verus_rpc::OfferSide::Identity {
                identity_id,
                name,
                system_id,
            } => Self::Identity {
                identity_id,
                name,
                system_id,
            },
        }
    }
}

/// One offer standing on the marketplace, read against a particular tip.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsListing {
    /// What the maker is giving.
    pub offering: JsOfferSide,
    /// What the maker wants for it.
    pub accepting: JsOfferSide,
    /// Height after which the offer can no longer be completed. Zero means it
    /// never expires.
    pub block_expiry: u32,
    /// The transaction holding the output the maker signed away — **not** the
    /// id of the offer transaction itself.
    ///
    /// The daemon calls this `txid`, which reads as "this offer's transaction"
    /// and is the wrong thing to fetch. Renamed here so the mistake is harder
    /// to make.
    pub funding_txid: String,
    /// The maker's signed half-transaction, when `withOfferBytes` was set.
    /// This is what `planOfferTerms` and `planTakeOffer` take.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_offer: Option<String>,
    /// The daemon's own price, **verbatim text**.
    ///
    /// Not a number, and not an amount. A price is a *ratio* between the two
    /// sides, so it is not denominated in anything; and the daemon divides in
    /// `double` and prints the result, so it arrives already rounded. Reading
    /// it into an exact type would dress a rounded figure as a precise one.
    pub price: String,
    /// Which of the daemon's price buckets this was listed in.
    pub bucket: String,
    /// Whether it could still be completed at the tip this was read against.
    ///
    /// Usually true, and that is a measurement rather than an assumption: every
    /// offer the two public nodes returned was live when checked. The flag
    /// earns its place for the other reason — this records the offer against
    /// *a* tip, and the chain moves.
    pub live: bool,
}

impl From<verus_flows::Listing> for JsListing {
    fn from(found: verus_flows::Listing) -> Self {
        let live = found.live;
        let listing = found.listing;
        Self {
            offering: listing.offering.into(),
            accepting: listing.accepting.into(),
            block_expiry: listing.block_expiry,
            funding_txid: listing.funding_txid.to_display_hex(),
            raw_offer: listing.raw_offer,
            price: listing.price,
            bucket: listing.bucket,
            live,
        }
    }
}

/// An offer to read against the chain.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OfferTermsRequest {
    /// The maker's signed half-transaction, hex — a listing's `rawOffer`.
    pub offer: String,
}

impl OfferTermsRequest {
    /// The keys an `OfferTermsRequest` object may carry.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[("offer", None)],
    };
}

/// What a maker is asking to be paid.
#[derive(Clone, Debug, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub enum JsDemand {
    /// Native coins.
    Native {
        /// How much, in satoshis, as a decimal string.
        amount: String,
        /// The address the maker wants paying.
        recipient: String,
    },
    /// A token, as a reserve output.
    Token {
        /// Which token, by its `i` address.
        currency: String,
        /// How much, in the token's smallest unit, as a decimal string.
        amount: String,
        /// The address the maker wants paying.
        recipient: String,
    },
}

impl Default for JsDemand {
    fn default() -> Self {
        Self::Native {
            amount: String::new(),
            recipient: String::new(),
        }
    }
}

impl From<verus_flows::Demand> for JsDemand {
    fn from(demand: verus_flows::Demand) -> Self {
        match demand {
            verus_flows::Demand::Native { amount, recipient } => Self::Native {
                amount: dto::sats_string(amount),
                recipient: dto::key_hash_address(recipient),
            },
            verus_flows::Demand::Token {
                currency,
                amount,
                recipient,
            } => Self::Token {
                currency: dto::identity_address(currency.to_bytes()),
                amount: dto::sats_string(amount),
                recipient: dto::key_hash_address(recipient),
            },
        }
    }
}

/// An offer, checked against the chain rather than against the maker's word.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsOfferTerms {
    /// The transaction holding the output the offer spends.
    pub funding_txid: String,
    /// Which output of it.
    pub funding_vout: u32,
    /// What that output really holds, in satoshis, **read from the chain** and
    /// not from the maker's message.
    pub offered: String,
    /// The address that controls the funding output: the maker.
    pub control: String,
    /// What the maker wants in return.
    pub demand: JsDemand,
    /// Height after which this can no longer be completed. Zero means never.
    pub expiry_height: u32,
    /// Confirmations on the funding **transaction**.
    ///
    /// Not proof the output is still unspent — the public node cannot answer
    /// that, because it runs without `spentindex` and returns the same `-5` for
    /// spent and unspent outpoints alike. Zero means it is in the mempool,
    /// which is a reason to wait.
    pub confirmations: u32,
}

impl From<verus_flows::OfferTerms> for JsOfferTerms {
    fn from(terms: verus_flows::OfferTerms) -> Self {
        Self {
            funding_txid: terms.funding_txid.to_display_hex(),
            funding_vout: terms.funding_vout,
            offered: dto::sats_string(terms.offered),
            control: dto::key_hash_address(terms.control),
            demand: terms.demand.into(),
            expiry_height: terms.expiry_height,
            confirmations: terms.confirmations,
        }
    }
}

/// What a taker supplies to complete an offer.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TakeOfferRequest {
    /// The maker's signed half-transaction, hex.
    pub offer: String,
    /// The outputs paying what the maker demands, plus the miner fee.
    ///
    /// Named rather than discovered, for the same reason a token send names
    /// them: paying a token demand means spending reserve outputs, and
    /// `getaddressutxos` does not say which token an output carries.
    pub utxos: Vec<crate::dto::JsUtxo>,
    /// Where what the maker is giving should land — an `R…` address.
    pub recipient: String,
    /// Where change returns.
    pub change_address: String,
    /// The miner fee, in satoshis, as a decimal string.
    pub fee: String,
}

impl TakeOfferRequest {
    /// The keys a `TakeOfferRequest` object may carry.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[
            ("offer", None),
            ("utxos", Some(&crate::dto::JsUtxo::SHAPE)),
            ("recipient", None),
            ("changeAddress", None),
            ("fee", None),
        ],
    };
}

/// A completed offer, built and signed.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsTaken {
    /// The raw transaction, hex — what `sendrawtransaction` takes.
    pub hex: String,
    /// Its txid in display order, computed from `hex` before anything is sent.
    pub txid: String,
    /// The terms this was completed against, as they were read from the chain.
    pub terms: JsOfferTerms,
}

/// Verify a VerusID login, against the identity **as it stood when the
/// signature was made**.
///
/// Rotation and revocation are treated differently, deliberately:
///
/// * a key **rotated** after signing does not invalidate the signature — the
///   identity is resolved at the signature's own height, and a routine key
///   change should not log everyone out;
/// * an identity **revoked** after signing is refused anyway. Revocation is a
///   break-glass action, so it takes effect now rather than when the signature
///   ages out — otherwise an attacker holding a signature stamped minutes
///   before the revocation keeps logging in for another `maxAgeBlocks`.
///
/// That costs one extra read, in the same round as the others.
///
/// Key a session on `identityAddress`, not on `name` — a name can be
/// transferred to someone else, an `i` address cannot.
///
/// # Errors
///
/// Throws if the signature is stale or stamped ahead of the chain, if the
/// identity did not exist or was revoked at that height, or if the signature
/// does not meet the identity's threshold.
#[wasm_bindgen(js_name = planVerifyLogin)]
pub fn plan_verify_login(
    request: VerifyLoginRequestValue,
    answers: &mut Answers,
) -> WasmResult<VerifyLoginStepValue> {
    let request: VerifyLoginRequest = dto::from_js(request.into(), &VerifyLoginRequest::SHAPE)?;
    let signature = verus_tx::signature::IdentitySignature::from_base64(&request.signature)
        .map_err(WasmError::from)?;
    let challenge = verus_flows::LoginRequest {
        audience: request.audience.clone(),
        challenge: request.challenge.clone(),
    };
    let policy = verus_flows::LoginPolicy {
        max_age_blocks: request
            .max_age_blocks
            .unwrap_or(verus_flows::LoginPolicy::default().max_age_blocks),
        max_future_blocks: request
            .max_future_blocks
            .unwrap_or(verus_flows::LoginPolicy::default().max_future_blocks),
    };

    let step = advance(&mut answers.inner, |client: &RpcClient<Cassette>| {
        verus_flows::verify_login(client, &request.identity, &signature, &challenge, &policy)
    })
    .map_err(WasmError::from)?;

    let step = PlanStep::of(step, JsLoggedIn::from);
    Ok(crate::to_js(&step)?.unchecked_into())
}

/// Plan a read of what an address can actually spend.
///
/// Not a balance. A balance counts what exists; this counts what a transaction
/// can use *now* — which differs whenever the address holds an immature
/// coinbase or a token. `notYetSpendable` is the gap, so a wallet can explain
/// it instead of showing a number a payment then fails to reach.
///
/// Costs one round, plus one more if any output is young enough that its
/// maturity has to be checked.
#[wasm_bindgen(js_name = planSpendable)]
pub fn plan_spendable(
    request: SpendableRequestValue,
    answers: &mut Answers,
) -> WasmResult<SpendableStepValue> {
    let request: SpendableRequest = dto::from_js(request.into(), &SpendableRequest::SHAPE)?;
    let step = advance(&mut answers.inner, |client: &RpcClient<Cassette>| {
        verus_flows::spendable(client, &request.address)
    })
    .map_err(WasmError::from)?;

    let step = PlanStep::of(step, JsFunding::from);
    Ok(crate::to_js(&step)?.unchecked_into())
}

/// Plan a read of everything an identity stores **now**.
///
/// Keyed by the VDXF key as a `contentmultimap` prints it — an `i` address, not
/// hex. The same identity object spells its older `contentmap` keys as hex, so
/// comparing a derived key against the wrong rendering silently finds nothing.
///
/// This is current state. For every value ever published under a key, including
/// superseded ones, use [`plan_content_history`].
#[wasm_bindgen(js_name = planContent)]
pub fn plan_content(
    request: ContentRequestValue,
    answers: &mut Answers,
) -> WasmResult<ContentStepValue> {
    let request: ContentRequest = dto::from_js(request.into(), &ContentRequest::SHAPE)?;
    let step = advance(&mut answers.inner, |client: &RpcClient<Cassette>| {
        verus_flows::read_all(client, &request.identity)
    })
    .map_err(WasmError::from)?;

    let step = PlanStep::of(
        step,
        |content: BTreeMap<String, Vec<verus_rpc::ContentValue>>| {
            content
                .into_iter()
                .map(|(key, values)| {
                    (
                        key,
                        values
                            .into_iter()
                            .map(JsContentValue::from)
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        },
    );
    Ok(crate::to_js(&step)?.unchecked_into())
}

/// Plan a read of every value an identity has **ever** published under its
/// keys, oldest first.
///
/// The audit view, and not what an application reading back its own data wants:
/// a key rewritten three times appears three times, with no marker saying which
/// is current. [`plan_content`] answers that.
#[wasm_bindgen(js_name = planContentHistory)]
pub fn plan_content_history(
    request: ContentRequestValue,
    answers: &mut Answers,
) -> WasmResult<ContentStepValue> {
    let request: ContentRequest = dto::from_js(request.into(), &ContentRequest::SHAPE)?;
    let step = advance(&mut answers.inner, |client: &RpcClient<Cassette>| {
        Ok(client.identity_content(&request.identity)?)
    })
    .map_err(WasmError::from)?;

    let step = PlanStep::of(step, |content: verus_rpc::IdentityContent| {
        content
            .content_multimap
            .into_iter()
            .map(|(key, values)| {
                (
                    key,
                    values
                        .into_iter()
                        .map(JsContentValue::from)
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>()
    });
    Ok(crate::to_js(&step)?.unchecked_into())
}

/// Read a stored pending back, insisting it is at the step this call needs.
///
/// The Rust API makes this a type error; JSON cannot, so it is a check. Getting
/// it wrong is not a cosmetic mistake — running step two against a commitment
/// that has not confirmed spends the registration fee against an output the
/// chain will not accept.
fn pending_at<S>(stored: &JsPending, want: &str) -> WasmResult<verus_flows::Pending<S>>
where
    S: serde::de::DeserializeOwned,
{
    if stored.state != want {
        return Err(WasmError::new(
            "WrongStep",
            format!(
                "this registration is at {:?} and this step needs {want:?}",
                stored.state
            ),
        ));
    }
    serde_json::from_value(stored.pending.clone()).map_err(|e| {
        WasmError::new(
            "InvalidArgument",
            format!("the stored registration could not be read back: {e}"),
        )
    })
}

/// Render a flow `Pending` for JavaScript to hold.
fn stored_pending<S>(pending: &verus_flows::Pending<S>, state: &str) -> WasmResult<JsPending>
where
    S: serde::Serialize,
{
    Ok(JsPending {
        state: state.to_string(),
        name: pending.name().to_string(),
        registration_fee: dto::sats_string(pending.registration_fee),
        commitment_hex: pending.commitment_hex.clone(),
        commitment_txid: pending.commitment_txid.clone(),
        pending: serde_json::to_value(pending).map_err(|e| {
            WasmError::new("VerusError", format!("the registration did not store: {e}"))
        })?,
    })
}

/// Ask whether a commitment has confirmed. **One call, no waiting.**
///
/// Poll this; do not busy-loop it. A commitment takes a block, and the public
/// infrastructure this asks is not yours. It costs up to four requests: the
/// confirmation count, then the tip and the hash at the anchored height to spot
/// a reorg, and on the round it settles the commitment transaction, to confirm
/// which output actually carries the commitment rather than assuming.
///
/// # Errors
///
/// Throws if the stored value is not at `"awaitingCommitment"`.
#[wasm_bindgen(js_name = planCommitmentStatus)]
pub fn plan_commitment_status(
    request: PendingRequestValue,
    answers: &mut Answers,
) -> WasmResult<CommitmentStatusStepValue> {
    let request: PendingRequest = dto::from_js(request.into(), &PendingRequest::SHAPE)?;
    let pending: verus_flows::Pending<verus_flows::AwaitingCommitment> =
        pending_at(&request.pending, "awaitingCommitment")?;

    let step = advance(&mut answers.inner, |client: &RpcClient<Cassette>| {
        pending.poll(client)
    })
    .map_err(WasmError::from)?;

    let step = match step {
        verus_flows::drive::Step::Ask(ask) => PlanStep {
            kind: "ask".into(),
            ask,
            value: None,
        },
        verus_flows::drive::Step::Ready(status) => PlanStep {
            kind: "ready".into(),
            ask: Vec::new(),
            value: Some(match status {
                verus_flows::CommitmentStatus::Waiting { confirmations } => {
                    JsCommitmentStatus::Waiting { confirmations }
                }
                verus_flows::CommitmentStatus::Ready(ready) => JsCommitmentStatus::Ready {
                    pending: stored_pending(&*ready, "readyToRegister")?,
                },
                verus_flows::CommitmentStatus::Reorged { detail } => {
                    JsCommitmentStatus::Reorged { detail }
                }
                verus_flows::CommitmentStatus::CommitmentGone => JsCommitmentStatus::Gone,
            }),
        },
    };
    Ok(crate::to_js(&step)?.unchecked_into())
}

/// Plan a read of every offer standing against a currency or an identity.
///
/// The half of the marketplace that used to be missing: making and taking an
/// offer both worked, and there was no way to *discover* one.
///
/// Costs **two** rounds, and deliberately so: the offers are read first and the
/// tip only after. That order is the whole safety argument — the tip is then
/// never older than the listings, so an offer expiring in the gap is judged
/// dead rather than alive.
///
/// Reading them together would save a round trip and flip that the unsafe way.
/// It is not an optimisation waiting to be made, and a test pins the count to
/// say so.
///
/// # Errors
///
/// Throws if `target` cannot be read. An empty result is **not** an error, and
/// is also what asking about a currency as an identity produces — see
/// `isCurrency`.
#[wasm_bindgen(js_name = planOffers)]
pub fn plan_offers(
    request: OffersRequestValue,
    answers: &mut Answers,
) -> WasmResult<OffersStepValue> {
    let request: OffersRequest = dto::from_js(request.into(), &OffersRequest::SHAPE)?;
    let step = advance(&mut answers.inner, |client: &RpcClient<Cassette>| {
        verus_flows::browse(
            client,
            &request.target,
            request.is_currency,
            request.with_offer_bytes,
        )
    })
    .map_err(WasmError::from)?;

    let step = PlanStep::of(step, |found: Vec<verus_flows::Listing>| {
        found.into_iter().map(JsListing::from).collect::<Vec<_>>()
    });
    Ok(crate::to_js(&step)?.unchecked_into())
}

/// Plan a read of what an offer really holds and really demands.
///
/// **The value a maker is giving lives in an outpoint, not in the offer**, so
/// without this a taker has to take the maker's word for it. This reads the
/// funding output from the chain.
///
/// It is not anti-fraud machinery, and it is worth being precise about that:
/// consensus already prevents the theft case, because an offer whose funding
/// outpoint is gone or holds less than claimed is simply rejected. What this
/// buys is that the taker sees the trade before signing it, that the offered
/// value stops being a number they could mistype, and that a failure arrives
/// with a reason instead of as a broadcast rejection.
///
/// Refuses anything that is not a well-formed offer over a genuine funding
/// output — including one spending an ordinary coin, which would mean the
/// maker's signature covers something other than what the offer claims.
///
/// # What it can read, which is narrower than what the marketplace lists
///
/// Worth stating plainly, because a refusal here reads like "this offer is
/// broken" and usually means "this SDK does not model that shape yet":
///
/// * the funding output must be a **native** offer funding output;
/// * the demand must be native coins, or a single token, paid to an `R…`
///   address.
///
/// So a demand paid to an `i` address is refused even though the transaction
/// builder underneath supports it, and an **identity sale** — which
/// [`planOffers`](plan_offers) will happily list, and which
/// `OfferSide::Identity` exists to display — cannot be read or completed at
/// all, because its funding output is not an offer funding output.
///
/// Of the four offers in this repo's own recorded VRSCTEST capture, one is
/// completable through here. Listing and completing are not the same surface,
/// and a browser wallet should expect to display more than it can take.
#[wasm_bindgen(js_name = planOfferTerms)]
pub fn plan_offer_terms(
    request: OfferTermsRequestValue,
    answers: &mut Answers,
) -> WasmResult<OfferTermsStepValue> {
    let request: OfferTermsRequest = dto::from_js(request.into(), &OfferTermsRequest::SHAPE)?;
    let step = advance(&mut answers.inner, |client: &RpcClient<Cassette>| {
        verus_flows::inspect(client, &request.offer)
    })
    .map_err(WasmError::from)?;

    let step = PlanStep::of(step, JsOfferTerms::from);
    Ok(crate::to_js(&step)?.unchecked_into())
}

#[wasm_bindgen]
impl Key {
    /// Plan a native send: find the spendable coins, choose the expiry, build
    /// and sign.
    ///
    /// This is [`Key::send`](crate::keys::Key) with the lookup included, and
    /// the difference is not convenience. `send` is handed UTXOs the
    /// application found, and an application has no cheap way to know which of
    /// them are **spendable**: a coinbase output is unspendable for a hundred
    /// blocks, `getaddressutxos` does not say which outputs are coinbases, and
    /// a transaction that spends an immature one is rejected with a message
    /// that names nothing. This asks — once per young output, and only for the
    /// young ones.
    ///
    /// The expiry is set twenty blocks past the tip rather than left at
    /// "never", so a payment that does not confirm dies instead of landing
    /// months later against coins since spent elsewhere.
    ///
    /// Nothing is broadcast. See the module docs.
    ///
    /// # Errors
    ///
    /// Throws if the request is malformed, if the address holds too little,
    /// or if a recorded reply cannot be understood. `InsufficientFunds` counts
    /// only what is spendable *now*, so it can fire while a balance shows more.
    #[wasm_bindgen(js_name = planSend)]
    pub fn plan_send(
        &self,
        request: PlanSendRequestValue,
        answers: &mut Answers,
    ) -> WasmResult<TransactionStepValue> {
        let request: PlanSendRequest = dto::from_js(request.into(), &PlanSendRequest::SHAPE)?;
        let amount = dto::sats(&request.satoshis)?;
        let to = request.to;

        let step = advance(&mut answers.inner, |client: &RpcClient<Cassette>| {
            verus_flows::prepare_send(client, self.private(), &to, amount)
        })
        .map_err(WasmError::from)?;

        // The `Unsent` is taken apart here and only the bytes survive, which is
        // the point: nothing this module hands back can be sent by anything in
        // this crate.
        let step = PlanStep::of(step, |unsent: verus_flows::Unsent<verus_flows::Sent>| {
            JsPlannedTransaction::from(unsent.outcome)
        });
        Ok(crate::to_js(&step)?.unchecked_into())
    }

    /// Plan a token payment.
    ///
    /// The token moves as a reserve output while the miner fee is still paid in
    /// native coins, so this reads the key's own spendable coins for the fee
    /// and spends them alongside the token outputs you supply.
    ///
    /// Every token input is spent whole and the surplus returns as token
    /// change — **a token output left out of `tokenUtxos` is not "saved", it is
    /// simply not spent**, and one included but not needed still returns.
    ///
    /// Nothing is broadcast. See the module docs.
    #[wasm_bindgen(js_name = planSendToken)]
    pub fn plan_send_token(
        &self,
        request: PlanSendTokenRequestValue,
        answers: &mut Answers,
    ) -> WasmResult<TransactionStepValue> {
        let request: PlanSendTokenRequest =
            dto::from_js(request.into(), &PlanSendTokenRequest::SHAPE)?;
        let currency = dto::currency("currency", &request.currency)?;
        let amount = dto::sats(&request.amount)?;
        let token_utxos = dto::utxos_named("tokenUtxos", &request.token_utxos)?;
        let to = request.to;

        let step = advance(&mut answers.inner, |client: &RpcClient<Cassette>| {
            verus_flows::prepare_send_token(
                client,
                self.private(),
                currency,
                &to,
                amount,
                &token_utxos,
            )
        })
        .map_err(WasmError::from)?;

        let step = PlanStep::of(step, |unsent: verus_flows::Unsent<verus_flows::Sent>| {
            JsPlannedTransaction::from(unsent.outcome)
        });
        Ok(crate::to_js(&step)?.unchecked_into())
    }

    /// Plan a payment out of funds a **VerusID** holds, rather than out of this
    /// key's own coins.
    ///
    /// This is the everyday shape of money on Verus — funds live under an
    /// identity — and it is a different signature from a plain spend: each
    /// input carries a fulfillment, the same construction an identity update
    /// uses. The surplus returns to the identity.
    ///
    /// The identity's current primary addresses are read from the chain and
    /// checked against this key before anything is signed, because signing with
    /// a key the identity no longer lists builds cleanly and then fails script
    /// verification with a message that names nothing.
    ///
    /// # One signature only
    ///
    /// This signs with this key alone, so it can satisfy an identity whose
    /// `minimumsignatures` is 1. An identity that needs more is refused by
    /// name rather than built and rejected — collecting signatures from several
    /// `Key` handles is not something this binding expresses yet.
    ///
    /// # Errors
    ///
    /// Throws if the identity does not exist, is revoked, does not list this
    /// key as a primary address, or needs more signatures than one.
    #[wasm_bindgen(js_name = planSendFromIdentity)]
    pub fn plan_send_from_identity(
        &self,
        request: PlanSendFromIdentityRequestValue,
        answers: &mut Answers,
    ) -> WasmResult<TransactionStepValue> {
        let request: PlanSendFromIdentityRequest =
            dto::from_js(request.into(), &PlanSendFromIdentityRequest::SHAPE)?;
        let amount = dto::sats(&request.satoshis)?;
        let (identity, to) = (request.identity, request.to);

        let step = advance(&mut answers.inner, |client: &RpcClient<Cassette>| {
            verus_flows::prepare_send_from_identity(
                client,
                &[self.private()],
                &identity,
                &to,
                amount,
            )
        })
        .map_err(WasmError::from)?;

        let step = PlanStep::of(step, |unsent: verus_flows::Unsent<verus_flows::Sent>| {
            JsPlannedTransaction::from(unsent.outcome)
        });
        Ok(crate::to_js(&step)?.unchecked_into())
    }

    /// Plan storing application data on a VerusID.
    ///
    /// # An update republishes the whole identity
    ///
    /// There is no "set this field" transaction. An update states the identity
    /// in full, and **anything not carried over is erased** — content,
    /// authorities, private addresses, permanently.
    ///
    /// So this decodes the identity from its own output script, which is the
    /// copy consensus reads, changes exactly the one entry, and leaves
    /// everything else byte for byte. It never sets `allow_authority_change`:
    /// publishing content cannot cost you the identity.
    ///
    /// # Pass an `i` address, not a name
    ///
    /// Both the outpoint and the transaction come from the node, so a hostile
    /// endpoint can try to redirect the write to some *other* identity this key
    /// controls — and with an empty `values`, that is a deletion of somebody
    /// else's content.
    ///
    /// An `i` address **is** the identity's id, so naming one lets this compare
    /// the decoded identity against your own input and refuse, without asking
    /// the node anything. Give it a `name@` instead and the node resolves the
    /// name: it will still catch an endpoint that contradicts itself, but not
    /// one that lies consistently about both answers.
    ///
    /// The miner fee comes from this key's own coins, so the key must be one of
    /// the identity's primary addresses.
    ///
    /// # One signature only
    ///
    /// As with [`Key::plan_send_from_identity`].
    ///
    /// Nothing is broadcast. See the module docs.
    #[wasm_bindgen(js_name = planPublish)]
    pub fn plan_publish(
        &self,
        request: PlanPublishRequestValue,
        answers: &mut Answers,
    ) -> WasmResult<UpdateStepValue> {
        let request: PlanPublishRequest = dto::from_js(request.into(), &PlanPublishRequest::SHAPE)?;
        let key = dto::identity_id("key", &request.key)?;
        let values = request
            .values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                hex::decode(value)
                    .map_err(|e| WasmError::new("InvalidHex", format!("values[{index}]: {e}")))
            })
            .collect::<WasmResult<Vec<Vec<u8>>>>()?;
        let identity = request.identity;
        let funding = self.address();

        let step = advance(&mut answers.inner, |client: &RpcClient<Cassette>| {
            verus_flows::prepare_publish(
                client,
                &[self.private()],
                &identity,
                &funding,
                key,
                values.clone(),
            )
        })
        .map_err(WasmError::from)?;

        let step = PlanStep::of(
            step,
            |unsent: verus_flows::Unsent<verus_flows::Published>| JsPlannedUpdate {
                hex: unsent.hex,
                txid: unsent.txid,
                fee: dto::sats_string(unsent.outcome.fee),
                change: dto::sats_string(unsent.outcome.change),
                key: unsent.outcome.key,
                values: unsent.outcome.values,
            },
        );
        Ok(crate::to_js(&step)?.unchecked_into())
    }

    /// Plan completing an offer, paying what the chain says it demands.
    ///
    /// The offered value is the one read from the funding outpoint, not a
    /// number the caller supplies — so a mistyped digit cannot hand the
    /// difference to a miner. That one is a real fund-loss bug and it is the
    /// caller's own to make, which is why it is taken away from them.
    ///
    /// Refuses an offer that has already expired at the current tip, which
    /// would otherwise be built, signed and rejected.
    ///
    /// Nothing is broadcast. See the module docs.
    #[wasm_bindgen(js_name = planTakeOffer)]
    pub fn plan_take_offer(
        &self,
        request: TakeOfferRequestValue,
        answers: &mut Answers,
    ) -> WasmResult<TakeOfferStepValue> {
        let request: TakeOfferRequest = dto::from_js(request.into(), &TakeOfferRequest::SHAPE)?;
        let utxos = dto::utxos_named("utxos", &request.utxos)?;
        let recipient = dto::pubkey_hash_address("recipient", &request.recipient)?;
        let change: verus_keys::Address =
            dto::pubkey_hash_address("changeAddress", &request.change_address)?;
        // A transposed digit here is paid to a miner, not caught: this binding
        // takes the *offered* value away from the caller for that reason, and
        // leaving the fee unbounded beside it would be inconsistent.
        let fee = checked_fee(&request.fee)?.to_sat();
        let offer = request.offer;

        let step = advance(&mut answers.inner, |client: &RpcClient<Cassette>| {
            let params = verus_flows::Taking::new(&offer, &utxos, recipient.hash(), change, fee);
            verus_flows::prepare_take(client, self.private(), &params)
        })
        .map_err(WasmError::from)?;

        let step = PlanStep::of(step, |unsent: verus_flows::Unsent<verus_flows::Taken>| {
            JsTaken {
                hex: unsent.hex,
                txid: unsent.txid,
                terms: unsent.outcome.terms.into(),
            }
        });
        Ok(crate::to_js(&step)?.unchecked_into())
    }

    /// Plan a conversion from one currency into another.
    ///
    /// # Read this before wiring it to a button
    ///
    /// A conversion is a **request at an unknown price**. The transaction says
    /// what goes in and where the result should land; it says nothing about
    /// what comes out. The chain performs the conversion when it *imports* the
    /// output, a block later at best, at whatever the reserve ratios are then.
    ///
    /// There is no slippage bound in the protocol. `minExpected` refuses before
    /// signing if the node's own estimate has already fallen below it, and that
    /// is the only price check that exists. **A wallet showing a user a number
    /// must show it as an estimate.**
    ///
    /// Nothing is broadcast. See the module docs.
    #[wasm_bindgen(js_name = planConvert)]
    pub fn plan_convert(
        &self,
        request: PlanConvertRequestValue,
        answers: &mut Answers,
    ) -> WasmResult<TransactionStepValue> {
        let request: PlanConvertRequest = dto::from_js(request.into(), &PlanConvertRequest::SHAPE)?;
        let kind = request.conversion_kind()?;
        let amount = dto::sats(&request.amount)?;
        let fee = checked_fee(&request.fee)?;
        let min_expected = match &request.min_expected {
            Some(text) => Some(dto::sats(text)?),
            None => None,
        };
        let token_funding = dto::utxos_named("tokenFunding", &request.token_funding)?;
        let (from, recipient) = (request.from, request.recipient);

        let step = advance(&mut answers.inner, |client: &RpcClient<Cassette>| {
            verus_flows::prepare_conversion(
                client,
                self.private(),
                &from,
                amount,
                kind,
                &recipient,
                fee,
                min_expected,
                &token_funding,
            )
        })
        .map_err(WasmError::from)?;

        let step = PlanStep::of(step, |unsent: verus_flows::Unsent<verus_flows::Sent>| {
            JsPlannedTransaction::from(unsent.outcome)
        });
        Ok(crate::to_js(&step)?.unchecked_into())
    }

    /// Plan destroying supply of a token.
    ///
    /// **A burn cannot be undone.** Nothing is paid back, there is no recovery,
    /// and for a fractional currency the supply change moves the price for
    /// every holder. It is a separate binding rather than a flag on
    /// [`Key::plan_convert`] for exactly that reason.
    ///
    /// Nothing is broadcast. See the module docs.
    #[wasm_bindgen(js_name = planBurn)]
    pub fn plan_burn(
        &self,
        request: PlanBurnRequestValue,
        answers: &mut Answers,
    ) -> WasmResult<TransactionStepValue> {
        let request: PlanBurnRequest = dto::from_js(request.into(), &PlanBurnRequest::SHAPE)?;
        let amount = dto::sats(&request.amount)?;
        let fee = checked_fee(&request.fee)?;
        let token_funding = dto::utxos_named("tokenFunding", &request.token_funding)?;
        let currency = request.currency;

        let step = advance(&mut answers.inner, |client: &RpcClient<Cassette>| {
            verus_flows::prepare_burn(
                client,
                self.private(),
                &currency,
                amount,
                fee,
                &token_funding,
            )
        })
        .map_err(WasmError::from)?;

        let step = PlanStep::of(step, |unsent: verus_flows::Unsent<verus_flows::Sent>| {
            JsPlannedTransaction::from(unsent.outcome)
        });
        Ok(crate::to_js(&step)?.unchecked_into())
    }

    /// Plan minting new supply of a centralized currency.
    ///
    /// `currency` is the token's `i` address — which is **also** the id of the
    /// identity that controls it, and that coincidence is the mechanism:
    /// consensus accepts a mint only from a transaction that spends an output
    /// the controlling identity holds, signed with that identity's authority.
    ///
    /// So the transaction is funded from the identity's own pay-to-identity
    /// outputs, not from this key's coins — **the identity must hold enough
    /// native coins to pay for it**, and an ordinary `planSend` to the `i`
    /// address is how you top it up.
    ///
    /// This key must be one of the identity's primary addresses, and as with
    /// the other identity-authorised plans it signs alone, so a
    /// `minimumsignatures` above one is refused by name.
    ///
    /// Nothing is broadcast. See the module docs.
    #[wasm_bindgen(js_name = planMint)]
    pub fn plan_mint(
        &self,
        request: PlanMintRequestValue,
        answers: &mut Answers,
    ) -> WasmResult<TransactionStepValue> {
        let request: PlanMintRequest = dto::from_js(request.into(), &PlanMintRequest::SHAPE)?;
        let amount = dto::sats(&request.amount)?;
        let fee = checked_fee(&request.fee)?;
        let (currency, recipient) = (request.currency, request.recipient);

        let step = advance(&mut answers.inner, |client: &RpcClient<Cassette>| {
            verus_flows::prepare_mint(client, self.private(), &currency, amount, &recipient, fee)
        })
        .map_err(WasmError::from)?;

        let step = PlanStep::of(step, |unsent: verus_flows::Unsent<verus_flows::Sent>| {
            JsPlannedTransaction::from(unsent.outcome)
        });
        Ok(crate::to_js(&step)?.unchecked_into())
    }

    /// Plan step one of a VerusID registration: the name commitment.
    ///
    /// Registration is **two transactions with a wait between them**, and the
    /// order is not a convenience. The commitment claims the name without
    /// revealing it, so nobody watching the mempool can register it ahead of
    /// you; the registration then reveals it and pays the fee. What joins them
    /// is a salt that exists only in the value this returns.
    ///
    /// **Persist what comes back before you post the commitment.** Once those
    /// bytes are on the network the commitment fee is spent, and without the
    /// salt it cannot be redeemed — the name is not claimed and the fee is not
    /// recoverable. See [`JsPending`].
    ///
    /// Nothing is broadcast. See the module docs.
    ///
    /// # Errors
    ///
    /// Throws if the name is already taken — checked before anything is spent —
    /// if the address cannot cover the registration fee, or if a named referrer
    /// does not exist.
    #[wasm_bindgen(js_name = planRegistration)]
    pub fn plan_registration(
        &self,
        request: PlanRegistrationRequestValue,
        answers: &mut Answers,
    ) -> WasmResult<RegistrationStepValue> {
        let request: PlanRegistrationRequest =
            dto::from_js(request.into(), &PlanRegistrationRequest::SHAPE)?;
        let options = verus_flows::RegistrationOptions {
            primary_addresses: request.primary_addresses.clone(),
            min_sigs: request.min_sigs,
            referral: request.referral.clone(),
            pin_fee: match &request.pin_fee {
                Some(text) => Some(dto::sats(text)?),
                None => None,
            },
        };
        let salt = match &request.salt {
            Some(text) => Some(dto::fixed_hex::<32>("salt", text)?),
            None => None,
        };
        let name = request.name;

        let step = advance(
            &mut answers.inner,
            |client: &RpcClient<Cassette>| match salt {
                // A salt the caller chose makes the whole plan reproducible: same
                // name, key and salt, same commitment. Worth having, because a page
                // that loses its state can then re-derive rather than lose the fee.
                Some(salt) => verus_flows::prepare_registration_with_salt(
                    client,
                    self.private(),
                    &name,
                    &options,
                    salt,
                ),
                // Otherwise one is drawn per call — and therefore a different one
                // on every round of the driver. That is harmless here, and worth
                // knowing why: no request this operation makes mentions the salt,
                // so every round asks the same questions and the salt in the value
                // that finally returns is the one its commitment was built from.
                None => verus_flows::prepare_registration(client, self.private(), &name, &options),
            },
        )
        .map_err(WasmError::from)?;

        let step = match step {
            verus_flows::drive::Step::Ask(ask) => PlanStep {
                kind: "ask".into(),
                ask,
                value: None,
            },
            verus_flows::drive::Step::Ready(pending) => PlanStep {
                kind: "ready".into(),
                ask: Vec::new(),
                value: Some(stored_pending(&pending, "awaitingCommitment")?),
            },
        };
        Ok(crate::to_js(&step)?.unchecked_into())
    }

    /// Record where the chain was, before posting the commitment.
    ///
    /// The anchor is a (height, hash) pair that
    /// [`planCommitmentStatus`](plan_commitment_status) compares against later,
    /// so a chain that was rewritten under this registration is noticed instead
    /// of being registered against. Call this, persist the result, then post
    /// `commitmentHex`.
    ///
    /// The anchor lands on the value returned here whatever the broadcast then
    /// does — an ambiguous post, where the commitment may well be on the
    /// network, is exactly when it is still needed.
    ///
    /// Reads nothing else and signs nothing: the commitment was signed by
    /// `planRegistration`.
    #[wasm_bindgen(js_name = planCommitmentAnchor)]
    pub fn plan_commitment_anchor(
        &self,
        request: PendingRequestValue,
        answers: &mut Answers,
    ) -> WasmResult<RegistrationStepValue> {
        let request: PendingRequest = dto::from_js(request.into(), &PendingRequest::SHAPE)?;
        let pending: verus_flows::Pending<verus_flows::AwaitingCommitment> =
            pending_at(&request.pending, "awaitingCommitment")?;

        let step = advance(&mut answers.inner, |client: &RpcClient<Cassette>| {
            let mut anchored = pending.clone();
            anchored.anchor(client)?;
            Ok(anchored)
        })
        .map_err(WasmError::from)?;

        let step = match step {
            verus_flows::drive::Step::Ask(ask) => PlanStep {
                kind: "ask".into(),
                ask,
                value: None,
            },
            verus_flows::drive::Step::Ready(anchored) => PlanStep {
                kind: "ready".into(),
                ask: Vec::new(),
                value: Some(stored_pending(&anchored, "awaitingCommitment")?),
            },
        };
        Ok(crate::to_js(&step)?.unchecked_into())
    }

    /// Plan step two: the registration itself.
    ///
    /// Only reachable from a `"readyToRegister"` value — the one
    /// [`planCommitmentStatus`](plan_commitment_status) hands back once the
    /// commitment has confirmed. Running it earlier spends the registration fee
    /// against an output the chain will not accept, which is why the step is
    /// checked rather than assumed.
    ///
    /// Nothing is broadcast. See the module docs.
    #[wasm_bindgen(js_name = planRegistrationComplete)]
    pub fn plan_registration_complete(
        &self,
        request: PendingRequestValue,
        answers: &mut Answers,
    ) -> WasmResult<RegisteredStepValue> {
        let request: PendingRequest = dto::from_js(request.into(), &PendingRequest::SHAPE)?;
        let pending: verus_flows::Pending<verus_flows::ReadyToRegister> =
            pending_at(&request.pending, "readyToRegister")?;

        let step = advance(&mut answers.inner, |client: &RpcClient<Cassette>| {
            pending.prepare(client, self.private())
        })
        .map_err(WasmError::from)?;

        let step = PlanStep::of(
            step,
            |unsent: verus_flows::Unsent<verus_flows::Registered>| JsRegistered {
                hex: unsent.hex,
                txid: unsent.txid,
                name: unsent.outcome.name,
                identity_address: dto::identity_address(unsent.outcome.identity_address),
                fee_paid: dto::sats_string(unsent.outcome.fee_paid),
            },
        );
        Ok(crate::to_js(&step)?.unchecked_into())
    }

    /// Sign a login challenge as an identity, stamped with the current tip.
    ///
    /// The tip is what a verifier checks freshness against, which is why this
    /// reads the chain rather than being an offline signature. `Key.signMessage`
    /// is the offline form, for a caller who already knows the height and the
    /// identity's `i` address.
    ///
    /// The value is the signature, base64 — hand it to the verifier alongside
    /// the audience and challenge it was issued with.
    ///
    /// # Errors
    ///
    /// Throws if the identity does not exist. It does **not** check that this
    /// key is one of the identity's primary addresses: that is the verifier's
    /// job, and doing it here would be a check the signer could skip.
    #[wasm_bindgen(js_name = planLogin)]
    pub fn plan_login(
        &self,
        identity: JsText,
        request: LoginRequestValue,
        answers: &mut Answers,
    ) -> WasmResult<LoginStepValue> {
        let identity = dto::text("identity", identity.as_ref())?;
        let request: LoginRequest = dto::from_js(request.into(), &LoginRequest::SHAPE)?;
        let challenge = request.to_flow();

        let step = advance(&mut answers.inner, |client: &RpcClient<Cassette>| {
            verus_flows::sign_login(client, self.private(), &identity, &challenge)
        })
        .map_err(WasmError::from)?;

        let step = PlanStep::of(step, |signature: verus_tx::signature::IdentitySignature| {
            signature.to_base64()
        });
        Ok(crate::to_js(&step)?.unchecked_into())
    }
}
