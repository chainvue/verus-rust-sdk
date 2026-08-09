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
use wasm_bindgen::JsCast;

use verus_flows::drive::{advance, Step};
use verus_rpc::{Cassette, ChainReader, RpcClient};
use verus_tx::currency_definition::CurrencyDefinition;

use crate::dto::{self, Shape};
use crate::error::{WasmError, WasmResult};
use crate::keys::Key;
use crate::types::{
    CommitmentStatusStepValue, ContentRequestValue, ContentStepValue, HistoryRequestValue,
    HistoryStepValue, JsText, LaunchStepValue, LoginRequestValue, LoginStepValue,
    OfferTermsRequestValue, OfferTermsStepValue, OffersRequestValue, OffersStepValue,
    PendingRequestValue, PlanBurnRequestValue, PlanConvertFromIdentityRequestValue,
    PlanConvertRequestValue, PlanLaunchRequestValue, PlanMintRequestValue, PlanPublishRequestValue,
    PlanRegistrationRequestValue, PlanSendFromIdentityRequestValue, PlanSendRequestValue,
    PlanSendTokenFromIdentityRequestValue, PlanSendTokenRequestValue, RegisteredStepValue,
    RegistrationStepValue, SpendableRequestValue, SpendableStepValue, TakeOfferRequestValue,
    TakeOfferStepValue, TransactionStepValue, UpdateStepValue, VerifyLoginRequestValue,
    VerifyLoginStepValue,
};

/// What a driven operation knows so far, carried between rounds.
///
/// # Make a new one for every operation
///
/// **An `Answers` is a frozen view of the chain, not a connection.** Nothing in
/// it expires, and it is spent the moment a `plan…` call returns `"ready"`.
/// Passing it to another `plan…` call after that throws rather than planning
/// against the *first* operation's tip and the first operation's UTXO set —
/// which is what would happen otherwise, however long ago that was, because a
/// cached answer is indistinguishable from a fresh one. A wallet that kept one
/// around and reused it would eventually build a payment from coins it had
/// already spent, with nothing on this side to notice.
///
/// Within one operation that same frozen view is exactly what is wanted: every
/// round sees the same chain, so a plan cannot be built half from one view and
/// half from another. Driving the *same* operation again after a round's fetch
/// failed is unaffected — the handle is only spent once it reaches `"ready"`,
/// and a transient network failure happens before that.
///
/// So: `new Answers()`, drive one operation to `"ready"`, `free()`.
///
/// # The round cap
///
/// It counts rounds and gives up after sixteen. An operation that asks for
/// something new every round is a bug, and without the cap it presents as a tab
/// that fetches forever. The count is per `Answers`, so it only ever reflects
/// one operation's own rounds — reuse across operations is refused outright,
/// before a shared count could ever be the thing that caught it.
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
        // **Measured before it is copied.** `dto::text` allocates the whole
        // string into linear memory, and the ceiling exists precisely because
        // that copy is what kills the module: a browser that cannot grow memory
        // for a 300 MB reply does not get an error, it gets a dead instance
        // with any imported key inside it. Checking afterwards enforced the
        // limit only for callers who had already survived the thing it guards
        // against — and linear memory never shrinks, so every refused reply
        // left the module permanently larger.
        //
        // See `reject_oversized_reply` for how the size is measured without
        // touching linear memory, and without the three-times-too-generous
        // bound an earlier version used.
        reject_oversized_reply(reply.as_ref())?;
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

// Bound directly rather than through `web-sys`, whose generated `encode()`
// takes a Rust `&str` — which would force the very conversion this exists to
// avoid making before the size is known to be safe. Taking the `JsString` we
// already hold instead means the reply is never touched on the Rust side
// until it is known to fit.
#[wasm_bindgen]
extern "C" {
    type TextEncoder;

    #[wasm_bindgen(constructor)]
    fn new() -> TextEncoder;

    #[wasm_bindgen(method)]
    fn encode(this: &TextEncoder, input: &js_sys::JsString) -> js_sys::Uint8Array;
}

/// Refuse a reply too large to copy, without copying it.
///
/// Returns `Ok` for anything that is not a string: `dto::text` reports that
/// better, and this is only about size.
///
/// # Why this measures exactly, not `units * 3`
///
/// An earlier version bounded the reply by its UTF-16 length times three —
/// the worst-case UTF-8 expansion. JSON-RPC replies are overwhelmingly ASCII,
/// where the true ratio is one, so that bound made the effective wasm ceiling
/// roughly a third of the native one, and told a caller whose reply was
/// refused a byte count up to 3x too high (verus-rust-sdk#146).
///
/// `TextEncoder::encode` gives the exact count instead, and does so without
/// giving up the property the worst-case bound existed to protect: the
/// `Uint8Array` it returns is a handle onto a buffer the JS engine keeps on
/// its own heap, so reading its `.length()` costs one property read, and no
/// byte of the reply crosses into this module's linear memory before the
/// size is known to be safe. Copying into linear memory is still exactly
/// what `dto::text` does afterwards, for a reply this function has already
/// let through.
fn reject_oversized_reply(reply: &JsValue) -> WasmResult<()> {
    let Some(string) = reply.dyn_ref::<js_sys::JsString>() else {
        return Ok(());
    };
    let ceiling = verus_flows::drive::MAX_REPLY_BYTES as u64;

    // Every UTF-16 code unit is at least one UTF-8 byte, so the unit count
    // alone is a true lower bound on the encoded size. When that already
    // clears the ceiling, the reply is provably oversized without spending
    // an encode — load-bearing for a hostile multi-hundred-megabyte reply,
    // which this rejects without the JS engine ever encoding it.
    let units = u64::from(js_sys::JsString::length(string));
    if units > ceiling {
        return Err(WasmError::new(
            "ReplyTooLarge",
            format!(
                "a reply of at least {units} bytes exceeds the {ceiling}-byte ceiling; it is \
                 refused before being copied into the module"
            ),
        ));
    }

    let exact = u64::from(TextEncoder::new().encode(string).length());
    if exact > ceiling {
        return Err(WasmError::new(
            "ReplyTooLarge",
            format!(
                "a reply of {exact} bytes exceeds the {ceiling}-byte ceiling; it is refused \
                 before being copied into the module"
            ),
        ));
    }
    Ok(())
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
    /// Value in outputs an unconfirmed transaction already spends, in satoshis,
    /// as a decimal string.
    ///
    /// Withheld from `utxos` because spending one again would build a
    /// conflicting transaction. Kept out of `notYetSpendable` deliberately:
    /// that figure means "wait", and this money is not waiting for anything —
    /// it has left and is settling. This is what a wallet should label
    /// "pending", not "unavailable".
    ///
    /// **Best-effort.** A mempool belongs to one node: another node, or this
    /// one after a restart, may not have the spending transaction, in which
    /// case this reads zero and the coins reappear in `utxos`.
    pub spent_unconfirmed: String,
}

impl From<verus_flows::Funding> for JsFunding {
    fn from(funding: verus_flows::Funding) -> Self {
        Self {
            tip: funding.tip,
            total: dto::sats_string(funding.total),
            not_yet_spendable: dto::sats_string(funding.immature_total()),
            spent_unconfirmed: dto::sats_string(funding.spent_unconfirmed_total()),
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

/// A token payment out of a VerusID's own outputs.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanSendTokenFromIdentityRequest {
    /// The identity holding the token — a name or an `i…` address.
    pub identity: String,
    /// The token's currency id, as an `i…` address.
    pub currency: String,
    /// Where the token is going.
    pub to: String,
    /// How much, in satoshis, as a decimal string.
    pub amount: String,
}

impl PlanSendTokenFromIdentityRequest {
    /// The keys a `PlanSendTokenFromIdentityRequest` object may carry.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[
            ("identity", None),
            ("currency", None),
            ("to", None),
            ("amount", None),
        ],
    };
}

/// A conversion funded straight out of the VerusID that holds the token.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanConvertFromIdentityRequest {
    /// The identity holding the token — a name or an `i…` address.
    pub identity: String,
    /// The currency being spent, as an `i…` address.
    ///
    /// The token the identity holds, **not** the identity itself. For a token
    /// whose supply was preallocated to its defining identity the two look
    /// alike in a wallet and are different values here.
    pub from: String,
    /// How much of it, in satoshis, as a decimal string.
    pub amount: String,
    /// Which kind of conversion. One of `"intoFractional"`, `"intoReserve"`,
    /// `"reserveToReserve"`, `"preconvert"`.
    ///
    /// Minting and burning are not here, for the same reason they are not on
    /// `planConvert`.
    pub kind: String,
    /// The currency being bought — the fractional, the reserve, or the target.
    pub into: String,
    /// The fractional to route through. **Only** for `"reserveToReserve"`.
    #[serde(default)]
    pub via: Option<String>,
    /// Where the result should land — an `R…` or `i…` address.
    pub recipient: String,
    /// The conversion fee, in satoshis, as a decimal string.
    pub fee: String,
}

impl PlanConvertFromIdentityRequest {
    /// The keys a `PlanConvertFromIdentityRequest` object may carry.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[
            ("identity", None),
            ("from", None),
            ("amount", None),
            ("kind", None),
            ("into", None),
            ("via", None),
            ("recipient", None),
            ("fee", None),
        ],
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
        conversion_kind_of(&self.kind, &self.into, &self.via)
    }
}

/// Resolve a conversion kind from the three flat fields that carry it.
///
/// Shared by `planConvert` and `planConvertFromIdentity` so the two cannot
/// drift on which strings are accepted or which combinations are refused.
fn conversion_kind_of(
    kind: &str,
    into_text: &str,
    via: &Option<String>,
) -> WasmResult<verus_tx::convert::ConversionKind> {
    {
        use verus_tx::convert::ConversionKind;
        let into = dto::currency("into", into_text)?;

        let routed = matches!(kind, "reserveToReserve");
        match (via, routed) {
            (Some(_), false) => {
                return Err(WasmError::new(
                    "InvalidArgument",
                    format!(
                        "via is only used by a reserveToReserve conversion, and kind is {:?}",
                        kind
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

        Ok(match kind {
            "intoFractional" => ConversionKind::IntoFractional { fractional: into },
            "intoReserve" => ConversionKind::IntoReserve { reserve: into },
            "reserveToReserve" => ConversionKind::ReserveToReserve {
                via: dto::currency("via", via.as_deref().unwrap_or_default())?,
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
                        kind
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
/// and `planRegistrationComplete` refuses a value that is not
/// `"readyToRegister"`.
///
/// That is a real weakening and worth naming precisely. `state` is the **only**
/// thing distinguishing the two steps: the inner blob serializes identically
/// either way, so editing the string is enough to get past the check. What
/// stops it there is the chain rather than this crate — a registration built
/// against a commitment that has not confirmed spends an input the chain will
/// not accept, so the transaction is rejected rather than mined. Nothing
/// further is lost; the commitment fee went when the commitment did.
///
/// So the check catches the mistake, not an attack, and the attack it does not
/// catch costs the person making it. Both halves of that are worth knowing
/// before building on it.
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
    /// The flow's own state, including the salt. **Opaque** — a JSON string to
    /// store and hand back unchanged, not an object to look inside.
    ///
    /// (The field, not the wrapper: [`JsPending`] itself is rebuilt like every
    /// other request object — see its `SHAPE`.)
    ///
    /// A string rather than a nested object deliberately. The request sanitizer
    /// does not recurse into a leaf, so an object here would reach
    /// `serde_json::Value` with its nesting bounded only by the stack — the
    /// module-bricking overflow [`crate::dto::from_js`] documents closing for
    /// `utxos`. As text it goes through `serde_json::from_str`, whose own
    /// recursion limit refuses a hostile blob cleanly, and "hand it back
    /// unchanged" becomes literally true rather than a request.
    pub pending: String,
}

impl JsPending {
    /// The keys a stored registration may carry.
    ///
    /// Declared, and reached through [`PendingRequest`]'s nested pointer, so
    /// this object is **rebuilt** like every other request rather than trusted.
    /// It was a leaf first, and that was the one place in the crate where
    /// `from_js`'s promise — that nested objects get the same treatment — did
    /// not hold: a page with a polluted `Object.prototype` could supply `state`
    /// from the prototype chain and walk past the step check that replaces
    /// Rust's type-level ordering.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[
            ("state", None),
            ("name", None),
            ("registrationFee", None),
            ("commitmentHex", None),
            ("commitmentTxid", None),
            ("pending", None),
        ],
    };
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
    /// The reservation salt, 32 bytes as hex. Omit and one is drawn here.
    ///
    /// Supplying one makes the **reservation** reproducible: the same name,
    /// key and salt always derive the same claim, and therefore the same
    /// commitment *hash*. That is what lets a page which lost its state
    /// re-derive the claim and go looking for its commitment output on chain,
    /// rather than losing the fee.
    ///
    /// It does **not** make the commitment *transaction* reproducible. That
    /// one spends whichever outputs were available and expires relative to the
    /// tip, so re-planning after the chain has moved gives different bytes and
    /// a different txid for the same reservation. Recovery means matching the
    /// commitment script, not the txid.
    ///
    /// Whatever you choose must be unpredictable: the salt is what stops
    /// somebody else seeing your name before you have claimed it. An
    /// all-zero salt is refused for that reason.
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
    /// The nested shape is followed, so the stored value is rebuilt rather
    /// than trusted — every field of it comes from the object's own
    /// properties, never from its prototype.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[("pending", Some(&JsPending::SHAPE))],
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
    /// The node has never seen the commitment, and it can still be mined. It
    /// may never have been posted, or it may have been dropped from the
    /// mempool. Re-broadcast it.
    ///
    /// The default only because a drift check needs one, and this is the
    /// variant that claims least.
    #[default]
    Gone,
    /// The commitment can never be mined. **Start over** — this is not a
    /// retry state.
    ///
    /// Its expiry is inside the signed bytes, so re-posting sends the same
    /// doomed transaction and the node answers `-26: tx-expiring-soon`. The
    /// salt in the stored `pending` is worthless now; discard it and make a
    /// fresh reservation, which costs another commitment fee.
    Expired {
        /// The height it stopped being minable at.
        expiry_height: u32,
        /// Where the chain was when that was established.
        tip: u32,
    },
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

/// A currency to define and launch.
///
/// # Two fields the daemon has and this does not
///
/// **`conversions`** is absent because the daemon ignores it. Its own captures
/// settle it: a definition created by passing `conversions: [4.0]` comes back
/// carrying `[0.0]`, and every one of the fourteen fractional vectors in this
/// repo's daemon fixtures has an all-zero conversions vector. Launch prices are derived at
/// launch from what was actually contributed. Accepting the field would let a
/// caller build a definition in a byte shape no daemon has ever emitted.
///
/// **`initialContributions`** is absent because nothing here can honour it. A
/// contribution is not just a number in the definition: the daemon's own
/// contribution launch carries an **extra value-bearing output** funding it,
/// and this SDK's launch builder makes seven outputs and never that one.
/// Declaring reserves no output funds is a currency claiming backing it does
/// not have. The sibling TypeScript SDK refuses the field for the same reason.
///
/// # The parallel arrays
///
/// A fractional basket is described by several arrays that are read
/// **positionally**: `currencies[i]`, `weights[i]`, `conversions[i]` and the
/// preconversion bounds all describe the same reserve. They must therefore be
/// the same length and in the same order, and nothing on chain checks that for
/// you — a launch defined with them misaligned pays its fee and creates a
/// currency whose reserves are not what its author meant.
///
/// So they are checked here, by name, before anything is built. It is the one
/// guard worth having: a launch fee is not refundable and a currency cannot be
/// redefined.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JsCurrencyDefinition {
    /// The name, without the parent. Must match the defining identity's.
    pub name: String,
    /// The parent currency, as an `i…` address — the chain's own currency for
    /// a top-level identity, or the parent identity's id for a sub-identity.
    ///
    /// Named rather than derived, and then **checked against the identity the
    /// chain holds** — refused before signing rather than left to consensus.
    pub parent: String,
    /// `"token"` for a simple token, `"fractional"` for a reserve basket.
    pub kind: String,
    /// The height conversions become possible and preconversions stop. Must be
    /// after the current tip — the chain refuses a launch in the past.
    pub start_block: f64,
    /// The height the currency stops, or omit for never.
    #[serde(default)]
    pub end_block: Option<f64>,
    /// Supply created at launch, in satoshis, as a decimal string.
    #[serde(default)]
    pub initial_supply: Option<String>,
    /// `2` makes the currency **centralized**: its controlling identity may
    /// mint new supply. Omit for `1`, which cannot.
    #[serde(default)]
    pub proof_protocol: Option<i32>,
    /// The reserve currencies, as `i…` addresses. Fractional only.
    #[serde(default)]
    pub currencies: Vec<String>,
    /// Each reserve's weight, in satoshis. Same length and order as
    /// `currencies`.
    #[serde(default)]
    pub weights: Vec<String>,
    /// The least that must be preconverted per reserve for the launch to go
    /// ahead. Below it, **every** contribution is refunded.
    #[serde(default)]
    pub min_preconversion: Vec<String>,
    /// The most that may be preconverted per reserve.
    #[serde(default)]
    pub max_preconversion: Vec<String>,
    /// Supply handed to named identities at launch.
    #[serde(default)]
    pub preallocations: Vec<JsPreallocation>,
    /// What registering a sub-identity under this currency costs, in satoshis.
    #[serde(default)]
    pub id_registration_fees: Option<String>,
    /// How many referral levels pay out.
    #[serde(default)]
    pub id_referral_levels: Option<f64>,
    /// What importing an identity costs, in satoshis.
    #[serde(default)]
    pub id_import_fees: Option<String>,
}

/// Supply handed to a named identity at launch.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JsPreallocation {
    /// The recipient identity's `i…` address.
    pub recipient: String,
    /// How much, in satoshis, as a decimal string.
    pub amount: String,
}

impl JsPreallocation {
    /// The keys a preallocation object may carry.
    pub const SHAPE: Shape = Shape {
        fields: &[("recipient", None), ("amount", None)],
    };
}

impl JsCurrencyDefinition {
    /// The keys a `CurrencyDefinition` object may carry.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[
            ("name", None),
            ("parent", None),
            ("kind", None),
            ("startBlock", None),
            ("endBlock", None),
            ("initialSupply", None),
            ("proofProtocol", None),
            ("currencies", None),
            ("weights", None),
            ("minPreconversion", None),
            ("maxPreconversion", None),
            ("preallocations", Some(&JsPreallocation::SHAPE)),
            ("idRegistrationFees", None),
            ("idReferralLevels", None),
            ("idImportFees", None),
        ],
    };
}

/// What to launch, and under which identity.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanLaunchRequest {
    /// The defining identity — a name or an `i…` address. The currency takes
    /// its name and its id.
    pub identity: String,
    /// The currency to define.
    pub definition: JsCurrencyDefinition,
    /// Override the launch fee read from the parent's chain policy, in
    /// satoshis. The node reports that figure and it is **burned outright**,
    /// so pinning it is the escape hatch for a node that misreports it.
    #[serde(default)]
    pub pin_launch_fee: Option<String>,
}

impl PlanLaunchRequest {
    /// The keys a `PlanLaunchRequest` object may carry.
    pub(crate) const SHAPE: Shape = Shape {
        fields: &[
            ("identity", None),
            ("definition", Some(&JsCurrencyDefinition::SHAPE)),
            ("pinLaunchFee", None),
        ],
    };
}

/// A currency launch, built and signed. **Not broadcast.**
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsLaunched {
    /// The raw transaction, hex — what `sendrawtransaction` takes.
    pub hex: String,
    /// Its txid in display order, computed before anything is sent.
    pub txid: String,
    /// The new currency's id — the defining identity's `i` address.
    pub currency_id: String,
    /// The height conversions become possible.
    pub start_block: f64,
    /// The launch fee, in satoshis. **Burned**, not paid to anyone.
    pub launch_fee: String,
}

impl JsCurrencyDefinition {
    /// Build the SDK's definition, checking what only the caller can get wrong.
    fn to_definition(&self) -> WasmResult<CurrencyDefinition> {
        let parent = dto::currency("parent", &self.parent)?;
        // The parallel arrays, checked against `currencies` by name. A launch
        // defined with them misaligned pays its fee and creates a currency
        // whose reserves are not what its author meant, and no chain rule
        // catches it.
        let reserves = self.currencies.len();
        for (field, list) in [
            ("minPreconversion", &self.min_preconversion),
            ("maxPreconversion", &self.max_preconversion),
        ] {
            // These two the daemon does emit empty, so an empty one is a
            // caller declining to set bounds rather than a misalignment.
            if !list.is_empty() && list.len() != reserves {
                return Err(WasmError::new(
                    "InvalidArgument",
                    format!(
                        "{field} has {} entries but currencies has {reserves}; they describe the \
                         same reserves position by position",
                        list.len()
                    ),
                ));
            }
        }

        let fractional = match self.kind.as_str() {
            "token" => false,
            "fractional" => true,
            other => {
                return Err(WasmError::new(
                    "InvalidArgument",
                    format!("unknown currency kind {other:?}; expected token or fractional"),
                ))
            }
        };
        if fractional && reserves == 0 {
            return Err(WasmError::new(
                "InvalidArgument",
                "a fractional currency is a basket of reserves and needs at least one",
            ));
        }
        if !fractional && reserves > 0 {
            return Err(WasmError::new(
                "InvalidArgument",
                "a token holds no reserves; use kind \"fractional\" to define a basket",
            ));
        }

        let mut definition = CurrencyDefinition::token(
            parent,
            self.name.clone(),
            height("startBlock", self.start_block)?,
        );
        if fractional {
            definition.options |= verus_tx::currency_definition::option::FRACTIONAL;
        }
        if let Some(end) = self.end_block {
            definition.end_block = height("endBlock", end)?;
        }
        if let Some(supply) = &self.initial_supply {
            definition.initial_supply = dto::sats(supply)?;
        }
        if let Some(protocol) = self.proof_protocol {
            if protocol != 1 && protocol != 2 {
                return Err(WasmError::new(
                    "InvalidArgument",
                    format!("proofProtocol is 1 or 2, not {protocol}"),
                ));
            }
            definition.proof_protocol = protocol;
        }

        definition.currencies = self
            .currencies
            .iter()
            .map(|id| dto::currency("currencies", id))
            .collect::<WasmResult<_>>()?;
        // Weights carry the reserve ratios, so they are the field where being
        // wrong is least visible and least recoverable.
        if fractional && self.weights.len() != reserves {
            return Err(WasmError::new(
                "InvalidArgument",
                format!(
                    "a fractional currency needs one weight per reserve: {} currencies, {} \
                     weights",
                    reserves,
                    self.weights.len()
                ),
            ));
        }
        let weights = amounts("weights", &self.weights)?;
        definition.weights = weights
            .iter()
            .map(|amount| {
                // Clamping was the previous answer and it is the wrong one:
                // it rewrites a weight rather than refusing it, and a rewritten
                // weight is a reserve ratio nobody chose.
                i32::try_from(amount.to_sat()).map_err(|_| {
                    WasmError::new(
                        "InvalidArgument",
                        format!("weight {} is larger than a weight can be", amount.to_sat()),
                    )
                })
            })
            .collect::<WasmResult<_>>()?;
        // Weights are fractions of one, and every definition the daemon has
        // ever produced sums to exactly one coin. A set that does not is a
        // basket whose reserves do not add up.
        if fractional {
            let total: u64 = weights.iter().map(|w| w.to_sat()).sum();
            if total != verus_tx::SATS_PER_COIN {
                return Err(WasmError::new(
                    "InvalidArgument",
                    format!(
                        "weights are fractions of one and must sum to {} satoshis; these sum \
                         to {total}",
                        verus_tx::SATS_PER_COIN
                    ),
                ));
            }
        }
        // Every positional vector is present at reserve length, zero-filled
        // where the caller said nothing — because that is what the daemon
        // emits, and a byte comparison against its own captures is what
        // established it. Leaving them empty produced a definition shorter than
        // any the daemon has ever written.
        //
        // `conversions`, `initialContributions` and `preconverted` are zero
        // and not settable: see this type's docs for why.
        // Three of the five are zero-filled at reserve length and two are left
        // empty when unset. That asymmetry is the daemon's, read out of its own
        // captures byte by byte rather than guessed: `fractional_two_reserves`
        // carries `conversions`, `initialContributions` and `preconverted` as
        // two zeros each, and both preconversion bounds as nothing at all.
        //
        // Zero-filling all five, which was the first attempt, produced a
        // definition the daemon has never written.
        let zeros = || vec![verus_tx::Amount::ZERO; reserves];
        definition.conversions = zeros();
        definition.min_preconversion = amounts("minPreconversion", &self.min_preconversion)?;
        definition.max_preconversion = amounts("maxPreconversion", &self.max_preconversion)?;
        definition.initial_contributions = zeros();
        definition.preconverted = zeros();

        definition.preallocations = self
            .preallocations
            .iter()
            .map(|pre| {
                Ok(verus_tx::currency_definition::Preallocation {
                    recipient: dto::identity_id("preallocations.recipient", &pre.recipient)?,
                    amount: dto::sats(&pre.amount)?,
                })
            })
            .collect::<WasmResult<_>>()?;

        if let Some(fee) = &self.id_registration_fees {
            definition.id_registration_fees = dto::sats(fee)?.to_sat();
        }
        if let Some(levels) = self.id_referral_levels {
            let levels = whole_number("idReferralLevels", levels)?;
            if levels > MAX_ID_REFERRAL_LEVELS {
                return Err(WasmError::new(
                    "InvalidArgument",
                    format!("idReferralLevels is at most {MAX_ID_REFERRAL_LEVELS}, not {levels}"),
                ));
            }
            definition.id_referral_levels = levels;
            // Levels without the option bit is a number the chain never reads.
            if levels > 0 {
                definition.options |= verus_tx::currency_definition::option::ID_REFERRALS;
            }
        }
        if let Some(fee) = &self.id_import_fees {
            definition.id_import_fees = dto::sats(fee)?.to_sat();
        }
        Ok(definition)
    }
}

/// The most referral levels a currency may pay out.
const MAX_ID_REFERRAL_LEVELS: u64 = 5;

/// A whole, non-negative count from a JavaScript number.
///
/// Separate from [`height`] because the message matters: a fractional referral
/// level reported as "must be a whole, non-negative block height" sends a
/// caller looking at the wrong field entirely.
fn whole_number(field: &str, value: f64) -> WasmResult<u64> {
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > f64::from(u32::MAX) {
        return Err(WasmError::new(
            "InvalidArgument",
            format!("{field} must be a whole, non-negative count, not {value}"),
        ));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(value as u64)
}

/// A launch height on its way back to JavaScript.
///
/// Heights are well inside what a float64 holds exactly, so this is not the
/// lossy conversion the money rule exists to prevent — written out rather than
/// left implicit so that is visible.
fn launch_height(height: u64) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    {
        height as f64
    }
}

/// A list of decimal-string satoshi amounts.
fn amounts(field: &str, list: &[String]) -> WasmResult<Vec<verus_tx::Amount>> {
    list.iter()
        .enumerate()
        .map(|(index, text)| {
            dto::sats(text)
                .map_err(|e| WasmError::new(e.code(), format!("{field}[{index}]: {}", e.message())))
        })
        .collect()
}

/// A block height from a JavaScript number, refusing one that is not a height.
///
/// A `number` is a float64, so it can arrive fractional, negative or beyond
/// what a height can hold. Silently truncating any of those picks a block
/// nobody asked for — and `startBlock` decides when a currency launches.
fn height(field: &str, value: f64) -> WasmResult<u64> {
    // `i32::MAX`, not what a float64 can hold: `startBlock` and `endBlock` go
    // on the wire as int32, so a larger value serializes into bytes the daemon
    // cannot read back — a signed transaction rejected unparsed.
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > f64::from(i32::MAX) {
        return Err(WasmError::new(
            "InvalidArgument",
            format!("{field} must be a whole, non-negative block height, not {value}"),
        ));
    }
    // Exact: the guard above bounds it to the integers a float64 holds.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(value as u64)
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
    // `from_str`, so serde_json's own recursion limit applies: a blob nested
    // thousands deep is refused here rather than unwound on the wasm stack.
    serde_json::from_str(&stored.pending).map_err(|e| {
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
        pending: serde_json::to_string(pending).map_err(|e| {
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
                verus_flows::CommitmentStatus::Expired { expiry_height, tip } => {
                    JsCommitmentStatus::Expired { expiry_height, tip }
                }
                // `CommitmentStatus` is `#[non_exhaustive]`, so a newer
                // `verus-flows` can name a state this binding was built before.
                //
                // Refused rather than mapped onto the nearest known variant.
                // Every arm above tells a wallet something different about
                // money it has already committed — whether to keep waiting,
                // re-register, or give up — and guessing wrong tells a user to
                // wait for something dead, or to abandon a registration that
                // was still live. An error names the mismatch; a wrong status
                // hides it.
                other => {
                    return Err(WasmError::new(
                        "UnknownCommitmentStatus",
                        format!(
                            "this build reports commitment states it knows; verus-flows \
                             returned {other:?}, which postdates it. Rebuild the wasm module \
                             against the same verus-flows version"
                        ),
                    ))
                }
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

    /// Plan moving a **token** a VerusID holds, rather than its native coins.
    ///
    /// The missing half of [`planSendFromIdentity`](Self::plan_send_from_identity),
    /// and the only way to reach a non-mintable token's supply. A token's
    /// supply is the sum of its `preallocations`, and a preallocation names an
    /// identity — so for `proofprotocol` 1 every unit that will ever exist is
    /// created into an identity-held output and never passes through a
    /// key-held address. Without this, that supply cannot be spent at all.
    ///
    /// The token inputs are the identity's and carry fulfillments; the miner
    /// fee comes from this key's own coins, because an identity holding a
    /// token need not hold native coins as well. Token surplus returns to the
    /// identity, never to the fee key — money under an identity's authority
    /// should not migrate to a bare key.
    ///
    /// # Errors
    ///
    /// Throws if the identity does not exist, is revoked, does not list this
    /// key as a primary address, needs more signatures than one, or holds none
    /// of that token.
    #[wasm_bindgen(js_name = planSendTokenFromIdentity)]
    pub fn plan_send_token_from_identity(
        &self,
        request: PlanSendTokenFromIdentityRequestValue,
        answers: &mut Answers,
    ) -> WasmResult<TransactionStepValue> {
        let request: PlanSendTokenFromIdentityRequest =
            dto::from_js(request.into(), &PlanSendTokenFromIdentityRequest::SHAPE)?;
        let amount = dto::sats(&request.amount)?;
        let currency = dto::currency("currency", &request.currency)?;
        let (identity, to) = (request.identity, request.to);

        let step = advance(&mut answers.inner, |client: &RpcClient<Cassette>| {
            verus_flows::prepare_send_token_from_identity(
                client,
                &[self.private()],
                self.private(),
                &identity,
                currency,
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

    /// Plan a conversion funded straight out of the VerusID holding the token.
    ///
    /// The identity supplies the token; this key signs both its fulfillment and
    /// the plain coins that pay the miner fee. Those coins are required rather
    /// than optional — a token an identity holds is a reserve output carrying
    /// **zero satoshis**, so it cannot pay its own way, and an identity holding
    /// a token need not hold native coins at all.
    ///
    /// # Why not send it out and convert it
    ///
    /// A token's supply is the sum of its preallocations, and a preallocation
    /// names an identity — so for `proofprotocol` 1 every unit exists on the
    /// defining identity and never touches a key-held address. Seeding a basket
    /// with it otherwise takes two transactions, and between them the supply
    /// sits at a bare address while the launch window runs down. A basket that
    /// reaches its start block with an empty reserve refunds its **entire**
    /// launch, and the name cannot be reused.
    ///
    /// # Where the money goes
    ///
    /// Token surplus returns to the **identity**; native change to this key's
    /// own address.
    ///
    /// # Errors
    ///
    /// Throws if the identity does not exist, is revoked, is timelocked, does
    /// not list this key as a primary address, needs more than one signature,
    /// holds none of that token, or if this key has no coins for the fee.
    #[wasm_bindgen(js_name = planConvertFromIdentity)]
    pub fn plan_convert_from_identity(
        &self,
        request: PlanConvertFromIdentityRequestValue,
        answers: &mut Answers,
    ) -> WasmResult<TransactionStepValue> {
        let request: PlanConvertFromIdentityRequest =
            dto::from_js(request.into(), &PlanConvertFromIdentityRequest::SHAPE)?;
        let kind = conversion_kind_of(&request.kind, &request.into, &request.via)?;
        let amount = dto::sats(&request.amount)?;
        let fee = checked_fee(&request.fee)?;
        let (identity, from, recipient) = (request.identity, request.from, request.recipient);

        let step = advance(&mut answers.inner, |client: &RpcClient<Cassette>| {
            verus_flows::prepare_conversion_from_identity(
                client,
                self.private(),
                &identity,
                &from,
                amount,
                kind,
                &recipient,
                fee,
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
            Some(text) => {
                let salt = dto::fixed_hex::<32>("salt", text)?;
                // Entropy cannot be judged from one value, but the sentinel a
                // caller reaches for while wiring things up can be. A
                // predictable salt lets somebody else derive the commitment
                // hash for a name they can see you are about to claim.
                if salt == [0u8; 32] {
                    return Err(WasmError::new(
                        "InvalidArgument",
                        "an all-zero salt is not a secret; the salt is what stops somebody                          claiming the name before you do",
                    ));
                }
                Some(salt)
            }
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

    /// Plan defining and launching a currency under an identity's authority.
    ///
    /// The currency takes the identity's name, and **the identity's id becomes
    /// the currency's id**. An identity defines exactly one currency, ever, so
    /// this is not an operation to retry casually: the launch fee is **burned**
    /// rather than paid to anyone, and a currency cannot be redefined.
    ///
    /// Checked before anything is signed — each of these otherwise costs the
    /// fee and produces a currency nobody wanted:
    ///
    /// * the identity exists, is not revoked, and this key is a primary address
    ///   on it;
    /// * it does not already define a currency;
    /// * the definition's name and parent match the identity the chain holds —
    ///   a mismatch is refused here, before signing, not left to consensus;
    /// * `startBlock` is after the tip, because the chain refuses a launch in
    ///   the past;
    /// * the reserve arrays are the same length, because they are read position
    ///   by position and nothing on chain notices when they are not.
    ///
    /// # One signature only
    ///
    /// As with the other identity-authorised plans, this signs with this key
    /// alone, so an identity needing more is refused by name.
    ///
    /// Nothing is broadcast. See the module docs.
    #[wasm_bindgen(js_name = planLaunch)]
    pub fn plan_launch(
        &self,
        request: PlanLaunchRequestValue,
        answers: &mut Answers,
    ) -> WasmResult<LaunchStepValue> {
        let request: PlanLaunchRequest = dto::from_js(request.into(), &PlanLaunchRequest::SHAPE)?;
        let pin = match &request.pin_launch_fee {
            Some(text) => Some(dto::sats(text)?),
            None => None,
        };
        let definition = request.definition.to_definition()?;
        let identity = request.identity;

        let step = advance(&mut answers.inner, |client: &RpcClient<Cassette>| {
            verus_flows::prepare_launch(client, &[self.private()], &identity, &definition, pin)
        })
        .map_err(WasmError::from)?;

        let step = PlanStep::of(
            step,
            |unsent: verus_flows::Unsent<verus_flows::Launched>| JsLaunched {
                hex: unsent.hex,
                txid: unsent.txid,
                currency_id: dto::identity_address(unsent.outcome.currency_id),
                start_block: launch_height(unsent.outcome.start_block),
                launch_fee: dto::sats_string(unsent.outcome.launch_fee),
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

#[cfg(test)]
mod launch_definition_tests {
    use super::*;

    /// The daemon's own captures, and what a `JsCurrencyDefinition` naming the
    /// same thing must serialize to.
    ///
    /// This is the test the launch binding most needed and did not have. Every
    /// other assertion about `planLaunch` is a refusal, so the field-by-field
    /// mapping — the highest-risk copy in the crate, and the one that decides
    /// what a burned launch fee buys — had no coverage at all. Swapping two
    /// fields in `to_definition` left the whole gate green.
    ///
    /// The oracle is `fixtures/daemon/currency_definitions.json`: definitions
    /// the daemon itself produced, with the script bytes it emitted.
    fn vector(name: &str) -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/daemon/currency_definitions.json"
        );
        let file: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("fixtures")).expect("json");
        file["vectors"][name].clone()
    }

    /// Build the script the SDK would put on chain for `spec`.
    fn script_of(spec: &JsCurrencyDefinition) -> String {
        let definition = spec.to_definition().expect("the definition converts");
        hex::encode(
            verus_tx::currency_definition::currency_definition_script(&definition)
                .expect("the definition serializes"),
        )
    }

    const VRSCTEST: &str = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";
    const NAME: &str = "verusrpc-test-mrhu3gpo3wws";
    const START: f64 = 1_167_853.0;

    fn base(kind: &str) -> JsCurrencyDefinition {
        JsCurrencyDefinition {
            name: NAME.into(),
            parent: VRSCTEST.into(),
            kind: kind.into(),
            start_block: START,
            // Every one of these vectors carries a 1-coin sub-identity fee and
            // a 0.02-coin import fee.
            id_registration_fees: Some("100000000".into()),
            id_import_fees: Some("2000000".into()),
            ..JsCurrencyDefinition::default()
        }
    }

    #[test]
    fn a_plain_token_matches_the_daemons_own_bytes() {
        let expected = vector("token_simple");
        assert_eq!(
            script_of(&base("token")),
            expected["definition_script"].as_str().expect("script")
        );
    }

    /// `proofProtocol: 2` is what makes a currency mintable by its identity, so
    /// getting this bit wrong decides whether supply can ever be created.
    #[test]
    fn a_centralized_token_matches_the_daemons_own_bytes() {
        let expected = vector("token_centralized");
        let spec = JsCurrencyDefinition {
            proof_protocol: Some(2),
            ..base("token")
        };
        assert_eq!(
            script_of(&spec),
            expected["definition_script"].as_str().expect("script")
        );
    }

    /// Referral levels only mean anything with the option bit set, and the
    /// daemon sets it: this vector's options are 40, which is `TOKEN | 0x8`.
    #[test]
    fn referral_levels_carry_their_option_bit() {
        let expected = vector("token_idreferrals");
        let spec = JsCurrencyDefinition {
            id_referral_levels: Some(3.0),
            ..base("token")
        };
        assert_eq!(
            script_of(&spec),
            expected["definition_script"].as_str().expect("script"),
            "levels without ID_REFERRALS is a number the chain never reads"
        );
    }

    /// The shape where the positional arrays matter.
    #[test]
    fn a_fractional_basket_matches_the_daemons_own_bytes() {
        let expected = vector("fractional_two_reserves");
        let spec = JsCurrencyDefinition {
            initial_supply: Some("100000000000".into()),
            currencies: vec![VRSCTEST.into(), "i713y8RkyAhfWZrreBgUq8tG9J5SxqCbRX".into()],
            weights: vec!["50000000".into(), "50000000".into()],
            ..base("fractional")
        };
        assert_eq!(
            script_of(&spec),
            expected["definition_script"].as_str().expect("script")
        );
    }

    /// Weights are fractions of one. A set that does not sum to one is a basket
    /// whose reserves do not add up, and no daemon vector has ever been one.
    #[test]
    fn weights_that_do_not_sum_to_one_are_refused() {
        let spec = JsCurrencyDefinition {
            currencies: vec![VRSCTEST.into(), "i713y8RkyAhfWZrreBgUq8tG9J5SxqCbRX".into()],
            weights: vec!["50000000".into(), "40000000".into()],
            ..base("fractional")
        };
        let error = spec.to_definition().expect_err("weights must sum to one");
        assert!(error.message().contains("sum to"), "{}", error.message());
    }

    /// A weight larger than the field can hold used to be clamped to
    /// `i32::MAX`, which rewrites a reserve ratio rather than refusing it.
    #[test]
    fn an_oversized_weight_is_refused_rather_than_clamped() {
        let spec = JsCurrencyDefinition {
            currencies: vec![VRSCTEST.into()],
            weights: vec!["3000000000".into()],
            ..base("fractional")
        };
        let error = spec.to_definition().expect_err("a weight has a ceiling");
        assert!(
            error.message().contains("larger than"),
            "{}",
            error.message()
        );
    }

    /// A basket needs one weight per reserve, and an empty list used to pass:
    /// the length check exempted it, and a fractional currency with no weights
    /// is not a currency anybody meant to define.
    #[test]
    fn a_fractional_currency_needs_a_weight_for_every_reserve() {
        let spec = JsCurrencyDefinition {
            currencies: vec![VRSCTEST.into(), "i713y8RkyAhfWZrreBgUq8tG9J5SxqCbRX".into()],
            weights: Vec::new(),
            ..base("fractional")
        };
        let error = spec
            .to_definition()
            .expect_err("weights are not optional here");
        assert!(error.message().contains("one weight per reserve"));
    }

    /// `startBlock` and `endBlock` go on the wire as int32, so a larger height
    /// serializes into bytes the daemon cannot read back.
    #[test]
    fn a_height_beyond_int32_is_refused() {
        let spec = JsCurrencyDefinition {
            start_block: 2f64.powi(40),
            ..base("token")
        };
        assert!(spec.to_definition().is_err());
    }
}
