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
    ContentRequestValue, ContentStepValue, HistoryRequestValue, HistoryStepValue, JsText,
    LoginRequestValue, LoginStepValue, PlanSendRequestValue, SendStepValue, SpendableRequestValue,
    SpendableStepValue, VerifyLoginRequestValue, VerifyLoginStepValue,
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
    ) -> WasmResult<SendStepValue> {
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
