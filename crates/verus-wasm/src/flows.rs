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
//! import init, { Key, Answers, planHistory } from "@chainvue/verus-wasm";
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
//!     await post(JSON.stringify({ method: "sendrawtransaction", params: [step.transaction.hex] }));
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
//! different transaction each time. So `step.transaction.hex` comes back and
//! the page posts it, once, deliberately, outside the loop.
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
use verus_rpc::{Cassette, RpcClient};

use crate::dto::{self, Shape};
use crate::error::{WasmError, WasmResult};
use crate::keys::Key;
use crate::types::{
    HistoryRequestValue, HistoryStepValue, JsText, PlanSendRequestValue, SendStepValue,
};

/// What a driven operation knows so far, carried between rounds.
///
/// One of these belongs to one operation's planning and is discarded
/// afterwards. That is deliberate rather than wasteful: every round sees the
/// same tip, the same UTXO set and the same identity, so a plan cannot be built
/// half from one view of the chain and half from another.
///
/// It also counts rounds, and gives up after sixteen. An operation that asks
/// for something new every round is a bug, and without the cap it presents as a
/// tab that fetches forever.
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
        self.inner.record(body, reply);
        Ok(())
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

/// One round of a payment plan.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendStep {
    /// `"ask"` or `"ready"`.
    pub kind: String,
    /// JSON-RPC bodies to post verbatim. Empty when `kind` is `"ready"`.
    pub ask: Vec<String>,
    /// The signed transaction. Present only when `kind` is `"ready"`, and
    /// **not broadcast** — see the module docs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<JsPlannedTransaction>,
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

/// One round of a history read.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryStep {
    /// `"ask"` or `"ready"`.
    pub kind: String,
    /// JSON-RPC bodies to post verbatim. Empty when `kind` is `"ready"`.
    pub ask: Vec<String>,
    /// The transactions, oldest first. Present only when `kind` is `"ready"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<JsHistoryEntry>>,
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

    let step = match step {
        Step::Ask(ask) => HistoryStep {
            kind: "ask".into(),
            ask,
            entries: None,
        },
        Step::Ready(entries) => HistoryStep {
            kind: "ready".into(),
            ask: Vec::new(),
            entries: Some(entries.into_iter().map(JsHistoryEntry::from).collect()),
        },
    };
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

        let step = match step {
            Step::Ask(ask) => SendStep {
                kind: "ask".into(),
                ask,
                transaction: None,
            },
            // The `Unsent` is taken apart here and only the bytes survive,
            // which is the point: nothing this module hands back can be sent by
            // anything in this crate.
            Step::Ready(unsent) => SendStep {
                kind: "ready".into(),
                ask: Vec::new(),
                transaction: Some(JsPlannedTransaction::from(unsent.outcome)),
            },
        };
        Ok(crate::to_js(&step)?.unchecked_into())
    }
}
