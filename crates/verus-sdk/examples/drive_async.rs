//! The non-blocking driver: `advance` in an async loop, each round's requests
//! fetched concurrently. Read-only — this spends nothing.
//!
//! ```sh
//! VERUS_ADDRESS=RK9izAySZHQAaCEkRmVV4Xtu73uV5sqsZy \
//!   cargo run -p verus-sdk --features network --example drive_async
//! ```
//!
//! Every other online example here passes an `RpcClient<HttpTransport>` and
//! blocks. That is the right thing for a script and the wrong thing for a
//! wallet, whose UI thread cannot block on a network round trip — so this shows
//! the other caller.
//!
//! # What is actually async, and what is not
//!
//! **The flow is not.** `spendable` below is the same synchronous function a
//! blocking caller uses, unchanged and undeduplicated. `advance` performs no
//! I/O at all: it runs the operation against what is already known and returns
//! either the answer or the request bodies still outstanding.
//!
//! Only the fetching between rounds is async. That is the whole design — the
//! reason `verus-flows` has no async duplicate of every operation, and the
//! reason the same code serves a browser, where the page does the fetching.
//!
//! # Why the requests in a round go out together
//!
//! `Step::Ask` documents its bodies as independent: an operation that needed
//! one answer to form the next question would have stopped at the first one.
//! So a round *can* cost one network round trip rather than one per request,
//! and this drives them accordingly.
//!
//! # What that is actually worth, measured
//!
//! Set `VERUS_COMPARE=1` and each round is fetched **twice** — once
//! concurrently, once one at a time — and both times are printed. Against
//! `api.verustest.net` from a home connection, one run:
//!
//! ```text
//! round 1: 2 request(s) — 0.23s concurrently, 0.09s one at a time
//! round 2: 3 request(s) — 0.09s concurrently, 0.13s one at a time
//! ```
//!
//! Read that honestly. The first round is **slower** concurrently: the
//! connection pool is cold, so two simultaneous requests pay two TLS
//! handshakes where a sequential pair pays one and reuses it. By the second
//! round the pool is warm and three requests come back in 0.09s against 0.13s
//! — a real win, and a modest one. The comparison also flatters sequential,
//! because it runs *second*, on connections the concurrent pass just opened.
//!
//! So the case for fetching a round concurrently is not a large constant
//! factor at n=3 against a fast nearby node. It is that the cost stops scaling
//! with `n`: the coinbase probes below are one request per candidate output, a
//! wallet with forty of them issues forty, and that is where the difference
//! stops being a rounding error. It also matters more the further away the
//! endpoint is, since every saved round trip is a whole RTT.
//!
//! The number this example refuses to print is the tempting one: the sum of
//! each concurrent task's own duration. It looks like the sequential cost and
//! is not — under concurrency every request pays its own handshake and they
//! contend for the link, so the sum overstates the alternative, worst in
//! exactly the wide rounds where the saving is being claimed. A number that
//! flatters the design is not evidence for it.
//!
//! `spendable` is a good subject for this. It asks for the UTXO set and the tip
//! together, and then — because `getaddressutxos` does not say which outputs
//! are coinbases, and a coinbase is unspendable for 100 blocks — probes the
//! transaction behind each candidate.

use std::time::Instant;

use verus_sdk::network::{advance, spendable, Answers, Step};

type Error = Box<dyn std::error::Error>;

/// POST one complete JSON-RPC body, verbatim.
///
/// The bodies come from Rust and are passed through untouched. Nothing here
/// composes a request, which is what keeps the method surface the typed one
/// `verus-rpc` allows — a driver that built its own bodies could reach any
/// method a node exposes, including the wallet ones this SDK exists not to
/// call.
async fn post(
    http: &reqwest::Client,
    endpoint: &str,
    body: String,
) -> Result<String, reqwest::Error> {
    let response = http
        .post(endpoint)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await?;
    response.text().await
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let address = std::env::var("VERUS_ADDRESS").map_err(|_| "set VERUS_ADDRESS=R…")?;
    let endpoint =
        std::env::var("VERUS_ENDPOINT").unwrap_or_else(|_| "https://api.verustest.net".to_string());
    let http = reqwest::Client::new();
    // Off by default: it doubles every request purely to produce a number.
    let compare = std::env::var("VERUS_COMPARE").as_deref() == Ok("1");

    let mut answers = Answers::new();
    let mut requests = 0usize;
    let started = Instant::now();

    let funding = loop {
        // The operation runs here, synchronously, against the cache. No socket
        // is touched inside this closure.
        let step = advance(&mut answers, |client| spendable(client, &address))?;

        let bodies = match step {
            Step::Ready(funding) => break funding,
            Step::Ask(bodies) => bodies,
        };

        requests += bodies.len();
        let round_started = Instant::now();

        // All of them at once. Tagged by index because completion order is not
        // request order, and a reply recorded against the wrong body would be
        // an answer to a question nobody asked.
        let mut tasks = tokio::task::JoinSet::new();
        for (index, body) in bodies.iter().cloned().enumerate() {
            let http = http.clone();
            let endpoint = endpoint.clone();
            tasks.spawn(async move { (index, post(&http, &endpoint, body).await) });
        }

        // A wallet must not copy this error path. One failed request aborts the
        // whole operation, with no retry and no partial recording — which is
        // right for an example (nothing is left half-done) and wrong for a
        // wallet, where a single flaky response should be retried rather than
        // discarding the rounds already paid for. Recording is deliberately
        // after the join, so `Answers` can never hold a partial round.
        let mut replies: Vec<Option<String>> = vec![None; bodies.len()];
        while let Some(joined) = tasks.join_next().await {
            let (index, reply) = joined?;
            replies[index] = Some(reply?);
        }
        let concurrent = round_started.elapsed();

        // The comparison, when asked for: the same bodies again, one at a time,
        // on the same warmed client. Both numbers are then measurements of the
        // same work rather than one measurement and one estimate.
        let sequential = if compare {
            let one_at_a_time = Instant::now();
            for body in bodies.iter().cloned() {
                let _ = post(&http, &endpoint, body).await?;
            }
            Some(one_at_a_time.elapsed())
        } else {
            None
        };

        match sequential {
            Some(sequential) => println!(
                "round {}: {} request(s) — {:.2}s concurrently, {:.2}s one at a time",
                answers.rounds(),
                bodies.len(),
                concurrent.as_secs_f64(),
                sequential.as_secs_f64(),
            ),
            None => println!(
                "round {}: {} request(s) in {:.2}s (set VERUS_COMPARE=1 to time the alternative)",
                answers.rounds(),
                bodies.len(),
                concurrent.as_secs_f64(),
            ),
        }

        for (body, reply) in bodies.into_iter().zip(replies) {
            // `record` refuses an oversized reply. A driver fetches for itself,
            // so nothing else bounds what an endpoint can hand back.
            answers.record(body, reply.expect("every task reported"))?;
        }
    };

    println!(
        "\n{address}: {} spendable across {} output(s) at tip {}",
        funding.total,
        funding.utxos.len(),
        funding.tip,
    );
    // Both lists are reported rather than dropped: "you have 500 and can spend
    // 20" is a fact a wallet has to be able to explain.
    if !funding.immature.is_empty() {
        println!("{} output(s) held back as immature", funding.immature.len());
    }
    if !funding.other.is_empty() {
        println!(
            "{} output(s) are not plain P2PKH — tokens or identities",
            funding.other.len()
        );
    }
    println!(
        "{} request(s) over {} round(s) in {:.2}s total",
        requests,
        answers.rounds(),
        started.elapsed().as_secs_f64(),
    );
    Ok(())
}
