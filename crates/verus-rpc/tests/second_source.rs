//! What a second opinion is worth, and what it costs.
//!
//! The crate docs name one thing an untrusted node can do that is not
//! survivable: misreport chain policy. A wrong `idregistrationfees` is
//! discovered *after* a name commitment has been spent, because the transaction
//! built from it is exactly what the SDK meant to build — no signature check
//! catches it and no sighash commits to it.
//!
//! `SecondSourced` is the mechanism for that one case. These tests pin what it
//! corroborates, what it deliberately does not, and that a disagreement stops
//! the caller *before* anything is paid for.

use std::cell::RefCell;

use verus_rpc::{ChainReader, CurrencyPolicy, RpcError, SecondSourced};
use verus_tx::Amount;

/// A reader that answers from a script and counts what it was asked.
struct Node {
    name: &'static str,
    chain_id: &'static str,
    fee: &'static str,
    referral_levels: u32,
    /// Every question this node was asked, in order.
    asked: RefCell<Vec<String>>,
    /// When set, every call fails with this message instead.
    dead: Option<&'static str>,
    /// The primary address this node reports for any identity.
    identity_key: &'static str,
}

impl Node {
    fn new(fee: &'static str) -> Self {
        Self {
            name: "VRSCTEST",
            chain_id: "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq",
            fee,
            referral_levels: 3,
            asked: RefCell::new(Vec::new()),
            dead: None,
            identity_key: "Rhonest",
        }
    }

    fn dead() -> Self {
        Self::dead_with("connection refused")
    }

    fn dead_with(message: &'static str) -> Self {
        Self {
            dead: Some(message),
            ..Self::new("100")
        }
    }

    fn with_identity_key(mut self, key: &'static str) -> Self {
        self.identity_key = key;
        self
    }

    fn on_chain(mut self, name: &'static str, chain_id: &'static str) -> Self {
        self.name = name;
        self.chain_id = chain_id;
        self
    }

    fn with_referral_levels(mut self, levels: u32) -> Self {
        self.referral_levels = levels;
        self
    }

    fn asked(&self) -> Vec<String> {
        self.asked.borrow().clone()
    }

    /// An identity whose only interesting field is the primary address — which
    /// is exactly the field a forged answer would change.
    fn identity_record(&self, name: &str) -> verus_rpc::IdentityRecord {
        verus_rpc::IdentityRecord {
            fully_qualified_name: name.to_string(),
            identity_address: "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq".into(),
            status: "active".into(),
            outpoint: (
                verus_tx::Txid::from_display_hex(&"ab".repeat(32)).expect("a txid"),
                0,
            ),
            block_height: 900,
            identity: serde_json::json!({
                "primaryaddresses": [self.identity_key],
                "minimumsignatures": 1,
            }),
        }
    }

    fn record<T>(&self, what: &str, answer: T) -> Result<T, RpcError> {
        self.asked.borrow_mut().push(what.to_string());
        if let Some(message) = self.dead {
            return Err(RpcError::Transport(message.into()));
        }
        Ok(answer)
    }
}

impl ChainReader for Node {
    fn chain_info(&self) -> Result<verus_rpc::ChainInfo, RpcError> {
        self.record(
            "getinfo",
            verus_rpc::ChainInfo {
                name: self.name.to_string(),
                chain_id: self.chain_id.to_string(),
                // Deliberately different per node: two healthy nodes are
                // routinely a block apart, and that must not read as a lie.
                blocks: if self.fee == "100" { 1_000 } else { 1_001 },
                longest_chain: 1_001,
                version: "1.2.3".into(),
            },
        )
    }

    fn currency(&self, name_or_id: &str) -> Result<CurrencyPolicy, RpcError> {
        self.record(
            &format!("getcurrency {name_or_id}"),
            CurrencyPolicy {
                currency_id: self.chain_id.to_string(),
                name: self.name.to_string(),
                id_registration_fee: Amount::from_coins_str(self.fee).expect("a fee"),
                id_referral_levels: self.referral_levels,
                id_import_fee: Amount::from_sat(0),
                currency_registration_fee: Amount::from_coins_str("200").expect("a fee"),
                proof_protocol: 1,
            },
        )
    }

    fn block_count(&self) -> Result<u32, RpcError> {
        self.record("getblockcount", 1_000)
    }

    fn mempool(&self) -> Result<Vec<String>, RpcError> {
        self.record("getrawmempool", Vec::new())
    }

    // Everything else is unreachable in these tests and says so rather than
    // answering something plausible.
    fn best_block_hash(&self) -> Result<String, RpcError> {
        unimplemented!("not asked by these tests")
    }
    fn block_hash(&self, _height: u32) -> Result<String, RpcError> {
        unimplemented!("not asked by these tests")
    }
    fn block(&self, _height_or_hash: &str) -> Result<serde_json::Value, RpcError> {
        unimplemented!("not asked by these tests")
    }
    fn address_utxos(&self, _a: &[&str]) -> Result<Vec<verus_rpc::AddressUtxo>, RpcError> {
        unimplemented!("not asked by these tests")
    }
    fn address_deltas(
        &self,
        _a: &[&str],
        _r: Option<(u32, u32)>,
    ) -> Result<Vec<verus_rpc::AddressDelta>, RpcError> {
        unimplemented!("not asked by these tests")
    }
    fn address_balance(&self, _a: &[&str]) -> Result<verus_rpc::AddressBalance, RpcError> {
        unimplemented!("not asked by these tests")
    }
    fn estimate_conversion(
        &self,
        _f: &str,
        _t: &str,
        _a: &str,
        _v: Option<&str>,
    ) -> Result<verus_rpc::ConversionEstimate, RpcError> {
        unimplemented!("not asked by these tests")
    }
    fn currency_state(&self, _n: &str) -> Result<serde_json::Value, RpcError> {
        unimplemented!("not asked by these tests")
    }
    fn list_currencies(&self) -> Result<Vec<verus_rpc::CurrencySummary>, RpcError> {
        unimplemented!("not asked by these tests")
    }
    fn currency_converters(
        &self,
        _c: &[&str],
    ) -> Result<Vec<verus_rpc::CurrencyConverter>, RpcError> {
        unimplemented!("not asked by these tests")
    }
    fn estimate_fee(&self, _b: u32) -> Result<Option<Amount>, RpcError> {
        unimplemented!("not asked by these tests")
    }
    fn identity(&self, name_or_id: &str) -> Result<verus_rpc::IdentityRecord, RpcError> {
        let record = self.identity_record(name_or_id);
        self.record(&format!("getidentity {name_or_id}"), record)
    }
    fn identity_at(
        &self,
        name_or_id: &str,
        height: u32,
    ) -> Result<verus_rpc::IdentityRecord, RpcError> {
        let record = self.identity_record(name_or_id);
        self.record(&format!("getidentity {name_or_id} @ {height}"), record)
    }
    fn identity_content(&self, _n: &str) -> Result<verus_rpc::IdentityContent, RpcError> {
        unimplemented!("not asked by these tests")
    }
    fn identity_registration(&self, name_or_id: &str) -> Result<String, RpcError> {
        // Keyed off the identity key so a "lying" node names a different
        // registration, which is what a forged referral chain looks like.
        let txid = format!("{:0>64}", self.identity_key.to_lowercase());
        self.record(&format!("getidentity {name_or_id} (registration)"), txid)
    }
    fn vdxf_id(&self, _n: &str) -> Result<[u8; 20], RpcError> {
        unimplemented!("not asked by these tests")
    }
    fn offers(
        &self,
        _c: &str,
        _i: bool,
        _w: bool,
    ) -> Result<Vec<verus_rpc::OfferListing>, RpcError> {
        unimplemented!("not asked by these tests")
    }
    fn verify_message(&self, _i: &str, _s: &str, _m: &str) -> Result<bool, RpcError> {
        unimplemented!("not asked by these tests")
    }
    fn raw_transaction(&self, _t: &str) -> Result<serde_json::Value, RpcError> {
        unimplemented!("not asked by these tests")
    }
    fn decode_raw_transaction(&self, _h: &str) -> Result<serde_json::Value, RpcError> {
        unimplemented!("not asked by these tests")
    }
    fn confirmations(&self, _t: &str) -> Result<Option<u32>, RpcError> {
        unimplemented!("not asked by these tests")
    }
}

/// Two honest nodes agree, and both were actually asked.
#[test]
fn agreement_returns_the_answer_and_consults_both() {
    let reader = SecondSourced::new(Node::new("100"), Node::new("100"));
    let policy = reader.currency("VRSCTEST").expect("they agree");
    assert_eq!(
        policy.id_registration_fee,
        Amount::from_coins_str("100").unwrap()
    );

    // The whole mechanism is worthless if the second node is not consulted.
    assert_eq!(reader.primary().asked(), vec!["getcurrency VRSCTEST"]);
    assert_eq!(reader.secondary().asked(), vec!["getcurrency VRSCTEST"]);
}

/// The failure this exists for: one node lies about the registration fee.
///
/// A wrong fee here is not caught by anything downstream — the commitment is
/// built correctly *from the wrong number*, paid for, and only the registration
/// that follows fails. So the disagreement has to stop the caller now.
#[test]
fn a_lie_about_the_registration_fee_is_caught_before_anything_is_spent() {
    // 100 and 7, not 100 and 1: `Amount` renders as `Amount(10000000000)` and
    // `Amount(100000000)`, and *both* of those contain "100" and "1". With
    // those the assertions below would pass even if the implementation reported
    // the two sides the wrong way round.
    let reader = SecondSourced::new(Node::new("100"), Node::new("7"));
    match reader.currency("VRSCTEST") {
        Err(RpcError::SourcesDisagree {
            question,
            primary,
            secondary,
        }) => {
            assert_eq!(question, "getcurrency VRSCTEST");
            // Both answers are named, and attributed to the right side. "They
            // disagree" without the numbers leaves an operator nothing to
            // judge.
            assert!(primary.contains("10000000000"), "{primary}");
            assert!(secondary.contains("700000000"), "{secondary}");
        }
        other => panic!("expected a disagreement, got {other:?}"),
    }
}

/// A forged identity is an authentication bypass, and it is caught.
///
/// `verify_login` reads an identity's authority set from a node and then
/// verifies the signature locally *against whatever the node said*. There is no
/// transaction, so nothing downstream rejects it: one lying node answering with
/// an attacker's key in `primaryaddresses` logs the attacker in as someone
/// else.
#[test]
fn a_forged_identity_is_caught() {
    let reader = SecondSourced::new(
        Node::new("100").with_identity_key("Rhonest"),
        Node::new("100").with_identity_key("Rattacker"),
    );
    match reader.identity("alice@") {
        Err(RpcError::SourcesDisagree { question, .. }) => {
            assert_eq!(question, "getidentity alice@");
        }
        other => panic!("expected a disagreement, got {other:?}"),
    }
}

/// And the same read at a settled height, which is what a login actually makes.
///
/// An identity as it stood at a past height is immutable chain history, so two
/// honest nodes cannot differ — this is the corroboration with no false-positive
/// rate at all.
#[test]
fn a_forged_historical_identity_is_caught() {
    let reader = SecondSourced::new(
        Node::new("100").with_identity_key("Rhonest"),
        Node::new("100").with_identity_key("Rattacker"),
    );
    match reader.identity_at("alice@", 1_000) {
        Err(RpcError::SourcesDisagree { question, .. }) => {
            assert_eq!(question, "getidentity alice@ @ 1000");
        }
        other => panic!("expected a disagreement, got {other:?}"),
    }
    // Two honest nodes still agree, so the check is not simply always failing.
    let honest = SecondSourced::new(
        Node::new("100").with_identity_key("Rhonest"),
        Node::new("100").with_identity_key("Rhonest"),
    );
    assert!(honest.identity_at("alice@", 1_000).is_ok());
}

/// When both sources fail, the primary's error is the one reported.
///
/// It is the more useful one: the primary is the node every uncorroborated read
/// is served from, so its failure is the one that describes the session.
#[test]
fn both_sources_dead_reports_the_primary() {
    let reader = SecondSourced::new(
        Node::dead_with("primary is gone"),
        Node::dead_with("so is the other"),
    );
    match reader.currency("VRSCTEST") {
        Err(RpcError::Transport(message)) => assert_eq!(message, "primary is gone"),
        other => panic!("expected the primary's error, got {other:?}"),
    }
}

/// Every field of the policy is compared, not only the fee.
///
/// `id_referral_levels` decides how many referrers get paid out of that fee, so
/// a node lying about it produces a fee split the chain rejects — after the
/// commitment.
#[test]
fn the_whole_policy_is_compared_not_just_the_fee() {
    let reader = SecondSourced::new(
        Node::new("100").with_referral_levels(3),
        Node::new("100").with_referral_levels(0),
    );
    assert!(matches!(
        reader.currency("VRSCTEST"),
        Err(RpcError::SourcesDisagree { .. })
    ));
}

/// Two nodes on different chains is a configuration mistake worth catching.
#[test]
fn two_nodes_on_different_chains_are_refused() {
    let reader = SecondSourced::new(
        Node::new("100"),
        Node::new("100").on_chain("VRSC", "i5w5MuNik5NtLcYmNzcvaoixooEebB6MGV"),
    );
    match reader.chain_info() {
        Err(RpcError::SourcesDisagree {
            primary, secondary, ..
        }) => {
            assert!(primary.starts_with("VRSCTEST /"), "{primary}");
            // `starts_with`, not `contains`: "VRSCTEST" contains "VRSC", so a
            // `contains` here would pass even if both sides were the same
            // chain.
            assert!(secondary.starts_with("VRSC /"), "{secondary}");
        }
        other => panic!("expected a disagreement, got {other:?}"),
    }
}

/// But a height difference is not a lie.
///
/// Two healthy nodes are routinely a block apart. A decorator that reported
/// that as a disagreement would fire constantly and be turned off, taking the
/// fee check with it — so the heights are deliberately different in the double
/// above and this must still pass.
#[test]
fn a_height_difference_is_not_a_disagreement() {
    let reader = SecondSourced::new(Node::new("100"), Node::new("101"));
    let info = reader.chain_info().expect("same chain, different tips");
    assert_eq!(info.name, "VRSCTEST");
    // And the two doubles really did report different heights, so this is not
    // passing because they happened to match.
    assert_ne!(
        reader.primary().chain_info().unwrap().blocks,
        reader.secondary().chain_info().unwrap().blocks
    );
}

/// A second source that cannot answer is a failure, not a pass.
///
/// The point is a *corroborated* answer. Silently substituting an
/// uncorroborated one would make the whole thing decorative the first time a
/// node went down — which is exactly when a caller most wants to know.
#[test]
fn an_unreachable_second_source_does_not_silently_pass() {
    let reader = SecondSourced::new(Node::new("100"), Node::dead());
    assert!(matches!(
        reader.currency("VRSCTEST"),
        Err(RpcError::Transport(_))
    ));
    // And it was genuinely asked, rather than skipped.
    assert_eq!(reader.secondary().asked(), vec!["getcurrency VRSCTEST"]);
}

/// A dead *primary* fails too, and for the same reason.
#[test]
fn an_unreachable_primary_does_not_fall_through_to_the_secondary() {
    let reader = SecondSourced::new(Node::dead(), Node::new("100"));
    assert!(matches!(
        reader.currency("VRSCTEST"),
        Err(RpcError::Transport(_))
    ));
}

/// Everything else costs one request, not two.
///
/// Corroborating a tip or a mempool would report a disagreement whenever two
/// nodes were momentarily out of step, which is most of the time — and those
/// are the answers whose failure mode is already benign. This pins that the
/// line is where the docs say it is.
#[test]
fn uncorroborated_reads_only_touch_the_primary() {
    let reader = SecondSourced::new(Node::new("100"), Node::new("999"));

    assert_eq!(reader.block_count().expect("primary only"), 1_000);
    assert!(reader.mempool().expect("primary only").is_empty());

    assert_eq!(
        reader.primary().asked(),
        vec!["getblockcount", "getrawmempool"]
    );
    assert!(
        reader.secondary().asked().is_empty(),
        "the second node must not be asked: {:?}",
        reader.secondary().asked()
    );
}

/// An uncorroborated read comes from the primary, not the secondary.
///
/// Counting requests shows the secondary was not *asked*; it does not show the
/// answer came from the right node. A delegation routed to `self.secondary`
/// would ask exactly one node and return the wrong answer, and the count test
/// above would still pass.
#[test]
fn an_uncorroborated_answer_comes_from_the_primary() {
    let reader = SecondSourced::new(Node::new("100"), Node::new("999"));
    // Only the primary reports 1_000; the secondary reports 1_001.
    assert_eq!(reader.chain_info().expect("same chain").blocks, 1_000);
    assert_eq!(reader.primary().chain_info().unwrap().blocks, 1_000);
    assert_eq!(reader.secondary().chain_info().unwrap().blocks, 1_001);
}

// --------------------------------------------------------------------- live

/// Two nodes on different chains, live.
///
/// `api.verustest.net` and `api.verus.services` are the public testnet and
/// mainnet endpoints. Pointing a wallet at one while believing it is the other
/// is an ordinary configuration mistake, and every answer that followed would
/// be about the wrong chain — so this is the corroboration firing on real
/// infrastructure rather than on a double.
///
/// ```sh
/// VERUS_LIVE_RPC=1 cargo test -p verus-rpc --test second_source -- --nocapture
/// ```
#[cfg(feature = "http")]
#[test]
fn live_two_public_nodes_on_different_chains_disagree() {
    if std::env::var("VERUS_LIVE_RPC").is_err() {
        eprintln!("skipping: set VERUS_LIVE_RPC=1");
        return;
    }
    use verus_rpc::{HttpTransport, RpcClient};

    let testnet = RpcClient::new(HttpTransport::new("https://api.verustest.net").expect("url"));
    let mainnet = RpcClient::new(HttpTransport::new("https://api.verus.services").expect("url"));
    let reader = SecondSourced::new(testnet, mainnet);

    match reader.chain_info() {
        Err(RpcError::SourcesDisagree {
            primary, secondary, ..
        }) => eprintln!("caught, as it should be: {primary} vs {secondary}"),
        other => panic!("two chains should not agree: {other:?}"),
    }
}

/// And two nodes on the *same* chain agreeing about policy, live.
///
/// Needs a second VRSCTEST endpoint, because the whole point is two
/// independent nodes — corroborating an endpoint against itself would prove
/// only that the comparison compiles.
///
/// ```sh
/// VERUS_LIVE_RPC=1 VERUS_LIVE_SECOND_RPC='http://user:password@127.0.0.1:18843' \
///   cargo test -p verus-rpc --test second_source -- --nocapture
/// ```
///
/// `HttpTransport` moves credentials out of the URL into a redacted field, so
/// they do not reach a log.
#[cfg(feature = "http")]
#[test]
fn live_two_nodes_agree_about_registration_policy() {
    let Ok(second) = std::env::var("VERUS_LIVE_SECOND_RPC") else {
        eprintln!("skipping: set VERUS_LIVE_SECOND_RPC to a second VRSCTEST endpoint");
        return;
    };
    if std::env::var("VERUS_LIVE_RPC").is_err() {
        eprintln!("skipping: set VERUS_LIVE_RPC=1");
        return;
    }
    use verus_rpc::{HttpTransport, RpcClient};

    let public = RpcClient::new(HttpTransport::new("https://api.verustest.net").expect("url"));
    let own = RpcClient::new(HttpTransport::new(second).expect("url"));
    let reader = SecondSourced::new(public, own);

    let info = reader.chain_info().expect("both should be on VRSCTEST");
    eprintln!("both nodes report {} / {}", info.name, info.chain_id);

    let policy = reader
        .currency("VRSCTEST")
        .expect("both should report the same registration policy");
    eprintln!(
        "corroborated: idregistrationfees {} across {} referral level(s)",
        policy.id_registration_fee, policy.id_referral_levels
    );
}

/// The second step of a referral chain is corroborated too.
///
/// `identity()` resolves the immediate referrer; the levels above it are walked
/// through `identity_registration()`. Corroborating only the first step leaves
/// the deeper payees on one node's word — and `idreferrallevels` is 3 on the
/// chains that matter, so most of the chain would be uncovered.
#[test]
fn a_forged_referral_chain_is_caught() {
    let reader = SecondSourced::new(
        Node::new("100").with_identity_key("Rhonest"),
        Node::new("100").with_identity_key("Rattacker"),
    );
    match reader.identity_registration("bob@") {
        Err(RpcError::SourcesDisagree { question, .. }) => {
            assert!(question.contains("bob@"), "{question}");
        }
        other => panic!("expected a disagreement, got {other:?}"),
    }

    // Two honest nodes still agree, so this is not simply always failing.
    let honest = SecondSourced::new(
        Node::new("100").with_identity_key("Rhonest"),
        Node::new("100").with_identity_key("Rhonest"),
    );
    assert!(honest.identity_registration("bob@").is_ok());
    // And both were consulted.
    assert_eq!(honest.secondary().asked().len(), 1);
}
