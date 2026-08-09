//! Parsing bodies the live network actually produced.
//!
//! The fixtures under `fixtures/rpc/` are captures from the live network,
//! committed for the same reason `fixtures/daemon/` is: a mock written from
//! documentation tests my reading of the docs, not the wire.
//!
//! Most are verbatim replies from `api.verustest.net`. The two `getoffers_*`
//! files are the exceptions and are labelled as such in the fixture README:
//! one is from **mainnet**, because shapes that matter — an offer side naming
//! several currencies, an amount in exponent form — do not occur on VRSCTEST
//! at all; and both are trimmed to a few representative entries, the full
//! replies being 96 KB and 671 KB. Trimming drops whole listings and never
//! edits one.
//!
//! Three of the bugs this crate is shaped around are invisible unless the bytes
//! are real: a money field arriving as a JSON float, an error reply omitting
//! `result` rather than nulling it, and an identity name arriving with its
//! non-ASCII characters escaped.

use std::cell::RefCell;

use verus_rpc::{Broadcaster, ChainReader, RequestBody, RpcClient, RpcError, Transport};

/// Answers from a recorded body, and records what was asked.
///
/// Also the proof that [`Transport`] is a usable extension point: everything
/// here is reachable by an outside implementor, and composing a request is not.
struct Recorded {
    body: String,
    asked: RefCell<Vec<String>>,
}

impl Recorded {
    fn new(fixture: &str) -> Self {
        let path = format!(
            "{}/../../fixtures/rpc/{fixture}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        Recorded {
            body: std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}")),
            asked: RefCell::new(Vec::new()),
        }
    }
}

impl Transport for Recorded {
    fn post(&self, body: &RequestBody) -> Result<String, RpcError> {
        self.asked.borrow_mut().push(body.as_str().to_string());
        Ok(self.body.clone())
    }
}

fn client(fixture: &str) -> RpcClient<Recorded> {
    RpcClient::new(Recorded::new(fixture))
}

#[test]
fn reads_chain_info() {
    let info = client("getinfo").chain_info().unwrap();
    assert_eq!(info.name, "VRSCTEST");
    assert_eq!(info.chain_id, "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq");
    assert_eq!(info.blocks, 1_167_555);
    assert_eq!(info.longest_chain, 1_167_555);
    assert_eq!(info.version, "1.2.17");
}

/// The fixture this crate exists for.
///
/// `idregistrationfees` is `100.0` in the captured body — coins, as a JSON
/// float — while every builder takes satoshis. Reading it as a number and
/// multiplying by 1e8 is the float path the workspace bans; this asserts the
/// exact result instead.
#[test]
fn reads_the_registration_fee_from_a_float_literal_without_a_float() {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/rpc/getcurrency_vrsctest.json"
    ))
    .unwrap();
    assert!(
        raw.contains(r#""idregistrationfees":100.0"#),
        "the fixture no longer carries the float literal, so this test proves nothing"
    );

    let policy = client("getcurrency_vrsctest").currency("VRSCTEST").unwrap();
    assert_eq!(policy.name, "VRSCTEST");
    assert_eq!(policy.id_registration_fee.to_sat(), 100_00000000);
    assert_eq!(policy.id_referral_levels, 3);
    assert_eq!(policy.id_import_fee.to_sat(), 2_000_000);
    assert_eq!(policy.proof_protocol, 1);
}

/// The one figure a currency launch cannot proceed without.
///
/// Half of it becomes the reserve deposit and half is consumed by consensus with
/// no output accounting for it, so a wrong value produces a transaction the
/// daemon rejects. It is chain policy, which is why it is read rather than
/// assumed — and it arrives as a JSON float like the rest.
#[test]
fn reads_the_currency_registration_fee() {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/rpc/getcurrency_vrsctest.json"
    ))
    .unwrap();
    assert!(
        raw.contains(r#""currencyregistrationfee":200.0"#),
        "the fixture no longer carries the literal, so this test proves nothing"
    );

    let policy = client("getcurrency_vrsctest").currency("VRSCTEST").unwrap();
    assert_eq!(policy.currency_registration_fee.to_sat(), 200_00000000);

    // The split a launch is built from: the ceiling half is the reserve
    // deposit, the rest is burned.
    let fee = policy.currency_registration_fee.to_sat();
    assert_eq!(fee - fee / 2, 100_00000000);
}

/// A currency whose definition carries no launch fee reads as zero rather than
/// failing — the field is absent from some replies, and a launch that needs it
/// refuses on the zero.
#[test]
fn an_absent_currency_registration_fee_is_zero() {
    let policy = client("getcurrency_vrsctest").currency("VRSCTEST").unwrap();
    assert!(policy.currency_registration_fee.to_sat() > 0, "sanity");

    struct Bare;
    impl Transport for Bare {
        fn post(&self, _body: &RequestBody) -> Result<String, RpcError> {
            Ok(
                r#"{"result":{"currencyid":"i","name":"X","idregistrationfees":1.0,
                   "idreferrallevels":0,"idimportfees":0.0}}"#
                    .replace('\n', "")
                    .clone(),
            )
        }
    }
    let bare = RpcClient::new(Bare).currency("X").unwrap();
    assert_eq!(bare.currency_registration_fee.to_sat(), 0);
}

/// The fee and the referral split, straight from the node's own policy — the
/// numbers a caller should see before spending a name commitment.
#[test]
fn the_registration_split_follows_the_currencys_own_policy() {
    let policy = client("getcurrency_vrsctest").currency("VRSCTEST").unwrap();

    let (outlay, referral) = verus_rpc::registration_cost(&policy, false);
    assert_eq!(referral.to_sat(), 0);
    assert_eq!(outlay.to_sat(), 100_00000000);

    // 3 levels: the registrant pays fee * (levels + 1) / (levels + 2).
    let (outlay, referral) = verus_rpc::registration_cost(&policy, true);
    assert_eq!(referral.to_sat(), 100_00000000 / 5);
    assert_eq!(outlay.to_sat(), 100_00000000 / 5 * 4);
}

#[test]
fn reads_unspent_outputs() {
    let utxos = client("getaddressutxos_funded")
        .address_utxos(&["RJUgxvDnDLsRGCXNKDK56Rxngzh6m25J6F"])
        .unwrap();
    assert_eq!(utxos.len(), 6);

    let first = &utxos[0];
    assert_eq!(first.utxo.vout, 1);
    assert_eq!(first.utxo.satoshis.to_sat(), 8_830_000);
    assert_eq!(first.height, 1_166_385);
    assert!(first.is_spendable);
    // Display order, as a user would paste it.
    assert_eq!(
        first.utxo.txid.to_display_hex(),
        "5e19de6d3f77b5e1f49ec92db23027d5f026db92004b026465a61bff8ab13d7e"
    );
    assert!(first.utxo.script_pubkey.starts_with(&[0x76, 0xa9, 0x14]));
}

/// An address with nothing is an ordinary answer, not an error. A client that
/// treats `[]` as a failure makes "you have no funds" indistinguishable from
/// "the node is broken".
#[test]
fn an_address_with_nothing_is_an_empty_list_not_an_error() {
    let utxos = client("getaddressutxos_empty")
        .address_utxos(&["RHFuSSCAdBCbWt7wxSJeEXphH8W9XNQYs1"])
        .unwrap();
    assert!(utxos.is_empty());
}

/// The clearest illustration of why [`verus_rpc`] has two money readers: this
/// one reply carries the **same** native balance twice — `112006615800` as
/// satoshis, and `1120.066158` as coins under the chain's own currency id.
/// Reading either field with the other's units is wrong by 1e8.
#[test]
fn a_balance_reports_the_same_money_in_two_units_and_both_read_exactly() {
    let balance = client("getaddressbalance")
        .address_balance(&["RJUgxvDnDLsRGCXNKDK56Rxngzh6m25J6F"])
        .unwrap();

    assert_eq!(balance.balance.to_sat(), 112_006_615_800);
    assert_eq!(balance.received.to_sat(), 2_186_125_143_800);

    // The native currency, reported in coins, must land on the same satoshis.
    let native = &balance.currency_balance["iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq"];
    assert_eq!(*native, balance.balance);

    // And the tokens this session minted, also in coins.
    assert_eq!(
        balance.currency_balance["i7UCaJkKRFXBCK4S1AMrkfKTnPwdLc7dV7"].to_sat(),
        150_00000000
    );
}

/// A node could answer with an output belonging to an address nobody asked
/// about. The sighash commits to the script, so the worst case is a rejected
/// transaction rather than a misdirected one — but failing here names the cause
/// instead of leaving a `-26` to be interpreted.
#[test]
fn an_output_for_an_address_we_did_not_ask_about_is_refused() {
    let wrong = client("getaddressutxos_funded").address_utxos(&["RSomeOtherAddress"]);
    match wrong {
        Err(RpcError::Unexpected(message)) => assert!(message.contains("not asked about")),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn reads_an_identity_and_the_output_holding_it() {
    let record = client("getidentity_rustsdk").identity("rustsdk@").unwrap();
    assert_eq!(record.fully_qualified_name, "rustsdk.VRSCTEST@");
    assert_eq!(
        record.identity_address,
        "iPYbC4ExJ7dRBZnpxq2LGXGgkWDQNQR48g"
    );
    assert_eq!(record.block_height, 1_166_566);
    assert!(!record.is_revoked());
    // The whole object stays reachable: an update has to rebuild every field,
    // and dropping the ones this crate does not model would silently clear them.
    assert!(record.identity.get("contentmap").is_some());
    assert_eq!(record.identity["minimumsignatures"], 1);
}

/// A reply with no `identityaddress` — or one that is not a string — is
/// refused rather than read as an identity whose address is empty. An empty
/// string would parse as a real answer to anything that string-compares this
/// field instead of decoding it, turning a malformed reply into a silent
/// non-match instead of the error it should be.
#[test]
fn an_identity_with_no_identityaddress_is_refused() {
    struct Body(&'static str);
    impl Transport for Body {
        fn post(&self, _body: &RequestBody) -> Result<String, RpcError> {
            Ok(self.0.to_string())
        }
    }

    for broken in [
        // Missing entirely.
        r#"{"version":1}"#,
        // Present but not a string.
        r#"{"identityaddress":42,"version":1}"#,
    ] {
        let body = format!(
            r#"{{"result":{{"fullyqualifiedname":"x.VRSC@","status":"active",
            "txid":"00000000000000000000000000000000000000000000000000000000000000ab",
            "vout":0,"blockheight":1,
            "identity":{broken}}}}}"#
        );
        match RpcClient::new(Body(Box::leak(body.into_boxed_str()))).identity("x") {
            Err(RpcError::Unexpected(message)) => {
                assert!(message.contains("identityaddress"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}

/// `-5` on `getidentity` means "no such identity", which is a *fact about the
/// chain*, not a failure. `confirmations` relies on the same code meaning "never
/// seen it", so the mapping has to be exact.
#[test]
fn an_unknown_identity_is_a_node_error_with_its_code_intact() {
    match client("err_notfound").identity("nosuchname@") {
        Err(RpcError::Node { code, message }) => {
            assert_eq!(code, -5);
            assert_eq!(message, "Identity not found");
        }
        other => panic!("expected -5, got {other:?}"),
    }
    // And the same code, on a transaction, is an answer rather than an error.
    assert_eq!(
        client("err_notfound")
            .confirmations("00".repeat(32).as_str())
            .unwrap(),
        None
    );
}

/// The reply to a broadcast the node would not decode. Surfacing the daemon's
/// own message verbatim matters: `-22` and `-26` need completely different
/// responses from a wallet.
#[test]
fn a_rejected_broadcast_keeps_the_daemons_own_message() {
    match client("err_baddecode").send_raw_transaction("not hex") {
        Err(RpcError::Node { code, message }) => {
            assert_eq!(code, -22);
            assert_eq!(message, "TX decode failed");
        }
        other => panic!("expected -22, got {other:?}"),
    }
}

/// A long help text, returned as an error message, must not be truncated or
/// swallowed — it is usually the only clue about which parameter was wrong.
#[test]
fn a_long_error_message_survives_intact() {
    match client("err_badparam").currency("") {
        Err(RpcError::Node { code, message }) => {
            assert_eq!(code, -1);
            assert!(message.len() > 200, "message was {} bytes", message.len());
            assert!(message.contains("getcurrency"));
        }
        other => panic!("expected -1, got {other:?}"),
    }
}

/// The failure that defines what this SDK can do on public infrastructure.
///
/// `getblock`, `z_gettreestate` and `getsaplingtree` all answer this way on
/// `api.verustest.net`, which is exactly why shielded flows cannot be served
/// there. It needs its own variant because the remedy — use another endpoint —
/// is nothing like the remedy for a node that said no.
#[test]
fn a_missing_method_is_distinguishable_from_a_refusal() {
    match client("err_methodmissing").raw_transaction("00".repeat(32).as_str()) {
        Err(RpcError::MethodUnavailable { method }) => assert_eq!(method, "getrawtransaction"),
        other => panic!("expected MethodUnavailable, got {other:?}"),
    }
    // And it must not be mistaken for "the node has never seen this
    // transaction", which would report a real outage as a missing payment.
    assert!(client("err_methodmissing")
        .confirmations("00".repeat(32).as_str())
        .is_err());
}

/// Every request this crate emits is one of the typed methods, addressed to a
/// node as JSON-RPC. Pinning the framing keeps a daemon-side parser change
/// visible.
#[test]
fn requests_name_their_method_and_nothing_else() {
    let client = client("getinfo");
    let _ = client.chain_info();
    let _ = client.block_count();

    let asked = client.transport().asked.borrow();
    assert_eq!(asked.len(), 2);
    assert!(asked[0].contains(r#""method":"getinfo""#));
    assert!(asked[1].contains(r#""method":"getblockcount""#));
    for body in asked.iter() {
        assert!(body.contains(r#""jsonrpc":"1.0""#));
    }
}

/// The captured reply is the settled token demand seen from the taker's side —
/// `6a9256a4ecf4f7cfc9fb46c6c87a875f1cdd12efbcce0612e7d7bfa871c414ab`, block
/// 1170750, the row `PROVEN.md` records.
///
/// It is the fixture worth having because it exercises every awkward part of
/// the shape at once: a spend row and a receive row for the same output, a
/// token leg carrying `satoshis` of **zero**, and a native leg reported twice
/// in one row — once as satoshis, once under the chain's own id in coins.
#[test]
fn reads_address_deltas_with_their_signs_intact() {
    let deltas = client("getaddressdeltas")
        .address_deltas(
            &["RGRTws8PJQC5oBqftKMCAaBD1Vj5MHKKSz"],
            Some((1_170_740, 1_170_760)),
        )
        .unwrap();
    assert_eq!(deltas.len(), 7);

    // The output being spent by the swap: negative, and negative in both units.
    let spent = deltas
        .iter()
        .find(|d| d.spending && d.satoshis.to_sat() != 0)
        .expect("a native spend row");
    assert_eq!(spent.satoshis.to_sat(), -200_000_000);
    assert!(spent.satoshis.is_negative());
    assert_eq!(
        spent.currency_values["iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq"].to_sat(),
        -200_000_000
    );

    // A token leg moves no native value at all. Reading only `satoshis` here
    // reports five tokens arriving as nothing happening.
    let token_in = deltas
        .iter()
        .find(|d| !d.spending && d.height == 1_170_746 && d.satoshis.to_sat() == 0)
        .expect("a token receive row");
    assert_eq!(
        token_in.currency_values["i7UCaJkKRFXBCK4S1AMrkfKTnPwdLc7dV7"].to_sat(),
        500_000_000
    );
}

/// What the fold in `verus_flows::history` has to arrive at, asserted here on
/// the raw rows so the two cannot drift apart silently.
///
/// The taker paid 1 `sdkcuralpha` and received 0.5 VRSCTEST, less a 0.0002
/// fee. So across the swap transaction the token nets to **-1** and the native
/// side to **+0.4998** — which is the economics the network accepted, not an
/// arithmetic identity that would hold for any numbers.
#[test]
fn the_deltas_of_the_settled_swap_net_to_what_was_traded() {
    let deltas = client("getaddressdeltas")
        .address_deltas(
            &["RGRTws8PJQC5oBqftKMCAaBD1Vj5MHKKSz"],
            Some((1_170_740, 1_170_760)),
        )
        .unwrap();

    let swap: Vec<_> = deltas.iter().filter(|d| d.height == 1_170_750).collect();
    let native: i64 = swap.iter().map(|d| d.satoshis.to_sat()).sum();
    assert_eq!(native, 49_980_000, "0.4998 VRSCTEST in");

    let token: i64 = swap
        .iter()
        .filter_map(|d| d.currency_values.get("i7UCaJkKRFXBCK4S1AMrkfKTnPwdLc7dV7"))
        .map(|v| v.to_sat())
        .sum();
    assert_eq!(token, -100_000_000, "1 sdkcuralpha out");
}

/// Offers as VRSCTEST actually lists them, asked for with `with_tx`.
///
/// The reply is an object whose **keys are data** — one bucket per direction,
/// named after the currencies involved — so there is no fixed schema to
/// deserialize into and the shape has to be read as a map.
#[test]
fn reads_offers_from_every_bucket() {
    let listings = client("getoffers_vrsctest")
        .offers("iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq", true, true)
        .unwrap();
    assert_eq!(listings.len(), 4);

    // Three buckets, and the direction each one records is kept rather than
    // flattened away.
    let buckets: std::collections::BTreeSet<&str> =
        listings.iter().map(|l| l.bucket.as_str()).collect();
    assert_eq!(buckets.len(), 3);

    // An identity can be on **either** side, and both directions are standing
    // on VRSCTEST right now. That is not a curiosity — it is why the two sides
    // share one type. A reader modelling "what is offered" as currency and only
    // "what is wanted" as possibly-an-identity would parse half the marketplace
    // and silently drop the rest.
    let for_sale = listings
        .iter()
        .find_map(|l| match (&l.offering, &l.accepting) {
            (verus_rpc::OfferSide::Identity { name, .. }, verus_rpc::OfferSide::Currencies(_)) => {
                Some(name.as_str())
            }
            _ => None,
        })
        .expect("an identity offered for currency");
    assert_eq!(for_sale, "PulseDigital");

    let wanted = listings
        .iter()
        .find_map(|l| match (&l.offering, &l.accepting) {
            (verus_rpc::OfferSide::Currencies(_), verus_rpc::OfferSide::Identity { name, .. }) => {
                Some(name.as_str())
            }
            _ => None,
        })
        .expect("currency offered for an identity");
    assert_eq!(wanted, "OnyxSpark");

    // And the plain case: currency for currency.
    assert!(listings.iter().any(|l| matches!(
        (&l.offering, &l.accepting),
        (
            verus_rpc::OfferSide::Currencies(_),
            verus_rpc::OfferSide::Currencies(_)
        )
    )));
}

/// The finding that decided what this field is called.
///
/// The daemon names it `txid`, which reads as "this offer's transaction". It is
/// not: it is the **funding** outpoint's transaction, the one holding the output
/// the maker signed away. Proven here from the reply alone — `raw_offer` is the
/// maker's half-transaction, and its single input's prevout is exactly this
/// value, while hashing those bytes gives something else entirely.
#[test]
fn the_listed_txid_is_the_funding_outpoint_not_the_offer() {
    let listings = client("getoffers_vrsctest")
        .offers("iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq", true, true)
        .unwrap();

    let listing = listings
        .iter()
        .find(|l| l.raw_offer.is_some())
        .expect("with_tx was asked for");
    let raw = hex::decode(listing.raw_offer.as_ref().unwrap()).expect("offer hex");

    // header(4) + version group id(4) + input count(1), then the prevout.
    let prevout: [u8; 32] = raw[9..41].try_into().unwrap();
    assert_eq!(
        verus_tx::Txid::from_internal(prevout),
        listing.funding_txid,
        "the listed txid is the outpoint the offer spends"
    );
}

/// Mainnet carries shapes VRSCTEST has none of, and both of them would have
/// broken a narrower reader.
///
/// An offer side can name **several currencies at once** — a token normally
/// travels with a little native currency, because the output must pay its own
/// way — and the amounts arrive in exponent form, `1e-8` being one satoshi.
/// A reader assuming one currency per side, or refusing exponents, parses
/// VRSCTEST perfectly and fails on the chain that has the volume.
#[test]
fn reads_multi_currency_offer_sides_and_their_exponent_amounts() {
    let listings = client("getoffers_mainnet_vrsc")
        .offers("i5w5MuNik5NtLcYmNzcvaoixooEebB6MGV", true, false)
        .unwrap();

    let multi = listings
        .iter()
        .find_map(|l| match &l.offering {
            verus_rpc::OfferSide::Currencies(c) if c.len() > 1 => Some(c),
            _ => None,
        })
        .expect("an offer of more than one currency");

    // The satoshi-sized leg is the one an exponent-refusing reader loses.
    assert!(
        multi.values().any(|amount| amount.to_sat() == 1),
        "a one-satoshi leg, which the daemon writes as 1e-8: {multi:?}"
    );
}

/// An identity name arrives **JSON-escaped**, and stripping the quotes is not
/// the same as decoding it.
///
/// `RawValue::get()` hands back verbatim wire text, which is exactly what money
/// parsing needs and exactly wrong for a string. Identity names are chosen by
/// people, so escapes are ordinary rather than exotic: this crate's own mainnet
/// fixture lists one named `(⌐■_■)`, which the daemon writes as
/// `"(⌐■_■)"`.
///
/// Unquoting alone yields a 21-character string of literal backslashes that
/// matches nothing — least of all the same name read back through
/// `getidentity`, which decodes properly. A caller cross-referencing the two
/// would silently find no match.
#[test]
fn an_identity_name_is_decoded_and_not_merely_unquoted() {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/rpc/getoffers_mainnet_vrsc.json"
    ))
    .unwrap();
    // The escape sequence itself, as a raw string so the backslashes survive.
    // If a regeneration ever writes the name as literal UTF-8 instead, this
    // test stops proving anything and says so.
    assert!(
        raw.contains(r#""name":"(\u2310\u25a0_\u25a0)""#),
        "the fixture no longer carries an escaped name, so this test proves nothing"
    );

    let listings = client("getoffers_mainnet_vrsc")
        .offers("i5w5MuNik5NtLcYmNzcvaoixooEebB6MGV", true, false)
        .unwrap();

    let names: Vec<&str> = listings
        .iter()
        .filter_map(|l| match &l.offering {
            verus_rpc::OfferSide::Identity { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect();

    assert!(
        names.contains(&"(⌐■_■)"),
        "expected the decoded name, got {names:?}"
    );
    assert!(
        !names.iter().any(|n| n.contains("\\u")),
        "an escape survived into the typed value: {names:?}"
    );
}

/// A side that announces itself as an identity and then does not name one is a
/// malformed answer. Inventing an empty string for it would hand the caller an
/// id it may go on to look up.
#[test]
fn an_identity_side_missing_its_fields_is_refused() {
    struct Body(&'static str);
    impl Transport for Body {
        fn post(&self, _body: &RequestBody) -> Result<String, RpcError> {
            Ok(self.0.to_string())
        }
    }

    // `identityid` present but null — the shape that read as the string "null".
    let null_id = r#"{"result":{"b":[{"price":1.0,"offer":{"blockexpiry":0,
        "txid":"00000000000000000000000000000000000000000000000000000000000000ab",
        "offer":{"identityid":null,"name":"x","systemid":"y"},
        "accept":{"iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq":1.0}}}]}}"#;
    assert!(RpcClient::new(Body(null_id))
        .offers("x", true, false)
        .is_err());

    // A currency side carrying a stray numeric field would otherwise become a
    // holding of a phantom currency, and be added to a total.
    let stray = r#"{"result":{"b":[{"price":1.0,"offer":{"blockexpiry":0,
        "txid":"00000000000000000000000000000000000000000000000000000000000000ab",
        "offer":{"iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq":1.0,"someheight":12345},
        "accept":{"iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq":1.0}}}]}}"#;
    assert!(RpcClient::new(Body(stray))
        .offers("x", true, false)
        .is_err());
}

/// `estimatefee` answers in **exponent form**, and that is the whole reason
/// the money readers grew an expander.
///
/// `1e-6` coins per kilobyte is 100 satoshis. A reader that refuses exponents
/// cannot read this method at all; one that reaches for `f64` gives up the
/// exactness the rest of the crate is built on.
#[test]
fn reads_a_fee_rate_written_as_an_exponent() {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/rpc/estimatefee.json"
    ))
    .unwrap();
    assert!(
        raw.contains("1e-6"),
        "the fixture no longer carries the exponent literal, so this proves nothing"
    );

    let fee = client("estimatefee").estimate_fee(1).unwrap();
    assert_eq!(fee.map(verus_tx::Amount::to_sat), Some(100));
}

/// A node that will not estimate answers a **negative** number, which is not a
/// negative fee. It has to be recognised before the money reader sees it —
/// that reader refuses negatives, correctly, and would turn "no opinion" into
/// a parse failure indistinguishable from a broken node.
#[test]
fn a_node_that_will_not_estimate_is_not_a_parse_failure() {
    struct Refuses;
    impl Transport for Refuses {
        fn post(&self, _body: &RequestBody) -> Result<String, RpcError> {
            Ok(r#"{"result":-1}"#.to_string())
        }
    }
    assert_eq!(RpcClient::new(Refuses).estimate_fee(1).unwrap(), None);
}

/// The root chain is the one currency defined under nothing.
///
/// `parent` is absent from exactly one of the 290 currencies on VRSCTEST —
/// VRSCTEST itself — so its absence carries meaning rather than being a gap in
/// the reply, and it is the reason the field is an `Option`.
#[test]
fn the_root_chain_is_the_only_currency_without_a_parent() {
    let currencies = client("listcurrencies_vrsctest").list_currencies().unwrap();

    let rootless: Vec<&str> = currencies
        .iter()
        .filter(|c| c.parent.is_none())
        .map(|c| c.name.as_str())
        .collect();
    assert_eq!(rootless, vec!["VRSCTEST"]);

    // And everything else names one.
    for currency in currencies.iter().filter(|c| c.name != "VRSCTEST") {
        assert!(currency.parent.is_some(), "{} has no parent", currency.name);
    }
}

/// A converter's definition hides behind **a key that is its own currency id**,
/// the same "keys are data" shape `getoffers` uses for buckets. It is found by
/// elimination from the four fields that do have names.
#[test]
fn a_converters_definition_is_found_under_its_own_id() {
    let converters = client("getcurrencyconverters_vrsctest")
        .currency_converters(&["VRSCTEST"])
        .unwrap();
    assert!(!converters.is_empty());

    for converter in &converters {
        // The id really is a key of the entry, not a name we invented.
        assert!(converter.converter_id.starts_with('i'));
        assert_eq!(converter.converter_id.len(), 34);
        // And the definition found under it is that currency's own.
        assert_eq!(
            converter.definition["currencyid"].as_str(),
            Some(converter.converter_id.as_str())
        );
        // Every converter listed for VRSCTEST must actually trade it, or the
        // routing answer is worthless. `trades`, not `reserves`: a converter
        // trades its own currency too.
        assert!(
            converter.trades("iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq"),
            "{} does not trade VRSCTEST: {:?}",
            converter.name,
            converter.reserves
        );
    }
}

/// Reading what an application stored on an identity, rather than who controls
/// it.
#[test]
fn reads_the_content_published_on_an_identity() {
    let content = client("getidentitycontent_rustsdk")
        .identity_content("rustsdk.VRSCTEST@")
        .unwrap();

    assert_eq!(content.identity.fully_qualified_name, "rustsdk.VRSCTEST@");
    assert_eq!(
        content.identity.identity_address,
        "iPYbC4ExJ7dRBZnpxq2LGXGgkWDQNQR48g"
    );

    // One VDXF key to one 32-byte hash — this identity's own update published
    // it, in the transaction `PROVEN.md` records at block 1166566.
    assert_eq!(content.content_map.len(), 1);
    let (key, value) = content.content_map.iter().next().unwrap();
    assert_eq!(key.len(), 40, "a 20-byte VDXF key in hex");
    assert_eq!(value.len(), 64, "a 32-byte value in hex");
}

/// A fractional currency converts between its reserves **and itself**, so its
/// own id is routable and is not in `reserves`.
///
/// Verified live: `getcurrencyconverters ["vlotto"]` answers with vlotto,
/// whose reserves are `[VRSCTEST]` alone. A caller filtering on `reserves`
/// would throw away the very converter it asked for — which an earlier version
/// of this crate's own documentation told it to do.
#[test]
fn a_converter_trades_its_own_currency_as_well_as_its_reserves() {
    let converter = verus_rpc::CurrencyConverter {
        converter_id: "i5PehtStE8dxdM53dhicjD6FcuGzvFoH2C".to_string(),
        name: "vlotto".to_string(),
        height: 1_170_000,
        reserves: vec!["iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq".to_string()],
        definition: serde_json::Value::Null,
        last_notarization: serde_json::Value::Null,
    };

    assert!(
        converter.trades("iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq"),
        "a reserve"
    );
    assert!(
        converter.trades("i5PehtStE8dxdM53dhicjD6FcuGzvFoH2C"),
        "its own currency, which `reserves` does not list"
    );
    assert!(!converter.trades("iQihXUcQt8G9TSh58YoM5NRwC1nAyoazFR"));

    // And the routing predicate both ways round.
    assert!(converter.routes(
        "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq",
        "i5PehtStE8dxdM53dhicjD6FcuGzvFoH2C"
    ));
    assert!(!converter.routes(
        "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq",
        "iQihXUcQt8G9TSh58YoM5NRwC1nAyoazFR"
    ));
}

/// The trigger the self-check exists for.
///
/// A converter entry's definition is found by elimination against four known
/// field names. Add a fifth — and `bestcurrencystate` is a key the daemon
/// already uses elsewhere — and `serde_json`'s `BTreeMap` ordering hands it to
/// the finder, because it sorts before any `i` address. Without the
/// `currencyid` check that yields a converter named after a field, with no
/// reserves, and a router that answers "no route" for the whole chain in
/// silence.
#[test]
fn a_fifth_named_field_is_refused_rather_than_mistaken_for_the_definition() {
    struct Body(&'static str);
    impl Transport for Body {
        fn post(&self, _body: &RequestBody) -> Result<String, RpcError> {
            Ok(self.0.to_string())
        }
    }

    let drifted = r#"{"result":[{
        "fullyqualifiedname":"basket","height":1,
        "bestcurrencystate":{"supply":1.0},
        "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq":{
            "currencyid":"iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq",
            "currencies":["iQihXUcQt8G9TSh58YoM5NRwC1nAyoazFR"]}}]}"#;

    let error = RpcClient::new(Body(drifted))
        .currency_converters(&["x"])
        .expect_err("the definition can no longer be identified by elimination");
    assert!(
        format!("{error}").contains("bestcurrencystate"),
        "the error must name what it found: {error}"
    );
}

/// A currency definition missing a universal field is refused rather than
/// given a zero.
///
/// `proofprotocol` is 1, 2 or 3 on every currency and decides the fee-output
/// shape a sub-identity registration must carry. A fabricated 0 is not a
/// neutral default — it is a value no currency has, handed to a consumer that
/// will branch on it.
#[test]
fn a_currency_missing_a_universal_field_is_refused_not_defaulted() {
    struct Body(&'static str);
    impl Transport for Body {
        fn post(&self, _body: &RequestBody) -> Result<String, RpcError> {
            Ok(self.0.to_string())
        }
    }

    let no_proof_protocol = r#"{"result":[{"currencydefinition":{
        "currencyid":"i1","name":"x","fullyqualifiedname":"x","systemid":"i2",
        "startblock":1,"endblock":0,"options":32}}]}"#;
    let error = RpcClient::new(Body(no_proof_protocol))
        .list_currencies()
        .expect_err("proofprotocol is universal");
    assert!(format!("{error}").contains("proofprotocol"), "{error}");
}

/// An identity older than version 3 has no `contentmultimap` key at all. That
/// reads as empty rather than as an error: such an identity cannot carry one,
/// so there is nothing missing to report.
#[test]
fn an_identity_too_old_for_a_multimap_reads_as_empty() {
    struct Body(&'static str);
    impl Transport for Body {
        fn post(&self, _body: &RequestBody) -> Result<String, RpcError> {
            Ok(self.0.to_string())
        }
    }

    let v1 = r#"{"result":{"fullyqualifiedname":"old.VRSC@","status":"active",
        "txid":"00000000000000000000000000000000000000000000000000000000000000ab",
        "vout":0,"blockheight":1,
        "identity":{"identityaddress":"iOld","version":1,"contentmap":{}}}}"#;
    let content = RpcClient::new(Body(v1)).identity_content("old").unwrap();
    assert!(content.content_multimap.is_empty());
    assert!(content.content_map.is_empty());
}

/// A contentmap value that is not a 32-byte hash is refused. Silently
/// substituting an empty string would be indistinguishable, to the application
/// that stored the data, from having published nothing.
#[test]
fn a_contentmap_value_that_is_not_a_hash_is_refused() {
    struct Body(&'static str);
    impl Transport for Body {
        fn post(&self, _body: &RequestBody) -> Result<String, RpcError> {
            Ok(self.0.to_string())
        }
    }

    for broken in [
        r#""contentmap":{"a667b2e677b4b0d4dd664a7709a9e504185127dc":42}"#,
        r#""contentmap":{"a667b2e677b4b0d4dd664a7709a9e504185127dc":"beef"}"#,
    ] {
        let body = format!(
            r#"{{"result":{{"fullyqualifiedname":"x.VRSC@","status":"active",
            "txid":"00000000000000000000000000000000000000000000000000000000000000ab",
            "vout":0,"blockheight":1,
            "identity":{{"identityaddress":"iX",{broken}}}}}}}"#
        );
        let leaked: &'static str = Box::leak(body.into_boxed_str());
        assert!(
            RpcClient::new(Body(leaked)).identity_content("x").is_err(),
            "{broken}"
        );
    }
}

/// The daemon renders a multimap value in more than one shape, and an earlier
/// version of this reader accepted only one of them.
///
/// Taken from the reference implementation's own reader — `ContentMultiMap`
/// in `verus-typescript-primitives` — which handles a list of hex strings **or
/// objects**, a bare hex string, and a bare object. Which shape arrives depends
/// on whether the daemon recognises the key, so requiring hex made every
/// identity using a recognised key unreadable through this method.
#[test]
fn every_multimap_rendering_the_daemon_uses_is_readable() {
    struct Body(String);
    impl Transport for Body {
        fn post(&self, _body: &RequestBody) -> Result<String, RpcError> {
            Ok(self.0.clone())
        }
    }
    fn read(multimap: &str) -> Result<Vec<verus_rpc::ContentValue>, RpcError> {
        let body = format!(
            r#"{{"result":{{"fullyqualifiedname":"x.VRSC@","status":"active",
            "txid":"00000000000000000000000000000000000000000000000000000000000000ab",
            "vout":0,"blockheight":1,
            "identity":{{"identityaddress":"iX","contentmultimap":{multimap}}}}}}}"#
        );
        RpcClient::new(Body(body))
            .identity_content("x")
            .map(|c| c.content_multimap.into_values().next().unwrap_or_default())
    }

    // A list of hex — the shape both live mainnet examples use.
    let bytes = read(r#"{"iK":["0187ff"]}"#).unwrap();
    assert_eq!(bytes[0].as_bytes(), Some(&[0x01, 0x87, 0xff][..]));

    // A bare hex string, not wrapped in a list. Normalised to one value so a
    // caller has one shape to handle.
    let bare = read(r#"{"iK":"0187ff"}"#).unwrap();
    assert_eq!(bare.len(), 1);
    assert_eq!(bare[0].as_bytes(), Some(&[0x01, 0x87, 0xff][..]));

    // A structured value: the daemon recognised the key and already decoded
    // it, so there are no bytes in the reply to hand back.
    let structured = read(r#"{"iK":{"iSomeKey":"a value"}}"#).unwrap();
    assert_eq!(structured.len(), 1);
    assert!(structured[0].as_bytes().is_none());
    assert!(matches!(
        structured[0],
        verus_rpc::ContentValue::Structured(_)
    ));

    // Mixed inside one list, which the reference reader also permits.
    let mixed = read(r#"{"iK":["0187ff",{"iSomeKey":"v"}]}"#).unwrap();
    assert_eq!(mixed.len(), 2);
    assert!(mixed[0].as_bytes().is_some());
    assert!(mixed[1].as_bytes().is_none());

    // What is still refused: a shape nobody meant.
    assert!(read(r#"{"iK":[42]}"#).is_err());
    assert!(read(r#"{"iK":["nothex"]}"#).is_err());
    assert!(read("[]").is_err(), "a list is not a map of keys to values");
}

/// `getaddressmempool`, from a live pending transaction on 2026-08-05.
///
/// Not this SDK's transaction: an unrelated one that happened to be in flight
/// against `api.verustest.net` while this method was being written. That is why
/// it is the only shape of this reply anyone here has actually seen, and why it
/// is committed rather than hand-written from the daemon's help text.
///
/// It exercises the awkward parts at once: a spend row and two receive rows for
/// one transaction, a spend carrying `prevtxid`/`prevout`, and an `index` of
/// `0` appearing on both a receive and a spend — inputs and outputs are
/// numbered separately, so `index` alone is not a key.
#[test]
fn reads_mempool_deltas_from_a_live_pending_transaction() {
    let rows = client("getaddressmempool")
        .address_mempool(&["RJ7gsKDjUjPS8XZzENqmQMmWJRLuTnw5hp"])
        .expect("the recorded reply parses");
    assert_eq!(rows.len(), 3);

    // Row 0: money arriving. Positive, no prevout.
    assert_eq!(rows[0].satoshis.to_sat(), 40_000_000);
    assert!(!rows[0].spending);
    assert_eq!(rows[0].spends, None);
    assert_eq!(rows[0].index, 0);
    assert_eq!(rows[0].timestamp, 1_785_894_733);

    // Row 1: the input being spent. Negative, and it names what it consumes.
    assert_eq!(rows[1].satoshis.to_sat(), -489_990_000);
    assert!(rows[1].spending);
    let (prev_txid, prev_vout) = rows[1].spends.expect("a spend names its prevout");
    assert_eq!(
        prev_txid.to_display_hex(),
        "2aada70ae1f59cf0c61698eeeb97dbc4466417cbbf09e19b2123ebad31b07886"
    );
    assert_eq!(prev_vout, 1);

    // And `index` really does collide across the two, which is why the
    // uniqueness key in the client includes `spending`.
    assert_eq!(rows[0].index, rows[1].index);
    assert_eq!(rows[0].txid, rows[1].txid);

    // The native leg appears twice in every row: once as satoshis, once in
    // coins under the chain's own currency id. Summing both double-counts it.
    let native = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";
    assert_eq!(rows[0].currency_values[native].to_sat(), 40_000_000);
    assert_eq!(rows[1].currency_values[native].to_sat(), -489_990_000);

    // The whole transaction conserves value at this address, less the fee it
    // paid: 4.8999 spent, 0.4 + 4.4998 received back.
    let net: i64 = rows.iter().map(|r| r.satoshis.to_sat()).sum();
    assert_eq!(net, -10_000, "the fee, and nothing else, left the address");
}

/// `currencyvalues` arrive **without** asking for `verbosity`.
///
/// Worth pinning because the daemon's help reads the other way: its `verbosity`
/// option is described as adding "output information for spends, including all
/// reserve amounts and destinations", which invites sending it in order to see
/// token movements at all. Measured, the per-currency values are in the plain
/// reply, and a token transfer in flight is therefore visible without it.
///
/// What `verbosity: 1` does add is a `sent` object on spend rows — the *other*
/// addresses a spent output paid. This crate does not ask for it, and this test
/// records that both halves of that decision were checked against the wire
/// rather than the documentation.
#[test]
fn per_currency_values_do_not_need_the_verbosity_option() {
    let plain = client("getaddressmempool")
        .address_mempool(&["RJ7gsKDjUjPS8XZzENqmQMmWJRLuTnw5hp"])
        .expect("plain reply parses");
    let verbose = client("getaddressmempool_verbose")
        .address_mempool(&["RJ7gsKDjUjPS8XZzENqmQMmWJRLuTnw5hp"])
        .expect("verbose reply parses");

    assert!(
        plain.iter().all(|r| !r.currency_values.is_empty()),
        "the plain reply carried no currency values, so verbosity would be needed"
    );
    assert_eq!(
        plain, verbose,
        "verbosity changed the values this crate reads; the decision not to send it \
         would then be a decision to see less"
    );
}

/// One positional argument, and no `verbosity` inside it.
///
/// The proxy in front of `api.verustest.net` refuses this method outright
/// (`-32601`) when a second positional argument is present, the same way it
/// refuses `getblock` with a verbosity argument. A request that grew one would
/// work against a local daemon and fail against public infrastructure, which is
/// the failure that is expensive to diagnose.
#[test]
fn asks_for_the_mempool_with_exactly_one_argument() {
    let node = client("getaddressmempool");
    node.address_mempool(&["RJ7gsKDjUjPS8XZzENqmQMmWJRLuTnw5hp"])
        .expect("parses");

    let sent = node.transport().asked.borrow();
    assert_eq!(sent.len(), 1, "one request, not a probe and a retry");
    let body: serde_json::Value = serde_json::from_str(&sent[0]).expect("a JSON body");
    let params = body["params"].as_array().expect("params is an array");
    assert_eq!(
        params.len(),
        1,
        "a second positional argument is refused: {sent:?}"
    );
    assert!(
        params[0].get("verbosity").is_none(),
        "verbosity is deliberately not sent: {sent:?}"
    );
    assert!(params[0].get("addresses").is_some());
}

/// Answers a body chosen per test, so a malformed reply can be constructed
/// without committing a fixture that never came off the wire.
struct Fixed(&'static str);

impl Transport for Fixed {
    fn post(&self, _body: &RequestBody) -> Result<String, RpcError> {
        Ok(self.0.to_string())
    }
}

/// A row for an address nobody asked about is refused.
///
/// This matters more here than for `address_utxos`, where the same check
/// exists: nothing downstream builds a transaction from these rows, so no
/// sighash rejects them later. A caller sums them and shows a user money on its
/// way, and an invented row is an invented payment.
#[test]
fn a_mempool_row_for_an_address_we_did_not_ask_about_is_refused() {
    let node = RpcClient::new(Fixed(
        r#"{"result":[{"address":"RSomeoneElse","txid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","index":0,"satoshis":1,"spending":false,"timestamp":1}]}"#,
    ));
    match node.address_mempool(&["RJ7gsKDjUjPS8XZzENqmQMmWJRLuTnw5hp"]) {
        Err(RpcError::Unexpected(message)) => assert!(message.contains("not asked about")),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// The same row twice is refused, because a caller folding these into a total
/// would count the payment twice.
#[test]
fn a_repeated_mempool_row_is_refused() {
    const ROW: &str = r#"{"address":"RJ7gsKDjUjPS8XZzENqmQMmWJRLuTnw5hp","txid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","index":0,"satoshis":1,"spending":false,"timestamp":1}"#;
    let body: &'static str = Box::leak(format!(r#"{{"result":[{ROW},{ROW}]}}"#).into_boxed_str());
    match RpcClient::new(Fixed(body)).address_mempool(&["RJ7gsKDjUjPS8XZzENqmQMmWJRLuTnw5hp"]) {
        Err(RpcError::Unexpected(message)) => assert!(message.contains("more than once")),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A receive and a spend that share an index are **not** a repeat.
///
/// The live fixture contains exactly this, and a uniqueness key without
/// `spending` would reject the real reply — turning a correct answer into an
/// error and leaving a wallet unable to see its own pending payment.
#[test]
fn a_receive_and_a_spend_sharing_an_index_are_both_kept() {
    let rows = client("getaddressmempool")
        .address_mempool(&["RJ7gsKDjUjPS8XZzENqmQMmWJRLuTnw5hp"])
        .expect("the live reply is not a duplicate");
    assert_eq!(rows.len(), 3);
}

/// A spend whose prevout is missing is refused rather than read as a receipt.
///
/// The dangerous direction: `spending` says money left, the absent
/// `prevtxid`/`prevout` says nothing was consumed. Silently trusting either
/// half gives a wallet a row it will show as incoming.
#[test]
fn a_spend_without_a_prevout_is_refused() {
    let node = RpcClient::new(Fixed(
        r#"{"result":[{"address":"RJ7gsKDjUjPS8XZzENqmQMmWJRLuTnw5hp","txid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","index":0,"satoshis":-1,"spending":true,"timestamp":1}]}"#,
    ));
    match node.address_mempool(&["RJ7gsKDjUjPS8XZzENqmQMmWJRLuTnw5hp"]) {
        Err(RpcError::Unexpected(message)) => {
            assert!(message.contains("spending=true"), "{message}");
            assert!(message.contains("prevtxid=absent"), "{message}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// And the reverse: a prevout on a row that claims not to be a spend.
#[test]
fn a_prevout_on_a_receive_is_refused() {
    let node = RpcClient::new(Fixed(
        r#"{"result":[{"address":"RJ7gsKDjUjPS8XZzENqmQMmWJRLuTnw5hp","txid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","index":0,"satoshis":1,"spending":false,"prevtxid":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","prevout":0,"timestamp":1}]}"#,
    ));
    match node.address_mempool(&["RJ7gsKDjUjPS8XZzENqmQMmWJRLuTnw5hp"]) {
        Err(RpcError::Unexpected(message)) => {
            assert!(message.contains("spending=false"), "{message}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// Nothing pending is an empty list, not an error — the ordinary case, and the
/// one a wallet sees almost always.
#[test]
fn an_address_with_nothing_pending_is_an_empty_list() {
    let node = RpcClient::new(Fixed(r#"{"result":[]}"#));
    let rows = node
        .address_mempool(&["RJ7gsKDjUjPS8XZzENqmQMmWJRLuTnw5hp"])
        .expect("an empty list is a real answer");
    assert!(rows.is_empty());
}

/// One currency, one request — and the same object either way.
///
/// `getcurrency` and `listcurrencies` carry the same definition in different
/// wrappers: bare in one, nested under `currencydefinition` in the other. Both
/// go through `summary_from_definition`, and this asserts they land on the same
/// typed value rather than trusting that they do.
///
/// The drift this guards against is quiet: a single-currency read that reported
/// a different `options` than the whole-chain read would mislabel exactly the
/// currency a wallet just launched and cares most about.
#[test]
fn a_single_currency_reads_the_same_as_its_row_in_the_whole_chain() {
    let one = client("getcurrency_vrsctest")
        .currency_definition("VRSCTEST")
        .unwrap();
    let all = client("listcurrencies_vrsctest").list_currencies().unwrap();
    let row = all
        .iter()
        .find(|c| c.currency_id == one.currency_id)
        .expect("VRSCTEST is in the recorded listcurrencies reply");

    assert_eq!(one.name, row.name);
    assert_eq!(one.fully_qualified_name, row.fully_qualified_name);
    assert_eq!(one.parent, row.parent);
    assert_eq!(one.system_id, row.system_id);
    assert_eq!(one.start_block, row.start_block);
    assert_eq!(one.end_block, row.end_block);
    assert_eq!(one.options, row.options);
    assert_eq!(one.proof_protocol, row.proof_protocol);
}

/// The fields that were unreachable without pulling every currency on the chain.
///
/// `options` says what kind of currency it is and `proof_protocol` decides the
/// fee-output shape a sub-identity registration must carry. Neither is in
/// `CurrencyPolicy`, which is the fee-policy view of the same reply.
#[test]
fn a_currency_definition_carries_what_the_policy_view_drops() {
    let summary = client("getcurrency_vrsctest")
        .currency_definition("VRSCTEST")
        .unwrap();

    assert_eq!(summary.currency_id, "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq");
    assert_eq!(summary.options, 264);
    assert_eq!(summary.proof_protocol, 1);
    assert_eq!(
        summary.parent, None,
        "a root chain is defined under nothing, and absence means that here"
    );

    // And the long tail stays reachable rather than being typed and truncated.
    assert!(
        summary.definition.get("preallocations").is_some(),
        "the whole definition is kept alongside for the fields not typed above"
    );
    assert!(
        summary.definition.get("definitiontxid").is_some(),
        "including the txid that proves where the definition came from"
    );
}
