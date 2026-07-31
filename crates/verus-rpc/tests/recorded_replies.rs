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
                    .to_string(),
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
