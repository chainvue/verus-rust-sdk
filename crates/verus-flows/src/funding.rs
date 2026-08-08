//! Finding coins that can actually be spent right now.
//!
//! `getaddressutxos` reports what an address owns. That is not the same as what
//! it can spend: a coinbase output needs 100 confirmations, and one that has not
//! matured builds and signs perfectly before the daemon answers
//! `bad-txns-premature-spend-of-coinbase`. The whole cost of that mistake lands
//! after the work is done.
//!
//! # Only the young are suspect
//!
//! Telling a coinbase from an ordinary output needs the transaction that created
//! it, which is a round trip each. Doing that for every UTXO would make funding
//! a wallet with a hundred outputs a hundred requests.
//!
//! It is also unnecessary. An output with 100 or more confirmations is spendable
//! *whether or not* it is a coinbase, so its origin does not matter. Only
//! outputs younger than that can be immature, and there are rarely many. So this
//! checks exactly those and leaves the rest alone.
//!
//! # A confirmed output can already be spent
//!
//! `getaddressutxos` is confirmed-only by design, so an output consumed by a
//! transaction still in the mempool is *still reported as unspent*. Selecting
//! it again is worse than a wasted attempt, because everything downstream is
//! deterministic: `select_utxos` orders by value and RFC6979 signs
//! reproducibly, so a second payment of the same amount to the same recipient
//! at the same tip rebuilds the first **byte for byte**, txid included. Not a
//! conflicting spend a node explains — a duplicate.
//!
//! So the mempool is read too, and any output it already spends is withheld.
//! The daemon does the same thing, via `CWalletTx::IsTrusted`.
//!
//! **Best-effort, not a guarantee.** A mempool belongs to one node. A coin
//! filtered here may be free elsewhere, and a node that has not seen the
//! spending transaction cannot report it. This avoids conflicting with
//! yourself; it is not a correctness claim about the network.
//!
//! **Not yet done: spending your own unconfirmed change.** The daemon allows
//! it (`-spendzeroconfchange`, default on), and without it a wallet still has
//! to wait for a block between payments. It is deliberately left out here
//! rather than bundled in: it is a risk decision, not a correction, and Verus
//! sharpens it — a parent that expires unmined takes every child built on its
//! change with it, which upstream's non-expiring transactions never do. It
//! also needs an opt-in plumbed through every flow that funds itself.

use verus_rpc::{AddressUtxo, ChainReader, COINBASE_MATURITY};
use verus_tx::{Amount, Utxo};

use crate::error::FlowError;

/// Spendable coins at an address, and the height they were assessed at.
///
/// `#[non_exhaustive]` because this is a report, not a request: callers read it
/// and never build one. Naming a new category of withheld output — as
/// `spent_unconfirmed` was — should not be a breaking change, and a caller who
/// constructed this literally would silently omit whatever came next.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Funding {
    /// Outputs that can be spent now, ready for a builder.
    pub utxos: Vec<Utxo>,
    /// The chain tip this was decided against.
    pub tip: u32,
    /// The sum of [`Funding::utxos`].
    pub total: Amount,
    /// Outputs excluded because they cannot be spent **yet**, as distinct from
    /// [`Funding::other`], which is the wrong *kind* of output.
    ///
    /// Mostly immature coinbases, and named for that case, but it is whatever
    /// the maturity filter withheld — an output the node marked unspendable
    /// lands here too. So "wait a hundred blocks" is the usual explanation for
    /// this list, not a guaranteed one.
    ///
    /// Reported rather than silently dropped: "you have 500 but can spend 20"
    /// is a fact a wallet needs to be able to explain to a user.
    pub immature: Vec<AddressUtxo>,
    /// Outputs that are not plain P2PKH — reserve outputs holding tokens,
    /// identity outputs, anything CryptoCondition.
    ///
    /// Kept out of [`Funding::utxos`] because the native builders refuse them,
    /// and rightly: a reserve output's value is in its payload, not its satoshis,
    /// so spending one as ordinary funding would destroy whatever it carries.
    /// A wallet that holds a single token would otherwise be unable to make an
    /// ordinary payment at all.
    ///
    /// Handed back rather than dropped, because a token transfer needs exactly
    /// these — see `verus_tx::token` and `verus_flows::convert`.
    pub other: Vec<AddressUtxo>,
    /// Outputs an unconfirmed transaction already spends.
    ///
    /// Confirmed on chain and still reported by `getaddressutxos`, which is
    /// confirmed-only — but gone, as soon as the spending transaction is mined.
    ///
    /// Deliberately **not** folded into [`Funding::immature`]: that list means
    /// "wait", and these are not waiting for anything. Telling a user to wait a
    /// hundred blocks for a coin they have already spent would be worse than
    /// saying nothing.
    ///
    /// A wallet showing "pending" can use this: it is precisely the money that
    /// has left but not yet settled. See the module docs for why this is
    /// best-effort — a mempool belongs to one node.
    pub spent_unconfirmed: Vec<AddressUtxo>,
}

impl Funding {
    /// The value sitting in outputs that are not spendable yet.
    pub fn immature_total(&self) -> Amount {
        Amount::checked_sum(self.immature.iter().map(|found| found.utxo.satoshis))
            .unwrap_or(Amount::ZERO)
    }

    /// The value an unconfirmed transaction has already spent.
    ///
    /// What a wallet should show as "pending" — money that has left but has
    /// not settled. Best-effort for the same reason
    /// [`Funding::spent_unconfirmed`] is: it reflects one node's mempool.
    pub fn spent_unconfirmed_total(&self) -> Amount {
        Amount::checked_sum(
            self.spent_unconfirmed
                .iter()
                .map(|found| found.utxo.satoshis),
        )
        .unwrap_or(Amount::ZERO)
    }
}

/// Gather what `address` can spend at the current tip.
///
/// Costs three requests, plus one per output younger than
/// [`COINBASE_MATURITY`] — see the module docs for why that is the right
/// number and not one per output.
///
/// The third is the mempool. It is not optional: offering a coin some
/// unconfirmed transaction has already spent is what makes a second payment
/// rebuild the first byte for byte.
pub fn spendable(reader: &impl ChainReader, address: &str) -> Result<Funding, FlowError> {
    // Issued together, unwrapped after: none of the three needs another, and
    // against a driver that cannot answer immediately the `?` would stop the
    // operation at the first one. See [`crate::drive`].
    let tip = reader.block_count();
    let found = reader.address_utxos(&[address]);
    let pending = reader.address_mempool(&[address]);
    let (tip, found) = (tip?, found?);

    // The mempool read does NOT use `?`, and that is the whole point of
    // calling this filter best-effort.
    //
    // It is an optimisation over the confirmed UTXO set: it withholds coins
    // some unconfirmed transaction already spends. If the answer cannot be
    // had — an endpoint that does not serve `getaddressmempool`, or a reply
    // the reader refuses because a row's `spending` and `spends` disagree —
    // the honest degradation is to withhold nothing and fund from what is
    // confirmed, which is exactly what every flow did before this filter
    // existed.
    //
    // Propagating it instead would turn a missing optimisation into a wallet
    // that cannot spend at all: `send`, `mint`, `launch`, `publish`, `update`
    // and `take_offer` all fund through here.
    //
    // The driver sentinel is the one error that must NOT be swallowed. Under
    // `crate::drive` an unanswered read returns `RpcError::AnswerNeeded`, and
    // treating that as "no mempool data" would make the driver believe the
    // operation had finished with a stale candidate set.
    let spent_in_mempool = best_effort_spent(pending)?;

    let coinbase_heights = probe_coinbase_heights(reader, &found, tip)?;
    let mature = verus_rpc::spendable_at(&found, tip, &coinbase_heights);
    let mature: Vec<Utxo> = mature
        .into_iter()
        .filter(|u| !spent_in_mempool.contains(&(u.txid, u.vout)))
        .collect();
    let mature_outpoints: Vec<_> = mature.iter().map(|u| (u.txid, u.vout)).collect();

    // A native builder can only spend P2PKH. Everything else is separated here
    // rather than refused later by the builder, which cannot tell a caller
    // which of their outputs was the problem.
    let (utxos, other): (Vec<Utxo>, Vec<Utxo>) = mature
        .into_iter()
        .partition(|utxo| is_p2pkh(&utxo.script_pubkey));
    let other_outpoints: Vec<_> = other.iter().map(|u| (u.txid, u.vout)).collect();

    let mut immature = Vec::new();
    let mut non_native = Vec::new();
    let mut spent_unconfirmed = Vec::new();
    for utxo in found {
        let outpoint = (utxo.utxo.txid, utxo.utxo.vout);
        if spent_in_mempool.contains(&outpoint) {
            // Checked first: this one is gone, whatever else it also is. A
            // mempool-spent coin classified as immature would be reported as
            // "wait a hundred blocks" for something that is never coming back.
            spent_unconfirmed.push(utxo);
        } else if other_outpoints.contains(&outpoint) {
            non_native.push(utxo);
        } else if !mature_outpoints.contains(&outpoint) {
            immature.push(utxo);
        }
    }

    let total = Amount::checked_sum(utxos.iter().map(|u| u.satoshis)).ok_or_else(|| {
        FlowError::NotReady("the address holds more than can be represented".into())
    })?;

    Ok(Funding {
        utxos,
        tip,
        total,
        immature,
        other: non_native,
        spent_unconfirmed,
    })
}

/// The already-spent set, or an empty one when the mempool cannot be read.
///
/// The mempool filter is an **optimisation over the confirmed UTXO set**: it
/// withholds coins some unconfirmed transaction already spends. When the answer
/// cannot be had — an endpoint that does not serve `getaddressmempool`, or a
/// reply the reader refuses because a row's `spending` and `spends` disagree —
/// the honest degradation is to withhold nothing and fund from what is
/// confirmed, which is what every flow did before the filter existed.
///
/// Propagating the error instead would turn a missing optimisation into a
/// wallet that cannot spend at all: `send`, `mint`, `launch`, `publish`,
/// `update` and `take_offer` all fund through here. That is the failure this
/// exists to prevent, and it is why the module docs call the filter
/// best-effort rather than a guarantee.
///
/// # The one error that must not be swallowed
///
/// [`RpcError::AnswerNeeded`](verus_rpc::RpcError::AnswerNeeded) is the
/// driver's sentinel, not a node failure — see [`crate::drive`]. Reading it as
/// "no mempool data" would make a driven caller believe the operation had
/// finished against a candidate set that was never filtered.
fn best_effort_spent(
    pending: Result<Vec<verus_rpc::MempoolDelta>, verus_rpc::RpcError>,
) -> Result<Vec<(verus_tx::Txid, u32)>, FlowError> {
    match pending {
        Ok(rows) => Ok(already_spent(&rows)),
        Err(sentinel @ verus_rpc::RpcError::AnswerNeeded) => Err(FlowError::Rpc(sentinel)),
        Err(_) => Ok(Vec::new()),
    }
}

/// The outpoints an unconfirmed transaction already consumes.
///
/// `spends` is `Some` exactly when the row is a spend, and
/// [`verus_rpc::ChainReader::address_mempool`] refuses a reply where those two
/// disagree — so this cannot read a receipt as a spend and withhold a coin
/// that was arriving rather than leaving.
///
/// Shared by [`spendable`] and [`identity_held`] so the two cannot drift, the
/// same reason `probe_coinbase_heights` is shared.
fn already_spent(pending: &[verus_rpc::MempoolDelta]) -> Vec<(verus_tx::Txid, u32)> {
    pending
        .iter()
        // Redundant with the `filter_map` below, and kept anyway. The reader
        // guarantees `spends.is_some()` exactly when `spending`, so selecting
        // on either field alone gives the same rows — no test can tell the two
        // apart without constructing a reply the reader would have refused.
        // Stating the condition that actually matters is worth one line.
        .filter(|row| row.spending)
        .filter_map(|row| row.spends)
        .collect()
}

/// The heights of the coinbase outputs in `found` that could still be
/// immature. Only an output younger than [`COINBASE_MATURITY`] is worth the
/// round trip — shared by [`spendable`] and [`identity_held`] so their
/// maturity rules cannot drift apart.
fn probe_coinbase_heights(
    reader: &impl ChainReader,
    found: &[AddressUtxo],
    tip: u32,
) -> Result<Vec<u32>, FlowError> {
    // Every probe is issued before any is unwrapped. The probes are mutually
    // independent, so a `?` inside the loop would make each one its own network
    // round trip against a non-blocking driver — turning a wallet with five
    // young outputs into five sequential fetches. Collecting first costs a
    // `Vec` and makes it one. See [`crate::drive`].
    let probes: Vec<(u32, Result<bool, FlowError>)> = found
        .iter()
        .filter(|utxo| utxo.confirmations(tip) < COINBASE_MATURITY)
        .map(|utxo| {
            (
                utxo.height,
                is_coinbase(reader, &utxo.utxo.txid.to_display_hex()),
            )
        })
        .collect();

    let mut heights = Vec::new();
    for (height, probe) in probes {
        if probe? {
            heights.push(height);
        }
    }
    Ok(heights)
}

/// `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`, and nothing else.
fn is_p2pkh(script: &[u8]) -> bool {
    script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
}

/// Whether a transaction is a coinbase.
///
/// A coinbase has exactly one input and that input has a `coinbase` field
/// instead of an outpoint. Checked positively — an unrecognised shape is
/// treated as *not* coinbase, because the alternative is refusing to spend
/// ordinary money whenever a daemon changes how it prints an input.
fn is_coinbase(reader: &impl ChainReader, txid: &str) -> Result<bool, FlowError> {
    let tx = reader.raw_transaction(txid)?;
    Ok(tx["vin"]
        .as_array()
        .and_then(|vin| vin.first())
        .is_some_and(|input| input.get("coinbase").is_some()))
}

/// Refuse early when there is plainly not enough to work with.
///
/// The builder would refuse too, but only after selecting and estimating. This
/// produces the message a user can act on, and names the immature portion when
/// that is what makes the difference.
pub fn require(funding: &Funding, needed: Amount, address: &str) -> Result<(), FlowError> {
    if funding.total >= needed {
        return Ok(());
    }
    Err(FlowError::InsufficientFunds {
        needed,
        available: funding.total,
        address: address.to_string(),
        utxos: funding.utxos.len(),
    })
}

/// Gather the **token-bearing** outputs a VerusID holds, for one currency.
///
/// The companion to [`identity_held`], which deliberately returns only the
/// plain pay-to-identity outputs — native value. A token an identity holds is
/// a *reserve output* whose destination is the identity: a different script,
/// so `identity_held` never matches it and never finds it.
///
/// # Why this exists at all
///
/// A token's supply is the sum of its `preallocations`, and a preallocation
/// names an **identity**. So for a currency that cannot be minted
/// (`proofprotocol` 1) every unit that will ever exist is created at launch
/// into an output held by the defining identity, and never passes through a
/// key-held address. Without a way to locate those outputs the whole supply is
/// unreachable — which is exactly what happened to `aaa@` on VRSCTEST, whose
/// 1,000,000,000 units sit in one reserve output nothing could find.
///
/// # What it returns
///
/// Outputs paying `identity` that carry `currency` and nothing else. A
/// multi-currency reserve output is skipped rather than returned: the
/// conversion builder refuses one, because spending it would have to account
/// for the currencies nobody asked about, and silently destroying them is the
/// failure worth designing out.
///
/// Maturity and the mempool are applied exactly as in [`identity_held`], for
/// the same reasons — an identity spend consumes every output it is handed, so
/// one unusable coin poisons the whole transaction rather than shrinking it.
pub fn identity_held_tokens(
    reader: &impl ChainReader,
    identity: &str,
    currency: verus_tx::CurrencyId,
) -> Result<Vec<Utxo>, FlowError> {
    let address: verus_keys::Address = identity
        .parse()
        .map_err(|e| FlowError::NoSuchIdentity(format!("{identity}: {e}")))?;

    let tip = reader.block_count();
    let found = reader.address_utxos(&[identity]);
    let pending = reader.address_mempool(&[identity]);
    let (tip, found) = (tip?, found?);

    let coinbase_heights = probe_coinbase_heights(reader, &found, tip)?;
    // Best-effort, exactly as in `spendable` — see the note there.
    let spent_in_mempool = best_effort_spent(pending)?;

    Ok(verus_rpc::spendable_at(&found, tip, &coinbase_heights)
        .into_iter()
        .filter(|utxo| !spent_in_mempool.contains(&(utxo.txid, utxo.vout)))
        .filter(|utxo| holds_only(utxo, address.hash(), currency))
        .collect())
}

/// Whether `utxo` is a reserve output paying `identity` and carrying exactly
/// `currency`.
///
/// Decoded rather than pattern-matched on the script bytes: the payload's
/// amount varies, so there is no fixed script to compare against the way
/// [`identity_held`] can.
fn holds_only(utxo: &Utxo, identity: [u8; 20], currency: verus_tx::CurrencyId) -> bool {
    match verus_tx::decode_output_script(&utxo.script_pubkey) {
        Ok(verus_tx::OutputKind::ReserveOutput {
            tokens,
            destination,
        }) => {
            destination == verus_tx::Destination::Identity(identity)
                && tokens.len() == 1
                && tokens[0].0 == currency
        }
        // Anything else is the identity's own output, native value, or a shape
        // no builder here spends. Not an error: an identity legitimately holds
        // a mixture, and this is a filter rather than a validator.
        _ => false,
    }
}

/// Gather the outputs a VerusID holds — the standard pay-to-identity outputs
/// for `identity`, mature and ready to fund an identity-authorised spend or a
/// mint.
///
/// `identity` is the `i` address. Only outputs whose script is *exactly* the
/// identity's payment script are returned: the identity's own identity output
/// (the one carrying its definition), tokens it holds, and anything else
/// CryptoCondition are all excluded, because the identity-funded builders
/// refuse them and rightly so.
pub fn identity_held(reader: &impl ChainReader, identity: &str) -> Result<Vec<Utxo>, FlowError> {
    let address: verus_keys::Address = identity
        .parse()
        .map_err(|e| FlowError::NoSuchIdentity(format!("{identity}: {e}")))?;
    let expected = verus_tx::identity_payment_script(address.hash())?;
    // Issued together, unwrapped after, exactly as in [`spendable`] and for the
    // same reason — see [`crate::drive`].
    let tip = reader.block_count();
    let found = reader.address_utxos(&[identity]);
    let pending = reader.address_mempool(&[identity]);
    let (tip, found) = (tip?, found?);

    // Coinbase maturity applies here exactly as in `spendable` — an identity
    // that stakes is paid in coinbase outputs carrying this very script, and
    // an identity spend consumes EVERY output it is handed, so one immature
    // output would poison the whole spend for a hundred blocks with an error
    // that names nothing.
    let coinbase_heights = probe_coinbase_heights(reader, &found, tip)?;

    // And the same is true of an output some unconfirmed transaction already
    // spends — more so, because "consumes every output" means one stale coin
    // poisons the whole spend rather than merely shrinking it.
    //
    // Best-effort, exactly as in `spendable` — see the note there.
    let spent_in_mempool = best_effort_spent(pending)?;

    Ok(verus_rpc::spendable_at(&found, tip, &coinbase_heights)
        .into_iter()
        .filter(|utxo| utxo.script_pubkey == expected)
        .filter(|utxo| !spent_in_mempool.contains(&(utxo.txid, utxo.vout)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::ScriptedReader;

    #[test]
    fn sums_what_can_be_spent() {
        let reader = ScriptedReader::new(1_000)
            .with_utxo("R1", 100, 5_000_000)
            .with_utxo("R1", 200, 3_000_000);
        let funding = spendable(&reader, "R1").unwrap();
        assert_eq!(funding.utxos.len(), 2);
        assert_eq!(funding.total.to_sat(), 8_000_000);
        assert_eq!(funding.tip, 1_000);
        assert!(funding.immature.is_empty());
    }

    /// The case this module exists for. The coins are there; they cannot be
    /// spent; and a wallet has to be able to say which is which.
    #[test]
    fn an_immature_coinbase_is_excluded_and_reported() {
        let reader = ScriptedReader::new(1_000)
            .with_utxo("R1", 950, 5_000_000)
            .with_coinbase_at(950)
            .with_utxo("R1", 100, 3_000_000);

        let funding = spendable(&reader, "R1").unwrap();
        assert_eq!(funding.utxos.len(), 1);
        assert_eq!(funding.total.to_sat(), 3_000_000);
        assert_eq!(funding.immature.len(), 1);
        assert_eq!(funding.immature_total().to_sat(), 5_000_000);
    }

    /// A coinbase past maturity is ordinary money.
    #[test]
    fn a_mature_coinbase_is_spendable() {
        let reader = ScriptedReader::new(2_000)
            .with_utxo("R1", 950, 5_000_000)
            .with_coinbase_at(950);
        let funding = spendable(&reader, "R1").unwrap();
        assert_eq!(funding.utxos.len(), 1);
        assert!(funding.immature.is_empty());
    }

    /// The optimisation that keeps funding cheap: an old output is spendable
    /// whether or not it is a coinbase, so its origin is never looked up.
    #[test]
    fn old_outputs_cost_no_extra_requests() {
        let reader = ScriptedReader::new(100_000)
            .with_utxo("R1", 10, 1)
            .with_utxo("R1", 20, 1)
            .with_utxo("R1", 30, 1);
        let funding = spendable(&reader, "R1").unwrap();
        assert_eq!(funding.utxos.len(), 3);
        // getblockcount + getaddressutxos + getaddressmempool, and nothing per
        // output. The mempool read is flat: one call covers every candidate,
        // which is why excluding already-spent coins costs a constant rather
        // than scaling with the wallet.
        assert_eq!(reader.requests(), 3);
    }

    /// Only the young ones are looked up, and only they.
    #[test]
    fn only_young_outputs_are_looked_up() {
        let reader = ScriptedReader::new(1_000)
            .with_utxo("R1", 10, 1)
            .with_utxo("R1", 950, 1)
            .with_utxo("R1", 960, 1);
        spendable(&reader, "R1").unwrap();
        // Three flat reads, then two lookups: 950 and 960 are within 100 of
        // the tip, 10 is not. The per-output cost is what this pins, and it is
        // unchanged.
        assert_eq!(reader.requests(), 5);
    }

    /// The bug this separation exists for: a wallet holding one token could not
    /// make an ordinary payment, because the reserve output was handed to a
    /// native builder that correctly refused it.
    #[test]
    fn a_token_output_does_not_break_a_native_send() {
        let address = "R1";
        let reader = ScriptedReader::new(1_000)
            .with_utxo(address, 100, 5_000_000)
            .with_reserve_utxo(address, 200);

        let funding = spendable(&reader, address).unwrap();
        assert_eq!(funding.utxos.len(), 1, "the reserve output was left in");
        assert_eq!(funding.total.to_sat(), 5_000_000);
        assert_eq!(funding.other.len(), 1, "the reserve output was dropped");
        assert!(funding.immature.is_empty());
    }

    /// A reserve output's value is in its payload, so it must not be counted as
    /// native funds either.
    #[test]
    fn a_token_output_is_not_counted_as_native_value() {
        let reader = ScriptedReader::new(1_000).with_reserve_utxo("R1", 200);
        let funding = spendable(&reader, "R1").unwrap();
        assert_eq!(funding.total.to_sat(), 0);
        assert!(funding.utxos.is_empty());
    }

    /// An identity's funding is filtered by the mempool too, and it matters
    /// more here than for an ordinary send.
    ///
    /// An identity spend consumes **every** output it is handed, so a single
    /// already-spent coin does not merely shrink the funding — it makes the
    /// whole transaction conflict. Exactly the reasoning the coinbase-maturity
    /// filter already carries, for the same list.
    #[test]
    fn an_identity_does_not_offer_a_coin_the_mempool_already_spends() {
        const IDENTITY: &str = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";
        let address: verus_keys::Address = IDENTITY.parse().unwrap();
        let script = verus_tx::identity_payment_script(address.hash()).unwrap();

        let reader = ScriptedReader::new(1_000).with_script_utxo(IDENTITY, 200, 5_000, script);
        let held = identity_held(&reader, IDENTITY).unwrap();
        assert_eq!(held.len(), 1, "the identity holds one spendable output");
        let outpoint = (held[0].txid, held[0].vout);

        let after = reader.with_mempool_spend(IDENTITY, outpoint, 5_000);
        assert!(
            identity_held(&after, IDENTITY).unwrap().is_empty(),
            "a coin already spent in the mempool must not be offered again"
        );
    }

    #[test]
    fn refuses_when_there_is_not_enough() {
        let reader = ScriptedReader::new(1_000).with_utxo("R1", 100, 1_000);
        let funding = spendable(&reader, "R1").unwrap();
        assert!(require(&funding, Amount::from_sat(500), "R1").is_ok());
        match require(&funding, Amount::from_sat(5_000), "R1") {
            Err(FlowError::InsufficientFunds {
                needed, available, ..
            }) => {
                assert_eq!(needed.to_sat(), 5_000);
                assert_eq!(available.to_sat(), 1_000);
            }
            other => panic!("expected InsufficientFunds, got {other:?}"),
        }
    }
}
