//! What happened at an address, as a list a wallet can show.
//!
//! # Why a UTXO set is not a history
//!
//! [`crate::spendable`] answers "what can I spend", and that is the present
//! tense: an output that arrived and was later spent is simply gone from it. A
//! wallet built on UTXOs alone can show a balance and nothing else — every
//! completed payment, sent or received, is invisible.
//!
//! `getaddressdeltas` is the other half. It reports every *movement* of value
//! at an address, past and present, which is what a transaction list is made of.
//!
//! # What this adds over the raw deltas
//!
//! Deltas are per-output, and a wallet wants per-transaction. One ordinary
//! payment produces several rows at the sender's address — the input spent, the
//! change returned, and a separate row per currency leg — so displaying deltas
//! directly shows one payment as three or four confusing lines, two of them
//! negative.
//!
//! [`history`] folds them: one [`HistoryEntry`] per transaction, carrying the
//! **net** effect across every address asked about. A send of 1 with 0.0999
//! change becomes a single entry of `-0.9001`, which is what actually left.
//!
//! It also separates the two ways the same money is reported. A delta's
//! `currencyvalues` map includes the chain's own currency, duplicating the
//! `satoshis` field; summing both double-counts the native leg. Here the native
//! movement is [`HistoryEntry::net_native`] and
//! [`HistoryEntry::net_currencies`] holds only the rest.

use std::collections::{BTreeMap, HashMap, HashSet};

use verus_keys::{Address, AddressKind};
use verus_rpc::{ChainReader, SignedAmount};
use verus_tx::Txid;

use crate::error::FlowError;

/// The chain's own currency, spelled the way a delta's `currencyvalues` map
/// keys it — an `i` address, not the raw bytes [`verus_tx::CurrencyId`] holds.
///
/// Derived offline from the chain's name, for the reason
/// [`crate::balances::native_currency`] gives: a **root** chain's currency id *is* the id of its name.
///
/// # And then checked against what the node says
///
/// That derivation is only true for a root chain. Under a PBaaS chain the
/// currency id comes from the name under its parent, so the derived string
/// would simply be wrong — and wrong in the quietest possible way: the native
/// leg stops being recognised, so it is no longer stripped out, and every entry
/// silently reports the chain's own currency twice. Nothing fails; the numbers
/// are just doubled.
///
/// So the node's own `chainid` is compared against it. That value arrives in
/// the *same* `getinfo` reply, so the check costs no extra request, and it
/// converts a silent doubling into a refusal that names the problem.
fn native_i_address(reader: &impl ChainReader) -> Result<String, FlowError> {
    let info = reader.chain_info()?;
    let derived = Address::new(
        AddressKind::Identity,
        verus_tx::root_namespace(&info.name)?.to_bytes(),
    )
    .to_string();

    if derived != info.chain_id {
        return Err(FlowError::Rpc(verus_rpc::RpcError::Unexpected(format!(
            "{} reports chainid {} but its name derives to {derived} — the native currency \
             cannot be identified, so a transaction history built here would count it twice",
            info.name, info.chain_id
        ))));
    }
    Ok(derived)
}

/// One transaction's effect on the addresses that were asked about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryEntry {
    /// The transaction.
    pub txid: Txid,
    /// Block it was mined in.
    pub height: u32,
    /// Position within that block.
    pub block_index: u32,
    /// The block's timestamp as the daemon reports it.
    ///
    /// Miner-chosen and only loosely monotonic — fine to display, not a source
    /// of ordering. These entries are already sorted by height.
    pub block_time: i64,
    /// Net native value, negative when more left than arrived.
    ///
    /// **Zero does not mean nothing happened.** A token-only transfer moves no
    /// native value at all; check [`HistoryEntry::net_currencies`] too.
    pub net_native: SignedAmount,
    /// Net movement per currency, keyed by i-address, **excluding** the chain's
    /// own currency.
    ///
    /// Entries that net to exactly zero are dropped: a transaction that spent a
    /// 5-token output and took 5 back as change did not move that token, and
    /// listing it as `0` invites a wallet to render a phantom line.
    pub net_currencies: BTreeMap<String, SignedAmount>,
    /// Whether any output belonging to these addresses was spent here.
    ///
    /// Distinct from a negative net: a self-transfer spends an output and
    /// returns the value, netting to just the fee.
    pub spent_something: bool,
}

impl HistoryEntry {
    /// Whether value left on balance — in any currency.
    pub fn is_outgoing(&self) -> bool {
        self.net_native.is_negative() || self.net_currencies.values().any(|v| v.is_negative())
    }
}

/// Every transaction touching these addresses, oldest first.
///
/// `range` bounds the search to `(start, end)` heights inclusive; `None` asks
/// for the whole chain, which on a busy address is a large reply. Page with
/// explicit ranges rather than finding the transport's size ceiling.
///
/// Costs **two** requests: one for the chain's own currency id, which is needed
/// to tell the native leg apart from a token, and one for the deltas.
///
/// # Several addresses at once
///
/// The net effect is across all of them taken together, and a movement is
/// counted **once** even where the index reports it under more than one — an
/// output payable to several of your addresses is one arrival, not several.
/// Passing addresses separately and adding up the results would double-count
/// exactly those.
///
/// The usual caveat still applies: asking about several addresses in one call
/// tells the node they belong together.
///
/// # What a node can do to this
///
/// Under-report, and a payment is missing from the list. Nothing here can
/// detect that, and no amount of care in this crate could — the answer is the
/// only evidence there is. What *is* checked, in [`verus_rpc`], is that every
/// row belongs to an address that was asked about and that no row repeats for
/// the same address; both would otherwise inflate these totals with nothing
/// downstream to notice.
pub fn history(
    reader: &impl ChainReader,
    addresses: &[&str],
    range: Option<(u32, u32)>,
) -> Result<Vec<HistoryEntry>, FlowError> {
    let native = native_i_address(reader)?;
    let deltas = reader.address_deltas(addresses, range)?;

    // One movement, counted once — even when it is indexed under several of the
    // addresses that were asked about.
    //
    // The daemon's index is keyed per address, so an output payable to more
    // than one of them comes back as one row *each*: a CryptoCondition output
    // with several destinations, or an identity's `i` address queried alongside
    // one of its primary `R` addresses. Those rows describe the same input or
    // output. Summing them all would report money that arrived once as having
    // arrived twice, and the error would grow with how many of your own
    // addresses you asked about together — worst exactly when a wallet does the
    // obvious thing and passes them all at once.
    //
    // `(txid, spending, index)` names the movement itself: `index` is a
    // position within the transaction, an input's or an output's according to
    // `spending`.
    let mut counted = HashSet::new();

    let mut folded: HashMap<Txid, HistoryEntry> = HashMap::new();
    for delta in deltas {
        let entry = folded.entry(delta.txid).or_insert_with(|| HistoryEntry {
            txid: delta.txid,
            height: delta.height,
            block_index: delta.block_index,
            block_time: delta.block_time,
            net_native: SignedAmount::ZERO,
            net_currencies: BTreeMap::new(),
            spent_something: false,
        });

        // Still recorded as a spend of ours, even on a repeat sighting: that
        // is a fact about the transaction, not a quantity to be summed.
        entry.spent_something |= delta.spending;
        if !counted.insert((delta.txid, delta.spending, delta.index)) {
            continue;
        }

        entry.net_native = entry
            .net_native
            .checked_add(delta.satoshis)
            .ok_or_else(|| {
                FlowError::Rpc(verus_rpc::RpcError::OutOfRange(format!(
                    "native deltas for {} do not sum without overflowing",
                    delta.txid.to_display_hex()
                )))
            })?;

        for (currency, value) in delta.currency_values {
            // The native leg is already in `net_native`; keeping it here as
            // well would make a caller summing the map double-count it.
            if currency == native {
                continue;
            }
            let running = entry
                .net_currencies
                .entry(currency.clone())
                .or_insert(SignedAmount::ZERO);
            *running = running.checked_add(value).ok_or_else(|| {
                FlowError::Rpc(verus_rpc::RpcError::OutOfRange(format!(
                    "{currency} deltas for {} do not sum without overflowing",
                    delta.txid.to_display_hex()
                )))
            })?;
        }
    }

    let mut entries: Vec<HistoryEntry> = folded.into_values().collect();
    for entry in &mut entries {
        entry.net_currencies.retain(|_, v| *v != SignedAmount::ZERO);
    }
    // `folded` is a hash map, so its iteration order is not even stable between
    // runs. Sort by where the transaction actually sits in the chain, with the
    // txid as a last resort so the order is total and reproducible.
    entries.sort_by(|a, b| {
        (a.height, a.block_index)
            .cmp(&(b.height, b.block_index))
            .then_with(|| a.txid.to_internal().cmp(&b.txid.to_internal()))
    });
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::ScriptedReader;
    use verus_rpc::AddressDelta;

    /// VRSCTEST's own currency id.
    const NATIVE: &str = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";
    const TOKEN: &str = "i7UCaJkKRFXBCK4S1AMrkfKTnPwdLc7dV7";

    fn delta(
        txid: u8,
        height: u32,
        index: u32,
        sats: i64,
        spending: bool,
        currencies: &[(&str, i64)],
    ) -> AddressDelta {
        AddressDelta {
            address: "RJUgxvDnDLsRGCXNKDK56Rxngzh6m25J6F".to_string(),
            txid: Txid::from_internal([txid; 32]),
            height,
            block_time: 1_785_250_449,
            block_index: 1,
            index,
            satoshis: SignedAmount::from_sat(sats),
            currency_values: currencies
                .iter()
                .map(|(c, v)| (c.to_string(), SignedAmount::from_sat(*v)))
                .collect(),
            spending,
        }
    }

    fn reader(deltas: Vec<AddressDelta>) -> ScriptedReader {
        ScriptedReader::new(1_170_800).with_deltas(deltas)
    }

    /// The whole native-versus-token split rests on deriving this string
    /// offline. `iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq` is what VRSCTEST reports
    /// as its `chainid`, and what its deltas key the native leg by. If the
    /// derivation drifts, nothing fails loudly — the native leg simply stops
    /// being recognised and starts appearing twice in every entry.
    #[test]
    fn the_native_id_is_derived_to_the_string_the_chain_reports() {
        let reader = reader(Vec::new());
        assert_eq!(native_i_address(&reader).unwrap(), NATIVE);
    }

    /// The shape this module exists for: one payment, three delta rows, one
    /// line in a wallet — and the amount shown is what actually left.
    #[test]
    fn a_send_with_change_folds_into_one_entry() {
        let reader = reader(vec![
            // The output being spent.
            delta(
                0xaa,
                1_166_191,
                0,
                -100_000_000,
                true,
                &[(NATIVE, -100_000_000)],
            ),
            // Change coming back.
            delta(0xaa, 1_166_191, 1, 9_990_000, false, &[(NATIVE, 9_990_000)]),
        ]);

        let entries = history(&reader, &["RJUgxvDnDLsRGCXNKDK56Rxngzh6m25J6F"], None).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].net_native.to_sat(), -90_010_000);
        assert!(entries[0].is_outgoing());
        assert!(entries[0].spent_something);
    }

    /// The native leg is reported twice in one row — once in `satoshis` and
    /// once under the chain's own id in `currencyvalues`. Counting both is a
    /// doubled figure in a wallet, so the map keeps only what is not native.
    #[test]
    fn the_native_leg_is_not_counted_twice() {
        let reader = reader(vec![delta(
            0xbb,
            1_170_746,
            0,
            200_000_000,
            false,
            &[(NATIVE, 200_000_000)],
        )]);

        let entries = history(&reader, &["RJUgxvDnDLsRGCXNKDK56Rxngzh6m25J6F"], None).unwrap();
        assert_eq!(entries[0].net_native.to_sat(), 200_000_000);
        assert!(
            entries[0].net_currencies.is_empty(),
            "the native id must not appear in the currency map as well"
        );
    }

    /// A token transfer moves no native value. A wallet reading only the
    /// native field shows it as nothing happening.
    #[test]
    fn a_token_only_transfer_is_visible() {
        let reader = reader(vec![delta(
            0xcc,
            1_170_746,
            0,
            0,
            false,
            &[(TOKEN, 500_000_000)],
        )]);

        let entries = history(&reader, &["RJUgxvDnDLsRGCXNKDK56Rxngzh6m25J6F"], None).unwrap();
        assert_eq!(entries[0].net_native, SignedAmount::ZERO);
        assert_eq!(entries[0].net_currencies[TOKEN].to_sat(), 500_000_000);
    }

    /// Spending a token output and taking the whole amount back as change did
    /// not move that token. Reporting a zero line invites a phantom row.
    #[test]
    fn a_currency_that_nets_to_zero_is_dropped() {
        let reader = reader(vec![
            delta(0xdd, 1_170_750, 0, 0, true, &[(TOKEN, -500_000_000)]),
            delta(0xdd, 1_170_750, 2, 0, false, &[(TOKEN, 500_000_000)]),
        ]);

        let entries = history(&reader, &["RJUgxvDnDLsRGCXNKDK56Rxngzh6m25J6F"], None).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].net_currencies.is_empty());
        // But something *did* happen: an output of ours was spent.
        assert!(entries[0].spent_something);
    }

    /// Folding is keyed by txid, whose order is a hash. Entries must come back
    /// in chain order regardless.
    #[test]
    fn entries_come_back_oldest_first() {
        let reader = reader(vec![
            delta(0xff, 1_170_750, 0, 100, false, &[]),
            delta(0x11, 1_166_191, 0, 200, false, &[]),
            delta(0x88, 1_167_607, 0, 300, false, &[]),
        ]);

        let heights: Vec<u32> = history(&reader, &["RJUgxvDnDLsRGCXNKDK56Rxngzh6m25J6F"], None)
            .unwrap()
            .iter()
            .map(|e| e.height)
            .collect();
        assert_eq!(heights, vec![1_166_191, 1_167_607, 1_170_750]);
    }

    /// A CryptoCondition output payable to two of your own addresses is
    /// indexed under **both**, so asking about both returns two rows for one
    /// arrival. Summing them reports twice the money — and the overcount grows
    /// with how many of your addresses you ask about together, which is exactly
    /// what a wallet does.
    #[test]
    fn one_output_shared_by_two_queried_addresses_is_counted_once() {
        const OTHER: &str = "RJKGReAJv5qUZJvhVeaGB8exY1ku58D1n7";

        let shared = delta(
            0xee,
            1_170_760,
            0,
            200_000_000,
            false,
            &[(TOKEN, 300_000_000)],
        );
        let mut also_indexed_elsewhere = shared.clone();
        also_indexed_elsewhere.address = OTHER.to_string();

        let reader = reader(vec![shared, also_indexed_elsewhere]);
        let entries = history(
            &reader,
            &["RJUgxvDnDLsRGCXNKDK56Rxngzh6m25J6F", OTHER],
            None,
        )
        .unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].net_native.to_sat(),
            200_000_000,
            "one arrival, not two"
        );
        assert_eq!(entries[0].net_currencies[TOKEN].to_sat(), 300_000_000);
    }

    /// The same shape on the spending side: the row is deduplicated, but the
    /// fact that an output of ours was spent survives it.
    #[test]
    fn a_shared_spend_is_counted_once_and_still_recorded_as_a_spend() {
        const OTHER: &str = "RJKGReAJv5qUZJvhVeaGB8exY1ku58D1n7";

        let shared = delta(0x99, 1_170_760, 0, -200_000_000, true, &[]);
        let mut also_indexed_elsewhere = shared.clone();
        also_indexed_elsewhere.address = OTHER.to_string();

        let reader = reader(vec![shared, also_indexed_elsewhere]);
        let entries = history(
            &reader,
            &["RJUgxvDnDLsRGCXNKDK56Rxngzh6m25J6F", OTHER],
            None,
        )
        .unwrap();

        assert_eq!(entries[0].net_native.to_sat(), -200_000_000);
        assert!(entries[0].spent_something);
    }

    /// An address with nothing in the index is an empty history, not an error.
    #[test]
    fn an_unused_address_has_an_empty_history() {
        let reader = reader(Vec::new());
        assert!(
            history(&reader, &["RJUgxvDnDLsRGCXNKDK56Rxngzh6m25J6F"], None)
                .unwrap()
                .is_empty()
        );
    }
}
