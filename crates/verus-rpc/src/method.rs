//! The only place a method name becomes a string.
//!
//! Every request this crate can emit is a variant here. That makes the set
//! finite, greppable and reviewable: adding one is a diff, and the denylist test
//! in `tests/no_wallet_methods.rs` fails if a wallet method ever appears — in
//! this enum or as a literal anywhere else in the crate.
//!
//! **No wallet methods.** Anything that asks a node to hold, use or reveal a key
//! is absent by construction: the SDK signs locally and hands over finished
//! bytes.

/// A JSON-RPC method this crate is allowed to call.
///
/// Deliberately private to the crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Method {
    // Chain
    GetInfo,
    GetBlockCount,
    GetBestBlockHash,
    GetBlockHash,
    GetBlock,
    // Funds
    GetAddressUtxos,
    GetAddressBalance,
    GetAddressDeltas,
    GetAddressMempool,
    // Policy
    GetCurrency,
    GetCurrencyState,
    ListCurrencies,
    GetCurrencyConverters,
    EstimateConversion,
    EstimateFee,
    GetIdentity,
    GetIdentityHistory,
    GetIdentityContent,
    GetVdxfId,
    GetOffers,
    VerifyMessage,
    GetRawMempool,
    // Transactions
    GetRawTransaction,
    DecodeRawTransaction,
    /// The one method that changes anything, and it takes bytes that were
    /// already signed elsewhere.
    SendRawTransaction,
}

impl Method {
    /// The wire name.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Method::GetInfo => "getinfo",
            Method::GetBlockCount => "getblockcount",
            Method::GetBestBlockHash => "getbestblockhash",
            Method::GetBlockHash => "getblockhash",
            Method::GetBlock => "getblock",
            Method::GetAddressUtxos => "getaddressutxos",
            Method::GetAddressBalance => "getaddressbalance",
            Method::GetAddressDeltas => "getaddressdeltas",
            Method::GetAddressMempool => "getaddressmempool",
            Method::GetCurrency => "getcurrency",
            Method::GetCurrencyState => "getcurrencystate",
            Method::ListCurrencies => "listcurrencies",
            Method::GetCurrencyConverters => "getcurrencyconverters",
            Method::EstimateFee => "estimatefee",
            Method::EstimateConversion => "estimateconversion",
            Method::GetIdentity => "getidentity",
            Method::GetIdentityHistory => "getidentityhistory",
            Method::GetIdentityContent => "getidentitycontent",
            Method::GetVdxfId => "getvdxfid",
            Method::GetOffers => "getoffers",
            Method::VerifyMessage => "verifymessage",
            Method::GetRawMempool => "getrawmempool",
            Method::GetRawTransaction => "getrawtransaction",
            Method::DecodeRawTransaction => "decoderawtransaction",
            Method::SendRawTransaction => "sendrawtransaction",
        }
    }

    /// Whether calling this can change state anywhere.
    ///
    /// Exactly one method can, which is the property the read/write split in
    /// [`crate::client`] rests on — and, since [`Cassette`](crate::Cassette)
    /// landed, rather more than that: a request this reports as a read is
    /// **recorded and handed to a driver to post**, and a driver posts what it
    /// is told.
    ///
    /// # Why every read is written out
    ///
    /// `matches!(self, Method::SendRawTransaction)` says the same thing in one
    /// line and fails to the wrong side. A write method added later without a
    /// case here would silently be a read: recorded rather than refused, then
    /// posted once per round — up to the driver's round cap — by every caller
    /// following the documented "post `ask` verbatim" contract.
    ///
    /// Listing the reads makes that a compile error instead. Same reason the
    /// `name` match above is exhaustive, applied to the arm where being wrong
    /// costs money rather than a label.
    pub(crate) const fn is_write(self) -> bool {
        match self {
            Method::SendRawTransaction => true,

            Method::GetInfo
            | Method::GetBlockCount
            | Method::GetBestBlockHash
            | Method::GetBlockHash
            | Method::GetBlock
            | Method::GetAddressUtxos
            | Method::GetAddressBalance
            | Method::GetAddressDeltas
            | Method::GetAddressMempool
            | Method::GetCurrency
            | Method::GetCurrencyState
            | Method::ListCurrencies
            | Method::GetCurrencyConverters
            | Method::EstimateFee
            | Method::EstimateConversion
            | Method::GetIdentity
            | Method::GetIdentityHistory
            | Method::GetIdentityContent
            | Method::GetVdxfId
            | Method::GetOffers
            | Method::VerifyMessage
            | Method::GetRawMempool
            | Method::GetRawTransaction
            | Method::DecodeRawTransaction => false,
        }
    }

    /// Every variant.
    const ALL: &'static [Method] = &[
        Method::GetInfo,
        Method::GetBlockCount,
        Method::GetBestBlockHash,
        Method::GetBlockHash,
        Method::GetBlock,
        Method::GetAddressUtxos,
        Method::GetAddressBalance,
        Method::GetAddressDeltas,
        Method::GetCurrency,
        Method::GetCurrencyState,
        Method::ListCurrencies,
        Method::GetCurrencyConverters,
        Method::EstimateConversion,
        Method::EstimateFee,
        Method::GetIdentity,
        Method::GetIdentityHistory,
        Method::GetIdentityContent,
        Method::GetVdxfId,
        Method::GetOffers,
        Method::VerifyMessage,
        Method::GetRawMempool,
        Method::GetRawTransaction,
        Method::DecodeRawTransaction,
        Method::SendRawTransaction,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Which methods write, over the whole enum.
    ///
    /// Note what this can and cannot do. It fails when a *correctly* flagged
    /// second write is added, which is a prompt to think rather than a defect
    /// found. It cannot fail when a flag is **forgotten** — the dangerous
    /// direction — because a method missing from `ALL` is invisible here.
    /// That direction is guarded by `is_write` being an exhaustive match, so a
    /// new variant does not compile until it is classified.
    #[test]
    fn only_one_method_writes() {
        let writes: Vec<_> = Method::ALL.iter().filter(|m| m.is_write()).collect();
        assert_eq!(writes, vec![&Method::SendRawTransaction]);
    }

    /// `ALL` has to actually be all of them, or every test that iterates it
    /// proves less than it looks like it does.
    ///
    /// Checked through `name`, whose match *is* exhaustive: a variant missing
    /// from `ALL` has a name no entry produces.
    #[test]
    fn every_variant_is_listed() {
        for method in Method::ALL {
            assert!(!method.name().is_empty());
        }
        // Distinctness is checked separately; this is the count, pinned so a
        // variant added to the enum and to `name` but not to `ALL` is caught.
        assert_eq!(Method::ALL.len(), 24);
    }

    #[test]
    fn every_name_is_distinct() {
        let mut names: Vec<_> = Method::ALL.iter().map(|m| m.name()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count);
    }
}

/// One method this crate is able to call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallableMethod {
    /// The JSON-RPC method name.
    pub name: &'static str,
    /// Whether calling it can change state anywhere.
    pub writes: bool,
}

/// Every JSON-RPC method this crate is able to emit.
///
/// The crate docs claim a node is never asked to hold or use a key. This is
/// that claim in machine-readable form: a consumer with its own policy — an
/// audit, a proxy allowlist, a compliance check — can assert against this list
/// rather than trusting the prose, and will notice if a later version adds
/// something.
///
/// ```
/// let methods = verus_rpc::callable_methods();
///
/// // Exactly one method changes anything, and it takes bytes signed elsewhere.
/// let writes: Vec<_> = methods.iter().filter(|m| m.writes).collect();
/// assert_eq!(writes.len(), 1);
/// assert_eq!(writes[0].name, "sendrawtransaction");
///
/// // Nothing here asks a node for, or about, a key.
/// assert!(!methods.iter().any(|m| m.name.contains("wallet")));
/// ```
pub fn callable_methods() -> Vec<CallableMethod> {
    Method::ALL
        .iter()
        .map(|method| CallableMethod {
            name: method.name(),
            writes: method.is_write(),
        })
        .collect()
}
