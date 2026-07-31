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
    // Policy
    GetCurrency,
    GetCurrencyState,
    EstimateConversion,
    GetIdentity,
    GetIdentityHistory,
    GetVdxfId,
    VerifyMessage,
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
            Method::GetCurrency => "getcurrency",
            Method::GetCurrencyState => "getcurrencystate",
            Method::EstimateConversion => "estimateconversion",
            Method::GetIdentity => "getidentity",
            Method::GetIdentityHistory => "getidentityhistory",
            Method::GetVdxfId => "getvdxfid",
            Method::VerifyMessage => "verifymessage",
            Method::GetRawTransaction => "getrawtransaction",
            Method::DecodeRawTransaction => "decoderawtransaction",
            Method::SendRawTransaction => "sendrawtransaction",
        }
    }

    /// Whether calling this can change state anywhere.
    ///
    /// Exactly one method can, which is the property the read/write split in
    /// [`crate::client`] rests on.
    const fn is_write(self) -> bool {
        matches!(self, Method::SendRawTransaction)
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
        Method::GetCurrency,
        Method::GetCurrencyState,
        Method::EstimateConversion,
        Method::GetIdentity,
        Method::GetIdentityHistory,
        Method::GetVdxfId,
        Method::VerifyMessage,
        Method::GetRawTransaction,
        Method::DecodeRawTransaction,
        Method::SendRawTransaction,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_method_writes() {
        let writes: Vec<_> = Method::ALL.iter().filter(|m| m.is_write()).collect();
        assert_eq!(writes, vec![&Method::SendRawTransaction]);
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
