//! The finite set of gRPC methods this crate can call.
//!
//! Same discipline as `verus_rpc::method`: one private enum is the only place a
//! method name becomes a string, so the callable surface is enumerable and a
//! reviewer can check it without reading every call site.
//!
//! The stakes are lower here than on the JSON-RPC client — `CompactTxStreamer`
//! has no wallet, no key handling and nothing that can sign — but the property
//! is cheap to keep and [`callable_methods`] makes it testable.

/// The gRPC service every method below belongs to.
const SERVICE: &str = "cash.z.wallet.sdk.rpc.CompactTxStreamer";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    GetLatestBlock,
    GetTreeState,
    GetBlockRange,
    GetTransaction,
    SendTransaction,
    GetLightdInfo,
}

impl Method {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::GetLatestBlock => "GetLatestBlock",
            Self::GetTreeState => "GetTreeState",
            Self::GetBlockRange => "GetBlockRange",
            Self::GetTransaction => "GetTransaction",
            Self::SendTransaction => "SendTransaction",
            Self::GetLightdInfo => "GetLightdInfo",
        }
    }

    /// The full path a grpc-web request is POSTed to.
    pub(crate) fn path(self) -> String {
        format!("{SERVICE}/{}", self.name())
    }

    /// Whether the call hands the network something, rather than asking it a
    /// question.
    ///
    /// # Why every read is written out
    ///
    /// `matches!(self, Self::SendTransaction)` says the same thing in one line
    /// and fails to the wrong side. A write method added later without a case
    /// here would silently be a read — and [`callable_methods`], the list an
    /// audit or a proxy allowlist asserts against, would report it as one.
    /// Nothing would fail: not the build, not a test.
    ///
    /// Listing the reads makes that a compile error instead. Same argument
    /// `verus_rpc::Method::is_write` makes one crate over, and lightwalletd
    /// does accept transaction submission, so the arm being wrong is not a
    /// labelling mistake.
    pub(crate) fn writes(self) -> bool {
        match self {
            Self::SendTransaction => true,

            Self::GetLatestBlock
            | Self::GetTreeState
            | Self::GetBlockRange
            | Self::GetTransaction
            | Self::GetLightdInfo => false,
        }
    }

    const ALL: [Self; 6] = [
        Self::GetLatestBlock,
        Self::GetTreeState,
        Self::GetBlockRange,
        Self::GetTransaction,
        Self::SendTransaction,
        Self::GetLightdInfo,
    ];
}

/// One method this crate is able to call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallableMethod {
    /// The method name, as it appears after the service path.
    pub name: &'static str,
    /// True if the call submits something to the network.
    pub writes: bool,
}

/// Every gRPC method this crate can emit — for audit, and for tests that assert
/// the surface has not grown.
///
/// ```
/// let methods = verus_light::callable_methods();
/// // Exactly one of them hands anything to the network.
/// assert_eq!(methods.iter().filter(|m| m.writes).count(), 1);
/// ```
#[must_use]
pub fn callable_methods() -> Vec<CallableMethod> {
    Method::ALL
        .iter()
        .map(|method| CallableMethod {
            name: method.name(),
            writes: method.writes(),
        })
        .collect()
}
