//! Asking a light server for the data a shielded wallet cannot compute.

use crate::error::LightError;
use crate::grpc::{decode_body, frame_request};
use crate::messages::{
    encode_block_range, encode_tx_filter, BlockId, CompactBlock, RawTransaction, SendResponse,
    ServerInfo, TreeState,
};
use crate::method::Method;
use crate::transport::LightTransport;

/// Most blocks [`LightClient::block_range`] will fetch in one call.
///
/// Not a protocol limit — the server streams as many as you ask for. It is a
/// guard against a caller turning one typo into a multi-gigabyte response, and
/// it is enforced by refusing the request rather than by quietly returning the
/// first `MAX_BLOCK_RANGE` blocks. A silently short range is the worst possible
/// failure here: the wallet would conclude the missing blocks held no notes.
pub const MAX_BLOCK_RANGE: u64 = 10_000;

/// A read-only client for a lightwalletd server.
///
/// Everything here except [`send_transaction`](Self::send_transaction) is a
/// question. The server sees which blocks you ask for and the transactions you
/// submit; it never sees a key, because there is no method that could carry one.
pub struct LightClient<T> {
    transport: T,
}

impl<T: LightTransport> LightClient<T> {
    /// Wrap a transport.
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// The underlying transport.
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    /// Make a call and return every message the server streamed back.
    fn call(&self, method: Method, request: &[u8]) -> Result<Vec<Vec<u8>>, LightError> {
        let framed = frame_request(request);
        let response = self.transport.call(&method.path(), &framed)?;

        // A non-zero status in the HTTP headers means a trailers-only error
        // response, whose body is empty. Classify it before looking at frames,
        // or an error reads as a successful empty result.
        if let Some(status) = response.status.clone() {
            status.check()?;
        }

        let body = decode_body(&response.body)?;
        match (body.status, response.status) {
            // A trailer frame is authoritative when present.
            (Some(status), _) => status.check()?,
            // Headers said OK and there was no trailer: accept it.
            (None, Some(_)) => {}
            (None, None) => {
                return Err(LightError::Framing(
                    "response carried no grpc-status, in headers or in a trailer frame".into(),
                ))
            }
        }

        Ok(body.messages.into_iter().map(<[u8]>::to_vec).collect())
    }

    /// Make a call that must return exactly one message.
    fn unary(&self, method: Method, request: &[u8]) -> Result<Vec<u8>, LightError> {
        let mut messages = self.call(method, request)?;
        if messages.len() != 1 {
            return Err(LightError::NotUnary(messages.len()));
        }
        Ok(messages.remove(0))
    }

    /// The tip of the best chain, as this server sees it.
    pub fn latest_block(&self) -> Result<BlockId, LightError> {
        BlockId::decode(&self.unary(Method::GetLatestBlock, &[])?)
    }

    /// What the server says about itself and the chain it follows.
    ///
    /// Worth calling once at startup: [`ServerInfo::consensus_branch_id`] must
    /// match the branch id this SDK signs under, and
    /// [`ServerInfo::chain_name`] tells you whether you are pointed at testnet.
    pub fn server_info(&self) -> Result<ServerInfo, LightError> {
        ServerInfo::decode(&self.unary(Method::GetLightdInfo, &[])?)
    }

    /// The Sapling commitment tree as of the end of `height`.
    ///
    /// To witness a note mined in block `h`, ask for `h - 1`: the frontier
    /// *before* its block. That frontier is the one input an offline signer
    /// cannot derive for itself, because a commitment tree cannot be walked
    /// backwards.
    pub fn tree_state(&self, height: u64) -> Result<TreeState, LightError> {
        TreeState::decode(&self.unary(Method::GetTreeState, &BlockId::encode_height(height))?)
    }

    /// Every compact block from `start` to `end`, inclusive.
    ///
    /// Blocks with no shielded activity come back with an empty transaction
    /// list rather than being skipped, which is what witness maintenance needs
    /// — a skipped block silently corrupts every witness being advanced.
    ///
    /// Refuses a range wider than [`MAX_BLOCK_RANGE`], or one that runs
    /// backwards.
    pub fn block_range(&self, start: u64, end: u64) -> Result<Vec<CompactBlock>, LightError> {
        if end < start {
            return Err(LightError::Refused(format!(
                "block range {start}..={end} runs backwards"
            )));
        }
        // `end - start` cannot underflow (checked above), but `+ 1` can
        // overflow for `end == u64::MAX` — `block_range(0, u64::MAX)` being
        // the obvious way to hit it. A wrapping `count` of 0 would sail
        // straight past the `MAX_BLOCK_RANGE` guard below, and the trailing
        // `blocks.len() != count` check would then pass vacuously against
        // whatever the server actually sent, for the same silent-empty-range
        // failure this module exists to prevent.
        let count = (end - start).checked_add(1).ok_or_else(|| {
            LightError::Refused(format!(
                "block range {start}..={end} has no representable block count"
            ))
        })?;
        if count > MAX_BLOCK_RANGE {
            return Err(LightError::Refused(format!(
                "{count} blocks is more than the {MAX_BLOCK_RANGE} this client will fetch at once; \
                 split the range so no block is silently dropped"
            )));
        }

        let messages = self.call(Method::GetBlockRange, &encode_block_range(start, end))?;
        let blocks = messages
            .iter()
            .map(|message| CompactBlock::decode(message))
            .collect::<Result<Vec<_>, _>>()?;

        // The server streams blocks in order and omits none. Checking is cheap,
        // and a gap here would be indistinguishable from "no notes in those
        // blocks" everywhere downstream.
        for (offset, block) in blocks.iter().enumerate() {
            let offset = u64::try_from(offset).expect("an index fits in u64");
            // `count` is bounded by `MAX_BLOCK_RANGE` for what this client
            // *asked* for, but a hostile server can stream back more messages
            // than it was asked for, so `offset` here is not actually bounded
            // by that guard. Combined with a `start` near `u64::MAX`, a plain
            // `start + offset` can overflow; `checked_add` turns that into an
            // error instead of a wrapped height that could coincidentally
            // match `block.height` and mask the overflow entirely.
            let expected = start.checked_add(offset).ok_or_else(|| {
                LightError::Protobuf(format!(
                    "block position {offset} overflows a height starting at {start}"
                ))
            })?;
            if block.height != expected {
                return Err(LightError::Protobuf(format!(
                    "expected block {expected} at position {offset} of the range, got {}",
                    block.height
                )));
            }
        }
        if blocks.len() != usize::try_from(count).unwrap_or(usize::MAX) {
            return Err(LightError::Protobuf(format!(
                "asked for {count} blocks in {start}..={end}, got {}",
                blocks.len()
            )));
        }

        Ok(blocks)
    }

    /// A full transaction by hash.
    ///
    /// `hash` is in internal byte order — the reverse of what an explorer
    /// displays. Use `verus_tx::Txid` if you have a display-order string.
    pub fn transaction(&self, hash: &[u8; 32]) -> Result<RawTransaction, LightError> {
        RawTransaction::decode(&self.unary(Method::GetTransaction, &encode_tx_filter(hash))?)
    }

    /// Hand a signed transaction to the network.
    ///
    /// The only method here that is not a question. A non-zero `errorCode`
    /// becomes an error; on success the server's message is returned **verbatim**.
    ///
    /// # The reply is not a bare txid
    ///
    /// lightwalletd passes the daemon's `sendrawtransaction` answer straight
    /// through, JSON encoding included. A real success, observed 2026-07-29:
    ///
    /// ```text
    /// "8f9e0a6b1073349bd6f25433e617de3bd4826ab4afeae68b293d23d6e68a78c8"
    /// ```
    ///
    /// — 66 characters, with the quotation marks. Use
    /// [`txid_from_reply`](Self::txid_from_reply) rather than treating this as a
    /// hash; a caller that compares it to a txid gets an inequality it cannot
    /// explain, and one that stores it produces an id no explorer will resolve.
    ///
    /// **Never retry this automatically.** A transport failure is ambiguous:
    /// the server may have relayed it already. Re-read with
    /// [`transaction`](Self::transaction) before deciding.
    pub fn send_transaction(&self, raw: &[u8]) -> Result<String, LightError> {
        let response = SendResponse::decode(
            &self.unary(Method::SendTransaction, &RawTransaction::encode(raw))?,
        )?;
        if response.error_code != 0 {
            return Err(LightError::Status {
                code: response.error_code,
                message: response.error_message,
            });
        }
        Ok(response.error_message)
    }

    /// Extract a transaction id from a [`send_transaction`](Self::send_transaction)
    /// reply.
    ///
    /// Strips the JSON quoting lightwalletd passes through from the daemon, and
    /// refuses anything that is not 64 hex characters — so a server that answers
    /// with a status string, an empty body or an error message cannot be
    /// mistaken for a transaction that exists. A caller polling a fabricated id
    /// waits forever on a payment that was never relayed.
    ///
    /// ```
    /// # use verus_light::{LightClient, LightTransport};
    /// # fn f<T: LightTransport>(c: &LightClient<T>) {
    /// let reply = "\"8f9e0a6b1073349bd6f25433e617de3bd4826ab4afeae68b293d23d6e68a78c8\"";
    /// assert_eq!(
    ///     LightClient::<T>::txid_from_reply(reply).unwrap(),
    ///     "8f9e0a6b1073349bd6f25433e617de3bd4826ab4afeae68b293d23d6e68a78c8"
    /// );
    /// assert!(LightClient::<T>::txid_from_reply("ok").is_err());
    /// # }
    /// ```
    pub fn txid_from_reply(reply: &str) -> Result<String, LightError> {
        let trimmed = reply.trim().trim_matches('"');
        if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(LightError::Protobuf(format!(
                "the server's reply is not a transaction id: {reply:?}"
            )));
        }
        Ok(trimmed.to_ascii_lowercase())
    }
}
