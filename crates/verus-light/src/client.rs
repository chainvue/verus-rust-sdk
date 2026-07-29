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
        let count = end - start + 1;
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
            let expected = start + u64::try_from(offset).expect("an index fits in u64");
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
    /// The only method here that is not a question. A non-zero `errorCode` from
    /// the server becomes an error; on success the server's message is returned
    /// verbatim, which for lightwalletd is the daemon's `sendrawtransaction`
    /// reply — conventionally the txid, though the protocol does not say so.
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
}
