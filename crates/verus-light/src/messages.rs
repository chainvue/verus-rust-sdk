//! The lightwalletd messages this crate reads and writes.
//!
//! Field numbers come from `fixtures/lightwalletd/compact_formats.proto` and
//! `service.proto`, copied verbatim from the server this was developed against.
//! Every decoder here is exercised against a real captured response body, not
//! only against bytes this crate encoded itself — a round-trip test cannot catch
//! a field number that is wrong in both directions.

use crate::error::LightError;
use crate::proto::{
    put_bytes_field, put_message_field, put_varint_field, Reader, WIRE_BYTES, WIRE_VARINT,
};

/// Length of the compact note ciphertext lightwalletd serves: the first 52
/// bytes of an output's `encCiphertext`, which is all that trial decryption
/// needs.
pub const COMPACT_NOTE_SIZE: usize = 52;

/// A block identified by height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockId {
    /// Block height.
    pub height: u64,
    /// Block hash, in the daemon's internal little-endian byte order.
    pub hash: [u8; 32],
}

impl BlockId {
    /// Encode a height-only `BlockID`, which is the only form lightwalletd
    /// accepts as a request ("specification by hash is not implemented").
    pub(crate) fn encode_height(height: u64) -> Vec<u8> {
        let mut out = Vec::new();
        put_varint_field(&mut out, 1, height);
        out
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, LightError> {
        let mut reader = Reader::new(bytes);
        let mut height = 0;
        let mut hash = [0u8; 32];
        let mut saw_field = false;
        while !reader.is_empty() {
            saw_field = true;
            match reader.tag()? {
                (1, WIRE_VARINT) => height = reader.varint()?,
                (2, WIRE_BYTES) => hash = reader.array("block hash")?,
                (_, wire) => reader.skip(wire)?,
            }
        }
        // `proto3` never distinguishes "field absent" from "field equal to its
        // default", so an entirely empty message and a real block at height 0
        // are indistinguishable field-by-field. But a genuinely empty wire
        // payload — zero bytes — is not something a real server sends for
        // this message; refusing it catches a truncated or fabricated
        // response instead of quietly reporting `height: 0, hash: [0; 32]`.
        if !saw_field {
            return Err(LightError::Protobuf(
                "BlockId message is empty; expected at least a height or hash field".into(),
            ));
        }
        Ok(Self { height, hash })
    }

    /// The block hash as it is displayed by explorers and the RPC — reversed.
    #[must_use]
    pub fn hash_display(&self) -> String {
        let mut bytes = self.hash;
        bytes.reverse();
        hex::encode(bytes)
    }
}

/// The Sapling note commitment tree as of the end of one block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeState {
    /// The server's name for the chain — `VRSCTEST` on the Verus fork, where
    /// stock Zcash lightwalletd would say `test`.
    pub network: String,
    /// Height this frontier is the state *after*.
    pub height: u64,
    /// Block hash, as displayed (already reversed by the server).
    pub hash: String,
    /// Unix time the block was mined.
    pub time: u32,
    /// The serialized commitment tree, hex-encoded.
    pub tree: String,
}

impl TreeState {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, LightError> {
        let mut reader = Reader::new(bytes);
        let mut state = Self {
            network: String::new(),
            height: 0,
            hash: String::new(),
            time: 0,
            tree: String::new(),
        };
        let mut saw_field = false;
        while !reader.is_empty() {
            saw_field = true;
            match reader.tag()? {
                (1, WIRE_BYTES) => state.network = reader.string()?,
                (2, WIRE_VARINT) => state.height = reader.varint()?,
                (3, WIRE_BYTES) => state.hash = reader.string()?,
                (4, WIRE_VARINT) => {
                    state.time = u32::try_from(reader.varint()?).map_err(|_| {
                        LightError::Protobuf("block time does not fit in 32 bits".into())
                    })?;
                }
                (5, WIRE_BYTES) => state.tree = reader.string()?,
                (_, wire) => reader.skip(wire)?,
            }
        }
        // See the identical check in `BlockId::decode`: a zero-byte message
        // decodes to every field at its default, which for `TreeState` is an
        // empty `tree` — silently telling a caller the commitment tree is
        // empty rather than that the server sent nothing at all.
        if !saw_field {
            return Err(LightError::Protobuf(
                "TreeState message is empty; expected at least one field".into(),
            ));
        }
        Ok(state)
    }

    /// Decode the serialized commitment tree to bytes.
    ///
    /// Feed these to `verus_sapling::scan::TreeStateBefore::from_serialized` —
    /// the frontier a witness is built on.
    pub fn tree_bytes(&self) -> Result<Vec<u8>, LightError> {
        hex::decode(&self.tree)
            .map_err(|e| LightError::Protobuf(format!("tree is not valid hex: {e}")))
    }

    /// How many commitments the tree holds — which is also the absolute
    /// position the next one will take.
    ///
    /// A Merkle frontier encodes its own size: the two level-0 slots count one
    /// leaf each, and a filled parent at level `i` stands for `2^(i+1)` leaves
    /// below it. Summing them recovers the count without any hashing.
    ///
    /// This is worth checking against
    /// [`CompactBlock::tree_size`](crate::CompactBlock::tree_size) for the same
    /// height. The two arrive by different calls in unrelated encodings — a
    /// serialized frontier here, a varint there — so agreement is real evidence
    /// that a note's position is right, and a position that is off by one
    /// produces a witness that proves, costs a fee, and is rejected.
    pub fn leaf_count(&self) -> Result<u64, LightError> {
        let bytes = self.tree_bytes()?;
        let mut reader = FrontierReader {
            bytes: &bytes,
            offset: 0,
        };
        let mut count = u64::from(reader.optional_node()?) + u64::from(reader.optional_node()?);
        let parents = reader.compact_size()?;
        // A Sapling tree is 32 levels deep; more than that is a corrupt blob.
        if parents > 32 {
            return Err(LightError::Protobuf(format!(
                "{parents} parents, but a Sapling tree has at most 32 levels"
            )));
        }
        for level in 0..parents {
            if reader.optional_node()? == 1 {
                count += 1u64 << (level + 1);
            }
        }
        if reader.offset != bytes.len() {
            return Err(LightError::Protobuf(format!(
                "{} bytes left over after the commitment tree",
                bytes.len() - reader.offset
            )));
        }
        Ok(count)
    }
}

/// A minimal walk over a serialized commitment tree, counting rather than
/// hashing. `verus-sapling` parses the same bytes into nodes; this deliberately
/// does not depend on it, so the integrity check costs no proving stack.
struct FrontierReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl FrontierReader<'_> {
    /// Read `00` or `01` followed by a 32-byte node; returns whether one was
    /// present.
    fn optional_node(&mut self) -> Result<u8, LightError> {
        let tag = *self
            .bytes
            .get(self.offset)
            .ok_or_else(|| LightError::Protobuf("commitment tree ends early".into()))?;
        self.offset += 1;
        match tag {
            0 => Ok(0),
            1 => {
                if self.offset + 32 > self.bytes.len() {
                    return Err(LightError::Protobuf(
                        "commitment tree node is truncated".into(),
                    ));
                }
                self.offset += 32;
                Ok(1)
            }
            other => Err(LightError::Protobuf(format!(
                "commitment tree node tag {other} is neither absent (0) nor present (1)"
            ))),
        }
    }

    fn compact_size(&mut self) -> Result<u8, LightError> {
        let first = *self
            .bytes
            .get(self.offset)
            .ok_or_else(|| LightError::Protobuf("commitment tree has no parent count".into()))?;
        self.offset += 1;
        if first < 0xfd {
            return Ok(first);
        }
        Err(LightError::Protobuf(format!(
            "parent count prefix {first:#x} encodes more than 32 levels"
        )))
    }
}

/// One Sapling output, stripped to what trial decryption needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactSaplingOutput {
    /// Note commitment u-coordinate.
    pub cmu: [u8; 32],
    /// Ephemeral public key.
    pub epk: [u8; 32],
    /// First [`COMPACT_NOTE_SIZE`] bytes of the output's `encCiphertext`.
    pub ciphertext: [u8; COMPACT_NOTE_SIZE],
}

impl CompactSaplingOutput {
    fn decode(bytes: &[u8]) -> Result<Self, LightError> {
        let mut reader = Reader::new(bytes);
        let mut cmu = None;
        let mut epk = None;
        let mut ciphertext = None;
        while !reader.is_empty() {
            match reader.tag()? {
                (1, WIRE_BYTES) => cmu = Some(reader.array("cmu")?),
                (2, WIRE_BYTES) => epk = Some(reader.array("epk")?),
                (3, WIRE_BYTES) => ciphertext = Some(reader.array("compact ciphertext")?),
                (_, wire) => reader.skip(wire)?,
            }
        }
        // These are not optional in practice, and a zeroed cmu would be silently
        // appended to a commitment tree and corrupt every witness after it.
        Ok(Self {
            cmu: cmu.ok_or_else(|| LightError::Protobuf("output has no cmu".into()))?,
            epk: epk.ok_or_else(|| LightError::Protobuf("output has no epk".into()))?,
            ciphertext: ciphertext
                .ok_or_else(|| LightError::Protobuf("output has no ciphertext".into()))?,
        })
    }
}

/// One transaction, stripped to its shielded parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactTx {
    /// Index of this transaction within its block.
    pub index: u64,
    /// Transaction hash, internal byte order.
    pub hash: [u8; 32],
    /// Nullifiers of the notes this transaction spends. A wallet marks its own
    /// note spent when it sees that note's nullifier here.
    pub nullifiers: Vec<[u8; 32]>,
    /// Shielded outputs, in the order they enter the commitment tree.
    pub outputs: Vec<CompactSaplingOutput>,
}

impl CompactTx {
    fn decode(bytes: &[u8]) -> Result<Self, LightError> {
        let mut reader = Reader::new(bytes);
        let mut tx = Self {
            index: 0,
            hash: [0u8; 32],
            nullifiers: Vec::new(),
            outputs: Vec::new(),
        };
        while !reader.is_empty() {
            match reader.tag()? {
                (1, WIRE_VARINT) => tx.index = reader.varint()?,
                (2, WIRE_BYTES) => tx.hash = reader.array("transaction hash")?,
                (4, WIRE_BYTES) => {
                    let mut spend = Reader::new(reader.bytes()?);
                    while !spend.is_empty() {
                        match spend.tag()? {
                            (1, WIRE_BYTES) => tx.nullifiers.push(spend.array("nullifier")?),
                            (_, wire) => spend.skip(wire)?,
                        }
                    }
                }
                (5, WIRE_BYTES) => tx
                    .outputs
                    .push(CompactSaplingOutput::decode(reader.bytes()?)?),
                (_, wire) => reader.skip(wire)?,
            }
        }
        Ok(tx)
    }
}

/// One block, stripped to its shielded parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactBlock {
    /// Block height.
    pub height: u64,
    /// Block hash, internal byte order.
    pub hash: [u8; 32],
    /// Previous block hash, internal byte order. Chains one block to the next,
    /// which is how a wallet detects a reorg while scanning.
    pub prev_hash: [u8; 32],
    /// Unix time the block was mined.
    pub time: u32,
    /// Transactions with shielded components. Transparent-only transactions are
    /// absent, so this is **not** the block's full transaction list and its
    /// indices are the real in-block indices, not positions in this vector.
    pub transactions: Vec<CompactTx>,
    /// Size of the Sapling commitment tree at the **end** of this block, when
    /// the server provides it.
    ///
    /// Worth using: the size at the end of block `h - 1` is the absolute tree
    /// position of the first output in block `h`, so it cross-checks a position
    /// derived from a parsed frontier without trusting the parse.
    pub tree_size: Option<u64>,
}

impl CompactBlock {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, LightError> {
        let mut reader = Reader::new(bytes);
        let mut block = Self {
            height: 0,
            hash: [0u8; 32],
            prev_hash: [0u8; 32],
            time: 0,
            transactions: Vec::new(),
            tree_size: None,
        };
        while !reader.is_empty() {
            match reader.tag()? {
                (2, WIRE_VARINT) => block.height = reader.varint()?,
                (3, WIRE_BYTES) => block.hash = reader.array("block hash")?,
                (4, WIRE_BYTES) => block.prev_hash = reader.array("previous block hash")?,
                (5, WIRE_VARINT) => {
                    block.time = u32::try_from(reader.varint()?).map_err(|_| {
                        LightError::Protobuf("block time does not fit in 32 bits".into())
                    })?;
                }
                (7, WIRE_BYTES) => block.transactions.push(CompactTx::decode(reader.bytes()?)?),
                (8, WIRE_BYTES) => {
                    let mut meta = Reader::new(reader.bytes()?);
                    while !meta.is_empty() {
                        match meta.tag()? {
                            (1, WIRE_VARINT) => block.tree_size = Some(meta.varint()?),
                            (_, wire) => meta.skip(wire)?,
                        }
                    }
                }
                (_, wire) => reader.skip(wire)?,
            }
        }
        Ok(block)
    }

    /// Every shielded output in the block, in commitment-tree order.
    ///
    /// This is what a witness is advanced with — including outputs belonging to
    /// other people, which is most of them.
    #[must_use]
    pub fn commitments(&self) -> Vec<[u8; 32]> {
        self.transactions
            .iter()
            .flat_map(|tx| tx.outputs.iter().map(|out| out.cmu))
            .collect()
    }
}

/// A full transaction as the daemon serializes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawTransaction {
    /// Consensus-serialized transaction bytes.
    pub data: Vec<u8>,
    /// Height it was mined at.
    pub height: u64,
}

impl RawTransaction {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, LightError> {
        let mut reader = Reader::new(bytes);
        let mut tx = Self {
            data: Vec::new(),
            height: 0,
        };
        while !reader.is_empty() {
            match reader.tag()? {
                (1, WIRE_BYTES) => tx.data = reader.bytes()?.to_vec(),
                (2, WIRE_VARINT) => tx.height = reader.varint()?,
                (_, wire) => reader.skip(wire)?,
            }
        }
        Ok(tx)
    }

    pub(crate) fn encode(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put_bytes_field(&mut out, 1, data);
        out
    }
}

/// What a server says about a transaction it was asked to relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendResponse {
    /// Zero on success.
    pub error_code: i32,
    /// On success this is the daemon's reply to `sendrawtransaction`, which is
    /// the txid — but that is a lightwalletd convention rather than something
    /// the protocol promises, so it is surfaced as the string it is rather than
    /// parsed into a [`crate::BlockId`]-like type.
    pub error_message: String,
}

impl SendResponse {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, LightError> {
        let mut reader = Reader::new(bytes);
        let mut response = Self {
            error_code: 0,
            error_message: String::new(),
        };
        while !reader.is_empty() {
            match reader.tag()? {
                (1, WIRE_VARINT) => response.error_code = reader.int32()?,
                (2, WIRE_BYTES) => response.error_message = reader.string()?,
                (_, wire) => reader.skip(wire)?,
            }
        }
        Ok(response)
    }
}

/// What the server says about itself.
///
/// Only the fields worth acting on are decoded; the rest are build metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    /// lightwalletd's own version string.
    pub version: String,
    /// Chain name — `VRSCTEST` or `VRSC` on the Verus fork.
    pub chain_name: String,
    /// Height Sapling activated at.
    pub sapling_activation_height: u64,
    /// Consensus branch id, hex. Must match the branch id this SDK signs under,
    /// or every transaction it builds will be rejected.
    pub consensus_branch_id: String,
    /// The server's view of the chain tip.
    pub block_height: u64,
    /// Where the daemon has synced to, which lags the tip while it catches up.
    pub estimated_height: u64,
}

impl ServerInfo {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, LightError> {
        let mut reader = Reader::new(bytes);
        let mut info = Self {
            version: String::new(),
            chain_name: String::new(),
            sapling_activation_height: 0,
            consensus_branch_id: String::new(),
            block_height: 0,
            estimated_height: 0,
        };
        let mut saw_field = false;
        while !reader.is_empty() {
            saw_field = true;
            match reader.tag()? {
                (1, WIRE_BYTES) => info.version = reader.string()?,
                (4, WIRE_BYTES) => info.chain_name = reader.string()?,
                (5, WIRE_VARINT) => info.sapling_activation_height = reader.varint()?,
                (6, WIRE_BYTES) => info.consensus_branch_id = reader.string()?,
                (7, WIRE_VARINT) => info.block_height = reader.varint()?,
                (12, WIRE_VARINT) => info.estimated_height = reader.varint()?,
                (_, wire) => reader.skip(wire)?,
            }
        }
        // See the identical check in `BlockId::decode`. `consensus_branch_id`
        // in particular is meant to be checked against the id this SDK signs
        // under (see the doc comment on the field): a caller that skips that
        // check because an empty response decoded to an empty-but-valid
        // string would sign transactions for the wrong chain.
        if !saw_field {
            return Err(LightError::Protobuf(
                "ServerInfo message is empty; expected at least one field".into(),
            ));
        }
        Ok(info)
    }
}

/// Encode a `BlockRange` from two heights.
pub(crate) fn encode_block_range(start: u64, end: u64) -> Vec<u8> {
    let mut out = Vec::new();
    // `start` and `end` are message-typed (`BlockID`), not `bytes` scalars —
    // proto3 tracks presence for them, so both must be emitted even when the
    // submessage they hold serializes to zero bytes (a height-0 `BlockID`).
    // See `put_message_field`'s doc comment.
    put_message_field(&mut out, 1, &BlockId::encode_height(start));
    put_message_field(&mut out, 2, &BlockId::encode_height(end));
    out
}

/// Encode a `TxFilter` selecting a transaction by hash.
pub(crate) fn encode_tx_filter(hash: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    put_bytes_field(&mut out, 3, hash);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `BlockRange.start`/`end` are message-typed (`BlockID`), not `bytes`
    /// scalars. `block_range(0, 10)` asks for a `Start` whose `BlockID`
    /// serializes to zero bytes — `BlockId::encode_height(0)` elides the
    /// height field the way a `proto3` scalar correctly does — and the
    /// encoder must still emit `Start`'s tag with `len=0` rather than drop
    /// the field entirely, or lightwalletd sees only `End` and rejects the
    /// request as missing a start height.
    #[test]
    fn block_range_from_height_zero_encodes_both_bounds() {
        let encoded = encode_block_range(0, 10);

        let mut reader = Reader::new(&encoded);
        let mut fields = Vec::new();
        while !reader.is_empty() {
            let (field, wire) = reader.tag().unwrap();
            reader.skip(wire).unwrap();
            fields.push(field);
        }

        assert_eq!(
            fields,
            vec![1, 2],
            "BlockRange must carry both Start (height 0) and End, in that order"
        );
    }
}
