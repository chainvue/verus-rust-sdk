//! A chain you can write down.
//!
//! Flows are mostly *sequencing* — look up, decide, build, broadcast, look up
//! again — and sequencing is what breaks. The interesting cases are things a
//! live node will not produce on demand: a height that does not move for three
//! polls, the same height under a different block hash, a commitment that
//! vanishes, a broadcast that fails ambiguously.
//!
//! So the tests script the chain instead of asking for one. Nothing here sleeps
//! and nothing opens a socket, which is what makes the reorg and timeout paths
//! testable at all.
//!
//! Available to dependents under the `testing` feature, because a wallet built
//! on these flows has exactly the same problem.

use std::cell::RefCell;

use serde_json::json;
use verus_rpc::{
    AddressBalance, AddressDelta, AddressUtxo, Broadcaster, ChainInfo, ChainReader, CurrencyPolicy,
    IdentityRecord, RpcError,
};
use verus_tx::{Amount, Txid, Utxo};

/// A chain whose answers are decided in advance.
pub struct ScriptedReader {
    tip: RefCell<u32>,
    hash_override: RefCell<Option<String>>,
    utxos: RefCell<Vec<AddressUtxo>>,
    coinbase_heights: RefCell<Vec<u32>>,
    identities: RefCell<Vec<(String, IdentityRecord)>>,
    policy: RefCell<Option<CurrencyPolicy>>,
    confirmations: RefCell<Vec<(String, u32)>>,
    /// Heights handed out by successive `block_count` calls, consumed in order.
    /// Empty means "the tip does not move".
    heights: RefCell<Vec<u32>>,
    requests: RefCell<usize>,
    broadcasts: RefCell<Vec<String>>,
    broadcast_failure: RefCell<Option<RpcError>>,
    estimate: RefCell<Option<verus_rpc::ConversionEstimate>>,
    deltas: RefCell<Vec<AddressDelta>>,
    pub(crate) raw_transactions: RefCell<std::collections::HashMap<String, serde_json::Value>>,
}

impl ScriptedReader {
    /// A chain sitting at `tip` with nothing in it.
    pub fn new(tip: u32) -> Self {
        Self {
            tip: RefCell::new(tip),
            hash_override: RefCell::new(None),
            utxos: RefCell::new(Vec::new()),
            coinbase_heights: RefCell::new(Vec::new()),
            identities: RefCell::new(Vec::new()),
            policy: RefCell::new(None),
            confirmations: RefCell::new(Vec::new()),
            heights: RefCell::new(Vec::new()),
            requests: RefCell::new(0),
            broadcasts: RefCell::new(Vec::new()),
            broadcast_failure: RefCell::new(None),
            estimate: RefCell::new(None),
            deltas: RefCell::new(Vec::new()),
            raw_transactions: RefCell::new(std::collections::HashMap::new()),
        }
    }

    /// An unspent output at `address`, mined at `height`, with the script
    /// given verbatim.
    ///
    /// The escape hatch the two helpers below are written in terms of: some
    /// shapes only exist on chain — a proof-of-stake coinbase's stakeguard
    /// output, a reserve output held by a VerusID — and a scripted node is
    /// worth much less if it can only produce the shapes this crate emits.
    pub fn with_script_utxo(
        self,
        address: &str,
        height: u32,
        satoshis: u64,
        script_pubkey: Vec<u8>,
    ) -> Self {
        let index = u32::try_from(self.utxos.borrow().len()).expect("few utxos");
        let mut txid = [0u8; 32];
        // Deliberately wrapping: these bytes are an identifier, not a value.
        // Byte 1 carries the height so `is_coinbase` can be answered without a
        // second table — see `raw_transaction`.
        txid[0] = (index + 1).to_le_bytes()[0];
        txid[1] = height.to_le_bytes()[0];
        self.utxos.borrow_mut().push(AddressUtxo {
            utxo: Utxo {
                txid: Txid::from_internal(txid),
                vout: index,
                satoshis: Amount::from_sat(satoshis),
                script_pubkey,
            },
            address: address.to_string(),
            height,
            is_spendable: true,
        });
        self
    }

    /// An unspent output at `address`, mined at `height`.
    pub fn with_utxo(self, address: &str, height: u32, satoshis: u64) -> Self {
        // P2PKH, so the builders accept it as funding.
        let script = p2pkh_script(address);
        self.with_script_utxo(address, height, satoshis, script)
    }

    /// A CryptoCondition reserve output — a token, not spendable as native
    /// funding.
    pub fn with_reserve_utxo(self, address: &str, height: u32) -> Self {
        let script = verus_tx::cc::reserve_output_script(
            [0x11; 20],
            verus_tx::CurrencyId::from_bytes([0x22; 20]),
            1_000_000,
        )
        .expect("reserve script");
        self.with_script_utxo(address, height, 0, script)
    }

    /// Mark outputs at `height` as coming from a coinbase.
    pub fn with_coinbase_at(self, height: u32) -> Self {
        self.coinbase_heights.borrow_mut().push(height);
        self
    }

    /// The heights successive `block_count` calls return, in order.
    ///
    /// The last one repeats once the list runs out, so "the tip stopped moving"
    /// is expressible without an infinite list.
    pub fn with_heights(self, heights: &[u32]) -> Self {
        *self.heights.borrow_mut() = heights.iter().rev().copied().collect();
        self
    }

    /// Force every block hash to this value, staging a rewritten chain.
    pub fn with_best_hash(self, hash: &str) -> Self {
        *self.hash_override.borrow_mut() = Some(hash.to_string());
        self
    }

    /// How many confirmations a given transaction has. Absent means the node has
    /// never seen it.
    pub fn with_confirmations(self, txid: &str, confirmations: u32) -> Self {
        self.confirmations
            .borrow_mut()
            .push((txid.to_string(), confirmations));
        self
    }

    /// The registration policy `currency` returns.
    pub fn with_policy(self, policy: CurrencyPolicy) -> Self {
        *self.policy.borrow_mut() = Some(policy);
        self
    }

    /// Serve a full raw-transaction JSON for `txid`, as `getrawtransaction`
    /// verbosity 1 would. Flows that decode real outputs — a currency launch
    /// spending its identity's output — script the holding transaction here.
    pub fn with_raw_transaction(self, txid: &str, json: serde_json::Value) -> Self {
        self.raw_transactions
            .borrow_mut()
            .insert(txid.to_string(), json);
        self
    }

    /// Serve `record` for `getidentity` lookups of `name`.
    pub fn with_identity(self, name: &str, record: IdentityRecord) -> Self {
        self.identities
            .borrow_mut()
            .push((name.to_string(), record));
        self
    }

    /// Movements `address_deltas` will report.
    ///
    /// Handed over verbatim and in the order given, because the cases worth
    /// scripting here are the ones a live index will not produce on demand: a
    /// token leg with no native value, a spend and its change in one
    /// transaction, rows arriving out of chain order.
    pub fn with_deltas(self, deltas: Vec<AddressDelta>) -> Self {
        *self.deltas.borrow_mut() = deltas;
        self
    }

    /// What `estimate_conversion` answers.
    pub fn with_estimate(self, estimate: verus_rpc::ConversionEstimate) -> Self {
        *self.estimate.borrow_mut() = Some(estimate);
        self
    }

    /// Make every broadcast fail this way.
    pub fn failing_broadcast(self, error: RpcError) -> Self {
        *self.broadcast_failure.borrow_mut() = Some(error);
        self
    }

    /// Move the tip, as a block arriving would.
    pub fn advance_to(&self, height: u32) {
        *self.tip.borrow_mut() = height;
    }

    /// Rewrite history without changing the height — a reorg.
    pub fn reorg_to(&self, hash: &str) {
        *self.hash_override.borrow_mut() = Some(hash.to_string());
    }

    /// Drop every unspent output, as a competing spend would.
    pub fn spend_everything(&self) {
        self.utxos.borrow_mut().clear();
    }

    /// How many requests have been made. Guards against a flow that polls
    /// harder than it looks.
    pub fn requests(&self) -> usize {
        *self.requests.borrow()
    }

    /// Every transaction handed to `send_raw_transaction`, in order.
    pub fn broadcasts(&self) -> Vec<String> {
        self.broadcasts.borrow().clone()
    }

    fn count(&self) {
        *self.requests.borrow_mut() += 1;
    }

    /// The hash at a height.
    ///
    /// Derived from the height, so `best_block_hash()` and `block_hash(tip)`
    /// agree the way they do on a real node — a double where they disagree makes
    /// every reorg check fire spuriously. An override set by
    /// [`ScriptedReader::reorg_to`] replaces it, which is how a reorg is staged.
    fn block_hash_at(&self, height: u32) -> String {
        if let Some(hash) = self.hash_override.borrow().as_ref() {
            return hash.clone();
        }
        format!("{height:064x}")
    }
}

/// `OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG`, with the hash
/// derived from the address text so different addresses differ.
fn p2pkh_script(address: &str) -> Vec<u8> {
    let mut script = vec![0x76, 0xa9, 0x14];
    let bytes = address.as_bytes();
    for i in 0..20 {
        script.push(bytes.get(i % bytes.len()).copied().unwrap_or(0));
    }
    script.extend_from_slice(&[0x88, 0xac]);
    script
}

impl ChainReader for ScriptedReader {
    fn chain_info(&self) -> Result<ChainInfo, RpcError> {
        self.count();
        Ok(ChainInfo {
            name: "VRSCTEST".into(),
            chain_id: "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq".into(),
            blocks: *self.tip.borrow(),
            longest_chain: *self.tip.borrow(),
            version: "1.2.17".into(),
        })
    }

    fn block_count(&self) -> Result<u32, RpcError> {
        self.count();
        if let Some(height) = self.heights.borrow_mut().pop() {
            *self.tip.borrow_mut() = height;
        }
        Ok(*self.tip.borrow())
    }

    fn best_block_hash(&self) -> Result<String, RpcError> {
        self.count();
        Ok(self.block_hash_at(*self.tip.borrow()))
    }

    fn block_hash(&self, height: u32) -> Result<String, RpcError> {
        self.count();
        Ok(self.block_hash_at(height))
    }

    fn block(&self, _height_or_hash: &str) -> Result<serde_json::Value, RpcError> {
        self.count();
        Ok(json!({ "tx": [], "finalsaplingroot": "00".repeat(32) }))
    }

    fn address_utxos(&self, addresses: &[&str]) -> Result<Vec<AddressUtxo>, RpcError> {
        self.count();
        Ok(self
            .utxos
            .borrow()
            .iter()
            .filter(|utxo| addresses.contains(&utxo.address.as_str()))
            .cloned()
            .collect())
    }

    fn address_deltas(
        &self,
        addresses: &[&str],
        range: Option<(u32, u32)>,
    ) -> Result<Vec<AddressDelta>, RpcError> {
        self.count();
        Ok(self
            .deltas
            .borrow()
            .iter()
            .filter(|delta| addresses.contains(&delta.address.as_str()))
            .filter(|delta| match range {
                Some((start, end)) => delta.height >= start && delta.height <= end,
                None => true,
            })
            .cloned()
            .collect())
    }

    fn address_balance(&self, addresses: &[&str]) -> Result<AddressBalance, RpcError> {
        self.count();
        let total = self
            .utxos
            .borrow()
            .iter()
            .filter(|utxo| addresses.contains(&utxo.address.as_str()))
            .map(|utxo| utxo.utxo.satoshis.to_sat())
            .sum();
        Ok(AddressBalance {
            balance: Amount::from_sat(total),
            received: Amount::from_sat(total),
            currency_balance: Default::default(),
        })
    }

    fn currency(&self, name_or_id: &str) -> Result<CurrencyPolicy, RpcError> {
        self.count();
        self.policy.borrow().clone().ok_or(RpcError::Node {
            code: -5,
            message: format!("currency {name_or_id} not found"),
        })
    }

    fn estimate_conversion(
        &self,
        _from: &str,
        _to: &str,
        _amount: &str,
        _via: Option<&str>,
    ) -> Result<verus_rpc::ConversionEstimate, RpcError> {
        self.count();
        Ok(self
            .estimate
            .borrow()
            .clone()
            .unwrap_or(verus_rpc::ConversionEstimate {
                estimated_out: Amount::ZERO,
                fee: None,
            }))
    }

    fn currency_state(&self, _name_or_id: &str) -> Result<serde_json::Value, RpcError> {
        self.count();
        Ok(json!({}))
    }

    fn identity(&self, name_or_id: &str) -> Result<IdentityRecord, RpcError> {
        self.count();
        self.identities
            .borrow()
            .iter()
            .find(|(name, _)| name == name_or_id)
            .map(|(_, record)| record.clone())
            .ok_or(RpcError::Node {
                code: -5,
                message: "Identity not found".into(),
            })
    }

    fn vdxf_id(&self, _name: &str) -> Result<[u8; 20], RpcError> {
        self.count();
        Err(RpcError::Unexpected(
            "the scripted chain does not derive VDXF keys".into(),
        ))
    }

    fn verify_message(
        &self,
        _identity: &str,
        _signature: &str,
        _message: &str,
    ) -> Result<bool, RpcError> {
        self.count();
        // A scripted node has no opinion. Tests verify locally, which is the
        // path a wallet should use anyway.
        Err(RpcError::Unexpected(
            "the scripted chain does not verify signatures".into(),
        ))
    }

    fn identity_registration(&self, name_or_id: &str) -> Result<String, RpcError> {
        self.count();
        // The scripted chain has no history, so an identity's registration is
        // the outpoint it was scripted with. A test that needs a referrer with
        // its own upstream chain scripts the registration transaction through
        // `with_raw_transaction`.
        self.identity(name_or_id)
            .map(|record| record.outpoint.0.to_display_hex())
    }

    fn identity_at(&self, name_or_id: &str, _height: u32) -> Result<IdentityRecord, RpcError> {
        // The scripted chain has no history, so an identity is the same at
        // every height. Tests that care about rotation script it explicitly.
        self.identity(name_or_id)
    }

    fn raw_transaction(&self, txid: &str) -> Result<serde_json::Value, RpcError> {
        self.count();
        if let Some(json) = self.raw_transactions.borrow().get(txid) {
            return Ok(json.clone());
        }
        // The height encoded into a scripted txid, so `is_coinbase` can be
        // answered without a separate table. Display hex is byte-reversed, so
        // the byte written at index 1 arrives at the far end.
        let height = u32::from(
            hex::decode(txid)
                .ok()
                .and_then(|bytes| {
                    let mut internal = bytes;
                    internal.reverse();
                    internal.get(1).copied()
                })
                .unwrap_or(0),
        );
        let coinbase = self
            .coinbase_heights
            .borrow()
            .iter()
            .any(|h| *h % 256 == height);
        let vin = if coinbase {
            json!([{ "coinbase": "03" }])
        } else {
            json!([{ "txid": "00".repeat(32), "vout": 0 }])
        };
        let confirmations = self
            .confirmations
            .borrow()
            .iter()
            .find(|(id, _)| id == txid)
            .map(|(_, n)| *n);
        // Outputs, for a transaction this node was actually given.
        let vout: Vec<_> = self
            .broadcasts
            .borrow()
            .iter()
            .find(|hex| txid_of(hex) == txid)
            .map(|hex| decode_outputs(hex))
            .unwrap_or_default()
            .into_iter()
            // A daemon reports `value` in COINS and `valueSat` in satoshis.
            // Emitting satoshis under `value` would let a reader that confuses
            // the two pass here and misread real chain data by 10^8.
            .map(|(value, script)| {
                json!({
                    "value": verus_tx::Amount::from_sat(value).to_coins_string(),
                    "valueSat": value,
                    "scriptPubKey": { "hex": script },
                })
            })
            .collect();

        match confirmations {
            Some(n) => Ok(json!({ "vin": vin, "vout": vout, "confirmations": n })),
            None if !self.confirmations.borrow().is_empty() => Err(RpcError::Node {
                code: -5,
                message: "No information available about transaction".into(),
            }),
            None => Ok(json!({ "vin": vin, "vout": vout, "confirmations": 1 })),
        }
    }

    fn decode_raw_transaction(&self, _hex: &str) -> Result<serde_json::Value, RpcError> {
        self.count();
        Ok(json!({}))
    }

    fn confirmations(&self, txid: &str) -> Result<Option<u32>, RpcError> {
        match self.raw_transaction(txid) {
            Ok(tx) => Ok(Some(
                tx.get("confirmations")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|n| u32::try_from(n).ok())
                    .unwrap_or(0),
            )),
            Err(RpcError::Node { code: -5, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// The outputs of a serialized v4 transaction, as `getrawtransaction` prints
/// them.
///
/// A real node decodes what it was given; a double that returned no outputs
/// would make every flow that inspects one pass vacuously. The layout is fixed:
///
/// ```text
/// header(4) versionGroupId(4) varint(vin) [ txid(32) vout(4) varslice(script) sequence(4) ]…
/// varint(vout) [ value(8) varslice(script) ]…
/// ```
fn decode_outputs(hex: &str) -> Vec<(u64, String)> {
    let bytes = match hex::decode(hex) {
        Ok(bytes) => bytes,
        Err(_) => return Vec::new(),
    };
    let mut at = 8; // header + versionGroupId

    let varint = |at: &mut usize| -> u64 {
        let first = *bytes.get(*at).unwrap_or(&0);
        *at += 1;
        match first {
            0xfd => {
                let n = u64::from(u16::from_le_bytes([bytes[*at], bytes[*at + 1]]));
                *at += 2;
                n
            }
            0xfe => {
                let n = u64::from(u32::from_le_bytes(
                    bytes[*at..*at + 4].try_into().unwrap_or([0; 4]),
                ));
                *at += 4;
                n
            }
            0xff => {
                let n = u64::from_le_bytes(bytes[*at..*at + 8].try_into().unwrap_or([0; 8]));
                *at += 8;
                n
            }
            n => u64::from(n),
        }
    };

    let inputs = varint(&mut at);
    for _ in 0..inputs {
        at += 36; // outpoint
        let Ok(script) = usize::try_from(varint(&mut at)) else {
            return Vec::new();
        };
        at += script + 4; // scriptSig + sequence
        if at > bytes.len() {
            return Vec::new();
        }
    }

    let count = varint(&mut at);
    let mut outputs = Vec::new();
    for _ in 0..count {
        if at + 8 > bytes.len() {
            break;
        }
        let value = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or([0; 8]));
        at += 8;
        let Ok(length) = usize::try_from(varint(&mut at)) else {
            break;
        };
        if at + length > bytes.len() {
            break;
        }
        let script = bytes[at..at + length]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        at += length;
        outputs.push((value, script));
    }
    outputs
}

/// The transaction id of some raw bytes: SHA256d, printed in reverse.
///
/// Computed rather than canned, so this behaves like a node — which matters
/// because [`verus_flows::broadcast`] checks the id a node reports against the
/// one it computed locally, and a double that always agrees would never exercise
/// that check.
fn txid_of(hex: &str) -> String {
    use sha2::{Digest, Sha256};
    let bytes = hex::decode(hex).unwrap_or_default();
    let digest = Sha256::digest(Sha256::digest(&bytes));
    digest.iter().rev().map(|b| format!("{b:02x}")).collect()
}

impl Broadcaster for ScriptedReader {
    fn send_raw_transaction(&self, hex: &str) -> Result<String, RpcError> {
        self.count();
        if let Some(error) = self.broadcast_failure.borrow().as_ref() {
            return Err(match error {
                RpcError::Transport(m) => RpcError::Transport(m.clone()),
                RpcError::Node { code, message } => RpcError::Node {
                    code: *code,
                    message: message.clone(),
                },
                other => RpcError::Unexpected(other.to_string()),
            });
        }
        self.broadcasts.borrow_mut().push(hex.to_string());
        Ok(txid_of(hex))
    }
}
