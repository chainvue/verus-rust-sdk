//! The one input type every builder takes.

use crate::amount::Amount;
use crate::txid::Txid;

/// An unspent output available to spend.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Utxo {
    /// Transaction that created it.
    pub txid: Txid,
    /// Index of the output within that transaction.
    pub vout: u32,
    /// What it is worth.
    pub satoshis: Amount,
    /// The scriptPubKey it pays to. Must be P2PKH for now.
    pub script_pubkey: Vec<u8>,
}
