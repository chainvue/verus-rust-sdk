//! Paying someone.
//!
//! The whole operation, from "which coins do I have" to "here is the txid":
//! look up spendable outputs, build, sign locally, hand the finished bytes to a
//! node. The key never leaves this process.

use verus_keys::{Address, PrivateKey};
use verus_rpc::{Broadcaster, ChainReader};
use verus_tx::{
    build_token_send, build_transparent_send, Amount, CurrencyId, Expiry, Recipient, SendParams,
    SignedTransaction, TokenRecipient, TokenSendParams, DEFAULT_EXPIRY_BLOCKS,
};

use crate::broadcast::broadcast;
use crate::error::FlowError;
use crate::funding;

/// A completed operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sent {
    /// The transaction id the node accepted.
    pub txid: String,
    /// Fee paid.
    pub fee: Amount,
    /// Change returned, zero if it would have been dust.
    pub change: Amount,
    /// The raw bytes, kept so a caller can re-broadcast or archive them.
    pub hex: String,
}

impl From<SignedTransaction> for Sent {
    fn from(signed: SignedTransaction) -> Self {
        Sent {
            txid: signed.txid,
            fee: signed.fee,
            change: signed.change,
            hex: signed.hex,
        }
    }
}

/// Pay native coins to one address.
///
/// Change returns to the funding key's own address. Expiry is set
/// [`DEFAULT_EXPIRY_BLOCKS`] past the tip rather than left at "never" — a
/// payment that does not confirm should die rather than linger and land months
/// later against coins the user has since spent elsewhere.
///
/// # Errors
///
/// [`FlowError::InsufficientFunds`] counts only what is spendable *now*, so it
/// can fire while a balance lookup shows more; an immature coinbase is the usual
/// reason, and [`funding::Funding::immature`] says how much.
///
/// [`FlowError::BroadcastUncertain`] means the transaction was signed and the
/// send failed ambiguously. **Do not simply retry** — read the module docs on
/// [`crate::broadcast`](mod@crate::broadcast).
pub fn send(
    reader: &impl ChainReader,
    broadcaster: &impl Broadcaster,
    key: &PrivateKey,
    to: &str,
    amount: Amount,
) -> Result<Sent, FlowError> {
    let to: Address = to.parse()?;
    let from = key.address();
    let funding = funding::spendable(reader, &from.to_string())?;

    // The fee is not known until selection, so this only catches the case where
    // the amount alone is out of reach. The builder still refuses if the fee
    // tips it over — this exists to give the common failure a clear message.
    funding::require(&funding, amount, &from.to_string())?;

    let recipients = [Recipient {
        address: to,
        satoshis: amount,
    }];
    let params = SendParams::new(
        &funding.utxos,
        &recipients,
        from,
        Expiry::within(funding.tip, DEFAULT_EXPIRY_BLOCKS),
    );
    let signed = build_transparent_send(key, &params)?;

    broadcast(broadcaster, &signed.hex, &signed.txid)?;
    Ok(signed.into())
}

/// Pay a token to one address.
///
/// The token moves as a reserve output while the miner fee is still paid in
/// native coins, so the funding address needs both — and the builder is given
/// one combined list, because a single transaction spends from both.
///
/// `token_utxos` are the outputs holding the token. They are **not** discovered
/// here: `getaddressutxos` reports a reserve output's native value, not what
/// token it carries or how much, so recognising them means decoding each script.
/// A wallet that tracks its own token outputs already knows them; asking for
/// them explicitly is honest about that, rather than pretending to a lookup this
/// crate cannot do.
///
/// `currency` is the token's currency id — for a tokenised identity, the
/// identity's own `i` address, via [`CurrencyId::of_identity`].
pub fn send_token(
    reader: &impl ChainReader,
    broadcaster: &impl Broadcaster,
    key: &PrivateKey,
    currency: CurrencyId,
    to: &str,
    amount: Amount,
    token_utxos: &[verus_tx::Utxo],
) -> Result<Sent, FlowError> {
    let to: Address = to.parse()?;
    let from = key.address();
    let funding = funding::spendable(reader, &from.to_string())?;

    // One list: the transaction spends the token outputs and the native ones
    // together, and the builder sorts out which is which.
    let mut utxos = token_utxos.to_vec();
    utxos.extend(funding.utxos.iter().cloned());

    let recipients = [TokenRecipient {
        address: to,
        currency,
        amount,
    }];
    let params = TokenSendParams::new(
        &utxos,
        &recipients,
        from,
        Expiry::within(funding.tip, DEFAULT_EXPIRY_BLOCKS),
    );
    let signed = build_token_send(key, &params)?;

    broadcast(broadcaster, &signed.hex, &signed.txid)?;
    Ok(signed.into())
}

/// Build a payment without sending it.
///
/// Takes a [`ChainReader`] and no [`Broadcaster`], so it *cannot* broadcast —
/// the dry run is enforced by the signature rather than by remembering not to
/// call the other function.
pub fn prepare_send(
    reader: &impl ChainReader,
    key: &PrivateKey,
    to: &str,
    amount: Amount,
) -> Result<SignedTransaction, FlowError> {
    let to: Address = to.parse()?;
    let from = key.address();
    let funding = funding::spendable(reader, &from.to_string())?;
    funding::require(&funding, amount, &from.to_string())?;

    let recipients = [Recipient {
        address: to,
        satoshis: amount,
    }];
    let params = SendParams::new(
        &funding.utxos,
        &recipients,
        from,
        Expiry::within(funding.tip, DEFAULT_EXPIRY_BLOCKS),
    );
    Ok(build_transparent_send(key, &params)?)
}
