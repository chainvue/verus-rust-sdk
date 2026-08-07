//! Paying someone.
//!
//! The whole operation, from "which coins do I have" to "here is the txid":
//! look up spendable outputs, build, sign locally, hand the finished bytes to a
//! node. The key never leaves this process.

use verus_keys::{Address, PrivateKey};
use verus_rpc::{Broadcaster, ChainReader};
use verus_tx::{
    build_token_send, build_transparent_send, plan_transparent_send, Amount, CurrencyId, Expiry,
    InputKind, PartialTransaction, Recipient, SendParams, SignedTransaction, Timelock,
    TokenRecipient, TokenSendParams, DEFAULT_EXPIRY_BLOCKS, FLAG_LOCKED,
};

use crate::broadcast::Unsent;
use crate::error::FlowError;
use crate::funding;

/// A payment, built and signed.
///
/// Returned by [`send`] once a node has accepted it, and inside an
/// [`Unsent`] before it has been offered to one — so `txid` is the id computed
/// from `hex` rather than one a node reported. [`broadcast`](fn@crate::broadcast)
/// refuses a node that names a different transaction, which is what keeps the
/// two the same value.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Sent {
    /// The transaction id, computed locally from `hex`.
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

/// Finished bytes, still unsent. Every `prepare_…` in this module ends here, so
/// the two halves cannot disagree about what `hex` and `txid` are.
impl From<SignedTransaction> for Unsent<Sent> {
    fn from(signed: SignedTransaction) -> Self {
        Unsent {
            hex: signed.hex.clone(),
            txid: signed.txid.clone(),
            outcome: signed.into(),
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
    prepare_send(reader, key, to, amount)?.broadcast(broadcaster)
}

/// Build a payment without sending it.
///
/// Takes a [`ChainReader`] and no [`Broadcaster`], so it *cannot* broadcast —
/// the dry run is enforced by the signature rather than by remembering not to
/// call the other function. That is also what makes it safe to run under
/// [`drive`](mod@crate::drive), which re-runs an operation once per round.
pub fn prepare_send(
    reader: &impl ChainReader,
    key: &PrivateKey,
    to: &str,
    amount: Amount,
) -> Result<Unsent<Sent>, FlowError> {
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
    Ok(build_transparent_send(key, &params)?.into())
}

/// Build a payment for someone **else** to sign.
///
/// Takes an address rather than a key, so it can run on a machine that holds no
/// key at all — a watch-only wallet, or the online half of an air-gapped pair.
/// The result is a [`PartialTransaction`], which serializes with
/// [`PartialTransaction::to_bytes`] and can be carried to the signer over any
/// channel, including one that is read off a screen.
///
/// The coins, the fee, the change and the output order come from
/// [`plan_transparent_send`], the same function [`prepare_send`] goes through.
/// Signing the result and finalizing it produces the identical transaction —
/// `tests/airgap_send.rs` asserts the two hex strings are equal byte for byte,
/// because "almost the same transaction" is a different transaction.
///
/// # What the signer still has to check
///
/// Everything. Whoever built this chose the outputs, and a signature is the one
/// irreversible step — see [`PartialTransaction::summary`] and the module docs
/// on [`verus_tx::partial`](mod@verus_tx::partial). This function's caller is
/// not necessarily trusted by its signer; that is the whole point of splitting
/// them.
///
/// # Errors
///
/// [`FlowError::InsufficientFunds`] counts only what is spendable *now*, the
/// same as [`prepare_send`]. Nothing here can fail because of a missing key,
/// because no key is involved.
pub fn prepare_unsigned_send(
    reader: &impl ChainReader,
    from: &Address,
    to: &str,
    amount: Amount,
) -> Result<PartialTransaction, FlowError> {
    let to: Address = to.parse()?;
    let funding = funding::spendable(reader, &from.to_string())?;
    funding::require(&funding, amount, &from.to_string())?;

    let recipients = [Recipient {
        address: to,
        satoshis: amount,
    }];
    let params = SendParams::new(
        &funding.utxos,
        &recipients,
        *from,
        Expiry::within(funding.tip, DEFAULT_EXPIRY_BLOCKS),
    );
    let plan = plan_transparent_send(&params)?;

    // Every input is P2PKH: `plan_transparent_send` refuses any funding UTXO
    // that is not, so this is a fact rather than an assumption.
    let kinds = vec![InputKind::PubKeyHash; plan.selected.len()];
    Ok(PartialTransaction::start(
        &plan.selected,
        &kinds,
        plan.outputs,
        plan.expiry,
        plan.lock_time,
    )?)
}

/// Pay from funds a VerusID holds.
///
/// The identity’s pay-to-identity outputs fund the payment; `keys` are its
/// current primary addresses, enough to meet its `minsigs`, and the surplus
/// returns to the identity. This is the everyday shape of money on Verus —
/// funds live under an identity, not under a bare key — and it is a different
/// signature from a P2PKH spend: each input carries a fulfillment, the same
/// construction an identity update uses.
///
/// The primary addresses are read from the chain and checked against `keys`
/// before signing, because signing with a stale key builds cleanly and then
/// fails script verification with a message that names nothing.
///
/// The check is point-in-time: an identity whose keys rotate or which is
/// revoked between this read and the broadcast produces a rejected
/// transaction, not a loss — the same window every offline builder has.
pub fn send_from_identity(
    reader: &impl ChainReader,
    broadcaster: &impl Broadcaster,
    keys: &[&PrivateKey],
    identity: &str,
    to: &str,
    amount: Amount,
) -> Result<Sent, FlowError> {
    prepare_send_from_identity(reader, keys, identity, to, amount)?.broadcast(broadcaster)
}

/// The timelock as `getidentity` renders it, read the way [`Timelock::of`]
/// reads the decoded object: the flag and the height together.
///
/// The flag must be masked, not merely compared against zero — `flags` also
/// carries `FLAG_ACTIVE_CURRENCY` and `FLAG_TOKENIZED_CONTROL`. `VRSCTEST@`
/// itself reports `flags = 1`, which is an active currency and not a lock.
///
/// A node that omits either field is read as unlocked, which is the direction
/// that lets the spend proceed to consensus rather than refusing on a missing
/// key. The node is not trusted to be right here, only to be answering about
/// the identity that was asked for — the same standing every other check in
/// [`prepare_send_from_identity`] gives it.
fn timelock_of(identity: &serde_json::Value) -> Timelock {
    let flags = u32::try_from(identity["flags"].as_u64().unwrap_or(0)).unwrap_or(u32::MAX);
    let unlock_after =
        u32::try_from(identity["timelock"].as_u64().unwrap_or(0)).unwrap_or(u32::MAX);
    if flags & FLAG_LOCKED != 0 {
        Timelock::DelayAfterUnlock(unlock_after)
    } else if unlock_after != 0 {
        Timelock::UntilBlock(unlock_after)
    } else {
        Timelock::None
    }
}

/// Build an identity-funded payment without sending it.
///
/// The read-only half of [`send_from_identity`]; every check that function
/// makes is made here, because all of them are reads.
///
/// # Timelocks
///
/// An identity whose funds are still held by a timelock is refused here with
/// [`TxError::FundsTimelocked`](verus_tx::TxError::FundsTimelocked), naming the
/// height they open at. Consensus refuses the same spend with
/// `mandatory-script-verify-flag-failed`, which names neither the identity nor
/// the lock nor the height — and a caller with no way to tell that from a wrong
/// key or a stale identity guesses, usually at their node.
pub fn prepare_send_from_identity(
    reader: &impl ChainReader,
    keys: &[&PrivateKey],
    identity: &str,
    to: &str,
    amount: Amount,
) -> Result<Unsent<Sent>, FlowError> {
    let to: Address = to.parse()?;
    let record = crate::error::look_up_identity(reader, identity)?
        .ok_or_else(|| FlowError::NoSuchIdentity(identity.to_string()))?;

    // Refuse everything the chain would refuse later with a message that
    // names nothing: a revoked identity cannot spend, a key the identity does
    // not list cannot sign, and fewer keys than `minimumsignatures` cannot
    // meet the condition. The raw identity object carries all three facts.
    if record.is_revoked() {
        return Err(FlowError::Tx(verus_tx::TxError::AlreadyRevoked));
    }
    let primaries: Vec<String> = record.identity["primaryaddresses"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    for key in keys {
        let address = key.address().to_string();
        if !primaries.contains(&address) {
            return Err(FlowError::Tx(verus_tx::TxError::NotAPrimaryAddress {
                address,
            }));
        }
    }
    // Counted by DISTINCT address: the same key twice satisfies nothing, and
    // would otherwise sail through to the nameless on-chain failure this whole
    // precheck exists to prevent.
    let mut distinct: Vec<String> = keys.iter().map(|k| k.address().to_string()).collect();
    distinct.sort();
    distinct.dedup();
    let min_sigs = record.identity["minimumsignatures"].as_u64().unwrap_or(1);
    if (distinct.len() as u64) < min_sigs {
        return Err(FlowError::Tx(verus_tx::TxError::NotEnoughSigners {
            supplied: distinct.len(),
            required: u32::try_from(min_sigs).unwrap_or(u32::MAX),
        }));
    }

    let identity_address: Address = record
        .identity_address
        .parse()
        .map_err(|e| FlowError::NoSuchIdentity(format!("{identity}: {e}")))?;
    // Issued together, unwrapped after — see [`crate::drive`]. `identity_held`
    // asks for the tip itself, so under a driver the second read is a cache hit
    // and costs no round; on a blocking client it is a second real request.
    let utxos = funding::identity_held(reader, &record.identity_address);
    let tip = reader.block_count();
    let (utxos, tip) = (utxos?, tip?);

    // A timelock holds the funds, not just the identity object. Consensus
    // refuses the spend on a path the lifecycle flows' `check_timelock` never
    // sees — that one guards changes *to* the lock — and refuses it with the
    // same `mandatory-script-verify-flag-failed` that names nothing.
    //
    // Read from the node's rendering, like the revoked and primary-address
    // checks above, and free: the tip was already needed for the expiry.
    let timelock = timelock_of(&record.identity);
    if !timelock.spendable_at(tip) {
        return Err(FlowError::Tx(verus_tx::TxError::FundsTimelocked {
            unlock_at: match timelock {
                Timelock::UntilBlock(height) => Some(height),
                _ => None,
            },
        }));
    }

    let recipients = [Recipient {
        address: to,
        satoshis: amount,
    }];
    let params = verus_tx::IdentitySpendParams::new(
        identity_address.hash(),
        &utxos,
        &recipients,
        Expiry::within(tip, DEFAULT_EXPIRY_BLOCKS),
    );
    Ok(verus_tx::build_identity_spend(keys, &params)?.into())
}

/// Move a token a VerusID holds, to any address.
///
/// The gap this closes: a token's supply is the sum of its `preallocations`,
/// and a preallocation names an **identity**. So for a currency that cannot be
/// minted, every unit that will ever exist is created at launch into an
/// identity-held output and never passes through a key-held address — and
/// nothing could move it. `aaa@` on VRSCTEST has 1,000,000,000 units sitting
/// in one such output.
///
/// # Unlike [`prepare_send_token`], the outputs ARE discovered here
///
/// That function asks the caller for `token_utxos`, and says why: recognising
/// a reserve output means decoding each script, and a wallet tracking its own
/// tokens already knows them. Neither applies to an identity's holdings. The
/// caller may not control the identity's outputs at all — they hold its keys —
/// and there is a definite question to ask, "what does this identity hold of
/// this currency", which [`funding::identity_held_tokens`] answers.
///
/// # Two kinds of input, and why
///
/// A reserve output carries **no native value**, so this spend cannot pay its
/// own miner fee the way a native identity spend does. `key` supplies ordinary
/// coins for that and signs them; `keys` are the identity's primary keys and
/// sign the token inputs by fulfillment. Native change goes back to `key`,
/// because it is the fee payer's own money; token change returns to the
/// identity.
// Eight, and each names a distinct thing the transaction cannot be built
// without: who authorises (`keys`), who pays the fee (`fee_key` — a separate
// party, because a token output carries no native value and the identity's
// primary key need not hold coins), which identity, which currency, to whom,
// and how much. Bundling them into a struct would move the arity rather than
// reduce it.
#[allow(clippy::too_many_arguments)]
pub fn send_token_from_identity(
    reader: &impl ChainReader,
    broadcaster: &impl Broadcaster,
    keys: &[&PrivateKey],
    fee_key: &PrivateKey,
    identity: &str,
    currency: CurrencyId,
    to: &str,
    amount: Amount,
) -> Result<Sent, FlowError> {
    prepare_send_token_from_identity(reader, keys, fee_key, identity, currency, to, amount)?
        .broadcast(broadcaster)
}

/// Build the move without sending it.
///
/// The read-only half of [`send_token_from_identity`], including every check
/// the chain would otherwise refuse late and namelessly.
pub fn prepare_send_token_from_identity(
    reader: &impl ChainReader,
    keys: &[&PrivateKey],
    fee_key: &PrivateKey,
    identity: &str,
    currency: CurrencyId,
    to: &str,
    amount: Amount,
) -> Result<Unsent<Sent>, FlowError> {
    if keys.is_empty() {
        return Err(FlowError::Tx(verus_tx::TxError::NoSignatures));
    }
    let to: Address = to.parse()?;
    let record = crate::error::look_up_identity(reader, identity)?
        .ok_or_else(|| FlowError::NoSuchIdentity(identity.to_string()))?;

    // The same prechecks the native identity spend makes, and for the same
    // reason: consensus refuses each of these with a message that names
    // nothing.
    if record.is_revoked() {
        return Err(FlowError::Tx(verus_tx::TxError::AlreadyRevoked));
    }
    let primaries: Vec<String> = record.identity["primaryaddresses"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    for key in keys {
        let address = key.address().to_string();
        if !primaries.contains(&address) {
            return Err(FlowError::Tx(verus_tx::TxError::NotAPrimaryAddress {
                address,
            }));
        }
    }
    let mut distinct: Vec<String> = keys.iter().map(|k| k.address().to_string()).collect();
    distinct.sort();
    distinct.dedup();
    let min_sigs = record.identity["minimumsignatures"].as_u64().unwrap_or(1);
    if (distinct.len() as u64) < min_sigs {
        return Err(FlowError::Tx(verus_tx::TxError::NotEnoughSigners {
            supplied: distinct.len(),
            required: u32::try_from(min_sigs).unwrap_or(u32::MAX),
        }));
    }

    let identity_address: Address = record
        .identity_address
        .parse()
        .map_err(|e| FlowError::NoSuchIdentity(format!("{identity}: {e}")))?;

    let token_utxos =
        crate::funding::identity_held_tokens(reader, &record.identity_address, currency)?;
    let fee_from = fee_key.address();
    let fee_funding = crate::funding::spendable(reader, &fee_from.to_string())?;

    // A timelock holds the identity's funds whatever kind they are — the token
    // outputs are spent under the same condition the native ones are. Checked
    // here for the same reason it is checked on the native path: consensus
    // refuses with `mandatory-script-verify-flag-failed`, which names neither
    // the identity nor the lock nor the height.
    let timelock = timelock_of(&record.identity);
    if !timelock.spendable_at(fee_funding.tip) {
        return Err(FlowError::Tx(verus_tx::TxError::FundsTimelocked {
            unlock_at: match timelock {
                Timelock::UntilBlock(height) => Some(height),
                _ => None,
            },
        }));
    }

    if token_utxos.is_empty() {
        return Err(FlowError::NotReady(format!(
            "{identity} holds no outputs of that currency"
        )));
    }
    if fee_funding.utxos.is_empty() {
        return Err(FlowError::NotReady(format!(
            "a token output carries no native value, so the miner fee must come from \
             elsewhere — {fee_from} has nothing spendable"
        )));
    }

    let params = verus_tx::IdentityTokenSpendParams::new(
        identity_address.hash(),
        currency,
        &token_utxos,
        &fee_funding.utxos,
        to,
        amount,
        fee_from,
        Expiry::within(fee_funding.tip, DEFAULT_EXPIRY_BLOCKS),
    );
    Ok(verus_tx::build_identity_token_spend(keys, fee_key, &params)?.into())
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
    prepare_send_token(reader, key, currency, to, amount, token_utxos)?.broadcast(broadcaster)
}

/// Build a token payment without sending it.
///
/// The read-only half of [`send_token`].
pub fn prepare_send_token(
    reader: &impl ChainReader,
    key: &PrivateKey,
    currency: CurrencyId,
    to: &str,
    amount: Amount,
    token_utxos: &[verus_tx::Utxo],
) -> Result<Unsent<Sent>, FlowError> {
    let to: Address = to.parse()?;
    let from = key.address();

    // The same outpoint twice builds and signs cleanly, then dies at the daemon
    // as `bad-txns-inputs-duplicate` — an error naming nothing, after the
    // caller has been shown a transaction. Refused here instead, which is what
    // this crate does everywhere else it can.
    //
    // It is a plausible mistake rather than a contrived one: a wallet
    // concatenating two views of its own token outputs, or one that lists an
    // output `spendable` will also find.
    let mut seen: Vec<(verus_tx::Txid, u32)> = Vec::new();
    for utxo in token_utxos {
        let outpoint = (utxo.txid, utxo.vout);
        if seen.contains(&outpoint) {
            return Err(FlowError::NotReady(format!(
                "token output {}:{} is listed twice; an outpoint can only be spent once",
                utxo.txid.to_display_hex(),
                utxo.vout
            )));
        }
        seen.push(outpoint);
    }

    let funding = funding::spendable(reader, &from.to_string())?;

    // One list: the transaction spends the token outputs and the native ones
    // together, and the builder sorts out which is which.
    let mut utxos = token_utxos.to_vec();
    // And a native output the caller listed as a token output would collide
    // with the same output found by `spendable`.
    utxos.extend(
        funding
            .utxos
            .iter()
            .filter(|found| !seen.contains(&(found.txid, found.vout)))
            .cloned(),
    );

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
    Ok(build_token_send(key, &params)?.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::ScriptedReader;
    use serde_json::json;
    use verus_rpc::IdentityRecord;
    use verus_tx::Txid;

    const TIP: u32 = 1_170_800;
    const ID: [u8; 20] = [0x3f; 20];

    fn key() -> PrivateKey {
        PrivateKey::from_bytes(&[0x7c; 32], true).expect("a valid scalar")
    }

    fn i_address() -> String {
        Address::new(verus_keys::AddressKind::Identity, ID).to_string()
    }

    /// The currency `aaa@` on VRSCTEST holds all of, in the shape it holds it.
    const TOKEN: verus_tx::CurrencyId = verus_tx::CurrencyId::from_bytes([0x5c; 20]);

    /// A node where the identity holds a TOKEN — a reserve output paying it,
    /// carrying no native value — and the fee key holds ordinary coins.
    ///
    /// This is the shape a non-mintable token's whole supply is created in: a
    /// preallocation names an identity, so every unit lands here and never
    /// passes through a key-held address.
    fn reader_holding_a_token(token_amount: u64) -> ScriptedReader {
        let address = i_address();
        let reserve = verus_tx::cc::reserve_output_script_to(
            verus_tx::Destination::Identity(ID),
            TOKEN,
            token_amount,
        )
        .expect("a reserve output paying the identity");
        ScriptedReader::new(TIP)
            // Zero satoshis: that is the whole reason a fee key is needed.
            .with_script_utxo(&address, 1_170_000, 0, reserve)
            .with_utxo(&key().address().to_string(), 1_170_000, 500_000_000)
            .with_identity(
                "app@",
                IdentityRecord {
                    fully_qualified_name: "app@".into(),
                    identity_address: address.clone(),
                    status: "active".into(),
                    outpoint: (Txid::from_internal([0x22; 32]), 0),
                    block_height: 1_170_000,
                    identity: json!({
                        "identityaddress": address,
                        "primaryaddresses": [key().address().to_string()],
                        "minimumsignatures": 1,
                        "flags": 0,
                        "timelock": 0,
                    }),
                },
            )
    }

    /// **A non-mintable token's supply can be moved.**
    ///
    /// The reported bug: every unit exists only in an identity-held reserve
    /// output, and nothing could spend one. The key-signed token path refuses
    /// it by design, and the identity-funded path only ever accepted the plain
    /// pay-to-identity script.
    #[test]
    fn a_token_an_identity_holds_can_be_sent() {
        let chain = reader_holding_a_token(100_000_000_000_000_000);
        let unsent = prepare_send_token_from_identity(
            &chain,
            &[&key()],
            &key(),
            "app@",
            TOKEN,
            &key().address().to_string(),
            Amount::from_sat(100_000_000),
        )
        .expect("an identity's token is spendable");

        let tx = verus_wire::TxV4::deserialize(&hex::decode(&unsent.hex).unwrap()).unwrap();

        // Two kinds of input in one transaction: the identity's token output,
        // signed by fulfillment, and the fee key's coins, signed ordinarily.
        assert_eq!(tx.inputs.len(), 2, "the token input and the fee input");

        // The recipient's token output, and change back to the IDENTITY.
        let reserves: Vec<_> = tx
            .outputs
            .iter()
            .filter_map(|o| match verus_tx::decode_output_script(&o.script_pubkey) {
                Ok(verus_tx::OutputKind::ReserveOutput {
                    tokens,
                    destination,
                }) => Some((destination, tokens)),
                _ => None,
            })
            .collect();
        assert_eq!(reserves.len(), 2, "the payment and the token change");
        assert_eq!(
            reserves[0].0,
            verus_tx::Destination::PubKeyHash(key().address().hash())
        );
        assert_eq!(reserves[0].1, vec![(TOKEN, 100_000_000)]);
        assert_eq!(
            reserves[1].0,
            verus_tx::Destination::Identity(ID),
            "token change must return to the identity, not to a bare key"
        );
        assert_eq!(
            reserves[1].1,
            vec![(TOKEN, 100_000_000_000_000_000 - 100_000_000)]
        );
    }

    /// The fee cannot come from the token itself.
    ///
    /// A reserve output carries no satoshis, so without native coins there is
    /// nothing to pay a miner with. Saying so beats building a transaction
    /// whose fee arithmetic credits value that is not there.
    #[test]
    fn a_token_send_from_an_identity_needs_native_coins_for_the_fee() {
        let address = i_address();
        let reserve = verus_tx::cc::reserve_output_script_to(
            verus_tx::Destination::Identity(ID),
            TOKEN,
            1_000,
        )
        .unwrap();
        // The identity holds the token; the fee key holds nothing.
        let chain = ScriptedReader::new(TIP)
            .with_script_utxo(&address, 1_170_000, 0, reserve)
            .with_identity(
                "app@",
                IdentityRecord {
                    fully_qualified_name: "app@".into(),
                    identity_address: address.clone(),
                    status: "active".into(),
                    outpoint: (Txid::from_internal([0x22; 32]), 0),
                    block_height: 1_170_000,
                    identity: json!({
                        "identityaddress": address,
                        "primaryaddresses": [key().address().to_string()],
                        "minimumsignatures": 1,
                        "flags": 0,
                        "timelock": 0,
                    }),
                },
            );

        let error = prepare_send_token_from_identity(
            &chain,
            &[&key()],
            &key(),
            "app@",
            TOKEN,
            &key().address().to_string(),
            Amount::from_sat(1),
        )
        .expect_err("no native coins, no fee");
        assert!(
            error.to_string().contains("no native value"),
            "the refusal must say why: {error}"
        );
    }

    /// An output paying a **different** identity is not this identity's.
    ///
    /// `getaddressutxos` on an identity's address also reports outputs
    /// belonging to identities *under* it — the parent/child indexing this
    /// repository documents in `fixtures/daemon/identities.json`. A finder that
    /// checked only "is a reserve output of this currency" would hand back a
    /// child's tokens, and since an identity spend consumes every input it is
    /// given, one such output poisons the whole transaction.
    #[test]
    fn a_token_paying_a_different_identity_is_not_offered() {
        let address = i_address();
        let mine = verus_tx::cc::reserve_output_script_to(
            verus_tx::Destination::Identity(ID),
            TOKEN,
            1_000,
        )
        .unwrap();
        // Same currency, same indexed address, different owner.
        let theirs = verus_tx::cc::reserve_output_script_to(
            verus_tx::Destination::Identity([0xc7; 20]),
            TOKEN,
            9_999,
        )
        .unwrap();

        let chain = ScriptedReader::new(TIP)
            .with_script_utxo(&address, 1_170_000, 0, mine)
            .with_script_utxo(&address, 1_170_000, 0, theirs);

        let found = crate::funding::identity_held_tokens(&chain, &address, TOKEN)
            .expect("the lookup succeeds");
        assert_eq!(found.len(), 1, "only the identity's own output");
        assert_eq!(
            verus_tx::decode_output_script(&found[0].script_pubkey).unwrap(),
            verus_tx::OutputKind::ReserveOutput {
                tokens: vec![(TOKEN, 1_000)],
                destination: verus_tx::Destination::Identity(ID),
            }
        );
    }

    /// A currency the identity does not hold is refused by name.
    #[test]
    fn a_currency_the_identity_does_not_hold_is_refused() {
        let chain = reader_holding_a_token(1_000);
        let other = verus_tx::CurrencyId::from_bytes([0x9d; 20]);
        let error = prepare_send_token_from_identity(
            &chain,
            &[&key()],
            &key(),
            "app@",
            other,
            &key().address().to_string(),
            Amount::from_sat(1),
        )
        .expect_err("the identity holds none of that currency");
        assert!(
            error.to_string().contains("no outputs of that currency"),
            "{error}"
        );
    }

    /// More than the identity holds is refused before signing.
    #[test]
    fn spending_more_of_the_token_than_is_held_is_refused() {
        let chain = reader_holding_a_token(1_000);
        let error = prepare_send_token_from_identity(
            &chain,
            &[&key()],
            &key(),
            "app@",
            TOKEN,
            &key().address().to_string(),
            Amount::from_sat(5_000),
        )
        .expect_err("more than is held");
        assert!(
            matches!(
                error,
                FlowError::Tx(verus_tx::TxError::InsufficientTokens { .. })
            ),
            "{error:?}"
        );
    }

    /// A node answering about an identity that holds one spendable output.
    ///
    /// `flags` and `timelock` are given raw, because the point of these tests is
    /// what this crate makes of the two together.
    fn reader_for(flags: u32, timelock: u32) -> ScriptedReader {
        let address = i_address();
        let script = verus_tx::identity_payment_script(ID).expect("the pay-to-identity script");
        ScriptedReader::new(TIP)
            .with_script_utxo(&address, 1_170_000, 500_000_000, script)
            .with_identity(
                "app@",
                IdentityRecord {
                    fully_qualified_name: "app@".into(),
                    identity_address: address.clone(),
                    status: "active".into(),
                    outpoint: (Txid::from_internal([0x22; 32]), 0),
                    block_height: 1_170_000,
                    identity: json!({
                        "identityaddress": address,
                        "primaryaddresses": [key().address().to_string()],
                        "minimumsignatures": 1,
                        "flags": flags,
                        "timelock": timelock,
                    }),
                },
            )
    }

    fn send(reader: &ScriptedReader) -> Result<Unsent<crate::Sent>, FlowError> {
        let k = key();
        prepare_send_from_identity(
            reader,
            &[&k],
            "app@",
            &k.address().to_string(),
            Amount::from_sat(100_000_000),
        )
    }

    /// The baseline, so the refusals below are not just "nothing ever builds".
    #[test]
    fn an_unlocked_identity_spends_normally() {
        send(&reader_for(0, 0)).expect("an unlocked identity can spend what it holds");
    }

    /// `flags` is a bitfield, and the common non-zero value is not a lock.
    ///
    /// `VRSCTEST@` itself reports `flags = 1` — `FLAG_ACTIVE_CURRENCY`. Testing
    /// the field against zero rather than masking `FLAG_LOCKED` would freeze
    /// every currency-bearing identity on the chain out of its own funds.
    #[test]
    fn an_active_currency_flag_is_not_a_lock() {
        // 0x1 is `FLAG_ACTIVE_CURRENCY`, spelled out because `verus_tx`
        // re-exports `FLAG_LOCKED` and `FLAG_TOKENIZED_CONTROL` but not this one.
        const ACTIVE_CURRENCY: u32 = 0x1;
        assert_eq!(
            timelock_of(&json!({"flags": ACTIVE_CURRENCY, "timelock": 0})),
            Timelock::None
        );
        send(&reader_for(ACTIVE_CURRENCY, 0)).expect("an active currency is not a timelock");
    }

    /// A running countdown holds the funds, and the refusal says until when.
    #[test]
    fn a_countdown_still_running_refuses_the_spend_and_names_the_height() {
        let err = send(&reader_for(0, TIP + 39)).expect_err("the funds are still held");
        let message = format!("{err}");
        assert!(
            message.contains(&(TIP + 39).to_string()),
            "the caller needs the height to know when to retry: {message}"
        );
    }

    /// A delay lock has no unlock height at all, and saying so is the honest
    /// answer — "when does this open" has no answer until someone asks it to.
    #[test]
    fn a_delay_lock_says_no_unlock_has_been_started() {
        let err = send(&reader_for(FLAG_LOCKED, 100)).expect_err("a delay lock holds the funds");
        let message = format!("{err}");
        assert!(
            message.contains("no unlock has been started"),
            "a delay is not a height and must not be reported as one: {message}"
        );
        assert!(
            !message.contains("100"),
            "100 is a delay, not a block to wait for: {message}"
        );
    }

    /// The state every previously-unlocked identity rests in — see #104. The
    /// stale height is behind the tip, so it holds nothing.
    #[test]
    fn an_elapsed_countdown_does_not_hold_the_funds() {
        send(&reader_for(0, TIP - 300)).expect("a countdown the chain has passed holds nothing");
    }
}
