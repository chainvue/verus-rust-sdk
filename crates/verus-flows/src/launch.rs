//! Launching a currency: lookup → build → sign → broadcast, composed.
//!
//! The builders in `verus_tx::currency_launch` are proven on chain, but they
//! want five things a caller must otherwise gather by hand: the defining
//! identity as the chain holds it, the output that identity currently sits in,
//! the chain's launch fee, the tip, and funding. This flow gathers all five,
//! checks what the daemon would only reject *after* the fees are spent, and
//! broadcasts the result.
//!
//! # The identity output comes from the chain's bytes, not from JSON
//!
//! A launch spends the identity's own output, and the sighash commits to that
//! output's exact script. Reconstructing the script from `getidentity`'s JSON
//! means re-serializing content maps, timelocks and every future field
//! faithfully — one drift and the signature verifies against a script the
//! chain does not hold. So this flow fetches the holding transaction and
//! **decodes the output that is actually there**; the JSON is used only to
//! find it.
//!
//! # What is checked before money moves
//!
//! * The identity exists, is not revoked, and does not already carry
//!   [`verus_tx::identity::FLAG_ACTIVE_CURRENCY`] — an identity defines a
//!   currency exactly once, and the daemon's rejection would name nothing.
//! * The signing keys are the identity's primaries, enough for `minsigs`.
//! * The definition's name and parent match the identity — a mismatch builds
//!   cleanly and is rejected only at consensus.
//! * The definition's `start_block` is still in the future.
//! * The launch fee is read from the parent's chain policy (or pinned by the
//!   caller), and a zero fee is refused: it means the parent's definition does
//!   not carry one, and a transaction built around zero is rejected on chain.

use verus_keys::PrivateKey;
use verus_rpc::{Broadcaster, ChainReader};
use verus_tx::currency_definition::CurrencyDefinition;
use verus_tx::currency_launch::{build_currency_launch, LaunchContext, LaunchParams};
use verus_tx::identity::FLAG_ACTIVE_CURRENCY;
use verus_tx::{Amount, Expiry, Utxo, DEFAULT_EXPIRY_BLOCKS};

use crate::broadcast::broadcast;
use crate::error::FlowError;
use crate::funding;

/// A currency launched and broadcast.
#[derive(Clone, Debug)]
pub struct Launched {
    /// The `definecurrency` transaction id.
    pub txid: String,
    /// The new currency's id — the defining identity's `i` address hash.
    pub currency_id: [u8; 20],
    /// The height conversions become possible and preconversions stop.
    pub start_block: u64,
    /// The launch fee that was paid, read from chain policy or pinned.
    pub launch_fee: Amount,
}

/// Define and launch a currency under its identity's authority.
///
/// `keys` are the defining identity's primary keys — `keys[0]` also funds the
/// launch fee, the reserve deposit and the miner fee from its P2PKH coins.
/// `identity` names the defining identity (`name@` or its `i` address). The
/// `definition` is the caller's — build it with
/// [`CurrencyDefinition::token`](verus_tx::currency_definition::CurrencyDefinition::token)
/// and adjust; this flow validates it against the identity and the chain
/// rather than second-guessing its economics.
///
/// `pin_launch_fee` overrides the fee read from the parent's policy — the same
/// escape hatch registration has, for a node that misreports it.
pub fn launch_currency(
    reader: &impl ChainReader,
    broadcaster: &impl Broadcaster,
    keys: &[&PrivateKey],
    identity: &str,
    definition: &CurrencyDefinition,
    pin_launch_fee: Option<Amount>,
) -> Result<Launched, FlowError> {
    if keys.is_empty() {
        return Err(FlowError::Tx(verus_tx::TxError::NoSignatures));
    }

    let record = reader
        .identity(identity)
        .map_err(|_| FlowError::NoSuchIdentity(identity.to_string()))?;
    if record.is_revoked() {
        return Err(FlowError::Tx(verus_tx::TxError::AlreadyRevoked));
    }

    // The chain's copy of the identity, decoded from the output that will be
    // spent — not reconstructed from JSON. See the module docs.
    let (chain_identity, identity_output) = holding_output(reader, &record)?;

    if chain_identity.flags & FLAG_ACTIVE_CURRENCY != 0 {
        return Err(FlowError::NotReady(format!(
            "{identity} already defines a currency; an identity defines exactly one"
        )));
    }

    // The same prechecks the chain applies at script verification, surfaced
    // with names: every signer must be a primary, and there must be enough
    // distinct signers to meet the threshold.
    let primaries: Vec<String> = chain_identity
        .primary_addresses
        .iter()
        .filter_map(|destination| match destination {
            verus_tx::Destination::PubKeyHash(hash) => Some(
                verus_keys::Address::new(verus_keys::AddressKind::PubKeyHash, *hash).to_string(),
            ),
            _ => None,
        })
        .collect();
    let mut distinct: Vec<String> = keys.iter().map(|k| k.address().to_string()).collect();
    distinct.sort();
    distinct.dedup();
    for address in &distinct {
        if !primaries.contains(address) {
            return Err(FlowError::Tx(verus_tx::TxError::NotAPrimaryAddress {
                address: address.clone(),
            }));
        }
    }
    if u64::try_from(distinct.len()).unwrap_or(u64::MAX) < u64::from(chain_identity.min_sigs) {
        return Err(FlowError::Tx(verus_tx::TxError::NotEnoughSigners {
            supplied: distinct.len(),
            required: chain_identity.min_sigs,
        }));
    }

    // A definition whose name or parent disagrees with the identity builds
    // cleanly and dies at consensus, after the fee.
    if !definition.name.eq_ignore_ascii_case(&chain_identity.name) {
        return Err(FlowError::NotReady(format!(
            "the definition names {:?} but the identity is {:?}",
            definition.name, chain_identity.name
        )));
    }
    if definition.parent.to_bytes() != chain_identity.parent {
        return Err(FlowError::NotReady(
            "the definition's parent is not the identity's parent".into(),
        ));
    }
    if definition.system_id.to_bytes() != chain_identity.system_id
        || definition.launch_system_id.to_bytes() != chain_identity.system_id
    {
        return Err(FlowError::NotReady(
            "the definition's system is not the identity's system; a same-chain launch \
             names the chain it lives on"
                .into(),
        ));
    }

    let tip = reader.block_count()?;
    if definition.start_block <= u64::from(tip) {
        return Err(FlowError::NotReady(format!(
            "start_block {} is not after the tip {tip}; the chain refuses a launch in the past",
            definition.start_block
        )));
    }

    // The launch fee is chain policy, read from the parent currency. Zero
    // means the parent's definition carries none — refusing beats building a
    // transaction the daemon rejects with an unrelated-looking message.
    let launch_fee = match pin_launch_fee {
        Some(fee) => fee,
        None => {
            let parent = verus_keys::Address::new(
                verus_keys::AddressKind::Identity,
                definition.parent.to_bytes(),
            )
            .to_string();
            reader.currency(&parent)?.currency_registration_fee
        }
    };
    if launch_fee == Amount::ZERO {
        return Err(FlowError::NotReady(
            "the parent reports no currency registration fee; pin one if you know better".into(),
        ));
    }

    let from = keys[0].address();
    let available = funding::spendable(reader, &from.to_string())?;
    funding::require(&available, launch_fee, &from.to_string())?;

    let identity_address: verus_keys::Address = record
        .identity_address
        .parse()
        .map_err(|e| FlowError::NoSuchIdentity(format!("{identity}: {e}")))?;
    let context = LaunchContext {
        identity: chain_identity,
        identity_address: identity_address.hash(),
        height: tip,
        launch_fee,
    };
    let signed = build_currency_launch(
        keys[0],
        keys,
        &LaunchParams {
            identity_output: &identity_output,
            definition,
            context: &context,
            utxos: &available.utxos,
            change_address: from,
            expiry: Expiry::within(tip, DEFAULT_EXPIRY_BLOCKS),
            fee_per_kb: verus_tx::fee::DEFAULT_FEE_PER_KB,
        },
    )?;

    let txid = broadcast(broadcaster, &signed.hex, &signed.txid)?;
    Ok(Launched {
        txid,
        currency_id: identity_address.hash(),
        start_block: definition.start_block,
        launch_fee,
    })
}

/// Fetch and decode the output currently holding the identity.
fn holding_output(
    reader: &impl ChainReader,
    record: &verus_rpc::IdentityRecord,
) -> Result<(verus_tx::identity::Identity, Utxo), FlowError> {
    let (txid, vout) = record.outpoint;
    let raw = reader.raw_transaction(&txid.to_display_hex())?;
    let script_hex = raw["vout"]
        .get(vout as usize)
        .and_then(|out| out["scriptPubKey"]["hex"].as_str())
        .ok_or_else(|| {
            FlowError::NotReady(format!(
                "the node's copy of {} has no output {vout}",
                txid.to_display_hex()
            ))
        })?;
    let script = hex::decode(script_hex)
        .map_err(|e| FlowError::NotReady(format!("identity output script: {e}")))?;

    let identity = match verus_tx::decode_output_script(&script)? {
        verus_tx::OutputKind::IdentityPrimary { identity } => *identity,
        other => {
            return Err(FlowError::NotReady(format!(
                "the identity's outpoint does not hold an identity output ({other:?})"
            )))
        }
    };
    // An identity output carries no native value; if it somehow did, the
    // assembler refuses it by name. A node that omits the field entirely is
    // refused HERE — signing over a guessed amount produces a signature the
    // chain rejects with no explanation at all.
    let satoshis = raw["vout"][vout as usize]["valueSat"]
        .as_u64()
        .ok_or_else(|| {
            FlowError::NotReady(format!(
                "the node's copy of {} output {vout} reports no valueSat",
                txid.to_display_hex()
            ))
        })?;
    Ok((
        identity,
        Utxo {
            txid,
            vout,
            satoshis: Amount::from_sat(satoshis),
            script_pubkey: script,
        },
    ))
}
