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
//!
//! # Which fee a launch pays
//!
//! Two fields, chosen by the definition's own `NFT_TOKEN` bit, because that is
//! what consensus does — `CCurrencyDefinition::GetCurrencyImportFee` returns
//! `idImportFees` for a tokenized-control currency and `currencyImportFee` for
//! everything else:
//!
//! | definition | field read | VRSCTEST |
//! |---|---|---|
//! | token, basket | `currency_registration_fee` | 200 |
//! | NFT | `id_import_fee` | 0.02 |
//!
//! Four orders of magnitude apart, and half of whichever it is becomes the
//! reserve deposit at output 5 — so the wrong field is not a cosmetic error.

use verus_keys::PrivateKey;
use verus_rpc::{Broadcaster, ChainReader};
use verus_tx::currency_definition::{option, CurrencyDefinition};
use verus_tx::currency_launch::{build_currency_launch, LaunchContext, LaunchParams};
use verus_tx::identity::FLAG_ACTIVE_CURRENCY;
use verus_tx::{Amount, Expiry, Utxo, DEFAULT_EXPIRY_BLOCKS};

use crate::broadcast::Unsent;
use crate::error::FlowError;
use crate::funding;
use crate::identity::check_trusted_node_fee;

/// A currency launch — broadcast by [`launch_currency`], still unsent from
/// [`prepare_launch`].
#[derive(Clone, Debug)]
pub struct Launched {
    /// The `definecurrency` transaction id, computed locally from its bytes.
    pub txid: String,
    /// The new currency's id — the defining identity's `i` address hash.
    pub currency_id: [u8; 20],
    /// The height conversions become possible and preconversions stop.
    pub start_block: u64,
    /// The launch fee that was paid, read from chain policy or pinned.
    ///
    /// This is the figure a wallet shows before the user consents, so which
    /// field it came from matters: an NFT pays the parent's `id_import_fee`,
    /// everything else its `currency_registration_fee`. See the module docs.
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
    prepare_launch(reader, keys, identity, definition, pin_launch_fee)?.broadcast(broadcaster)
}

/// Build the launch without sending it.
///
/// The read-only half of [`launch_currency`], including every check it makes
/// against the identity, the definition and chain policy.
pub fn prepare_launch(
    reader: &impl ChainReader,
    keys: &[&PrivateKey],
    identity: &str,
    definition: &CurrencyDefinition,
    pin_launch_fee: Option<Amount>,
) -> Result<Unsent<Launched>, FlowError> {
    if keys.is_empty() {
        return Err(FlowError::Tx(verus_tx::TxError::NoSignatures));
    }

    let record = crate::error::look_up_identity(reader, identity)?
        .ok_or_else(|| FlowError::NoSuchIdentity(identity.to_string()))?;
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
    let launch_fee = if let Some(fee) = pin_launch_fee {
        fee
    } else {
        let parent = verus_keys::Address::new(
            verus_keys::AddressKind::Identity,
            definition.parent.to_bytes(),
        )
        .to_string();
        let policy = reader.currency(&parent)?;
        // Consensus picks between two fields, and so must this.
        // `CCurrencyDefinition::GetCurrencyImportFee` (`crosschainrpc.h:1020`)
        // returns `idImportFees` for a tokenized-control currency and
        // `currencyImportFee` for everything else, and every call site passes
        // `def.ChainOptions() & def.OPTION_NFT_TOKEN` as that bit.
        //
        // The difference is four orders of magnitude — 0.02 against 200 on
        // VRSCTEST — and it is not inert: half the fee becomes the reserve
        // deposit at output 5, so the wrong field puts 100 VRSCTEST of real
        // value into an output consensus is not expecting. Confirmed against
        // the chain: both NFT launches on VRSCTEST, `sdknftbeta`
        // (`4ad8fb14…7d7e`) and `kmerg` (`8d8671d4…b6b3`), carry a reserve
        // deposit of 0.01, which is `fee - fee/2` for a fee of 0.02.
        //
        // It is also what a wallet shows on the confirmation panel before the
        // user consents, so getting it wrong misstates the price by 10,000x.
        let reported = if definition.options & option::NFT_TOKEN != 0 {
            policy.id_import_fee
        } else {
            policy.currency_registration_fee
        };
        // H4: node-supplied and BURNED outright — see
        // `check_trusted_node_fee`. A caller who pins the fee explicitly
        // has taken responsibility for it, so it skips this bar and is
        // checked against `MAX_DECLARED_BURN` instead, later at assembly.
        //
        // The bar is a ceiling only, so an NFT's much smaller fee passes it
        // unchanged — there is no floor to trip from below.
        check_trusted_node_fee("currency launch", reported)?
    };
    if launch_fee == Amount::ZERO {
        // Name the field that was actually read, since the two live in
        // different places in the parent's definition.
        let field = if definition.options & option::NFT_TOKEN != 0 {
            "identity import fee, which is what an NFT launch is charged"
        } else {
            "currency registration fee"
        };
        return Err(FlowError::NotReady(format!(
            "the parent reports no {field}; pin one if you know better"
        )));
    }

    let from = keys[0].address();
    let available = funding::spendable(reader, &from.to_string())?;

    // A contribution is funded by the launch transaction itself — a
    // value-bearing output on top of the fee — so the pre-check has to count
    // it. Without this the shortfall surfaces from the assembler as a generic
    // insufficient-funds error naming the fee alone, which sends a caller
    // looking for the wrong missing money.
    //
    // Grossed up for the same reason the output is: the declared figure is
    // what lands in the reserve, not what leaves the wallet.
    let contributed = definition
        .initial_contributions
        .iter()
        .try_fold(Amount::ZERO, |sum, c| sum.checked_add(*c))
        .ok_or(verus_tx::TxError::ValueOverflow)?;
    let needed = launch_fee
        .checked_add(contributed)
        .ok_or(verus_tx::TxError::ValueOverflow)?;
    funding::require(&available, needed, &from.to_string())?;

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

    Ok(Unsent {
        hex: signed.hex.clone(),
        txid: signed.txid.clone(),
        outcome: Launched {
            txid: signed.txid,
            currency_id: identity_address.hash(),
            start_block: definition.start_block,
            launch_fee,
        },
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
