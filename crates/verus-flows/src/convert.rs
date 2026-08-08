//! Converting one currency into another, and burning one.
//!
//! # Read this before wiring it into a button
//!
//! A conversion is a **request at an unknown price**. The transaction says what
//! goes in and where the result should land; it says nothing about what comes
//! out. The chain performs the conversion when it *imports* the output, at
//! whatever the reserve ratios are then — a block later at best.
//!
//! There is no slippage bound in the protocol. [`estimate`] asks a node what it
//! expects, and [`ConversionPlan::min_expected`] lets a caller record what they
//! were willing to accept, but **nothing enforces either one**. If the price
//! moves between signing and import, the conversion still executes. A wallet
//! that shows a user a number must show it as an estimate.
//!
//! # A burn cannot be undone
//!
//! [`burn`] destroys value. There is no output that pays anything back, no
//! recovery, and the supply change moves a fractional currency's price for
//! everyone. It is deliberately a separate function rather than a flag.

use verus_keys::{Address, PrivateKey};
use verus_rpc::{Broadcaster, ChainReader, ConversionEstimate};
use verus_tx::convert::{
    build_conversion, build_conversion_transaction, ConversionKind, ConversionParams,
    ReserveTransfer,
};
use verus_tx::{Amount, CurrencyId, Expiry, Utxo, DEFAULT_EXPIRY_BLOCKS};

use crate::broadcast::Unsent;
use crate::error::FlowError;
use crate::funding;
use crate::send::Sent;

/// What a node expects a conversion to yield.
///
/// Advisory. See the module docs.
pub fn estimate(
    reader: &impl ChainReader,
    from: &str,
    to: &str,
    amount: Amount,
    via: Option<&str>,
) -> Result<ConversionEstimate, FlowError> {
    Ok(reader.estimate_conversion(from, to, &amount.to_coins_string(), via)?)
}

/// A conversion that has been priced but not yet signed.
#[derive(Clone, Debug)]
pub struct ConversionPlan {
    /// The transfer that will be built.
    pub transfer: ReserveTransfer,
    /// What the node expected when this was planned.
    pub estimated_out: Amount,
    /// The least the caller is willing to accept.
    ///
    /// **Checked here, before signing, and never again.** The chain does not
    /// enforce it — if the price moves after the transaction is broadcast, the
    /// conversion still happens. Recording it makes the intent explicit and
    /// catches a price that has already moved.
    ///
    /// Not accepted for a [`ConversionKind::Preconvert`] at all: there is no
    /// market to price a pre-launch currency against, so a floor there could
    /// only be checked against a fabricated number.
    pub min_expected: Option<Amount>,
}

impl ConversionPlan {
    /// Whether the estimate still satisfies the caller's floor.
    pub fn acceptable(&self) -> bool {
        match self.min_expected {
            Some(floor) => self.estimated_out >= floor,
            None => true,
        }
    }
}

/// Price a conversion and check it against a floor, without signing anything.
///
/// Takes a [`ChainReader`] and no [`Broadcaster`], so it cannot send.
///
/// `refund` is where the value returns if the conversion cannot be completed.
/// It is normally the sender's own address, and it matters most for a
/// [`ConversionKind::Preconvert`]: a launch that misses its `min_preconversion`
/// refunds **every** contribution, so for that kind the refund path is the
/// ordinary outcome rather than a rare one. Naming the recipient here instead
/// would send your money back to whoever you were converting for.
#[allow(clippy::too_many_arguments)]
pub fn plan_conversion(
    reader: &impl ChainReader,
    source: &str,
    amount: Amount,
    kind: ConversionKind,
    recipient: &str,
    refund: Address,
    fee: Amount,
    min_expected: Option<Amount>,
) -> Result<ConversionPlan, FlowError> {
    let info = reader.chain_info()?;
    let chain_currency = currency_of(&info.chain_id)?;
    let source_id = currency_of(source)?;
    let recipient: Address = recipient.parse()?;
    // No kind guard here any more. It existed because the builder flattened
    // every address to a key hash, so an `i` address silently paid the R-form
    // of the same bytes — an address nobody controls. The builder now writes
    // the identity destination the wire has always had a type byte for, so
    // naming a VerusID means what it says.

    let (to, via) = match &kind {
        ConversionKind::IntoFractional { fractional }
        | ConversionKind::Preconvert { fractional } => (id_text(*fractional), None),
        ConversionKind::IntoReserve { reserve } => (id_text(*reserve), None),
        ConversionKind::ReserveToReserve { via, target } => (id_text(*target), Some(id_text(*via))),
        ConversionKind::Mint { currency } => (id_text(*currency), None),
        ConversionKind::Burn => (source.to_string(), None),
        // A contribution exists only inside a `definecurrency`, emitted by the
        // launch builder. There is nothing here to plan or price: it is not a
        // transaction a caller submits.
        ConversionKind::Contribution { .. } => {
            return Err(FlowError::NotReady(
                "a contribution is part of a currency's own definition transaction, not a \
                 conversion; declare it with `CurrencyDefinition::with_contributions` and \
                 launch"
                    .into(),
            ))
        }
    };

    let estimated_out = if matches!(kind, ConversionKind::Burn) {
        // Nothing comes out of a burn, so there is nothing to estimate.
        Amount::ZERO
    } else if matches!(kind, ConversionKind::Mint { .. }) {
        // A mint creates exactly what it asks for — there is no price and
        // nothing to estimate.
        amount
    } else if matches!(kind, ConversionKind::Preconvert { .. }) {
        // A pre-launch currency has no reserves, so there is no market to price
        // against and `estimateconversion` has nothing to answer with. What a
        // preconversion returns is decided at launch, from the final ratio of
        // everyone's contributions — not knowable now.
        //
        // **So a floor cannot be checked here, and pretending otherwise was
        // worse than refusing.** The zero below used to be compared against
        // `min_expected` like any other estimate, which failed every floor
        // above zero and reported it as "the node expects 0" — a number the
        // node was never asked for and never produced. Refused by name
        // instead.
        if min_expected.is_some() {
            return Err(FlowError::NotReady(
                "a preconversion cannot be checked against a floor: the currency has not \
                 launched, so it has no reserves to price against, and what you receive \
                 is decided at launch from everyone's contributions together"
                    .into(),
            ));
        }
        Amount::ZERO
    } else {
        estimate(reader, source, &to, amount, via.as_deref())?.estimated_out
    };

    let transfer = build_conversion(
        source_id,
        amount,
        kind,
        recipient,
        refund,
        // The fee is paid natively unless a caller has reason to do otherwise;
        // that is what the daemon does for every template captured here.
        chain_currency,
        fee,
    )?;

    Ok(ConversionPlan {
        transfer,
        estimated_out,
        min_expected,
    })
}

/// Convert `amount` of `source` into another currency, and broadcast it.
///
/// `token_funding` carries the source currency when it is a token; leave it
/// empty when converting the chain's own currency. As with a sub-identity fee,
/// every token input is spent whole and the surplus returns as change — a token
/// left out is a token destroyed.
///
/// Refuses before signing if the node's estimate has already fallen below
/// `min_expected`. That is the only price check available; see the module docs.
#[allow(clippy::too_many_arguments)]
pub fn convert(
    reader: &impl ChainReader,
    broadcaster: &impl Broadcaster,
    key: &PrivateKey,
    source: &str,
    amount: Amount,
    kind: ConversionKind,
    recipient: &str,
    fee: Amount,
    min_expected: Option<Amount>,
    token_funding: &[Utxo],
) -> Result<Sent, FlowError> {
    prepare_conversion(
        reader,
        key,
        source,
        amount,
        kind,
        recipient,
        fee,
        min_expected,
        token_funding,
    )?
    .broadcast(broadcaster)
}

/// Build a conversion without sending it.
///
/// The read-only half of [`convert`], including the price floor check — that
/// too is a read, and it belongs before signing rather than before sending.
#[allow(clippy::too_many_arguments)]
pub fn prepare_conversion(
    reader: &impl ChainReader,
    key: &PrivateKey,
    source: &str,
    amount: Amount,
    kind: ConversionKind,
    recipient: &str,
    fee: Amount,
    min_expected: Option<Amount>,
    token_funding: &[Utxo],
) -> Result<Unsent<Sent>, FlowError> {
    // The refund goes back to the signer, which is what the daemon does and
    // what a caller converting on somebody else's behalf needs.
    let plan = plan_conversion(
        reader,
        source,
        amount,
        kind,
        recipient,
        key.address(),
        fee,
        min_expected,
    )?;
    if !plan.acceptable() {
        return Err(FlowError::NotReady(format!(
            "the node expects {} but {} was required",
            plan.estimated_out.to_coins_string(),
            plan.min_expected.unwrap_or(Amount::ZERO).to_coins_string()
        )));
    }
    prepare_submission(reader, key, &plan.transfer, token_funding)
}

/// Destroy `amount` of a token.
///
/// Separate from [`convert`] because it is irreversible: nothing is paid back,
/// and the supply change moves a fractional's price for every holder.
pub fn burn(
    reader: &impl ChainReader,
    broadcaster: &impl Broadcaster,
    key: &PrivateKey,
    currency: &str,
    amount: Amount,
    fee: Amount,
    token_funding: &[Utxo],
) -> Result<Sent, FlowError> {
    prepare_burn(reader, key, currency, amount, fee, token_funding)?.broadcast(broadcaster)
}

/// Build a burn without sending it.
///
/// The read-only half of [`burn`]. Nothing about it is less irreversible; the
/// bytes it returns destroy the value the moment they are accepted.
pub fn prepare_burn(
    reader: &impl ChainReader,
    key: &PrivateKey,
    currency: &str,
    amount: Amount,
    fee: Amount,
    token_funding: &[Utxo],
) -> Result<Unsent<Sent>, FlowError> {
    let info = reader.chain_info()?;
    let chain_currency = currency_of(&info.chain_id)?;
    let transfer = build_conversion(
        currency_of(currency)?,
        amount,
        ConversionKind::Burn,
        key.address(),
        // A burn's destination carries no auxiliary, so this is unused.
        key.address(),
        chain_currency,
        fee,
    )?;
    prepare_submission(reader, key, &transfer, token_funding)
}

/// Mint new supply of a centralized currency, authorised by its identity.
///
/// `currency` is the token’s `i` address — which is also the id of its
/// controlling identity, and that coincidence is the whole mechanism:
/// consensus accepts a mint only from a transaction that *spends an output the
/// controlling identity holds*, signed with the identity’s own authority
/// (`CheckIdentitySpends`). So this flow funds the transaction from the
/// identity’s pay-to-identity outputs, signs their fulfillments with `key`
/// — which must be one of the identity’s primary addresses — and returns the
/// surplus to the identity.
///
/// The identity must hold enough native coins to cover the transfer fee plus
/// the miner fee; [`crate::funding::identity_held`] reports what it has, and
/// an ordinary [`crate::send()`] to the `i` address tops it up.
///
/// The authority check is point-in-time: an identity whose keys rotate or
/// which is revoked between the read and the broadcast produces a rejected
/// transaction, not a loss.
pub fn mint(
    reader: &impl ChainReader,
    broadcaster: &impl Broadcaster,
    key: &PrivateKey,
    currency: &str,
    amount: Amount,
    recipient: &str,
    fee: Amount,
) -> Result<Sent, FlowError> {
    prepare_mint(reader, key, currency, amount, recipient, fee)?.broadcast(broadcaster)
}

/// Build a mint without sending it.
///
/// The read-only half of [`mint`], including every authority precheck.
pub fn prepare_mint(
    reader: &impl ChainReader,
    key: &PrivateKey,
    currency: &str,
    amount: Amount,
    recipient: &str,
    fee: Amount,
) -> Result<Unsent<Sent>, FlowError> {
    let currency_id = currency_of(currency)?;
    let recipient: Address = recipient.parse()?;
    // A mint may pay a VerusID, and minting to the *controlling* identity is
    // the ordinary treasury pattern rather than a special case — eight
    // centralized currencies on VRSCTEST hold their own token at their issuing
    // identity's address. The guard that used to be here existed only because
    // the builder flattened the address kind away.

    // All four reads are issued before any is unwrapped: none needs another's
    // answer, and a `?` between them would cost a network round trip each
    // against a driver that cannot answer immediately. See [`crate::drive`].
    //
    // It does mean a revoked identity has its outputs fetched before the
    // refusal below — `getblockcount`, `getaddressutxos` and any coinbase
    // probes those turn up. Wasted work on a path that was going to fail
    // anyway, against a round saved on every path that works.
    let info = reader.chain_info();
    let record = crate::error::look_up_identity(reader, currency);
    let identity_funding = crate::funding::identity_held(reader, currency);
    let definition = reader.currency_definition(currency);
    let (info, record, identity_funding, definition) =
        (info?, record?, identity_funding?, definition?);
    let chain_currency = currency_of(&info.chain_id)?;

    // Only a centralized currency can be minted at all: `proofprotocol` 2 is
    // what hands issuance to the controlling identity. Anything else has a
    // supply fixed at definition time, and there is no later way to add to it.
    //
    // Refused here because consensus refuses it *after* the fee is spent, with
    // `-25: bad-txns-failed-precheck` — a message that names neither the field
    // nor the value it wanted. Worse, a currency in this state cannot be fixed:
    // the definition is immutable and the defining identity has spent its
    // one-time ability to define a currency, so the name cannot be reused
    // either. Naming the field is the whole value of checking it.
    if definition.proof_protocol != verus_tx::CENTRALIZED_PROOF_PROTOCOL {
        return Err(FlowError::NotReady(format!(
            "{currency} has proofprotocol {}, and only a centralized currency \
             (proofprotocol {}) can be minted — its supply is whatever its definition \
             preallocated and cannot be added to",
            definition.proof_protocol,
            verus_tx::CENTRALIZED_PROOF_PROTOCOL,
        )));
    }

    // The same prechecks the chain applies, surfaced with names. The
    // controlling identity IS the currency id; `CheckIdentitySpends` will
    // demand its primary keys and threshold, and this flow signs with one key.
    let record = record.ok_or_else(|| FlowError::NoSuchIdentity(currency.to_string()))?;
    if record.is_revoked() {
        return Err(FlowError::Tx(verus_tx::TxError::AlreadyRevoked));
    }
    let primaries = record.identity["primaryaddresses"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let signer = key.address().to_string();
    if !primaries.contains(&signer) {
        return Err(FlowError::Tx(verus_tx::TxError::NotAPrimaryAddress {
            address: signer,
        }));
    }
    let min_sigs = record.identity["minimumsignatures"].as_u64().unwrap_or(1);
    if min_sigs > 1 {
        return Err(FlowError::Tx(verus_tx::TxError::NotEnoughSigners {
            supplied: 1,
            required: u32::try_from(min_sigs).unwrap_or(u32::MAX),
        }));
    }

    // The daemon’s own template: the transfer’s SOURCE slot names the system
    // currency while the destination names what is created.
    let transfer = build_conversion(
        chain_currency,
        amount,
        ConversionKind::Mint {
            currency: currency_id,
        },
        recipient,
        // A mint's destination carries no auxiliary either.
        recipient,
        chain_currency,
        fee,
    )?;

    if identity_funding.is_empty() {
        return Err(FlowError::NotReady(format!(
            "{currency} holds no spendable outputs; a mint is paid for by the identity — \
             send() it some coins first"
        )));
    }
    // `identity_held` has already asked for this, so under a driver it is a
    // cache hit and costs no round. On a blocking client it is a second real
    // request — cheap, and not worth threading the tip back out for.
    let tip = reader.block_count()?;
    let params = ConversionParams::new(
        &transfer,
        // No P2PKH funding: a mint is paid for by the identity it spends from.
        &[],
        chain_currency,
        key.address(),
        Expiry::within(tip, DEFAULT_EXPIRY_BLOCKS),
    )
    .with_identity_funding(&identity_funding);

    Ok(build_conversion_transaction(key, &params)?.into())
}

/// Fund and sign a prepared transfer, without sending it.
/// Convert a token a VerusID holds, without moving it out first.
///
/// The identity supplies the token; `key` signs both its fulfillment and the
/// plain coins that pay the miner fee. Those coins are necessary rather than
/// convenient: a token an identity holds is a reserve output carrying **zero
/// satoshis**, so it cannot pay its own way, and an identity holding a token
/// need not hold native coins at all.
///
/// # Why this exists rather than sending the token out and converting it
///
/// A token's supply is the sum of its `preallocations`, and a preallocation
/// names an identity — so for `proofprotocol` 1 every unit exists on the
/// defining identity and never touches a key-held address. Seeding a basket
/// with it otherwise takes two transactions, and between them the supply sits
/// at a bare address while the launch window runs down. A basket that reaches
/// its start block with an empty reserve refunds its **entire** launch, and the
/// name cannot be reused, because an identity defines exactly one currency.
///
/// One conversion funded from the identity removes that window.
///
/// # What comes back where
///
/// Token surplus returns to the **identity**; native change goes to `key`'s own
/// address. Money under an identity's authority should not quietly migrate to a
/// bare key, and the fee did not come from the identity in the first place.
#[allow(clippy::too_many_arguments)]
pub fn prepare_conversion_from_identity(
    reader: &impl ChainReader,
    key: &PrivateKey,
    identity: &str,
    source: &str,
    amount: Amount,
    kind: ConversionKind,
    recipient: &str,
    fee: Amount,
) -> Result<Unsent<Sent>, FlowError> {
    let source_id = currency_of(source)?;
    let from = key.address();

    // Three reads, issued together — none needs another's answer. The
    // identity's own token outputs are NOT among them: `identity` may be a
    // `name@`, and the address to ask about is the one the record reports. That
    // is a real dependency and costs a second round, exactly as it does in
    // `prepare_send_token_from_identity`. See [`crate::drive`].
    let info = reader.chain_info();
    let record = crate::error::look_up_identity(reader, identity);
    let fee_funding = funding::spendable(reader, &from.to_string());
    let (info, record, fee_funding) = (info?, record?, fee_funding?);

    let chain_currency = currency_of(&info.chain_id)?;
    let record = record.ok_or_else(|| FlowError::NoSuchIdentity(identity.to_string()))?;
    if record.is_revoked() {
        return Err(FlowError::Tx(verus_tx::TxError::AlreadyRevoked));
    }

    // The same point-in-time checks the identity spend paths make. Consensus
    // refuses a short fulfillment with `mandatory-script-verify-flag-failed`,
    // which names neither the identity nor the key nor the threshold.
    let primaries = record.identity["primaryaddresses"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if !primaries.contains(&from.to_string()) {
        return Err(FlowError::Tx(verus_tx::TxError::NotAPrimaryAddress {
            address: from.to_string(),
        }));
    }
    let min_sigs = record.identity["minimumsignatures"].as_u64().unwrap_or(1);
    if min_sigs > 1 {
        return Err(FlowError::Tx(verus_tx::TxError::NotEnoughSigners {
            supplied: 1,
            required: u32::try_from(min_sigs).unwrap_or(u32::MAX),
        }));
    }

    // A timelock holds the identity's token outputs exactly as it holds its
    // native ones.
    let timelock = crate::send::timelock_of(&record.identity);
    if !timelock.spendable_at(fee_funding.tip) {
        return Err(FlowError::Tx(verus_tx::TxError::FundsTimelocked {
            unlock_at: match timelock {
                verus_tx::Timelock::UntilBlock(height) => Some(height),
                _ => None,
            },
        }));
    }

    // Asked for by the address the record reports, not by whatever the caller
    // wrote — a `name@` has to be resolved before there is an address at all.
    let held = crate::funding::identity_held_tokens(reader, &record.identity_address, source_id)?;
    if held.is_empty() {
        return Err(FlowError::NotReady(format!(
            "{identity} holds no outputs of {source}"
        )));
    }
    if fee_funding.utxos.is_empty() {
        return Err(FlowError::NotReady(format!(
            "a token output carries no native value, so the miner fee must come from \
             elsewhere — {from} has nothing spendable"
        )));
    }

    // A mint is authorised by the currency's own identity and a burn destroys
    // value; neither is reachable by naming a different kind here. A
    // contribution is not a standalone transaction at all — it exists only
    // inside a `definecurrency`, and its flag word says so.
    if matches!(
        kind,
        ConversionKind::Mint { .. } | ConversionKind::Burn | ConversionKind::Contribution { .. }
    ) {
        return Err(FlowError::NotReady(
            "a mint, a burn or a contribution is not a conversion; use prepare_mint, \
             prepare_burn, or declare the contribution on the definition and launch"
                .into(),
        ));
    }
    let recipient: Address = recipient.parse()?;

    let transfer = build_conversion(
        source_id,
        amount,
        kind,
        recipient,
        // The refund goes back to the signer, as everywhere else here.
        from,
        chain_currency,
        fee,
    )?;

    let params = ConversionParams::new(
        &transfer,
        &fee_funding.utxos,
        chain_currency,
        from,
        Expiry::within(fee_funding.tip, DEFAULT_EXPIRY_BLOCKS),
    )
    .with_identity_funding(&held);

    Ok(build_conversion_transaction(key, &params)?.into())
}

fn prepare_submission(
    reader: &impl ChainReader,
    key: &PrivateKey,
    transfer: &ReserveTransfer,
    token_funding: &[Utxo],
) -> Result<Unsent<Sent>, FlowError> {
    let from = key.address();
    // Issued together, unwrapped after — see [`crate::drive`].
    let info = reader.chain_info();
    let funding = funding::spendable(reader, &from.to_string());
    let (info, funding) = (info?, funding?);
    let chain_currency = currency_of(&info.chain_id)?;

    // What must be available natively, before the miner fee.
    let native = transfer.native_value(chain_currency)?;
    funding::require(&funding, native, &from.to_string())?;

    let params = ConversionParams::new(
        transfer,
        &funding.utxos,
        chain_currency,
        from,
        Expiry::within(funding.tip, DEFAULT_EXPIRY_BLOCKS),
    )
    .with_token_funding(token_funding);

    Ok(build_conversion_transaction(key, &params)?.into())
}

fn currency_of(id: &str) -> Result<CurrencyId, FlowError> {
    let address: Address = id.parse()?;
    Ok(CurrencyId::from_bytes(address.hash()))
}

fn id_text(currency: CurrencyId) -> String {
    Address::new(verus_keys::AddressKind::Identity, currency.to_bytes()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::ScriptedReader;

    const WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";
    const VRSCTEST: &str = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";
    const SHYLOCK: &str = "iQihXUcQt8G9TSh58YoM5NRwC1nAyoazFR";

    fn key() -> PrivateKey {
        PrivateKey::from_wif(WIF).unwrap()
    }

    fn chain(tip: u32, out: u64) -> ScriptedReader {
        ScriptedReader::new(tip)
            .with_utxo(&key().address().to_string(), tip - 500, 100_00000000)
            .with_estimate(ConversionEstimate {
                estimated_out: Amount::from_sat(out),
                fee: None,
            })
    }

    fn shylock() -> ConversionKind {
        ConversionKind::IntoFractional {
            fractional: currency_of(SHYLOCK).unwrap(),
        }
    }

    #[test]
    fn a_native_conversion_is_built_and_broadcast() {
        let node = chain(1_000, 1_49165329);
        let sent = convert(
            &node,
            &node,
            &key(),
            VRSCTEST,
            Amount::from_sat(1_50000000),
            shylock(),
            &key().address().to_string(),
            Amount::from_sat(20_010),
            None,
            &[],
        )
        .unwrap();
        assert_eq!(node.broadcasts().len(), 1);
        assert_eq!(node.broadcasts()[0], sent.hex);
    }

    /// **A conversion may pay a VerusID.**
    ///
    /// This test is the inverse of the one it replaces. That one asserted an
    /// identity address was refused, and it was right to: the builder
    /// flattened every address to a key hash, so an `i` address paid the
    /// R-form of the same 20 bytes — an address nobody holds a key to.
    ///
    /// The refusal was the correct response to that bug, not a rule about
    /// Verus. `CTransferDestination` has carried a type byte for an identity
    /// all along, and `destination_type` already wrote `4` for one.
    #[test]
    fn a_conversion_can_pay_a_verusid() {
        let node = chain(1_000, 1_49165329);
        let identity =
            verus_keys::Address::new(verus_keys::AddressKind::Identity, key().address().hash());

        let to_identity = prepare_conversion(
            &node,
            &key(),
            VRSCTEST,
            Amount::from_sat(1_50000000),
            shylock(),
            &identity.to_string(),
            Amount::from_sat(20_010),
            None,
            &[],
        )
        .expect("an identity is a destination the wire has always had a byte for");

        // Not merely accepted: the bytes must differ from the R-address form.
        // Both carry the same 20 bytes, so a builder that still flattened the
        // kind would produce an identical transaction and pass a weaker test.
        let to_r_address = prepare_conversion(
            &node,
            &key(),
            VRSCTEST,
            Amount::from_sat(1_50000000),
            shylock(),
            &key().address().to_string(),
            Amount::from_sat(20_010),
            None,
            &[],
        )
        .expect("the R-address form still works");

        assert_ne!(
            to_identity.hex, to_r_address.hex,
            "paying an identity must not build the same transaction as paying \
             the R-address that shares its bytes"
        );
    }

    /// **Converting for somebody else must not refund to them.**
    ///
    /// The auxiliary destination on a converting transfer is the refund
    /// address: where the value goes if the conversion cannot be completed. It
    /// used to be filled with the recipient, which is right only when the
    /// recipient is you.
    ///
    /// For a preconversion that is not a corner case — a launch missing its
    /// `min_preconversion` refunds every contribution, so the refund path is
    /// the ordinary outcome. Paying one to a friend's address would have sent
    /// them your money back as well as their tokens.
    #[test]
    fn a_conversion_refunds_to_the_signer_not_the_recipient() {
        let node = chain(1_000, 1_49165329);
        let stranger = PrivateKey::from_bytes(&[0x99; 32], true).unwrap().address();
        assert_ne!(stranger, key().address());

        let unsent = prepare_conversion(
            &node,
            &key(),
            VRSCTEST,
            Amount::from_sat(1_50000000),
            shylock(),
            &stranger.to_string(),
            Amount::from_sat(20_010),
            None,
            &[],
        )
        .expect("prepare");

        // Read the reserve transfer back out of the bytes that would be sent,
        // rather than trusting the builder's report of what it did.
        let raw = hex::decode(&unsent.hex).expect("hex");
        let tx = verus_wire::TxV4::deserialize(&raw).expect("parse");
        let transfer = tx
            .outputs
            .iter()
            .find_map(
                |out| match verus_tx::decode_output_script(&out.script_pubkey) {
                    Ok(verus_tx::OutputKind::ReserveTransfer { transfer, .. }) => Some(*transfer),
                    _ => None,
                },
            )
            .expect("the conversion carries a reserve transfer");

        assert_eq!(
            transfer.destination.recipient,
            verus_tx::Destination::PubKeyHash(stranger.hash()),
            "the tokens go where they were sent"
        );
        assert_eq!(
            transfer.destination.auxiliary,
            vec![verus_tx::Destination::PubKeyHash(key().address().hash())],
            "and the refund comes back to whoever paid"
        );
    }

    /// A floor cannot be checked against a market that does not exist yet, and
    /// the previous answer was to compare it against a fabricated zero — which
    /// failed every floor above zero and blamed the node for a number it was
    /// never asked for.
    #[test]
    fn a_preconversion_refuses_a_floor_rather_than_inventing_one() {
        let node = chain(1_000, 0);
        let error = prepare_conversion(
            &node,
            &key(),
            VRSCTEST,
            Amount::from_sat(1_00000000),
            ConversionKind::Preconvert {
                fractional: currency_of(SHYLOCK).unwrap(),
            },
            &key().address().to_string(),
            Amount::from_sat(20_010),
            Some(Amount::from_sat(1)),
            &[],
        )
        .expect_err("a preconversion has no price to check a floor against");
        let message = format!("{error}");
        assert!(message.contains("has not launched"), "{message}");
        assert!(
            !message.contains("the node expects"),
            "the node was never asked: {message}"
        );

        // Without a floor it plans normally — the refusal is about the floor,
        // not about preconverting.
        assert!(prepare_conversion(
            &node,
            &key(),
            VRSCTEST,
            Amount::from_sat(1_00000000),
            ConversionKind::Preconvert {
                fractional: currency_of(SHYLOCK).unwrap(),
            },
            &key().address().to_string(),
            Amount::from_sat(20_010),
            None,
            &[],
        )
        .is_ok());
    }

    /// A floor that the node's own estimate already fails must stop before
    /// anything is signed. It is the only price check that exists.
    #[test]
    fn a_price_below_the_floor_is_refused_before_signing() {
        let node = chain(1_000, 1_00000000);
        let result = convert(
            &node,
            &node,
            &key(),
            VRSCTEST,
            Amount::from_sat(1_50000000),
            shylock(),
            &key().address().to_string(),
            Amount::from_sat(20_010),
            Some(Amount::from_sat(1_40000000)),
            &[],
        );
        assert!(matches!(result, Err(FlowError::NotReady(_))));
        assert!(node.broadcasts().is_empty(), "it signed anyway");
    }

    /// A floor the estimate satisfies goes through.
    #[test]
    fn a_price_above_the_floor_proceeds() {
        let node = chain(1_000, 1_49165329);
        assert!(convert(
            &node,
            &node,
            &key(),
            VRSCTEST,
            Amount::from_sat(1_50000000),
            shylock(),
            &key().address().to_string(),
            Amount::from_sat(20_010),
            Some(Amount::from_sat(1_40000000)),
            &[],
        )
        .is_ok());
    }

    /// Planning must not sign or send — it takes no broadcaster at all.
    #[test]
    fn planning_sends_nothing() {
        let node = chain(1_000, 1_49165329);
        let plan = plan_conversion(
            &node,
            VRSCTEST,
            Amount::from_sat(1_50000000),
            shylock(),
            &key().address().to_string(),
            key().address(),
            Amount::from_sat(20_010),
            Some(Amount::from_sat(1_40000000)),
        )
        .unwrap();
        assert!(plan.acceptable());
        assert_eq!(plan.estimated_out.to_sat(), 1_49165329);
        assert!(node.broadcasts().is_empty());
    }

    /// The native value a conversion of the chain's own currency must carry is
    /// the amount plus the fee. Understating it hands the difference to a miner.
    #[test]
    fn a_native_conversion_carries_amount_plus_fee() {
        let node = chain(1_000, 1);
        let plan = plan_conversion(
            &node,
            VRSCTEST,
            Amount::from_sat(1_50000000),
            shylock(),
            &key().address().to_string(),
            key().address(),
            Amount::from_sat(20_010),
            None,
        )
        .unwrap();
        assert_eq!(
            plan.transfer
                .native_value(currency_of(VRSCTEST).unwrap())
                .unwrap()
                .to_sat(),
            1_50020010
        );
    }

    /// An address with nothing cannot convert, and must say so rather than
    /// building a transaction that fails at broadcast.
    #[test]
    fn an_unfunded_address_is_refused() {
        let node = ScriptedReader::new(1_000).with_estimate(ConversionEstimate {
            estimated_out: Amount::from_sat(1),
            fee: None,
        });
        assert!(matches!(
            convert(
                &node,
                &node,
                &key(),
                VRSCTEST,
                Amount::from_sat(1_50000000),
                shylock(),
                &key().address().to_string(),
                Amount::from_sat(20_010),
                None,
                &[],
            ),
            Err(FlowError::InsufficientFunds { .. })
        ));
    }

    /// A burn asks for no estimate — there is nothing to receive — and it is a
    /// separate function so it cannot be reached by flipping an argument.
    #[test]
    fn a_burn_needs_no_token_it_does_not_hold() {
        let node = chain(1_000, 0);
        // No token inputs for a token burn: refused rather than building a
        // transfer of value that is not there.
        assert!(burn(
            &node,
            &node,
            &key(),
            SHYLOCK,
            Amount::from_sat(1_00000000),
            Amount::from_sat(20_000),
            &[],
        )
        .is_err());
        assert!(node.broadcasts().is_empty());
    }
}
