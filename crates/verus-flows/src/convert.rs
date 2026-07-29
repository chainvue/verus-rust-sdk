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

use crate::broadcast::broadcast;
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
pub fn plan_conversion(
    reader: &impl ChainReader,
    source: &str,
    amount: Amount,
    kind: ConversionKind,
    recipient: &str,
    fee: Amount,
    min_expected: Option<Amount>,
) -> Result<ConversionPlan, FlowError> {
    let info = reader.chain_info()?;
    let chain_currency = currency_of(&info.chain_id)?;
    let source_id = currency_of(source)?;
    let recipient: Address = recipient.parse()?;

    let (to, via) = match &kind {
        ConversionKind::IntoFractional { fractional } => (id_text(*fractional), None),
        ConversionKind::IntoReserve { reserve } => (id_text(*reserve), None),
        ConversionKind::ReserveToReserve { via, target } => (id_text(*target), Some(id_text(*via))),
        ConversionKind::Burn => (source.to_string(), None),
    };

    let estimated_out = if matches!(kind, ConversionKind::Burn) {
        // Nothing comes out of a burn, so there is nothing to estimate.
        Amount::ZERO
    } else {
        estimate(reader, source, &to, amount, via.as_deref())?.estimated_out
    };

    let transfer = build_conversion(
        source_id,
        amount,
        kind,
        recipient,
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
    let plan = plan_conversion(reader, source, amount, kind, recipient, fee, min_expected)?;
    if !plan.acceptable() {
        return Err(FlowError::NotReady(format!(
            "the node expects {} but {} was required",
            plan.estimated_out.to_coins_string(),
            plan.min_expected.unwrap_or(Amount::ZERO).to_coins_string()
        )));
    }
    submit(reader, broadcaster, key, &plan.transfer, token_funding)
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
    let info = reader.chain_info()?;
    let chain_currency = currency_of(&info.chain_id)?;
    let transfer = build_conversion(
        currency_of(currency)?,
        amount,
        ConversionKind::Burn,
        key.address(),
        chain_currency,
        fee,
    )?;
    submit(reader, broadcaster, key, &transfer, token_funding)
}

/// Fund, sign and broadcast a prepared transfer.
fn submit(
    reader: &impl ChainReader,
    broadcaster: &impl Broadcaster,
    key: &PrivateKey,
    transfer: &ReserveTransfer,
    token_funding: &[Utxo],
) -> Result<Sent, FlowError> {
    let info = reader.chain_info()?;
    let chain_currency = currency_of(&info.chain_id)?;
    let from = key.address();
    let funding = funding::spendable(reader, &from.to_string())?;

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

    let signed = build_conversion_transaction(key, &params)?;
    broadcast(broadcaster, &signed.hex, &signed.txid)?;
    Ok(signed.into())
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
