//! Spending funds a VerusID holds.
//!
//! Money paid to an identity sits in CryptoCondition outputs whose destination
//! is the identity itself — the standard pay-to-identity script the chain
//! emits, and the normal place funds live on Verus. Spending one is not a
//! P2PKH signature: the scriptSig is a **fulfillment** carrying signatures by
//! the identity's *primary addresses*, enough of them to meet its `minsigs`,
//! exactly as an identity update is signed.
//!
//! # Authority comes from the identity as it stands on chain
//!
//! The keys that can spend are whatever the identity's current primary
//! addresses are — not the key that registered it, not the key that funded it.
//! This crate cannot look that up offline, so the caller supplies the signing
//! keys and this builder cannot verify they are the right ones. Signing with a
//! stale key builds cleanly and fails at script verification, which reports
//! only that a script finished false. Read the identity first.
//!
//! # Change returns to the identity
//!
//! Every funding output here is spent whole; the surplus goes back as a fresh
//! pay-to-identity output. That is what the daemon does, and it is the safe
//! default: money under an identity's authority should not quietly migrate to
//! a bare key because a builder wanted a simpler change output.

use verus_keys::{Address, AddressKind, PrivateKey};

use verus_tx_primitives::cc::{identity_payment_script, reserve_output_script_to, Destination};
use verus_tx_primitives::fee::DEFAULT_FEE_PER_KB;
use verus_tx_primitives::Amount;
use verus_tx_primitives::CurrencyId;
use verus_tx_primitives::Expiry;
use verus_tx_primitives::TxError;
use verus_tx_primitives::Utxo;
use verus_tx_transparent::assemble::{assemble, Assembly};
use verus_tx_transparent::{Recipient, SignedTransaction};

/// What to build.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct IdentitySpendParams<'a> {
    /// The identity whose funds are being spent — its 20-byte `i` hash.
    pub identity: [u8; 20],
    /// Outputs the identity holds. Each must be the standard pay-to-identity
    /// script for `identity`; anything else is refused before signing.
    pub identity_utxos: &'a [Utxo],
    /// Who gets paid. `R` addresses and `i` addresses both work.
    pub recipients: &'a [Recipient],
    /// When the transaction stops being minable.
    pub expiry: Expiry,
    /// Fee rate in satoshis per kilobyte.
    pub fee_per_kb: u64,
}

impl<'a> IdentitySpendParams<'a> {
    /// A spend of `identity`'s funds to `recipients`.
    pub fn new(
        identity: [u8; 20],
        identity_utxos: &'a [Utxo],
        recipients: &'a [Recipient],
        expiry: Expiry,
    ) -> Self {
        Self {
            identity,
            identity_utxos,
            recipients,
            expiry,
            fee_per_kb: DEFAULT_FEE_PER_KB,
        }
    }

    /// Override the fee rate.
    pub fn with_fee_per_kb(mut self, fee_per_kb: u64) -> Self {
        self.fee_per_kb = fee_per_kb;
        self
    }
}

/// Build and sign a spend of identity-held funds.
///
/// `keys` are the identity's primary keys — as many as its `minsigs` demands,
/// all signed into one fulfillment per input. The surplus returns to the
/// identity as change; the miner fee comes out of the identity's funds.
pub fn build_identity_spend(
    keys: &[&PrivateKey],
    params: &IdentitySpendParams<'_>,
) -> Result<SignedTransaction, TxError> {
    params.expiry.check()?;
    if keys.is_empty() {
        return Err(TxError::NoSignatures);
    }
    if params.recipients.is_empty() {
        return Err(TxError::NoOutputs);
    }
    if params.identity_utxos.is_empty() {
        return Err(TxError::InsufficientFunds {
            // #194: this sum used to be a raw `u64` `.sum()`, so recipients
            // whose total exceeds `u64::MAX` reported a wrapped — and therefore
            // misleading — `required` (and panicked in a debug build). It stays
            // best-effort rather than a hard `ValueOverflow`: the failure here
            // is the empty UTXO set, not the arithmetic, and `u64::MAX` is the
            // honest "more than everything". Matches #166's `available`
            // handling in `fee.rs::select_utxos`.
            required: Amount::checked_sum(params.recipients.iter().map(|r| r.satoshis))
                .map(Amount::to_sat)
                .unwrap_or(u64::MAX),
            available: 0,
        });
    }

    // Refuse anything that is not this identity's own payment script. A UTXO
    // holding some other script — another identity's, a token's, a P2PKH —
    // would sign but not verify, or worse, move value this builder cannot see.
    let identity_script = identity_payment_script(params.identity)?;
    for utxo in params.identity_utxos {
        if utxo.script_pubkey != identity_script {
            return Err(TxError::IdentityOutputMismatch);
        }
    }

    let outputs = params
        .recipients
        .iter()
        .enumerate()
        .map(|(index, recipient)| {
            if recipient.satoshis == Amount::ZERO {
                return Err(TxError::ZeroValueOutput { index });
            }
            let script = match recipient.address.kind() {
                AddressKind::PubKeyHash => recipient.address.p2pkh_script_pubkey()?,
                AddressKind::Identity => identity_payment_script(recipient.address.hash())?,
                _ => return Err(TxError::UnsupportedRecipient),
            };
            Ok(verus_wire::TxOut {
                value: recipient.satoshis.to_sat(),
                script_pubkey: script,
            })
        })
        .collect::<Result<Vec<_>, TxError>>()?;
    let output_count = outputs.len() as u64 + 1;

    // The change address below is never used — change carries the identity's
    // own script — but Assembly wants one, and the first key's address is the
    // honest fallback if that ever changes.
    let fallback_change: Address = keys[0].address();
    assemble(
        keys[0],
        keys,
        Assembly {
            leading: params.identity_utxos,
            funding: &[],
            outputs,
            burn: Amount::ZERO,
            fee_output_count: output_count,
            change_address: &fallback_change,
            change_script: Some(identity_script),
            value_bearing_leading: true,
            expiry: params.expiry,
            fee_per_kb: params.fee_per_kb,
        },
    )
}

/// What to build for a **token** an identity holds.
///
/// The token counterpart of [`IdentitySpendParams`], and separate from it for
/// a reason that only shows up in the outputs: a token an identity holds is a
/// *reserve output* paying the identity, and a reserve output carries **no
/// native value**. `aaa@` on VRSCTEST holds 1,000,000,000 units in an output
/// whose satoshi value is zero.
///
/// So this spend cannot pay its own miner fee the way a native identity spend
/// does. It needs two kinds of input at once — the identity's token outputs
/// for the value, signed by a fulfillment, and ordinary coins for the fee,
/// signed by a key. That is why `fee_funding` exists here and has no
/// counterpart on the native params.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct IdentityTokenSpendParams<'a> {
    /// The identity holding the token — its 20-byte `i` hash.
    pub identity: [u8; 20],
    /// The token being moved.
    pub currency: CurrencyId,
    /// Reserve outputs paying `identity` and carrying `currency`. Each is
    /// spent whole and the surplus returns to the identity.
    pub identity_utxos: &'a [Utxo],
    /// P2PKH coins belonging to `fee_key`, to pay the miner fee.
    ///
    /// Not optional in practice: the token outputs carry no satoshis, so
    /// without these there is nothing to pay a fee with.
    pub fee_funding: &'a [Utxo],
    /// Who receives the token, and how much.
    pub recipient: Address,
    /// How much of `currency` to send.
    pub amount: Amount,
    /// Where native change from `fee_funding` returns.
    pub change_address: Address,
    /// When the transaction stops being minable.
    pub expiry: Expiry,
    /// Fee rate in satoshis per kilobyte.
    pub fee_per_kb: u64,
}

impl<'a> IdentityTokenSpendParams<'a> {
    /// A token spend of `identity`'s holdings.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: [u8; 20],
        currency: CurrencyId,
        identity_utxos: &'a [Utxo],
        fee_funding: &'a [Utxo],
        recipient: Address,
        amount: Amount,
        change_address: Address,
        expiry: Expiry,
    ) -> Self {
        Self {
            identity,
            currency,
            identity_utxos,
            fee_funding,
            recipient,
            amount,
            change_address,
            expiry,
            fee_per_kb: DEFAULT_FEE_PER_KB,
        }
    }

    /// Override the fee rate.
    pub fn with_fee_per_kb(mut self, fee_per_kb: u64) -> Self {
        self.fee_per_kb = fee_per_kb;
        self
    }
}

/// Move a token an identity holds.
///
/// `keys` are the identity's primary keys, meeting its `minsigs` — the same
/// authority a native identity spend needs. `fee_key` owns
/// [`IdentityTokenSpendParams::fee_funding`] and signs those inputs
/// ordinarily.
///
/// # Why this exists
///
/// A token's supply is the sum of its `preallocations`, and a preallocation
/// names an **identity**. For a currency that cannot be minted every unit that
/// will ever exist is created at launch into an identity-held output and never
/// passes through a key-held address. Without this, that supply cannot move:
/// the key-signed token path refuses an identity-held reserve output by
/// design, and the identity-funded path only ever accepted the plain
/// pay-to-identity script.
///
/// # Token change returns to the identity
///
/// Every token input is spent whole and the remainder comes back as a reserve
/// output paying the identity, for the same reason native change does: money
/// under an identity's authority must not migrate to a bare key because a
/// builder wanted a simpler output. Native change from `fee_funding` goes to
/// `change_address`, because that is the fee payer's own money.
pub fn build_identity_token_spend(
    keys: &[&PrivateKey],
    fee_key: &PrivateKey,
    params: &IdentityTokenSpendParams<'_>,
) -> Result<SignedTransaction, TxError> {
    params.expiry.check()?;
    if keys.is_empty() {
        return Err(TxError::NoSignatures);
    }
    if params.amount == Amount::ZERO {
        return Err(TxError::ZeroValueOutput { index: 0 });
    }
    if params.identity_utxos.is_empty() {
        return Err(TxError::InsufficientTokens {
            currency: hex::encode(params.currency.to_bytes()),
            missing: params.amount.to_sat(),
        });
    }

    // Every input must be a reserve output paying THIS identity and carrying
    // exactly this currency. A multi-currency input is refused rather than
    // spent: the others would have to come back as change too, and silently
    // destroying them is the failure worth designing out.
    let mut held: u64 = 0;
    for utxo in params.identity_utxos {
        match verus_tx_protocol::decode::decode_output_script(&utxo.script_pubkey)? {
            verus_tx_protocol::decode::OutputKind::ReserveOutput {
                tokens,
                destination,
            } => {
                if destination != Destination::Identity(params.identity) {
                    return Err(TxError::IdentityOutputMismatch);
                }
                if tokens.len() != 1 || tokens[0].0 != params.currency {
                    return Err(TxError::InvalidConversion(
                        "a token input does not carry exactly the currency being sent".into(),
                    ));
                }
                held = held
                    .checked_add(tokens[0].1)
                    .ok_or(TxError::ValueOverflow)?;
            }
            _ => return Err(TxError::IdentityOutputMismatch),
        }
    }

    let change =
        held.checked_sub(params.amount.to_sat())
            .ok_or_else(|| TxError::InsufficientTokens {
                currency: hex::encode(params.currency.to_bytes()),
                missing: params.amount.to_sat().saturating_sub(held),
            })?;

    let to = match params.recipient.kind() {
        AddressKind::PubKeyHash => Destination::PubKeyHash(params.recipient.hash()),
        AddressKind::Identity => Destination::Identity(params.recipient.hash()),
        _ => return Err(TxError::UnsupportedRecipient),
    };
    let mut outputs = vec![verus_wire::TxOut {
        value: 0,
        script_pubkey: reserve_output_script_to(to, params.currency, params.amount.to_sat())?,
    }];
    if change > 0 {
        outputs.push(verus_wire::TxOut {
            value: 0,
            script_pubkey: reserve_output_script_to(
                Destination::Identity(params.identity),
                params.currency,
                change,
            )?,
        });
    }
    let output_count = outputs.len() as u64 + 1;

    assemble(
        fee_key,
        keys,
        Assembly {
            // Identity-signed, by a fulfillment.
            leading: params.identity_utxos,
            // Key-signed, and the only source of native value here.
            funding: params.fee_funding,
            outputs,
            burn: Amount::ZERO,
            fee_output_count: output_count,
            change_address: &params.change_address,
            change_script: None,
            // The token outputs carry no satoshis, so the leading inputs bring
            // no native value to the fee arithmetic. Saying otherwise would
            // credit the fee with money that is not there.
            value_bearing_leading: false,
            expiry: params.expiry,
            fee_per_kb: params.fee_per_kb,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use verus_tx_primitives::fee::{DUST_THRESHOLD, MIN_FEE};
    use verus_tx_primitives::Txid;
    use verus_tx_protocol::decode::{decode_output_script, OutputKind};
    use verus_wire::TxV4;

    const TEST_WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";

    fn key() -> PrivateKey {
        PrivateKey::from_wif(TEST_WIF).unwrap()
    }

    fn identity() -> [u8; 20] {
        [0x42; 20]
    }

    fn held(satoshis: u64, vout: u32) -> Utxo {
        Utxo {
            txid: Txid::from_display_hex(
                "59a1097f1162b8dfd7037b5933d7156700bb0fe4230f14f003ba5f1c087206b3",
            )
            .unwrap(),
            vout,
            satoshis: Amount::from_sat(satoshis),
            script_pubkey: identity_payment_script(identity()).unwrap(),
        }
    }

    const TOKEN: CurrencyId = CurrencyId::from_bytes([0x5c; 20]);

    fn token_held(currency: CurrencyId, amount: u64, vout: u32) -> Utxo {
        Utxo {
            txid: Txid::from_display_hex(
                "59a1097f1162b8dfd7037b5933d7156700bb0fe4230f14f003ba5f1c087206b3",
            )
            .unwrap(),
            vout,
            // Zero, as every reserve output is — the reason a fee key exists.
            satoshis: Amount::ZERO,
            script_pubkey: reserve_output_script_to(
                Destination::Identity(identity()),
                currency,
                amount,
            )
            .unwrap(),
        }
    }

    fn fee_coin() -> Utxo {
        Utxo {
            txid: Txid::from_internal([0xbb; 32]),
            vout: 0,
            satoshis: Amount::from_sat(100_000_000),
            script_pubkey: key().address().p2pkh_script_pubkey().unwrap(),
        }
    }

    /// The builder is public, so its checks have to hold against a caller who
    /// passes the wrong thing — the flow filters by currency before it gets
    /// here, which means nothing else exercises this.
    #[test]
    fn an_input_carrying_another_currency_is_refused() {
        let wrong = token_held(CurrencyId::from_bytes([0x9d; 20]), 1_000, 0);
        let fee = [fee_coin()];
        let inputs = [wrong];
        let params = IdentityTokenSpendParams::new(
            identity(),
            TOKEN,
            &inputs,
            &fee,
            key().address(),
            Amount::from_sat(1),
            key().address(),
            Expiry::AtHeight(1_170_820),
        );
        assert!(matches!(
            build_identity_token_spend(&[&key()], &key(), &params),
            Err(TxError::InvalidConversion(_))
        ));
    }

    /// An output paying a different identity is refused before signing.
    #[test]
    fn an_input_paying_another_identity_is_refused() {
        let theirs = Utxo {
            script_pubkey: reserve_output_script_to(
                Destination::Identity([0xc7; 20]),
                TOKEN,
                1_000,
            )
            .unwrap(),
            ..token_held(TOKEN, 1_000, 0)
        };
        let fee = [fee_coin()];
        let inputs = [theirs];
        let params = IdentityTokenSpendParams::new(
            identity(),
            TOKEN,
            &inputs,
            &fee,
            key().address(),
            Amount::from_sat(1),
            key().address(),
            Expiry::AtHeight(1_170_820),
        );
        assert!(matches!(
            build_identity_token_spend(&[&key()], &key(), &params),
            Err(TxError::IdentityOutputMismatch)
        ));
    }

    fn recipient(satoshis: u64) -> Recipient {
        Recipient {
            address: "RJGYC29RTSGQbWMrstQziJxfQaiDCjm5iP".parse().unwrap(),
            satoshis: Amount::from_sat(satoshis),
        }
    }

    /// The whole shape: identity inputs spent whole, recipient paid, surplus
    /// back to the identity itself, exact conservation.
    #[test]
    fn spends_identity_funds_and_returns_change_to_the_identity() {
        let utxos = [held(1_00000000, 0), held(50000000, 1)];
        let recipients = [recipient(60000000)];
        let params = IdentitySpendParams::new(identity(), &utxos, &recipients, Expiry::Never);
        let signed = build_identity_spend(&[&key()], &params).unwrap();

        let tx = TxV4::deserialize(&hex::decode(&signed.hex).unwrap()).unwrap();
        assert_eq!(tx.inputs.len(), 2, "both identity outputs are spent");
        assert_eq!(tx.outputs.len(), 2, "recipient plus identity change");

        // Output 0 pays the recipient as plain P2PKH.
        assert_eq!(tx.outputs[0].value, 60000000);

        // Output 1 is the change, carrying the identity's OWN script.
        assert_eq!(
            tx.outputs[1].script_pubkey,
            identity_payment_script(identity()).unwrap()
        );

        // Exact conservation: inputs − outputs = fee.
        let inputs: u64 = 1_50000000;
        let outputs: u64 = tx.outputs.iter().map(|o| o.value).sum();
        assert_eq!(inputs - outputs, signed.fee.to_sat());

        // Every input's scriptSig is a fulfillment, not a P2PKH signature:
        // one push of [version=1, hash_type, count, entries…]. Consensus
        // insists the fulfillment's own hash type is SIGHASH_ALL
        // (`CheckIdentitySpends` skips anything else), so pin those bytes,
        // after whichever push encoding the length demanded.
        for input in &tx.inputs {
            let data = match input.script_sig.as_slice() {
                [0x4c, _, rest @ ..] => rest,
                [op, rest @ ..] if *op < 0x4c => rest,
                other => panic!("not a single push: {other:02x?}"),
            };
            assert_eq!(data[0], 1, "SmartTransactionSignatures v1");
            assert_eq!(data[1], 0x01, "SIGHASH_ALL, stated inline");
        }
    }

    /// A recipient that is itself an identity gets a pay-to-identity output.
    #[test]
    fn pays_an_identity_recipient_with_the_identity_script() {
        let utxos = [held(1_00000000, 0)];
        let other = Address::new(AddressKind::Identity, [0x77; 20]);
        let recipients = [Recipient {
            address: other,
            satoshis: Amount::from_sat(10000000),
        }];
        let params = IdentitySpendParams::new(identity(), &utxos, &recipients, Expiry::Never);
        let signed = build_identity_spend(&[&key()], &params).unwrap();
        let tx = TxV4::deserialize(&hex::decode(&signed.hex).unwrap()).unwrap();
        assert_eq!(
            tx.outputs[0].script_pubkey,
            identity_payment_script([0x77; 20]).unwrap()
        );
    }

    /// A UTXO carrying any other script is refused before signing — another
    /// identity's, a P2PKH, anything.
    #[test]
    fn refuses_a_utxo_that_is_not_this_identitys() {
        let mut wrong = held(1_00000000, 0);
        wrong.script_pubkey = identity_payment_script([0x99; 20]).unwrap();
        let utxos = [wrong];
        let recipients = [recipient(10000000)];
        let params = IdentitySpendParams::new(identity(), &utxos, &recipients, Expiry::Never);
        assert!(matches!(
            build_identity_spend(&[&key()], &params),
            Err(TxError::IdentityOutputMismatch)
        ));
    }

    /// Not enough identity funds to cover recipient plus fee.
    #[test]
    fn refuses_insufficient_identity_funds() {
        let utxos = [held(10000000, 0)];
        let recipients = [recipient(9999999)];
        let params = IdentitySpendParams::new(identity(), &utxos, &recipients, Expiry::Never);
        assert!(matches!(
            build_identity_spend(&[&key()], &params),
            Err(TxError::InsufficientFunds { .. })
        ));
    }

    /// Change at or below dust folds into the fee instead of creating an
    /// output nobody would relay.
    #[test]
    fn folds_dust_change_into_the_fee() {
        let amount = 10000000;
        let utxos = [held(amount + MIN_FEE + DUST_THRESHOLD, 0)];
        let recipients = [recipient(amount)];
        let params = IdentitySpendParams::new(identity(), &utxos, &recipients, Expiry::Never);
        let signed = build_identity_spend(&[&key()], &params).unwrap();
        let tx = TxV4::deserialize(&hex::decode(&signed.hex).unwrap()).unwrap();
        assert_eq!(
            tx.outputs.len(),
            1,
            "dust change becomes fee, not an output"
        );
        assert_eq!(signed.fee.to_sat(), MIN_FEE + DUST_THRESHOLD);
    }

    /// The change output decodes as an identity destination, so a wallet
    /// scanning its own transaction sees where the money went.
    #[test]
    fn change_decodes_as_the_identity() {
        let utxos = [held(1_00000000, 0)];
        let recipients = [recipient(10000000)];
        let params = IdentitySpendParams::new(identity(), &utxos, &recipients, Expiry::Never);
        let signed = build_identity_spend(&[&key()], &params).unwrap();
        let tx = TxV4::deserialize(&hex::decode(&signed.hex).unwrap()).unwrap();
        match decode_output_script(&tx.outputs[1].script_pubkey).unwrap() {
            OutputKind::IdentityPayment { identity: id } => assert_eq!(id, identity()),
            other => panic!("change is not an identity payment: {other:?}"),
        }
    }

    /// Guard-rails: no keys, no recipients, no funds.
    #[test]
    fn refuses_empty_inputs() {
        let utxos = [held(1_00000000, 0)];
        let recipients = [recipient(10000000)];
        let params = IdentitySpendParams::new(identity(), &utxos, &recipients, Expiry::Never);
        assert!(matches!(
            build_identity_spend(&[], &params),
            Err(TxError::NoSignatures)
        ));

        let no_recipients = IdentitySpendParams::new(identity(), &utxos, &[], Expiry::Never);
        assert!(matches!(
            build_identity_spend(&[&key()], &no_recipients),
            Err(TxError::NoOutputs)
        ));

        let no_funds = IdentitySpendParams::new(identity(), &[], &recipients, Expiry::Never);
        assert!(matches!(
            build_identity_spend(&[&key()], &no_funds),
            Err(TxError::InsufficientFunds { .. })
        ));
    }

    /// #194: recipients whose total exceeds `u64::MAX` must not be reported
    /// back as a wrapped `required` — and must not panic in a debug build,
    /// which is what the unchecked sum did here.
    ///
    /// The error itself is still `InsufficientFunds`: the failure is the empty
    /// UTXO set, not the arithmetic. `u64::MAX` is the honest "more than
    /// everything", the same answer `select_utxos` gives for an overflowing
    /// `available`.
    #[test]
    fn an_overflowing_recipient_total_is_reported_as_more_than_everything() {
        // Derived from `u64::MAX`, not pinned.
        let offset: u64 = 1_000_000;
        let (first, second) = (u64::MAX - offset, offset + 1);
        assert!(
            first.checked_add(second).is_none(),
            "the fixture has to actually overflow u64"
        );
        assert_eq!(first.wrapping_add(second), 0, "an unchecked sum reports 0");

        let recipients = [recipient(first), recipient(second)];
        let params = IdentitySpendParams::new(identity(), &[], &recipients, Expiry::Never);
        match build_identity_spend(&[&key()], &params) {
            Err(TxError::InsufficientFunds {
                required,
                available,
            }) => {
                assert_eq!(required, u64::MAX, "saturated, not wrapped");
                assert_eq!(available, 0, "the identity holds nothing");
            }
            other => panic!("expected InsufficientFunds, got {other:?}"),
        }
    }
}
