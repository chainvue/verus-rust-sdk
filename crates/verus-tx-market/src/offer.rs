//! On-chain marketplace orders: making an offer and taking one.
//!
//! This is Verus's `makeoffer`/`takeoffer` mechanism — a decentralized
//! marketplace order settled atomically in one transaction. It is *not* an
//! "atomic swap" in the cross-chain HTLC sense: both legs live on this chain.
//!
//! An offer is a **half-signed transaction**. The maker signs an input that
//! gives something away, paired with one output that says what they want back,
//! under `SIGHASH_SINGLE | ANYONECANPAY`. That hash type commits to exactly two
//! things — this input, and the output at the same index — so a taker can add
//! their own inputs and outputs without invalidating the maker's signature.
//!
//! ```text
//! maker signs        input 0  (what I give)      output 0  (what I want, paid to me)
//! taker completes  + input 1… (what I pay with) + output 1… (what I take, paid to them)
//! ```
//!
//! Neither side can be cheated. The maker's signature is void if output 0 is
//! altered, so the taker cannot pay less. The taker builds and broadcasts the
//! final transaction, so they see exactly what they are getting before it exists.
//! Nothing is escrowed and no third party is involved.
//!
//! # The offered funds sit in a commitment output first
//!
//! An offer cannot spend an ordinary P2PKH output, because a maker must be able
//! to publish a signature over an input whose *other* spends they do not
//! control. The funds move into a CryptoCondition output first — one paying
//! [`offer_funding_script`] — and the offer spends that.
//!
//! Reproduced from `makeoffer` on VRSCTEST, which uses the same eval code as a
//! name commitment with an **all-zero** payload. That surprised me enough to
//! check twice: two offers built minutes apart both carried 32 zero bytes, so
//! the field is a placeholder rather than a hash of the terms. Nothing about the
//! trade is committed to by the funding output — the terms live entirely in the
//! maker's signature.
//!
//! # An offer is a standing authorisation until it is spent or expires
//!
//! There is no cancel message. A maker who changes their mind must **spend the
//! funding output themselves**, which invalidates the offer by consuming what it
//! was going to give away. Until then, anyone holding the half-signed
//! transaction may complete it. Set [`OfferParams::expiry`] and mean it.
//!
//! # What a taker must check, and this crate cannot
//!
//! [`take_offer`] builds what the maker asked for. It cannot tell you whether
//! the trade is a good one, and — more importantly — it cannot tell you the
//! maker's funding output still exists. That value lives in an outpoint, not in
//! the offer, so [`TakeParams::offered_value`] is taken on trust from the
//! caller. **Look the outpoint up before completing.** A maker who spent it
//! after publishing leaves an offer that costs you a fee to discover.

use verus_keys::PrivateKey;
use verus_wire::consensus::{SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_SINGLE, VERUS_BRANCH_ID};
use verus_wire::{TxIn, TxOut, TxV4};

use verus_tx_primitives::cc::EVAL_IDENTITY_COMMITMENT;
use verus_tx_primitives::cc::{
    cc_script, fulfillment_script_sig, Destination, OptCcParams, EVAL_NONE,
};
use verus_tx_primitives::Amount;
use verus_tx_primitives::Expiry;
use verus_tx_primitives::TxError;
use verus_tx_primitives::Txid;
use verus_tx_primitives::Utxo;

/// The hash type an offer's input is signed under.
///
/// `SIGHASH_SINGLE | ANYONECANPAY`. Taken from a real `makeoffer` transaction,
/// where it appears as the byte `0x83` in the fulfillment.
pub const OFFER_HASH_TYPE: u32 = SIGHASH_SINGLE | SIGHASH_ANYONECANPAY;

/// The output script that holds funds while they are on offer.
///
/// A CryptoCondition locked to `control`, carrying the all-zero payload the
/// daemon writes. Spendable only by `control` — until the maker signs an offer
/// over it, at which point anyone may spend it *on the maker's terms*.
pub fn offer_funding_script(control: [u8; 20]) -> Result<Vec<u8>, TxError> {
    let destination = Destination::PubKeyHash(control);
    let master = OptCcParams::one_of_one(EVAL_NONE, destination.clone());
    let params = OptCcParams {
        // Not a hash of anything: the daemon writes 32 zero bytes here.
        vdata: vec![vec![0u8; 32]],
        ..OptCcParams::one_of_one(EVAL_IDENTITY_COMMITMENT, destination)
    };
    cc_script(&master, &params)
}

/// What the maker wants in return.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Wanted {
    /// Native coins, paid to the maker's address.
    Native {
        /// How much.
        amount: Amount,
        /// Where it goes.
        recipient: [u8; 20],
    },
    /// A token, paid to the maker's address as a reserve output.
    Token {
        /// Which token.
        currency: verus_tx_primitives::CurrencyId,
        /// How much.
        amount: Amount,
        /// Where it goes.
        recipient: [u8; 20],
    },
}

impl Wanted {
    /// The single output the maker's signature commits to.
    fn to_output(&self) -> Result<TxOut, TxError> {
        Ok(match self {
            Wanted::Native { amount, recipient } => TxOut {
                value: amount.to_sat(),
                script_pubkey: verus_keys::Address::new(
                    verus_keys::AddressKind::PubKeyHash,
                    *recipient,
                )
                .p2pkh_script_pubkey()
                .map_err(TxError::from)?,
            },
            Wanted::Token {
                currency,
                amount,
                recipient,
            } => TxOut {
                value: 0,
                script_pubkey: verus_tx_primitives::cc::reserve_output_script(
                    *recipient,
                    *currency,
                    amount.to_sat(),
                )?,
            },
        })
    }
}

/// What to build.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct OfferParams<'a> {
    /// The funding output holding what is being offered.
    ///
    /// Must be an [`offer_funding_script`] output controlled by the signing key.
    pub funding: &'a Utxo,
    /// What the maker wants in return.
    pub wanted: Wanted,
    /// When the offer stops being completable.
    ///
    /// **Not optional in practice.** An offer with no expiry is a standing
    /// authorisation that only spending the funding output revokes.
    pub expiry: Expiry,
}

impl<'a> OfferParams<'a> {
    /// An offer of the funding output for `wanted`.
    ///
    /// `expiry` has no default on purpose: an offer that never expires is a
    /// standing authorisation revocable only by spending the funding output.
    pub fn new(funding: &'a Utxo, wanted: Wanted, expiry: Expiry) -> Self {
        Self {
            funding,
            wanted,
            expiry,
        }
    }
}

/// A half-signed offer, waiting for a taker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedOffer {
    /// The partial transaction, serialized. Not broadcastable as it stands: it
    /// does not balance until a taker completes it.
    pub hex: String,
    /// What the maker gives up.
    pub offered: Amount,
    /// The outpoint the offer spends.
    pub funding_outpoint: (Txid, u32),
}

/// Move funds into an output that can back an offer.
///
/// An offer cannot be signed over an ordinary P2PKH output, so this is the step
/// before [`make_offer`]: an ordinary transaction whose first output pays
/// [`offer_funding_script`] for the signing key.
///
/// The resulting output is spendable by nobody but the key — until an offer is
/// signed over it, at which point anyone may spend it *on the maker's terms*.
pub fn fund_offer(
    key: &PrivateKey,
    utxos: &[Utxo],
    amount: Amount,
    change_address: &verus_keys::Address,
    expiry: Expiry,
    fee_per_kb: u64,
) -> Result<verus_tx_transparent::SignedTransaction, TxError> {
    expiry.check()?;
    if amount == Amount::ZERO {
        return Err(TxError::InvalidOffer(
            "an offer of nothing cannot be taken".into(),
        ));
    }
    verus_tx_transparent::assemble::assemble(
        key,
        &[],
        verus_tx_transparent::assemble::Assembly {
            leading: &[],
            funding: utxos,
            outputs: vec![TxOut {
                value: amount.to_sat(),
                script_pubkey: offer_funding_script(key.address().hash())?,
            }],
            burn: Amount::ZERO,
            fee_output_count: 2,
            change_address,
            change_script: None,
            value_bearing_leading: false,
            expiry,
            fee_per_kb,
        },
    )
}

/// Sign an offer.
///
/// The result does **not** balance and must not be broadcast as it is; that is
/// the point. Publish it, and a taker completes it with [`take_offer`].
pub fn make_offer(key: &PrivateKey, params: &OfferParams<'_>) -> Result<SignedOffer, TxError> {
    params.expiry.check()?;

    let expected = offer_funding_script(key.address().hash())?;
    if params.funding.script_pubkey != expected {
        return Err(TxError::InvalidOffer(
            "the funding output is not an offer commitment controlled by this key".into(),
        ));
    }

    let mut transaction = TxV4 {
        inputs: vec![TxIn::unsigned(
            params.funding.txid.to_internal(),
            params.funding.vout,
            0xffff_ffff,
        )],
        outputs: vec![params.wanted.to_output()?],
        lock_time: 0,
        expiry_height: params.expiry.to_height(),
        value_balance: 0,
        shielded_spends: Vec::new(),
        shielded_outputs: Vec::new(),
        binding_sig: None,
    };

    // SIGHASH_SINGLE pairs input 0 with output 0, and ANYONECANPAY frees every
    // other input. Together they are what makes this completable by a stranger.
    let sighash = transaction
        .transparent_sighash(
            VERUS_BRANCH_ID,
            0,
            &params.funding.script_pubkey,
            params.funding.satoshis.to_sat(),
            OFFER_HASH_TYPE,
        )
        .map_err(TxError::from)?;

    let signature = key.sign_prehash_compact(&sighash)?;
    let hash_type = u8::try_from(OFFER_HASH_TYPE)
        .map_err(|_| TxError::InvalidOffer("the offer hash type does not fit a byte".into()))?;
    transaction.inputs[0].script_sig =
        fulfillment_script_sig(&[(key.public_key().to_bytes(), signature)], hash_type)?;

    Ok(SignedOffer {
        hex: hex::encode(transaction.serialize().map_err(TxError::from)?),
        offered: params.funding.satoshis,
        funding_outpoint: (params.funding.txid, params.funding.vout),
    })
}

/// What a taker adds to complete an offer.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct TakeParams<'a> {
    /// The maker's half-signed transaction.
    pub offer: &'a str,
    /// The taker's funding, paying what the maker asked for plus the miner fee.
    pub utxos: &'a [Utxo],
    /// Where the offered funds go.
    pub recipient: [u8; 20],
    /// Where the taker's change goes.
    pub change_address: verus_keys::Address,
    /// What the maker's funding output is worth.
    ///
    /// **The taker must verify this on chain**, and this crate cannot: the value
    /// lives in an outpoint, not in the offer. Take the maker's word for it and
    /// you may pay for an output that is already spent or never held what was
    /// claimed.
    pub offered_value: Amount,
    /// The miner fee, in satoshis. Paid by the taker.
    pub fee: u64,
}

impl<'a> TakeParams<'a> {
    /// What a taker supplies to complete an offer.
    pub fn new(
        offer: &'a str,
        utxos: &'a [Utxo],
        recipient: [u8; 20],
        change_address: verus_keys::Address,
        offered_value: Amount,
        fee: u64,
    ) -> Self {
        Self {
            offer,
            utxos,
            recipient,
            change_address,
            offered_value,
            fee,
        }
    }
}

/// Complete an offer and produce a broadcastable transaction.
///
/// The maker's input and output are left **exactly** as they are — altering
/// either voids their signature — and the taker's inputs and outputs are
/// appended after them.
///
/// Native and token demands are both funded. A token demand is paid from
/// reserve inputs among `utxos`, with surplus returned as token change — and a
/// reserve input is unlocked by a CryptoCondition fulfillment rather than a
/// P2PKH `scriptSig`, which this handles. Supplying no tokens for a token demand
/// is refused with the shortfall named, rather than built into a transaction
/// that fails to conserve them.
///
/// # What a taker must check first
///
/// This builds what the maker asked for. It does not judge whether the trade is
/// a good one, and it cannot: the value the maker is giving comes from an
/// outpoint that must be looked up on chain. Verify that outpoint yourself
/// before completing, or you may pay for something already spent.
pub fn take_offer(key: &PrivateKey, params: &TakeParams<'_>) -> Result<Vec<u8>, TxError> {
    let bytes = hex::decode(params.offer)
        .map_err(|e| TxError::InvalidOffer(format!("offer is not hex: {e}")))?;
    let offer = TxV4::deserialize(&bytes).map_err(TxError::from)?;

    // What a maker's half-signed offer must look like. Anything else is not an
    // offer, and completing it would sign something whose shape is unknown.
    if offer.inputs.len() != 1 || offer.outputs.len() != 1 {
        return Err(TxError::InvalidOffer(format!(
            "an offer has one input and one output, this has {} and {}",
            offer.inputs.len(),
            offer.outputs.len()
        )));
    }
    // The hash type sits in the fulfillment: PUSH(version, hash_type, …). If it
    // is not SIGHASH_SINGLE|ANYONECANPAY then the maker's signature covers more
    // than their own input and output, and appending to it would void it.
    let fulfillment = &offer.inputs[0].script_sig;
    let hash_type = fulfillment
        .iter()
        .position(|b| *b == 0x01)
        .and_then(|start| fulfillment.get(start + 1).copied())
        .ok_or_else(|| TxError::InvalidOffer("the offer input has no fulfillment".into()))?;
    if u32::from(hash_type) != OFFER_HASH_TYPE {
        return Err(TxError::InvalidOffer(format!(
            "the offer is signed under hash type {hash_type:#x}, not {OFFER_HASH_TYPE:#x}; \
             adding to it would void the maker's signature"
        )));
    }

    // The maker's input and output are carried over untouched, in place. Their
    // signature covers input 0 paired with output 0, so neither may move.
    let mut transaction = offer;

    // What the taker receives: the whole offered value. The miner fee comes out
    // of the taker's own funding below — charging it here as well would take it
    // twice, which is exactly the bug the conservation test caught.
    transaction.outputs.push(TxOut {
        value: params.offered_value.to_sat(),
        script_pubkey: verus_keys::Address::new(
            verus_keys::AddressKind::PubKeyHash,
            params.recipient,
        )
        .p2pkh_script_pubkey()
        .map_err(TxError::from)?,
    });

    // What the taker pays: whatever output 0 demands, funded from their own
    // coins.
    //
    // What the maker demands, decided per output shape — every variant
    // deliberately, because the wrong default in either direction is a bug
    // this crate has already made once each way.
    //
    // A decode failure must PROPAGATE rather than default to "no demand": that
    // is the "unreadable smart output becomes native-only" reclassification
    // decode.rs forbids, and here it would let a token demand this crate
    // cannot read fall through as a free trade.
    //
    // But refusing everything that is not a bare `PubKeyHash` is too strict in
    // the other direction: a daemon `makeoffer` demanding native payment to
    // the maker's **i-address** is an ordinary shape — arguably the common one
    // on Verus — and it is native value only, exactly as fully understood as a
    // key-hash payment. The native side is accounted from `outputs[0].value`
    // whatever the script shape, so both carry no token demand.
    let token_demand = match verus_tx_protocol::decode::decode_output_script(
        &transaction.outputs[0].script_pubkey,
    )? {
        // Value in the payload, nothing native: the token side, accounted
        // separately below.
        verus_tx_protocol::decode::OutputKind::ReserveOutput { tokens, .. } => tokens,
        // Native value only. Paying a key or paying an identity differ in
        // who can spend the output, not in what is being asked for.
        verus_tx_protocol::decode::OutputKind::PubKeyHash { .. }
        | verus_tx_protocol::decode::OutputKind::IdentityPayment { .. } => Vec::new(),
        // An output that HOLDS an identity is not a payment at all, and an
        // eval code this crate cannot decode may carry value it cannot
        // see. Neither is a demand `take_offer` can honour.
        other => {
            return Err(TxError::InvalidOffer(format!(
                "the offer's demand output is not a shape this crate can account for: \
                     {other:?}"
            )))
        }
    };

    let mut balances = verus_tx_protocol::token::Balances::default();
    for (currency, amount) in &token_demand {
        balances.add_required(*currency, *amount);
    }

    // Decode the taker's coins once: their tokens fund the demand, and whether
    // each is a CryptoCondition decides how it must be signed.
    let mut taker_inputs = Vec::with_capacity(params.utxos.len());
    for utxo in params.utxos {
        let (tokens, is_cryptocondition) =
            match verus_tx_protocol::decode::decode_output_script(&utxo.script_pubkey)? {
                verus_tx_protocol::decode::OutputKind::ReserveOutput {
                    tokens,
                    destination,
                } => {
                    verus_tx_protocol::token::reject_unspendable_reserve(utxo, &destination)?;
                    (tokens, true)
                }
                _ => (Vec::new(), false),
            };
        // Tokens riding on a coin pulled in for its native value have to come
        // back as change, or they are handed to the miner.
        for (currency, amount) in &tokens {
            balances.sub(*currency, *amount);
        }
        taker_inputs.push((utxo, is_cryptocondition));
    }

    let shortfalls = balances.shortfalls();
    if !shortfalls.is_empty() {
        let missing = shortfalls
            .iter()
            .map(|(currency, amount)| format!("{amount} of {}", currency))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(TxError::InvalidOffer(format!(
            "this offer asks to be paid in a token, and the coins supplied are short by {missing}"
        )));
    }

    let owed = Amount::from_sat(transaction.outputs[0].value);
    let available = Amount::checked_sum(params.utxos.iter().map(|u| u.satoshis))
        .ok_or(TxError::ValueOverflow)?;
    let needed = owed
        .checked_add(Amount::from_sat(params.fee))
        .ok_or(TxError::ValueOverflow)?;
    if available < needed {
        return Err(TxError::InvalidOffer(format!(
            "taking this offer costs {} but only {} was supplied",
            needed.to_coins_string(),
            available.to_coins_string()
        )));
    }

    let first_taker_input = transaction.inputs.len();
    for utxo in params.utxos {
        transaction.inputs.push(TxIn::unsigned(
            utxo.txid.to_internal(),
            utxo.vout,
            0xffff_ffff,
        ));
    }

    // Token change first, then native change — the same order `build_token_send`
    // emits, so a reader comparing the two sees one convention.
    let change_hash = params.change_address.hash();
    for (currency, amount) in balances.change() {
        transaction.outputs.push(TxOut {
            value: 0,
            script_pubkey: verus_tx_primitives::cc::reserve_output_script(
                change_hash,
                currency,
                amount,
            )?,
        });
    }

    let change = available
        .checked_sub(needed)
        .ok_or_else(|| TxError::InvalidOffer("change underflowed".into()))?;
    if change > Amount::ZERO {
        transaction.outputs.push(TxOut {
            value: change.to_sat(),
            script_pubkey: params
                .change_address
                .p2pkh_script_pubkey()
                .map_err(TxError::from)?,
        });
    }

    // The taker signs with SIGHASH_ALL, committing to the whole completed
    // transaction — including the maker's side, which is what stops anyone
    // altering it in flight.
    let pubkey = key.public_key().to_bytes();
    for (offset, (utxo, is_cryptocondition)) in taker_inputs.iter().enumerate() {
        let index = first_taker_input + offset;
        let sighash = transaction
            .transparent_sighash(
                VERUS_BRANCH_ID,
                index,
                &utxo.script_pubkey,
                utxo.satoshis.to_sat(),
                SIGHASH_ALL,
            )
            .map_err(TxError::from)?;
        transaction.inputs[index].script_sig = if *is_cryptocondition {
            // A reserve output is unlocked by a fulfillment carrying a compact
            // r||s signature, not a DER one in a P2PKH scriptSig. Signing a
            // token input the P2PKH way produces a transaction the daemon
            // rejects at broadcast.
            let signature = key.sign_prehash(&sighash)?;
            let compact: [u8; 64] = signature.to_bytes().into();
            fulfillment_script_sig(&[(pubkey.clone(), compact)], 1)?
        } else {
            let signature = key.sign_prehash_der(&sighash, 1)?;
            let mut script_sig = Vec::new();
            push_data(&mut script_sig, &signature)?;
            push_data(&mut script_sig, &pubkey)?;
            script_sig
        };
    }

    transaction.serialize().map_err(TxError::from)
}

/// Minimal push encoding for a scriptSig element.
fn push_data(script: &mut Vec<u8>, data: &[u8]) -> Result<(), TxError> {
    if data.len() >= 0x4c {
        return Err(TxError::InvalidOffer(
            "a scriptSig element is unexpectedly large".into(),
        ));
    }
    script.push(u8::try_from(data.len()).expect("refused above unless the length is below 0x4c"));
    script.extend_from_slice(data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use verus_tx_primitives::CurrencyId;

    fn key() -> PrivateKey {
        PrivateKey::from_wif("UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc").unwrap()
    }

    fn funding(amount: u64) -> Utxo {
        Utxo {
            txid: Txid::from_internal([0x3d; 32]),
            vout: 0,
            satoshis: Amount::from_sat(amount),
            script_pubkey: offer_funding_script(key().address().hash()).unwrap(),
        }
    }

    /// The funding output matches the shape `makeoffer` produced on VRSCTEST:
    /// a 1-of-1 CryptoCondition under the commitment eval code, carrying 32 zero
    /// bytes rather than a hash of anything.
    #[test]
    fn the_funding_output_matches_the_daemons_shape() {
        let script = offer_funding_script(
            hex::decode("6299813ef10e47ac626d3c87257308b7d25a204c")
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        // Built rather than pasted, so a stray zero cannot slip in: the first
        // 54 hex chars are the master params, then OP_CHECKCRYPTOCONDITION,
        // then the eval-17 params, then a 32-byte zero payload and OP_DROP.
        let expected = format!(
            "1a0403000101146299813ef10e47ac626d3c87257308b7d25a204c\
             cc\
             3b0403110101146299813ef10e47ac626d3c87257308b7d25a204c\
             20{}75",
            "00".repeat(32)
        )
        .replace(['\n', ' '], "");
        assert_eq!(hex::encode(&script), expected);
        // And the prefix the daemon actually produced, verbatim.
        assert!(expected.starts_with(
            "1a0403000101146299813ef10e47ac626d3c87257308b7d25a204ccc3b04031101\
             01146299813ef10e47ac626d3c87257308b7d25a204c2000000000"
                .replace(['\n', ' '], "")
                .as_str()
        ));
    }

    /// The maker's fulfillment must carry hash type 0x83. The daemon's does, and
    /// it is the single byte that makes an offer completable by a stranger
    /// rather than a transaction only the maker can finish.
    #[test]
    fn the_offer_is_signed_under_single_plus_anyonecanpay() {
        let funding = funding(1_00000000);
        let offer = make_offer(
            &key(),
            &OfferParams {
                funding: &funding,
                wanted: Wanted::Native {
                    amount: Amount::from_sat(2_00000000),
                    recipient: key().address().hash(),
                },
                expiry: Expiry::AtHeight(1_167_992),
            },
        )
        .unwrap();

        let bytes = hex::decode(&offer.hex).unwrap();
        // The fulfillment is pushed into the scriptSig; its second byte is the
        // hash type. 0x83 = SIGHASH_SINGLE | SIGHASH_ANYONECANPAY.
        let marker = bytes
            .windows(2)
            .position(|w| w == [0x01, 0x83])
            .expect("no fulfillment carrying hash type 0x83");
        assert!(marker > 0);
        assert_eq!(OFFER_HASH_TYPE, 0x83);
    }

    /// Changing what the maker asked for must void the signature. If it did not,
    /// a taker could pay less than the offer states.
    #[test]
    fn altering_the_wanted_output_changes_the_signed_hash() {
        let funding = funding(1_00000000);
        let mut params = OfferParams {
            funding: &funding,
            wanted: Wanted::Native {
                amount: Amount::from_sat(2_00000000),
                recipient: key().address().hash(),
            },
            expiry: Expiry::AtHeight(1_167_992),
        };
        let honest = make_offer(&key(), &params).unwrap();

        params.wanted = Wanted::Native {
            amount: Amount::from_sat(1),
            recipient: key().address().hash(),
        };
        let cheapened = make_offer(&key(), &params).unwrap();
        assert_ne!(
            honest.hex, cheapened.hex,
            "the price is not covered by the maker's signature"
        );
    }

    /// A token offer pays the maker with a reserve output rather than natively.
    #[test]
    fn a_token_can_be_asked_for() {
        let funding = funding(1_00000000);
        let offer = make_offer(
            &key(),
            &OfferParams {
                funding: &funding,
                wanted: Wanted::Token {
                    currency: CurrencyId::from_bytes([0x2b; 20]),
                    amount: Amount::from_sat(2_00000000),
                    recipient: key().address().hash(),
                },
                expiry: Expiry::AtHeight(1_167_992),
            },
        )
        .unwrap();
        // A reserve output carries no native value; the token is in the payload.
        assert!(offer.hex.contains("2b2b2b2b"));
    }

    /// Signing an output the key does not control would produce an offer nobody
    /// can complete, discovered only when a taker's transaction is rejected.
    #[test]
    fn a_funding_output_this_key_does_not_control_is_refused() {
        let mut foreign = funding(1_00000000);
        foreign.script_pubkey = offer_funding_script([0x99; 20]).unwrap();
        assert!(make_offer(
            &key(),
            &OfferParams {
                funding: &foreign,
                wanted: Wanted::Native {
                    amount: Amount::from_sat(1),
                    recipient: key().address().hash(),
                },
                expiry: Expiry::AtHeight(1_000),
            },
        )
        .is_err());
    }

    /// An ordinary P2PKH output cannot back an offer.
    #[test]
    fn a_plain_output_cannot_back_an_offer() {
        let mut plain = funding(1_00000000);
        plain.script_pubkey = key().address().p2pkh_script_pubkey().unwrap();
        assert!(make_offer(
            &key(),
            &OfferParams {
                funding: &plain,
                wanted: Wanted::Native {
                    amount: Amount::from_sat(1),
                    recipient: key().address().hash(),
                },
                expiry: Expiry::AtHeight(1_000),
            },
        )
        .is_err());
    }

    /// Signing is deterministic, so an offer republished is the same offer
    /// rather than a second one competing with the first.
    #[test]
    fn making_the_same_offer_twice_gives_the_same_bytes() {
        let funding = funding(1_00000000);
        let params = OfferParams {
            funding: &funding,
            wanted: Wanted::Native {
                amount: Amount::from_sat(2_00000000),
                recipient: key().address().hash(),
            },
            expiry: Expiry::AtHeight(1_167_992),
        };
        assert_eq!(
            make_offer(&key(), &params).unwrap(),
            make_offer(&key(), &params).unwrap()
        );
    }

    fn taker() -> PrivateKey {
        PrivateKey::from_bytes(&[0x27; 32], true).unwrap()
    }

    fn taker_utxo(amount: u64) -> Utxo {
        Utxo {
            txid: Txid::from_internal([0x71; 32]),
            vout: 0,
            satoshis: Amount::from_sat(amount),
            script_pubkey: taker().address().p2pkh_script_pubkey().unwrap(),
        }
    }

    fn sample_offer(wanted: u64) -> (Utxo, SignedOffer) {
        let funding = funding(1_00000000);
        let offer = make_offer(
            &key(),
            &OfferParams::new(
                &funding,
                Wanted::Native {
                    amount: Amount::from_sat(wanted),
                    recipient: key().address().hash(),
                },
                Expiry::AtHeight(1_167_992),
            ),
        )
        .unwrap();
        (funding, offer)
    }

    /// The whole order: a maker's half-signed offer completed by a taker into a
    /// transaction that balances.
    #[test]
    fn a_taker_completes_an_offer_into_a_balanced_transaction() {
        let (funding, offer) = sample_offer(2_00000000);
        let utxos = [taker_utxo(3_00000000)];
        let fee = 10_000u64;

        let completed = take_offer(
            &taker(),
            &TakeParams::new(
                &offer.hex,
                &utxos,
                taker().address().hash(),
                taker().address(),
                funding.satoshis,
                fee,
            ),
        )
        .unwrap();

        let tx = TxV4::deserialize(&completed).expect("the result must be a transaction");
        assert_eq!(tx.inputs.len(), 2, "maker's input plus the taker's");
        // maker wants, taker receives, taker change.
        assert_eq!(tx.outputs.len(), 3);

        // Value conserves: in = maker's offered + taker's funding.
        let inputs = funding.satoshis.to_sat() + utxos[0].satoshis.to_sat();
        let outputs: u64 = tx.outputs.iter().map(|o| o.value).sum();
        assert_eq!(inputs - outputs, fee, "the fee is not what was asked for");
    }

    /// The maker's input and output must survive completion untouched. Moving
    /// either voids their signature, so this is the invariant the whole scheme
    /// depends on.
    #[test]
    fn completion_leaves_the_makers_side_exactly_where_it_was() {
        let (funding, offer) = sample_offer(2_00000000);
        let original = TxV4::deserialize(&hex::decode(&offer.hex).unwrap()).unwrap();

        let utxos = [taker_utxo(3_00000000)];
        let completed = take_offer(
            &taker(),
            &TakeParams::new(
                &offer.hex,
                &utxos,
                taker().address().hash(),
                taker().address(),
                funding.satoshis,
                10_000,
            ),
        )
        .unwrap();
        let tx = TxV4::deserialize(&completed).unwrap();

        assert_eq!(tx.inputs[0], original.inputs[0], "the maker's input moved");
        assert_eq!(
            tx.outputs[0], original.outputs[0],
            "the maker's output moved"
        );
    }

    /// A taker who cannot cover what the maker asked for is stopped before
    /// signing, rather than producing a transaction the network rejects.
    #[test]
    fn a_taker_who_cannot_pay_is_refused() {
        let (funding, offer) = sample_offer(2_00000000);
        let utxos = [taker_utxo(1_00000000)];
        assert!(take_offer(
            &taker(),
            &TakeParams::new(
                &offer.hex,
                &utxos,
                taker().address().hash(),
                taker().address(),
                funding.satoshis,
                10_000,
            ),
        )
        .is_err());
    }

    /// A transaction signed under some other hash type is not an offer. Adding
    /// to it would void the signature, so completing it is refused.
    #[test]
    fn a_transaction_that_is_not_an_offer_is_refused() {
        let (funding, offer) = sample_offer(2_00000000);
        let mut tx = TxV4::deserialize(&hex::decode(&offer.hex).unwrap()).unwrap();
        // Rewrite the fulfillment's hash type byte to SIGHASH_ALL.
        let position = tx.inputs[0]
            .script_sig
            .windows(2)
            .position(|w| w == [0x01, 0x83])
            .expect("hash type");
        tx.inputs[0].script_sig[position + 1] = 0x01;
        let tampered = hex::encode(tx.serialize().unwrap());

        let utxos = [taker_utxo(3_00000000)];
        assert!(take_offer(
            &taker(),
            &TakeParams::new(
                &tampered,
                &utxos,
                taker().address().hash(),
                taker().address(),
                funding.satoshis,
                10_000,
            ),
        )
        .is_err());
    }

    const TOKEN: [u8; 20] = [0x2b; 20];

    /// A reserve output holding `amount` of [`TOKEN`], spendable by the taker.
    fn taker_token_utxo(amount: u64, native: u64) -> Utxo {
        Utxo {
            txid: Txid::from_internal([0x72; 32]),
            vout: 1,
            satoshis: Amount::from_sat(native),
            script_pubkey: verus_tx_primitives::cc::reserve_output_script(
                taker().address().hash(),
                CurrencyId::from_bytes(TOKEN),
                amount,
            )
            .unwrap(),
        }
    }

    fn token_offer(wanted: u64) -> (Utxo, SignedOffer) {
        let funding = funding(1_00000000);
        let offer = make_offer(
            &key(),
            &OfferParams::new(
                &funding,
                Wanted::Token {
                    currency: CurrencyId::from_bytes(TOKEN),
                    amount: Amount::from_sat(wanted),
                    recipient: key().address().hash(),
                },
                Expiry::AtHeight(1_167_992),
            ),
        )
        .unwrap();
        (funding, offer)
    }

    fn tokens_in(script: &[u8]) -> u64 {
        match verus_tx_protocol::decode::decode_output_script(script) {
            Ok(verus_tx_protocol::decode::OutputKind::ReserveOutput { tokens, .. }) => tokens
                .iter()
                .filter(|(id, _)| *id == CurrencyId::from_bytes(TOKEN))
                .map(|(_, amount)| *amount)
                .sum(),
            _ => 0,
        }
    }

    /// A token demand funded from reserve inputs — the case that used to be
    /// refused outright.
    #[test]
    fn a_token_demand_is_funded_from_reserve_inputs() {
        let (funding, offer) = token_offer(2_00000000);
        // Three tokens in, two demanded: one must come back as change.
        let utxos = [
            taker_token_utxo(3_00000000, 0),
            taker_utxo(1_00000000), // native, to pay the fee
        ];
        let raw = take_offer(
            &taker(),
            &TakeParams::new(
                &offer.hex,
                &utxos,
                taker().address().hash(),
                taker().address(),
                funding.satoshis,
                10_000,
            ),
        )
        .unwrap();
        let tx = TxV4::deserialize(&raw).unwrap();

        // Tokens in must equal tokens out, or the difference is burned. This is
        // the check the old refusal existed to avoid needing.
        let token_out: u64 = tx.outputs.iter().map(|o| tokens_in(&o.script_pubkey)).sum();
        assert_eq!(
            token_out, 3_00000000,
            "three tokens went in, so three must come out: two to the maker, one as change"
        );

        // The maker's demand is still output 0, untouched — moving it would void
        // their signature.
        assert_eq!(tokens_in(&tx.outputs[0].script_pubkey), 2_00000000);
    }

    /// Signing a reserve input the P2PKH way produces a transaction the daemon
    /// rejects at broadcast, so the fulfillment path must actually be taken.
    #[test]
    fn a_reserve_input_is_signed_with_a_fulfillment() {
        let (funding, offer) = token_offer(2_00000000);
        let utxos = [taker_token_utxo(2_00000000, 0), taker_utxo(1_00000000)];
        let raw = take_offer(
            &taker(),
            &TakeParams::new(
                &offer.hex,
                &utxos,
                taker().address().hash(),
                taker().address(),
                funding.satoshis,
                10_000,
            ),
        )
        .unwrap();
        let tx = TxV4::deserialize(&raw).unwrap();

        // Input 0 is the maker's. Then the token input, then the native one.
        let token_input = &tx.inputs[1].script_sig;
        let native_input = &tx.inputs[2].script_sig;

        // A P2PKH scriptSig opens with a DER signature push (0x47/0x48). A
        // fulfillment opens with PUSHDATA1 of the CryptoCondition structure,
        // then version and hash type.
        //
        // Length is NOT the discriminator: the fulfillment here is 105 bytes and
        // the P2PKH scriptSig 106, so a "fulfillments are longer" check passes
        // and fails for the wrong reasons.
        assert_eq!(
            native_input[0], 0x47,
            "the native input should carry a DER signature push"
        );
        assert_eq!(
            token_input[0], 0x4c,
            "the reserve input got a P2PKH scriptSig instead of a fulfillment"
        );
        // Inside the fulfillment: version 1, then the hash type the taker signs
        // under, which is SIGHASH_ALL and not the maker's 0x83.
        assert_eq!(&token_input[2..4], &[0x01, 0x01]);
    }

    /// Asking for a token and supplying none must say so, rather than build a
    /// transaction that quietly fails to conserve it.
    #[test]
    fn a_token_demand_with_no_tokens_supplied_is_refused() {
        let (funding, offer) = token_offer(2_00000000);
        let utxos = [taker_utxo(3_00000000)];
        let err = take_offer(
            &taker(),
            &TakeParams::new(
                &offer.hex,
                &utxos,
                taker().address().hash(),
                taker().address(),
                funding.satoshis,
                10_000,
            ),
        )
        .unwrap_err();
        match err {
            TxError::InvalidOffer(ref text) => assert!(text.contains("short by"), "{text}"),
            other => panic!("expected a shortfall, got {other:?}"),
        }
    }

    /// The funding step produces an output an offer can actually be signed over.
    #[test]
    fn funding_produces_an_output_make_offer_accepts() {
        let coins = [Utxo {
            txid: Txid::from_internal([0xc0; 32]),
            vout: 0,
            satoshis: Amount::from_sat(5_00000000),
            script_pubkey: key().address().p2pkh_script_pubkey().unwrap(),
        }];
        let funded = fund_offer(
            &key(),
            &coins,
            Amount::from_sat(1_00000000),
            &key().address(),
            Expiry::AtHeight(1_167_992),
            verus_tx_primitives::fee::DEFAULT_FEE_PER_KB,
        )
        .unwrap();

        let tx = TxV4::deserialize(&hex::decode(&funded.hex).unwrap()).unwrap();
        assert_eq!(
            tx.outputs[0].script_pubkey,
            offer_funding_script(key().address().hash()).unwrap(),
            "output 0 is not an offer funding output"
        );
        assert_eq!(tx.outputs[0].value, 1_00000000);
    }

    /// Rubbish in place of an offer is refused rather than panicking.
    #[test]
    fn malformed_offers_are_refused() {
        let utxos = [taker_utxo(3_00000000)];
        for bad in ["", "zz", "00", "0400008085202f89"] {
            assert!(take_offer(
                &taker(),
                &TakeParams::new(
                    bad,
                    &utxos,
                    taker().address().hash(),
                    taker().address(),
                    Amount::from_sat(1_00000000),
                    10_000,
                ),
            )
            .is_err());
        }
    }
}
