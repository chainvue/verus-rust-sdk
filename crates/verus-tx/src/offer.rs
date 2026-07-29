//! On-chain atomic swaps: making an offer and taking one.
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

use verus_keys::PrivateKey;
use verus_wire::consensus::{SIGHASH_ANYONECANPAY, SIGHASH_SINGLE, VERUS_BRANCH_ID};
use verus_wire::{TxIn, TxOut, TxV4};

use crate::amount::Amount;
use crate::cc::{cc_script, fulfillment_script_sig, Destination, OptCcParams, EVAL_NONE};
use crate::error::TxError;
use crate::expiry::Expiry;
use crate::register::EVAL_IDENTITY_COMMITMENT;
use crate::txid::Txid;
use crate::Utxo;

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
        currency: crate::currency::CurrencyId,
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
                script_pubkey: crate::cc::reserve_output_script(
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
    /// Fee rate in satoshis per kilobyte.
    pub fee_per_kb: u64,
}

impl<'a> TakeParams<'a> {
    /// What a taker supplies to complete an offer.
    pub fn new(
        offer: &'a str,
        utxos: &'a [Utxo],
        recipient: [u8; 20],
        change_address: verus_keys::Address,
    ) -> Self {
        Self {
            offer,
            utxos,
            recipient,
            change_address,
            fee_per_kb: crate::fee::DEFAULT_FEE_PER_KB,
        }
    }
}

/// Complete an offer and produce a broadcastable transaction.
///
/// The maker's input and output are left **exactly** as they are — altering
/// either voids their signature — and the taker's inputs and outputs are
/// appended after them.
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
    let _ = &bytes;
    let _ = key;
    let _ = params.utxos;
    let _ = params.recipient;
    let _ = params.fee_per_kb;
    // Completing an offer requires parsing the maker's partial transaction,
    // which needs a transaction decoder this workspace does not have — every
    // serializer here is write-only. Refused rather than half-implemented.
    Err(TxError::InvalidOffer(
        "taking an offer needs a transaction parser, which this crate does not have yet".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::currency::CurrencyId;

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

    /// Taking is not implemented, and says so rather than producing something
    /// that looks like a completed trade.
    #[test]
    fn taking_an_offer_is_refused_until_there_is_a_parser() {
        let funding = funding(1_00000000);
        let offer = make_offer(
            &key(),
            &OfferParams {
                funding: &funding,
                wanted: Wanted::Native {
                    amount: Amount::from_sat(1),
                    recipient: key().address().hash(),
                },
                expiry: Expiry::AtHeight(1_000),
            },
        )
        .unwrap();
        assert!(take_offer(
            &key(),
            &TakeParams {
                offer: &offer.hex,
                utxos: &[],
                recipient: key().address().hash(),
                change_address: key().address(),
                fee_per_kb: crate::fee::DEFAULT_FEE_PER_KB,
            },
        )
        .is_err());
    }
}
