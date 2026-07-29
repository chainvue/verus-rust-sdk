//! Registering a VerusID — the two-step commit/reveal.
//!
//! A name cannot be claimed in one transaction. Doing so would publish the name
//! into the mempool where anyone could copy it into a transaction of their own
//! and pay a higher fee, so registration is split:
//!
//! 1. **Commitment.** Publish `SHA256d(name || referral || salt)` and nothing
//!    else. The name is hidden behind the salt, so there is nothing to front-run.
//! 2. **Registration.** Spend the commitment, revealing the name, the salt and
//!    the identity itself. Consensus re-derives the hash and checks it matches
//!    the commitment being spent.
//!
//! Both halves are built here. Step 2 spends a CryptoCondition output, which is
//! the first thing in this crate that is not unlocked by a P2PKH scriptSig — see
//! [`crate::cc::fulfillment_script_sig`].
//!
//! # The salt is the whole security property
//!
//! [`NameReservation::new`] takes the salt rather than generating one, because
//! this crate has no opinion about where randomness comes from and a signing
//! library that quietly seeds its own RNG is a library you cannot audit. It must
//! be 32 bytes from a CSPRNG, and it must not be reused: two commitments sharing
//! a salt leak that they came from the same registrant, and a *predictable* salt
//! puts the name back in reach of a front-runner, since the commitment can then
//! be brute-forced from the candidate names.
//!
//! Keep the salt after step 1. It is not recoverable from the chain and without
//! it the commitment cannot be redeemed — the fee is simply lost.
//!
//! # Handing a commitment to the daemon's `registeridentity`
//!
//! If you make the commitment here and complete it with the RPC instead of with
//! [`build_identity_registration`], the `namereservation` object **must carry
//! both `version` and `parent`**. The daemon decides which layout to hash from
//! the presence of those two fields, and nothing else:
//!
//! ```cpp
//! // VerusCoin src/rpc/pbaasrpc.cpp, registeridentity
//! if (!find_value(nameResUni, "version").isNull() && !find_value(nameResUni, "parent").isNull())
//!     advReservation = CAdvancedNameReservation(nameResUni);
//! else
//!     reservation = CNameReservation(nameResUni, ...);
//! ```
//!
//! Omit either and it silently falls back to the legacy `CNameReservation`,
//! hashes the old layout, and reports a mismatch against the commitment it
//! wrote itself — `registernamecommitment` output pasted back in verbatim fails
//! this way, because it prints `version` and `parent` but they are easy to drop.
//! The salt goes in exactly as that RPC printed it: display order, reversed from
//! [`NameReservation::salt`].
//!
//! Its other error, `"Invalid commitment hash"`, is not about hashes at all —
//! it is raised when the daemon's own wallet does not control the commitment's
//! destination, which is the normal case for a commitment this crate made.
//! There is no way to complete such a commitment through that RPC; use
//! [`build_identity_registration`].

use verus_keys::{hash160, Address, AddressKind, PrivateKey};
use verus_wire::hash::sha256d;
use verus_wire::TxOut;

use crate::assemble::{assemble, check_expiry, check_p2pkh_funding, Assembly};
use crate::cc::{
    cc_script, identity_payment_script, identity_primary_script, reserve_output_script_to,
    OptCcParams, EVAL_RESERVE_OUTPUT,
};
use crate::cc::{Destination, EVAL_NONE};
use crate::decode::{decode_output_script, OutputKind};
use crate::error::TxError;
use crate::fee::DEFAULT_FEE_PER_KB;
use crate::identity::Identity;
use crate::send::SignedTransaction;
use crate::Utxo;

/// `EVAL_IDENTITY_COMMITMENT` — the hidden half of a name claim.
pub const EVAL_IDENTITY_COMMITMENT: u8 = 17;
/// `EVAL_IDENTITY_ADVANCEDRESERVATION` — the revealed name, spent into the
/// registration.
///
/// **Not** `EVAL_IDENTITY_RESERVATION` (18), which goes with the older
/// `CNameReservation` layout. The eval code and the payload travel together: a
/// current daemon writes the advanced reservation under eval 10, and a
/// registration that pairs the advanced bytes with eval 18 is rejected as
/// `bad-txns-failed-precheck` — with the name commitment already spent.
/// Confirmed by diffing a `registeridentity` transaction the daemon built on
/// VRSCTEST against one this crate built for the same name.
pub const EVAL_IDENTITY_ADVANCEDRESERVATION: u8 = 10;

/// The only parent `proofprotocol` whose fee output this crate builds: a
/// centralized or token currency, which takes a plain reserve output. A
/// fractional parent takes a `CReserveTransfer` instead.
const CENTRALIZED_PROOF_PROTOCOL: u32 = 2;

/// The identity version a fresh registration publishes: PBaaS, which carries
/// `system_id` and a content multimap.
const IDENTITY_VERSION_PBAAS: u32 = 3;

/// Lowercase the way the C locale does: ASCII only, everything else untouched.
///
/// Rust's `to_lowercase` is Unicode-aware and would fold characters the daemon
/// leaves alone, deriving a different id for the same name. Names are restricted
/// to ASCII by [`validate_name`] anyway; this keeps the derivation honest for
/// anything that slips past a caller building ids directly.
fn to_lower_c_locale(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii() {
                c.to_ascii_lowercase()
            } else {
                c
            }
        })
        .collect()
}

/// Derive a VerusID's 20-byte id from its name and parent.
///
/// ```text
/// id_hash = SHA256d(lowercase(name))
/// id_hash = SHA256d(parent || id_hash)      when there is a parent
/// id      = RIPEMD160(SHA256(id_hash))
/// ```
///
/// Note the parent goes in as its raw 20-byte hash, so an `R` address and an `i`
/// address with the same hash derive the same child — which is why callers must
/// pass a real parent identity and not merely something that decoded.
///
/// A root identity on a chain has that chain's system id as its parent: on
/// VRSCTEST every ordinary registration is a child of `VRSCTEST` itself.
pub fn identity_id(name: &str, parent: Option<[u8; 20]>) -> [u8; 20] {
    let mut id_hash = sha256d(to_lower_c_locale(name).as_bytes());
    if let Some(parent) = parent {
        let mut combined = Vec::with_capacity(52);
        combined.extend_from_slice(&parent);
        combined.extend_from_slice(&id_hash);
        id_hash = sha256d(&combined);
    }
    hash160(&id_hash)
}

/// Names this crate will commit to.
///
/// Deliberately narrower than what consensus accepts. A name with whitespace, a
/// dot, or mixed case derives an id the registrant may not expect, and the
/// mistake is only visible after the fee is spent.
fn validate_name(name: &str) -> Result<(), TxError> {
    let acceptable = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-';
    if name.is_empty() || name.len() > 64 || !name.chars().all(acceptable) {
        return Err(TxError::InvalidIdentityName(name.to_string()));
    }
    Ok(())
}

/// The `CAdvancedNameReservation` version this crate writes.
const NAME_RESERVATION_VERSION: u32 = 1;

/// The claim published in step 1 and revealed in step 2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameReservation {
    /// The name being claimed, without the parent qualification or `@`.
    pub name: String,
    /// The parent the name is claimed under — the chain's system id for an
    /// ordinary registration. It is part of the committed bytes, so a
    /// registration under a different parent will not match its own commitment.
    pub parent: [u8; 20],
    /// The identity that referred this registration, if any. Referrals reduce
    /// the fee and pay part of it onward.
    pub referral: Option<[u8; 20]>,
    /// 32 bytes from a CSPRNG, in **wire order**. See the module docs — this is
    /// load-bearing — and [`NameReservation::salt_display`] for the byte order
    /// the daemon prints.
    pub salt: [u8; 32],
}

impl NameReservation {
    /// A reservation for `name`, hidden behind `salt`.
    pub fn new(
        name: &str,
        parent: [u8; 20],
        referral: Option<[u8; 20]>,
        salt: [u8; 32],
    ) -> Result<Self, TxError> {
        validate_name(name)?;
        Ok(Self {
            name: name.to_string(),
            parent,
            referral,
            salt,
        })
    }

    /// The salt as `registernamecommitment` prints it: byte-reversed.
    ///
    /// The daemon renders it as a uint256, the same convention that reverses
    /// txids, so a salt copied from RPC output must be reversed on the way in
    /// and on the way out. Feeding the displayed order straight through produces
    /// a commitment hash that is perfectly valid and matches nothing.
    pub fn salt_display(&self) -> [u8; 32] {
        let mut salt = self.salt;
        salt.reverse();
        salt
    }

    /// Serialize as `CAdvancedNameReservation`: the bytes both halves hash.
    ///
    /// ```text
    /// version(uint32 LE) || CompactSize(name.len) || name
    ///                    || parent(20) || referral(20) || salt(32)
    /// ```
    ///
    /// The **advanced** layout — carrying an explicit version and parent — is
    /// what a current daemon commits to even for a plain root registration under
    /// the chain itself. The older `CNameReservation` (no version, no parent) is
    /// what the TypeScript SDK writes for a VRSC-parent name, and it hashes to
    /// something consensus will not accept here. Confirmed by reproducing the
    /// commitment hash of a `registernamecommitment` on VRSCTEST, daemon
    /// 1.2.17-2 — see `reproduces_a_daemon_commitment`.
    ///
    /// An absent referral is 20 zero bytes, not an omitted field.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TxError> {
        let name = self.name.as_bytes();
        let mut out = Vec::with_capacity(4 + 1 + name.len() + 72);
        out.extend_from_slice(&NAME_RESERVATION_VERSION.to_le_bytes());
        write_compact_size(&mut out, name.len());
        out.extend_from_slice(name);
        out.extend_from_slice(&self.parent);
        out.extend_from_slice(&self.referral.unwrap_or([0u8; 20]));
        out.extend_from_slice(&self.salt);
        Ok(out)
    }

    /// The hash published in step 1.
    pub fn commitment_hash(&self) -> Result<[u8; 32], TxError> {
        Ok(sha256d(&self.to_bytes()?))
    }
}

/// CompactSize, as used for vector lengths (not the `VARINT` in [`crate::cc`]).
fn write_compact_size(out: &mut Vec<u8>, value: usize) {
    match value {
        0..=252 => out.push(u8::try_from(value).expect("checked above")),
        253..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&u16::try_from(value).expect("checked above").to_le_bytes());
        }
        // Names are capped at 64 bytes by `validate_name`, so nothing this crate
        // writes reaches even the two-byte form; the wider arms exist so the
        // encoder is correct rather than merely sufficient.
        _ => {
            out.push(0xfe);
            out.extend_from_slice(
                &u32::try_from(value)
                    .expect("a CompactSize above u32::MAX is unreachable here")
                    .to_le_bytes(),
            );
        }
    }
}

/// The step-1 output: a commitment hash, spendable only by `control`.
///
/// `control` must be the key that will sign step 2 — the registration spends
/// this output, so a commitment locked to any other key is a commitment that can
/// never be redeemed.
pub fn commitment_script(
    commitment_hash: &[u8; 32],
    control: [u8; 20],
) -> Result<Vec<u8>, TxError> {
    let master = OptCcParams::one_of_one(EVAL_NONE, Destination::PubKeyHash(control));
    let params = OptCcParams {
        vdata: vec![commitment_hash.to_vec()],
        ..OptCcParams::one_of_one(EVAL_IDENTITY_COMMITMENT, Destination::PubKeyHash(control))
    };
    cc_script(&master, &params)
}

/// The step-2 output that reveals the name.
///
/// Paid to the identity being created, which does not exist yet — that is
/// deliberate: consensus takes the reservation as the proof it may exist.
pub fn reservation_script(
    identity_id: [u8; 20],
    reservation: &NameReservation,
) -> Result<Vec<u8>, TxError> {
    let master = OptCcParams::one_of_one(EVAL_NONE, Destination::Identity(identity_id));
    let params = OptCcParams {
        vdata: vec![reservation.to_bytes()?],
        ..OptCcParams::one_of_one(
            EVAL_IDENTITY_ADVANCEDRESERVATION,
            Destination::Identity(identity_id),
        )
    };
    cc_script(&master, &params)
}

/// What step 1 needs.
#[derive(Clone, Debug)]
pub struct CommitmentParams<'a> {
    /// P2PKH UTXOs controlled by the signing key.
    pub utxos: &'a [Utxo],
    /// The claim being committed to.
    pub reservation: &'a NameReservation,
    /// Where change goes.
    pub change_address: Address,
    /// Block height after which the transaction expires; `0` never expires.
    pub expiry_height: u32,
    /// Fee rate in satoshis per kilobyte.
    pub fee_per_kb: u64,
}

impl<'a> CommitmentParams<'a> {
    /// Parameters with the default fee rate.
    pub fn new(
        utxos: &'a [Utxo],
        reservation: &'a NameReservation,
        change_address: Address,
        expiry_height: u32,
    ) -> Self {
        Self {
            utxos,
            reservation,
            change_address,
            expiry_height,
            fee_per_kb: DEFAULT_FEE_PER_KB,
        }
    }
}

/// Step 1: build and sign the name commitment.
///
/// The commitment output carries no value — it exists to be spent by step 2 —
/// so this costs only the miner fee.
pub fn build_name_commitment(
    key: &PrivateKey,
    params: &CommitmentParams<'_>,
) -> Result<SignedTransaction, TxError> {
    check_expiry(params.expiry_height)?;
    check_p2pkh_funding(params.utxos)?;

    let script = commitment_script(&params.reservation.commitment_hash()?, key.address().hash())?;
    assemble(
        key,
        // No CryptoCondition inputs: a commitment is funded from plain P2PKH.
        &[],
        Assembly {
            leading: &[],
            funding: params.utxos,
            outputs: vec![TxOut {
                value: 0,
                script_pubkey: script,
            }],
            burn: 0,
            fee_output_count: 1,
            change_address: &params.change_address,
            expiry_height: params.expiry_height,
            fee_per_kb: params.fee_per_kb,
        },
    )
}

/// What step 2 needs.
#[derive(Clone, Debug)]
pub struct RegistrationParams<'a> {
    /// The step-1 commitment output, which this transaction spends.
    pub commitment: &'a Utxo,
    /// The same reservation committed to in step 1, salt included.
    pub reservation: &'a NameReservation,
    /// P2PKH UTXOs funding the registration fee.
    pub utxos: &'a [Utxo],
    /// The addresses that will be able to sign for the new identity.
    pub primary_addresses: &'a [Address],
    /// How many of `primary_addresses` must sign.
    pub min_sigs: u32,
    /// The chain this identity lives on.
    pub system_id: [u8; 20],
    /// Who may revoke. Defaults to the identity itself when `None`.
    pub revocation_authority: Option<[u8; 20]>,
    /// Who may recover after revocation. Defaults to the identity itself.
    pub recovery_authority: Option<[u8; 20]>,
    /// The registration fee, in satoshis, before any referral discount.
    ///
    /// Chain policy, not a constant this crate can know: `getcurrency` reports
    /// it as `idregistrationfees`. Passing the wrong value gets the transaction
    /// rejected with the commitment already spent.
    pub registration_fee: u64,
    /// How many referral levels the chain pays out — `getcurrency`'s
    /// `idreferrallevels`, 3 on VRSCTEST. Only consulted when the reservation
    /// names a referral; it sets the size of each payout.
    pub referral_levels: u32,
    /// Registering under a parent CURRENCY instead of the chain itself.
    ///
    /// `None` for an ordinary registration under the chain. A sub-identity is
    /// funded differently in every respect — see [`ParentCurrencyFee`].
    pub parent_currency: Option<ParentCurrencyFee<'a>>,
    /// The referral chain to pay, nearest referrer first.
    ///
    /// Empty means "just the referrer named in the reservation". Supply more
    /// only when that referrer was itself referred: the chain is chain state
    /// this crate cannot see, and each entry is read from the previous one's
    /// `getidentity` output. Too few or too many entries is a transaction the
    /// daemon rejects with the commitment already spent.
    pub referral_chain: &'a [[u8; 20]],
    /// Where change goes.
    pub change_address: Address,
    /// Block height after which the transaction expires; `0` never expires.
    pub expiry_height: u32,
    /// Fee rate in satoshis per kilobyte.
    pub fee_per_kb: u64,
}

/// Registering a sub-identity: a name under a parent currency.
///
/// A sub-identity is not a parameter change on an ordinary registration, it is a
/// different transaction:
///
/// * The parent must be a **currency**, not merely an identity. A plain VerusID
///   is rejected as `Invalid parent currency`.
/// * The registration fee is paid in the **parent's own currency**, to the
///   parent's `i` address, as a reserve output carrying no native value.
/// * What is burned natively is the parent's `idimportfees`, not
///   `idregistrationfees`.
/// * The fee therefore has to be funded with token-bearing inputs, which are
///   CryptoConditions and are spent with a fulfillment like any other.
///
/// Confirmed against a `registeridentity` the daemon built on VRSCTEST for a
/// sub-identity of `ownora-nft`: a 1.0 reserve output to the parent, and exactly
/// 0.02 native burned.
///
/// Only `proofprotocol` 2 — a centralized or token parent — is built here. A
/// fractional or PBaaS parent pays through a `CReserveTransfer` instead, which
/// is a different output this crate has not tested, so it is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParentCurrencyFee<'a> {
    /// `idregistrationfees`, in the parent currency's smallest unit.
    pub fee: u64,
    /// `idimportfees`, burned natively.
    pub native_import_fee: u64,
    /// Token-bearing inputs paying the fee. Every one is spent in full and the
    /// surplus comes back as token change, so a token left out is a token burned.
    pub token_funding: &'a [Utxo],
    /// The parent's `proofprotocol`. Anything but 2 is refused.
    pub proof_protocol: u32,
}

/// What a registration actually costs, once a referral is taken into account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistrationFees {
    /// Paid to each referrer in the chain.
    pub referral_amount: u64,
    /// What the registrant parts with in total: the payouts plus the burn.
    pub outlay: u64,
}

/// Split a registration fee the way consensus does.
///
/// Unreferred, the registrant burns the whole fee. Referred, they pay
/// `fee * (levels + 1) / (levels + 2)` and each referrer takes
/// `fee / (levels + 2)` out of it. Integer division throughout, matching the
/// daemon — 100 VRSC over 3 levels is 80 paid, 20 per referrer.
pub fn registration_fees(fee: u64, levels: u32, referred: bool) -> RegistrationFees {
    if !referred {
        return RegistrationFees {
            referral_amount: 0,
            outlay: fee,
        };
    }
    let levels = u64::from(levels);
    RegistrationFees {
        referral_amount: fee / (levels + 2),
        outlay: fee * (levels + 1) / (levels + 2),
    }
}

/// A registration, signed and ready to broadcast.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRegistration {
    /// The signed transaction.
    pub transaction: SignedTransaction,
    /// The identity's 20-byte id.
    pub identity_id: [u8; 20],
    /// The identity's `i` address.
    pub identity_address: Address,
    /// The identity as it will be published.
    pub identity: Identity,
}

/// Step 2: build and sign the registration that creates the identity.
///
/// Spends the step-1 commitment as input 0 and publishes three things: the
/// identity itself, the revealed reservation, and the registration fee — which
/// is *burned*, appearing as an oversized miner fee rather than as an output.
///
/// # Referrals
///
/// When the reservation names a referral the registrant pays **less**, not
/// more. With `idreferrallevels` of 3 and a 100 VRSC fee, each referrer is paid
/// `fee / (levels + 2)` = 20, the registrant's total outlay is
/// `fee * (levels + 1) / (levels + 2)` = 80, and the remaining 60 is burned.
/// Funding the full 100 overpays by 20 on every referred registration.
///
/// Verified against a `registeridentity` the daemon built on VRSCTEST: one
/// 20.0 payout to the referrer, inputs minus outputs exactly 60.
pub fn build_identity_registration(
    key: &PrivateKey,
    params: &RegistrationParams<'_>,
) -> Result<SignedRegistration, TxError> {
    check_expiry(params.expiry_height)?;
    check_p2pkh_funding(params.utxos)?;
    if params.primary_addresses.is_empty() {
        return Err(TxError::NoOutputs);
    }
    if params.min_sigs == 0 || params.min_sigs as usize > params.primary_addresses.len() {
        return Err(TxError::InvalidMinSigs {
            min_sigs: params.min_sigs,
            primaries: params.primary_addresses.len(),
        });
    }

    // The commitment is spendable only by the key that created it. Checking the
    // control hash here turns "the daemon rejected it, and the commitment is now
    // spent" into an error before anything is signed.
    let control = key.address().hash();
    let expected = commitment_script(&params.reservation.commitment_hash()?, control)?;
    if params.commitment.script_pubkey != expected {
        return Err(TxError::CommitmentMismatch);
    }

    // The parent lives on the reservation, where it is part of the committed
    // bytes — taking it from anywhere else would let the identity be published
    // under a parent its own commitment never covered.
    let parent = params.reservation.parent;
    let identity_id = identity_id(&params.reservation.name, Some(parent));
    let identity_address = Address::new(AddressKind::Identity, identity_id);
    let revocation = params.revocation_authority.unwrap_or(identity_id);
    let recovery = params.recovery_authority.unwrap_or(identity_id);

    let mut primary_addresses = Vec::with_capacity(params.primary_addresses.len());
    for address in params.primary_addresses {
        if address.kind() != AddressKind::PubKeyHash {
            return Err(TxError::UnsupportedRecipient);
        }
        primary_addresses.push(Destination::PubKeyHash(address.hash()));
    }

    let identity = Identity {
        version: IDENTITY_VERSION_PBAAS,
        flags: 0,
        primary_addresses,
        min_sigs: params.min_sigs,
        parent,
        name: params.reservation.name.clone(),
        content_multimap: Vec::new(),
        content_map: Vec::new(),
        revocation_authority: revocation,
        recovery_authority: recovery,
        private_addresses: Vec::new(),
        system_id: params.system_id,
        unlock_after: 0,
    };

    // Referral payouts sit between the identity and the reservation, which is
    // where the daemon puts them.
    let fees = registration_fees(
        params.registration_fee,
        params.referral_levels,
        params.reservation.referral.is_some(),
    );
    let referrers: Vec<[u8; 20]> = match (params.reservation.referral, params.referral_chain) {
        (None, []) => Vec::new(),
        (None, _) => return Err(TxError::ReferralNotCommitted),
        (Some(referrer), []) => vec![referrer],
        (Some(_), chain) => chain.to_vec(),
    };
    if referrers.len() > params.referral_levels as usize {
        return Err(TxError::ReferralChainTooLong {
            entries: referrers.len(),
            levels: params.referral_levels,
        });
    }

    let mut outputs = Vec::with_capacity(referrers.len() + 3);
    outputs.push(TxOut {
        value: 0,
        script_pubkey: identity_primary_script(
            identity_id,
            identity.to_bytes()?,
            revocation,
            recovery,
        )?,
    });
    // The parent's fee, in the parent's currency, paid to the parent itself.
    if let Some(sub) = &params.parent_currency {
        if sub.proof_protocol != CENTRALIZED_PROOF_PROTOCOL {
            return Err(TxError::UnsupportedParentProofProtocol(sub.proof_protocol));
        }
        outputs.push(TxOut {
            value: 0,
            script_pubkey: reserve_output_script_to(
                Destination::Identity(parent),
                parent,
                sub.fee,
            )?,
        });
    }
    for referrer in &referrers {
        outputs.push(TxOut {
            value: fees.referral_amount,
            script_pubkey: identity_payment_script(*referrer)?,
        });
    }
    outputs.push(TxOut {
        value: 0,
        script_pubkey: reservation_script(identity_id, params.reservation)?,
    });

    // Token change: every token-bearing input is spent whole, so whatever the
    // parent's fee does not consume must come back or it is destroyed.
    let mut token_leading: Vec<Utxo> = Vec::new();
    if let Some(sub) = &params.parent_currency {
        let mut held: u64 = 0;
        for utxo in sub.token_funding {
            match decode_output_script(&utxo.script_pubkey)? {
                OutputKind::ReserveOutput { tokens, .. } => {
                    for (currency, amount) in tokens {
                        if currency != parent {
                            return Err(TxError::UnsupportedFundingEval {
                                txid: utxo.txid.to_display_hex(),
                                vout: utxo.vout,
                                eval_code: EVAL_RESERVE_OUTPUT,
                            });
                        }
                        held = held.checked_add(amount).ok_or(TxError::ValueOverflow)?;
                    }
                }
                _ => {
                    return Err(TxError::UnsupportedFundingScript {
                        txid: utxo.txid.to_display_hex(),
                        vout: utxo.vout,
                    })
                }
            }
            token_leading.push(utxo.clone());
        }
        let change = held
            .checked_sub(sub.fee)
            .ok_or(TxError::InsufficientTokens {
                currency: hex::encode(parent),
                missing: sub.fee - held.min(sub.fee),
            })?;
        if change > 0 {
            outputs.push(TxOut {
                value: 0,
                script_pubkey: reserve_output_script_to(
                    Destination::PubKeyHash(params.change_address.hash()),
                    parent,
                    change,
                )?,
            });
        }
    }

    // The payouts come OUT OF the registrant's outlay; the remainder is burned.
    // A sub-identity burns the parent's import fee instead: its registration fee
    // left in the parent's currency, not natively.
    let paid_out = fees.referral_amount * referrers.len() as u64;
    let burn = match &params.parent_currency {
        Some(sub) => sub.native_import_fee,
        None => fees
            .outlay
            .checked_sub(paid_out)
            .ok_or(TxError::ReferralChainTooLong {
                entries: referrers.len(),
                levels: params.referral_levels,
            })?,
    };

    // The commitment first, then any token inputs — all CryptoConditions, all
    // satisfied by the same control key.
    let mut leading = vec![params.commitment.clone()];
    leading.extend(token_leading);

    let transaction = assemble(
        key,
        // The commitment is a 1-of-1 condition over the control key.
        &[key],
        Assembly {
            leading: &leading,
            funding: params.utxos,
            outputs,
            burn,
            // The TypeScript SDK sizes the fee for the declared outputs plus one
            // extra change slot on top of what selection already reserves. Kept
            // as-is: it decides the change value, and a different estimate is a
            // different transaction.
            fee_output_count: 3 + referrers.len() as u64,
            change_address: &params.change_address,
            expiry_height: params.expiry_height,
            fee_per_kb: params.fee_per_kb,
        },
    )?;

    Ok(SignedRegistration {
        transaction,
        identity_id,
        identity_address,
        identity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Txid;

    /// `VRSCTEST`, the system id every testnet registration parents to.
    const VRSCTEST: &str = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";

    fn parse(address: &str) -> Address {
        address.parse().unwrap()
    }

    /// The daemon derives the same id for a name under a parent. These pairs are
    /// real VRSCTEST identities from `fixtures/daemon/identities.json`, where the
    /// address is what `getidentity` reported for the name.
    #[test]
    fn derives_identity_ids_the_daemon_agrees_with() {
        let parent = parse(VRSCTEST).hash();
        for (name, expected) in [
            ("test", "i8jHXEEYEQ7KEoYe6eKXBib8cUBZ6vjWSd"),
            ("bob", "i3bCS2hfQXktHXHmXEAxKPeby5cb6Px6Le"),
            ("chris", "iPsFBfFoCcxtuZNzE8yxPQhXVn4dmytf8j"),
            ("odin-user-001", "iNaTw2pgBpn1YPBb1TAp9JydCoWz9ts8HQ"),
        ] {
            let id = identity_id(name, Some(parent));
            assert_eq!(
                Address::new(AddressKind::Identity, id).to_string(),
                expected,
                "{name}"
            );
        }
    }

    /// Case must not change the id: the daemon lowercases in the C locale before
    /// hashing, so `Chips` and `chips` are the same identity.
    #[test]
    fn identity_ids_ignore_case() {
        let parent = parse(VRSCTEST).hash();
        assert_eq!(
            identity_id("Test", Some(parent)),
            identity_id("test", Some(parent))
        );
    }

    #[test]
    fn a_parent_changes_the_id() {
        let parent = parse(VRSCTEST).hash();
        assert_ne!(identity_id("test", Some(parent)), identity_id("test", None));
    }

    fn reservation(name: &str, salt: [u8; 32]) -> NameReservation {
        NameReservation::new(name, parse(VRSCTEST).hash(), None, salt).unwrap()
    }

    #[test]
    fn reservation_bytes_are_version_name_parent_referral_salt() {
        let reservation = reservation("chips", [0x11; 32]);
        let bytes = reservation.to_bytes().unwrap();
        assert_eq!(bytes.len(), 4 + 1 + 5 + 20 + 20 + 32);
        assert_eq!(&bytes[..4], &1u32.to_le_bytes());
        assert_eq!(bytes[4], 5);
        assert_eq!(&bytes[5..10], b"chips");
        assert_eq!(&bytes[10..30], &parse(VRSCTEST).hash());
        assert_eq!(&bytes[30..50], &[0u8; 20]);
        assert_eq!(&bytes[50..], &[0x11; 32]);
    }

    /// The decisive vector: a real `registernamecommitment` on VRSCTEST
    /// (daemon 1.2.17-2, txid 49a57a4e2e1c7b67287860c61c1b8e9ca9dfdf3b51bdc1f240bdbb8467714766).
    ///
    /// The RPC reported the salt in display order, so it is reversed here. Both
    /// the commitment hash the daemon derived and the whole output script it
    /// published must come back out byte for byte — that is what says this crate
    /// commits to the same thing consensus will later re-derive.
    #[test]
    fn reproduces_a_daemon_commitment() {
        let mut salt =
            hex_bytes("a8b54ed11d30dbce90fedd589445ce196f37a691c6e062183f687bdce7b61e42");
        salt.reverse();
        let reservation = reservation("rustdiff01", salt.try_into().unwrap());

        assert_eq!(
            hex::encode(reservation.commitment_hash().unwrap()),
            "262e23fbee501a63b39f4da689e9068a7d781433925db5703d50bf8a63f039a1"
        );

        // Control address RJUgxvDnDLsRGCXNKDK56Rxngzh6m25J6F.
        let control = parse("RJUgxvDnDLsRGCXNKDK56Rxngzh6m25J6F").hash();
        let script = commitment_script(&reservation.commitment_hash().unwrap(), control).unwrap();
        assert_eq!(
            hex::encode(script),
            "1a04030001011464e5d216af5fafa39f88cb6000353479ee7a1ef8cc3b0403110101\
             1464e5d216af5fafa39f88cb6000353479ee7a1ef820262e23fbee501a63b39f4da6\
             89e9068a7d781433925db5703d50bf8a63f039a175"
                .replace(['\n', ' '], "")
        );

        // The id the daemon reported for the same name.
        assert_eq!(
            Address::new(
                AddressKind::Identity,
                identity_id("rustdiff01", Some(parse(VRSCTEST).hash()))
            )
            .to_string(),
            "iGoNkZjM6hRx3YYpH8b9zciXMk6PqxKkE8"
        );
    }

    fn hex_bytes(text: &str) -> Vec<u8> {
        hex::decode(text).unwrap()
    }

    /// The salt is what hides the name; a different salt must produce a
    /// different commitment for the same name.
    #[test]
    fn the_salt_changes_the_commitment() {
        assert_ne!(
            reservation("chips", [0x11; 32]).commitment_hash().unwrap(),
            reservation("chips", [0x22; 32]).commitment_hash().unwrap()
        );
    }

    /// The parent is committed to as well, so the same name under a different
    /// parent is a different claim.
    #[test]
    fn the_parent_changes_the_commitment() {
        let under_chain = reservation("chips", [0x11; 32]);
        let under_other = NameReservation::new("chips", [0x07; 20], None, [0x11; 32]).unwrap();
        assert_ne!(
            under_chain.commitment_hash().unwrap(),
            under_other.commitment_hash().unwrap()
        );
    }

    #[test]
    fn rejects_names_that_would_derive_a_surprising_id() {
        for name in ["", "Chips", "chips.vrsc", "with space", "chips@"] {
            assert!(
                matches!(
                    NameReservation::new(name, [0; 20], None, [0; 32]),
                    Err(TxError::InvalidIdentityName(_))
                ),
                "{name:?} should be refused"
            );
        }
    }

    /// The daemon's own arithmetic: 100 VRSC over 3 referral levels pays the
    /// referrer 20 and costs the registrant 80, of which 60 is burned. Taken
    /// from a referred `registeridentity` on VRSCTEST, where inputs minus
    /// outputs came to exactly 60 with a single 20.0 payout.
    #[test]
    fn splits_a_referred_registration_fee_the_way_the_daemon_does() {
        let fees = registration_fees(100_00000000, 3, true);
        assert_eq!(fees.referral_amount, 20_00000000);
        assert_eq!(fees.outlay, 80_00000000);
        assert_eq!(fees.outlay - fees.referral_amount, 60_00000000);
    }

    /// Without a referral the registrant burns the whole fee and nobody is paid.
    #[test]
    fn an_unreferred_registration_burns_the_whole_fee() {
        let fees = registration_fees(100_00000000, 3, false);
        assert_eq!(fees.referral_amount, 0);
        assert_eq!(fees.outlay, 100_00000000);
    }

    /// A fractional parent pays its fee through a CReserveTransfer, not a plain
    /// reserve output. Building the wrong shape would pay the fee somewhere
    /// consensus does not look for it, so it is refused rather than guessed.
    #[test]
    fn refuses_a_parent_whose_proofprotocol_is_untested() {
        let key =
            PrivateKey::from_wif("UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc").unwrap();
        let parent = parse(VRSCTEST).hash();
        let reservation = NameReservation::new("sub", parent, None, [0x11; 32]).unwrap();
        let commitment = Utxo {
            txid: Txid::from_internal([0xaa; 32]),
            vout: 0,
            satoshis: 0,
            script_pubkey: commitment_script(
                &reservation.commitment_hash().unwrap(),
                key.address().hash(),
            )
            .unwrap(),
        };
        let funding = [Utxo {
            txid: Txid::from_internal([0xbb; 32]),
            vout: 0,
            satoshis: 100_000_000,
            script_pubkey: key.address().p2pkh_script_pubkey().unwrap(),
        }];
        let primaries = [key.address()];
        let params = RegistrationParams {
            commitment: &commitment,
            reservation: &reservation,
            utxos: &funding,
            primary_addresses: &primaries,
            min_sigs: 1,
            system_id: parent,
            revocation_authority: None,
            recovery_authority: None,
            registration_fee: 0,
            parent_currency: Some(ParentCurrencyFee {
                fee: 1_00000000,
                native_import_fee: 2_000_000,
                token_funding: &[],
                // 1 = fractional / PBaaS.
                proof_protocol: 1,
            }),
            referral_levels: 0,
            referral_chain: &[],
            change_address: key.address(),
            expiry_height: 0,
            fee_per_kb: DEFAULT_FEE_PER_KB,
        };
        assert!(matches!(
            build_identity_registration(&key, &params),
            Err(TxError::UnsupportedParentProofProtocol(1))
        ));
    }

    /// A registration whose commitment was locked to somebody else's key cannot
    /// be signed — catching it here is what stops the commitment being spent
    /// into a transaction the daemon will reject.
    #[test]
    fn refuses_a_commitment_it_does_not_control() {
        let key =
            PrivateKey::from_wif("UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc").unwrap();
        let reservation = reservation("chips", [0x11; 32]);
        let commitment = Utxo {
            txid: Txid::from_internal([0xaa; 32]),
            vout: 0,
            satoshis: 0,
            // Locked to a different control hash than the signing key's.
            script_pubkey: commitment_script(&reservation.commitment_hash().unwrap(), [0x99; 20])
                .unwrap(),
        };
        let funding = [Utxo {
            txid: Txid::from_internal([0xbb; 32]),
            vout: 0,
            satoshis: 200_00000000,
            script_pubkey: key.address().p2pkh_script_pubkey().unwrap(),
        }];
        let primaries = [key.address()];
        let params = RegistrationParams {
            commitment: &commitment,
            reservation: &reservation,
            utxos: &funding,
            primary_addresses: &primaries,
            min_sigs: 1,
            system_id: parse(VRSCTEST).hash(),
            revocation_authority: None,
            recovery_authority: None,
            registration_fee: 100_00000000,
            parent_currency: None,
            referral_levels: 3,
            referral_chain: &[],
            change_address: key.address(),
            expiry_height: 0,
            fee_per_kb: DEFAULT_FEE_PER_KB,
        };
        assert!(matches!(
            build_identity_registration(&key, &params),
            Err(TxError::CommitmentMismatch)
        ));
    }
}
