//! Registering a VerusID, which takes two transactions and a wait.
//!
//! ```text
//! prepare  →  broadcast  →  …confirm…  →  complete
//!  salt        commitment    poll()       registration
//!  exists      is spent      or wait      identity exists
//! ```
//!
//! # The salt is the whole problem
//!
//! Step 1 publishes a *hash* of the name being claimed, so nobody watching the
//! mempool can race ahead and register it first. Step 2 reveals the name and the
//! salt that produced that hash.
//!
//! The salt exists only in memory. **It cannot be recovered from the chain** —
//! that is precisely what makes the commitment hiding. A process that broadcasts
//! step 1 and then dies has spent the commitment fee on a claim it can never
//! complete, and the name stays locked up until the commitment expires.
//!
//! So the API is arranged to make losing it awkward:
//! [`prepare_registration`] does all the work and broadcasts **nothing**,
//! handing back a serializable [`Pending`] that already contains the salt. Write
//! it down, *then* call [`Pending::broadcast_commitment`]. Ordering the API this
//! way is the only protection available; a function that did both at once could
//! not offer any.
//!
//! # Why step 2 is a different type
//!
//! Running step 2 before step 1 confirms produces a rejected transaction **with
//! the commitment already spent** — the expensive failure, and the one the
//! builder documentation warns about four separate times. So the two steps are
//! different types: [`Pending<AwaitingCommitment>`] has no method that
//! registers, and the only way to obtain a [`Pending<ReadyToRegister>`] is to
//! poll and be told the commitment has confirmed. Getting the order wrong stops
//! being a runtime error and starts being a compile error.
//!
//! # Polling, not sleeping
//!
//! [`Pending::poll`] performs **one** request and returns. It does not sleep, so
//! it works inside a GUI event loop, an async runtime, or a wasm build, none of
//! which can block. [`Pending::wait_blocking`] is built on top for the cases
//! where blocking is fine.

use std::marker::PhantomData;

use serde::{Deserialize, Serialize};
use verus_keys::{Address, PrivateKey};
use verus_rpc::{Broadcaster, ChainReader};
use verus_tx::{
    build_identity_registration, build_name_commitment, identity_id, Amount, CommitmentParams,
    CurrencyId, Expiry, NameReservation, RegistrationParams, Txid, Utxo, DEFAULT_EXPIRY_BLOCKS,
};

use crate::broadcast::broadcast;
use crate::error::FlowError;
use crate::funding;

/// Step 1 has not been broadcast, or has not confirmed.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct AwaitingCommitment;

/// Step 1 has confirmed and step 2 can run.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ReadyToRegister;

/// A registration in progress, safe to write to disk and pick up later.
///
/// The type parameter records which step it is at; see the module docs.
///
/// # Step 2 cannot run early
///
/// `complete` exists only on `Pending<ReadyToRegister>`, and the only way to get
/// one is a [`poll`](Pending::poll) that saw the commitment confirm. Trying it
/// on an unconfirmed registration is a compile error, not a rejected
/// transaction with the commitment already spent:
///
/// ```compile_fail
/// # use verus_flows::{Pending, AwaitingCommitment};
/// # use verus_rpc::{ChainReader, Broadcaster};
/// # fn no(pending: Pending<AwaitingCommitment>, reader: &impl ChainReader,
/// #       broadcaster: &impl Broadcaster, key: &verus_keys::PrivateKey) {
/// // no method named `complete` found for `Pending<AwaitingCommitment>`
/// pending.complete(reader, broadcaster, key);
/// # }
/// ```
///
/// The same call on a `Pending<ReadyToRegister>` compiles, which is what makes
/// the check above mean something rather than merely failing:
///
/// ```no_run
/// # use verus_flows::{Pending, ReadyToRegister};
/// # use verus_rpc::{ChainReader, Broadcaster};
/// # fn yes(pending: Pending<ReadyToRegister>, reader: &impl ChainReader,
/// #        broadcaster: &impl Broadcaster, key: &verus_keys::PrivateKey) {
/// pending.complete(reader, broadcaster, key).unwrap();
/// # }
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pending<S> {
    /// The claim, salt included. Not recoverable from anywhere else.
    pub reservation: NameReservation,
    /// The signed step-1 transaction.
    pub commitment_hex: String,
    /// Its transaction id.
    pub commitment_txid: String,
    /// Which output of it carries the commitment.
    pub commitment_vout: u32,
    /// The registration fee read from chain policy when this was prepared.
    ///
    /// Recorded rather than re-read at step 2: the fee is what the whole
    /// operation was budgeted against, and a node that reports a different one
    /// later should be noticed, not silently obeyed.
    pub registration_fee: Amount,
    /// `idreferrallevels`, read from chain policy when this was prepared.
    ///
    /// Needed at step 2 to actually pay a referral out — see
    /// [`Pending::complete`] — so it has to survive the same round trip to
    /// disk the rest of this type does. `#[serde(default)]` so a `Pending`
    /// persisted before this field existed still deserializes: it lands as
    /// `0`, which reproduces the H2 bug (referred registrations refused with
    /// `ReferralChainTooLong`) for exactly the in-flight registrations that
    /// predate the fix, rather than failing to load at all. There is no
    /// better default available after the fact — the real figure was read
    /// once, at prepare time, and a resumed process has no chain policy to
    /// re-derive it from.
    #[serde(default)]
    pub referral_levels: u32,
    /// The full chain of referrers this registration must pay, in the order
    /// consensus expects: the immediate referrer first, then theirs. Computed
    /// at prepare, when getting it wrong still costs nothing.
    #[serde(default)]
    pub referral_chain: Vec<[u8; 20]>,
    /// The addresses that will control the identity.
    pub primary_addresses: Vec<String>,
    /// How many of them must sign.
    pub min_sigs: u32,
    /// The chain the identity lives on.
    pub system_id: [u8; 20],
    /// Where change goes.
    pub change_address: String,
    /// `(height, best block hash)` when the commitment was broadcast, so a
    /// reorg underneath it can be noticed.
    pub anchored_at: Option<(u32, String)>,
    #[serde(skip)]
    state: PhantomData<S>,
}

impl<S> Pending<S> {
    /// The name being claimed.
    pub fn name(&self) -> &str {
        &self.reservation.name
    }

    /// The `i` address the identity will have, computable before it exists.
    pub fn identity_address(&self) -> Result<[u8; 20], FlowError> {
        Ok(identity_id(
            &self.reservation.name,
            Some(self.reservation.parent),
        ))
    }

    fn transition<T>(self) -> Pending<T> {
        Pending {
            reservation: self.reservation,
            commitment_hex: self.commitment_hex,
            commitment_txid: self.commitment_txid,
            commitment_vout: self.commitment_vout,
            registration_fee: self.registration_fee,
            referral_levels: self.referral_levels,
            referral_chain: self.referral_chain,
            primary_addresses: self.primary_addresses,
            min_sigs: self.min_sigs,
            system_id: self.system_id,
            change_address: self.change_address,
            anchored_at: self.anchored_at,
            state: PhantomData,
        }
    }
}

/// Where a pending registration stands.
#[derive(Clone, Debug)]
pub enum CommitmentStatus {
    /// Not confirmed yet. Carries how many confirmations it has.
    Waiting {
        /// Confirmations so far — `0` means it is in the mempool.
        confirmations: u32,
    },
    /// Confirmed. Step 2 can run.
    Ready(Box<Pending<ReadyToRegister>>),
    /// The chain moved under this operation.
    ///
    /// Not necessarily fatal — the commitment may still be in the new chain —
    /// but nothing built against the old state should be trusted without
    /// re-reading. Poll again once the chain settles.
    Reorged {
        /// What changed.
        detail: String,
    },
    /// The node has never seen the commitment.
    ///
    /// Either it never propagated, or it expired and was dropped. The salt is
    /// still good, so the commitment can be re-broadcast — but if it expired,
    /// a fresh one is needed.
    CommitmentGone,
}

/// Options for a registration, all with sane defaults.
#[derive(Clone, Debug, Default)]
pub struct RegistrationOptions {
    /// Addresses that will control the identity. Defaults to the funding key's.
    pub primary_addresses: Vec<String>,
    /// How many must sign. Defaults to 1.
    pub min_sigs: Option<u32>,
    /// A referrer, which reduces what the registrant pays.
    pub referral: Option<String>,
    /// Use this fee instead of the one the node reports.
    ///
    /// A node that misreports `idregistrationfees` is discovered *after* the
    /// commitment is spent, so a caller who knows the real figure can pin it.
    pub pin_fee: Option<Amount>,
}

/// Build and sign step 1 **without broadcasting it**.
///
/// Broadcasting nothing is the point: the returned [`Pending`] already holds the
/// salt, so it can be persisted before any money is spent. See the module docs.
///
/// Reads chain policy for the real registration fee and refuses early if the
/// name is taken — both cheaper to learn now than after the commitment.
pub fn prepare_registration(
    reader: &impl ChainReader,
    key: &PrivateKey,
    name: &str,
    options: &RegistrationOptions,
) -> Result<Pending<AwaitingCommitment>, FlowError> {
    let salt = random_salt();
    prepare_registration_with_salt(reader, key, name, options, salt)
}

/// As [`prepare_registration`], with the salt supplied.
///
/// For a wallet with its own entropy source, and for tests that need the bytes
/// to be reproducible. The salt must be unpredictable: a guessable one lets
/// somebody else compute the commitment hash and front-run the name.
pub fn prepare_registration_with_salt(
    reader: &impl ChainReader,
    key: &PrivateKey,
    name: &str,
    options: &RegistrationOptions,
    salt: [u8; 32],
) -> Result<Pending<AwaitingCommitment>, FlowError> {
    let info = reader.chain_info()?;
    let system_id = currency_id_bytes(&info.chain_id)?;

    // Cheaper to find out now than after paying for a commitment.
    //
    // **A failure here is not an answer.** The obvious `if …is_ok()` reads
    // "anything but success means the name is free", and that is wrong for
    // every failure except the one it means: a timeout, a malformed reply, or —
    // against the driver in [`crate::drive`] — a request that has simply not
    // been answered yet would all be taken as permission to spend a commitment
    // fee on a name somebody already owns.
    //
    // So only the node saying so counts. `-5` is what a daemon answers for an
    // identity it does not have.
    let qualified = format!("{name}@");
    if crate::error::look_up_identity(reader, &qualified)?.is_some() {
        return Err(FlowError::NameTaken(qualified));
    }

    let policy = reader.currency(&info.name)?;
    let fee = match options.pin_fee {
        Some(fee) => fee,
        // Node-supplied and BURNED outright — see `check_trusted_node_fee`.
        // An explicitly pinned fee skips this bar: the caller has taken
        // responsibility for the number, and it is `pin_fee` that is checked
        // against the wider `MAX_DECLARED_BURN` backstop instead, later at
        // assembly.
        None => check_trusted_node_fee("identity registration", policy.id_registration_fee)?,
    };

    // Referral policy is node-supplied too, and it decides the fee split that
    // step two computes. Checking it HERE — before any broadcast — is the
    // point: left to `complete()`, an implausible value is refused only after
    // the commitment fee is spent, and the name commitment is wasted with the
    // salt still valid but useless. Only checked when a referral is actually
    // wanted; the levels are irrelevant otherwise.
    let referral = match &options.referral {
        Some(referrer) => {
            if policy.id_referral_levels > verus_tx::register::MAX_REFERRAL_LEVELS {
                return Err(FlowError::ImplausibleReferralLevels {
                    reported: policy.id_referral_levels,
                    ceiling: verus_tx::register::MAX_REFERRAL_LEVELS,
                });
            }
            if policy.id_referral_levels == 0 {
                return Err(FlowError::CurrencyPaysNoReferrals {
                    referrer: referrer.clone(),
                });
            }
            Some(referral_id(reader, referrer)?)
        }
        None => None,
    };
    // Resolved here, not at step two: a chain that cannot be built is a
    // refusal worth having before the commitment is broadcast.
    let referral_chain = match referral {
        Some(referrer) => referral_chain(reader, referrer, policy.id_referral_levels)?,
        None => Vec::new(),
    };
    let reservation = NameReservation::new(name, system_id, referral, salt)?;

    let from = key.address();
    let funding = funding::spendable(reader, &from.to_string())?;
    // The commitment itself costs only a miner fee, but there is no point
    // starting if the registration that follows cannot be paid for.
    funding::require(&funding, fee, &from.to_string())?;

    let params = CommitmentParams::new(
        &funding.utxos,
        &reservation,
        from,
        Expiry::within(funding.tip, DEFAULT_EXPIRY_BLOCKS),
    );
    let signed = build_name_commitment(key, &params)?;

    let primary_addresses = if options.primary_addresses.is_empty() {
        vec![from.to_string()]
    } else {
        options.primary_addresses.clone()
    };

    Ok(Pending {
        reservation,
        commitment_hex: signed.hex,
        commitment_txid: signed.txid,
        // The commitment is the only declared output; change follows it. Not
        // assumed for long — `poll` re-derives the script and confirms the index
        // against what the chain actually holds.
        commitment_vout: 0,
        registration_fee: fee,
        referral_levels: policy.id_referral_levels,
        referral_chain,
        primary_addresses,
        min_sigs: options.min_sigs.unwrap_or(1),
        system_id,
        change_address: from.to_string(),
        anchored_at: None,
        state: PhantomData,
    })
}

impl Pending<AwaitingCommitment> {
    /// Broadcast step 1.
    ///
    /// **Persist this value first.** Once these bytes are on the network the
    /// commitment fee is committed, and without the salt it cannot be redeemed.
    pub fn broadcast_commitment(
        mut self,
        reader: &impl ChainReader,
        broadcaster: &impl Broadcaster,
    ) -> Result<Self, FlowError> {
        // Recorded before sending: a reorg is detected by comparing against
        // where the chain was when this was committed to.
        //
        // The hash is read with `block_hash(height)`, not `best_block_hash()`.
        // Those differ: the tip can advance between the two calls, and the pair
        // would then describe a hash at one height recorded against another —
        // a mismatch that reads as a reorg on the very next poll. Asking for the
        // hash *of that height* is racy in no useful sense: the answer is the
        // same whenever it is asked, unless the block really was replaced, which
        // is precisely what this is for.
        let height = reader.block_count()?;
        let hash = reader.block_hash(height)?;
        broadcast(broadcaster, &self.commitment_hex, &self.commitment_txid)?;
        self.anchored_at = Some((height, hash));
        Ok(self)
    }

    /// Ask once whether step 1 has confirmed.
    ///
    /// **One request, and no sleeping.** A GUI, an async runtime and a wasm
    /// build can all call this; none of them can call something that blocks.
    pub fn poll(self, reader: &impl ChainReader) -> Result<CommitmentStatus, FlowError> {
        let confirmations = match reader.confirmations(&self.commitment_txid)? {
            Some(confirmations) => confirmations,
            None => return Ok(CommitmentStatus::CommitmentGone),
        };

        if let Some(status) = self.check_for_reorg(reader)? {
            return Ok(status);
        }

        if confirmations == 0 {
            return Ok(CommitmentStatus::Waiting { confirmations });
        }

        // The vout was assumed at build time; confirm it against the chain
        // rather than carrying the assumption into a transaction that spends it.
        let vout = self.locate_commitment(reader)?;
        let mut ready = self.transition::<ReadyToRegister>();
        ready.commitment_vout = vout;
        Ok(CommitmentStatus::Ready(Box::new(ready)))
    }

    /// Whether the chain moved under this operation.
    ///
    /// `getblockhash` is available but `getblock` cannot be relied on to walk
    /// backwards, so this compares the hash at the anchored height. A different
    /// hash there means that block was replaced; a tip below the anchor means
    /// the chain got shorter. Either way what was read before is suspect.
    fn check_for_reorg(
        &self,
        reader: &impl ChainReader,
    ) -> Result<Option<CommitmentStatus>, FlowError> {
        let Some((height, ref hash)) = self.anchored_at else {
            return Ok(None);
        };
        let tip = reader.block_count()?;
        if tip < height {
            return Ok(Some(CommitmentStatus::Reorged {
                detail: format!("tip is {tip}, below the height {height} this was anchored at"),
            }));
        }
        let now = reader.block_hash(height)?;
        if now != *hash {
            return Ok(Some(CommitmentStatus::Reorged {
                detail: format!("block {height} was {hash} and is now {now}"),
            }));
        }
        Ok(None)
    }

    /// Find the output carrying the commitment, by matching its script.
    fn locate_commitment(&self, reader: &impl ChainReader) -> Result<u32, FlowError> {
        let expected = verus_tx::register::commitment_script(
            &self.reservation.commitment_hash()?,
            commitment_owner(&self.change_address)?,
        )?;
        let expected = hex_of(&expected);

        let tx = reader.raw_transaction(&self.commitment_txid)?;
        let outputs = tx["vout"].as_array().ok_or_else(|| {
            FlowError::NotReady("the commitment transaction has no outputs".into())
        })?;
        for (index, output) in outputs.iter().enumerate() {
            if output["scriptPubKey"]["hex"].as_str() == Some(expected.as_str()) {
                return u32::try_from(index).map_err(|_| {
                    FlowError::NotReady("the commitment output index does not fit".into())
                });
            }
        }
        Err(FlowError::NotReady(format!(
            "no output of {} carries this commitment",
            self.commitment_txid
        )))
    }

    /// Poll until the commitment confirms.
    ///
    /// Defined entirely in terms of [`Pending::poll`], and deliberately not
    /// available on wasm, where blocking a thread is not an option.
    ///
    /// The interval is floored at [`WaitPolicy::MINIMUM_INTERVAL`]: this polls
    /// infrastructure nobody here pays for.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn wait_blocking(
        self,
        reader: &impl ChainReader,
        policy: &WaitPolicy,
    ) -> Result<CommitmentStatus, FlowError> {
        let interval = policy.interval.max(WaitPolicy::MINIMUM_INTERVAL);
        let mut pending = self;
        for attempt in 0..policy.max_polls {
            match pending.clone().poll(reader)? {
                CommitmentStatus::Waiting { confirmations } => {
                    (policy.progress)(attempt, confirmations);
                    if attempt + 1 < policy.max_polls {
                        std::thread::sleep(interval);
                    }
                }
                settled => return Ok(settled),
            }
            pending = pending.clone();
        }
        Ok(CommitmentStatus::Waiting { confirmations: 0 })
    }
}

impl Pending<ReadyToRegister> {
    /// Run step 2, creating the identity.
    ///
    /// Only reachable from a [`CommitmentStatus::Ready`], so the ordering
    /// mistake that costs a commitment fee cannot be expressed.
    pub fn complete(
        self,
        reader: &impl ChainReader,
        broadcaster: &impl Broadcaster,
        key: &PrivateKey,
    ) -> Result<Registered, FlowError> {
        let from = key.address();
        let funding = funding::spendable(reader, &from.to_string())?;
        funding::require(&funding, self.registration_fee, &from.to_string())?;

        let commitment = Utxo {
            txid: Txid::from_display_hex(&self.commitment_txid)
                .map_err(|e| FlowError::NotReady(format!("commitment txid: {e}")))?,
            vout: self.commitment_vout,
            satoshis: Amount::ZERO,
            script_pubkey: verus_tx::register::commitment_script(
                &self.reservation.commitment_hash()?,
                commitment_owner(&self.change_address)?,
            )?,
        };

        let primary: Vec<Address> = self
            .primary_addresses
            .iter()
            .map(|address| address.parse())
            .collect::<Result<_, _>>()?;
        let change: Address = self.change_address.parse()?;

        let params = RegistrationParams::new(
            &commitment,
            &self.reservation,
            &funding.utxos,
            &primary,
            self.system_id,
            self.registration_fee,
            change,
            Expiry::within(funding.tip, DEFAULT_EXPIRY_BLOCKS),
        )
        .with_min_sigs(self.min_sigs)
        // H2: without this, `referral_levels` stays at `RegistrationParams`'s
        // default of 0 and `build_identity_registration` computes
        // `referrers = vec![referrer]` for every referred reservation, then
        // refuses it with `ReferralChainTooLong` — after the commitment fee is
        // already spent. The empty chain is correct here: this facade only
        // ever commits to a single, immediate referrer (see `referral_id` in
        // `prepare_registration_with_salt`), never a multi-level chain, so
        // there is nothing beyond `self.reservation.referral` for
        // `build_identity_registration` to walk.
        .with_referrals(self.referral_levels, &self.referral_chain);

        let signed = build_identity_registration(key, &params)?;
        broadcast(
            broadcaster,
            &signed.transaction.hex,
            &signed.transaction.txid,
        )?;

        Ok(Registered {
            name: self.reservation.name.clone(),
            identity_address: signed.identity_id,
            txid: signed.transaction.txid,
            hex: signed.transaction.hex,
            fee_paid: self.registration_fee,
        })
    }
}

/// A registration that has been broadcast.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registered {
    /// The name, without the parent.
    pub name: String,
    /// The identity's `i` address, as raw bytes.
    pub identity_address: [u8; 20],
    /// The step-2 transaction id.
    pub txid: String,
    /// The signed bytes.
    pub hex: String,
    /// What the registration cost.
    pub fee_paid: Amount,
}

/// How [`Pending::wait_blocking`] should wait.
///
/// The progress callback has no default. Waiting minutes for a commitment while
/// showing a user nothing is the behaviour that gets reported as a hang, so
/// silence has to be chosen explicitly — see [`WaitPolicy::silent`].
pub struct WaitPolicy {
    /// How long between polls.
    pub interval: std::time::Duration,
    /// How many times to poll before giving up and reporting `Waiting`.
    pub max_polls: u32,
    /// Called before each sleep, with the attempt number and confirmations.
    pub progress: Box<dyn Fn(u32, u32)>,
}

impl WaitPolicy {
    /// The shortest interval permitted.
    ///
    /// This polls infrastructure that is not ours. A tight loop against a public
    /// endpoint is rude at best and gets the user rate-limited at worst.
    pub const MINIMUM_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

    /// Poll every `interval`, reporting progress.
    pub fn new(
        interval: std::time::Duration,
        max_polls: u32,
        progress: Box<dyn Fn(u32, u32)>,
    ) -> Self {
        Self {
            interval,
            max_polls,
            progress,
        }
    }

    /// Wait without reporting anything.
    ///
    /// Named so that choosing it is visible in a diff.
    pub fn silent(interval: std::time::Duration, max_polls: u32) -> Self {
        Self {
            interval,
            max_polls,
            progress: Box::new(|_, _| {}),
        }
    }
}

/// 32 unpredictable bytes.
fn random_salt() -> [u8; 32] {
    use rand::RngCore;
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// The 20 bytes of an `i` address.
fn currency_id_bytes(id: &str) -> Result<[u8; 20], FlowError> {
    let address: Address = id.parse()?;
    Ok(address.hash())
}

/// H4: refuse a registration fee read from a node, unless it looks plausible.
///
/// `policy.id_registration_fee` is whatever `getcurrency` answered — a value
/// the node controls completely, with no consensus proof behind it — and it
/// is *burned*, so there is no output a caller could inspect and reject before
/// it is gone. The only prior bound, `verus_tx::fee::MAX_DECLARED_BURN`, is a
/// backstop sized for a *pinned* fee a caller already decided on (1000 coins,
/// to catch a typo); it does nothing to stop a hostile or misconfigured node
/// reporting 999 against a real 100-coin fee. See
/// [`verus_tx::fee::MAX_TRUSTED_NODE_FEE`] for why 500 was chosen as the
/// tighter default bar.
///
/// Shared with the currency-launch flow, whose fee has the same shape: a
/// node-supplied number that is burned rather than paid to an output anyone
/// could inspect. Only the `operation` string differs.
///
/// Returns the fee unchanged when it passes, so this composes into the
/// `let fee = ...;` it guards.
pub(crate) fn check_trusted_node_fee(
    operation: &'static str,
    reported: Amount,
) -> Result<Amount, FlowError> {
    if reported.to_sat() > verus_tx::fee::MAX_TRUSTED_NODE_FEE {
        return Err(FlowError::ImplausibleNodeFee {
            operation,
            reported,
            ceiling: Amount::from_sat(verus_tx::fee::MAX_TRUSTED_NODE_FEE),
        });
    }
    Ok(reported)
}

/// The referral chain a registration must pay, as consensus computes it.
///
/// **Paying only the immediate referrer is not enough.** `identity.cpp`'s
/// `PrecheckIdentityReservation` builds its expected list as
/// `[referrer, ...upstream]` — the upstream part read by walking the
/// *referrer's own registration transaction* — and then refuses on
/// `referrers.size() != checkReferrers.size()` with "incorrect referral
/// payments". So a referral to someone who was themselves referred needs
/// their referrers paid too, and getting it wrong is discovered only when
/// the registration is broadcast, after the commitment fee is spent.
///
/// The walk mirrors the daemon's: in the referrer's registration, skip to the
/// identity output, then take the pay-to-identity outputs that follow until
/// the reservation output ends them, capping at the currency's level count.
/// An identity registered without a referrer contributes nothing, which is
/// why the single-referrer case worked and hid this for so long.
fn referral_chain(
    reader: &impl ChainReader,
    referrer: [u8; 20],
    levels: u32,
) -> Result<Vec<[u8; 20]>, FlowError> {
    let mut chain = vec![referrer];
    if levels <= 1 {
        return Ok(chain);
    }

    let referrer_address = Address::new(verus_keys::AddressKind::Identity, referrer).to_string();
    let registration = reader.identity_registration(&referrer_address)?;
    let raw = reader.raw_transaction(&registration)?;
    let outputs = raw["vout"].as_array().ok_or_else(|| {
        FlowError::NotReady(format!(
            "{registration} has no outputs to read referrals from"
        ))
    })?;

    let mut after_identity = false;
    for output in outputs {
        let Some(hex_text) = output["scriptPubKey"]["hex"].as_str() else {
            continue;
        };
        let Ok(script) = hex::decode(hex_text) else {
            continue;
        };
        match verus_tx::decode_output_script(&script) {
            Ok(verus_tx::OutputKind::IdentityPrimary { .. }) => after_identity = true,
            Ok(verus_tx::OutputKind::IdentityPayment { identity }) if after_identity => {
                chain.push(identity);
                if u64::try_from(chain.len()).unwrap_or(u64::MAX) >= u64::from(levels) {
                    break;
                }
            }
            // Anything else after the identity output ends the referral run —
            // the reservation, or a change output. Same as the daemon's break.
            _ if after_identity => break,
            _ => {}
        }
    }
    Ok(chain)
}

/// The identity id of a referrer, given by name or by `i` address.
fn referral_id(reader: &impl ChainReader, referrer: &str) -> Result<[u8; 20], FlowError> {
    if let Ok(address) = referrer.parse::<Address>() {
        return Ok(address.hash());
    }
    // `map_err(|_| NoSuchIdentity)` here would turn a timeout — or, driven, a
    // request not yet answered — into a definite statement that the referrer
    // does not exist. A caller that then registers without the referral pays
    // the full unreferred fee.
    let record = crate::error::look_up_identity(reader, referrer)?
        .ok_or_else(|| FlowError::NoSuchIdentity(referrer.to_string()))?;
    currency_id_bytes(&record.identity_address)
}

/// The key hash a commitment is locked to.
fn commitment_owner(address: &str) -> Result<[u8; 20], FlowError> {
    let parsed: Address = address.parse()?;
    Ok(parsed.hash())
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The currency a sub-identity's fee is paid in.
///
/// Re-exported convenience so a caller registering under a tokenised parent does
/// not have to reach into `verus-tx` for the one conversion.
pub fn parent_currency(identity: [u8; 20]) -> CurrencyId {
    CurrencyId::of_identity(identity)
}
