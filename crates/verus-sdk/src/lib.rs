//! Verus SDK — build and sign transactions; optionally look up and broadcast.
//!
//! This crate is the facade: it re-exports a coherent API over `verus-wire`,
//! `verus-keys`, `verus-tx` and (behind features) `verus-sapling`, `verus-rpc`,
//! `verus-flows` and `verus-light`. By default it builds and signs bytes and
//! never opens a socket; the `network` feature adds lookup and broadcast.
//!
//! ```text
//! default = transparent    send VRSC and tokens; no prover, no network
//! shielded                + find your notes and derive ZIP-32 keys
//! prover                  + BUILD t→z / z→z / z→t; needs the Sapling parameters
//! multicore               native-only speedup for the prover
//! network                 + ask a node, compose flows, broadcast (verus-rpc + verus-flows)
//! light                   + scan and witness shielded notes via lightwalletd
//! ```
//!
//! # Where the wallet-shaped pieces are
//!
//! Not everything a wallet needs is in an obviously-named module, so:
//!
//! * **A recovery phrase** — [`verus_keys::bip39::mnemonic_from_entropy`],
//!   from 32 bytes you supply. There is no RNG in this crate; see the
//!   `keygen_phrase` example.
//! * **A shielded account, and spending from it** — [`light`], which carries
//!   the whole path from `derive_account` through `plan_spend` and
//!   `prove_spend`.
//! * **Pending payments** — `network::ChainReader::mempool`, the one thing a
//!   UTXO set and a delta list both leave out.
//! * **A second opinion on a node** — [`network::SecondSourced`], for the reads
//!   where one lying node costs money or lets someone in.
//!
//! `shielded` on its own deliberately cannot build a shielded transaction — it
//! is the light half a balance-only wallet wants, with no bellman in the
//! dependency graph. Ask for `prover` when you need to spend.
//!
//! `network` is off by default for the same reason `shielded` is split from
//! `prover`: the offline half is usable from an air-gapped signer, and linking
//! an HTTP client should be a decision, not a side effect. With it on, a wallet
//! is one dependency: `network::RpcClient` answers questions, `network::send`
//! and friends do lookup → build → sign → broadcast, and the node never sees a
//! key. (Plain spans, not links: the module only exists with the feature on.)

#![doc(html_no_source)]

pub use verus_keys;
pub use verus_wire;

#[cfg(feature = "transparent")]
pub use verus_tx;

#[cfg(feature = "shielded")]
pub use verus_sapling;

#[cfg(feature = "network")]
pub use verus_flows;

#[cfg(feature = "network")]
pub use verus_rpc;

#[cfg(feature = "light")]
pub use verus_light;

/// Money, and the transaction primitives every flow shares.
///
/// Re-exported here so a consumer writes `verus_sdk::money::Amount` rather than
/// reaching through the crate that happens to define it. The underlying crates
/// stay public — this is a shorter path to the same types, not a wrapper.
#[cfg(feature = "transparent")]
pub mod money {
    pub use verus_tx::fee::DEFAULT_FEE_PER_KB;
    pub use verus_tx::{Amount, Expiry, TxError, Txid, Utxo, DEFAULT_EXPIRY_BLOCKS, SATS_PER_COIN};
}

/// Sending value: native coins and tokens.
#[cfg(feature = "transparent")]
pub mod send {
    pub use verus_tx::{
        build_token_send, build_transparent_send, CurrencyId, Recipient, SendParams,
        SignedTransaction, TokenRecipient, TokenSendParams,
    };
}

/// The VerusID lifecycle: register, update, revoke, recover.
///
/// The order matters more than it looks. A freshly registered identity is its
/// own revocation and recovery authority, which makes it **unrevokable** —
/// pointing recovery elsewhere is a decision at registration time, through
/// [`identity::RegistrationParams::with_authorities`], not a later refinement.
#[cfg(feature = "transparent")]
pub mod identity {
    pub use verus_tx::identity::{Identity, FLAG_LOCKED, FLAG_REVOKED};
    pub use verus_tx::register::{
        build_identity_registration, build_name_commitment, commitment_script, identity_id,
        registration_fees, CommitmentParams, NameReservation, ParentCurrencyFee,
        RegistrationParams, SignedRegistration,
    };
    pub use verus_tx::revoke::{
        build_identity_recovery, build_identity_revocation, RecoveryParams, RevocationParams,
    };
    pub use verus_tx::update::{build_identity_update, UpdateParams};
    pub use verus_tx::{build_identity_spend, IdentitySpendParams};
    pub use verus_tx::{identity_payment_script, identity_primary_script};
}

/// Signing across machines, for identities that need more than one key.
#[cfg(feature = "transparent")]
pub mod cosign {
    pub use verus_tx::partial::{
        CollectedSignature, InputKind, PartialInput, PartialTransaction, Summary,
    };
}

/// Reading what an output is, before deciding whether it can be spent.
#[cfg(feature = "transparent")]
pub mod decode {
    pub use verus_tx::{decode_output_script, Destination, OutputKind};
    pub use verus_tx::{token_balances, TokenBalances};
}

/// Converting between currencies: convert, preconvert, burn and mint.
///
/// All four are the same output on the wire — a `CReserveTransfer` — differing
/// only in flags and destination, which is why they share
/// [`convert::ConversionKind`] rather than four builders.
#[cfg(feature = "transparent")]
pub mod convert {
    pub use verus_tx::convert::{RT_CONVERT, RT_MINT_CURRENCY, RT_PRECONVERT, RT_VALID};
    pub use verus_tx::{
        build_conversion, build_conversion_transaction, ConversionKind, ConversionParams,
        ReserveTransfer, TransferDestination,
    };
}

/// Marketplace offers: fund one, make one, take one.
///
/// The maker signs an input under `SIGHASH_SINGLE | ANYONECANPAY` paired with
/// the output they demand; the taker appends their side and signs the whole.
/// Neither holds the other's key, and nothing is escrowed.
#[cfg(feature = "transparent")]
pub mod offer {
    pub use verus_tx::offer::{
        fund_offer, make_offer, offer_funding_script, take_offer, OfferParams, SignedOffer,
        TakeParams, Wanted, OFFER_HASH_TYPE,
    };
}

/// Transparent P2SH multisig: m-of-n conditions held by a script hash.
///
/// Distinct from a multi-address VerusID (see [`identity`]): this is the plain
/// Bitcoin-style construction, reproducing the daemon's `createmultisig`.
#[cfg(feature = "transparent")]
pub mod multisig {
    pub use verus_tx::multisig::{
        address, multisig_script_sig, p2sh_script_pubkey, redeem_script, script_hash,
        MultisigSignature, MAX_MULTISIG_KEYS,
    };
}

/// Signing messages as a VerusID, and verifying them.
///
/// This is a signature over data, not a transaction: nothing here spends. The
/// scheme is the daemon's own — `verify_message` accepts what `signmessage`
/// produces and vice versa.
#[cfg(feature = "transparent")]
pub mod signature {
    pub use verus_tx::signature::{
        add_signature, identity_signature_hash, message_hash, recover_signers, sign_message,
        verify_message, IdentitySignature, SIGNATURE_PREFIX,
    };
}

/// Defining and launching currencies: tokens, fractional baskets, and the
/// seven-output launch transaction.
///
/// Same-chain tokens and baskets only — a PBaaS chain launch depends on live
/// notarization state and is refused. See `verus_tx::currency_launch` for why
/// the same-chain case can be built offline at all.
#[cfg(feature = "transparent")]
pub mod currency {
    pub use verus_tx::currency_definition::{
        currency_definition_script, serialize_definition, CurrencyDefinition, Preallocation,
    };
    pub use verus_tx::currency_launch::{
        build_currency_launch, build_launch_outputs, LaunchContext, LaunchOutputs, LaunchParams,
    };
    pub use verus_tx::CurrencyId;
}

/// VDXF: derive the 20-byte keys that address data on identities, offline.
///
/// `getvdxfid` without a node. The same name yields the same key for
/// everyone — apps define their data keys at compile time and write content
/// to identities fully offline. Mind the namespace trap documented in
/// `verus_tx::vdxf`: a friendly `ns::` resolves as a ROOT name, so a
/// chain-registered app identity must namespace by its `i` address.
#[cfg(feature = "transparent")]
pub mod vdxf {
    pub use verus_tx::{data_key, qualified_key, root_namespace};
}

/// The networked half: ask a node, compose whole operations, broadcast.
///
/// Everything here talks to infrastructure, and none of it ever sends a key —
/// the node is asked questions and given finished bytes. Reading and
/// broadcasting are separate traits ([`network::ChainReader`],
/// [`network::Broadcaster`]), so a dry-run build can take a reader and be
/// *incapable* of sending.
///
/// The transport is bundled: [`network::HttpTransport`] over TLS, native only.
/// A wasm build or a custom transport takes `verus-flows` directly and
/// implements `verus_rpc::Transport` itself — the facade's `network` feature
/// deliberately picks the batteries-included path.
#[cfg(feature = "network")]
pub mod network {
    pub use verus_flows::drive::{advance, Answers, Step};
    pub use verus_flows::{
        broadcast, browse, burn, convert, currency_names, estimate, history, identity_held,
        inspect, key_address, launch_currency, mint, native_currency, plan_conversion,
        prepare_burn, prepare_conversion, prepare_launch, prepare_mint, prepare_publish,
        prepare_registration, prepare_registration_with_salt, prepare_send,
        prepare_send_from_identity, prepare_send_token, prepare_take, publish, read, read_all,
        read_history, send, send_from_identity, send_token, sign_login, spendable, take,
        token_balances, verify_login, AwaitingCommitment, CommitmentStatus, ConversionPlan, Demand,
        FlowError, Funding, HistoryEntry, Launched, Listing, LoggedIn, LoginPolicy, LoginRequest,
        Namespace, OfferTerms, Pending, Published, ReadyToRegister, Registered,
        RegistrationOptions, Sent, Taken, Taking, TokenBalances, Unsent, WaitPolicy,
    };
    pub use verus_rpc::{
        AddressBalance, AddressDelta, AddressUtxo, Broadcaster, Cassette, ChainInfo, ChainReader,
        ContentValue, ConversionEstimate, CurrencyConverter, CurrencyPolicy, CurrencySummary,
        HttpTransport, IdentityContent, IdentityRecord, OfferListing, OfferSide, RpcClient,
        RpcError, SecondSourced, SignedAmount,
    };
}

/// Shielded notes over the network: derive, scan, value, witness and spend.
///
/// The whole wallet path is here, in the order a wallet walks it: derive an
/// account from a BIP-39 seed ([`light::derive_account`] — the phrase itself
/// comes from [`verus_keys::bip39`]), [`light::scan`] for notes, take a balance
/// off a [`light::ScanResult`] with `scan(..).balance(&spent)`, then
/// [`light::plan_spend`] and [`light::prove_spend`].
///
/// [`light::ScanResult`] is what a wallet persists between runs — the notes and
/// the nullifiers together, which is the pair [`light::ScanResult::unspent`]
/// needs and the pair that is wrong in the dangerous direction if they are
/// stored apart. Turn on the `serde` feature and it round-trips; hand it back
/// to [`light::scan_after`] and the next scan covers only the tail, and proves
/// it is the same chain — then fold that tail back in with
/// [`light::ScanResult::absorb`], which is what keeps the history rather than
/// replacing it.
#[cfg(feature = "light")]
pub mod light {
    pub use verus_flows::shielded::{
        check_anchor, full_output, plan_spend, scan, scan_after, select_notes, witness_note,
        Checkpoint, ScanResult, SeenNullifier, SpendPlan, WitnessedNote, MAX_SPEND_NOTES,
        REORG_CHECKPOINTS,
    };
    pub use verus_light::{GrpcWebTransport, LightClient, LightError, LightTransport};
    /// Deriving the account a scan and a spend are about.
    pub use verus_sapling::derive::{
        derive_account, DerivedAccount, COIN_TYPE_MAINNET, COIN_TYPE_TESTNET,
    };
    pub use verus_sapling::scan::{
        dfvk_from_bytes, dfvk_from_extsk, read_note, DetectedNote, DiversifiableFullViewingKey,
        FullOutput,
    };
    /// `zs…` addresses, which every shielded recipient is decoded from.
    pub use verus_sapling::zaddr;
    /// Note-plaintext encoding — always this on Verus, and a parameter of
    /// [`read_note`].
    pub use verus_sapling::VERUS_ZIP212;

    /// Spending needs the prover as well: selecting, witnessing and checking
    /// the anchor are cheap and available above, but turning that into a
    /// transaction is Groth16 and ~50 MB of Sapling parameters.
    ///
    /// [`SaplingParams`] is re-exported here because it appears in the
    /// signatures of the functions beside it — a re-exported function whose
    /// argument type a caller has to go and find somewhere else is only half
    /// re-exported.
    #[cfg(feature = "prover")]
    pub use verus_flows::shielded::{
        prepare_spend, prove_spend, spend, ShieldedRecipient, ShieldedSpent, SpendRequest,
        TransparentRecipient,
    };
    #[cfg(feature = "prover")]
    pub use verus_sapling::build::MEMO_SIZE;
    #[cfg(feature = "prover")]
    pub use verus_sapling::params::SaplingParams;
}
