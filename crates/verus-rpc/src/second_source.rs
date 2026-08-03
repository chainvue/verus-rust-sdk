//! Asking two nodes the questions where one lying node costs money.
//!
//! [The crate docs](crate) list what an untrusted node can and cannot do. Most
//! of it is survivable: hiding UTXOs makes a spend fail rather than misdirect,
//! and misreporting a value or a script produces a transaction the network
//! rejects, because the sighash commits to both. One entry is different.
//!
//! > **Can** misreport chain policy, and this one has teeth: a wrong
//! > `idregistrationfees` is discovered *after* a name commitment has been
//! > spent.
//!
//! That is the shape worth a second opinion, and it is worth being precise
//! about which half of it is unrecoverable. A fee reported **too low** produces
//! a step-two registration the chain rejects: the commitment output is still
//! unspent and the salt is still held, so it can be retried with the right
//! number — the loss is a miner fee and some time. A fee reported **too high**
//! is the one with no way back. `verus_tx` bounds it, but that bound exists to
//! catch a typo rather than to doubt a number nobody here chose: against a real
//! 100-coin fee, a node answering 400 sails through with room to spare, the
//! overburn is accepted by consensus, and the difference is gone with no error
//! raised anywhere. Pinning the fee does not help, because the default value
//! being pinned is the node's.
//!
//! [`SecondSourced`] is the mechanism for that, and for the identity reads
//! below.
//!
//! # It ships a mechanism, not a policy
//!
//! Which two nodes, and what to do when they disagree, are the application's
//! decisions and stay there. This type takes two readers, asks both the
//! questions below, and returns [`RpcError::SourcesDisagree`] when the answers
//! differ. It does not pick nodes, rank them, vote among three, retry, or fall
//! back — every one of those is a policy that would be wrong for somebody.
//!
//! It implements no [`Broadcaster`](crate::Broadcaster) either: which node
//! finished bytes go to is the same kind of decision, and
//! [`SecondSourced::primary`] is there to make it explicitly.
//!
//! ```no_run
//! # use verus_rpc::{ChainReader, HttpTransport, RpcClient, RpcError, SecondSourced};
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let a = RpcClient::new(HttpTransport::new("https://api.verustest.net")?);
//! let b = RpcClient::new(HttpTransport::new("http://127.0.0.1:18843")?);
//! let reader = SecondSourced::new(a, b);
//!
//! match reader.currency("VRSCTEST") {
//!     Ok(policy) => { /* both nodes said the same thing */ }
//!     Err(RpcError::SourcesDisagree { question, primary, secondary }) => {
//!         // Nothing has been spent. Decide, or ask a third.
//!         eprintln!("{question}: {primary} vs {secondary}");
//!     }
//!     Err(other) => return Err(other.into()),
//! }
//! # Ok(()) }
//! ```
//!
//! # What is corroborated
//!
//! Four questions, chosen because each has a failure mode that is **not**
//! benign and an answer that does not legitimately churn between two healthy
//! nodes:
//!
//! * [`ChainReader::currency`] — the registration and launch fees, the referral
//!   levels and the proof protocol. The one above.
//! * [`ChainReader::identity_at`] — the trust root of
//!   `verus_flows::verify_login`, which reads an identity's authority set from
//!   a node and then verifies the signature locally *against whatever the node
//!   said*. One lying node answering with an attacker's key in
//!   `primaryaddresses` is an authentication bypass, not a failed request —
//!   there is no transaction, so nothing downstream rejects it. At a settled
//!   height this is immutable chain history, so corroborating it cannot cry
//!   wolf.
//! * [`ChainReader::identity`] — how a referrer name becomes an address. A
//!   lying node resolving `bob@` to an attacker's identity produces a
//!   registration whose referral outputs pay the attacker, and **consensus
//!   accepts it**, because the payouts match the registration it checks
//!   against. Same shape as the fee: the transaction is exactly what this SDK
//!   meant to build, from a lie.
//! * [`ChainReader::chain_info`] — **name and chain id only**. Two nodes on
//!   different chains make every other answer meaningless, and it is an easy
//!   configuration mistake. Heights are excluded because they legitimately
//!   differ; comparing them would report a disagreement every time one node was
//!   a block ahead.
//!
//! `identity` is the one of these that *can* churn: an identity updated between
//! the two calls is a genuine difference, not a lie. That surfaces as a
//! disagreement and the remedy is to ask again — which is the safe direction,
//! since the alternative is acting on one of two real answers without knowing
//! there were two.
//!
//! # What is not, and what that leaves open
//!
//! Everything else delegates to the primary. For most reads that is right on
//! the merits: corroborating a UTXO set, a mempool or a tip would report a
//! disagreement whenever two nodes were momentarily out of step, which is most
//! of the time, and those are answers whose corruption is already benign — a
//! hidden UTXO makes a spend fail rather than misdirect, and a misreported
//! value or script produces a transaction the network rejects, because the
//! sighash commits to both.
//!
//! Two gaps are worth naming rather than leaving to be discovered:
//!
//! * **[`ChainReader::block_count`] bounds login freshness.**
//!   `verus_flows::verify_login` refuses a signature older than
//!   `max_age_blocks` against the tip *this node reports*. A node that freezes
//!   its reported tip keeps a captured signature fresh indefinitely, turning
//!   that bound into no bound. Not corroborated here because two healthy nodes
//!   differ by a block routinely, and any comparison would need a tolerance —
//!   which is a policy threshold, and belongs to the application.
//! * **[`ChainReader::block`] carries the `finalsaplingroot`** a shielded spend
//!   checks its anchor against. Reading both the anchor's inputs and the header
//!   from the same node would be circular; `verus_flows::shielded` avoids that
//!   by taking the commitments from a lightwalletd server and the header from
//!   here, which is already two sources. Corroborating the header as well would
//!   strengthen it and is not done.
//!
//! # What it costs, and what it does not prove
//!
//! A corroborated question is two requests instead of one, issued
//! **sequentially** — this crate has no async, so the latency is the sum of
//! both nodes rather than the slower of them.
//!
//! Two nodes agreeing is not proof. They may share an operator, an upstream, or
//! a bug. What this defeats is *one* endpoint being wrong — the case the crate
//! docs name — and that is worth stating exactly rather than letting it read as
//! a trust guarantee.
//!
//! A source that cannot answer is a failure, not a pass. The point is a
//! corroborated answer; an uncorroborated one silently substituted would make
//! the whole thing decorative the first time a node went down. A caller can
//! always tell the two apart: disagreement is
//! [`RpcError::SourcesDisagree`], and "could not check" is whatever the node
//! returned.
//!
//! # Not for `verus_flows::drive::advance`
//!
//! That driver builds the client it hands to an operation, so a `SecondSourced`
//! cannot be passed to one at all — this is a compile-time limitation of
//! `advance`, not of this type. A hand-rolled driver holding one cassette per
//! node would work correctly, since each side's misses are recorded against its
//! own cache. On the ordinary blocking path there is nothing to think about.

use serde_json::Value;
use verus_tx::Amount;

use crate::client::ChainReader;
use crate::error::RpcError;
use crate::types::{
    AddressBalance, AddressDelta, AddressUtxo, ChainInfo, ConversionEstimate, CurrencyConverter,
    CurrencyPolicy, CurrencySummary, IdentityContent, IdentityRecord, OfferListing,
};

/// A [`ChainReader`] that asks two nodes the questions where being lied to
/// costs money or lets someone in.
///
/// Corroborates [`ChainReader::currency`], [`ChainReader::identity`],
/// [`ChainReader::identity_at`] and the chain identity half of
/// [`ChainReader::chain_info`]; everything else is served from the primary.
/// The [module docs](crate::second_source) give the reasoning, the cost, and
/// the two gaps this deliberately leaves open.
pub struct SecondSourced<A, B> {
    primary: A,
    secondary: B,
}

impl<A, B> SecondSourced<A, B> {
    /// Corroborate `primary` against `secondary`.
    ///
    /// The primary's answer is the one returned when they agree, so it is also
    /// the one every uncorroborated question is served from. Order matters for
    /// that reason and for no other: the comparison itself is symmetric.
    pub fn new(primary: A, secondary: B) -> Self {
        Self { primary, secondary }
    }

    /// The node whose answers are returned.
    pub fn primary(&self) -> &A {
        &self.primary
    }

    /// The node whose answers are only ever compared.
    pub fn secondary(&self) -> &B {
        &self.secondary
    }
}

/// Compare two answers to the same question, or say how they differed.
///
/// Both sides are **asked** before either is unwrapped, so the second source is
/// consulted even when the first has already failed. That is deliberate but
/// modest: it does not stop one node's failure from masking a disagreement,
/// because there is nothing to compare a missing answer against. When both
/// fail, the primary's error surfaces — the right one, since the primary is the
/// node everything uncorroborated is served from.
fn agreed<T: PartialEq + std::fmt::Debug>(
    question: String,
    primary: Result<T, RpcError>,
    secondary: Result<T, RpcError>,
) -> Result<T, RpcError> {
    let (primary, secondary) = (primary?, secondary?);
    if primary != secondary {
        return Err(RpcError::SourcesDisagree {
            question,
            primary: format!("{primary:?}"),
            secondary: format!("{secondary:?}"),
        });
    }
    Ok(primary)
}

impl<A: ChainReader, B: ChainReader> ChainReader for SecondSourced<A, B> {
    // ------------------------------------------------------- corroborated

    /// Both nodes, compared on **name and chain id only**.
    ///
    /// Heights are excluded: two healthy nodes are routinely a block apart, and
    /// a decorator that cried wolf about that would be turned off. What is
    /// worth catching is being pointed at two different chains, which is a
    /// configuration mistake that makes every other answer meaningless.
    fn chain_info(&self) -> Result<ChainInfo, RpcError> {
        let primary = self.primary.chain_info();
        let secondary = self.secondary.chain_info();
        let (primary, secondary) = (primary?, secondary?);
        if (&primary.name, &primary.chain_id) != (&secondary.name, &secondary.chain_id) {
            return Err(RpcError::SourcesDisagree {
                question: "getinfo (chain identity)".into(),
                primary: format!("{} / {}", primary.name, primary.chain_id),
                secondary: format!("{} / {}", secondary.name, secondary.chain_id),
            });
        }
        Ok(primary)
    }

    /// Both nodes, compared in full.
    ///
    /// Every field here is chain policy rather than node state, so any
    /// difference is one of them being wrong. This is the read the whole type
    /// exists for: a wrong `idregistrationfees` is discovered after a name
    /// commitment has been spent.
    fn currency(&self, name_or_id: &str) -> Result<CurrencyPolicy, RpcError> {
        let primary = self.primary.currency(name_or_id);
        let secondary = self.secondary.currency(name_or_id);
        agreed(format!("getcurrency {name_or_id}"), primary, secondary)
    }

    /// Both nodes, compared in full.
    ///
    /// The trust root of `verus_flows::verify_login`, which reads an identity's
    /// authority set from a node and then verifies the signature locally
    /// against it. One lying node here is an authentication bypass rather than
    /// a failed request, because there is no transaction for anything
    /// downstream to reject.
    ///
    /// Also how a referrer name becomes an address, where a lie produces a
    /// registration that pays the attacker and that consensus **accepts**.
    ///
    /// This is the corroborated read that can legitimately differ: an identity
    /// updated between the two calls is a real difference. Asking again is the
    /// remedy, and it is the safe direction.
    fn identity(&self, name_or_id: &str) -> Result<IdentityRecord, RpcError> {
        let primary = self.primary.identity(name_or_id);
        let secondary = self.secondary.identity(name_or_id);
        agreed(format!("getidentity {name_or_id}"), primary, secondary)
    }

    /// Both nodes, compared in full.
    ///
    /// As [`Self::identity`], and without its caveat: an identity as it stood
    /// at a settled height is immutable chain history, so two honest nodes
    /// cannot differ and corroborating it cannot cry wolf. This is the exact
    /// read a login verification makes.
    fn identity_at(&self, name_or_id: &str, height: u32) -> Result<IdentityRecord, RpcError> {
        let primary = self.primary.identity_at(name_or_id, height);
        let secondary = self.secondary.identity_at(name_or_id, height);
        agreed(
            format!("getidentity {name_or_id} @ {height}"),
            primary,
            secondary,
        )
    }

    // --------------------------------------------------- primary only

    fn block_count(&self) -> Result<u32, RpcError> {
        self.primary.block_count()
    }

    fn best_block_hash(&self) -> Result<String, RpcError> {
        self.primary.best_block_hash()
    }

    fn block_hash(&self, height: u32) -> Result<String, RpcError> {
        self.primary.block_hash(height)
    }

    fn mempool(&self) -> Result<Vec<String>, RpcError> {
        self.primary.mempool()
    }

    fn block(&self, height_or_hash: &str) -> Result<Value, RpcError> {
        self.primary.block(height_or_hash)
    }

    fn address_utxos(&self, addresses: &[&str]) -> Result<Vec<AddressUtxo>, RpcError> {
        self.primary.address_utxos(addresses)
    }

    fn address_deltas(
        &self,
        addresses: &[&str],
        range: Option<(u32, u32)>,
    ) -> Result<Vec<AddressDelta>, RpcError> {
        self.primary.address_deltas(addresses, range)
    }

    fn address_balance(&self, addresses: &[&str]) -> Result<AddressBalance, RpcError> {
        self.primary.address_balance(addresses)
    }

    fn estimate_conversion(
        &self,
        from: &str,
        to: &str,
        amount: &str,
        via: Option<&str>,
    ) -> Result<ConversionEstimate, RpcError> {
        self.primary.estimate_conversion(from, to, amount, via)
    }

    fn currency_state(&self, name_or_id: &str) -> Result<Value, RpcError> {
        self.primary.currency_state(name_or_id)
    }

    fn list_currencies(&self) -> Result<Vec<CurrencySummary>, RpcError> {
        self.primary.list_currencies()
    }

    fn currency_converters(&self, currencies: &[&str]) -> Result<Vec<CurrencyConverter>, RpcError> {
        self.primary.currency_converters(currencies)
    }

    fn estimate_fee(&self, blocks: u32) -> Result<Option<Amount>, RpcError> {
        self.primary.estimate_fee(blocks)
    }

    fn identity_content(&self, name_or_id: &str) -> Result<IdentityContent, RpcError> {
        self.primary.identity_content(name_or_id)
    }

    fn identity_registration(&self, name_or_id: &str) -> Result<String, RpcError> {
        self.primary.identity_registration(name_or_id)
    }

    fn vdxf_id(&self, name: &str) -> Result<[u8; 20], RpcError> {
        self.primary.vdxf_id(name)
    }

    fn offers(
        &self,
        currency_or_id: &str,
        is_currency: bool,
        with_tx: bool,
    ) -> Result<Vec<OfferListing>, RpcError> {
        self.primary.offers(currency_or_id, is_currency, with_tx)
    }

    fn verify_message(
        &self,
        identity: &str,
        signature: &str,
        message: &str,
    ) -> Result<bool, RpcError> {
        self.primary.verify_message(identity, signature, message)
    }

    fn raw_transaction(&self, txid: &str) -> Result<Value, RpcError> {
        self.primary.raw_transaction(txid)
    }

    fn decode_raw_transaction(&self, hex: &str) -> Result<Value, RpcError> {
        self.primary.decode_raw_transaction(hex)
    }

    fn confirmations(&self, txid: &str) -> Result<Option<u32>, RpcError> {
        self.primary.confirmations(txid)
    }
}
