//! CryptoCondition outputs — how Verus carries tokens.
//!
//! A token does not live in a P2PKH output. It lives in a CryptoCondition (CC)
//! output whose script is:
//!
//! ```text
//! PUSH(OptCCParams master) OP_CHECKCRYPTOCONDITION PUSH(OptCCParams params) OP_DROP
//! ```
//!
//! where each `OptCCParams` is itself a compiled script:
//!
//! ```text
//! PUSH([version, eval_code, m, n]) PUSH(destination) PUSH(vdata)...
//! ```
//!
//! The master params carry `eval_code = 0`; the second carries the real eval
//! code (9 = reserve output, i.e. "this output holds token value") and the
//! payload describing which currency and how much.
//!
//! # Where this layout comes from
//!
//! Decoded from a transaction the TypeScript SDK produced and cross-checked
//! against VerusCoin's own serializers — `OptCCParams::toBuffer` in the
//! `@bitgo/utxo-lib` fork and `TokenOutput::toBuffer` in
//! `verus-typescript-primitives`. The tests below pin it against golden bytes
//! rather than against that reading, because a comment cannot be wrong in a way
//! a test cannot catch.

use crate::currency::CurrencyId;
use crate::error::TxError;

// The eval codes all live here.
//
// Every one of them names a CryptoCondition, so they belong beside the encoder
// that writes them rather than beside whichever builder happened to need one
// first. They were spread across five modules, and that spread is what made
// `cc` depend on `identity`, `decode` on `convert` and `currency_launch`, and
// `token` on `register` — dependencies between feature groups carrying nothing
// but a `u8`. Each module still re-exports the codes it is about, so no import
// path changed.

/// `EVAL_NONE` — the master params of every CC output.
pub const EVAL_NONE: u8 = 0;
/// `EVAL_CURRENCY_DEFINITION`.
pub const EVAL_CURRENCY_DEFINITION: u8 = 2;
/// `EVAL_ACCEPTEDNOTARIZATION`.
pub const EVAL_ACCEPTEDNOTARIZATION: u8 = 5;
/// `EVAL_RESERVE_TRANSFER` — an output requesting a conversion, export or burn.
pub const EVAL_RESERVE_TRANSFER: u8 = 8;
/// `EVAL_RESERVE_OUTPUT` — an output holding token (reserve) value.
pub const EVAL_RESERVE_OUTPUT: u8 = 9;
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
/// `EVAL_RESERVE_DEPOSIT`.
pub const EVAL_RESERVE_DEPOSIT: u8 = 11;
/// `EVAL_CROSSCHAIN_EXPORT`.
pub const EVAL_CROSSCHAIN_EXPORT: u8 = 12;
/// `EVAL_CROSSCHAIN_IMPORT`.
pub const EVAL_CROSSCHAIN_IMPORT: u8 = 13;
/// `EVAL_IDENTITY_PRIMARY` — the output that holds a VerusID.
pub const EVAL_IDENTITY_PRIMARY: u8 = 14;
/// `EVAL_IDENTITY_REVOKE` — the condition letting the revocation authority spend.
pub const EVAL_IDENTITY_REVOKE: u8 = 15;
/// `EVAL_IDENTITY_RECOVER` — the condition letting the recovery authority spend.
pub const EVAL_IDENTITY_RECOVER: u8 = 16;
/// `EVAL_IDENTITY_COMMITMENT` — the hidden half of a name claim.
pub const EVAL_IDENTITY_COMMITMENT: u8 = 17;

/// `OP_CHECKCRYPTOCONDITION`, from the Verus fork of `bitcoin-ops`.
const OP_CHECKCRYPTOCONDITION: u8 = 0xcc;
/// `OP_DROP`.
const OP_DROP: u8 = 0x75;
/// `OP_PUSHDATA1`.
const OP_PUSHDATA1: u8 = 0x4c;
/// `OP_PUSHDATA2`.
const OP_PUSHDATA2: u8 = 0x4d;

/// The `OptCCParams` serialization version Verus uses.
pub const OPT_CC_PARAMS_VERSION: u8 = 3;

/// The `TokenOutput` version that carries exactly one currency amount.
///
/// Bit 1 of the version selects the "multivalue" encoding, which prefixes the
/// map with a count. Version 1 does not: it is a bare `uint160` plus amount.
const TOKEN_OUTPUT_VERSION_SINGLE: u64 = 1;

/// Append `bytes` as a minimally-encoded script push.
///
/// Minimal encoding is consensus-relevant: a non-minimal push is a different
/// script, so a different output, so a different transaction.
fn push_data(script: &mut Vec<u8>, bytes: &[u8]) -> Result<(), TxError> {
    match bytes.len() {
        0..=75 => script.push(u8::try_from(bytes.len()).expect("the match arm bounds this to 75")),
        76..=255 => {
            script.push(OP_PUSHDATA1);
            script.push(u8::try_from(bytes.len()).expect("the match arm bounds this to 255"));
        }
        // An identity carrying any content outgrows OP_PUSHDATA1 immediately —
        // a single content-map entry puts the params chunk at 266 bytes. The
        // daemon writes those as OP_PUSHDATA2, little-endian length.
        256..=65535 => {
            script.push(OP_PUSHDATA2);
            script.extend_from_slice(
                &u16::try_from(bytes.len())
                    .expect("the match arm bounds this to 65535")
                    .to_le_bytes(),
            );
        }
        other => {
            // OP_PUSHDATA4 exists but no CC payload this crate builds reaches
            // it; refusing beats emitting an untested encoding.
            return Err(TxError::CcPayloadTooLarge(other));
        }
    }
    script.extend_from_slice(bytes);
    Ok(())
}

/// Bitcoin's `VARINT` (base-128, MSB continuation, most significant group
/// first) — *not* the CompactSize used for vector lengths. Verus uses both, in
/// different fields, and mixing them produces a script the daemon rejects.
pub fn var_int(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut first = true;
    loop {
        let byte = u8::try_from(value & 0x7f).expect("masked to 7 bits");
        out.push(if first { byte } else { byte | 0x80 });
        if value <= 0x7f {
            break;
        }
        value = (value >> 7) - 1;
        first = false;
    }
    out.reverse();
    out
}

/// Who a CryptoCondition output pays.
///
/// # The encoding trap
///
/// These are **not** all serialized the same way. A key hash and a public key go
/// in bare — their length alone identifies them — while every other kind carries
/// a leading type byte:
///
/// ```text
/// PubKeyHash   PUSH(20 bytes)                 no tag
/// PubKey       PUSH(33 bytes)                 no tag
/// ScriptHash   PUSH(0x03 || 20 bytes)         tagged
/// Identity     PUSH(0x04 || 20 bytes)         tagged
/// ```
///
/// Writing an identity as a bare 20-byte hash produces a script that pays a
/// *transparent address* which happens to share the identity's hash — spendable
/// by nobody. Confirmed against `TxDestination::toBuffer` in
/// `verus-typescript-primitives` and against live pay-to-identity outputs on
/// VRSCTEST (`fixtures/daemon/identity_outputs.json`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Destination {
    /// A transparent `R` address.
    PubKeyHash([u8; 20]),
    /// A raw public key, 33 bytes compressed or 65 uncompressed.
    PubKey(Vec<u8>),
    /// A script hash.
    ScriptHash([u8; 20]),
    /// A VerusID — an `i` address.
    Identity([u8; 20]),
}

/// `TYPE_SH` from `TxDestination`.
const DEST_TYPE_SCRIPT_HASH: u8 = 3;
/// `TYPE_ID` from `TxDestination`.
const DEST_TYPE_IDENTITY: u8 = 4;

impl Destination {
    /// The bytes that get pushed into an `OptCCParams` chunk.
    pub fn to_push(&self) -> Vec<u8> {
        match self {
            Destination::PubKeyHash(hash) => hash.to_vec(),
            Destination::PubKey(key) => key.clone(),
            Destination::ScriptHash(hash) => tagged(DEST_TYPE_SCRIPT_HASH, hash),
            Destination::Identity(hash) => tagged(DEST_TYPE_IDENTITY, hash),
        }
    }

    /// Read a destination back from one push.
    pub fn from_push(bytes: &[u8]) -> Result<Self, TxError> {
        match bytes.len() {
            20 => Ok(Destination::PubKeyHash(
                bytes
                    .try_into()
                    .expect("the match arm requires exactly 20 bytes"),
            )),
            33 | 65 => Ok(Destination::PubKey(bytes.to_vec())),
            21 => {
                let hash: [u8; 20] = bytes[1..]
                    .try_into()
                    .expect("a 21-byte push, less its one type byte, is 20");
                match bytes[0] {
                    DEST_TYPE_SCRIPT_HASH => Ok(Destination::ScriptHash(hash)),
                    DEST_TYPE_IDENTITY => Ok(Destination::Identity(hash)),
                    other => Err(TxError::MalformedCryptoCondition(format!(
                        "destination type {other} is not one this crate decodes"
                    ))),
                }
            }
            other => Err(TxError::MalformedCryptoCondition(format!(
                "a destination of {other} bytes matches no known kind"
            ))),
        }
    }
}

fn tagged(kind: u8, hash: &[u8; 20]) -> Vec<u8> {
    let mut out = Vec::with_capacity(21);
    out.push(kind);
    out.extend_from_slice(hash);
    out
}

/// One `OptCCParams` section of a CryptoCondition script.
#[derive(Clone, Debug)]
pub struct OptCcParams {
    /// Serialization version; 3 for everything this crate builds.
    pub version: u8,
    /// What the output means to consensus.
    pub eval_code: u8,
    /// Signatures required.
    pub m: u8,
    /// Destinations provided.
    pub n: u8,
    /// Who the output pays.
    pub destinations: Vec<Destination>,
    /// Serialized payload objects.
    pub vdata: Vec<Vec<u8>>,
}

impl OptCcParams {
    /// A `1-of-1` condition over a single destination, carrying no payload — the
    /// shape most CryptoCondition sections have.
    pub fn one_of_one(eval_code: u8, destination: Destination) -> Self {
        Self {
            version: OPT_CC_PARAMS_VERSION,
            eval_code,
            m: 1,
            n: 1,
            destinations: vec![destination],
            vdata: Vec::new(),
        }
    }

    /// Serialize to the chunk that gets pushed into the outer script.
    pub fn to_chunk(&self) -> Result<Vec<u8>, TxError> {
        let mut chunk = Vec::new();
        push_data(&mut chunk, &[self.version, self.eval_code, self.m, self.n])?;
        for destination in &self.destinations {
            push_data(&mut chunk, &destination.to_push())?;
        }
        for data in &self.vdata {
            push_data(&mut chunk, data)?;
        }
        Ok(chunk)
    }
}

/// Assemble the two `OptCCParams` sections into a scriptPubKey.
///
/// Every CryptoCondition output this crate builds has the same outer frame:
///
/// ```text
/// PUSH(master) OP_CHECKCRYPTOCONDITION PUSH(params) OP_DROP
/// ```
///
/// What varies is only what goes in the two sections.
pub fn cc_script(master: &OptCcParams, params: &OptCcParams) -> Result<Vec<u8>, TxError> {
    let mut script = Vec::new();
    push_data(&mut script, &master.to_chunk()?)?;
    script.push(OP_CHECKCRYPTOCONDITION);
    push_data(&mut script, &params.to_chunk()?)?;
    script.push(OP_DROP);
    Ok(script)
}

/// Build the standard pay-to-identity output script.
///
/// This is what the chain itself emits when paying a VerusID: a CryptoCondition
/// with **no** eval code — the identity is expressed entirely by the
/// destination, not by a special output type.
///
/// Note the master params carry `m = 0, n = 0` and no destinations, unlike a
/// token output's `1-of-1`. That asymmetry is not cosmetic: it is what the
/// daemon's `MakeMofNCCScript` produces for an `EVAL_NONE` condition, and the
/// 36 bytes below are byte-identical to live outputs on VRSCTEST.
pub fn identity_payment_script(identity: [u8; 20]) -> Result<Vec<u8>, TxError> {
    let master = OptCcParams {
        version: OPT_CC_PARAMS_VERSION,
        eval_code: EVAL_NONE,
        m: 0,
        n: 0,
        destinations: Vec::new(),
        vdata: Vec::new(),
    };
    let params = OptCcParams::one_of_one(EVAL_NONE, Destination::Identity(identity));
    cc_script(&master, &params)
}

/// Serialize a single-currency `TokenOutput`: the payload that says *which*
/// token an output holds and *how much*.
pub fn token_output(currency: CurrencyId, amount: u64) -> Vec<u8> {
    let mut out = var_int(TOKEN_OUTPUT_VERSION_SINGLE);
    out.extend_from_slice(&currency.to_bytes());
    out.extend_from_slice(&var_int(amount));
    out
}

/// Build a CryptoCondition output script paying `destination` a token amount.
///
/// The resulting output's *native* value is normally zero — the value it carries
/// is the token amount inside the payload, not the satoshis on the output.
pub fn reserve_output_script(
    destination: [u8; 20],
    currency: CurrencyId,
    amount: u64,
) -> Result<Vec<u8>, TxError> {
    reserve_output_script_to(Destination::PubKeyHash(destination), currency, amount)
}

/// As [`reserve_output_script`], but paying any destination kind.
///
/// A sub-identity's registration fee is paid to the parent *identity*, so the
/// destination is an `i` address rather than a key hash. Writing it as a key
/// hash produces an output nobody can spend.
pub fn reserve_output_script_to(
    destination: Destination,
    currency: CurrencyId,
    amount: u64,
) -> Result<Vec<u8>, TxError> {
    let master = OptCcParams::one_of_one(EVAL_NONE, destination.clone());
    let params = OptCcParams {
        vdata: vec![token_output(currency, amount)],
        ..OptCcParams::one_of_one(EVAL_RESERVE_OUTPUT, destination)
    };
    cc_script(&master, &params)
}

/// Build the scriptSig that SPENDS a CryptoCondition output.
///
/// A CC output is not unlocked by a P2PKH scriptSig. It takes a
/// `SmartTransactionSignatures` fulfillment:
///
/// ```text
/// PUSH( version(1) || hash_type(1) || count(varint)
///       || [ sig_type(1) || varslice(pubkey) || varslice(signature) ]... )
/// ```
///
/// Two details bite here. The signature is the **64-byte compact `r || s`**, not
/// DER — the encoding every other Verus signature uses. And the hash type lives
/// *inside* the fulfillment rather than trailing the signature.
///
/// The count is a real count: an `m-of-n` condition takes `m` entries in one
/// fulfillment, not `m` separate scriptSigs. Their order follows the order the
/// signers were supplied.
///
/// Layout confirmed against `SmartTransactionSignatures::toBuffer` and
/// `SmartTransactionSignature::toBuffer` in the `@bitgo/utxo-lib` fork.
pub fn fulfillment_script_sig(
    signatures: &[(Vec<u8>, [u8; 64])],
    hash_type: u8,
) -> Result<Vec<u8>, TxError> {
    /// `SmartTransactionSignatures` serialization version.
    const FULFILLMENT_VERSION: u8 = 1;
    /// A single-signature entry.
    const SIGNATURE_TYPE: u8 = 1;

    if signatures.is_empty() {
        return Err(TxError::NoSignatures);
    }

    let mut fulfillment = vec![FULFILLMENT_VERSION, hash_type];
    fulfillment.extend_from_slice(&compact_size(signatures.len())?);
    for (pubkey, signature) in signatures {
        fulfillment.push(SIGNATURE_TYPE);
        fulfillment.push(
            u8::try_from(pubkey.len()).map_err(|_| TxError::CcPayloadTooLarge(pubkey.len()))?,
        );
        fulfillment.extend_from_slice(pubkey);
        fulfillment.push(64);
        fulfillment.extend_from_slice(signature);
    }

    let mut script_sig = Vec::new();
    push_data(&mut script_sig, &fulfillment)?;
    Ok(script_sig)
}

/// CompactSize, for the fulfillment's signature count.
///
/// A condition with more than 252 signers would need the wider forms; none
/// exists, so this refuses rather than writing an encoding nothing has tested.
fn compact_size(value: usize) -> Result<Vec<u8>, TxError> {
    match value {
        0..=252 => Ok(vec![
            u8::try_from(value).expect("the match arm bounds this to 252")
        ]),
        other => Err(TxError::CcPayloadTooLarge(other)),
    }
}

/// The key hash the `EVAL_IDENTITY_RECOVER` contract spends under.
///
/// A constant, not something derived per identity: it is
/// `hash160` of `IdentityRecoverPubKey`, the fixed contract pubkey at
/// `src/cc/CCcustom.cpp:126`.
///
/// ```text
/// 03a058410b33f893fe182f15336577f3941c28c8cadcfb0395b9c31dd5c07ccd11
///   -> b6aff598ba595562ed96e7a4841936ed236cf3bd
/// ```
///
/// Confirmed on chain: output 0 of the two VRSCTEST NFT launches
/// `sdknftbeta` (`4ad8fb14…7d7e`) and `kmerg` (`8d8671d4…b6b3`) both end in
/// this same value, which is what makes it a constant rather than something
/// each identity computes for itself.
///
/// It goes into the recovery condition of a tokenized-control identity — see
/// [`identity_primary_script`].
pub const IDENTITY_RECOVER_KEYHASH: [u8; 20] = [
    0xb6, 0xaf, 0xf5, 0x98, 0xba, 0x59, 0x55, 0x62, 0xed, 0x96, 0xe7, 0xa4, 0x84, 0x19, 0x36, 0xed,
    0x23, 0x6c, 0xf3, 0xbd,
];

/// Build the output script that HOLDS a VerusID.
///
/// Its shape is not the token layout. The master condition is `1-of-3` over the
/// identity and its two authorities, and the params carry **three** `vdata`
/// entries: the identity itself, then compiled revoke and recover conditions.
/// Those last two are what let the revocation and recovery authorities spend the
/// output at all — an identity output without them cannot be revoked.
///
/// ```text
/// master  v3 eval 0  1-of-3  [identity, revocation, recovery]
/// params  v3 eval 14 1-of-1  [identity]
///         vdata: identity bytes
///                v3 eval 15 1-of-1 [revocation]
///                v3 eval 16 1-of-1 [recovery]
/// ```
///
/// Verified by re-encoding live VRSCTEST identity outputs byte for byte.
///
/// # Tokenized control
///
/// `tokenized_control` is the identity's `FLAG_TOKENIZED_CONTROL` bit — an NFT
/// launch sets it, and nothing else this crate builds does. When it is set the
/// **recovery** condition gains a second destination,
/// [`IDENTITY_RECOVER_KEYHASH`], and becomes `1-of-2`:
///
/// ```text
///                v3 eval 16 1-of-2 [recovery, IDENTITY_RECOVER_KEYHASH]
/// ```
///
/// The revoke condition and the master are untouched. This mirrors
/// `CIdentity::IdentityUpdateOutputScript` (`src/key_io.cpp:1881`), which
/// pushes the contract key hash onto `dests3` — and only `dests3` — under
/// `HasTokenizedControl()`.
///
/// It has to be passed in rather than read out of `identity_bytes` because this
/// crate treats that payload as opaque. Getting it wrong is not a soft failure:
/// an NFT launch whose identity output omits the destination is refused by
/// consensus as `-25: bad-txns-failed-precheck`, which names nothing.
pub fn identity_primary_script(
    identity_id: [u8; 20],
    identity_bytes: Vec<u8>,
    revocation_authority: [u8; 20],
    recovery_authority: [u8; 20],
    tokenized_control: bool,
) -> Result<Vec<u8>, TxError> {
    let master = OptCcParams {
        version: OPT_CC_PARAMS_VERSION,
        eval_code: EVAL_NONE,
        m: 1,
        n: 3,
        destinations: vec![
            Destination::Identity(identity_id),
            Destination::Identity(revocation_authority),
            Destination::Identity(recovery_authority),
        ],
        vdata: Vec::new(),
    };

    let revoke = OptCcParams::one_of_one(
        EVAL_IDENTITY_REVOKE,
        Destination::Identity(revocation_authority),
    );
    let mut recover = OptCcParams::one_of_one(
        EVAL_IDENTITY_RECOVER,
        Destination::Identity(recovery_authority),
    );
    if tokenized_control {
        recover
            .destinations
            .push(Destination::PubKeyHash(IDENTITY_RECOVER_KEYHASH));
        recover.n = 2;
    }

    let params = OptCcParams {
        vdata: vec![identity_bytes, revoke.to_chunk()?, recover.to_chunk()?],
        ..OptCcParams::one_of_one(EVAL_IDENTITY_PRIMARY, Destination::Identity(identity_id))
    };
    cc_script(&master, &params)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Output 0 of the TypeScript SDK's `sendCurrency (token transfer, token +
    /// native change)` golden: 0.4 of a token to `TEST_ADDRESS_B`.
    const GOLDEN_RESERVE_OUTPUT: &str = "1a040300010114a00a0a30a020a4f4708ee28aeb62f14eefc304d9cc34040309010114a00a0a30a020a4f4708ee28aeb62f14eefc304d91901f3ec553634ef174231a14c0a28ef4e72c9ba5fda9288b30075";
    /// hash160 of `RPsQDnaxXgrLjcVBh3SpvCpTabWxAdMdzu`.
    const RECIPIENT: [u8; 20] = [
        0xa0, 0x0a, 0x0a, 0x30, 0xa0, 0x20, 0xa4, 0xf4, 0x70, 0x8e, 0xe2, 0x8a, 0xeb, 0x62, 0xf1,
        0x4e, 0xef, 0xc3, 0x04, 0xd9,
    ];
    /// The token's currency id.
    const CURRENCY: CurrencyId = CurrencyId::from_bytes([
        0xf3, 0xec, 0x55, 0x36, 0x34, 0xef, 0x17, 0x42, 0x31, 0xa1, 0x4c, 0x0a, 0x28, 0xef, 0x4e,
        0x72, 0xc9, 0xba, 0x5f, 0xda,
    ]);

    #[test]
    fn reproduces_the_golden_reserve_output_script() {
        let script = reserve_output_script(RECIPIENT, CURRENCY, 40_000_000).unwrap();
        assert_eq!(hex::encode(script), GOLDEN_RESERVE_OUTPUT);
    }

    #[test]
    fn var_int_matches_the_golden_amount_encoding() {
        // 0.4 of a token, as it appears in the golden payload.
        assert_eq!(hex::encode(var_int(40_000_000)), "9288b300");
        // Boundaries of the base-128 continuation encoding.
        assert_eq!(hex::encode(var_int(0)), "00");
        assert_eq!(hex::encode(var_int(127)), "7f");
        assert_eq!(hex::encode(var_int(128)), "8000");
    }

    #[test]
    fn var_int_is_not_compact_size() {
        // The two encodings coexist in Verus and are easy to confuse: CompactSize
        // would render 128 as `8080` and 40_000_000 as a 0xfe-prefixed LE word.
        assert_ne!(hex::encode(var_int(128)), "8080");
        assert_eq!(var_int(40_000_000).len(), 4);
    }

    /// Output 0 of `sdknftbeta`'s launch on VRSCTEST,
    /// `4ad8fb14e5f1be8df45fb3b65be44a9c88005b894c556863e908a25e9a977d7e` — the
    /// only shape of identity output that carries a tokenized-control recovery
    /// condition.
    const GOLDEN_NFT_IDENTITY_OUTPUT: &str = "47040300010315049bd668e1e4c5091dc39d226dda6d78dff5ae6a0b15049bd668e1e4c5091dc39d226dda6d78dff5ae6a0b15049bd668e1e4c5091dc39d226dda6d78dff5ae6a0bcc4cee04030e010115049bd668e1e4c5091dc39d226dda6d78dff5ae6a0b4c8403000000050000000114485ec79f34a411df3e3eea999c75903bea91023401000000a6ef9ea235635e328124ff3429db9f9e91b64e2d0a73646b6e66746265746100009bd668e1e4c5091dc39d226dda6d78dff5ae6a0b9bd668e1e4c5091dc39d226dda6d78dff5ae6a0b00a6ef9ea235635e328124ff3429db9f9e91b64e2d000000001b04030f010115049bd668e1e4c5091dc39d226dda6d78dff5ae6a0b30040310010215049bd668e1e4c5091dc39d226dda6d78dff5ae6a0b14b6aff598ba595562ed96e7a4841936ed236cf3bd75";
    /// `sdknftbeta`'s own id, which is also its revocation and recovery
    /// authority.
    const NFT_IDENTITY: [u8; 20] = [
        0x9b, 0xd6, 0x68, 0xe1, 0xe4, 0xc5, 0x09, 0x1d, 0xc3, 0x9d, 0x22, 0x6d, 0xda, 0x6d, 0x78,
        0xdf, 0xf5, 0xae, 0x6a, 0x0b,
    ];

    /// The serialized identity from that output — everything between the
    /// `4c84` push and the revoke condition that follows it.
    fn nft_identity_bytes() -> Vec<u8> {
        let script = hex::decode(GOLDEN_NFT_IDENTITY_OUTPUT).unwrap();
        let start = script
            .windows(2)
            .position(|w| w == [OP_PUSHDATA1, 0x84])
            .unwrap()
            + 2;
        script[start..start + 0x84].to_vec()
    }

    /// Rebuilding a live tokenized-control identity output byte for byte.
    ///
    /// Without the contract destination the launch is refused as `-25:
    /// bad-txns-failed-precheck`, which names neither the output nor the field.
    #[test]
    fn reproduces_a_live_tokenized_control_identity_output() {
        let script = identity_primary_script(
            NFT_IDENTITY,
            nft_identity_bytes(),
            NFT_IDENTITY,
            NFT_IDENTITY,
            true,
        )
        .unwrap();
        assert_eq!(hex::encode(script), GOLDEN_NFT_IDENTITY_OUTPUT);
    }

    /// The flag changes exactly one condition: **recovery** grows a second
    /// destination and becomes `1-of-2`. Revocation is untouched — matching
    /// `CIdentity::IdentityUpdateOutputScript`, which pushes the contract key
    /// hash onto `dests3` and only `dests3`.
    ///
    /// Putting it on the revoke condition instead would hand revocation to a
    /// contract while leaving recovery unreachable, and the resulting script is
    /// the same length, so a test that only counted bytes would pass.
    #[test]
    fn tokenized_control_changes_recovery_and_not_revocation() {
        let build = |tokenized| {
            hex::encode(
                identity_primary_script(
                    NFT_IDENTITY,
                    nft_identity_bytes(),
                    NFT_IDENTITY,
                    NFT_IDENTITY,
                    tokenized,
                )
                .unwrap(),
            )
        };
        let id = hex::encode(NFT_IDENTITY);
        let contract = hex::encode(IDENTITY_RECOVER_KEYHASH);

        // PUSH(len) version 3, eval, m, n, then the destinations.
        let revoke = format!("1b04030f0101 1504{id}").replace(' ', "");
        let recover_plain = format!("1b040310 0101 1504{id}").replace(' ', "");
        let recover_tokenized = format!("30040310 0102 1504{id} 14{contract}").replace(' ', "");

        let plain = build(false);
        assert!(plain.contains(&revoke), "{plain}");
        assert!(plain.ends_with(&format!("{recover_plain}75")), "{plain}");
        assert!(!plain.contains(&contract), "{plain}");

        let tokenized = build(true);
        assert!(tokenized.contains(&revoke), "{tokenized}");
        assert!(
            tokenized.ends_with(&format!("{recover_tokenized}75")),
            "{tokenized}"
        );
    }

    #[test]
    fn the_amount_is_actually_committed_to() {
        let a = reserve_output_script(RECIPIENT, CURRENCY, 40_000_000).unwrap();
        let b = reserve_output_script(RECIPIENT, CURRENCY, 40_000_001).unwrap();
        assert_ne!(a, b);
    }

    fn params_carrying(payload: usize) -> OptCcParams {
        OptCcParams {
            vdata: vec![vec![0u8; payload]],
            ..OptCcParams::one_of_one(EVAL_RESERVE_OUTPUT, Destination::PubKeyHash(RECIPIENT))
        }
    }

    /// A payload over 255 bytes takes `OP_PUSHDATA2` with a little-endian
    /// length. An identity with any content lands here immediately, and the
    /// daemon writes `4d 0a01` for the 266-byte case.
    #[test]
    fn a_payload_over_255_bytes_uses_pushdata2() {
        let chunk = params_carrying(300).to_chunk().unwrap();
        // …[4-byte header push][20-byte destination push] then the payload push.
        let payload_push = &chunk[5 + 21..];
        assert_eq!(payload_push[0], OP_PUSHDATA2);
        assert_eq!(&payload_push[1..3], &300u16.to_le_bytes());
        assert_eq!(payload_push.len(), 3 + 300);
    }

    #[test]
    fn a_payload_of_255_bytes_still_uses_pushdata1() {
        let chunk = params_carrying(255).to_chunk().unwrap();
        let payload_push = &chunk[5 + 21..];
        assert_eq!(payload_push[0], OP_PUSHDATA1);
        assert_eq!(payload_push[1], 255);
    }

    /// `OP_PUSHDATA4` is not emitted: nothing this crate builds reaches it, and
    /// an untested encoding is worse than a refusal.
    #[test]
    fn refuses_an_oversized_payload() {
        assert!(matches!(
            params_carrying(70_000).to_chunk(),
            Err(TxError::CcPayloadTooLarge(70_000))
        ));
    }
}
