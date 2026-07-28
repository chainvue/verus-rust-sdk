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

use crate::error::TxError;
use crate::identity::{EVAL_IDENTITY_PRIMARY, EVAL_IDENTITY_RECOVER, EVAL_IDENTITY_REVOKE};

/// `EVAL_NONE` — the master params of every CC output.
pub const EVAL_NONE: u8 = 0;
/// `EVAL_RESERVE_OUTPUT` — an output holding token (reserve) value.
pub const EVAL_RESERVE_OUTPUT: u8 = 9;

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
        0..=75 => script.push(u8::try_from(bytes.len()).expect("checked above")),
        76..=255 => {
            script.push(OP_PUSHDATA1);
            script.push(u8::try_from(bytes.len()).expect("checked above"));
        }
        // An identity carrying any content outgrows OP_PUSHDATA1 immediately —
        // a single content-map entry puts the params chunk at 266 bytes. The
        // daemon writes those as OP_PUSHDATA2, little-endian length.
        256..=65535 => {
            script.push(OP_PUSHDATA2);
            script.extend_from_slice(
                &u16::try_from(bytes.len())
                    .expect("checked above")
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
                bytes.try_into().expect("checked length"),
            )),
            33 | 65 => Ok(Destination::PubKey(bytes.to_vec())),
            21 => {
                let hash: [u8; 20] = bytes[1..].try_into().expect("checked length");
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
pub fn token_output(currency: [u8; 20], amount: u64) -> Vec<u8> {
    let mut out = var_int(TOKEN_OUTPUT_VERSION_SINGLE);
    out.extend_from_slice(&currency);
    out.extend_from_slice(&var_int(amount));
    out
}

/// Build a CryptoCondition output script paying `destination` a token amount.
///
/// The resulting output's *native* value is normally zero — the value it carries
/// is the token amount inside the payload, not the satoshis on the output.
pub fn reserve_output_script(
    destination: [u8; 20],
    currency: [u8; 20],
    amount: u64,
) -> Result<Vec<u8>, TxError> {
    let master = OptCcParams::one_of_one(EVAL_NONE, Destination::PubKeyHash(destination));
    let params = OptCcParams {
        vdata: vec![token_output(currency, amount)],
        ..OptCcParams::one_of_one(EVAL_RESERVE_OUTPUT, Destination::PubKeyHash(destination))
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
/// Layout confirmed against `SmartTransactionSignatures::toBuffer` and
/// `SmartTransactionSignature::toBuffer` in the `@bitgo/utxo-lib` fork.
pub fn fulfillment_script_sig(
    pubkey: &[u8],
    signature: &[u8; 64],
    hash_type: u8,
) -> Result<Vec<u8>, TxError> {
    /// `SmartTransactionSignatures` serialization version.
    const FULFILLMENT_VERSION: u8 = 1;
    /// A single-signature entry.
    const SIGNATURE_TYPE: u8 = 1;

    let mut fulfillment = vec![FULFILLMENT_VERSION, hash_type, 1 /* one signature */];
    fulfillment.push(SIGNATURE_TYPE);
    fulfillment
        .push(u8::try_from(pubkey.len()).map_err(|_| TxError::CcPayloadTooLarge(pubkey.len()))?);
    fulfillment.extend_from_slice(pubkey);
    fulfillment.push(64);
    fulfillment.extend_from_slice(signature);

    let mut script_sig = Vec::new();
    push_data(&mut script_sig, &fulfillment)?;
    Ok(script_sig)
}

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
pub fn identity_primary_script(
    identity_id: [u8; 20],
    identity_bytes: Vec<u8>,
    revocation_authority: [u8; 20],
    recovery_authority: [u8; 20],
) -> Result<Vec<u8>, TxError> {
    let condition = |eval_code: u8, destination: [u8; 20]| {
        OptCcParams::one_of_one(eval_code, Destination::Identity(destination))
    };

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
    let params = OptCcParams {
        vdata: vec![
            identity_bytes,
            condition(EVAL_IDENTITY_REVOKE, revocation_authority).to_chunk()?,
            condition(EVAL_IDENTITY_RECOVER, recovery_authority).to_chunk()?,
        ],
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
    const CURRENCY: [u8; 20] = [
        0xf3, 0xec, 0x55, 0x36, 0x34, 0xef, 0x17, 0x42, 0x31, 0xa1, 0x4c, 0x0a, 0x28, 0xef, 0x4e,
        0x72, 0xc9, 0xba, 0x5f, 0xda,
    ];

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
