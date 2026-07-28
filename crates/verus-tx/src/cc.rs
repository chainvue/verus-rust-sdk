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
        other => {
            // Larger pushes exist in the script language but no CC payload this
            // crate builds reaches them; refusing beats emitting an untested
            // encoding.
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
    /// Destination hashes (20 bytes each).
    pub destinations: Vec<[u8; 20]>,
    /// Serialized payload objects.
    pub vdata: Vec<Vec<u8>>,
}

impl OptCcParams {
    /// Serialize to the chunk that gets pushed into the outer script.
    pub fn to_chunk(&self) -> Result<Vec<u8>, TxError> {
        let mut chunk = Vec::new();
        push_data(&mut chunk, &[self.version, self.eval_code, self.m, self.n])?;
        for destination in &self.destinations {
            push_data(&mut chunk, destination)?;
        }
        for data in &self.vdata {
            push_data(&mut chunk, data)?;
        }
        Ok(chunk)
    }
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
    let master = OptCcParams {
        version: 3,
        eval_code: EVAL_NONE,
        m: 1,
        n: 1,
        destinations: vec![destination],
        vdata: Vec::new(),
    };
    let params = OptCcParams {
        version: 3,
        eval_code: EVAL_RESERVE_OUTPUT,
        m: 1,
        n: 1,
        destinations: vec![destination],
        vdata: vec![token_output(currency, amount)],
    };

    let mut script = Vec::new();
    push_data(&mut script, &master.to_chunk()?)?;
    script.push(OP_CHECKCRYPTOCONDITION);
    push_data(&mut script, &params.to_chunk()?)?;
    script.push(OP_DROP);
    Ok(script)
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

    #[test]
    fn refuses_an_oversized_payload() {
        let params = OptCcParams {
            version: 3,
            eval_code: EVAL_RESERVE_OUTPUT,
            m: 1,
            n: 1,
            destinations: vec![RECIPIENT],
            vdata: vec![vec![0u8; 300]],
        };
        assert!(matches!(
            params.to_chunk(),
            Err(TxError::CcPayloadTooLarge(300))
        ));
    }
}
