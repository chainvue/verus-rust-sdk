//! Reading output scripts back — what a UTXO actually holds.
//!
//! Coin selection cannot work on token-bearing UTXOs without this: an output's
//! satoshi value says nothing about the tokens inside it, which live in the
//! CryptoCondition payload.
//!
//! # The rule that matters
//!
//! **A CryptoCondition script that fails to parse is an error, never "no
//! tokens".** Treating an unparseable smart output as plain native value
//! silently under-counts what a transaction is spending, which is how token
//! value gets burned. Only scripts that are genuinely not CryptoCondition
//! outputs take the native path.

use crate::cc::{EVAL_RESERVE_OUTPUT, OPT_CC_PARAMS_VERSION};
use crate::error::TxError;

/// `OP_CHECKCRYPTOCONDITION`.
const OP_CHECKCRYPTOCONDITION: u8 = 0xcc;
/// `OP_DROP`.
const OP_DROP: u8 = 0x75;
/// `OP_PUSHDATA1`.
const OP_PUSHDATA1: u8 = 0x4c;

/// What an output turned out to be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputKind {
    /// A plain pay-to-public-key-hash output: native value only.
    PubKeyHash {
        /// The 20-byte hash it pays to.
        hash: [u8; 20],
    },
    /// A CryptoCondition output holding token (reserve) value.
    ReserveOutput {
        /// Destination hash.
        destination: [u8; 20],
        /// `(currency id, amount)` pairs the output carries.
        tokens: Vec<([u8; 20], u64)>,
    },
    /// A CryptoCondition output whose eval code this crate does not decode yet
    /// — an identity, a reserve transfer, a currency definition.
    ///
    /// Returned rather than ignored so a caller can refuse to spend value it
    /// cannot account for.
    UnsupportedCryptoCondition {
        /// The eval code found.
        eval_code: u8,
    },
}

/// Read pushes out of a script, rejecting anything malformed.
struct ScriptReader<'a> {
    script: &'a [u8],
    offset: usize,
}

impl<'a> ScriptReader<'a> {
    fn new(script: &'a [u8]) -> Self {
        Self { script, offset: 0 }
    }

    fn done(&self) -> bool {
        self.offset >= self.script.len()
    }

    fn peek(&self) -> Option<u8> {
        self.script.get(self.offset).copied()
    }

    fn take_opcode(&mut self) -> Result<u8, TxError> {
        let byte = self.peek().ok_or_else(|| malformed("script ended early"))?;
        self.offset += 1;
        Ok(byte)
    }

    /// Read one push, returning its data. Errors on any non-push opcode.
    fn take_push(&mut self) -> Result<&'a [u8], TxError> {
        let opcode = self.take_opcode()?;
        let length = match opcode {
            1..=75 => usize::from(opcode),
            OP_PUSHDATA1 => usize::from(self.take_opcode()?),
            other => {
                return Err(malformed(&format!(
                    "expected a data push, found opcode {other:#04x}"
                )))
            }
        };
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| malformed("push length overflows"))?;
        let data = self
            .script
            .get(self.offset..end)
            .ok_or_else(|| malformed("push runs past the end of the script"))?;
        self.offset = end;
        Ok(data)
    }
}

fn malformed(detail: &str) -> TxError {
    TxError::MalformedCryptoCondition(detail.to_string())
}

/// Decode Bitcoin's `VARINT` (base-128, MSB continuation).
fn read_var_int(bytes: &[u8], offset: &mut usize) -> Result<u64, TxError> {
    let mut value: u64 = 0;
    loop {
        let byte = *bytes
            .get(*offset)
            .ok_or_else(|| malformed("VARINT ended early"))?;
        *offset += 1;
        value = value
            .checked_shl(7)
            .and_then(|v| v.checked_add(u64::from(byte & 0x7f)))
            .ok_or_else(|| malformed("VARINT overflows u64"))?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        value = value
            .checked_add(1)
            .ok_or_else(|| malformed("VARINT overflows u64"))?;
    }
}

/// Parse a single-currency `TokenOutput` payload.
fn parse_token_output(payload: &[u8]) -> Result<([u8; 20], u64), TxError> {
    let mut offset = 0;
    let version = read_var_int(payload, &mut offset)?;
    // Bit 1 selects the multivalue encoding, which prefixes a count. Nothing
    // here emits it and nothing here decodes it — refuse rather than misread the
    // bytes that follow as a currency id.
    if version != 1 {
        return Err(malformed(&format!(
            "unsupported TokenOutput version {version}; only single-value (1) is decoded"
        )));
    }
    let currency: [u8; 20] = payload
        .get(offset..offset + 20)
        .ok_or_else(|| malformed("TokenOutput ended before its currency id"))?
        .try_into()
        .expect("slice is 20 bytes");
    offset += 20;
    let amount = read_var_int(payload, &mut offset)?;
    if offset != payload.len() {
        return Err(malformed("trailing bytes after the TokenOutput amount"));
    }
    Ok((currency, amount))
}

/// Decode an output script.
pub fn decode_output_script(script: &[u8]) -> Result<OutputKind, TxError> {
    // P2PKH first: the overwhelmingly common case, and unambiguous.
    if script.len() == 25 && script[0..3] == [0x76, 0xa9, 0x14] && script[23..25] == [0x88, 0xac] {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&script[3..23]);
        return Ok(OutputKind::PubKeyHash { hash });
    }

    // Not a CryptoCondition output either? Then it is something this crate has
    // no opinion about, and saying so is better than guessing.
    if !script.contains(&OP_CHECKCRYPTOCONDITION) {
        return Err(TxError::UnsupportedScript(hex::encode(script)));
    }

    // From here on, failure is an ERROR and never a fallback to "native only":
    // a smart output we cannot read is value we cannot account for.
    let mut reader = ScriptReader::new(script);
    let _master = reader.take_push()?;
    if reader.take_opcode()? != OP_CHECKCRYPTOCONDITION {
        return Err(malformed(
            "expected OP_CHECKCRYPTOCONDITION after the master params",
        ));
    }
    let params_chunk = reader.take_push()?;
    if reader.take_opcode()? != OP_DROP {
        return Err(malformed("expected OP_DROP after the params"));
    }
    if !reader.done() {
        return Err(malformed("trailing bytes after OP_DROP"));
    }

    // The params chunk is itself a script: header push, destinations, payloads.
    let mut params = ScriptReader::new(params_chunk);
    let header = params.take_push()?;
    if header.len() != 4 {
        return Err(malformed("OptCCParams header is not 4 bytes"));
    }
    let (version, eval_code, _m, n) = (header[0], header[1], header[2], header[3]);
    if version != OPT_CC_PARAMS_VERSION {
        return Err(malformed(&format!(
            "unsupported OptCCParams version {version}"
        )));
    }

    let mut destinations = Vec::new();
    for _ in 0..n {
        let destination: [u8; 20] = params
            .take_push()?
            .try_into()
            .map_err(|_| malformed("destination is not a 20-byte hash"))?;
        destinations.push(destination);
    }

    if eval_code != EVAL_RESERVE_OUTPUT {
        return Ok(OutputKind::UnsupportedCryptoCondition { eval_code });
    }

    let mut tokens = Vec::new();
    while !params.done() {
        tokens.push(parse_token_output(params.take_push()?)?);
    }
    let destination = *destinations
        .first()
        .ok_or_else(|| malformed("reserve output has no destination"))?;
    Ok(OutputKind::ReserveOutput {
        destination,
        tokens,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cc::reserve_output_script;

    const GOLDEN_RESERVE_OUTPUT: &str = "1a040300010114a00a0a30a020a4f4708ee28aeb62f14eefc304d9cc34040309010114a00a0a30a020a4f4708ee28aeb62f14eefc304d91901f3ec553634ef174231a14c0a28ef4e72c9ba5fda9288b30075";
    const RECIPIENT: [u8; 20] = [
        0xa0, 0x0a, 0x0a, 0x30, 0xa0, 0x20, 0xa4, 0xf4, 0x70, 0x8e, 0xe2, 0x8a, 0xeb, 0x62, 0xf1,
        0x4e, 0xef, 0xc3, 0x04, 0xd9,
    ];
    const CURRENCY: [u8; 20] = [
        0xf3, 0xec, 0x55, 0x36, 0x34, 0xef, 0x17, 0x42, 0x31, 0xa1, 0x4c, 0x0a, 0x28, 0xef, 0x4e,
        0x72, 0xc9, 0xba, 0x5f, 0xda,
    ];

    #[test]
    fn reads_the_golden_reserve_output() {
        let script = hex::decode(GOLDEN_RESERVE_OUTPUT).unwrap();
        assert_eq!(
            decode_output_script(&script).unwrap(),
            OutputKind::ReserveOutput {
                destination: RECIPIENT,
                tokens: vec![(CURRENCY, 40_000_000)],
            }
        );
    }

    #[test]
    fn round_trips_with_the_encoder() {
        for amount in [1u64, 127, 128, 40_000_000, 100_000_000_000] {
            let script = reserve_output_script(RECIPIENT, CURRENCY, amount).unwrap();
            assert_eq!(
                decode_output_script(&script).unwrap(),
                OutputKind::ReserveOutput {
                    destination: RECIPIENT,
                    tokens: vec![(CURRENCY, amount)],
                },
                "amount {amount} did not survive a round trip"
            );
        }
    }

    #[test]
    fn reads_a_p2pkh_output() {
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&RECIPIENT);
        script.extend_from_slice(&[0x88, 0xac]);
        assert_eq!(
            decode_output_script(&script).unwrap(),
            OutputKind::PubKeyHash { hash: RECIPIENT }
        );
    }

    /// The rule this module exists to enforce.
    #[test]
    fn a_truncated_cryptocondition_is_an_error_not_native_value() {
        let full = hex::decode(GOLDEN_RESERVE_OUTPUT).unwrap();
        for cut in [10, 30, 60, full.len() - 1] {
            let truncated = &full[..cut];
            let result = decode_output_script(truncated);
            assert!(
                result.is_err(),
                "truncating to {cut} bytes decoded as {result:?} instead of failing"
            );
        }
    }

    #[test]
    fn a_corrupt_token_payload_is_an_error() {
        let mut script = reserve_output_script(RECIPIENT, CURRENCY, 40_000_000).unwrap();
        // Flip the TokenOutput version, which selects a different encoding.
        let position = script.len() - 26;
        script[position] = 0x02;
        assert!(matches!(
            decode_output_script(&script),
            Err(TxError::MalformedCryptoCondition(_))
        ));
    }

    #[test]
    fn an_unknown_eval_code_is_reported_rather_than_ignored() {
        // An identity output (eval 4) is not decoded here, but a caller must be
        // able to see that it is not plain native value.
        let mut script = reserve_output_script(RECIPIENT, CURRENCY, 40_000_000).unwrap();
        let eval_position = script
            .windows(4)
            .position(|w| w[0] == 0x03 && w[1] == EVAL_RESERVE_OUTPUT && w[2] == 1 && w[3] == 1)
            .expect("params header present")
            + 1;
        script[eval_position] = 4;
        match decode_output_script(&script) {
            Ok(OutputKind::UnsupportedCryptoCondition { eval_code }) => assert_eq!(eval_code, 4),
            other => panic!("expected an unsupported-CC report, got {other:?}"),
        }
    }

    #[test]
    fn an_unrecognised_script_is_refused() {
        assert!(matches!(
            decode_output_script(&[0x51]),
            Err(TxError::UnsupportedScript(_))
        ));
    }
}
