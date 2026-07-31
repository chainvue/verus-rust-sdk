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

use crate::cc::{Destination, EVAL_NONE, EVAL_RESERVE_OUTPUT, OPT_CC_PARAMS_VERSION};
use crate::convert::EVAL_RESERVE_TRANSFER;
use crate::currency::CurrencyId;
use crate::currency_launch::{EVAL_CROSSCHAIN_IMPORT, EVAL_RESERVE_DEPOSIT};
use crate::error::TxError;
use crate::identity::{
    Identity, EVAL_IDENTITY_PRIMARY, EVAL_IDENTITY_RECOVER, EVAL_IDENTITY_REVOKE,
};
use crate::register::EVAL_IDENTITY_COMMITMENT;

/// `OP_CHECKCRYPTOCONDITION`.
const OP_CHECKCRYPTOCONDITION: u8 = 0xcc;
/// `OP_DROP`.
const OP_DROP: u8 = 0x75;
/// `OP_PUSHDATA1`.
const OP_PUSHDATA1: u8 = 0x4c;
/// `OP_PUSHDATA2`.
const OP_PUSHDATA2: u8 = 0x4d;
/// `OP_PUSHDATA4`.
const OP_PUSHDATA4: u8 = 0x4e;

/// The sentinel that marks a name commitment as carrying a token output.
///
/// `CCommitmentHash` serializes its 32-byte hash and then, *conditionally*, a
/// `CTokenOutput` — the condition being that the hash's first twenty bytes
/// equal this key. So the same field is either a commitment hash or a tagged
/// header, and nothing but these bytes distinguishes the two.
///
/// It is the VDXF data key for `vrsc::system.identity.advancedcommitmenthash`,
/// which renders as `i74sHfYTqdfd5ZSmQSLHug4GuX2XHKwA7Y`. Hardcoded because it
/// is a constant of the protocol, and re-derived in a test through this
/// crate's own [`crate::data_key`] so that a wrong transcription cannot sit
/// here unnoticed.
pub const ADVANCED_COMMITMENT_KEY: [u8; 20] = [
    0x27, 0x67, 0x18, 0x1a, 0x4f, 0x6a, 0xbe, 0x20, 0x90, 0xa7, 0xdc, 0xa2, 0xc6, 0x89, 0x47, 0x7d,
    0x16, 0x39, 0x00, 0xf6,
];

/// Whether a CryptoCondition with this eval code is *able* to carry currency.
///
/// Not "does it" — "could it". A `false` here is a proof of absence: an output
/// with that eval code carries no reserve value, whatever else it does, so a
/// balance may count it as zero rather than refusing to answer.
///
/// # Where the list comes from
///
/// `CScript::ReserveOutValue` in VerusCoin's `src/script/script.cpp` is the one
/// function consensus uses to ask an output what currency it holds, and it is a
/// `switch` over exactly five eval codes. Everything else falls off the end and
/// returns an empty map — including `EVAL_STAKEGUARD`, which is what a
/// proof-of-stake coinbase pays its first output to, and every notarization,
/// finalization, currency definition and identity output.
///
/// That matters because the alternative is a balance that fails for anyone who
/// has ever staked. The refusal was honest but far too wide: it treated "this
/// crate cannot decode the payload" as "this output might hold money", when the
/// chain itself says the payload of a stakeguard output is not somewhere money
/// can be.
///
/// `EVAL_CROSSCHAIN_IMPORT` is on the list even though `ReserveOutValue`
/// returns nothing for it: the code there is commented out with the note that
/// the value "cannot be calculated in isolation as an input". An import output
/// does carry currency — it just cannot be read one output at a time — so this
/// says so, and a balance keeps refusing it. It is the only one of the five
/// this crate does not decode, and the only one where reading harder would not
/// help.
pub const fn may_carry_currency(eval_code: u8) -> bool {
    matches!(
        eval_code,
        EVAL_RESERVE_TRANSFER
            | EVAL_RESERVE_OUTPUT
            | EVAL_RESERVE_DEPOSIT
            | EVAL_CROSSCHAIN_IMPORT
            | EVAL_IDENTITY_COMMITMENT
    )
}

/// What an output turned out to be.
///
/// `#[non_exhaustive]` for the same reason [`TxError`] is: this crate learns to
/// read new output shapes over time, and a downstream `match` should get a
/// wildcard arm once rather than break on every discovery.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OutputKind {
    /// A plain pay-to-public-key-hash output: native value only.
    PubKeyHash {
        /// The 20-byte hash it pays to.
        hash: [u8; 20],
    },
    /// A pay-to-public-key output: native value only.
    ///
    /// The shape a proof-of-work coinbase pays itself with, so any address that
    /// has ever mined holds some. It carries no payload and cannot hold a
    /// currency — recognising it matters because the alternative is refusing
    /// the whole output as unreadable, and "unreadable" would be wrong: this
    /// crate cannot *spend* a P2PK output, but it can be certain there is no
    /// token hiding in one.
    PubKey {
        /// The public key it pays, 33 bytes compressed or 65 uncompressed.
        pubkey: Vec<u8>,
        /// The hash of that key — the `R` address that controls it.
        hash: [u8; 20],
    },
    /// A CryptoCondition output holding token (reserve) value.
    ReserveOutput {
        /// Who the output pays.
        ///
        /// A [`Destination`] rather than a bare hash, because the kind is the
        /// difference between an output a transparent key can spend and one
        /// only a VerusID's authority can. Tokens held by an identity are an
        /// ordinary shape on Verus — a mint pays them, and the SDK's own
        /// encoder has always been able to write them — and reading them back
        /// as a key-hash would name an `R` address that nobody controls.
        destination: Destination,
        /// `(currency id, amount)` pairs the output carries.
        tokens: Vec<(CurrencyId, u64)>,
    },
    /// A pay-to-identity output: native value held for a VerusID.
    ///
    /// Carries no eval code — an identity payment is expressed purely by the
    /// destination kind, which is why it cannot be recognised without decoding
    /// destinations properly.
    IdentityPayment {
        /// The identity's 20-byte hash — its `i` address.
        identity: [u8; 20],
    },
    /// An output holding a VerusID itself — its authority, its content, its
    /// revocation and recovery authorities.
    IdentityPrimary {
        /// The identity as the chain stores it.
        identity: Box<Identity>,
    },
    /// A name commitment — step one of registering a VerusID.
    ///
    /// Holds the hash that reserves a name, and, in the "advanced" form, a
    /// token output alongside it. See [`ADVANCED_COMMITMENT_KEY`] for how the
    /// two are told apart.
    IdentityCommitment {
        /// Who can redeem it. Step two must be signed by this destination.
        destination: Destination,
        /// The 32-byte commitment, as it appears in the script.
        ///
        /// The daemon prints this byte-reversed, the way it prints every
        /// hash; these are the bytes themselves.
        commitment: [u8; 32],
        /// Currency the commitment carries, which is empty for every ordinary
        /// one. Present because a commitment is one of the five output kinds
        /// consensus reads currency out of, so "a commitment holds nothing"
        /// would be a guess rather than a decode.
        tokens: Vec<(CurrencyId, u64)>,
    },
    /// Currency held on behalf of a currency's reserves.
    ///
    /// Not a user's holding: these are paid to a system condition, not to an
    /// address someone controls. Decoded because an output whose value cannot
    /// be accounted for is one a caller has to be able to look at.
    ReserveDeposit {
        /// Who the output nominally pays.
        destination: Destination,
        /// The currency whose reserves these are.
        controlling_currency: CurrencyId,
        /// The map as written, with the chain's own currency **still in it**.
        /// See [`crate::token_balances`] for why that has to be removed before
        /// the figure means anything.
        tokens: Vec<(CurrencyId, u64)>,
    },
    /// Value in flight: a conversion, export or burn awaiting import.
    ///
    /// Paid to [`crate::convert::RESERVE_TRANSFER_ADDRESS`], a protocol
    /// constant rather than a recipient — the real destination is inside the
    /// payload.
    ReserveTransfer {
        /// Who the output nominally pays.
        destination: Destination,
        /// The payload. Boxed because it is much larger than every other
        /// variant, and an enum is as big as its widest arm.
        transfer: Box<crate::convert::ReserveTransferPayload>,
    },
    /// A CryptoCondition output whose eval code this crate does not decode yet
    /// — a currency definition, a crosschain import.
    ///
    /// Returned rather than ignored so a caller can refuse to spend value it
    /// cannot account for.
    UnsupportedCryptoCondition {
        /// The eval code found.
        eval_code: u8,
        /// [`may_carry_currency`] for that eval code — whether the output is
        /// *able* to hold a token this crate cannot see.
        ///
        /// Carried on the variant rather than left to the caller to look up,
        /// so the distinction is unmissable at the `match` that has to make
        /// the decision. `false` means the output is undecodable *and*
        /// provably tokenless: refusing to count it would fail closed against
        /// nothing.
        may_carry_currency: bool,
    },
}

/// The public key a `PUSH(len) <pubkey> OP_CHECKSIG` script pays, if it is one.
///
/// Only the two lengths secp256k1 defines are accepted; a push of any other
/// size is not a public key and this crate should not claim to recognise it.
fn pay_to_pubkey(script: &[u8]) -> Option<&[u8]> {
    const OP_CHECKSIG: u8 = 0xac;
    let (&length, rest) = script.split_first()?;
    if length != 33 && length != 65 {
        return None;
    }
    let length = usize::from(length);
    if rest.len() != length + 1 || rest[length] != OP_CHECKSIG {
        return None;
    }
    Some(&rest[..length])
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
    ///
    /// `OP_PUSHDATA2` matters here, not just `OP_PUSHDATA1`: `cc.rs`'s
    /// `push_data` reaches for it the moment a payload passes 255 bytes, which
    /// an identity does immediately once it carries any content — a single
    /// `content_map` entry alone puts the params chunk at 266 bytes. Without
    /// this arm, every identity with real content, a private address, a 3-of-N
    /// key set, or a longish name failed to decode (`MalformedCryptoCondition`),
    /// which blocks update, revoke, recover and currency-launch on exactly the
    /// identities that use those features.
    ///
    /// `OP_PUSHDATA4` is deliberately NOT supported. `push_data` itself refuses
    /// to emit anything over 65535 bytes (`CcPayloadTooLarge`) rather than reach
    /// it, so no encoder in this crate has ever produced or round-tripped that
    /// form — decoding it would be trusting an encoding nothing here tests.
    /// Refusing it explicitly, rather than silently mis-reading the length or
    /// panicking on it, keeps the same "fail closed" contract as the rest of
    /// this module.
    fn take_push(&mut self) -> Result<&'a [u8], TxError> {
        let opcode = self.take_opcode()?;
        let length = match opcode {
            1..=75 => usize::from(opcode),
            OP_PUSHDATA1 => usize::from(self.take_opcode()?),
            OP_PUSHDATA2 => {
                let low = self.take_opcode()?;
                let high = self.take_opcode()?;
                usize::from(u16::from_le_bytes([low, high]))
            }
            OP_PUSHDATA4 => {
                return Err(malformed(
                    "OP_PUSHDATA4 push encountered; this crate's own encoder \
                     refuses to emit one (see cc.rs push_data's CcPayloadTooLarge), \
                     so decoding it would exercise an encoding nothing here has tested",
                ))
            }
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

/// The destination an output pays, or an error naming the shape that had none.
fn first_destination(destinations: Vec<Destination>, shape: &str) -> Result<Destination, TxError> {
    destinations
        .into_iter()
        .next()
        .ok_or_else(|| malformed(&format!("{shape} has no destination")))
}

/// Twenty bytes of currency id.
fn read_currency_at(payload: &[u8], offset: &mut usize) -> Result<CurrencyId, TxError> {
    let raw = payload
        .get(*offset..*offset + 20)
        .ok_or_else(|| malformed("a payload ended before a currency id"))?;
    *offset += 20;
    Ok(CurrencyId::from_bytes(
        raw.try_into().expect("slice is 20 bytes"),
    ))
}

/// Decode Bitcoin's `VARINT` (base-128, MSB continuation).
///
/// # Why `checked_mul`, not `checked_shl`
///
/// The overflow guard here used to be `value.checked_shl(7)`, which looks like
/// it rejects an oversized value but does not: `checked_shl` only returns
/// `None` when the *shift amount* is `>= 64` (the bit width), never when bits
/// are actually shifted out the top. `u64::MAX.checked_shl(7)` is `Some(_)`. A
/// crafted 10-byte token-amount VARINT (`ff ff ff ff ff ff ff ff ff 7f`) wrapped
/// silently to `9295997013522923647` instead of erroring — feeding a bogus
/// `Balances` entry in `token.rs`, a bogus demand in `offer.rs`, and a bogus
/// `held` in `convert.rs`. `checked_mul(128)` (equivalent to a real `<< 7`)
/// actually detects the overflow.
pub(crate) fn read_var_int(bytes: &[u8], offset: &mut usize) -> Result<u64, TxError> {
    let mut value: u64 = 0;
    loop {
        let byte = *bytes
            .get(*offset)
            .ok_or_else(|| malformed("VARINT ended early"))?;
        *offset += 1;
        value = value
            .checked_mul(128)
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

/// `CTokenOutput::VERSION_MULTIVALUE`, the high bit of the version VARINT.
///
/// Set when the payload holds a whole `CCurrencyValueMap` instead of one
/// currency and one amount. It is a serialization flag, not a version: the
/// daemon masks it off after reading, so `0x80000001` and `1` are both
/// version 1.
const TOKEN_OUTPUT_MULTIVALUE: u64 = 0x8000_0000;

/// Read a Bitcoin CompactSize, refusing the non-canonical encodings.
///
/// The same discipline `verus_wire`'s transaction reader applies, for the same
/// reason: accepting `fd 01 00` for 1 would let two different byte strings
/// decode to the same output, and this decoder's job is to say what a
/// *specific* script means.
pub(crate) fn read_compact_size(bytes: &[u8], offset: &mut usize) -> Result<u64, TxError> {
    let first = *bytes
        .get(*offset)
        .ok_or_else(|| malformed("CompactSize ended early"))?;
    *offset += 1;
    let mut fixed = |width: usize, minimum: u64| -> Result<u64, TxError> {
        let slice = bytes
            .get(*offset..*offset + width)
            .ok_or_else(|| malformed("CompactSize ended early"))?;
        *offset += width;
        let mut buffer = [0u8; 8];
        buffer[..width].copy_from_slice(slice);
        let value = u64::from_le_bytes(buffer);
        if value < minimum {
            return Err(malformed("non-canonical CompactSize"));
        }
        Ok(value)
    };
    match first {
        0xfd => fixed(2, 0xfd),
        0xfe => fixed(4, u64::from(u16::MAX) + 1),
        0xff => fixed(8, u64::from(u32::MAX) + 1),
        n => Ok(u64::from(n)),
    }
}

/// Read a `CCurrencyValueMap`: a CompactSize count, then that many
/// `(currency id, amount)` pairs.
///
/// The amount is a **fixed eight-byte little-endian `int64`**, not a VARINT —
/// Bitcoin's `std::map` serializer writes integral values plainly, and only
/// the surrounding `CTokenOutput` version uses `VARINT`. Getting that wrong
/// does not fail loudly; it reads a currency id out of the middle of an
/// amount and reports a balance in a currency that does not exist.
fn read_currency_value_map(
    payload: &[u8],
    offset: &mut usize,
) -> Result<Vec<(CurrencyId, u64)>, TxError> {
    /// Twenty bytes of currency id plus eight of amount.
    const ENTRY: usize = 28;

    let count = read_compact_size(payload, offset)?;
    // Bound the count by what is actually left before allocating, so a script
    // claiming four billion entries costs nothing to refuse.
    let remaining = payload.len().saturating_sub(*offset);
    let entries = usize::try_from(count)
        .ok()
        .filter(|count| count.saturating_mul(ENTRY) <= remaining)
        .ok_or_else(|| {
            malformed(&format!(
                "a currency map claims {count} entries, which is more than the \
                 {remaining} bytes left can hold"
            ))
        })?;

    let mut values = Vec::with_capacity(entries);
    for _ in 0..entries {
        let currency: [u8; 20] = payload[*offset..*offset + 20]
            .try_into()
            .expect("slice is 20 bytes");
        let amount = i64::from_le_bytes(
            payload[*offset + 20..*offset + ENTRY]
                .try_into()
                .expect("slice is 8 bytes"),
        );
        *offset += ENTRY;
        // `CAmount` is signed and this crate's `Amount` is not. A negative
        // entry is either a hostile script or a currency map this decoder has
        // no honest way to report, and turning it into a very large positive
        // number is the worst of the available answers.
        let amount = u64::try_from(amount).map_err(|_| {
            malformed(&format!(
                "a currency map holds a negative amount ({amount}) for {}",
                hex::encode(currency)
            ))
        })?;
        values.push((CurrencyId::from_bytes(currency), amount));
    }
    Ok(values)
}

/// Parse a `CTokenOutput` payload — what a reserve output actually holds.
///
/// Two encodings, chosen by [`TOKEN_OUTPUT_MULTIVALUE`]. The single-value one
/// is what this crate writes and what almost every output uses; the multivalue
/// one appears wherever several currencies share an output, which on a
/// fractional currency's reserves is normal rather than exotic.
fn parse_token_output(payload: &[u8]) -> Result<Vec<(CurrencyId, u64)>, TxError> {
    let mut offset = 0;
    let values = parse_token_output_at(payload, &mut offset)?;
    if offset != payload.len() {
        return Err(malformed("trailing bytes after the TokenOutput"));
    }
    Ok(values)
}

/// The same, without insisting it is the whole payload.
///
/// `CReserveTransfer` and `CReserveDeposit` both *begin* with a `CTokenOutput`
/// and carry their own fields after it — they inherit from it in the daemon —
/// so the reader has to be able to stop in the middle.
pub(crate) fn parse_token_output_at(
    payload: &[u8],
    offset: &mut usize,
) -> Result<Vec<(CurrencyId, u64)>, TxError> {
    let version = read_var_int(payload, offset)?;
    let multivalue = version & TOKEN_OUTPUT_MULTIVALUE != 0;
    let base = version & !TOKEN_OUTPUT_MULTIVALUE;
    if base != 1 {
        return Err(malformed(&format!(
            "unsupported TokenOutput version {base}; only version 1 is decoded"
        )));
    }

    if multivalue {
        return read_currency_value_map(payload, offset);
    }
    let currency: [u8; 20] = payload
        .get(*offset..*offset + 20)
        .ok_or_else(|| malformed("TokenOutput ended before its currency id"))?
        .try_into()
        .expect("slice is 20 bytes");
    *offset += 20;
    let amount = read_var_int(payload, offset)?;
    Ok(vec![(CurrencyId::from_bytes(currency), amount)])
}

/// Decode an output script.
pub fn decode_output_script(script: &[u8]) -> Result<OutputKind, TxError> {
    // P2PKH first: the overwhelmingly common case, and unambiguous.
    if script.len() == 25 && script[0..3] == [0x76, 0xa9, 0x14] && script[23..25] == [0x88, 0xac] {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&script[3..23]);
        return Ok(OutputKind::PubKeyHash { hash });
    }

    // P2PK: `PUSH(33|65) <pubkey> OP_CHECKSIG`. Native-only by construction —
    // there is nowhere in this script for a payload to live.
    if let Some(pubkey) = pay_to_pubkey(script) {
        return Ok(OutputKind::PubKey {
            hash: verus_keys::hash160(pubkey),
            pubkey: pubkey.to_vec(),
        });
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
        destinations.push(Destination::from_push(params.take_push()?)?);
    }

    // An identity payment has no eval code at all: it is an EVAL_NONE condition
    // whose single destination happens to be an identity. Checking the eval code
    // alone would classify it as "native, nothing special" and lose the fact
    // that only the identity can spend it.
    if eval_code == EVAL_NONE {
        return match destinations.first() {
            Some(Destination::Identity(identity)) if params.done() => {
                Ok(OutputKind::IdentityPayment {
                    identity: *identity,
                })
            }
            _ => Err(malformed(
                "an EVAL_NONE condition that is not a plain identity payment",
            )),
        };
    }

    if eval_code == EVAL_IDENTITY_PRIMARY {
        let payload = params.take_push()?;
        // The identity is followed by two more vdata entries, each itself a
        // compiled OptCCParams: the revoke and recover conditions that give
        // those authorities the right to spend this output. They are what makes
        // revocation possible at all, so their absence is a malformed identity
        // output rather than a detail to skip past.
        let mut auxiliary = Vec::new();
        while !params.done() {
            let chunk = params.take_push()?;
            let mut inner = ScriptReader::new(chunk);
            let header = inner.take_push()?;
            if header.len() != 4 || header[0] != OPT_CC_PARAMS_VERSION {
                return Err(malformed(
                    "an identity's trailing vdata is not a v3 OptCCParams chunk",
                ));
            }
            auxiliary.push(header[1]);
        }
        if auxiliary != [EVAL_IDENTITY_REVOKE, EVAL_IDENTITY_RECOVER] {
            return Err(malformed(&format!(
                "expected revoke ({EVAL_IDENTITY_REVOKE}) and recover                  ({EVAL_IDENTITY_RECOVER}) conditions, found {auxiliary:?}"
            )));
        }
        return Ok(OutputKind::IdentityPrimary {
            identity: Box::new(Identity::from_bytes(payload)?),
        });
    }

    if eval_code == EVAL_RESERVE_DEPOSIT {
        let payload = params.take_push()?;
        if !params.done() {
            return Err(malformed("trailing vdata after a reserve deposit"));
        }
        let mut offset = 0;
        let tokens = parse_token_output_at(payload, &mut offset)?;
        let controlling_currency = read_currency_at(payload, &mut offset)?;
        if offset != payload.len() {
            return Err(malformed("trailing bytes after a reserve deposit"));
        }
        return Ok(OutputKind::ReserveDeposit {
            destination: first_destination(destinations, "reserve deposit")?,
            controlling_currency,
            tokens,
        });
    }

    if eval_code == EVAL_RESERVE_TRANSFER {
        let payload = params.take_push()?;
        if !params.done() {
            return Err(malformed("trailing vdata after a reserve transfer"));
        }
        return Ok(OutputKind::ReserveTransfer {
            destination: first_destination(destinations, "reserve transfer")?,
            transfer: Box::new(crate::convert::ReserveTransferPayload::from_payload(
                payload,
            )?),
        });
    }

    if eval_code == EVAL_IDENTITY_COMMITMENT {
        let payload = params.take_push()?;
        if !params.done() {
            return Err(malformed("trailing vdata after a name commitment"));
        }
        let commitment: [u8; 32] = payload
            .get(..32)
            .ok_or_else(|| malformed("a name commitment is shorter than its hash"))?
            .try_into()
            .expect("slice is 32 bytes");
        // The hash's own first twenty bytes decide whether a token output
        // follows it. Anything else trailing the hash is a payload this
        // decoder has no rule for, and reading it as a `CTokenOutput` anyway
        // would invent a balance out of whatever the bytes happened to be.
        let tokens = match &payload[32..] {
            [] => Vec::new(),
            rest if commitment[..20] == ADVANCED_COMMITMENT_KEY => parse_token_output(rest)?,
            _ => {
                return Err(malformed(
                    "a name commitment carries data after its hash without the advanced \
                     commitment key that would say how to read it",
                ))
            }
        };
        let destination = destinations
            .into_iter()
            .next()
            .ok_or_else(|| malformed("name commitment has no destination"))?;
        return Ok(OutputKind::IdentityCommitment {
            destination,
            commitment,
            tokens,
        });
    }

    if eval_code != EVAL_RESERVE_OUTPUT {
        return Ok(OutputKind::UnsupportedCryptoCondition {
            eval_code,
            may_carry_currency: may_carry_currency(eval_code),
        });
    }

    let mut tokens = Vec::new();
    while !params.done() {
        tokens.extend(parse_token_output(params.take_push()?)?);
    }
    // Any destination kind, not just a key hash. Which one it is decides who
    // can *spend* the output — the funding paths in `token.rs`, `convert.rs`,
    // `register.rs` and `offer.rs` each refuse the ones this crate cannot sign
    // for — but it has no bearing on what the output *holds*, and refusing to
    // read it lost every token a VerusID owns.
    let destination = destinations
        .into_iter()
        .next()
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
    const CURRENCY: CurrencyId = CurrencyId::from_bytes([
        0xf3, 0xec, 0x55, 0x36, 0x34, 0xef, 0x17, 0x42, 0x31, 0xa1, 0x4c, 0x0a, 0x28, 0xef, 0x4e,
        0x72, 0xc9, 0xba, 0x5f, 0xda,
    ]);

    #[test]
    fn reads_the_golden_reserve_output() {
        let script = hex::decode(GOLDEN_RESERVE_OUTPUT).unwrap();
        assert_eq!(
            decode_output_script(&script).unwrap(),
            OutputKind::ReserveOutput {
                destination: Destination::PubKeyHash(RECIPIENT),
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
                    destination: Destination::PubKeyHash(RECIPIENT),
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
            Ok(OutputKind::UnsupportedCryptoCondition {
                eval_code,
                may_carry_currency,
            }) => {
                assert_eq!(eval_code, 4);
                assert!(
                    !may_carry_currency,
                    "an earned notarization holds no currency"
                );
            }
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

    /// `cc.rs` `push_data` reaches for `OP_PUSHDATA2` the moment a payload
    /// passes 255 bytes. Before this crate's own encoder wrote bytes the
    /// decoder could not read back.
    #[test]
    fn take_push_reads_a_pushdata2_encoded_push() {
        let mut script = vec![OP_PUSHDATA2];
        script.extend_from_slice(&300u16.to_le_bytes());
        script.extend(vec![0xab; 300]);
        let mut reader = ScriptReader::new(&script);
        assert_eq!(reader.take_push().unwrap().len(), 300);
        assert!(reader.done());
    }

    /// A full CryptoCondition output whose payload only fits in an
    /// `OP_PUSHDATA2` push must decode, not just the raw push in isolation —
    /// this is the shape `identity_primary_script` produces for any identity
    /// carrying content, a private address, or a longish name.
    #[test]
    fn decodes_an_output_whose_payload_needs_pushdata2() {
        let master =
            crate::cc::OptCcParams::one_of_one(EVAL_NONE, Destination::PubKeyHash(RECIPIENT));
        let params = crate::cc::OptCcParams {
            vdata: vec![vec![0u8; 300]],
            // An eval code this module does not special-case: the point of
            // this test is that the *push* parses, not the payload semantics.
            ..crate::cc::OptCcParams::one_of_one(200, Destination::PubKeyHash(RECIPIENT))
        };
        let script = crate::cc::cc_script(&master, &params).unwrap();
        assert_eq!(
            decode_output_script(&script).unwrap(),
            OutputKind::UnsupportedCryptoCondition {
                eval_code: 200,
                may_carry_currency: false,
            }
        );
    }

    /// `OP_PUSHDATA4` is refused explicitly rather than decoded: `push_data`
    /// itself refuses anything over 65535 bytes (`CcPayloadTooLarge`) rather
    /// than emit it, so no encoder here has ever produced or tested that form.
    #[test]
    fn take_push_refuses_a_pushdata4_encoded_push() {
        let mut script = vec![OP_PUSHDATA4];
        script.extend_from_slice(&300u32.to_le_bytes());
        script.extend(vec![0xab; 300]);
        let mut reader = ScriptReader::new(&script);
        assert!(matches!(
            reader.take_push(),
            Err(TxError::MalformedCryptoCondition(_))
        ));
    }

    /// The guard this replaces, `value.checked_shl(7)`, only rejects a shift
    /// amount `>= 64` — it never detects the value itself overflowing, so
    /// `u64::MAX.checked_shl(7)` is `Some(_)` and a 10-byte VARINT wrapped
    /// silently instead of erroring.
    #[test]
    fn a_varint_that_overflows_u64_is_an_error_not_a_wrapped_value() {
        let mut bytes = vec![0xffu8; 9];
        bytes.push(0x7f);
        let mut offset = 0;
        assert!(matches!(
            read_var_int(&bytes, &mut offset),
            Err(TxError::MalformedCryptoCondition(_))
        ));
    }

    /// A VARINT well within range still decodes normally after the fix — the
    /// guard must reject overflow without breaking the common case.
    #[test]
    fn a_varint_within_range_still_decodes() {
        let mut offset = 0;
        assert_eq!(read_var_int(&[0x7f], &mut offset).unwrap(), 127);
        offset = 0;
        assert_eq!(read_var_int(&[0x80, 0x00], &mut offset).unwrap(), 128);
    }
}
