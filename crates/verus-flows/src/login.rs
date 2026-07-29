//! Logging in with a VerusID.
//!
//! Signing is offline and lives in [`verus_tx::signature`]. What needs a chain
//! is everything around it: which chain this is, what height to stamp, and —
//! the part that is easy to get wrong — **which addresses controlled the
//! identity when the signature was made**.
//!
//! # Verify against the identity as it was, not as it is
//!
//! An identity's primary addresses can be rotated, and its recovery authority
//! can replace them outright. So there are two different questions:
//!
//! * *Could this signer sign for the identity at the moment they signed?* —
//!   what a login check should ask, and what [`verify_login`] answers.
//! * *Could they sign for it right now?* — a different question, and the one you
//!   get by verifying against the current identity.
//!
//! They diverge exactly when it matters: a key that was rotated out after being
//! compromised still verifies under the first question at its old height. That
//! is correct — the signature really was valid then — and it is why a login
//! should also check that the signature is **recent**, which is what
//! [`LoginPolicy::max_age_blocks`] is for. A signature with no freshness bound is
//! a bearer token that never expires.
//!
//! # What this cannot tell you
//!
//! That the person presenting the signature is the person who made it. A
//! signature over a fixed string is replayable by anyone who sees it, so a login
//! challenge must be **unique per attempt** — see [`LoginRequest`].

use verus_keys::{Address, PrivateKey};
use verus_rpc::ChainReader;
use verus_tx::signature::{sign_message, verify_message, IdentitySignature};

use crate::error::FlowError;

/// A challenge for someone to sign.
///
/// The `challenge` must be **unpredictable and used once**. A signature is not
/// bound to a session, a browser or a moment: anyone who observes one can
/// present it again. Signing a constant string like `"login"` produces a
/// credential that works forever, for whoever copies it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginRequest {
    /// Who is asking — included so a signature for one site cannot be replayed
    /// at another.
    pub audience: String,
    /// Random, single-use. 32 bytes of entropy, hex or base64 encoded, is ample.
    pub challenge: String,
}

impl LoginRequest {
    /// The exact text to sign.
    ///
    /// ```text
    /// verusid-login
    /// 19:https://example.com
    /// 10:9f2c4e7a1b
    /// ```
    ///
    /// Each field carries its own byte length, so an audience ending in digits
    /// cannot be confused with a challenge beginning with them, and neither can
    /// smuggle a newline to forge the other. Plain concatenation is the classic
    /// way two different field pairs hash to the same string.
    ///
    /// Deliberately **text**, not a packed binary struct. Every Verus tool —
    /// `signmessage`, `verifymessage`, the mobile wallet — takes a message as a
    /// string, so binary length prefixes would embed NUL bytes in something that
    /// is passed around as text and displayed to the person approving it.
    pub fn message(&self) -> Vec<u8> {
        self.message_text().into_bytes()
    }

    /// The message as a string, which is how every Verus tool takes it.
    pub fn message_text(&self) -> String {
        format!(
            "verusid-login\n{}:{}\n{}:{}",
            self.audience.len(),
            self.audience,
            self.challenge.len(),
            self.challenge
        )
    }
}

/// What a verifier will accept.
#[derive(Clone, Debug)]
pub struct LoginPolicy {
    /// How old the signature's height may be, in blocks.
    ///
    /// Without this, a signature is a credential that never expires. At roughly
    /// one block a minute on Verus, 60 is an hour.
    pub max_age_blocks: u32,
    /// Whether to reject a signature stamped ahead of the chain tip.
    ///
    /// A few blocks of slack is reasonable — the signer may be marginally ahead
    /// — but a height far in the future is either a broken clock or an attempt
    /// to mint a credential that stays valid longer than the policy allows.
    pub max_future_blocks: u32,
}

impl Default for LoginPolicy {
    /// An hour of validity, a couple of blocks of slack.
    fn default() -> Self {
        Self {
            max_age_blocks: 60,
            max_future_blocks: 2,
        }
    }
}

/// A verified login.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoggedIn {
    /// The fully qualified name, e.g. `alice.VRSCTEST@`.
    pub name: String,
    /// The identity's `i` address.
    pub identity_address: String,
    /// The height the signature was stamped with.
    pub signed_at: u32,
    /// The addresses that actually signed, and were authorised at that height.
    pub signers: Vec<Address>,
}

/// Sign a login challenge as an identity.
///
/// Stamps the current tip, which is what a verifier checks freshness against.
pub fn sign_login(
    reader: &impl ChainReader,
    key: &PrivateKey,
    identity: &str,
    request: &LoginRequest,
) -> Result<IdentitySignature, FlowError> {
    let info = reader.chain_info()?;
    let system_id = address_hash(&info.chain_id)?;
    let record = reader
        .identity(identity)
        .map_err(|_| FlowError::NoSuchIdentity(identity.to_string()))?;
    let identity_id = address_hash(&record.identity_address)?;
    let height = reader.block_count()?;

    Ok(sign_message(
        key,
        system_id,
        identity_id,
        height,
        &request.message(),
    )?)
}

/// Verify a login, against the identity as it stood when it was signed.
///
/// Resolves the identity at [`IdentitySignature::block_height`] — not at the
/// tip. See the module docs for why those differ and when it matters.
pub fn verify_login(
    reader: &impl ChainReader,
    identity: &str,
    signature: &IdentitySignature,
    request: &LoginRequest,
    policy: &LoginPolicy,
) -> Result<LoggedIn, FlowError> {
    let info = reader.chain_info()?;
    let system_id = address_hash(&info.chain_id)?;
    let tip = reader.block_count()?;

    // Freshness first: it needs no lookup, and refusing early keeps a flood of
    // stale signatures from turning into a flood of RPC calls.
    if signature.block_height > tip.saturating_add(policy.max_future_blocks) {
        return Err(FlowError::NotReady(format!(
            "signature is stamped at height {} but the chain is at {tip}",
            signature.block_height
        )));
    }
    if tip.saturating_sub(signature.block_height) > policy.max_age_blocks {
        return Err(FlowError::NotReady(format!(
            "signature is {} blocks old, older than the {} allowed",
            tip.saturating_sub(signature.block_height),
            policy.max_age_blocks
        )));
    }

    // The identity as it was at signing time. This is the whole point.
    let record = reader
        .identity_at(identity, signature.block_height)
        .map_err(|_| FlowError::NoSuchIdentity(identity.to_string()))?;

    if record.is_revoked() {
        return Err(FlowError::NotReady(format!(
            "{} was revoked",
            record.fully_qualified_name
        )));
    }

    let identity_id = address_hash(&record.identity_address)?;
    let (addresses, minimum) = authority(&record)?;
    let message = request.message();

    if !verify_message(
        signature,
        system_id,
        identity_id,
        &message,
        &addresses,
        minimum,
    )? {
        return Err(FlowError::NotReady(format!(
            "the signature does not satisfy {}'s {minimum}-of-{} authority",
            record.fully_qualified_name,
            addresses.len()
        )));
    }

    let signers =
        verus_tx::signature::recover_signers(signature, system_id, identity_id, &message)?
            .into_iter()
            .filter(|signer| addresses.contains(signer))
            .collect();

    Ok(LoggedIn {
        name: record.fully_qualified_name,
        identity_address: record.identity_address,
        signed_at: signature.block_height,
        signers,
    })
}

/// The primary addresses and threshold an identity publishes.
fn authority(record: &verus_rpc::IdentityRecord) -> Result<(Vec<Address>, u32), FlowError> {
    let addresses = record.identity["primaryaddresses"]
        .as_array()
        .ok_or_else(|| FlowError::NotReady("identity has no primary addresses".into()))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| FlowError::NotReady("a primary address is not a string".into()))
                .and_then(|text| text.parse::<Address>().map_err(FlowError::Key))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let minimum = record.identity["minimumsignatures"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        // Absent means one, which is what a single-signature identity reports.
        .unwrap_or(1);

    if addresses.is_empty() {
        return Err(FlowError::NotReady(
            "an identity with no primary addresses cannot sign".into(),
        ));
    }
    Ok((addresses, minimum))
}

fn address_hash(address: &str) -> Result<[u8; 20], FlowError> {
    let parsed: Address = address.parse()?;
    Ok(parsed.hash())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::ScriptedReader;
    use verus_rpc::IdentityRecord;
    use verus_tx::Txid;

    const WIF: &str = "UusoQWsobQKUkezgBJa22D9G4t9Avo6k8wD5UUxmmfAEoTN8bawc";

    fn key() -> PrivateKey {
        PrivateKey::from_wif(WIF).unwrap()
    }

    fn request() -> LoginRequest {
        LoginRequest {
            audience: "https://example.com".into(),
            challenge: "9f2c4e7a1b".into(),
        }
    }

    fn record(addresses: &[&str], minimum: u32, revoked: bool) -> IdentityRecord {
        IdentityRecord {
            fully_qualified_name: "alice.VRSCTEST@".into(),
            identity_address: "iPYbC4ExJ7dRBZnpxq2LGXGgkWDQNQR48g".into(),
            status: if revoked { "revoked" } else { "active" }.into(),
            outpoint: (Txid::from_internal([0xaa; 32]), 0),
            block_height: 900,
            identity: serde_json::json!({
                "identityaddress": "iPYbC4ExJ7dRBZnpxq2LGXGgkWDQNQR48g",
                "primaryaddresses": addresses,
                "minimumsignatures": minimum,
            }),
        }
    }

    fn chain(tip: u32, record: IdentityRecord) -> ScriptedReader {
        ScriptedReader::new(tip).with_identity("alice@", record)
    }

    #[test]
    fn a_signed_challenge_verifies() {
        let address = key().address().to_string();
        let node = chain(1_000, record(&[&address], 1, false));
        let signature = sign_login(&node, &key(), "alice@", &request()).unwrap();

        let logged_in = verify_login(
            &node,
            "alice@",
            &signature,
            &request(),
            &LoginPolicy::default(),
        )
        .unwrap();
        assert_eq!(logged_in.name, "alice.VRSCTEST@");
        assert_eq!(logged_in.signed_at, 1_000);
        assert_eq!(logged_in.signers, vec![key().address()]);
    }

    /// A different challenge is a different message, so an observed signature
    /// cannot be presented for a fresh login attempt.
    #[test]
    fn a_signature_for_one_challenge_does_not_work_for_another() {
        let address = key().address().to_string();
        let node = chain(1_000, record(&[&address], 1, false));
        let signature = sign_login(&node, &key(), "alice@", &request()).unwrap();

        let other = LoginRequest {
            audience: "https://example.com".into(),
            challenge: "different".into(),
        };
        assert!(
            verify_login(&node, "alice@", &signature, &other, &LoginPolicy::default()).is_err()
        );
    }

    /// And a signature for one site cannot be replayed at another.
    #[test]
    fn a_signature_for_one_audience_does_not_work_at_another() {
        let address = key().address().to_string();
        let node = chain(1_000, record(&[&address], 1, false));
        let signature = sign_login(&node, &key(), "alice@", &request()).unwrap();

        let elsewhere = LoginRequest {
            audience: "https://evil.example".into(),
            challenge: request().challenge,
        };
        assert!(verify_login(
            &node,
            "alice@",
            &signature,
            &elsewhere,
            &LoginPolicy::default()
        )
        .is_err());
    }

    /// The fields are length-prefixed, so moving a character between them
    /// changes the message. Concatenation would not.
    #[test]
    fn the_audience_and_challenge_cannot_be_confused_for_each_other() {
        let first = LoginRequest {
            audience: "abc".into(),
            challenge: "def".into(),
        };
        let second = LoginRequest {
            audience: "ab".into(),
            challenge: "cdef".into(),
        };
        assert_ne!(first.message(), second.message());
    }

    /// A newline inside a field must not be able to forge the structure around
    /// it — the reason the lengths are there rather than just the separators.
    #[test]
    fn a_field_cannot_smuggle_the_structure_of_another() {
        let honest = LoginRequest {
            audience: "site".into(),
            challenge: "abc".into(),
        };
        let forged = LoginRequest {
            audience: "site\n3:abc".into(),
            challenge: "abc".into(),
        };
        assert_ne!(honest.message(), forged.message());
    }

    /// The message is text, because that is how every Verus tool takes it. A
    /// packed binary form would put NUL bytes into a string a user is shown.
    #[test]
    fn the_message_is_printable_text() {
        let message = request().message_text();
        assert!(message.starts_with("verusid-login\n"));
        assert!(!message.contains('\0'));
        assert_eq!(request().message(), message.into_bytes());
    }

    /// A signature with no freshness bound is a credential that never expires.
    #[test]
    fn a_stale_signature_is_refused() {
        let address = key().address().to_string();
        let node = chain(1_000, record(&[&address], 1, false));
        let signature = sign_login(&node, &key(), "alice@", &request()).unwrap();

        // The chain moved on well past the policy window.
        let later = chain(2_000, record(&[&address], 1, false));
        match verify_login(
            &later,
            "alice@",
            &signature,
            &request(),
            &LoginPolicy::default(),
        ) {
            Err(FlowError::NotReady(message)) => assert!(message.contains("blocks old")),
            other => panic!("expected a staleness refusal, got {other:?}"),
        }
    }

    /// A height in the future would extend the credential's life past the
    /// policy, so it is refused rather than trusted.
    #[test]
    fn a_signature_from_the_future_is_refused() {
        let address = key().address().to_string();
        let node = chain(1_000, record(&[&address], 1, false));
        let mut signature = sign_login(&node, &key(), "alice@", &request()).unwrap();
        signature.block_height = 1_500;
        assert!(verify_login(
            &node,
            "alice@",
            &signature,
            &request(),
            &LoginPolicy::default()
        )
        .is_err());
    }

    /// A revoked identity cannot log in, whatever its keys say.
    #[test]
    fn a_revoked_identity_cannot_log_in() {
        let address = key().address().to_string();
        let node = chain(1_000, record(&[&address], 1, false));
        let signature = sign_login(&node, &key(), "alice@", &request()).unwrap();

        let revoked = chain(1_000, record(&[&address], 1, true));
        match verify_login(
            &revoked,
            "alice@",
            &signature,
            &request(),
            &LoginPolicy::default(),
        ) {
            Err(FlowError::NotReady(message)) => assert!(message.contains("revoked")),
            other => panic!("expected a revocation refusal, got {other:?}"),
        }
    }

    /// Someone who is not an authority on the identity cannot log in as it.
    #[test]
    fn a_stranger_cannot_log_in_as_someone_else() {
        let stranger = PrivateKey::from_bytes(&[0x99; 32], true).unwrap();
        let owner = key().address().to_string();
        let node = chain(1_000, record(&[&owner], 1, false));
        let signature = sign_login(&node, &stranger, "alice@", &request()).unwrap();
        assert!(verify_login(
            &node,
            "alice@",
            &signature,
            &request(),
            &LoginPolicy::default()
        )
        .is_err());
    }

    /// A 2-of-2 identity is not satisfied by one of its holders.
    #[test]
    fn a_multisig_identity_is_not_satisfied_by_one_signer() {
        let first = key();
        let second = PrivateKey::from_bytes(&[0x27; 32], true).unwrap();
        let addresses = [first.address().to_string(), second.address().to_string()];
        let refs: Vec<&str> = addresses.iter().map(String::as_str).collect();
        let node = chain(1_000, record(&refs, 2, false));

        let one = sign_login(&node, &first, "alice@", &request()).unwrap();
        assert!(verify_login(&node, "alice@", &one, &request(), &LoginPolicy::default()).is_err());

        // Both holders sign the same challenge at the same height.
        let info = node.chain_info().unwrap();
        let system = address_hash(&info.chain_id).unwrap();
        let identity = address_hash("iPYbC4ExJ7dRBZnpxq2LGXGgkWDQNQR48g").unwrap();
        let both = verus_tx::signature::add_signature(
            &one,
            &second,
            system,
            identity,
            &request().message(),
        )
        .unwrap();

        let logged_in =
            verify_login(&node, "alice@", &both, &request(), &LoginPolicy::default()).unwrap();
        assert_eq!(logged_in.signers.len(), 2);
    }

    /// The key that signed was rotated out afterwards. Verified against the
    /// height it was signed at it is valid; against today's identity it is not.
    /// A login must ask the first question — and the freshness bound is what
    /// stops that being a permanent backdoor.
    #[test]
    fn verification_uses_the_identity_as_it_was_at_signing_time() {
        let old_key = key();
        let new_key = PrivateKey::from_bytes(&[0x33; 32], true).unwrap();

        let before = chain(1_000, record(&[&old_key.address().to_string()], 1, false));
        let signature = sign_login(&before, &old_key, "alice@", &request()).unwrap();

        // The identity now names a different key. `identity_at` on the scripted
        // chain returns current state, so this stands in for "verified against
        // the wrong height" — and it must fail.
        let after = chain(1_010, record(&[&new_key.address().to_string()], 1, false));
        assert!(
            verify_login(
                &after,
                "alice@",
                &signature,
                &request(),
                &LoginPolicy::default()
            )
            .is_err(),
            "a rotated-out key must not verify against the new authority"
        );

        // Against the authority that was current when it was signed, it does.
        let logged_in = verify_login(
            &before,
            "alice@",
            &signature,
            &request(),
            &LoginPolicy::default(),
        )
        .unwrap();
        assert_eq!(logged_in.signers, vec![old_key.address()]);
    }

    /// An identity nobody has registered is not a login.
    #[test]
    fn an_unknown_identity_is_refused() {
        let node = ScriptedReader::new(1_000);
        let address = key().address().to_string();
        let signed_elsewhere = chain(1_000, record(&[&address], 1, false));
        let signature = sign_login(&signed_elsewhere, &key(), "alice@", &request()).unwrap();
        assert!(matches!(
            verify_login(
                &node,
                "alice@",
                &signature,
                &request(),
                &LoginPolicy::default()
            ),
            Err(FlowError::NoSuchIdentity(_))
        ));
    }
}
