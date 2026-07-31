//! Checking a recovery phrase, and turning one into a shielded seed.
//!
//! [`Key::from_seed_phrase`] accepts any text, because Verus wallets do — the
//! transparent key is `sha256(phrase)` and free text is a legitimate phrase.
//! The cost is that a mistyped word derives a real key for a real address
//! holding nothing, and nothing on that path can tell you it happened.
//!
//! `validateMnemonic` is how a wallet asks. It answers rather than throws,
//! because "not a mnemonic" is an ordinary thing for a Verus phrase to be and
//! must not read as a failure — the shape follows `verifyMessage`, which draws
//! the same distinction between "no" and "broken".
//!
//! [`Key::from_seed_phrase`]: crate::keys::Key::from_seed_phrase

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use verus_keys::MnemonicError;

use crate::dto;
use crate::error::WasmError;
use crate::types::{JsText, MnemonicCheckValue};

/// What a phrase turned out to be.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MnemonicCheck {
    /// Whether the phrase is a valid BIP-39 English mnemonic.
    pub valid: bool,
    /// How many words were found, so a UI can say "11 of 12".
    pub words: u32,
    /// Why not, when it is not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// For `unknownWord`: which word, counting from 1.
    ///
    /// The word itself is deliberately absent. This value reaches logs and
    /// screenshots, and a recovery phrase is the whole wallet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<u32>,
}

/// Host-testable core of [`validate_mnemonic`].
pub(crate) fn check(phrase: &str) -> MnemonicCheck {
    let words = u32::try_from(phrase.split_whitespace().count()).unwrap_or(u32::MAX);
    let base = MnemonicCheck {
        valid: false,
        words,
        ..MnemonicCheck::default()
    };
    match verus_keys::validate_mnemonic(phrase) {
        Ok(()) => MnemonicCheck {
            valid: true,
            ..base
        },
        Err(MnemonicError::WordCount(_)) => MnemonicCheck {
            reason: Some("wordCount".into()),
            ..base
        },
        Err(MnemonicError::UnknownWord { position }) => MnemonicCheck {
            reason: Some("unknownWord".into()),
            position: Some(u32::try_from(position).unwrap_or(u32::MAX)),
            ..base
        },
        Err(MnemonicError::Checksum) => MnemonicCheck {
            reason: Some("checksum".into()),
            ..base
        },
        // Reachable only from `mnemonicToSeed`, which takes a passphrase.
        // Validation does not, so this cannot occur — reported rather than
        // unwrapped, because a panic here would trap the whole module.
        Err(other) => MnemonicCheck {
            reason: Some(format!("{other}")),
            ..base
        },
    }
}

/// Check a recovery phrase against the BIP-39 English wordlist and checksum.
///
/// Read the three answers differently — this is the point of the function, and
/// treating them alike is the bug it exists to prevent:
///
/// | `reason` | what it means |
/// |---|---|
/// | *(absent)* | a real mnemonic |
/// | `wordCount` | **not a mnemonic at all** — ordinary for a Verus phrase. The transparent key still works; there is simply no shielded one. |
/// | `unknownWord` | mnemonic-shaped with a word off the list — a typo, or another language |
/// | `checksum` | every word real, the count right, the checksum wrong — almost always one mistyped or swapped word |
///
/// The last two are worth interrupting a user for. The first is not.
///
/// ```js
/// const check = validateMnemonic(phrase);
/// if (!check.valid && check.reason !== "wordCount") {
///   warn(`word ${check.position ?? "?"} looks wrong — check the phrase`);
/// }
/// ```
///
/// Never throws for an ordinary phrase: only a non-string argument is refused.
#[wasm_bindgen(js_name = validateMnemonic)]
pub fn validate_mnemonic(phrase: JsText) -> Result<MnemonicCheckValue, WasmError> {
    let phrase = dto::text("phrase", phrase.as_ref())?;
    Ok(crate::to_js(&check(&phrase))?.unchecked_into())
}

/// The 64-byte BIP-39 seed a mnemonic maps to — the shielded half of a wallet.
///
/// Feed it to `@chainvue/verus-sapling` to reach the `zs…` address a Verus
/// Mobile wallet shows for the same phrase. The transparent half comes from
/// `Key.fromSeedPhrase`, by a completely unrelated schedule.
///
/// `passphrase` is BIP-39's optional 25th word. **Verus wallets do not use
/// one — pass `""` or `null`.** It is not defaulted away because a wrong
/// answer here is undetectable: the seed is valid either way, and the wallet
/// is simply empty.
///
/// Throws if the phrase is not a valid mnemonic, rather than deriving a seed
/// from words that do not check out.
///
/// Returns raw bytes rather than hex on purpose: a `Uint8Array` can be zeroed
/// by the caller when it is done, and a JavaScript string cannot.
///
/// Whitespace does not affect the result — the words are rehashed joined by
/// single spaces. BIP-39 runs PBKDF2 over the phrase as *text*, so a pasted
/// newline would otherwise derive a different, empty wallet.
#[wasm_bindgen(js_name = mnemonicToSeed)]
pub fn mnemonic_to_seed(
    phrase: JsText,
    passphrase: crate::types::JsOptionalText,
) -> Result<Vec<u8>, WasmError> {
    let phrase = dto::text("phrase", phrase.as_ref())?;
    let passphrase = dto::optional_text("passphrase", &passphrase)?.unwrap_or_default();
    Ok(verus_keys::mnemonic_to_seed(&phrase, &passphrase)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn a_real_mnemonic_carries_no_reason() {
        let result = check(VALID);
        assert!(result.valid);
        assert_eq!(result.words, 12);
        assert!(result.reason.is_none());
        assert!(result.position.is_none());
    }

    /// The distinction the whole binding exists for. Free text is not a
    /// mnemonic, and a wallet must not show a user an error for it — their
    /// transparent key is fine.
    #[test]
    fn free_text_and_a_typo_are_told_apart() {
        let free = check("my own words");
        assert_eq!(free.reason.as_deref(), Some("wordCount"));
        assert_eq!(free.words, 3);

        let typo = check(&VALID.replace("about", "abandon"));
        assert_eq!(typo.reason.as_deref(), Some("checksum"));
        assert_eq!(typo.words, 12);
    }

    #[test]
    fn a_bad_word_is_reported_by_position_and_never_by_value() {
        let phrase = VALID.replace("about", "verus");
        let result = check(&phrase);
        assert_eq!(result.reason.as_deref(), Some("unknownWord"));
        assert_eq!(result.position, Some(12));
        let json = serde_json::to_string(&result).unwrap();
        assert!(
            !json.contains("verus"),
            "the phrase must not travel in the result: {json}"
        );
    }

    #[test]
    fn a_seed_is_only_derived_from_a_phrase_that_checks_out() {
        assert!(verus_keys::mnemonic_to_seed(VALID, "").is_ok());
        assert!(verus_keys::mnemonic_to_seed(&VALID.replace("about", "abandon"), "").is_err());
    }
}
