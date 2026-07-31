//! BIP-39 mnemonics: checking one, and turning one into a seed.
//!
//! # Why this is separate from [`private_key_from_seed_phrase`]
//!
//! A Verus recovery phrase drives **two unrelated key schedules**, and only one
//! of them is BIP-39:
//!
//! * **transparent** (`R…`) — `sha256(utf8(phrase))` plus the Iguana clamp. No
//!   BIP-39, no wordlist, no checksum. Any text at all is a valid phrase, and
//!   [`private_key_from_seed_phrase`] hashes it verbatim because that is what
//!   the wallets do.
//! * **shielded** (`zs…`) — BIP-39 → ZIP-32, where the phrase *must* be a real
//!   mnemonic. [`mnemonic_to_seed`] is the missing first half of that path;
//!   `verus_sapling::derive::derive_account` is the second.
//!
//! So validation cannot be folded into the transparent path: a Verus wallet
//! accepts `"correct horse battery staple"` and derives a real, spendable
//! address from it. Refusing that would strand funds. What this module gives a
//! wallet is the ability to *ask*, and to tell the two interesting cases apart.
//!
//! # The hole it closes
//!
//! Nothing else checks a restored phrase. Mistype one word of a 24-word Verus
//! Mobile phrase and the transparent derivation succeeds anyway — a valid key,
//! a valid address, and no funds, with nothing to distinguish "you typed it
//! wrong" from "this wallet is empty". [`validate_mnemonic`] separates them:
//!
//! ```
//! use verus_keys::bip39::{validate_mnemonic, MnemonicError};
//!
//! // A word count that is not BIP-39's: free text, which Verus allows.
//! assert_eq!(validate_mnemonic("my own words"), Err(MnemonicError::WordCount(3)));
//!
//! // Twelve real words whose checksum fails: almost certainly a typo.
//! let mistyped = "abandon abandon abandon abandon abandon abandon \
//!                 abandon abandon abandon abandon abandon abandon";
//! assert_eq!(validate_mnemonic(mistyped), Err(MnemonicError::Checksum));
//! ```
//!
//! `WordCount` is not a complaint — it means "this is not a mnemonic", which is
//! a perfectly ordinary thing for a Verus phrase to be. `UnknownWord` and
//! `Checksum` are the ones worth stopping a user for.
//!
//! # Scope
//!
//! English wordlist only, and no generation. Generating a phrase belongs with
//! the vault that will store it, which is the same reason this crate offers no
//! `PrivateKey::generate` — see `verus-sdk`'s `keygen` example.
//!
//! [`private_key_from_seed_phrase`]: crate::private_key_from_seed_phrase

use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;
use zeroize::Zeroizing;

/// The BIP-39 English wordlist, verbatim from `bitcoin/bips`.
///
/// Pinned by hash in the tests: it is a constant, and a constant that silently
/// changed by one word would derive a different seed for the phrases that use
/// it while every other test kept passing.
const ENGLISH: &str = include_str!("bip39_english.txt");

/// PBKDF2 iterations. Fixed by BIP-39; not a tuning knob.
const ITERATIONS: u32 = 2048;

/// Why a phrase is not a valid BIP-39 mnemonic.
///
/// Note what is *not* here: the offending word. An error message is the last
/// place key material should end up — it goes to logs, to crash reporters and
/// to screenshots — so a bad word is reported by position only.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum MnemonicError {
    /// Not one of BIP-39's word counts (12, 15, 18, 21 or 24).
    ///
    /// Usually means the phrase simply is not a mnemonic. Verus accepts free
    /// text for the transparent key, so on that path this is not a problem —
    /// it only means no shielded key can be derived.
    #[error("{0} words is not a BIP-39 mnemonic length (12, 15, 18, 21 or 24)")]
    WordCount(usize),

    /// The word at this 1-based position is not in the English wordlist.
    ///
    /// A mnemonic-shaped phrase with a word off the list is a typo, or a
    /// phrase from a wordlist this crate does not carry.
    #[error("word {position} is not in the BIP-39 English wordlist")]
    UnknownWord {
        /// Which word, counting from 1. The word itself is deliberately
        /// withheld.
        position: usize,
    },

    /// Every word is in the list and the count is right, but the checksum
    /// fails.
    ///
    /// This is the one worth interrupting a user for. BIP-39 spends its last
    /// few bits on exactly this check, and it is the only thing standing
    /// between a mistyped word and a valid-looking wallet with no funds in it.
    #[error("the mnemonic checksum does not match; a word is wrong or out of order")]
    Checksum,

    /// A non-ASCII passphrase.
    ///
    /// BIP-39 hashes the passphrase in Unicode NFKD. This crate carries no
    /// normalization tables, so rather than hash unnormalized bytes and derive
    /// a seed that disagrees with every other wallet, it refuses. ASCII is
    /// already NFKD-stable, and no Verus wallet uses a passphrase at all.
    #[error("passphrase must be ASCII")]
    NonAsciiPassphrase,
}

/// Check a phrase against the BIP-39 English wordlist and checksum.
///
/// Read the three failures differently — see [`MnemonicError`]. In particular
/// [`MnemonicError::WordCount`] is not a problem for a transparent Verus key.
///
/// ```
/// use verus_keys::bip39::validate_mnemonic;
///
/// let phrase = "abandon abandon abandon abandon abandon abandon \
///               abandon abandon abandon abandon abandon about";
/// assert!(validate_mnemonic(phrase).is_ok());
/// ```
pub fn validate_mnemonic(phrase: &str) -> Result<(), MnemonicError> {
    checked_words(phrase).map(|_| ())
}

/// The 64-byte BIP-39 seed a mnemonic maps to, for ZIP-32 shielded derivation.
///
/// Feed it to `verus_sapling::derive::derive_account` to reach the `zs…`
/// address a Verus Mobile wallet shows for the same phrase.
///
/// `passphrase` is BIP-39's optional 25th-word passphrase. **Verus wallets do
/// not use one — pass `""`.** It is a parameter rather than a default because
/// a wrong answer here is undetectable: the seed is valid either way, and the
/// wallet is simply empty.
///
/// # Whitespace does not change the seed
///
/// A deliberate deviation, and the opposite of what
/// [`private_key_from_seed_phrase`] does. BIP-39 runs PBKDF2 over the phrase
/// *as text*, so a doubled space or a trailing newline silently produces a
/// different seed — a restored wallet that is valid, empty, and gives no hint
/// why. Since every word here has already been checked against the wordlist,
/// the words are hashed rejoined by single spaces, which is the form a wallet
/// exports and the only form that can round-trip.
///
/// The transparent path cannot do this: it accepts free text, where whitespace
/// carries meaning and must be preserved exactly.
///
/// [`private_key_from_seed_phrase`]: crate::private_key_from_seed_phrase
pub fn mnemonic_to_seed(
    phrase: &str,
    passphrase: &str,
) -> Result<Zeroizing<[u8; 64]>, MnemonicError> {
    let words = checked_words(phrase)?;
    if !passphrase.is_ascii() {
        return Err(MnemonicError::NonAsciiPassphrase);
    }

    // Both inputs hold key material for as long as PBKDF2 runs.
    let canonical = Zeroizing::new(words.join(" "));
    let salt = Zeroizing::new(format!("mnemonic{passphrase}"));

    let mut seed = Zeroizing::new([0u8; 64]);
    pbkdf2::pbkdf2_hmac::<Sha512>(
        canonical.as_bytes(),
        salt.as_bytes(),
        ITERATIONS,
        seed.as_mut(),
    );
    Ok(seed)
}

/// The words of a valid mnemonic, in order.
///
/// Borrows from `phrase` rather than copying: the caller already owns the
/// secret, and a second copy would be a second thing to wipe.
fn checked_words(phrase: &str) -> Result<Vec<&str>, MnemonicError> {
    let words: Vec<&str> = phrase.split_whitespace().collect();

    // 12/15/18/21/24 words carry 128/160/192/224/256 bits of entropy plus a
    // checksum a thirty-second of that size, which is what makes every count a
    // multiple of three.
    if !matches!(words.len(), 12 | 15 | 18 | 21 | 24) {
        return Err(MnemonicError::WordCount(words.len()));
    }
    let entropy_len = words.len() * 4 / 3;
    let checksum_bits = words.len() / 3;

    let list: Vec<&str> = ENGLISH.lines().collect();
    debug_assert_eq!(list.len(), 2048, "the wordlist must hold 2048 words");

    // Big-endian bit buffer: 11 bits per word, 264 bits at the widest.
    let mut buffer = Zeroizing::new([0u8; 33]);
    let mut bit = 0usize;
    for (offset, word) in words.iter().enumerate() {
        let index = list
            .binary_search(word)
            .map_err(|_| MnemonicError::UnknownWord {
                position: offset + 1,
            })?;
        for shift in (0..11).rev() {
            if (index >> shift) & 1 == 1 {
                buffer[bit / 8] |= 0x80 >> (bit % 8);
            }
            bit += 1;
        }
    }

    // The entropy occupies whole bytes, so the checksum is exactly the top
    // `checksum_bits` of the byte that follows it, and must equal the top
    // `checksum_bits` of SHA-256 over the entropy.
    let mask = 0xffu8 << (8 - checksum_bits);
    let expected = Sha256::digest(&buffer[..entropy_len])[0];
    if buffer[entropy_len] & mask != expected & mask {
        return Err(MnemonicError::Checksum);
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Official BIP-39 vectors, from `trezor/python-mnemonic`'s `vectors.json`
    /// — the reference implementation's own suite. Passphrase is `"TREZOR"`
    /// for all of them, which is what the published seeds were computed with.
    ///
    /// `(mnemonic, seed)`, transcribed mechanically from that file rather than
    /// by hand. These are the acceptance test for the whole module at once:
    /// the wordlist, the index packing, the checksum and PBKDF2 all have to be
    /// right together, or the seed is wrong.
    const OFFICIAL: [(&str, &str); 24] = [
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        ),
        (
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
        ),
        (
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
        ),
        (
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
        ),
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
            "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
        ),
        (
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
            "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
        ),
        (
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
            "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
        ),
        (
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
            "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
        ),
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
        ),
        (
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
            "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
        ),
        (
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
            "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
        ),
        (
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
        ),
        (
            "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
            "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
        ),
        (
            "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
            "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
        ),
        (
            "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
            "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
        ),
        (
            "scheme spot photo card baby mountain device kick cradle pact join borrow",
            "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
        ),
        (
            "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
            "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
        ),
        (
            "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
            "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
        ),
        (
            "cat swing flag economy stadium alone churn speed unique patch report train",
            "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
        ),
        (
            "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
            "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
        ),
        (
            "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
            "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
        ),
        (
            "vessel ladder alter error federal sibling chat ability sun glass valve picture",
            "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
        ),
        (
            "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
            "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
        ),
        (
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
            "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
        ),
    ];

    /// The official suite has no 15- or 21-word vectors, so those two word
    /// counts — and with them `checksum_bits` of 5 and 7 — would go entirely
    /// untested. Filled in with Python's `hashlib`, which shares no code with
    /// this implementation. Same `"TREZOR"` passphrase, so they can be checked
    /// by the same loop.
    const FILLED_GAPS: [(&str, &str); 6] = [
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address",
            "fa08713f46bf5cb48728ceb70e3aae1bc53c5cb7b4e29c5610261d1cbb7be3bed4d805256fec515754d2be35974fc5da678168e9d9bb0cb70948026923b0def3",
        ),
        (
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage wise",
            "f938c2f3ebd11f1c9057b713d977b5260e4282a57811ab163a9708c4ce15307983ac24c4451c7cb353b2002d0a1ee8a404fa59f0f6aa8323fa9bb61248cf4808",
        ),
        (
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrist",
            "bfee6f9d2bcfa1331bd6482a24abca521e5f7e769498b9a0146672194c7356e4e409be22bc379c8b64fee2aa24b54d3ec20d10a083eaa5d1d6b4b365941ad37c",
        ),
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon admit",
            "e7dadc189d2e8d07ac278d9ec98a1d2d327e4a6b7df494c00cbf2cbf2d3543dac7000fc72d4ada8d9997dc8db388ff22c6d79f604a7455f2df5534a28eee04c6",
        ),
        (
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year viable",
            "99c0597b2bef5ca4859e21075fee0fc931747a30469b6f564d95f74913c357aceb55221b4f4fe6965e871340b45754b1ae59e53da1797b69b30c5fa40ec105b8",
        ),
        (
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo veteran",
            "4aa0af4ca02ef1d9fa675cd02aa06d318425564e7fadd3d51b6165cc56d77398f28d8522073cd036c2a4a24a83e919211c84500d96cb120084e613ff5fcd96c1",
        ),
    ];

    #[test]
    fn reproduces_the_official_vectors() {
        for (mnemonic, seed) in OFFICIAL.iter().chain(FILLED_GAPS.iter()) {
            assert_eq!(validate_mnemonic(mnemonic), Ok(()), "{mnemonic}");
            assert_eq!(
                hex::encode(*mnemonic_to_seed(mnemonic, "TREZOR").unwrap()),
                *seed,
                "{mnemonic}",
            );
        }
    }

    /// All five word counts must be exercised. Each has its own entropy width
    /// and its own checksum width, so a mistake in either for one length hides
    /// completely behind the other four.
    #[test]
    fn every_valid_length_is_covered_by_the_vectors() {
        let lengths: std::collections::BTreeSet<usize> = OFFICIAL
            .iter()
            .chain(FILLED_GAPS.iter())
            .map(|(mnemonic, _)| mnemonic.split_whitespace().count())
            .collect();
        assert_eq!(
            lengths,
            [12, 15, 18, 21, 24].into_iter().collect(),
            "a BIP-39 length is untested",
        );
    }

    /// The empty passphrase — the only one a Verus wallet uses, and so the
    /// only path that reaches a real user's z-address.
    ///
    /// The official vectors all use `"TREZOR"`, so these were computed
    /// independently with Python's `hashlib.pbkdf2_hmac`, which shares no code
    /// with this implementation.
    #[test]
    fn derives_the_seed_verus_wallets_use() {
        const NO_PASSPHRASE: [(&str, &str); 2] = [
            (
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            ),
            (
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
                "878386efb78845b3355bd15ea4d39ef97d179cb712b77d5c12b6be415fffeffe5f377ba02bf3f8544ab800b955e51fbff09828f682052a20faa6addbbddfb096",
            ),
        ];
        for (mnemonic, seed) in NO_PASSPHRASE {
            assert_eq!(
                hex::encode(*mnemonic_to_seed(mnemonic, "").unwrap()),
                seed,
                "{mnemonic}",
            );
        }
    }

    /// A passphrase is not decoration: it selects a different wallet, and
    /// getting it wrong is undetectable at derivation time.
    #[test]
    fn the_passphrase_changes_the_seed() {
        let phrase = OFFICIAL[0].0;
        assert_ne!(
            *mnemonic_to_seed(phrase, "").unwrap(),
            *mnemonic_to_seed(phrase, "TREZOR").unwrap(),
        );
    }

    /// The check that earns the module: one word changed, and the phrase is
    /// refused instead of deriving an empty wallet.
    #[test]
    fn a_single_mistyped_word_is_caught() {
        // `about` -> `abandon`; both are real words, so only the checksum can
        // tell. This is exactly what a user does when they mis-recall a phrase.
        let mistyped = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon";
        assert_eq!(validate_mnemonic(mistyped), Err(MnemonicError::Checksum));
        assert_eq!(mnemonic_to_seed(mistyped, ""), Err(MnemonicError::Checksum));
    }

    /// A swapped pair keeps every word and the count, so nothing but the
    /// checksum notices.
    #[test]
    fn a_swapped_pair_is_caught() {
        let swapped = "legal winner thank year wave sausage worth useful legal winner yellow thank";
        assert_eq!(validate_mnemonic(swapped), Err(MnemonicError::Checksum));
    }

    #[test]
    fn a_word_off_the_list_is_reported_by_position_only() {
        let phrase = "abandon abandon verus abandon abandon abandon \
                      abandon abandon abandon abandon abandon about";
        let error = validate_mnemonic(phrase).unwrap_err();
        assert_eq!(error, MnemonicError::UnknownWord { position: 3 });
        assert!(
            !error.to_string().contains("verus"),
            "an error message must not carry key material: {error}",
        );
    }

    /// Free text is not a mnemonic and must not be reported as a broken one —
    /// a Verus wallet derives a real transparent key from it.
    #[test]
    fn free_text_is_a_word_count_failure_not_a_checksum_one() {
        for text in ["a", "my own words", "sample verus seed phrase for testing"] {
            let words = text.split_whitespace().count();
            assert_eq!(
                validate_mnemonic(text),
                Err(MnemonicError::WordCount(words)),
                "{text}",
            );
        }
    }

    /// Whitespace must not reach PBKDF2. The words are what matter, and a
    /// pasted phrase carrying a newline or a double space would otherwise
    /// derive a different, empty wallet.
    #[test]
    fn whitespace_does_not_change_the_seed() {
        let canonical = OFFICIAL[0].0;
        let expected = *mnemonic_to_seed(canonical, "").unwrap();
        for sloppy in [
            format!("  {canonical}  "),
            canonical.replace(' ', "  "),
            format!("{canonical}\n"),
            canonical.replace(' ', "\n"),
        ] {
            assert_eq!(
                *mnemonic_to_seed(&sloppy, "").unwrap(),
                expected,
                "{sloppy:?}",
            );
        }
    }

    /// Unnormalized bytes would derive a seed no other wallet agrees with, so
    /// the passphrase is refused rather than guessed at.
    #[test]
    fn a_non_ascii_passphrase_is_refused_rather_than_mis_normalized() {
        assert_eq!(
            mnemonic_to_seed(OFFICIAL[0].0, "café"),
            Err(MnemonicError::NonAsciiPassphrase),
        );
    }

    /// The wordlist is a constant, and one changed word would quietly change
    /// the seed for every phrase containing it while the official vectors
    /// above still passed — they only cover a handful of words.
    #[test]
    fn the_wordlist_is_the_official_one() {
        let words: Vec<&str> = ENGLISH.lines().collect();
        assert_eq!(words.len(), 2048);
        assert_eq!(
            hex::encode(Sha256::digest(ENGLISH.as_bytes())),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
            "this is not the BIP-39 English wordlist",
        );
        // Sorted, because the lookup binary-searches it. An unsorted list
        // would not fail loudly — it would report real words as unknown.
        assert!(words.windows(2).all(|pair| pair[0] < pair[1]));
    }
}
