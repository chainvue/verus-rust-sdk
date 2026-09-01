//! The TypeScript the generated `.d.ts` carries.
//!
//! `wasm-bindgen` types a `JsValue` parameter as `any`, which loses the whole
//! point of shipping a typed package: the money-is-a-string rule, the optional
//! fields, and the shape of what comes back would all be invisible to a caller
//! until it threw. So the interfaces are declared here and attached to the
//! bindings by name — the text itself lives in `types.d.ts` beside this file.
//!
//! Hand-written TypeScript beside Rust structs is a drift risk, and it is
//! answered rather than accepted: `every_field_of_every_dto_is_declared`
//! serializes each DTO and asserts every field it produces is declared **in
//! that DTO's own interface**. The per-interface part is the whole strength of
//! it — an earlier version searched the file as one string, and since field
//! names repeat across interfaces (`satoshis` in `Utxo` and `Recipient`,
//! `txid` in three of them) a required field could be deleted from the
//! interface that needed it and every test stayed green.

use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const TYPESCRIPT: &'static str = include_str!("types.d.ts");

/// The same text, readable from Rust: the attribute above consumes its own
/// const. Both include the one file, which is what makes the drift check below
/// a check on what a caller actually receives.
#[cfg(test)]
const TYPESCRIPT_SOURCE: &str = include_str!("types.d.ts");

#[wasm_bindgen]
extern "C" {
    /// TypeScript `SendRequest`.
    #[wasm_bindgen(typescript_type = "SendRequest")]
    pub type SendRequestValue;
    /// TypeScript `TokenSendRequest`.
    #[wasm_bindgen(typescript_type = "TokenSendRequest")]
    pub type TokenSendRequestValue;
    /// TypeScript `ConvertRequest`.
    #[wasm_bindgen(typescript_type = "ConvertRequest")]
    pub type ConvertRequestValue;
    /// TypeScript `SignedTransaction`.
    #[wasm_bindgen(typescript_type = "SignedTransaction")]
    pub type SignedTransactionValue;
    /// TypeScript `SignRequest`.
    #[wasm_bindgen(typescript_type = "SignRequest")]
    pub type SignRequestValue;
    /// TypeScript `VerifyRequest`.
    #[wasm_bindgen(typescript_type = "VerifyRequest")]
    pub type VerifyRequestValue;
    /// TypeScript `VerifyResult`.
    #[wasm_bindgen(typescript_type = "VerifyResult")]
    pub type VerifyResultValue;
    /// TypeScript `DecodedOutput`.
    #[wasm_bindgen(typescript_type = "DecodedOutput")]
    pub type DecodedOutputValue;
    /// TypeScript `DecodedTransaction`.
    #[wasm_bindgen(typescript_type = "DecodedTransaction")]
    pub type DecodedTransactionValue;
    /// TypeScript `MnemonicCheck`.
    #[wasm_bindgen(typescript_type = "MnemonicCheck")]
    pub type MnemonicCheckValue;
    /// TypeScript `PlanSendRequest`.
    #[wasm_bindgen(typescript_type = "PlanSendRequest")]
    pub type PlanSendRequestValue;
    /// TypeScript `PlanSendTokenRequest`.
    #[wasm_bindgen(typescript_type = "PlanSendTokenRequest")]
    pub type PlanSendTokenRequestValue;
    /// TypeScript `PlanSendFromIdentityRequest`.
    #[wasm_bindgen(typescript_type = "PlanSendFromIdentityRequest")]
    pub type PlanSendFromIdentityRequestValue;
    /// TypeScript `PlanSendTokenFromIdentityRequest`.
    #[wasm_bindgen(typescript_type = "PlanSendTokenFromIdentityRequest")]
    pub type PlanSendTokenFromIdentityRequestValue;
    /// TypeScript `PlanConvertFromIdentityRequest`.
    #[wasm_bindgen(typescript_type = "PlanConvertFromIdentityRequest")]
    pub type PlanConvertFromIdentityRequestValue;
    /// TypeScript `PlanPublishRequest`.
    #[wasm_bindgen(typescript_type = "PlanPublishRequest")]
    pub type PlanPublishRequestValue;
    /// TypeScript `OffersRequest`.
    #[wasm_bindgen(typescript_type = "OffersRequest")]
    pub type OffersRequestValue;
    /// TypeScript `OfferTermsRequest`.
    #[wasm_bindgen(typescript_type = "OfferTermsRequest")]
    pub type OfferTermsRequestValue;
    /// TypeScript `TakeOfferRequest`.
    #[wasm_bindgen(typescript_type = "TakeOfferRequest")]
    pub type TakeOfferRequestValue;
    /// TypeScript `PlanConvertRequest`.
    #[wasm_bindgen(typescript_type = "PlanConvertRequest")]
    pub type PlanConvertRequestValue;
    /// TypeScript `PlanBurnRequest`.
    #[wasm_bindgen(typescript_type = "PlanBurnRequest")]
    pub type PlanBurnRequestValue;
    /// TypeScript `PlanMintRequest`.
    #[wasm_bindgen(typescript_type = "PlanMintRequest")]
    pub type PlanMintRequestValue;
    /// TypeScript `PlanRegistrationRequest`.
    #[wasm_bindgen(typescript_type = "PlanRegistrationRequest")]
    pub type PlanRegistrationRequestValue;
    /// TypeScript `PendingRequest`.
    #[wasm_bindgen(typescript_type = "PendingRequest")]
    pub type PendingRequestValue;
    /// TypeScript `PlanLaunchRequest`.
    #[wasm_bindgen(typescript_type = "PlanLaunchRequest")]
    pub type PlanLaunchRequestValue;
    /// TypeScript `LaunchStep`.
    #[wasm_bindgen(typescript_type = "LaunchStep")]
    pub type LaunchStepValue;
    /// TypeScript `RegistrationStep`.
    #[wasm_bindgen(typescript_type = "RegistrationStep")]
    pub type RegistrationStepValue;
    /// TypeScript `CommitmentStatusStep`.
    #[wasm_bindgen(typescript_type = "CommitmentStatusStep")]
    pub type CommitmentStatusStepValue;
    /// TypeScript `RegisteredStep`.
    #[wasm_bindgen(typescript_type = "RegisteredStep")]
    pub type RegisteredStepValue;
    /// TypeScript `HistoryRequest`.
    #[wasm_bindgen(typescript_type = "HistoryRequest")]
    pub type HistoryRequestValue;
    /// TypeScript `LoginRequest`.
    #[wasm_bindgen(typescript_type = "LoginRequest")]
    pub type LoginRequestValue;
    /// TypeScript `VerifyLoginRequest`.
    #[wasm_bindgen(typescript_type = "VerifyLoginRequest")]
    pub type VerifyLoginRequestValue;
    /// TypeScript `SpendableRequest`.
    #[wasm_bindgen(typescript_type = "SpendableRequest")]
    pub type SpendableRequestValue;
    /// TypeScript `ContentRequest`.
    #[wasm_bindgen(typescript_type = "ContentRequest")]
    pub type ContentRequestValue;

    // Every `plan…` call returns a `PlanStep<T>`; these name the `T`. One Rust
    // struct, one TypeScript interface, and an alias per flow so a caller gets
    // the payload typed instead of `unknown`.
    /// TypeScript `TransactionStep` — every plan that produces a transaction.
    #[wasm_bindgen(typescript_type = "TransactionStep")]
    pub type TransactionStepValue;
    /// TypeScript `UpdateStep`.
    #[wasm_bindgen(typescript_type = "UpdateStep")]
    pub type UpdateStepValue;
    /// TypeScript `OffersStep`.
    #[wasm_bindgen(typescript_type = "OffersStep")]
    pub type OffersStepValue;
    /// TypeScript `OfferTermsStep`.
    #[wasm_bindgen(typescript_type = "OfferTermsStep")]
    pub type OfferTermsStepValue;
    /// TypeScript `TakeOfferStep`.
    #[wasm_bindgen(typescript_type = "TakeOfferStep")]
    pub type TakeOfferStepValue;
    /// TypeScript `HistoryStep`.
    #[wasm_bindgen(typescript_type = "HistoryStep")]
    pub type HistoryStepValue;
    /// TypeScript `LoginStep`.
    #[wasm_bindgen(typescript_type = "LoginStep")]
    pub type LoginStepValue;
    /// TypeScript `VerifyLoginStep`.
    #[wasm_bindgen(typescript_type = "VerifyLoginStep")]
    pub type VerifyLoginStepValue;
    /// TypeScript `SpendableStep`.
    #[wasm_bindgen(typescript_type = "SpendableStep")]
    pub type SpendableStepValue;
    /// TypeScript `ContentStep`.
    #[wasm_bindgen(typescript_type = "ContentStep")]
    pub type ContentStepValue;

    /// TypeScript `Utxo[]`.
    #[wasm_bindgen(typescript_type = "Utxo[]")]
    pub type UtxoListValue;
    /// TypeScript `TokenAmount[]`.
    #[wasm_bindgen(typescript_type = "TokenAmount[]")]
    pub type TokenBalancesValue;

    /// A `string`, taken as a `JsValue` so a non-string can be *refused*
    /// rather than trapping the module.
    ///
    /// `wasm-bindgen` types a `&str` parameter as `string` but only enforces
    /// it in debug builds; in release it reads `.length` off whatever arrived.
    /// Declaring the TypeScript type here keeps the published signature honest
    /// while `dto::text` does the checking at runtime.
    #[wasm_bindgen(typescript_type = "string")]
    pub type JsText;

    /// An optional `string`, checked the same way.
    #[wasm_bindgen(typescript_type = "string | null | undefined")]
    pub type JsOptionalText;
}

#[cfg(test)]
mod tests {
    use super::TYPESCRIPT_SOURCE as TYPESCRIPT;
    use crate::dto::{Request, Shape};
    use serde::Serialize;
    use std::collections::{BTreeMap, BTreeSet};

    /// Every JSON field name a value serializes to.
    fn field_names<T: Serialize>(value: &T) -> BTreeSet<String> {
        let json = serde_json::to_value(value).expect("serializes");
        json.as_object()
            .expect("a DTO is an object")
            .keys()
            .cloned()
            .collect()
    }

    /// One member of an `export interface` block, as `types.d.ts` declares it.
    struct Member {
        /// The type written after the `:`, without its trailing semicolon.
        declared_as: String,
        /// Whether the name carries a `?`. The meta-guard refuses an optional
        /// member of the `Requests` index: `Requests["Foo"]` would then be
        /// `Foo | undefined`, whose `keyof` is `never`, and the value guard C
        /// declares would be type-checked against nothing at all.
        optional: bool,
    }

    /// One top-level construct of `types.d.ts`.
    ///
    /// These three are the entire vocabulary, on purpose: there is no variant
    /// for "something else". A line that fits none of them is a panic, never a
    /// line quietly passed over — see [`document`].
    enum Item {
        /// A blank line, a `//` line, or one whole `/* … */` comment: text tsc
        /// ignores. Held verbatim, because the round-trip check has to write
        /// the file back out byte for byte.
        Ignored(Vec<String>),
        /// An `export interface` block, from its header down to the `}` that
        /// closes it in the first column.
        Interface {
            name: String,
            /// The type-parameter list as written, `<T>` or empty.
            params: String,
            /// The 1-based line the header sits on, for the body's messages.
            line: usize,
            lines: Vec<String>,
        },
        /// An `export type` alias, from its first line to the `;` that ends it.
        Alias {
            name: String,
            params: String,
            /// The right-hand side, with runs of whitespace collapsed to one
            /// space so a declaration spread over several lines reads the same
            /// as one written on a single line.
            rhs: String,
            lines: Vec<String>,
        },
    }

    impl Item {
        /// The lines this item was read from, exactly as they were read.
        fn lines(&self) -> &[String] {
            match self {
                Item::Ignored(lines)
                | Item::Interface { lines, .. }
                | Item::Alias { lines, .. } => lines,
            }
        }

        /// Whether this item is one `//` line reading exactly `marker`.
        fn is_marker(&self, marker: &str) -> bool {
            matches!(self, Item::Ignored(lines) if lines.len() == 1 && lines[0] == marker)
        }
    }

    /// `name` has to be a TypeScript identifier, and saying so is the point.
    ///
    /// tsc reads the name after `export interface` however it is spaced. A
    /// reader that shrugged at anything else would be agreeing to guess, and
    /// guessing is what made `export interface  QuietRequest` — two spaces — a
    /// fully published declaration that no guard in this crate could see.
    fn assert_identifier(name: &str, what: &str) {
        assert!(
            !name.is_empty()
                && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_' || c == '$')
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$'),
            "{what}: {name:?} is not a TypeScript identifier. tsc will publish whatever \
             this really declares; this reader refuses to guess at it."
        );
    }

    /// A declaration's name and its type-parameter list, split apart.
    fn split_type_parameters(head: &str, what: &str) -> (String, String) {
        let (name, params) = match head.find('<') {
            Some(at) => (&head[..at], &head[at..]),
            None => (head, ""),
        };
        assert_identifier(name, what);
        assert!(
            params.is_empty() || (params.starts_with('<') && params.ends_with('>')),
            "{what}: a type-parameter list this reader cannot read: {params:?}"
        );
        (name.to_string(), params.to_string())
    }

    /// The index just past the `/* … */` comment beginning at `lines[at]`.
    ///
    /// `first` is the 1-based file line of `lines[0]`, so a failure names the
    /// line a reader can open.
    ///
    /// The closing `*/` has to be the last thing on its line. That is not
    /// tidiness: a comment that closes mid-line puts prose and a declaration on
    /// one line, and a reader that swallowed the rest of that line would be
    /// hiding from itself the very declaration tsc goes on to publish. So it is
    /// refused rather than interpreted.
    fn end_of_comment(lines: &[&str], at: usize, first: usize) -> usize {
        for (offset, line) in lines[at..].iter().enumerate() {
            let Some(close) = line.find("*/") else {
                continue;
            };
            assert_eq!(
                close + 2,
                line.trim_end().len(),
                "types.d.ts line {}: a block comment closes in the middle of a line. \
                 Whatever follows the `*/` is code to tsc, and this reader will not decide \
                 for itself what it is.",
                first + at + offset
            );
            return at + offset + 1;
        }
        panic!(
            "types.d.ts line {}: a block comment is never closed",
            first + at
        )
    }

    /// `types.d.ts`, read as the sequence of top-level constructs it is.
    ///
    /// # Why this is a parse and not a search
    ///
    /// Every earlier reader in this file answered questions about `types.d.ts`
    /// by searching its text — `match_indices("export interface ")` and
    /// friends. A search has a failure mode a parse does not: a declaration it
    /// does not match is a declaration it does not report, and a declaration
    /// nothing reports is a declaration nothing guards, while tsc publishes it
    /// in full to every caller. `export interface  QuietRequest`, with two
    /// spaces, was exactly that — invisible to the search, real API surface to
    /// the compiler.
    ///
    /// This reads the file instead. It is *total*: every line of it belongs to
    /// exactly one [`Item`], there is no variant meaning "something I did not
    /// recognise", and a line that fits none of the three panics with its line
    /// number. The two-space header is therefore not skipped — it is read as an
    /// interface whose name is not an identifier, which is a failure with a
    /// message.
    ///
    /// # Why you may believe it
    ///
    /// That nothing is skipped is not left to review.
    /// `the_document_parser_reads_every_byte_of_types_d_ts` writes these items
    /// back out and compares the result to the file byte for byte. A construct
    /// this parser dropped, merged, or rewrote cannot survive that comparison,
    /// and a comparison over bytes has no syntax left to be fooled about.
    ///
    /// What the parse *believes* is a separate question, and it has a separate
    /// answer: everything read here is written into
    /// `tests/node/declarations.pinned.ts` and compiled, so tsc — the reader
    /// every caller actually gets — has to agree with it.
    fn document() -> Vec<Item> {
        let lines: Vec<&str> = TYPESCRIPT.split('\n').collect();
        let own = |from: usize, to: usize| -> Vec<String> {
            lines[from..to].iter().map(|l| (*l).to_string()).collect()
        };

        let mut items = Vec::new();
        let mut at = 0;
        while at < lines.len() {
            let line = lines[at];
            // The file ends in a newline, so `split` yields a final empty
            // element; it carries no bytes and is `Ignored` like a blank line,
            // which is what lets the round-trip rejoin to the original.
            if line.is_empty() || line.starts_with("//") {
                items.push(Item::Ignored(own(at, at + 1)));
                at += 1;
            } else if line.starts_with("/*") {
                let end = end_of_comment(&lines, at, 1);
                items.push(Item::Ignored(own(at, end)));
                at = end;
            } else if let Some(rest) = line.strip_prefix("export interface ") {
                let what = format!("types.d.ts line {}", at + 1);
                let head = rest.strip_suffix(" {").unwrap_or_else(|| {
                    panic!(
                        "{what}: an `export interface` header this reader cannot read: \
                         {line:?}. A header ends in ` {{` and its body ends at a `}}` in the \
                         first column; anything else is refused rather than guessed at."
                    )
                });
                let (name, params) = split_type_parameters(head, &what);
                let mut end = at + 1;
                while end < lines.len() && lines[end] != "}" {
                    end += 1;
                }
                assert!(
                    end < lines.len(),
                    "{what}: interface {name} is never closed by a `}}` in the first column"
                );
                items.push(Item::Interface {
                    name,
                    params,
                    line: at + 1,
                    lines: own(at, end + 1),
                });
                at = end + 1;
            } else if line.starts_with("export type ") {
                let what = format!("types.d.ts line {}", at + 1);
                let mut end = at;
                while end < lines.len() && !lines[end].trim_end().ends_with(';') {
                    end += 1;
                }
                assert!(
                    end < lines.len(),
                    "{what}: an `export type` alias that never ends in a `;`"
                );
                let joined = lines[at..=end]
                    .iter()
                    .map(|line| line.trim())
                    .collect::<Vec<_>>()
                    .join(" ");
                let body = joined
                    .strip_prefix("export type ")
                    .and_then(|body| body.strip_suffix(';'))
                    .unwrap_or_else(|| panic!("{what}: an alias this reader cannot read"));
                let (head, rhs) = body
                    .split_once('=')
                    .unwrap_or_else(|| panic!("{what}: an `export type` with no `=`"));
                let (name, params) = split_type_parameters(head.trim(), &what);
                items.push(Item::Alias {
                    name,
                    params,
                    rhs: rhs.split_whitespace().collect::<Vec<_>>().join(" "),
                    lines: own(at, end + 1),
                });
                at = end + 1;
            } else {
                panic!(
                    "types.d.ts line {}: this reader has no place for {line:?}. Every line \
                     of that file is a blank, a comment, an `export interface` block or an \
                     `export type` alias — and it has to stay that way, because a line \
                     nobody here can read is a declaration tsc might publish that no guard \
                     in this crate would ever see.",
                    at + 1
                );
            }
        }
        items
    }

    /// The `name: type` pairs one `export interface` block declares.
    ///
    /// The block is taken from the parsed document, so the question "which
    /// block?" is answered by the parse rather than by a prefix search — which
    /// is what used to make `DecodedPubKey` resolvable to `DecodedPubKeyHash`,
    /// and what made a two-space header unfindable.
    ///
    /// Reading the members is total in the same way the document is: a body
    /// line is blank, a comment, or `name: type;`, and anything else panics.
    /// A member this could not read would be a member the pinned declarations
    /// never mention, and tsc is only held to what they mention.
    fn declared_members(interface: &str) -> BTreeMap<String, Member> {
        let (first, body) = document()
            .into_iter()
            .find_map(|item| match item {
                Item::Interface {
                    ref name,
                    line,
                    ref lines,
                    ..
                } if name == interface => Some((line + 1, lines[1..lines.len() - 1].to_vec())),
                _ => None,
            })
            .unwrap_or_else(|| panic!("types.d.ts declares no interface {interface}"));
        let body: Vec<&str> = body.iter().map(String::as_str).collect();

        let mut fields = BTreeMap::new();
        let mut at = 0;
        while at < body.len() {
            let what = format!("interface {interface} in types.d.ts, line {}", first + at);
            let line = body[at].trim();
            if line.is_empty() || line.starts_with("//") {
                at += 1;
                continue;
            }
            if line.starts_with("/*") {
                at = end_of_comment(&body, at, first);
                continue;
            }
            let declaration = line.strip_suffix(';').unwrap_or_else(|| {
                panic!(
                    "{what}: a member is `name: type;` on one line, and {line:?} is not. A \
                     member spread over several lines, or carrying an inline object, is \
                     refused rather than guessed at — a member this reader misses is a \
                     member the pinned declarations never hand to tsc."
                )
            });
            let (name, declared_as) = declaration
                .split_once(':')
                .unwrap_or_else(|| panic!("{what}: a member with no `:`: {line:?}"));
            assert!(
                !declared_as.contains('{'),
                "{what}: {line:?} declares an inline object, which this reader does not \
                 model and will not pretend to"
            );
            let name = name.trim();
            let optional = name.ends_with('?');
            let name = name.trim_end_matches('?');
            assert_identifier(name, &what);
            let previous = fields.insert(
                name.to_string(),
                Member {
                    declared_as: declared_as.trim().to_string(),
                    optional,
                },
            );
            assert!(
                previous.is_none(),
                "{what}: interface {interface} declares {name} twice. One of the two is what \
                 tsc uses and the other is what this reader would have reported."
            );
            at += 1;
        }
        fields
    }

    /// Just the names, which is all the per-DTO drift checks compare.
    fn declared_by(interface: &str) -> BTreeSet<String> {
        declared_members(interface).into_keys().collect()
    }

    /// Every `export interface` in `types.d.ts`, in declaration order, with the
    /// number of type parameters it carries.
    ///
    /// The arity is needed because `keyof PlanStepReady` is not a question:
    /// the interface has to be applied to something first.
    ///
    /// # What this is not
    ///
    /// This does **not** answer "which requests exist". That question used to be
    /// asked here, and the answer was a lie waiting to happen. The question now
    /// has one answer, `dto::request_list!`, and `types.d.ts` is checked against
    /// it rather than read for it — see
    /// `the_request_index_is_generated_from_the_registry`.
    ///
    /// What is left for this to do is feed the pinned declarations, whose whole
    /// purpose is to make tsc contradict this file's reader wherever the two
    /// read the same declaration differently. It comes off the parsed document,
    /// so an interface it misses is one the parse itself refused to read, and a
    /// refusal is a failing test rather than a silent omission.
    fn declared_interfaces() -> Vec<(String, usize)> {
        let mut found: Vec<(String, usize)> = Vec::new();
        for item in document() {
            let Item::Interface { name, params, .. } = item else {
                continue;
            };
            assert!(
                !found.iter().any(|(seen, _)| *seen == name),
                "types.d.ts declares interface {name} twice. TypeScript merges the two and \
                 publishes the members of both; this reader would report one of them, so \
                 the other's members would be guarded by nothing."
            );
            let arity = if params.is_empty() {
                0
            } else {
                params[1..params.len() - 1].split(',').count()
            };
            found.push((name, arity));
        }
        found
    }

    /// Every `export type` alias in `types.d.ts`: its name, its type-parameter
    /// list as written, and its right-hand side.
    ///
    /// The right-hand sides are pinned for tsc alongside the interfaces, which
    /// is what makes [`union_members`] something more than this reader's
    /// opinion.
    fn declared_aliases() -> Vec<(String, String, String)> {
        let mut found: Vec<(String, String, String)> = Vec::new();
        for item in document() {
            let Item::Alias {
                name, params, rhs, ..
            } = item
            else {
                continue;
            };
            assert!(
                !found.iter().any(|(seen, _, _)| *seen == name),
                "types.d.ts declares type {name} twice"
            );
            found.push((name, params, rhs));
        }
        found
    }

    /// The TypeScript that hands everything [`declared_members`] believes to
    /// tsc, so that tsc can contradict it.
    ///
    /// One block per `export interface`, saying: these are its members, these
    /// of them are optional, and this is what each one is declared as. Then one
    /// line per `export type`, saying what it is an alias *for*. Every line of
    /// it is what the Rust reader read; tsc resolves the same names against the
    /// same file and the two have to agree.
    ///
    /// The aliases are here because the unions are declarations too, and the
    /// checks over them — `every_commitment_status_variant_is_declared_and_reachable`
    /// and its siblings — are only worth as much as [`union_members`]. Pinning
    /// each right-hand side makes tsc the one that says whether a variant is
    /// really in the union a caller narrows over.
    fn pinned_declarations() -> String {
        let interfaces = declared_interfaces();
        let aliases = declared_aliases();
        let mut imports: BTreeSet<String> =
            interfaces.iter().map(|(name, _)| name.clone()).collect();
        imports.extend(aliases.iter().map(|(name, _, _)| name.clone()));

        let mut out = String::new();
        out.push_str(PINNED_PREAMBLE);
        out.push_str("import type {\n");
        for name in &imports {
            out.push_str(&format!("  {name},\n"));
        }
        out.push_str("} from \"../../pkg/verus_wasm.js\";\n");
        out.push_str(PINNED_OPERATORS);

        for (name, params) in &interfaces {
            // A generic interface has to be applied before anything can be
            // asked of it, and what it is applied to cannot change its member
            // names or which of them are optional.
            let applied = if *params == 0 {
                name.clone()
            } else {
                format!("{name}<{}>", ["any"].repeat(*params).join(", "))
            };
            let members = declared_members(name);
            let list = |mut names: Vec<String>| -> String {
                if names.is_empty() {
                    "never".to_string()
                } else {
                    names.sort();
                    names
                        .into_iter()
                        .map(|member| format!("\"{member}\""))
                        .collect::<Vec<_>>()
                        .join(" | ")
                }
            };
            out.push_str(&format!("\ntype _{name} = [\n"));
            out.push_str(&format!(
                "  Agrees<Exact<keyof {applied}, {}>>,\n",
                list(members.keys().cloned().collect())
            ));
            out.push_str(&format!(
                "  Agrees<Exact<OptionalKeys<{applied}>, {}>>,\n",
                list(
                    members
                        .iter()
                        .filter(|(_, member)| member.optional)
                        .map(|(name, _)| name.clone())
                        .collect()
                )
            ));
            if *params == 0 {
                for (member, declared) in &members {
                    out.push_str(&format!(
                        "  Agrees<Exact<Required<{applied}>[\"{member}\"], {}>>,\n",
                        declared.declared_as
                    ));
                }
            } else {
                out.push_str(
                    "  // Member types are left unpinned here: they may name this \
                     interface's own\n  // type parameters, which mean nothing outside it. \
                     Its member names and\n  // their optionality are pinned above like \
                     everybody else's.\n",
                );
            }
            out.push_str("];\n");
        }

        for (name, params, rhs) in &aliases {
            if params.is_empty() {
                out.push_str(&format!("\ntype _{name} = Agrees<Exact<{name}, {rhs}>>;\n"));
            } else {
                // A generic alias's right-hand side names its own type
                // parameters, which mean nothing outside it, so there is no
                // application of it that could be compared here. Nothing in
                // this crate reads one as a union.
                out.push_str(&format!(
                    "\n// {name}{params} is generic; its right-hand side is left unpinned.\n"
                ));
            }
        }
        out
    }

    /// The header of the generated file, up to its import list.
    const PINNED_PREAMBLE: &str = "\
// Generated by `every_declaration_this_file_reads_is_pinned_for_tsc` in
// crates/verus-wasm/src/types.rs. Do not edit: that test rewrites this file
// when run with UPDATE_TYPESCRIPT_PINS=1, and fails when the two disagree.
//
// # What this is for
//
// The Rust drift guards read `types.d.ts` with a small parser, and a parser
// that is wrong in a caller's favour is the whole failure mode this design
// exists to rule out: five adversarial rounds against the previous version all
// worked by making a deleted registration still *look* present to a scan. The
// parser here is not trusted either. Instead it writes down everything it
// believes, and tsc — which reads the same file for real, comments and all —
// is made to check it.
//
// So a member of an interface that a block comment hides from tsc but not from
// the parser lands here as a member tsc cannot find, and the compiler says so.
// Same for a member the parser reads with the wrong declared type, and for one
// it reads as required that ships optional.
//
// # Reading a failure
//
// `TS2344: Type 'false' does not satisfy the constraint 'true'` on a line below
// means the parser and tsc disagree about that exact line's claim; the line
// names the interface and, for a member, the member. `TS2339: Property 'x' does
// not exist` means the parser saw a member tsc does not.
//
// Nothing imports this file: `tsc --noEmit` is the whole test, and .github/
// workflows/ci.yml names it in the same step as the other declaration checks.

";

    /// The type operators the generated blocks are written in.
    const PINNED_OPERATORS: &str = "\
\n/** Two types, neither wider than the other. Wrapped in tuples so a union is \
compared whole rather than distributed member by member. */\ntype Exact<A, B> = \
[A] extends [B] ? ([B] extends [A] ? true : false) : false;\n\n/** Fails to \
instantiate unless what it is given is `true`, which is how a disagreement \
becomes a compile error rather than an unread type. */\ntype Agrees<T extends \
true> = T;\n\n/** The members declared with a `?`. `keyof` alone cannot tell \
them apart. */\ntype OptionalKeys<T> = { [K in keyof T]-?: {} extends Pick<T, K> \
? K : never }[keyof T];\n";

    /// The generated file as it is checked in.
    ///
    /// Included rather than read at run time so that deleting it stops this
    /// crate compiling. A pin nobody can find is a pin nobody is held to.
    const PINNED: &str = include_str!("../tests/node/declarations.pinned.ts");

    /// Guard C itself, as it is checked in.
    ///
    /// Included rather than read at run time so that deleting it stops this
    /// crate compiling: the `include` glob in `tests/node/tsconfig.json` cannot
    /// miss a file that is gone, but `include_str!` can.
    ///
    /// Deleting was never the cheap attack, though. Emptying was, and so were
    /// `// @ts-nocheck` on the first line, a `// @ts-ignore` above one mistyped
    /// value, and closing the object literal with `} as any;`. Each of them left
    /// every Rust test green and left tsc checking less — or nothing — while
    /// this crate went on reporting guard C as covering all twenty-four
    /// requests, because what Rust checked about this file was a handful of byte
    /// *patterns*, and none of those edits disturbs a pattern.
    ///
    /// So there are no patterns any more. The file is generated from
    /// [`REGISTRY`] and compared to what is checked in, whole, in
    /// `guard_c_exercises_every_registered_request`. Every one of those edits is
    /// a difference, and a difference is a failing test.
    const EXERCISED: &str = include_str!("../tests/node/requests.exercised.ts");

    /// The hand-written narrowing checks, held so that deleting them is loud.
    ///
    /// Nothing reads this string — including it *is* the check.
    /// `types.check.ts` was named by no `include_str!`, no test and no CI step,
    /// only by prose, so moving it away was green everywhere.
    ///
    /// # Deliberately not asserted here
    ///
    /// What that file *contains*. It is hand-written application code, not a
    /// generated obligation, and nothing here can say what the right amount of
    /// it is. Nothing else now depends on it either: the union memberships it
    /// used to catch incidentally are pinned for tsc by `pinned_declarations`.
    const _NARROWING: &str = include_str!("../tests/node/types.check.ts");

    /// The header of the generated file: its prose, its import, and the one
    /// value the request literals share.
    ///
    /// Generated like everything else in that file. Prose that explains a
    /// generated artefact and is itself hand-written is prose that goes stale
    /// the first time the artefact changes — and, worse here, it is a place to
    /// park a `// @ts-nocheck` that no comparison would reach.
    const EXERCISED_PREAMBLE: &str = r#"// Generated by `guard_c_exercises_every_registered_request` in
// crates/verus-wasm/src/types.rs. Do not edit: that test rewrites this file
// when run with UPDATE_TYPESCRIPT_PINS=1, and fails when the two disagree.
//
// # Does tsc actually exercise every published request type?
//
// This is guard C. Guards A and B live in Rust: A asserts that what a request
// struct serializes is what its `export interface` declares, B asserts that the
// runtime key list `dto::from_js` rebuilds a caller's object against lists the
// same fields. Both compare field *names*. Neither of them ever looks at the
// types beside those names, so a field declared `number` where the API returns
// a string is invisible to both — only a compiler reading the shipped `.d.ts`
// can see it.
//
// So this file makes tsc read it. `Requests` in the `.d.ts` indexes every
// request interface by name; the mapped type below asks for one value per key:
//
//   * a missing key is TS2741 — a published request nothing exercises;
//   * a field with the wrong type is TS2322;
//   * a field the interface does not declare is TS2353, because these are
//     object literals in a contextually typed position.
//
// The modifiers on the mapped type are what make it complete rather than nearly
// complete, and each of them closes a way for a published type to go unchecked
// while still looking exercised:
//
//   * `-?` on the outer key. A mapped type inherits the modifiers of what it
//     maps over, so without it a `?` on a member of `Requests` would make that
//     request's entry optional here — a published request tsc never asks for.
//     With it, such a member is worse than skipped rather than skipped:
//     `Requests["Foo"]` is `Foo | undefined`, `keyof` that is `never`, and the
//     value demanded for `Foo` is a value of `{}`, checked against nothing. So
//     the Rust meta-guard refuses an optional member of the index outright.
//   * `-?` on the inner keys. Without it, seven of these requests are satisfied
//     by an object that sets only their mandatory fields, and every optional one
//     — `startHeight`, `minExpected`, `salt`, `pinLaunchFee` — goes unchecked,
//     which is exactly the mistyped-field case above.
//   * `NonNullable`. `Required<…>` strips the `?` but not the `| null` beside
//     it, and `null` satisfies `string | null` and `number | null` alike: a
//     field answered with `null` has its declared type checked by nothing.
//     `SignRequest.existing` is the live case — it could be republished as a
//     `number` and no compiler would notice.
//
// # Why the whole file is generated
//
// Guard C is only guard C if it is compiled, and if what is compiled still
// demands something. Nothing in a TypeScript file can assert either about
// itself, so Rust has to. It used to do that by looking for a few byte patterns
// in this file — the mapped type above, and the bytes the file ends with — and
// that was worse than nothing, because it reported coverage the patterns could
// not see through. `// @ts-nocheck` on the first line switches tsc off entirely.
// A `// @ts-ignore` does the same for one line. `} as any;` closes the literal
// so that nothing inside it is checked, and appending an empty object literal
// puts the required ending bytes back. All three left every pattern intact,
// every Rust test green, and `tsc -p` exiting 0.
//
// So there are no patterns. This file — this comment included — is generated
// from `REGISTRY` in crates/verus-wasm/src/types.rs and compared to what is
// checked in byte for byte. A suppression pragma is a difference. A deleted
// request value is a difference. A widened one is a difference. Every
// difference is a failing test, and the test names the command that regenerates
// the file.
//
// The keys are not maintained by hand either: `REGISTRY` comes from
// `dto::request_list!`, the one list of request DTOs, so a new request arrives
// here as a regeneration rather than as an omission someone has to notice.
//
// `tsconfig.json` beside this file decides whether any of this is compiled at
// all, so it is generated and compared the same way — an added `"exclude"` is a
// difference like any other. And `types.rs` `include_str!`s this file, so
// deleting it stops the Rust tests compiling rather than quietly narrowing what
// CI checks.
//
// # What is left to review
//
// That the workflow still runs `tsc -p` at all, on purpose: guarding it would
// mean scanning the workflow's YAML for the shape a human edits, and a scan
// that tokenises differently from what it guards is the bug this design exists
// to stop repeating.
//
// And whether the values below are honest ones. They are object literals, and
// they have to be: an `as` cast, or a `satisfies` on a widened value, makes tsc
// check nothing while the key still appears present. No comparison of bytes can
// tell those apart from an honest literal. What it can do is move the question
// somewhere a reviewer looks — the values live in `EXERCISED_VALUES` in
// types.rs, so widening one is an edit to Rust source rather than a quiet edit
// to a checked-in artefact.
//
// Not compiled into anything: `tsc --noEmit` is the whole test.

import type { Requests } from "../../pkg/verus_wasm.js";

const utxo = {
  txid: "aa".repeat(32),
  vout: 0,
  satoshis: "1000000000",
  scriptPubKey: "76a914" + "22".repeat(20) + "88ac",
};

"#;

    /// The mapped type guard C's whole obligation is written in.
    ///
    /// A mapped type over `keyof Requests` with every modifier that would let
    /// something go unchecked stripped off. Each `-?` and the `NonNullable` is
    /// load-bearing, and each of them is a byte of the generated file, so
    /// weakening one in what is checked in is a failing comparison rather than a
    /// quietly smaller check.
    const EXERCISED_OBLIGATION: &str = "\
const exercised: {
  [K in keyof Requests]-?: { [F in keyof Requests[K]]-?: NonNullable<Requests[K][F]> };
} = {
";

    /// One populated value per registered request, in `REGISTRY` order.
    ///
    /// This is the hand-written half of guard C, and it is hand-written on
    /// purpose: nothing in this crate knows what a plausible address, a
    /// plausible currency id or a plausible offer blob looks like, and a value
    /// derived from `Default` would answer a string-literal union like
    /// `PlanConvertRequest.kind` with `""` — a value tsc refuses, which is not
    /// the check anybody wanted.
    ///
    /// What is *not* hand-written is which requests appear. The list is zipped
    /// with `REGISTRY` position by position in [`exercised_source`], so a
    /// request added to `dto::request_list!` without a value here fails before a
    /// line is generated, and a value here that no entry registers fails the
    /// same way.
    ///
    /// # Deliberately not asserted here
    ///
    /// That these literals are honest. `{ …, fee: "20010" as any }` written into
    /// one of them makes tsc check that entry against nothing and generates a
    /// file that matches itself perfectly. No comparison of bytes can see that;
    /// it is a review question, and this is where a reviewer finds it.
    const EXERCISED_VALUES: &[(&str, &str)] = &[
        (
            "SendRequest",
            r#"{
    utxos: [utxo],
    recipients: [{ address: "RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX", satoshis: "150000000" }],
    changeAddress: "RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX",
    expiryHeight: 1200020,
    feePerKb: "10000",
  }"#,
        ),
        (
            "TokenSendRequest",
            r#"{
    utxos: [utxo],
    recipients: [{ address: "RQr2…", currency: "iJhCez…", amount: "100000000" }],
    changeAddress: "RQr2…",
    expiryHeight: 1200020,
    feePerKb: "10000",
  }"#,
        ),
        (
            "ConvertRequest",
            // `reserveToReserve`, because the obligation strips optionality:
            // every field must be present and non-null, and `via` is only
            // coherent on the kind that routes.
            r#"{
    utxos: [utxo],
    tokenFunding: [utxo],
    from: "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq",
    amount: "100000000",
    kind: "reserveToReserve",
    into: "i9nwxtKuVYX4MSbeULLiK2ttVi6rUEhh4X",
    via: "iQihXUcQt8G9TSh58YoM5NRwC1nAyoazFR",
    recipient: "RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX",
    refund: "RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX",
    chainCurrency: "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq",
    feeCurrency: "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq",
    fee: "20000",
    changeAddress: "RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX",
    expiryHeight: 1200020,
    feePerKb: "10000",
  }"#,
        ),
        (
            "SignRequest",
            r#"{
    identity: "iL9bc…",
    systemId: "iJhCez…",
    blockHeight: 1200000,
    message: "log me in",
    existing: "AYAeAAABQR9hZ2lWaWVQAAAA…",
  }"#,
        ),
        (
            "VerifyRequest",
            r#"{
    identity: "iL9bc…",
    systemId: "iJhCez…",
    message: "log me in",
    signature: "AYAeAAAB…",
    primaryAddresses: ["RQr2…"],
    minimumSignatures: 1,
    currentHeight: 1200000,
    maxAgeBlocks: 60,
  }"#,
        ),
        (
            "PlanSendRequest",
            r#"{
    to: "RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX",
    satoshis: "150000000",
  }"#,
        ),
        (
            "HistoryRequest",
            r#"{
    addresses: ["RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX"],
    startHeight: 1100000,
    endHeight: 1200000,
  }"#,
        ),
        (
            "LoginRequest",
            r#"{
    audience: "https://example.test",
    challenge: "ab".repeat(16),
  }"#,
        ),
        (
            "VerifyLoginRequest",
            r#"{
    identity: "iL9bc…",
    signature: "AYAeAAAB…",
    audience: "https://example.test",
    challenge: "ab".repeat(16),
    maxAgeBlocks: 60,
    maxFutureBlocks: 3,
  }"#,
        ),
        (
            "SpendableRequest",
            r#"{
    address: "RQr2cUkF46n7y8WRzDkd1iV9gHusSSQuzX",
  }"#,
        ),
        (
            "ContentRequest",
            r#"{
    identity: "iL9bc…",
  }"#,
        ),
        (
            "PlanSendTokenRequest",
            r#"{
    currency: "iJhCez…",
    to: "RQr2…",
    amount: "100000000",
    tokenUtxos: [utxo],
  }"#,
        ),
        (
            "PlanSendFromIdentityRequest",
            r#"{
    identity: "iL9bc…",
    to: "RQr2…",
    satoshis: "150000000",
  }"#,
        ),
        (
            "PlanSendTokenFromIdentityRequest",
            r#"{
    identity: "iL9bc…",
    currency: "iJhCez…",
    to: "RQr2…",
    amount: "100000000",
  }"#,
        ),
        (
            "PlanConvertFromIdentityRequest",
            r#"{
    identity: "iL9bc…",
    from: "iJhCez…",
    amount: "150000000",
    kind: "intoFractional",
    into: "iQihX…",
    via: "iQihX…",
    recipient: "RQr2…",
    fee: "20010",
  }"#,
        ),
        (
            "PlanPublishRequest",
            r#"{
    identity: "iL9bc…",
    key: "vrsc::example.profile",
    values: ["68656c6c6f"],
  }"#,
        ),
        (
            "OffersRequest",
            r#"{
    target: "iJhCez…",
    isCurrency: true,
    withOfferBytes: true,
  }"#,
        ),
        (
            "OfferTermsRequest",
            r#"{
    offer: "00",
  }"#,
        ),
        (
            "TakeOfferRequest",
            r#"{
    offer: "00",
    utxos: [utxo],
    recipient: "RQr2…",
    changeAddress: "RQr2…",
    fee: "20000",
  }"#,
        ),
        (
            "PlanConvertRequest",
            r#"{
    from: "iJhCez…",
    amount: "150000000",
    kind: "intoFractional",
    into: "iQihX…",
    via: "iQihX…",
    recipient: "RQr2…",
    fee: "20010",
    minExpected: "149000000",
    tokenFunding: [utxo],
  }"#,
        ),
        (
            "PlanBurnRequest",
            r#"{
    currency: "iQihX…",
    amount: "1",
    fee: "20010",
    tokenFunding: [utxo],
  }"#,
        ),
        (
            "PlanMintRequest",
            r#"{
    currency: "iQihX…",
    amount: "1",
    recipient: "RQr2…",
    fee: "20010",
  }"#,
        ),
        (
            "PlanRegistrationRequest",
            r#"{
    name: "alice",
    primaryAddresses: ["RQr2…"],
    minSigs: 1,
    referral: "bob@",
    revocationAuthority: "iL9bc…",
    recoveryAuthority: "iL9bc…",
    pinFee: "10000000000",
    salt: "ff".repeat(32),
  }"#,
        ),
        (
            "PendingRequest",
            r#"{
    pending: {
      state: "awaitingCommitment",
      name: "alice",
      registrationFee: "10000000000",
      commitmentHex: "0400008085202f89",
      commitmentTxid: "bb".repeat(32),
      pending: "opaque-state-blob",
    },
  }"#,
        ),
        (
            "PlanLaunchRequest",
            r#"{
    identity: "basket@",
    definition: {
      name: "basket",
      parent: "iJhCez…",
      kind: "fractional",
      startBlock: 1200000,
      endBlock: 1300000,
      initialSupply: "100000000",
      proofProtocol: 2,
      currencies: ["iJhCez…"],
      weights: ["100000000"],
      minPreconversion: ["0"],
      maxPreconversion: ["100000000"],
      preallocations: [{ recipient: "iL9bc…", amount: "100000000" }],
      idRegistrationFees: "10000000000",
      idReferralLevels: 3,
      idImportFees: "10000000000",
    },
    pinLaunchFee: "10000000000",
  }"#,
        ),
    ];

    /// Guard C's file, as `REGISTRY` says it should read, byte for byte.
    fn exercised_source() -> String {
        assert_eq!(
            EXERCISED_VALUES.len(),
            REGISTRY.len(),
            "`EXERCISED_VALUES` has {} entries and `REGISTRY` has {}. Every registered \
             request needs a value for tsc to type-check, and a value no entry registers \
             is a value tsc checks against nothing.",
            EXERCISED_VALUES.len(),
            REGISTRY.len()
        );

        let mut out = String::from(EXERCISED_PREAMBLE);
        out.push_str(EXERCISED_OBLIGATION);
        for (entry, (name, value)) in REGISTRY.iter().zip(EXERCISED_VALUES) {
            assert_eq!(
                entry.interface, *name,
                "`EXERCISED_VALUES` and `REGISTRY` disagree at this position, so the value \
                 written for one request would be generated under another's name. The two \
                 are in the order `dto::request_list!` gives them."
            );
            out.push_str(&format!("  {name}: {value},\n"));
        }
        out.push_str("};\n\nvoid exercised;\n");
        out
    }

    /// Guard C exercises exactly the registered requests, and tsc sees all of it.
    ///
    /// # Why this is a whole-file comparison and not a check for what matters
    ///
    /// It was a check for what matters, and that is the bug. Rust looked for the
    /// mapped type and for the bytes the file ends with, on the reasoning that
    /// those are what make the obligation total. Three edits went straight past
    /// both: `// @ts-nocheck` on the first line switches tsc off for the file
    /// while every pattern still reads correctly; `// @ts-ignore` does the same
    /// for one mistyped value; and `} as any;` closes the object literal so
    /// nothing inside it is checked, after which an empty object literal restores
    /// the ending bytes the second pattern demanded. All three left `tsc -p`
    /// exiting 0 and every Rust test green.
    ///
    /// A pattern is a claim about part of a file, and the part it does not claim
    /// is where the next bypass goes. So there is no pattern: the file is
    /// generated here and compared to what is checked in, whole. Nothing can be
    /// added to it, removed from it or edited in it without differing, and a
    /// suppression pragma is nothing special — it is bytes that were not
    /// generated.
    ///
    /// This is the same arrangement as
    /// `every_declaration_this_file_reads_is_pinned_for_tsc`, and for the same
    /// reason. Regenerating after weakening the generator does not help either:
    /// the generator is Rust source, and what it emits is `REGISTRY` plus the
    /// literals in `EXERCISED_VALUES`, both of which a reviewer reads.
    ///
    /// # Deliberately not asserted here
    ///
    /// That the workflow still runs `tsc` at all. That is a visible deletion of
    /// a named step, and it is not a unit test's job: the only way to check it
    /// from Rust is to scan `.github/workflows/ci.yml` for the syntax a human
    /// edits — a scan that tokenises differently from the thing it guards, which
    /// is the entire failure class #191 exists to end. So it is written down as a
    /// boundary instead of defended with another scanner.
    #[test]
    fn guard_c_exercises_every_registered_request() {
        // An emptied registry would generate a file that demands nothing, and an
        // emptied file would compare equal to it — vacuously green while this
        // crate reported guard C as covering every request. The registry is what
        // guard C's obligation is made of, so its size is asserted before the
        // comparison that rests on it.
        assert!(
            REGISTRY.len() > 20,
            "`dto::request_list!` is down to {} entries. Guard C exercises what the \
             registry lists, so a truncated list generates a truncated obligation and this \
             comparison would hold over it.",
            REGISTRY.len()
        );

        let generated = exercised_source();

        if std::env::var_os("UPDATE_TYPESCRIPT_PINS").is_some() {
            std::fs::write(
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/node/requests.exercised.ts"
                ),
                &generated,
            )
            .expect("guard C's file is writable");
        }

        assert_eq!(
            EXERCISED, generated,
            "crates/verus-wasm/tests/node/requests.exercised.ts is not what `REGISTRY` \
             generates. It is generated, not written — including its comment header: \
             re-run with UPDATE_TYPESCRIPT_PINS=1 and read the diff. A `// @ts-nocheck`, a \
             `// @ts-ignore`, a `}} as any;` or a deleted request value all arrive here as \
             this difference. If the diff is not what you meant to change about the \
             request list, the change to `dto::request_list!` is the bug."
        );
    }

    /// The project that decides whether guard C is compiled, as checked in.
    ///
    /// `include_str!` for the same reason as [`EXERCISED`]: deleting the project
    /// stops this crate compiling rather than quietly leaving `tsc -p` with
    /// nothing to do.
    const TSCONFIG: &str = include_str!("../tests/node/tsconfig.json");

    /// And what it has to say, byte for byte.
    const TSCONFIG_SOURCE: &str = r#"// Generated by `guard_c_is_compiled_by_a_generated_project` in
// crates/verus-wasm/src/types.rs. Do not edit: that test rewrites this file
// when run with UPDATE_TYPESCRIPT_PINS=1, and fails when the two disagree.
//
// The TypeScript half of the drift guards, as one project.
//
// `include` is a glob over this directory rather than a list of file names, and
// that is the point: a list here would be a second copy of "which declaration
// checks exist", and a second copy is a thing that drifts. Every `.ts` file
// beside this one is compiled, so adding a check is adding a file, and no
// workflow, script or test has to be edited to keep up.
//
// This file is what decides whether guard C is compiled at all, and for a while
// nothing in Rust read it. That made it the quiet place to put the answer: an
// added `"exclude": ["requests.exercised.ts"]` takes guard C out of the build
// with tsc still exiting 0 and every Rust test still green, and so does a
// narrowed `"include"` or a dropped `"strict"`. So it is generated from a
// constant in types.rs and compared to what is checked in byte for byte, the
// same way the files it compiles are.
//
// Both CI (`.github/workflows/ci.yml`) and CONTRIBUTING.md invoke exactly this
// project — `npx -y -p typescript@5 tsc -p crates/verus-wasm/tests/node` — so
// the strictness a contributor gets locally is the strictness CI applies, and
// it is written down once, here.
//
// The `.mjs` differential harness is deliberately not matched: it is run by
// node, not type-checked.
{
    "compilerOptions": {
        "noEmit": true,
        "strict": true,
        "target": "esnext",
        "lib": ["esnext"],
        "module": "esnext",
        "moduleResolution": "bundler"
    },
    "include": ["*.ts"]
}
"#;

    /// The TypeScript project is generated too.
    ///
    /// # Why a file with nothing derived in it is still generated
    ///
    /// Because it is the file that answers "does guard C run?", and until this
    /// test existed no Rust code read it at all. That made it the quietest place
    /// in the arrangement to put a bypass: `"exclude": ["requests.exercised.ts"]`
    /// takes guard C out of the build, `tsc -p` exits 0 with nothing to say, and
    /// all of this crate's tests stay green. A narrowed `"include"` and a dropped
    /// `"strict"` are the same move with different bytes.
    ///
    /// Nothing here is derived from anything, so "generated" means only that the
    /// text lives in Rust and the checked-in file has to equal it. That is enough:
    /// the question stops living in an unread file, and every edit to it is a
    /// difference this test prints.
    #[test]
    fn guard_c_is_compiled_by_a_generated_project() {
        if std::env::var_os("UPDATE_TYPESCRIPT_PINS").is_some() {
            std::fs::write(
                concat!(env!("CARGO_MANIFEST_DIR"), "/tests/node/tsconfig.json"),
                TSCONFIG_SOURCE,
            )
            .expect("the TypeScript project is writable");
        }

        assert_eq!(
            TSCONFIG, TSCONFIG_SOURCE,
            "crates/verus-wasm/tests/node/tsconfig.json is not what types.rs says it is. \
             It is generated, not written: re-run with UPDATE_TYPESCRIPT_PINS=1 and read \
             the diff. This file decides which `.ts` files tsc compiles and how strictly, \
             so an added `exclude`, a narrowed `include` or a dropped `strict` is guard C \
             doing less while every Rust test stays green."
        );
    }

    /// tsc has to agree with what this file reads out of `types.d.ts`.
    ///
    /// # Why this exists
    ///
    /// Everything the drift guards say about the published declarations goes
    /// through `declared_members`, and `declared_members` is a line parser. It
    /// skips a line that *starts* a comment, which is not the same as knowing
    /// where a comment ends — so a member sitting on the continuation line of a
    /// `/* … */` block reads as declared to it and as deleted to tsc. That is
    /// bypass round one of the five, and it does not care which caller it is
    /// answering: through `declared_by` it makes guard A report a field the
    /// shipped `.d.ts` no longer publishes, and through the meta-guard's read of
    /// the `Requests` index it makes guard C report a request no compiler
    /// touches any more. Because the parser's map is keyed by member name, a
    /// dishonest declaration followed by the honest one inside a comment even
    /// survives the check that each index member points at its own interface:
    /// the second insert wins in Rust, and the first one is the only one tsc
    /// ever sees.
    ///
    /// The answer is not another rule in the parser — that is what the fourth
    /// round's fix bought the fifth round with. It is to stop the parser being
    /// the authority. `types.d.ts` already has a reader that is never wrong
    /// about it, because it is the reader every caller gets: tsc. So the parse
    /// is written out as TypeScript that asserts it, and CI compiles it. The
    /// parser may still be fooled; it can no longer be fooled *quietly*, and
    /// the guards downstream of it inherit that.
    ///
    /// # And what it can no longer be fooled about at all
    ///
    /// Pinning covers what the parser read. It says nothing about what it never
    /// read, and that was the last bypass: a declaration a search skipped was in
    /// no pin, so tsc was under no obligation about it. [`document`] is total
    /// for that reason — every line of `types.d.ts` becomes an `Item`, there is
    /// no "something else" to fall into, and
    /// `the_document_parser_reads_every_byte_of_types_d_ts` proves it by writing
    /// the items back out and comparing them to the file byte for byte.
    ///
    /// # What holds this in place
    ///
    /// Rewriting the generated file does not help an attacker: its contents are
    /// this parser's own belief, so regenerating it after fooling the parser
    /// reproduces the same disagreement with tsc. Editing it by hand fails the
    /// comparison below. Deleting it fails `include_str!` above, before any test
    /// runs. And CI compiles it because `tests/node/tsconfig.json` includes
    /// every `.ts` file in that directory — there is no list of file names
    /// anywhere that could quietly stop mentioning it, and that project file is
    /// itself generated and compared, so an `exclude` cannot be added to it
    /// either.
    #[test]
    fn every_declaration_this_file_reads_is_pinned_for_tsc() {
        let generated = pinned_declarations();
        // The parsed interfaces feed the pinned file, so a reader that came
        // back with nothing would write out an empty pin and every claim below
        // would hold over nothing.
        assert!(
            declared_interfaces().len() > 60,
            "found suspiciously few `export interface` declarations in types.d.ts; an empty \
             pin obliges tsc to nothing"
        );

        if std::env::var_os("UPDATE_TYPESCRIPT_PINS").is_some() {
            std::fs::write(
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/node/declarations.pinned.ts"
                ),
                &generated,
            )
            .expect("the pinned declarations are writable");
        }

        assert_eq!(
            PINNED, generated,
            "crates/verus-wasm/tests/node/declarations.pinned.ts is not what this file reads \
             out of types.d.ts. It is generated, not written: re-run with \
             UPDATE_TYPESCRIPT_PINS=1 and read the diff. If the diff is not what you meant to \
             change about types.d.ts, the change to types.d.ts is the bug."
        );
    }

    /// The reader accounts for every byte of `types.d.ts`.
    ///
    /// # What this is for
    ///
    /// Everything the drift guards know about `types.d.ts` comes through
    /// [`document`], and the pinned declarations make tsc check what that
    /// reader *believes*. Neither says anything about what it never read. That
    /// gap is where the last bypass lived: a search for `export interface `
    /// skipped `export interface  QuietRequest` — two spaces — so the
    /// declaration was in no pin, tsc was under no obligation about it, and no
    /// Rust guard had ever heard of it, while the shipped `.d.ts` published it
    /// in full to every caller.
    ///
    /// So the reader is required to be total, and this is where that is
    /// established: the items are written back out and compared to the file
    /// byte for byte. A line the parse dropped is a line missing here; a line it
    /// merged, reordered or rewrote is a line that differs. There is no syntax
    /// left to be fooled about, because nothing is being recognised — the bytes
    /// either come back or they do not.
    ///
    /// The two-space header does not survive by being skipped either: with no
    /// "something else" variant to fall into, it is read as an interface whose
    /// name is not an identifier, and `document` panics naming the line.
    #[test]
    fn the_document_parser_reads_every_byte_of_types_d_ts() {
        let mut lines: Vec<String> = Vec::new();
        for item in &document() {
            lines.extend(item.lines().iter().cloned());
        }
        assert_eq!(
            lines.join("\n"),
            TYPESCRIPT,
            "reading crates/verus-wasm/src/types.d.ts back out of the parsed document does \
             not reproduce it. Something in that file is not a blank line, a comment, an \
             `export interface` block or an `export type` alias — or one of those is \
             written in a way this reader silently changed. Either way there is text tsc \
             publishes that the guards here do not see, which is the whole of #191."
        );
    }

    /// The interface names a `export type X = A | B | …;` union lists.
    ///
    /// A variant interface that exists but is not a member of the union is
    /// unreachable: `decodeOutput` returns the union, so a caller can never
    /// narrow to it.
    ///
    /// # Why it is taken from the parsed document
    ///
    /// This used to be `TYPESCRIPT.find("export type X =")`, and `find` returns
    /// the *first* occurrence. A byte-verbatim copy of the declaration parked
    /// in a `/* … */` comment above the real one is the first occurrence, so
    /// the union this crate checked and the union tsc published could be
    /// different unions with nothing to say so — one variant short, and a
    /// wallet's exhaustive `switch` quietly missing a state. In the document a
    /// comment is an `Item::Ignored` and can never be mistaken for a
    /// declaration.
    ///
    /// # Why the reading itself is not trusted either
    ///
    /// `pinned_declarations` writes every alias's right-hand side into the file
    /// tsc compiles, so what this reads is held against the compiler in the same
    /// way every interface's members are. A union this read wrongly is a
    /// `TS2344` rather than a difference nobody notices.
    fn union_members(name: &str) -> BTreeSet<String> {
        let (_, _, rhs) = declared_aliases()
            .into_iter()
            .find(|(alias, _, _)| alias == name)
            .unwrap_or_else(|| panic!("types.d.ts declares no type {name}"));
        rhs.split('|')
            .map(str::trim)
            .filter(|member| !member.is_empty())
            .map(str::to_string)
            .collect()
    }

    fn assert_declared<T: Serialize>(interface: &str, value: &T) {
        let produced = field_names(value);
        let declared = declared_by(interface);
        assert_eq!(
            produced, declared,
            "interface {interface} in types.d.ts does not match what the Rust type \
             serializes; the .d.ts a caller gets would be wrong"
        );
    }

    /// The runtime shape must list exactly the fields the value serializes.
    ///
    /// Shared by the registry-driven guard and by the nested-field checks,
    /// so both halves of `every_shape_matches_the_type_it_guards` fail the
    /// same way and for the same reason.
    fn assert_shape_lists<T: Serialize>(name: &str, shape: &Shape, value: &T) {
        let declared: BTreeSet<String> = shape
            .fields
            .iter()
            .map(|(field, _)| (*field).to_string())
            .collect();
        assert_eq!(
            declared,
            field_names(value),
            "{name} does not match what the Rust type serializes"
        );
    }

    /// The drift check. A field added to, renamed in, or removed from a DTO
    /// fails here until its interface catches up — and because it compares the
    /// two *sets*, a field declared in TypeScript that no longer exists in
    /// Rust fails too.
    #[test]
    fn every_field_of_every_dto_is_declared() {
        use crate::decode::TokenAmount;
        use crate::dto::{JsOutpoint, JsRecipient, JsSignedTransaction, JsUtxo};
        use crate::flows::{
            JsContentValue, JsCurrencyDefinition, JsFunding, JsHistoryEntry, JsLaunched, JsListing,
            JsLoggedIn, JsOfferTerms, JsPlannedTransaction, JsPlannedUpdate, JsPreallocation,
            JsTaken, PlanStep,
        };
        use crate::login::VerifyResult;
        use crate::send::JsTokenRecipient;

        // The request DTOs, from the single list in `dto::request_list!`.
        // Guard A is `assert_declared` applied to each: exactly the call
        // the hand-written lines below make for the types that are not
        // requests.
        for entry in REGISTRY {
            (entry.fields_match_interface)();
        }

        // The types that are not requests. The registry is keyed on the
        // `*Request` interfaces the meta-guard can enumerate from
        // types.d.ts; there is no source of truth to derive the rest from,
        // so they stay hand-listed here and nothing claims otherwise.
        assert_declared("Utxo", &JsUtxo::default());
        assert_declared("Recipient", &JsRecipient::default());
        assert_declared("TokenRecipient", &JsTokenRecipient::default());
        assert_declared("Outpoint", &JsOutpoint::default());
        assert_declared("SignedTransaction", &JsSignedTransaction::default());
        // Every optional field populated, so `skip_serializing_if` cannot hide
        // one from the check.
        assert_declared(
            "VerifyResult",
            &VerifyResult {
                reason: Some(String::new()),
                ..VerifyResult::default()
            },
        );
        assert_declared("TokenAmount", &TokenAmount::default());
        // Every optional field populated, so `skip_serializing_if` cannot hide
        // one from the check.
        assert_declared(
            "MnemonicCheck",
            &crate::mnemonic::MnemonicCheck {
                reason: Some(String::new()),
                position: Some(0),
                ..crate::mnemonic::MnemonicCheck::default()
            },
        );

        // The flow bindings. Every optional field is populated, because a
        // `skip_serializing_if` field is exactly the one a drift check would
        // otherwise never see.
        // `PlanStep` is a discriminated union in TypeScript so that narrowing on
        // `kind` works, which one interface with an optional `value` could not
        // do. The Rust side stays a single struct, so each arm is checked
        // against the serialization that produces it: no `value` when asking,
        // a `value` when ready.
        assert_declared("PlanStepAsk", &PlanStep::<String>::default());
        assert_declared(
            "PlanStepReady",
            &PlanStep {
                value: Some(String::new()),
                ..PlanStep::<String>::default()
            },
        );
        assert_declared("PlannedTransaction", &JsPlannedTransaction::default());
        assert_declared("PlannedUpdate", &JsPlannedUpdate::default());
        assert_declared("HistoryEntry", &JsHistoryEntry::default());
        assert_declared("LoggedIn", &JsLoggedIn::default());
        assert_declared("Funding", &JsFunding::default());
        assert_declared(
            "Listing",
            &JsListing {
                raw_offer: Some(String::new()),
                ..JsListing::default()
            },
        );
        assert_declared("OfferTerms", &JsOfferTerms::default());
        assert_declared("Pending", &crate::flows::JsPending::default());
        assert_declared("Registered", &crate::flows::JsRegistered::default());
        assert_declared("Preallocation", &JsPreallocation::default());
        assert_declared(
            "CurrencyDefinition",
            &JsCurrencyDefinition {
                end_block: Some(0.0),
                initial_supply: Some(String::new()),
                proof_protocol: Some(0),
                id_registration_fees: Some(String::new()),
                id_referral_levels: Some(0.0),
                id_import_fees: Some(String::new()),
                ..JsCurrencyDefinition::default()
            },
        );
        assert_declared("Launched", &JsLaunched::default());
        assert_declared("Taken", &JsTaken::default());
        assert_declared(
            "ContentValue",
            &JsContentValue {
                hex: Some(String::new()),
                structured: Some(serde_json::Value::Null),
            },
        );
    }

    /// The offer unions, whose variants nothing checked until now.
    ///
    /// `DecodedOutput` has had this since it was added; `OfferSide` and
    /// `Demand` arrived later and slipped past, because the per-field check
    /// only ever sees the types it is handed by name.
    #[test]
    fn every_offer_union_variant_is_declared_and_reachable() {
        use crate::flows::{JsDemand, JsOfferSide};
        use std::collections::BTreeMap;

        fn side_interface(side: &JsOfferSide) -> &'static str {
            match side {
                JsOfferSide::Currencies { .. } => "OfferSideCurrencies",
                JsOfferSide::Identity { .. } => "OfferSideIdentity",
            }
        }
        fn demand_interface(demand: &JsDemand) -> &'static str {
            match demand {
                JsDemand::Native { .. } => "DemandNative",
                JsDemand::Token { .. } => "DemandToken",
            }
        }

        let sides = [
            JsOfferSide::Currencies {
                amounts: BTreeMap::new(),
            },
            JsOfferSide::Identity {
                identity_id: String::new(),
                name: String::new(),
                system_id: String::new(),
            },
        ];
        for side in &sides {
            assert_declared(side_interface(side), side);
        }
        assert_eq!(
            sides
                .iter()
                .map(|s| side_interface(s).to_string())
                .collect::<BTreeSet<_>>(),
            union_members("OfferSide")
        );

        let demands = [
            JsDemand::Native {
                amount: String::new(),
                recipient: String::new(),
            },
            JsDemand::Token {
                currency: String::new(),
                amount: String::new(),
                recipient: String::new(),
            },
        ];
        for demand in &demands {
            assert_declared(demand_interface(demand), demand);
        }
        assert_eq!(
            demands
                .iter()
                .map(|d| demand_interface(d).to_string())
                .collect::<BTreeSet<_>>(),
            union_members("Demand")
        );
    }

    /// The commitment status union.
    ///
    /// A registration reads this to decide whether to spend the registration
    /// fee, so a variant that is declared wrongly — or reachable in Rust and
    /// missing from the union — is a caller unable to tell "wait" from "the
    /// chain moved under you".
    #[test]
    fn every_commitment_status_variant_is_declared_and_reachable() {
        use crate::flows::{JsCommitmentStatus, JsPending};

        fn interface_of(status: &JsCommitmentStatus) -> &'static str {
            match status {
                JsCommitmentStatus::Waiting { .. } => "CommitmentWaiting",
                JsCommitmentStatus::Ready { .. } => "CommitmentReady",
                JsCommitmentStatus::Reorged { .. } => "CommitmentReorged",
                JsCommitmentStatus::Gone => "CommitmentGone",
                JsCommitmentStatus::Expired { .. } => "CommitmentExpired",
            }
        }

        let samples = [
            JsCommitmentStatus::Waiting { confirmations: 0 },
            JsCommitmentStatus::Ready {
                pending: JsPending::default(),
            },
            JsCommitmentStatus::Reorged {
                detail: String::new(),
            },
            JsCommitmentStatus::Gone,
            JsCommitmentStatus::Expired {
                expiry_height: 0,
                tip: 0,
            },
        ];
        for sample in &samples {
            assert_declared(interface_of(sample), sample);
        }
        assert_eq!(
            samples
                .iter()
                .map(|s| interface_of(s).to_string())
                .collect::<BTreeSet<_>>(),
            union_members("CommitmentStatus")
        );
    }

    /// `DecodedOutput` is a union, so the drift check has to be one too.
    ///
    /// Three holes are closed together, and it takes all three — each catches
    /// what the others miss when a variant is added:
    ///
    /// * `interface_of` matches exhaustively, so a new Rust variant does not
    ///   compile until it is named;
    /// * `assert_declared` fails if that name has no interface, or if the
    ///   interface's fields are not exactly what the variant serializes;
    /// * comparing against `union_members` fails if an interface exists but is
    ///   not in the union — unreachable to a caller — or if it is in the union
    ///   but has no sample here, which is how a variant gets declared and then
    ///   never checked again.
    #[test]
    fn every_decoded_output_variant_is_declared_and_reachable() {
        use crate::decode::DecodedOutput;

        /// Exhaustive by construction: adding a variant is a compile error
        /// here before it is a test failure anywhere else.
        fn interface_of(output: &DecodedOutput) -> &'static str {
            match output {
                DecodedOutput::PubKeyHash { .. } => "DecodedPubKeyHash",
                DecodedOutput::PubKey { .. } => "DecodedPubKey",
                DecodedOutput::ReserveOutput { .. } => "DecodedReserveOutput",
                DecodedOutput::IdentityPayment { .. } => "DecodedIdentityPayment",
                DecodedOutput::IdentityPrimary { .. } => "DecodedIdentityPrimary",
                DecodedOutput::IdentityCommitment { .. } => "DecodedIdentityCommitment",
                DecodedOutput::ReserveDeposit { .. } => "DecodedReserveDeposit",
                DecodedOutput::ReserveTransfer { .. } => "DecodedReserveTransfer",
                DecodedOutput::UnsupportedCryptoCondition { .. } => {
                    "DecodedUnsupportedCryptoCondition"
                }
                DecodedOutput::Unknown => "DecodedUnknown",
            }
        }

        let samples = [
            DecodedOutput::PubKeyHash {
                address: String::new(),
            },
            DecodedOutput::PubKey {
                address: String::new(),
            },
            DecodedOutput::ReserveOutput {
                address: String::new(),
                tokens: Vec::new(),
            },
            DecodedOutput::IdentityPayment {
                address: String::new(),
            },
            DecodedOutput::IdentityPrimary {
                address: String::new(),
                name: String::new(),
                primary_addresses: Vec::new(),
                minimum_signatures: 0,
            },
            DecodedOutput::IdentityCommitment {
                address: String::new(),
                commitment: String::new(),
                tokens: Vec::new(),
            },
            DecodedOutput::ReserveDeposit {
                address: String::new(),
                controlling_currency: String::new(),
                tokens: Vec::new(),
            },
            DecodedOutput::ReserveTransfer {
                address: String::new(),
                tokens: Vec::new(),
                flags: 0,
                fee_currency: String::new(),
                fees: String::new(),
                destination_currency: String::new(),
                recipient: String::new(),
                // `Some`, not `None`: the drift guard learns a variant's fields
                // from what it serializes, and an absent optional is a field it
                // would never see.
                refund: Some(String::new()),
                second_reserve: Some(String::new()),
            },
            DecodedOutput::UnsupportedCryptoCondition {
                eval_code: 0,
                may_carry_currency: false,
            },
            DecodedOutput::Unknown,
        ];

        for sample in &samples {
            assert_declared(interface_of(sample), sample);
        }

        let sampled: BTreeSet<String> = samples
            .iter()
            .map(|sample| interface_of(sample).to_string())
            .collect();
        assert_eq!(
            sampled,
            union_members("DecodedOutput"),
            "the DecodedOutput union in types.d.ts does not list exactly the variants \
             this crate can return"
        );
    }

    /// The runtime shapes that make unknown-key rejection work (see
    /// `dto::from_js`). A field added to a request type but missing from its
    /// `SHAPE` would be refused as unknown the first time a caller passed it;
    /// a stale entry left behind would let a typo through. Both are caught by
    /// comparing against what the type serializes — including the nested
    /// shapes, which is where the guarantee used to rest on prose alone.
    #[test]
    fn every_shape_matches_the_type_it_guards() {
        use crate::dto::{JsRecipient, JsUtxo};
        use crate::flows::{
            JsCurrencyDefinition, JsPreallocation, PlanBurnRequest, PlanConvertRequest,
            PlanLaunchRequest, PlanSendTokenRequest, TakeOfferRequest,
        };
        use crate::send::{JsTokenRecipient, SendRequest, TokenSendRequest};

        /// The shared assertion, for the nested shapes the registry does
        /// not reach. `T::default()` is enough here: none of these element
        /// types has a field a default value leaves unserialized.
        fn check<T: Serialize + Default>(name: &str, shape: &Shape) {
            assert_shape_lists(name, shape, &T::default());
        }

        /// The nested shape guarding `field`, or a failure naming what is
        /// missing.
        ///
        /// Following the pointer is the point. Comparing only field *names*
        /// would pass while a nested shape was `None` — and `None` means that
        /// object is not guarded at all, which is the exact bug the nested
        /// shapes were added to fix.
        fn nested(shape: &Shape, field: &str) -> &'static Shape {
            shape
                .fields
                .iter()
                .find(|(name, _)| *name == field)
                .unwrap_or_else(|| panic!("no field {field}"))
                .1
                .unwrap_or_else(|| {
                    panic!(
                        "{field} carries objects but declares no nested shape, so a stray key \
                         inside one would be silently dropped"
                    )
                })
        }

        // The request roots, from the same list guard A uses. Each entry
        // checks the type it names, so this cannot drift from the registry
        // the meta-guard compares against types.d.ts.
        for entry in REGISTRY {
            (entry.shape_matches_type)();
        }

        // The nested object fields, which stay hand-written on purpose.
        // They are keyed on `Type.field` rather than on an interface name,
        // and types.d.ts declares nothing this could be enumerated from —
        // so they sit outside the registry, and the meta-guard does not
        // claim to cover them.
        //
        // The stored registration is an object like any other request object,
        // and the pointer has to be followed or it is not guarded at all.
        check::<crate::flows::JsPending>(
            "PendingRequest.pending",
            nested(&crate::flows::PendingRequest::SHAPE, "pending"),
        );
        check::<JsCurrencyDefinition>(
            "PlanLaunchRequest.definition",
            nested(&PlanLaunchRequest::SHAPE, "definition"),
        );
        check::<JsPreallocation>(
            "CurrencyDefinition.preallocations",
            nested(&JsCurrencyDefinition::SHAPE, "preallocations"),
        );
        check::<crate::dto::JsUtxo>(
            "PlanConvertRequest.tokenFunding",
            nested(&PlanConvertRequest::SHAPE, "tokenFunding"),
        );
        check::<crate::dto::JsUtxo>(
            "PlanBurnRequest.tokenFunding",
            nested(&PlanBurnRequest::SHAPE, "tokenFunding"),
        );
        check::<crate::dto::JsUtxo>(
            "TakeOfferRequest.utxos",
            nested(&TakeOfferRequest::SHAPE, "utxos"),
        );
        // The one nested object among the new requests: a stray key inside a
        // token UTXO must be refused like any other.
        check::<crate::dto::JsUtxo>(
            "PlanSendTokenRequest.tokenUtxos",
            nested(&PlanSendTokenRequest::SHAPE, "tokenUtxos"),
        );

        // Every field that carries objects, reached through the pointer the
        // guard actually follows rather than through the type it ought to be.
        check::<JsUtxo>("SendRequest.utxos", nested(&SendRequest::SHAPE, "utxos"));
        check::<JsRecipient>(
            "SendRequest.recipients",
            nested(&SendRequest::SHAPE, "recipients"),
        );
        check::<JsUtxo>(
            "TokenSendRequest.utxos",
            nested(&TokenSendRequest::SHAPE, "utxos"),
        );
        check::<JsTokenRecipient>(
            "TokenSendRequest.recipients",
            nested(&TokenSendRequest::SHAPE, "recipients"),
        );
    }

    /// One request DTO's registration in guard A and guard B.
    ///
    /// The two checks are function pointers *inside* the entry, monomorphised
    /// on the type the entry names, so an entry cannot claim one interface and
    /// check another, and a registration cannot exist without being run. Both
    /// come from `crate::dto::request_list!` — the same list that generates the
    /// `Request` impls `dto::from_js` requires.
    struct Guarded {
        /// The `export interface` in `types.d.ts` that publishes this DTO.
        interface: &'static str,
        /// Guard A, bound to this entry's type.
        fields_match_interface: fn(),
        /// Guard B, bound to this entry's type.
        shape_matches_type: fn(),
    }

    /// Guard A for one request type: what it serializes is exactly what its
    /// interface declares.
    fn guard_a_for<T: Request>() {
        assert_declared(T::INTERFACE, &T::sample());
    }

    /// Guard B for one request type: its runtime `SHAPE` lists exactly the keys
    /// it serializes.
    fn guard_b_for<T: Request>() {
        assert_shape_lists(T::INTERFACE, T::SHAPE, &T::sample());
    }

    impl Guarded {
        /// The registration for `T`. Every part of it is derived from `T`, so
        /// there is nothing here that can disagree with itself.
        const fn of<T: Request>() -> Self {
            Self {
                interface: T::INTERFACE,
                fields_match_interface: guard_a_for::<T>,
                shape_matches_type: guard_b_for::<T>,
            }
        }
    }

    macro_rules! registry {
        (
            $( $ty:ty => $name:literal $({ $($field:ident : $value:expr),* $(,)? })? ),+ $(,)?
        ) => {
            /// Every request DTO, each with its two guards attached.
            ///
            /// Generated from `dto::request_list!`; the sample overrides in that
            /// list are consumed by the `Request` impls, not here.
            const REGISTRY: &[Guarded] = &[$( Guarded::of::<$ty>() ),+];
        };
    }
    crate::dto::request_list!(registry);

    /// The line that opens the generated block in `types.d.ts`.
    ///
    /// Matched as a whole top-level item of the parsed document, and the block
    /// is compared as one string, so there is no per-declaration tokenising
    /// left to be wrong about — the class of mistake that opened all five
    /// earlier bypasses. If either marker is missing the test panics rather
    /// than comparing nothing.
    const INDEX_BEGIN: &str = "// <generated: request index — do not edit by hand>";

    /// The line that closes it.
    const INDEX_END: &str = "// </generated: request index>";

    /// The doc comment the generated block carries, emitted with it.
    ///
    /// It is generated too, and on purpose: prose that explains a generated
    /// block and is itself hand-written is prose that goes stale the first time
    /// the block changes.
    const INDEX_DOC: &str = "\
/**
 * Every request object an exported function accepts, keyed by interface name.
 *
 * Nothing constructs this, and no exported function takes it. It exists so that
 * a request type cannot be published without something being forced to exercise
 * it: `tests/node/requests.exercised.ts` declares a value of a mapped type over
 * this index which strips every modifier that would let something go unchecked,
 * and which tsc then requires to be total and type-checks field by field — so
 * an interface listed here and nowhere else fails the build.
 *
 * Every member is required, and must stay required: `Requests[\"Foo\"]` with a `?`
 * on it is `Foo | undefined`, whose `keyof` is `never`, so the value that file
 * declares for `Foo` would be type-checked against `{}` while this index still
 * lists it. No `?` can appear here by accident, because no hand ever writes this
 * block: it is generated from the same list that generates the `Request` impls.
 *
 * A name here that this file does not declare is a compile error, which is the
 * other half of the arrangement: the list says which requests exist, and tsc
 * says whether each of them is really published.
 */
";

    /// The `Requests` index as `REGISTRY` says it should read, byte for byte.
    fn generated_request_index() -> String {
        let mut out = String::from(INDEX_DOC);
        out.push_str("export interface Requests {\n");
        for entry in REGISTRY {
            out.push_str(&format!("    {0}: {0};\n", entry.interface));
        }
        out.push_str("}\n");
        out
    }

    /// The text between the two markers, as `types.d.ts` has it checked in.
    ///
    /// The markers are located as top-level items of the parsed document, and
    /// each has to occur exactly once. Searching the file's text for them would
    /// take the first hit, and a byte-verbatim copy of this block parked in a
    /// comment above the real one is a first hit: the comparison would then hold
    /// over the decoy while tsc published whatever the real block said.
    fn checked_in_request_index() -> String {
        let document = document();
        let only = |marker: &str| -> usize {
            let mut hits = document
                .iter()
                .enumerate()
                .filter(|(_, item)| item.is_marker(marker))
                .map(|(at, _)| at);
            let first = hits.next().unwrap_or_else(|| {
                panic!(
                    "types.d.ts has no `{marker}` line. The `Requests` index is generated \
                     from `dto::request_list!`; without the markers there is nothing to \
                     compare it against, and guard C's obligation would be whatever \
                     someone typed."
                )
            });
            assert!(
                hits.next().is_none(),
                "types.d.ts carries `{marker}` more than once, so which block is the \
                 generated one is a matter of opinion"
            );
            first
        };

        let begin = only(INDEX_BEGIN);
        let end = only(INDEX_END);
        assert!(
            begin < end,
            "the generated request index in types.d.ts closes before it opens"
        );
        let mut out = String::new();
        for item in &document[begin + 1..end] {
            for line in item.lines() {
                out.push_str(line);
                out.push('\n');
            }
        }
        out
    }

    /// `types.d.ts`'s request index is an *output* of `dto::request_list!`.
    ///
    /// # Why this replaced a scan
    ///
    /// "Which `*Request` interfaces are published?" used to be answered by
    /// searching `types.d.ts` for `export interface `. That search and tsc read
    /// the same hand-written file and did not agree about it: written with two
    /// spaces, `export interface  QuietRequest` is a fully published request to
    /// tsc and nothing at all to the search. A request the search cannot see is
    /// a request that need not appear in any guard, so the coverage every test
    /// here reports would have been short by one and no test would have said so.
    ///
    /// Hardening the search is what the four previous rounds did, and each fix
    /// bought the next bypass. So the direction is reversed instead. There is
    /// one list of request DTOs, `dto::request_list!`; it generates the
    /// `Request` impls `from_js` needs — a request missing from it cannot be
    /// read from JavaScript at all, which is a compile error at its call site —
    /// and it generates `REGISTRY`. This test writes the index from `REGISTRY`
    /// and compares it to the file as one string.
    ///
    /// A string comparison has no syntax to be fooled about. Two spaces after
    /// `interface`, a member that is really a comment, a duplicated line, a `?`:
    /// every one of them is a byte that differs from what was generated, and the
    /// test is red. Adding a request to the file without adding it to the list
    /// is red for the same reason, and adding it to the list without
    /// regenerating is red before the first guard runs.
    ///
    /// # What this deliberately does not claim
    ///
    /// That `types.d.ts` declares no `*Request` interface outside this block.
    /// Answering that needs a scan of the file, which is the thing being
    /// removed. It rests instead on the two *sanctioned* ways a
    /// JavaScript-authored value becomes a Rust DTO, both named in
    /// `crate::dto`:
    ///
    /// * [`crate::dto::from_js`] takes `T: Request`, and the only `Request`
    ///   impls that exist come from `dto::request_list!`, which is sealed.
    /// * `dto::utxo_list_from_js` is the one array argument, and its return
    ///   type is concrete: nothing but `JsUtxo` comes out of it. It used to be
    ///   a generic `from_js_list<T: DeserializeOwned>` taking a hand-supplied
    ///   shape, which is how a request DTO could reach JavaScript without
    ///   appearing in any guard here (#200).
    ///
    /// Both reach `serde-wasm-bindgen` through one private function, and
    /// `clippy.toml` beside this crate's `Cargo.toml` denies that deserializer
    /// — and `serde_json`'s — everywhere else.
    ///
    /// That last part is a weaker promise than the two above, and it is spelled
    /// out here so nobody reads the stronger one. Three ways it is weaker, each
    /// of them checked rather than assumed:
    ///
    /// * An `#[allow]` for the lint lifts it. There are three in this crate
    ///   today, each naming its reason. A fourth is a review question, not a
    ///   compile error — and one placed on a *generic* helper reopens the
    ///   deserializer for every caller of that helper at once.
    /// * The lint bans named paths, not a property. Every deserialising entry
    ///   point it does not name is open, which is why `serde_json`'s four
    ///   spellings are listed rather than just `from_str`. Reading a value
    ///   field by field through `js_sys::Reflect` is not reachable by any list.
    /// * `clippy.toml` sits beside this crate's `Cargo.toml`, so it binds this
    ///   crate only. A helper in a sibling crate that deserialises on our
    ///   behalf is unlinted, and this crate depends on five of them.
    ///
    /// So the registry is sealed by the compiler and the rest is defence in
    /// depth. Anyone extending this should not read the paragraph above as
    /// "there is no other way in".
    #[test]
    fn the_request_index_is_generated_from_the_registry() {
        // An emptied registry would generate an empty index, and an empty index
        // compared against an emptied block would pass while guard C exercised
        // nothing. The registry is the source of truth, so this is where its
        // size is asserted.
        assert!(
            REGISTRY.len() > 20,
            "`dto::request_list!` is down to {} entries. Everything below is generated from \
             it, so a truncated list would quietly generate a truncated index and guard C \
             would exercise only what is left.",
            REGISTRY.len()
        );

        let generated = generated_request_index();

        if std::env::var_os("UPDATE_TYPESCRIPT_PINS").is_some() {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/types.d.ts");
            let on_disk = std::fs::read_to_string(path).expect("types.d.ts is readable");
            let opens = format!("{INDEX_BEGIN}\n");
            let at = on_disk
                .find(&opens)
                .expect("types.d.ts has no `<generated: request index>` marker")
                + opens.len();
            let len = on_disk[at..]
                .find(INDEX_END)
                .expect("the generated request index in types.d.ts is never closed");
            let rewritten = format!("{}{generated}{}", &on_disk[..at], &on_disk[at + len..]);
            std::fs::write(path, rewritten).expect("types.d.ts is writable");
        }

        let checked_in = checked_in_request_index();
        if checked_in == generated {
            return;
        }

        // Reported line by line rather than with `assert_eq!`: the block is two
        // dozen lines, and printing both copies whole leaves a reader to find
        // the one byte that moved by eye — which is how a two-space edit got
        // past review in the first place.
        let at = generated
            .lines()
            .zip(checked_in.lines())
            .position(|(want, got)| want != got);
        let difference = match at {
            Some(n) => format!(
                "First difference, line {} of the block:\n  generated:  {:?}\n  \
                 checked in: {:?}",
                n + 1,
                generated.lines().nth(n).unwrap_or_default(),
                checked_in.lines().nth(n).unwrap_or_default(),
            ),
            None => format!(
                "Every shared line agrees, so lines were added or removed at the end: \
                 {} generated, {} checked in.",
                generated.lines().count(),
                checked_in.lines().count(),
            ),
        };
        panic!(
            "the generated request index in crates/verus-wasm/src/types.d.ts is not what \
             `dto::request_list!` produces.\n\n{difference}\n\nThat block is generated, \
             not written. Run:\n\n    UPDATE_TYPESCRIPT_PINS=1 cargo test -p verus-wasm \
             --all-features the_request_index_is_generated_from_the_registry\n\nand read \
             the diff. If the diff is not the change you meant to make, the edit to \
             `dto::request_list!` is the bug, not the file."
        );
    }

    /// The generated block has to actually contain what the comparison is for.
    ///
    /// This is not a demonstration that string equality works. It is that each
    /// of the patterns below really occurs in what the generator emits, so the
    /// byte comparison above is comparing something: `String::replace` on a
    /// pattern that does not occur returns the original, and every case here
    /// would then fail. A generator reduced to emitting an empty block cannot
    /// make that comparison vacuously true and still pass this.
    ///
    /// The cases are the edits a hand would make to the block — including the
    /// two spaces after `interface` that made a declaration invisible to the
    /// scan this replaced, and which are now simply bytes that differ.
    #[test]
    fn the_generated_index_comparison_can_detect_an_edit() {
        let generated = generated_request_index();
        assert!(generated.contains("    SendRequest: SendRequest;\n"));
        assert_eq!(checked_in_request_index(), generated);

        for edited in [
            generated.replace(
                "export interface Requests {\n",
                "export interface Requests {\n    QuietRequest: QuietRequest;\n",
            ),
            generated.replace("    SendRequest: SendRequest;\n", ""),
            generated.replace("export interface Requests", "export interface  Requests"),
            generated.replace(
                "    SendRequest: SendRequest;",
                "    SendRequest?: SendRequest;",
            ),
        ] {
            assert_ne!(edited, generated, "an edit that must not compare equal did");
        }
    }

    /// The guard on the other three guards: every request DTO's interface has
    /// to be covered by `every_field_of_every_dto_is_declared`, by
    /// `every_shape_matches_the_type_it_guards`, *and* by tsc — or it can drift
    /// in all three at once and nothing here would know, which is exactly what
    /// happened to `PlanSendTokenFromIdentityRequest` (and, undetected until
    /// this test existed, `LoginRequest`, `PlanConvertFromIdentityRequest`,
    /// `OfferTermsRequest`, `PendingRequest`, and `SignRequest`).
    ///
    /// # Why there are three of them
    ///
    /// They do not ask the same question. Each is a different way for the
    /// published package to lie to a caller, and no one of them implies the
    /// others:
    ///
    /// * **A, the fields are declared.** What the Rust type serializes is
    ///   exactly what its `export interface` declares. Without it a field can
    ///   drift from the interface, and the `.d.ts` a caller programs against
    ///   describes a different object than the one they receive.
    /// * **B, the shape guards them.** The runtime key list `dto::from_js`
    ///   rebuilds a caller's object against lists exactly those fields. Without
    ///   it an unknown key sent for that request would be silently accepted, or
    ///   a legitimate one silently refused — the `expiryHieght` bug.
    /// * **C, tsc exercises the published type.** A value of the interface is
    ///   actually type-checked against the shipped `.d.ts`. Without it a field
    ///   can be mistyped — a `string` declared as a `number` — in the
    ///   declaration itself, which neither A nor B can see: both compare field
    ///   *names*, and never the types beside them.
    ///
    /// # What this reads, and what it no longer reads
    ///
    /// It no longer reads any guard's source text. It used to: it scanned this
    /// file and `types.check.ts` for `assert_declared("Foo"`, `check::<Foo>` and
    /// `: Foo`, with a hand-written tokenizer per language so that prose could
    /// not count as a registration. Five adversarial review rounds each found a
    /// way to delete a real registration and leave the scan green — a block
    /// comment whose continuation lines start with code, a trailing `//`, a Rust
    /// lifetime, a raw string, a nested template substitution — and the fifth
    /// was opened by the fix for the fourth. A guard that reports coverage it
    /// does not have is worse than no guard, so the scanning is gone (#191).
    ///
    /// In its place, and following the same principle as
    /// `every_decoded_output_variant_is_declared_and_reachable` and its
    /// siblings — derive the covered set from a source of truth rather than
    /// hand-listing it:
    ///
    /// * guards A and B are *driven* by `REGISTRY`, generated from
    ///   `dto::request_list!`. That is also where the `Request` impls come from,
    ///   and `dto::from_js` takes `T: Request`, so a request type missing from
    ///   the list cannot be read from JavaScript at all — a compile error at its
    ///   call site, before any test runs;
    /// * guard C is answered by tsc. `types.d.ts` publishes a `Requests` index
    ///   and `tests/node/requests.exercised.ts` declares a value of a mapped
    ///   type over it which strips every modifier that would let something go
    ///   unchecked — `-?` on the index, so no request can be skipped; `-?` and
    ///   `NonNullable` on each request's own fields, so no field can be omitted
    ///   or satisfied with `null` — and which tsc then requires to be total and
    ///   type-checks field by field. This test's share of that is the index
    ///   itself, because tsc's obligation is only ever as complete as
    ///   `Requests`: a member pointing at another interface has tsc checking
    ///   some other type, and a member declared *optional* has it checking
    ///   nothing — `Requests["Foo"]` becomes `Foo | undefined`, whose `keyof`
    ///   is `never`, so the demanded value is a value of `{}`. That index is not
    ///   read for the answer either: it is *generated* from `REGISTRY` and
    ///   compared to `types.d.ts` as one string, in
    ///   `the_request_index_is_generated_from_the_registry`. And CI compiles
    ///   the file because `tests/node/tsconfig.json` includes every `.ts` file
    ///   beside it — no list of file names exists to fall behind. What that
    ///   file *demands* is held down the same way as the index: it is generated
    ///   from `REGISTRY` and compared to what is checked in, whole, in
    ///   `guard_c_exercises_every_registered_request`, because emptying the file
    ///   was as easy as deleting it and a great deal quieter — as were
    ///   `// @ts-nocheck`, `// @ts-ignore` and `} as any;`, none of which a
    ///   comparison over the whole file can be talked past. The project that
    ///   compiles it is generated and compared too, in
    ///   `guard_c_is_compiled_by_a_generated_project`, so "is guard C in the
    ///   build?" is not answered by an unread file.
    ///
    /// So the question "which requests are there?" has exactly one answer in
    /// this crate, and `types.d.ts` is checked against it rather than read for
    /// it. The earlier version of this test read the answer out of that file by
    /// searching it for `export interface `, and that search disagreed with tsc
    /// about the very syntax it was searching: `export interface  QuietRequest`,
    /// with two spaces, is a published request to every caller and invisible to
    /// the search. Coverage that a scan cannot see is coverage that is quietly
    /// absent, which is the failure this whole design refuses (#191).
    ///
    /// What this test still reads out of `types.d.ts` is the `Requests` index,
    /// by name, and it reads it for a second reason: `declared_members` is the
    /// parser the pinned declarations hold tsc against, so comparing its
    /// reading of that index to `REGISTRY` chains the registry to what tsc
    /// itself sees. The byte comparison says the file's text is what the
    /// registry generated; this says the parser behind guards A and B agrees.
    ///
    /// Reading it is still a parse, and a parse can still be wrong: a member on
    /// the continuation line of a `/* … */` block is a declaration to the line
    /// parser and a deletion to tsc, which would let a field drop out of an
    /// interface with everything here still green. So the parse is not trusted
    /// on its own either. Every member `declared_members` reads out of that
    /// file, and the type it reads beside it, is written into
    /// `tests/node/declarations.pinned.ts` and compiled by tsc, which reads the
    /// same file for real — see
    /// `every_declaration_this_file_reads_is_pinned_for_tsc`.
    #[test]
    fn every_request_is_registered_in_all_three_guards() {
        // The set all three guards are supposed to track without missing one.
        // It comes from `dto::request_list!` — the list that also generates the
        // `Request` impls `from_js` requires — and not from searching
        // `types.d.ts`, which is the direction that could lose a request
        // silently.
        let registered: BTreeSet<String> = REGISTRY
            .iter()
            .map(|entry| entry.interface.to_string())
            .collect();
        // A truncated or emptied registry would make every comparison below
        // vacuous, so its size is asserted before anything is compared to it.
        assert!(
            REGISTRY.len() > 20,
            "`dto::request_list!` is down to {} entries; everything below is compared \
             against it, so a truncated list would pass over almost nothing",
            REGISTRY.len()
        );
        assert_eq!(
            registered.len(),
            REGISTRY.len(),
            "two entries in `dto::request_list!` name the same interface, so one request \
             DTO is registered under another's name and is guarded by nothing"
        );

        // Guard C. tsc's obligation in `requests.exercised.ts` is `keyof
        // Requests`, so `Requests` has to be that same set — and each member
        // has to point at its own interface, or the value tsc checks is a
        // value of some other type.
        let index = declared_members("Requests");
        assert_eq!(
            index.keys().cloned().collect::<BTreeSet<String>>(),
            registered,
            "the `Requests` index in types.d.ts is not the set of registered request \
             DTOs, so the total map in tests/node/requests.exercised.ts does not make tsc \
             exercise them all — a field could be mistyped (string vs. number) in the \
             .d.ts and nothing would fail. That index is generated from \
             `dto::request_list!`: re-run with UPDATE_TYPESCRIPT_PINS=1 rather than \
             editing it"
        );
        for (name, member) in &index {
            let declared_as = &member.declared_as;
            assert_eq!(
                name, declared_as,
                "`Requests.{name}` is declared as `{declared_as}`, so the use-site tsc \
                 checks for {name} is really checking {declared_as}"
            );
            assert!(
                !member.optional,
                "`Requests.{name}` is declared optional, which empties out guard C for \
                 {name} without emptying out anything visible. `Requests[\"{name}\"]` is \
                 then `{name} | undefined`, so the mapped type in \
                 tests/node/requests.exercised.ts maps over `keyof ({name} | undefined)` — \
                 which is `never`. Its `-?` still makes tsc demand the key, and tsc then \
                 type-checks nothing whatsoever inside it. Members of this index are an \
                 obligation, never a suggestion."
            );
        }

        // And the registrations themselves. They also run inside their own
        // tests; running them here means a registration cannot be present in
        // the list and inert, which is the shape the old scan could be fooled
        // into reporting.
        for entry in REGISTRY {
            (entry.fields_match_interface)();
            (entry.shape_matches_type)();
        }
    }

    /// Both checks must be able to fail, or they prove nothing. The
    /// per-interface parse is the part worth demonstrating: the previous
    /// whole-file substring search passed the first of these.
    #[test]
    fn the_drift_checks_can_detect_drift() {
        // `satoshis` IS in the file — in `Utxo` and in `Recipient` — so a
        // whole-file search would find it. Asking `Outpoint` for it must not.
        assert!(!declared_by("Outpoint").contains("satoshis"));
        assert_eq!(
            declared_by("Outpoint"),
            ["txid", "vout"]
                .iter()
                .map(|s| s.to_string())
                .collect::<BTreeSet<_>>()
        );
        // A nested object inside an interface must not leak its keys upward:
        // `tokens: TokenAmount[]` must not contribute TokenAmount's fields.
        assert!(!declared_by("DecodedReserveOutput").contains("currency"));
        // A name that is a prefix of another declared name must resolve to
        // itself. `DecodedPubKey` sits inside `DecodedPubKeyHash`, and the
        // latter is declared first, so a parser that takes the first textual
        // match reads the wrong block entirely.
        assert!(declared_by("DecodedPubKey").contains("address"));
        assert_eq!(declared_by("DecodedPubKey").len(), 2);
        // And a generic header is found at all.
        assert!(declared_by("PlanStepReady").contains("value"));
        // The asking arm must NOT declare one, or narrowing gives a caller a
        // `value` on a round that has none.
        assert!(!declared_by("PlanStepAsk").contains("value"));
        // And the union parse must find members rather than silently nothing,
        // which would make the equality above pass against an empty set.
        assert!(union_members("DecodedOutput").contains("DecodedPubKeyHash"));

        // The parser also yields each member's declared *type*, which is what
        // lets the meta-guard check that `Requests.SendRequest` points at
        // `SendRequest` rather than at some other interface. It has to come
        // back whole, and without the trailing semicolon.
        let outpoint = declared_members("Outpoint");
        let txid = outpoint.get("txid").expect("Outpoint declares txid");
        assert_eq!(txid.declared_as, "string");
        assert_eq!(
            declared_members("PendingRequest")
                .get("pending")
                .map(|member| member.declared_as.as_str()),
            Some("Pending")
        );
        // And it reports the `?`, which is the other half of the meta-guard's
        // reading of the `Requests` index: a mapped type over an index inherits
        // its members' modifiers, so an optional member there is a request tsc
        // can be excused from. An optional member still keeps its name without
        // the `?` and still reports its type — an index made of optionals must
        // not read as empty — but it must not read as required either.
        let history = declared_members("HistoryRequest");
        let start = history
            .get("startHeight")
            .expect("HistoryRequest declares startHeight");
        assert_eq!(start.declared_as, "number");
        assert!(start.optional);
        assert!(!txid.optional);
        assert!(
            !history
                .get("addresses")
                .expect("HistoryRequest declares addresses")
                .optional
        );
        // And prose contributes nothing: the multi-line doc comment above
        // `startHeight` must not become a member of its own.
        assert_eq!(history.len(), 3);
    }
}
