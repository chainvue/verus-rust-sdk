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
    /// TypeScript `MnemonicCheck`.
    #[wasm_bindgen(typescript_type = "MnemonicCheck")]
    pub type MnemonicCheckValue;
    /// TypeScript `PlanSendRequest`.
    #[wasm_bindgen(typescript_type = "PlanSendRequest")]
    pub type PlanSendRequestValue;
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
    /// TypeScript `SendStep`.
    #[wasm_bindgen(typescript_type = "SendStep")]
    pub type SendStepValue;
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
    use serde::Serialize;
    use std::collections::BTreeSet;

    /// Every JSON field name a value serializes to.
    fn field_names<T: Serialize>(value: &T) -> BTreeSet<String> {
        let json = serde_json::to_value(value).expect("serializes");
        json.as_object()
            .expect("a DTO is an object")
            .keys()
            .cloned()
            .collect()
    }

    /// The field names declared by one `export interface` block.
    ///
    /// A deliberately small parser: it finds the named block, then takes the
    /// identifier before each `:` at the block's own brace depth. Anything
    /// more would be a TypeScript parser, and anything less — searching the
    /// whole file for `"name:"` — is what let a deleted field pass.
    fn declared_by(interface: &str) -> BTreeSet<String> {
        // `PlanStep<T>` is generic, so a header is the name followed by either
        // a space or a type-parameter list — not simply `name {`.
        //
        // The name must still match *whole*: `DecodedPubKey` occurs inside
        // `DecodedPubKeyHash`, and both are declared here. So every occurrence
        // is scanned and the first one whose next character ends the name wins.
        // (The previous parser got this right by accident, by requiring a
        // literal `" {"`; making room for generics lost that, and this test
        // caught it.)
        let header = format!("export interface {interface}");
        let at = TYPESCRIPT
            .match_indices(&header)
            .map(|(at, _)| at)
            .find(|at| {
                let next = TYPESCRIPT[at + header.len()..].chars().next();
                matches!(next, Some('<') | Some(' '))
            })
            .unwrap_or_else(|| panic!("types.d.ts declares no interface {interface}"));
        let after = &TYPESCRIPT[at + header.len()..];
        let brace = after
            .find('{')
            .unwrap_or_else(|| panic!("interface {interface} has no body"));
        let start = at + header.len() + brace + 1;
        let body = &TYPESCRIPT[start..];

        let mut fields = BTreeSet::new();
        let mut depth = 0i32;
        for line in body.lines() {
            let line = line.trim();
            if line.starts_with('*') || line.starts_with("/*") || line.starts_with("//") {
                continue;
            }
            if depth == 0 && line.starts_with('}') {
                break;
            }
            if let Some((name, _)) = line.split_once(':') {
                let name = name.trim().trim_end_matches('?');
                if depth == 0
                    && !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
                {
                    fields.insert(name.to_string());
                }
            }
            depth += i32::try_from(line.matches('{').count()).expect("short line");
            depth -= i32::try_from(line.matches('}').count()).expect("short line");
        }
        fields
    }

    /// The interface names a `export type X = A | B | …;` union lists.
    ///
    /// A variant interface that exists but is not a member of the union is
    /// unreachable: `decodeOutput` returns the union, so a caller can never
    /// narrow to it.
    fn union_members(name: &str) -> BTreeSet<String> {
        let header = format!("export type {name} =");
        let start = TYPESCRIPT
            .find(&header)
            .unwrap_or_else(|| panic!("types.d.ts declares no type {name}"))
            + header.len();
        let len = TYPESCRIPT[start..]
            .find(';')
            .expect("a union declaration ends in a semicolon");
        TYPESCRIPT[start..start + len]
            .split('|')
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

    /// The drift check. A field added to, renamed in, or removed from a DTO
    /// fails here until its interface catches up — and because it compares the
    /// two *sets*, a field declared in TypeScript that no longer exists in
    /// Rust fails too.
    #[test]
    fn every_field_of_every_dto_is_declared() {
        use crate::decode::TokenAmount;
        use crate::dto::{JsOutpoint, JsRecipient, JsSignedTransaction, JsUtxo};
        use crate::flows::{
            ContentRequest, HistoryRequest, JsContentValue, JsFunding, JsHistoryEntry, JsLoggedIn,
            JsPlannedTransaction, LoginRequest, PlanSendRequest, PlanStep, SpendableRequest,
            VerifyLoginRequest,
        };
        use crate::login::{SignRequest, VerifyRequest, VerifyResult};
        use crate::send::{JsTokenRecipient, SendRequest, TokenSendRequest};

        assert_declared("Utxo", &JsUtxo::default());
        assert_declared("Recipient", &JsRecipient::default());
        assert_declared("TokenRecipient", &JsTokenRecipient::default());
        assert_declared("SendRequest", &SendRequest::default());
        assert_declared("TokenSendRequest", &TokenSendRequest::default());
        assert_declared("Outpoint", &JsOutpoint::default());
        assert_declared("SignedTransaction", &JsSignedTransaction::default());
        assert_declared("SignRequest", &SignRequest::default());
        assert_declared("VerifyRequest", &VerifyRequest::default());
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
        assert_declared(
            "PlanStep",
            &PlanStep {
                value: Some(String::new()),
                ..PlanStep::<String>::default()
            },
        );
        assert_declared("PlanSendRequest", &PlanSendRequest::default());
        assert_declared("PlannedTransaction", &JsPlannedTransaction::default());
        assert_declared(
            "HistoryRequest",
            &HistoryRequest {
                start_height: Some(0),
                end_height: Some(0),
                ..HistoryRequest::default()
            },
        );
        assert_declared("HistoryEntry", &JsHistoryEntry::default());
        assert_declared("LoginRequest", &LoginRequest::default());
        assert_declared(
            "VerifyLoginRequest",
            &VerifyLoginRequest {
                max_age_blocks: Some(0),
                max_future_blocks: Some(0),
                ..VerifyLoginRequest::default()
            },
        );
        assert_declared("LoggedIn", &JsLoggedIn::default());
        assert_declared("SpendableRequest", &SpendableRequest::default());
        assert_declared("Funding", &JsFunding::default());
        assert_declared("ContentRequest", &ContentRequest::default());
        assert_declared(
            "ContentValue",
            &JsContentValue {
                hex: Some(String::new()),
                structured: Some(serde_json::Value::Null),
            },
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
        use crate::dto::{JsRecipient, JsUtxo, Shape};
        use crate::flows::{
            ContentRequest, HistoryRequest, LoginRequest, PlanSendRequest, SpendableRequest,
            VerifyLoginRequest,
        };
        use crate::login::{SignRequest, VerifyRequest};
        use crate::send::{JsTokenRecipient, SendRequest, TokenSendRequest};

        fn check<T: Serialize + Default>(name: &str, shape: &Shape) {
            let declared: BTreeSet<String> = shape
                .fields
                .iter()
                .map(|(field, _)| (*field).to_string())
                .collect();
            assert_eq!(
                declared,
                field_names(&T::default()),
                "{name} does not match what the Rust type serializes"
            );
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

        check::<SendRequest>("SendRequest", &SendRequest::SHAPE);
        check::<TokenSendRequest>("TokenSendRequest", &TokenSendRequest::SHAPE);
        check::<SignRequest>("SignRequest", &SignRequest::SHAPE);
        check::<VerifyRequest>("VerifyRequest", &VerifyRequest::SHAPE);
        check::<PlanSendRequest>("PlanSendRequest", &PlanSendRequest::SHAPE);
        check::<HistoryRequest>("HistoryRequest", &HistoryRequest::SHAPE);
        check::<LoginRequest>("LoginRequest", &LoginRequest::SHAPE);
        check::<VerifyLoginRequest>("VerifyLoginRequest", &VerifyLoginRequest::SHAPE);
        check::<SpendableRequest>("SpendableRequest", &SpendableRequest::SHAPE);
        check::<ContentRequest>("ContentRequest", &ContentRequest::SHAPE);

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
        assert!(declared_by("PlanStep").contains("value"));
        // And the union parse must find members rather than silently nothing,
        // which would make the equality above pass against an empty set.
        assert!(union_members("DecodedOutput").contains("DecodedPubKeyHash"));
    }
}
