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
            ContentRequest, HistoryRequest, JsContentValue, JsCurrencyDefinition, JsFunding,
            JsHistoryEntry, JsLaunched, JsListing, JsLoggedIn, JsOfferTerms, JsPlannedTransaction,
            JsPlannedUpdate, JsPreallocation, JsTaken, LoginRequest, OfferTermsRequest,
            OffersRequest, PlanBurnRequest, PlanConvertFromIdentityRequest, PlanConvertRequest,
            PlanLaunchRequest, PlanMintRequest, PlanPublishRequest, PlanRegistrationRequest,
            PlanSendFromIdentityRequest, PlanSendRequest, PlanSendTokenFromIdentityRequest,
            PlanSendTokenRequest, PlanStep, SpendableRequest, TakeOfferRequest, VerifyLoginRequest,
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
        assert_declared("PlanSendRequest", &PlanSendRequest::default());
        assert_declared("PlanSendTokenRequest", &PlanSendTokenRequest::default());
        assert_declared(
            "PlanSendFromIdentityRequest",
            &PlanSendFromIdentityRequest::default(),
        );
        assert_declared(
            "PlanSendTokenFromIdentityRequest",
            &PlanSendTokenFromIdentityRequest::default(),
        );
        assert_declared("PlanPublishRequest", &PlanPublishRequest::default());
        assert_declared("PlannedTransaction", &JsPlannedTransaction::default());
        assert_declared("PlannedUpdate", &JsPlannedUpdate::default());
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
            "OffersRequest",
            &OffersRequest {
                with_offer_bytes: true,
                ..OffersRequest::default()
            },
        );
        assert_declared(
            "Listing",
            &JsListing {
                raw_offer: Some(String::new()),
                ..JsListing::default()
            },
        );
        assert_declared("OfferTermsRequest", &OfferTermsRequest::default());
        assert_declared("OfferTerms", &JsOfferTerms::default());
        assert_declared("TakeOfferRequest", &TakeOfferRequest::default());
        // Every optional populated: a `serde(default)` field is exactly the one
        // a drift check would otherwise never see.
        assert_declared(
            "PlanConvertFromIdentityRequest",
            &PlanConvertFromIdentityRequest {
                via: Some(String::new()),
                ..PlanConvertFromIdentityRequest::default()
            },
        );
        assert_declared(
            "PlanConvertRequest",
            &PlanConvertRequest {
                via: Some(String::new()),
                min_expected: Some(String::new()),
                ..PlanConvertRequest::default()
            },
        );
        assert_declared("PlanBurnRequest", &PlanBurnRequest::default());
        assert_declared("PlanMintRequest", &PlanMintRequest::default());
        assert_declared(
            "PlanRegistrationRequest",
            &PlanRegistrationRequest {
                min_sigs: Some(0),
                referral: Some(String::new()),
                pin_fee: Some(String::new()),
                salt: Some(String::new()),
                ..PlanRegistrationRequest::default()
            },
        );
        assert_declared("Pending", &crate::flows::JsPending::default());
        assert_declared("PendingRequest", &crate::flows::PendingRequest::default());
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
        assert_declared(
            "PlanLaunchRequest",
            &PlanLaunchRequest {
                pin_launch_fee: Some(String::new()),
                ..PlanLaunchRequest::default()
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
            ContentRequest, HistoryRequest, JsCurrencyDefinition, JsPreallocation, LoginRequest,
            OfferTermsRequest, OffersRequest, PlanBurnRequest, PlanConvertFromIdentityRequest,
            PlanConvertRequest, PlanLaunchRequest, PlanMintRequest, PlanPublishRequest,
            PlanRegistrationRequest, PlanSendFromIdentityRequest, PlanSendRequest,
            PlanSendTokenFromIdentityRequest, PlanSendTokenRequest, SpendableRequest,
            TakeOfferRequest, VerifyLoginRequest,
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
        check::<PlanSendTokenRequest>("PlanSendTokenRequest", &PlanSendTokenRequest::SHAPE);
        check::<PlanSendFromIdentityRequest>(
            "PlanSendFromIdentityRequest",
            &PlanSendFromIdentityRequest::SHAPE,
        );
        check::<PlanSendTokenFromIdentityRequest>(
            "PlanSendTokenFromIdentityRequest",
            &PlanSendTokenFromIdentityRequest::SHAPE,
        );
        check::<PlanPublishRequest>("PlanPublishRequest", &PlanPublishRequest::SHAPE);
        check::<OffersRequest>("OffersRequest", &OffersRequest::SHAPE);
        check::<OfferTermsRequest>("OfferTermsRequest", &OfferTermsRequest::SHAPE);
        check::<TakeOfferRequest>("TakeOfferRequest", &TakeOfferRequest::SHAPE);
        check::<PlanConvertRequest>("PlanConvertRequest", &PlanConvertRequest::SHAPE);
        check::<PlanConvertFromIdentityRequest>(
            "PlanConvertFromIdentityRequest",
            &PlanConvertFromIdentityRequest::SHAPE,
        );
        check::<PlanBurnRequest>("PlanBurnRequest", &PlanBurnRequest::SHAPE);
        check::<PlanMintRequest>("PlanMintRequest", &PlanMintRequest::SHAPE);
        check::<PlanRegistrationRequest>(
            "PlanRegistrationRequest",
            &PlanRegistrationRequest::SHAPE,
        );
        check::<crate::flows::PendingRequest>(
            "PendingRequest",
            &crate::flows::PendingRequest::SHAPE,
        );
        // The stored registration is an object like any other request object,
        // and the pointer has to be followed or it is not guarded at all.
        check::<crate::flows::JsPending>(
            "PendingRequest.pending",
            nested(&crate::flows::PendingRequest::SHAPE, "pending"),
        );
        check::<PlanLaunchRequest>("PlanLaunchRequest", &PlanLaunchRequest::SHAPE);
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

    /// Whether `haystack` annotates something with `name` — the
    /// `const foo: FooRequest = …` form `types.check.ts` standardises on —
    /// rather than merely mentioning the name somewhere.
    ///
    /// The annotation is what makes `tsc` actually check the type: a bare
    /// `type Foo,` import line compiles whatever the `.d.ts` happens to say,
    /// while an annotated const forces the object literal to be checked
    /// against the published interface.
    ///
    /// This does **not** itself discount a name that appears in a comment —
    /// the caller strips comments from the haystack first, which is what makes
    /// a commented-out use-site stop counting.
    ///
    /// The trailing boundary matters for the same reason `declared_by` needs
    /// it for interface headers: `TokenSendRequest` contains `SendRequest` as
    /// a literal substring, so a plain `.contains()` would call `SendRequest`
    /// present in a file that only ever names `TokenSendRequest`.
    fn has_annotated_use_site(haystack: &str, name: &str) -> bool {
        let is_word_char = |c: char| c.is_ascii_alphanumeric() || c == '_';
        let annotation = format!(": {name}");
        haystack.match_indices(&annotation).any(|(at, _)| {
            let after = haystack[at + annotation.len()..].chars().next();
            !after.is_some_and(is_word_char)
        })
    }

    /// The guard on the other three guards: every request DTO's interface has
    /// to be registered in `every_field_of_every_dto_is_declared`, checked in
    /// `every_shape_matches_the_type_it_guards`, *and* given a use-site in
    /// `types.check.ts` — or it can drift in all three at once and nothing
    /// here would know, which is exactly what happened to
    /// `PlanSendTokenFromIdentityRequest` (and, undetected until this test
    /// existed, `LoginRequest`, `PlanConvertFromIdentityRequest`,
    /// `OfferTermsRequest`, `PendingRequest`, and `SignRequest`).
    ///
    /// Follows the same shape as `every_decoded_output_variant_is_declared_and_reachable`
    /// and its siblings: the set that must be covered is derived from a
    /// source of truth (`types.d.ts`'s own `export interface *Request`
    /// declarations) rather than hand-listed, and what is *actually*
    /// registered is read from this file's own source and from
    /// `types.check.ts`'s, not from a fourth hand-maintained list that could
    /// itself drift from the other three.
    #[test]
    fn every_request_is_registered_in_all_three_guards() {
        // This file's own text, so the completeness check can find its
        // existing `assert_declared` and `check::<T>` calls directly.
        const THIS_FILE: &str = include_str!("types.rs");
        // The use-site test, so presence there is verified the same way.
        const TYPES_CHECK: &str = include_str!("../tests/node/types.check.ts");

        fn is_identifier(s: &str) -> bool {
            !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }

        // Every `export interface FooRequest` types.d.ts declares — the set
        // all three guards are supposed to track without missing one.
        let requests: BTreeSet<String> = TYPESCRIPT
            .match_indices("export interface ")
            .filter_map(|(at, m)| {
                let after = &TYPESCRIPT[at + m.len()..];
                let end = after.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))?;
                let name = &after[..end];
                name.ends_with("Request").then(|| name.to_string())
            })
            .collect();
        // A parser that quietly stopped matching would leave this empty and
        // every assertion below would vacuously pass — the same failure mode
        // `the_drift_checks_can_detect_drift` exists to rule out elsewhere.
        assert!(
            requests.len() > 20,
            "found suspiciously few `*Request` interfaces in types.d.ts; the scan above \
             likely stopped matching its syntax"
        );

        // Comments name these forms in prose — including the comments
        // describing this very guard — so a raw-text scan counts a comment as
        // a registration and the guard goes blind for that type. Every scan
        // below therefore reads a comment-blanked copy, and that applies to
        // `types.check.ts` as much as to this file: guard C was satisfiable by
        // a commented-out use-site for exactly the same reason.
        //
        // Line numbering is preserved so failures stay easy to locate.
        fn strip_comments(source: &str) -> String {
            source
                .lines()
                .map(|line| {
                    let t = line.trim_start();
                    if t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') {
                        ""
                    } else {
                        line
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        }

        let code = strip_comments(THIS_FILE);
        let types_check = strip_comments(TYPES_CHECK);

        // Blanking whole lines only helps if no *trailing* comment carries one
        // of these forms — `foo(); // check::<Bar>` would survive it and put
        // the original bug straight back. That holds today, and this is what
        // keeps it holding rather than leaving it to a code-review habit.
        assert!(
            !THIS_FILE.lines().any(|line| {
                let code_part = line.trim_start();
                !code_part.starts_with("//")
                    && line.split_once("//").is_some_and(|(_, tail)| {
                        tail.contains("check::<") || tail.contains("assert_declared(")
                    })
            }),
            "a trailing comment names one of the scanned call forms; whole-line \
             blanking leaves it in place and the guard would start counting prose \
             as a registration again — move it to its own line"
        );

        // Guard A: the interface name literal passed to `assert_declared`.
        // The literal has to be the *first* argument: the union tests call
        // `assert_declared(side_interface(side), side)` with no literal at
        // all, and an unbounded search for the next quote there walks into a
        // later statement and harvests a phantom entry from it.
        let guard_a: BTreeSet<String> = code
            .match_indices("assert_declared(")
            .filter_map(|(at, m)| {
                let after = code[at + m.len()..].trim_start();
                let rest = after.strip_prefix('"')?;
                let end = rest.find('"')?;
                let name = &rest[..end];
                is_identifier(name).then(|| name.to_string())
            })
            .collect();

        // Guard B: the type argument to `check::<T>`. Some call sites qualify
        // the type path, so only the last segment is kept.
        let guard_b: BTreeSet<String> = code
            .match_indices("check::<")
            .filter_map(|(at, m)| {
                let after = &code[at + m.len()..];
                let end = after.find('>')?;
                let raw = &after[..end];
                let name = raw.rsplit("::").next().unwrap_or(raw);
                is_identifier(name).then(|| name.to_string())
            })
            .collect();

        for name in &requests {
            assert!(
                guard_a.contains(name),
                "{name} is declared in types.d.ts but never passed to assert_declared \
                 in every_field_of_every_dto_is_declared — its fields can drift from the \
                 interface with nothing to catch it"
            );
            assert!(
                guard_b.contains(name),
                "{name} is declared in types.d.ts but never checked against a SHAPE \
                 in every_shape_matches_the_type_it_guards — an unknown key sent for it \
                 would be silently accepted or a legitimate one silently refused"
            );
            assert!(
                has_annotated_use_site(&types_check, name),
                "{name} is declared in types.d.ts but has no annotated use-site \
                 (`const … : {name} = …`) in types.check.ts, so tsc never exercises the \
                 published type — a field could be mistyped (string vs. number) in the \
                 .d.ts and nothing would fail. A bare `type {name},` import does not \
                 count: only the annotation makes tsc check anything."
            );
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
    }
}
