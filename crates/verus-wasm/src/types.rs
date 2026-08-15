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

        assert_only_modeled_constructs(THIS_FILE, Lang::Rust, "types.rs");
        assert_only_modeled_constructs(TYPES_CHECK, Lang::TypeScript, "types.check.ts");

        // Guard A needs the name literals; guards B and C must not see them.
        let code_with_literals = strip_comments(THIS_FILE, Lang::Rust, Strings::Keep);
        let code = strip_comments(THIS_FILE, Lang::Rust, Strings::Blank);
        let types_check = strip_comments(TYPES_CHECK, Lang::TypeScript, Strings::Blank);

        // Guard A: the interface name literal passed to `assert_declared`.
        // The literal has to be the *first* argument: the union tests call
        // `assert_declared(side_interface(side), side)` with no literal at
        // all, and an unbounded search for the next quote there walks into a
        // later statement and harvests a phantom entry from it.
        let guard_a: BTreeSet<String> = code_with_literals
            .match_indices("assert_declared(")
            .filter_map(|(at, m)| {
                let after = code_with_literals[at + m.len()..].trim_start();
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

    // Comments name these forms in prose — including the comments
    // describing this very guard — so a raw-text scan counts a comment as
    // a registration and the guard goes blind for that type. Every scan
    // below therefore reads a comment-blanked copy, of `types.check.ts`
    // as much as of this file.
    //
    // This replaces a line-based stripper that blanked a line only when
    // its first non-space characters were `//`, `/*` or `*`. Two shapes
    // walked straight through it, and both are how a person actually
    // disables code:
    //
    //     /* disabled for now:
    //     check::<OffersRequest>("OffersRequest", &OffersRequest::SHAPE);
    //     */
    //
    //     const browse = { … }; // was typed: OffersRequest
    //
    // The middle line of the block starts with `check`, and the trailing
    // comment is not at the start of its line, so both survived blanking
    // and satisfied a guard whose real registration was gone. Patching
    // each shape as it is found loses to the next one, so this is a real
    // (if small) scanner instead: it tracks whether it is inside a block
    // comment, honours `//` anywhere on a line, and skips string literals
    // so a `"//"` in a literal is not mistaken for a comment. Both
    // languages here have all three constructs, which is why one scanner
    // serves both files.
    //
    // Line count is preserved so failures stay easy to locate.
    /// Which language's comment and literal rules to apply.
    ///
    /// One scanner served both files at first, and it mis-modelled each of
    /// them: Rust nests block comments and TypeScript does not, `'` is a char
    /// literal or a lifetime in Rust and a string delimiter in TypeScript, and
    /// only TypeScript has template literals. Every one of those differences
    /// was a way to hide a deleted registration behind prose, so the scanner
    /// is told which language it is reading.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Lang {
        Rust,
        TypeScript,
    }

    /// Whether string *contents* survive stripping.
    ///
    /// Only guard A needs them: it reads the interface-name literal passed to
    /// `assert_declared`. Guards B and C look for `check::<T>` and `: Name` in
    /// code, and a string that happens to contain either — an assert message
    /// describing the guard, say, of which this file has several — is prose,
    /// not a registration. Keeping strings for those two is how a deleted
    /// registration could hide inside the very message explaining it.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Strings {
        Keep,
        Blank,
    }

    /// Byte length of the Rust char literal starting at `s`, if it is one.
    ///
    /// `s[0]` is `'`. Returns `None` for a lifetime, which is the same byte
    /// followed by an identifier and no closing quote. Both readings are in
    /// `types.rs`: `'"'` in the guard-A scan is a char literal holding a
    /// quote, and `&'static str` is a lifetime. Treating a lifetime as a
    /// string opener leaves a trailing `//` on that line unstripped, which is
    /// a bypass; treating `'"'` as one swallows the rest of the line.
    fn char_literal_len(s: &[u8]) -> Option<usize> {
        if s.len() < 3 {
            return None;
        }
        if s[1] == b'\\' {
            // An escape: `'\n'`, `'\\'`, `'\''`. Bounded so a stray backslash
            // cannot run to a quote far down the line.
            let close = s[2..].iter().take(12).position(|&c| c == b'\'')?;
            return Some(2 + close + 1);
        }
        // One character, possibly multi-byte, then the closing quote.
        let width = match s[1] {
            0x00..=0x7f => 1,
            0xc0..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf7 => 4,
            _ => return None,
        };
        (s.len() > 1 + width && s[1 + width] == b'\'').then_some(width + 2)
    }

    /// Refuse to scan a file containing a construct the scanner does not model.
    ///
    /// The scanner handles line and block comments (nested, for Rust), string
    /// literals, Rust char literals and lifetimes, and TypeScript template
    /// literals. Three things it does **not** model would each let prose scan
    /// as code — the precise failure this guard exists to catch:
    ///
    ///   - Rust raw strings (`r"…"`, `r#"…"#`), where `\` is not an escape and
    ///     the closing quote is not the first `"`;
    ///   - TypeScript regex literals, whose `'` and `/` are not delimiters;
    ///   - nested template literals, where an inner backtick would close the
    ///     outer one.
    ///
    /// None appear in either file today, so rather than model three unused
    /// constructs — and get them subtly wrong, which is how this guard has
    /// failed twice already — this fails loudly the day one is introduced. The
    /// guard going *blind* is the outcome that must never happen quietly; a
    /// build error telling someone to extend the scanner is fine.
    fn assert_only_modeled_constructs(source: &str, lang: Lang, file: &str) {
        // Every check below reads a *stripped* copy, never the raw source.
        // The first version of this read the raw text and promptly fired on
        // the `r#` in its own failure message — the same "prose satisfies the
        // scan" bug the whole guard exists to catch, one level up.
        let code = strip_comments(source, lang, Strings::Blank);
        let bytes = code.as_bytes();
        match lang {
            Lang::Rust => {
                // `r"`/`r#`/`br"`/`br#`, but only where `r` starts a token —
                // otherwise the `r"` ending a word like `…ReserveTransfer"`
                // matches.
                let raw = (0..bytes.len()).any(|i| {
                    let starts_token =
                        i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
                    if !starts_token {
                        return false;
                    }
                    let rest = &bytes[i..];
                    let rest = rest.strip_prefix(b"b").unwrap_or(rest);
                    rest.starts_with(b"r\"") || rest.starts_with(b"r#")
                });
                assert!(
                    !raw,
                    "{file} has gained a raw string literal, which strip_comments does not \
                     model: `\\` is not an escape there and the closing quote is not the \
                     first one, so its contents would scan as code and prose inside it \
                     would satisfy a guard. Teach the scanner the `r`/`r#` prefixes, or \
                     move the literal out of this file."
                );
            }
            Lang::TypeScript => {
                // Comments stripped but string contents kept, so an inner
                // backtick inside `${…}` is still visible.
                let with_literals = strip_comments(source, lang, Strings::Keep);
                // Refuse any quote or backtick inside an interpolation.
                //
                // Deliberately crude, after four attempts at being precise
                // were each evaded — the last one *by the fix for the one
                // before it*. The pattern every time: this detector and
                // `strip_comments` tokenised `${…}` differently, and the
                // disagreement was the hole. Teaching this scanner about
                // strings (round 4) immediately opened round 5, because
                // `strip_comments` closes a template at the first backtick it
                // sees — including one inside a string inside `${…}` — and it
                // structurally cannot do otherwise, since it never re-enters
                // code at `${`.
                //
                // So there is nothing to agree about any more. A quote or a
                // backtick inside an interpolation is refused outright, which
                // also makes the brace count unambiguous: a `}` can no longer
                // hide inside a string, because the string is refused first.
                //
                // The cost is real and bounded: an interpolation needing a
                // quoted string has to be restructured. The three in
                // `types.check.ts` today (`describe()`) contain neither.
                //
                // This is a holding position, not a design. See #191.
                let nested = with_literals.match_indices("${").any(|(at, _)| {
                    let mut depth = 1usize;
                    for c in with_literals[at + 2..].chars() {
                        match c {
                            '`' | '"' | '\'' => return true,
                            '{' => depth += 1,
                            '}' => {
                                depth -= 1;
                                if depth == 0 {
                                    return false;
                                }
                            }
                            _ => {}
                        }
                    }
                    // Unbalanced: refuse rather than guess.
                    true
                });
                assert!(
                    !nested,
                    "{file} has gained a nested template literal, which strip_comments does \
                     not model: the inner backtick closes the outer template, so everything \
                     after it scans as code. Teach the scanner `${{`/`}}` nesting, or split \
                     the literal."
                );
                // A regex literal's `/` and `'` are not delimiters. Detecting
                // one properly needs real parsing, so this refuses the shape
                // outright: after stripping, no bare `/` should remain in code.
                let stray = code.match_indices('/').next();
                assert!(
                    stray.is_none(),
                    "{file} has a `/` left in code after comment stripping, at byte {:?}. \
                     That is either a regex literal — whose `/` and `'` are not delimiters, \
                     so its contents would scan as code — or a comment shape the scanner \
                     mis-parsed. Either way the guard cannot be trusted until it is modelled.",
                    stray.map(|(at, _)| at)
                );
            }
        }
    }

    /// Blank every comment, leaving code and string contents in place.
    ///
    /// The guards below scan text, so anything they match inside a comment is
    /// prose being counted as a registration — which is the whole failure
    /// #169 was filed for, and which a line-based stripper kept re-opening:
    /// a block comment whose continuation lines start with code, a trailing
    /// `//` after real code, a lifetime, a template literal. Each was patched
    /// in turn and the next one appeared, so this models the two languages
    /// properly instead.
    ///
    /// Byte-wise on purpose. Every delimiter is ASCII, and non-ASCII bytes are
    /// either copied through untouched or replaced whole, so the output stays
    /// valid UTF-8 — but slicing `&str` by byte index panicked the moment a
    /// comment held an em dash, and this file is full of them.
    ///
    /// String **contents are kept**: guard A reads the name literals passed to
    /// `assert_declared`. So a scanned form planted inside a real string still
    /// counts as a registration. That is inherent to a text-scan guard and is
    /// adversarial rather than accidental — unlike a comment, which is how
    /// people actually disable code.
    ///
    /// Line count is preserved so failures stay locatable.
    fn strip_comments(source: &str, lang: Lang, strings: Strings) -> String {
        let src = source.as_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(src.len());
        // Rust nests block comments; TypeScript closes at the first `*/`.
        let mut block_depth: usize = 0;
        let mut in_string: Option<u8> = None;
        let mut i = 0;
        while i < src.len() {
            let b = src[i];
            if block_depth > 0 {
                if src[i..].starts_with(b"*/") {
                    block_depth -= 1;
                    out.extend_from_slice(b"  ");
                    i += 2;
                } else if lang == Lang::Rust && src[i..].starts_with(b"/*") {
                    block_depth += 1;
                    out.extend_from_slice(b"  ");
                    i += 2;
                } else {
                    // Keep newlines so line numbering survives.
                    out.push(if b == b'\n' { b'\n' } else { b' ' });
                    i += 1;
                }
                continue;
            }
            match in_string {
                // Deliberately no reset at a newline. A Rust string and a
                // TypeScript template literal both span lines, and resetting
                // made their continuation lines scan as code — so prose on the
                // second line of a wrapped assert message counted as a
                // registration. Valid source has balanced delimiters, which is
                // what makes running to the real closer safe.
                Some(quote) => {
                    let keep = strings == Strings::Keep;
                    if b == b'\\' && i + 1 < src.len() {
                        if keep {
                            out.extend_from_slice(&src[i..i + 2]);
                        } else {
                            out.extend_from_slice(b"  ");
                        }
                        i += 2;
                        continue;
                    }
                    // The delimiters themselves always survive, so guard A can
                    // still find where a literal starts.
                    if keep || b == quote || b == b'\n' {
                        out.push(b);
                    } else {
                        out.push(b' ');
                    }
                    if b == quote {
                        in_string = None;
                    }
                    i += 1;
                }
                None => {
                    if src[i..].starts_with(b"//") {
                        while i < src.len() && src[i] != b'\n' {
                            out.push(b' ');
                            i += 1;
                        }
                    } else if src[i..].starts_with(b"/*") {
                        block_depth = 1;
                        out.extend_from_slice(b"  ");
                        i += 2;
                    } else if lang == Lang::Rust && b == b'\'' {
                        match char_literal_len(&src[i..]) {
                            Some(len) => {
                                out.extend_from_slice(&src[i..i + len]);
                                i += len;
                            }
                            // A lifetime. Ordinary byte, opens nothing.
                            None => {
                                out.push(b);
                                i += 1;
                            }
                        }
                    } else {
                        let opens = match lang {
                            Lang::Rust => b == b'"',
                            // TypeScript has three, and a template literal is
                            // the one that spans lines.
                            Lang::TypeScript => matches!(b, b'"' | b'\'' | b'`'),
                        };
                        if opens {
                            in_string = Some(b);
                        }
                        out.push(b);
                        i += 1;
                    }
                }
            }
        }
        String::from_utf8(out).expect("only ASCII delimiters were substituted")
    }

    /// Shorthand for the tests below, which are all about Rust shapes unless
    /// they say otherwise.
    fn strip_comments_rust(source: &str) -> String {
        strip_comments(source, Lang::Rust, Strings::Keep)
    }

    /// The comment stripper the guard above depends on, tested directly.
    ///
    /// It is the whole basis of "the guard cannot be satisfied by prose", and
    /// the guard only exercises it against the two real files — which happen
    /// not to contain the shapes that once defeated it. These are those
    /// shapes, plus the two ways a scanner like this usually goes wrong:
    /// mistaking a `//` inside a string literal for a comment, and letting an
    /// escaped quote end the literal early.
    #[test]
    fn the_comment_stripper_removes_prose_and_keeps_code() {
        // Shadow the guard's private helper by re-declaring the same logic is
        // not possible here, so exercise it through the same path the guard
        // uses: a small source with each shape, asserted on the stripped text.
        let stripped = strip_comments_rust(concat!(
            "let a = 1; // check::<Ghost>(\"Ghost\")\n",
            "/* disabled:\n",
            "check::<Blocked>(\"Blocked\");\n",
            "*/\n",
            "let sep = \"//\"; let kept = 2;\n",
            "let esc = \"a\\\"// still a literal\"; let after = 3;\n",
            "check::<Real>(\"Real\");\n",
        ));

        assert!(
            !stripped.contains("Ghost"),
            "trailing // survived: {stripped}"
        );
        assert!(
            !stripped.contains("Blocked"),
            "block comment survived: {stripped}"
        );
        assert!(
            stripped.contains("check::<Real>"),
            "real code was eaten: {stripped}"
        );
        assert!(
            stripped.contains("let kept = 2;"),
            "a `//` inside a string literal was treated as a comment: {stripped}"
        );
        assert!(
            stripped.contains("let after = 3;"),
            "an escaped quote ended the literal early: {stripped}"
        );
        assert_eq!(
            stripped.lines().count(),
            7,
            "line numbering must survive so failures stay locatable"
        );
    }

    /// The scanner refuses what it cannot model, rather than going blind.
    ///
    /// Raw strings, regex literals and nested template literals each have
    /// delimiter rules the scanner does not implement, and in each case the
    /// consequence is prose scanning as code — a deleted registration staying
    /// green. None are in either file, so they are refused outright instead of
    /// modelled; these pin that the refusal actually fires.
    #[test]
    fn a_construct_the_scanner_cannot_model_is_refused() {
        let raw = std::panic::catch_unwind(|| {
            assert_only_modeled_constructs("let m = r#\"x\"#;\n", Lang::Rust, "f.rs");
        });
        assert!(raw.is_err(), "a raw string was accepted");

        // ...but an `r` that merely ends a word is not a raw string. This file
        // has `\"DecodedReserveTransfer\"`, which is why the check looks at
        // token starts.
        assert_only_modeled_constructs("let s = \"DecodedReserveTransfer\";\n", Lang::Rust, "f.rs");

        let nested = std::panic::catch_unwind(|| {
            assert_only_modeled_constructs("const t = `${`inner`}`;\n", Lang::TypeScript, "f.ts");
        });
        assert!(nested.is_err(), "a nested template literal was accepted");

        // A plain interpolation is fine, and this file has several.
        assert_only_modeled_constructs(
            "const t = `${o.address} holds`;\n",
            Lang::TypeScript,
            "f.ts",
        );

        // An interpolation may hold its own braces. Stopping at the *first*
        // `}` closed the window before the inner backtick, so this exact shape
        // read as modelled while its contents scanned as code.
        let braced = std::panic::catch_unwind(|| {
            assert_only_modeled_constructs(
                "const t = `${ {a:1}.a + `inner` }`;\n",
                Lang::TypeScript,
                "f.ts",
            );
        });
        assert!(
            braced.is_err(),
            "a nested template behind a brace was accepted"
        );

        // ...and behind a `}` inside a string, which defeated the brace count
        // because the counter tokenised differently from the stripper.
        for decoy in [
            "const t = `${ \"}\" + `x` }z`;\n",
            "const t = `${ '}' + `x` }z`;\n",
        ] {
            let quoted = std::panic::catch_unwind(move || {
                assert_only_modeled_constructs(decoy, Lang::TypeScript, "f.ts");
            });
            assert!(
                quoted.is_err(),
                "a nested template behind a quoted brace was accepted: {decoy}"
            );
        }

        // ...and one that merely contains braces is still fine.
        assert_only_modeled_constructs(
            "const t = `${ {a:1}.a } holds`;\n",
            Lang::TypeScript,
            "f.ts",
        );

        let regex = std::panic::catch_unwind(|| {
            assert_only_modeled_constructs("const m = s.split(/x/);\n", Lang::TypeScript, "f.ts");
        });
        assert!(regex.is_err(), "a regex literal was accepted");
    }

    /// The three shapes a single-language scanner got wrong, one per rule.
    ///
    /// Each was demonstrated live against the previous version: the guard
    /// stayed green with a real registration deleted. They are here as unit
    /// tests because the guard only ever scans the two real files, and those
    /// happen not to contain any of these.
    #[test]
    fn the_stripper_models_each_language_rather_than_guessing() {
        // Rust nests block comments — closing at the first `*/` left the
        // second half of the comment scanning as code.
        let stripped = strip_comments_rust("/* off /* note */\ncheck::<Ghost>(\"Ghost\");\n*/\n");
        assert!(
            !stripped.contains("Ghost"),
            "a nested block comment ended early: {stripped}"
        );

        // A Rust string spans lines. Resetting at the newline made the
        // continuation of a wrapped assert message scan as code.
        let stripped = strip_comments(
            "let m = \"first line \\\n     check::<Ghost>(\";\n",
            Lang::Rust,
            Strings::Blank,
        );
        assert!(
            !stripped.contains("check::<Ghost>("),
            "a continued string literal scanned as code: {stripped}"
        );

        // TypeScript does *not* nest, so the first `*/` really does close.
        let stripped = strip_comments(
            "/* off /* note */\nconst browse: OffersRequest = {};\n",
            Lang::TypeScript,
            Strings::Keep,
        );
        assert!(
            stripped.contains(": OffersRequest"),
            "TypeScript block comments must not nest: {stripped}"
        );

        // A template literal spans lines and can hold anything, including an
        // apostrophe that would otherwise open a phantom literal.
        let stripped = strip_comments(
            "const note = `it's fine\nstill inside`; const browse: OffersRequest = {};\n",
            Lang::TypeScript,
            Strings::Keep,
        );
        assert!(
            stripped.contains(": OffersRequest"),
            "a template literal swallowed the code after it: {stripped}"
        );
    }

    /// `'` means two different things in Rust and this file contains both.
    ///
    /// A lifetime that opened a literal would leave a trailing `//` on the
    /// same line unstripped — the bypass this stripper exists to close. A
    /// char literal holding a quote that did *not* open one would swallow the
    /// rest of the line instead, hiding real registrations. Both shapes are
    /// in `types.rs` already (`&'static str`, and `'\"'` in the guard-A scan),
    /// so neither is hypothetical.
    #[test]
    fn an_apostrophe_is_read_as_a_lifetime_or_a_char_literal_correctly() {
        // A lifetime must not start a literal, so the `//` after it is still
        // a comment.
        let stripped = strip_comments_rust("const T: &'static str = x; // check::<Ghost>\n");
        assert!(
            !stripped.contains("Ghost"),
            "a lifetime opened a phantom literal, so a trailing comment survived: {stripped}"
        );
        assert!(
            stripped.contains("&'static str"),
            "the lifetime itself was eaten: {stripped}"
        );

        // A char literal holding a quote must not start a string, or the rest
        // of the line disappears into it.
        let stripped = strip_comments_rust("let q = '\"'; check::<Real>(\"Real\");\n");
        assert!(
            stripped.contains("check::<Real>"),
            "a char literal holding a quote swallowed the code after it: {stripped}"
        );

        // And an escaped char literal must not either.
        let stripped = strip_comments_rust("let e = '\\''; check::<Also>(\"Also\");\n");
        assert!(
            stripped.contains("check::<Also>"),
            "an escaped char literal swallowed the code after it: {stripped}"
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
        assert!(declared_by("PlanStepReady").contains("value"));
        // The asking arm must NOT declare one, or narrowing gives a caller a
        // `value` on a round that has none.
        assert!(!declared_by("PlanStepAsk").contains("value"));
        // And the union parse must find members rather than silently nothing,
        // which would make the equality above pass against an empty set.
        assert!(union_members("DecodedOutput").contains("DecodedPubKeyHash"));
    }
}
