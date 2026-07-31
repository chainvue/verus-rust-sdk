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
//! serializes each DTO and asserts every field name it produces appears in the
//! file `types.d.ts`. Adding a field to a request struct fails that test until the
//! declaration catches up.

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
}

#[cfg(test)]
mod tests {
    use super::TYPESCRIPT_SOURCE as TYPESCRIPT;
    use serde::Serialize;

    /// Every JSON field name a value serializes to.
    fn field_names<T: Serialize>(value: &T) -> Vec<String> {
        let json = serde_json::to_value(value).expect("serializes");
        json.as_object()
            .expect("a DTO is an object")
            .keys()
            .cloned()
            .collect()
    }

    fn assert_declared<T: Serialize>(interface: &str, value: &T) {
        for field in field_names(value) {
            assert!(
                TYPESCRIPT.contains(&format!("{field}:"))
                    || TYPESCRIPT.contains(&format!("{field}?:")),
                "{interface}.{field} is not declared in the TypeScript section; \
                 the .d.ts a caller gets would not mention it"
            );
        }
    }

    /// The drift check. A field added to a request or response struct fails
    /// here until it is declared, so the published types cannot silently fall
    /// behind the bindings.
    #[test]
    fn every_field_of_every_dto_is_declared() {
        use crate::decode::{DecodedOutput, TokenAmount};
        use crate::dto::{JsOutpoint, JsRecipient, JsSignedTransaction, JsUtxo};
        use crate::login::{SignRequest, VerifyRequest, VerifyResult};
        use crate::send::{JsTokenRecipient, SendRequest, TokenSendRequest};

        assert_declared(
            "Utxo",
            &JsUtxo {
                txid: String::new(),
                vout: 0,
                satoshis: String::new(),
                script_pubkey: String::new(),
            },
        );
        assert_declared(
            "Recipient",
            &JsRecipient {
                address: String::new(),
                satoshis: String::new(),
            },
        );
        assert_declared(
            "TokenRecipient",
            &JsTokenRecipient {
                address: String::new(),
                currency: String::new(),
                amount: String::new(),
            },
        );
        assert_declared(
            "SendRequest",
            &SendRequest {
                utxos: Vec::new(),
                recipients: Vec::new(),
                change_address: String::new(),
                expiry_height: None,
                fee_per_kb: None,
            },
        );
        assert_declared(
            "TokenSendRequest",
            &TokenSendRequest {
                utxos: Vec::new(),
                recipients: Vec::new(),
                change_address: String::new(),
                expiry_height: None,
                fee_per_kb: None,
            },
        );
        assert_declared(
            "Outpoint",
            &JsOutpoint {
                txid: String::new(),
                vout: 0,
            },
        );
        assert_declared(
            "SignedTransaction",
            &JsSignedTransaction {
                hex: String::new(),
                txid: String::new(),
                fee: String::new(),
                change: String::new(),
                inputs_used: Vec::new(),
            },
        );
        assert_declared(
            "SignRequest",
            &SignRequest {
                identity: String::new(),
                system_id: String::new(),
                block_height: 0,
                message: String::new(),
                existing: None,
            },
        );
        assert_declared(
            "VerifyRequest",
            &VerifyRequest {
                identity: String::new(),
                system_id: String::new(),
                message: String::new(),
                signature: String::new(),
                primary_addresses: Vec::new(),
                minimum_signatures: 0,
            },
        );
        assert_declared(
            "VerifyResult",
            &VerifyResult {
                valid: false,
                block_height: 0,
                signers: Vec::new(),
            },
        );
        assert_declared(
            "TokenAmount",
            &TokenAmount {
                currency: String::new(),
                amount: String::new(),
            },
        );
        // Every optional field populated, so `skip_serializing_if` cannot hide
        // one from the check.
        assert_declared(
            "DecodedOutput",
            &DecodedOutput {
                kind: String::new(),
                address: Some(String::new()),
                tokens: Some(Vec::new()),
                name: Some(String::new()),
                primary_addresses: Some(Vec::new()),
                minimum_signatures: Some(0),
                eval_code: Some(0),
            },
        );
    }

    /// The other drift risk: the runtime field lists that make unknown-key
    /// rejection work (see `dto::from_js`). A field added to a request type
    /// but missing from its `FIELDS` would be refused as unknown the first
    /// time a caller passed it; a stale entry left behind would let a typo
    /// through. Both are caught by comparing against what the type serializes.
    #[test]
    fn every_request_types_field_list_matches_the_type() {
        use crate::login::{SignRequest, VerifyRequest};
        use crate::send::{SendRequest, TokenSendRequest};

        fn check<T: Serialize + Default>(name: &str, declared: &[&str]) {
            let mut actual = field_names(&T::default());
            let mut declared: Vec<String> = declared.iter().map(|s| (*s).to_string()).collect();
            actual.sort();
            declared.sort();
            assert_eq!(
                declared, actual,
                "{name}::FIELDS does not match what {name} serializes"
            );
        }

        check::<SendRequest>("SendRequest", SendRequest::FIELDS);
        check::<TokenSendRequest>("TokenSendRequest", TokenSendRequest::FIELDS);
        check::<SignRequest>("SignRequest", SignRequest::FIELDS);
        check::<VerifyRequest>("VerifyRequest", VerifyRequest::FIELDS);
    }

    /// And the check must be able to fail, or it proves nothing.
    #[test]
    fn the_drift_check_can_detect_an_undeclared_field() {
        #[derive(Serialize)]
        struct Undeclared {
            #[serde(rename = "aFieldNobodyDeclared")]
            field: u32,
        }
        let names = field_names(&Undeclared { field: 0 });
        assert_eq!(names, vec!["aFieldNobodyDeclared"]);
        assert!(!TYPESCRIPT.contains("aFieldNobodyDeclared:"));
    }
}
