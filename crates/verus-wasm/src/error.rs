//! What a failure looks like on the JavaScript side.
//!
//! Every fallible binding throws a real `Error`, so `try`/`catch`, stack traces
//! and `instanceof Error` all behave the way a JavaScript caller expects. The
//! interesting part is `.name`: it carries the *variant* that failed, so a
//! wallet can branch on the cause instead of matching on prose.
//!
//! ```js
//! try {
//!   key.send(params);
//! } catch (e) {
//!   if (e.name === "InsufficientFunds") topUp();
//!   else throw e;
//! }
//! ```
//!
//! The name comes from the Rust error's `Debug` output, cut at the first
//! character that cannot be part of an identifier. For a `#[derive(Debug)]`
//! enum that prefix *is* the variant name, which means new variants get a
//! usable code with no mapping table to fall out of date — the failure mode a
//! hand-written table has is silently reporting a stale code, and this has none
//! to be stale. Renaming a variant changes the code, deliberately: it is a
//! breaking change on both sides of the boundary at once.

use wasm_bindgen::JsValue;

/// An error on its way to JavaScript.
///
/// Carries the code and the message separately so the thrown object can expose
/// both, rather than a single flattened string a caller would have to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmError {
    code: String,
    message: String,
}

impl WasmError {
    /// An error with an explicit code, for failures that originate here rather
    /// than in a lower crate — bad hex, a missing field, a number where a
    /// decimal string belongs.
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }

    /// The variant that failed. Stable for as long as the Rust variant name is.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The human-readable description.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Wrap a lower-crate error, taking the code from its `Debug` prefix and
    /// the message from its `Display`.
    fn from_source(source: &(impl std::fmt::Debug + std::fmt::Display)) -> Self {
        Self {
            code: variant_name(&format!("{source:?}")),
            message: source.to_string(),
        }
    }
}

/// The leading identifier of a `Debug` rendering.
///
/// `InsufficientFunds { required: 5, available: 1 }` → `InsufficientFunds`;
/// `InvalidVdxfName("a b")` → `InvalidVdxfName`; a bare `NoOutputs` → itself.
fn variant_name(debug: &str) -> String {
    let name: String = debug
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        "VerusError".to_string()
    } else {
        name
    }
}

impl std::fmt::Display for WasmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for WasmError {}

impl From<verus_tx::TxError> for WasmError {
    fn from(error: verus_tx::TxError) -> Self {
        Self::from_source(&error)
    }
}

impl From<verus_keys::KeyError> for WasmError {
    fn from(error: verus_keys::KeyError) -> Self {
        Self::from_source(&error)
    }
}

impl From<verus_keys::MnemonicError> for WasmError {
    fn from(error: verus_keys::MnemonicError) -> Self {
        Self::from_source(&error)
    }
}

impl From<verus_wire::WireError> for WasmError {
    fn from(error: verus_wire::WireError) -> Self {
        Self::from_source(&error)
    }
}

impl From<hex::FromHexError> for WasmError {
    fn from(error: hex::FromHexError) -> Self {
        Self::new("InvalidHex", error.to_string())
    }
}

impl From<serde_wasm_bindgen::Error> for WasmError {
    fn from(error: serde_wasm_bindgen::Error) -> Self {
        // Reached when the object JavaScript passed does not have the shape the
        // DTO declares. The money hint is worth appending for the case it was
        // written for — a `number` where a decimal string belongs, which is the
        // mistake the string-typed fields exist to catch — and is noise on
        // `missing field \`utxos\``, so it is attached only when the message
        // shows a number arriving where one does not belong.
        let message = error.to_string();
        let numeric = message.contains("floating point")
            || message.contains("integer")
            || message.contains("expected a string");
        Self::new(
            "InvalidArgument",
            if numeric {
                format!(
                    "{message} — amounts are decimal strings rather than numbers, because a \
                     float64 cannot hold every satoshi value; pass `String(n)` or a bigint's \
                     `.toString()`"
                )
            } else {
                message
            },
        )
    }
}

impl From<WasmError> for JsValue {
    fn from(error: WasmError) -> Self {
        let thrown = js_sys::Error::new(&error.message);
        thrown.set_name(&error.code);
        thrown.into()
    }
}

/// The result type every binding returns.
pub type WasmResult<T> = Result<T, WasmError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_struct_variant_reports_its_name() {
        let error = WasmError::from(verus_tx::TxError::InsufficientFunds {
            required: 500,
            available: 100,
        });
        assert_eq!(error.code(), "InsufficientFunds");
        assert!(error.message().contains("500"), "{}", error.message());
    }

    #[test]
    fn a_tuple_variant_reports_its_name() {
        let error = WasmError::from(verus_tx::TxError::InvalidVdxfName("a b".into()));
        assert_eq!(error.code(), "InvalidVdxfName");
    }

    #[test]
    fn a_unit_variant_reports_its_name() {
        let error = WasmError::from(verus_tx::TxError::NoOutputs);
        assert_eq!(error.code(), "NoOutputs");
        assert_eq!(error.message(), "a transaction needs at least one output");
    }

    /// A key error is a different crate's enum, and must be coded the same way
    /// rather than collapsing to a catch-all.
    #[test]
    fn a_key_error_reports_its_name() {
        let error = WasmError::from(verus_keys::PrivateKey::from_wif("not a wif").unwrap_err());
        assert_ne!(error.code(), "VerusError", "{error}");
        assert!(
            error
                .code()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "a code must be usable as a JavaScript identifier comparison: {error}"
        );
    }

    /// The fallback exists so a `Debug` rendering that does not begin with an
    /// identifier still produces something a caller can compare against.
    #[test]
    fn an_unnameable_debug_rendering_falls_back() {
        assert_eq!(variant_name("(1, 2)"), "VerusError");
        assert_eq!(variant_name(""), "VerusError");
    }
}
