//! JSON-RPC framing, and reading a daemon's reply without trusting it.

use serde::Deserialize;
use serde_json::value::RawValue;

use crate::error::RpcError;
use crate::method::Method;
use crate::transport::RequestBody;

/// Build the request body for one call.
///
/// Private on purpose: this is the only way a [`RequestBody`] comes into
/// existence, so the set of requests this crate can emit is the set of
/// [`Method`] variants.
pub(crate) fn request(method: Method, params: serde_json::Value) -> Result<RequestBody, RpcError> {
    let body = serde_json::json!({
        "jsonrpc": "1.0",
        "id": "verus-rust-sdk",
        "method": method.name(),
        "params": params,
    });
    serde_json::to_string(&body)
        .map(RequestBody::new)
        .map_err(|e| RpcError::Malformed(format!("could not build request: {e}")))
}

/// A daemon's reply, before the result is interpreted.
///
/// `result` is doubly optional, which is not an accident:
///
/// * `None` — the key is **absent**, which is what an error reply looks like.
///   That is the shape a naive `struct { result: T, error: E }` gets wrong.
/// * `Some(None)` — the key is present and `null`.
///
/// They are told apart because they mean different things and want different
/// messages. No method here legitimately returns `null`, so an explicit null is
/// a node malfunctioning rather than answering, and saying so beats reporting
/// that the reply had no result at all.
#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(borrow, default, deserialize_with = "present_but_maybe_null")]
    result: Option<Option<&'a RawValue>>,
    #[serde(default)]
    error: Option<NodeError>,
}

/// Tell an absent key from one that is present and `null`.
///
/// `Option<Option<T>>` alone does not do it: serde's own `Option` impl maps
/// `null` to `None` before the inner layer is ever reached, so both cases arrive
/// as `None`. With `default` plus this, the function only runs when the key is
/// there, and the outer `Some` records that fact.
fn present_but_maybe_null<'de, D>(
    deserializer: D,
) -> Result<Option<Option<&'de RawValue>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<&'de RawValue>::deserialize(deserializer).map(|value| {
        // A present-but-null key arrives here as the raw token `null`.
        Some(value.filter(|raw| raw.get().trim() != "null"))
    })
}

#[derive(Deserialize)]
struct NodeError {
    code: i64,
    message: String,
}

/// `-32601`, the JSON-RPC "method not found" code.
const METHOD_NOT_FOUND: i64 = -32601;

/// Pull the result out of a reply, or turn the daemon's error into ours.
///
/// Takes the raw text so the caller can hand the borrowed result straight to
/// `serde_json`, keeping the original number tokens intact — see [`crate::json`]
/// for why that matters for money.
pub(crate) fn result_of<'a>(body: &'a str, method: Method) -> Result<&'a RawValue, RpcError> {
    let envelope: Envelope<'a> = serde_json::from_str(body).map_err(|e| {
        // A public endpoint under load answers with HTML, not JSON. Say so
        // rather than reporting a confusing parse error about byte 0.
        let head: String = body.chars().take(80).collect();
        RpcError::Malformed(format!("reply was not JSON-RPC ({e}): {head}"))
    })?;

    if let Some(error) = envelope.error {
        return Err(if error.code == METHOD_NOT_FOUND {
            RpcError::MethodUnavailable {
                method: method.name(),
            }
        } else {
            RpcError::Node {
                code: error.code,
                message: error.message,
            }
        });
    }

    match envelope.result {
        Some(Some(result)) => Ok(result),
        Some(None) => Err(RpcError::Unexpected(format!(
            "{} answered with a null result",
            method.name()
        ))),
        None => Err(RpcError::Malformed(
            "reply carried neither a result nor an error".to_string(),
        )),
    }
}

/// Deserialize a result into a concrete type.
pub(crate) fn parse<T: serde::de::DeserializeOwned>(
    result: &RawValue,
    what: &'static str,
) -> Result<T, RpcError> {
    serde_json::from_str(result.get()).map_err(|e| RpcError::Unexpected(format!("{what}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_request_naming_the_method() {
        let body = request(Method::GetInfo, serde_json::json!([])).unwrap();
        assert!(body.as_str().contains(r#""method":"getinfo""#));
    }

    #[test]
    fn reads_a_result() {
        let body = r#"{"result":{"blocks":42},"error":null,"id":"x"}"#;
        let result = result_of(body, Method::GetInfo).unwrap();
        assert!(result.get().contains("42"));
    }

    /// The shape that breaks the obvious struct: an error reply has **no**
    /// `result` key at all.
    #[test]
    fn an_error_reply_omits_the_result_key_entirely() {
        let body = r#"{"error":{"code":-5,"message":"Identity not found"}}"#;
        assert!(!body.contains("result"));
        match result_of(body, Method::GetIdentity) {
            Err(RpcError::Node { code, message }) => {
                assert_eq!(code, -5);
                assert_eq!(message, "Identity not found");
            }
            other => panic!("expected a node error, got {other:?}"),
        }
    }

    /// "This node cannot do that" is a different remedy from "the node said
    /// no", and on public infrastructure it is the commonest failure.
    #[test]
    fn method_not_found_is_its_own_error() {
        let body = r#"{"error":{"code":-32601,"message":"Method not found"}}"#;
        match result_of(body, Method::GetRawTransaction) {
            Err(RpcError::MethodUnavailable { method }) => {
                assert_eq!(method, "getrawtransaction");
            }
            other => panic!("expected MethodUnavailable, got {other:?}"),
        }
    }

    /// A public endpoint under load answers with HTML. The error should say so.
    #[test]
    fn a_non_json_body_is_reported_readably() {
        let body = "<html><head><title>502 Bad Gateway</title></head></html>";
        match result_of(body, Method::GetInfo) {
            Err(RpcError::Malformed(message)) => assert!(message.contains("502")),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    /// An explicit null and an absent key are different malfunctions, and the
    /// message should say which one happened.
    #[test]
    fn a_null_result_is_told_apart_from_a_missing_one() {
        match result_of(r#"{"result":null,"error":null}"#, Method::GetInfo) {
            Err(RpcError::Unexpected(message)) => assert!(message.contains("null result")),
            other => panic!("expected Unexpected, got {other:?}"),
        }
    }

    #[test]
    fn a_reply_with_neither_result_nor_error_is_refused() {
        match result_of(r#"{"id":"x"}"#, Method::GetInfo) {
            Err(RpcError::Malformed(_)) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }
}
