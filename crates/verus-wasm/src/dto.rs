//! The shapes JavaScript passes in and gets back, and how they become Rust.
//!
//! Three rules hold across every type here, and they are the whole reason this
//! module exists rather than deriving `Serialize` on the SDK's own types.
//!
//! **Money is a decimal string, never a `number`.** JavaScript's `number` is a
//! float64: it cannot hold every satoshi value a 64-bit chain can express, and
//! it rounds silently rather than failing. The workspace bans float money paths
//! end to end for that reason, and the boundary to JavaScript is precisely
//! where the ban would otherwise be lost. A string-typed field turns
//! `satoshis: 1e8` into a thrown error instead of a rounded amount — and a JS
//! `bigint` converts with `.toString()`, which is the intended path.
//!
//! **Hashes and scripts are hex strings**, spelled the way the daemon's JSON
//! spells them: a txid in display (reversed) order, a script as raw hex.
//!
//! **Unknown fields are refused** — see [`from_js`], which is where that is
//! actually enforced, and why `serde`'s own `deny_unknown_fields` is not
//! enough.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use verus_keys::Address;
use verus_tx::{Amount, CurrencyId, Expiry, Txid, Utxo};
use wasm_bindgen::JsValue;

use crate::error::{WasmError, WasmResult};

/// The keys an object may carry, and the shape of any object-valued ones.
///
/// A field's `Some(shape)` describes either a nested object or the elements of
/// a nested array; `None` means the value is a leaf (a string, a number, or an
/// array of them) that this module does not look inside.
pub struct Shape {
    /// `(key, shape of its value)`, in declaration order.
    pub fields: &'static [(&'static str, Option<&'static Shape>)],
}

impl Shape {
    fn names(&self) -> Vec<&'static str> {
        self.fields.iter().map(|(name, _)| *name).collect()
    }
}

mod sealed {
    /// Closes the [`super::Request`] impl set: only the `request_list!`
    /// expansion in this module can name a type here, so "implemented the
    /// trait but forgot the list" is not a state that exists.
    pub trait Sealed {}
}

/// A request object that crosses the JavaScript boundary.
///
/// Implementing this is what registers a DTO with the drift guards in
/// [`crate::types`], and [`from_js`] will not read a type that does not
/// implement it. `INTERFACE` names the `export interface` in `types.d.ts` that
/// publishes it, `SHAPE` is the key list `from_js` rebuilds the caller's object
/// against, and `sample` is the value the guards serialize.
///
/// There are no hand-written impls. They are generated from the single list in
/// `request_list!` below, so a DTO cannot be half-registered — the same reason
/// `methods!` in `verus-rpc` derives its enum, its names and its `ALL` from one
/// list rather than from three that can drift apart.
pub trait Request: sealed::Sealed + DeserializeOwned + Serialize + Default + Sized {
    /// The name of the `export interface` in `types.d.ts` that publishes this
    /// type to JavaScript.
    const INTERFACE: &'static str;

    /// The keys [`from_js`] will copy, and the shape of any object-valued ones.
    const SHAPE: &'static Shape;

    /// The value the drift guards serialize to learn this type's field set.
    ///
    /// [`Default`] is right unless a field is `skip_serializing_if` or
    /// otherwise absent when unset: that field is exactly the one a drift check
    /// would never see. Such a type gets a `{ field: Some(…) }` block in
    /// `request_list!`, which overrides this.
    fn sample() -> Self {
        Self::default()
    }
}

/// Every request DTO this crate publishes, once.
///
/// This list *is* the registration. It generates the [`Request`] impls below —
/// which [`from_js`] requires, so a request type missing from here cannot be
/// read from JavaScript at all — and, in `crate::types`'s tests, the registry
/// that the field guard and the shape guard iterate. There is no second list to
/// forget, which is what five rounds of adversarial review kept exploiting in
/// the text-scanning guard this replaced (#191).
///
/// A `{ … }` block after an entry gives that type a non-default sample, for the
/// optional fields a `Default` value would leave out of the serialization and
/// so out of the check.
macro_rules! request_list {
    ($consume:ident) => {
        $consume! {
            crate::send::SendRequest => "SendRequest",
            crate::send::TokenSendRequest => "TokenSendRequest",
            crate::login::SignRequest => "SignRequest",
            crate::login::VerifyRequest => "VerifyRequest",
            crate::flows::PlanSendRequest => "PlanSendRequest",
            crate::flows::HistoryRequest => "HistoryRequest"
                { start_height: Some(0), end_height: Some(0) },
            crate::flows::LoginRequest => "LoginRequest",
            crate::flows::VerifyLoginRequest => "VerifyLoginRequest"
                { max_age_blocks: Some(0), max_future_blocks: Some(0) },
            crate::flows::SpendableRequest => "SpendableRequest",
            crate::flows::ContentRequest => "ContentRequest",
            crate::flows::PlanSendTokenRequest => "PlanSendTokenRequest",
            crate::flows::PlanSendFromIdentityRequest => "PlanSendFromIdentityRequest",
            crate::flows::PlanSendTokenFromIdentityRequest => "PlanSendTokenFromIdentityRequest",
            crate::flows::PlanConvertFromIdentityRequest => "PlanConvertFromIdentityRequest"
                { via: Some(String::new()) },
            crate::flows::PlanPublishRequest => "PlanPublishRequest",
            crate::flows::OffersRequest => "OffersRequest"
                { with_offer_bytes: true },
            crate::flows::OfferTermsRequest => "OfferTermsRequest",
            crate::flows::TakeOfferRequest => "TakeOfferRequest",
            crate::flows::PlanConvertRequest => "PlanConvertRequest"
                { via: Some(String::new()), min_expected: Some(String::new()) },
            crate::flows::PlanBurnRequest => "PlanBurnRequest",
            crate::flows::PlanMintRequest => "PlanMintRequest",
            crate::flows::PlanRegistrationRequest => "PlanRegistrationRequest"
                {
                    min_sigs: Some(0),
                    referral: Some(String::new()),
                    pin_fee: Some(String::new()),
                    salt: Some(String::new()),
                },
            crate::flows::PendingRequest => "PendingRequest",
            crate::flows::PlanLaunchRequest => "PlanLaunchRequest"
                { pin_launch_fee: Some(String::new()) },
        }
    };
}
// `impl_requests!` below reaches the macro textually; this re-export is what
// lets `crate::types`'s drift guards consume the very same list, which is the
// only other place it is needed today.
#[cfg(test)]
pub(crate) use request_list;

macro_rules! impl_requests {
    ($( $ty:ty => $name:literal $({ $($field:ident : $value:expr),* $(,)? })? ),+ $(,)?) => {$(
        impl sealed::Sealed for $ty {}
        impl Request for $ty {
            const INTERFACE: &'static str = $name;
            const SHAPE: &'static Shape = &<$ty>::SHAPE;
            $(
                fn sample() -> Self {
                    Self {
                        $($field: $value,)*
                        ..Self::default()
                    }
                }
            )?
        }
    )+};
}
request_list!(impl_requests);

/// Read a request object, refusing anything the type does not declare.
///
/// # Why `deny_unknown_fields` is not enough, and why checking keys was not either
///
/// The request types carry `#[serde(deny_unknown_fields)]`, and against
/// `serde_json` it does what it says. Against `serde-wasm-bindgen` it does
/// **nothing**: that deserializer reads a struct by asking the JavaScript
/// object for the names it wants, so a key nobody asked for is never visited
/// and never reported. The attribute is silently inert.
///
/// That mattered. `expiryHieght: tip + 20` — one transposition — deserialized
/// as a request with no expiry at all, and produced a perfectly valid,
/// perfectly signed transaction minable for the rest of the chain's life.
///
/// The first fix enumerated the object's own enumerable keys and rejected the
/// unknown ones. That was still unsound, because it asked a **different
/// question** than the deserializer: `Object.keys` sees own enumerable string
/// keys, while `Reflect.get` walks the prototype chain and ignores
/// enumerability. Every gap between the two was reachable — an inherited
/// property, a non-enumerable one, a class getter, or a `Proxy` whose
/// `ownKeys` trap lies — and each one restored the original bug. Worse in the
/// other direction: `Object.prototype.expiryHeight = …` set the expiry of
/// transactions built from an ordinary object literal, invisibly, because the
/// checker never looked where the reader read.
///
/// So this does not check the caller's object. It **rebuilds** it: the
/// prototype must be `Object.prototype` or `null`, every own key (including
/// symbols and non-enumerable ones, via `Reflect.ownKeys`) must be declared,
/// and the declared keys are copied by value into a fresh prototype-less
/// object which is what serde then reads. The reader and the checker cannot
/// disagree, because they are looking at the same object, and it has nothing
/// on it that was not checked.
///
/// Nested objects and arrays of objects get the same treatment, so a stray key
/// inside a UTXO or a recipient is refused too — that one was not merely
/// cosmetic either: `recipients: [{address, satoshis, currency}]` passed to a
/// **native** send silently dropped `currency` and moved native coins.
///
/// The shape is the type's own [`Request::SHAPE`], not an argument: a caller
/// cannot hand one type's keys to another's, and a request type absent from
/// `request_list!` — and therefore covered by no drift guard — fails to compile
/// here rather than shipping unguarded.
pub fn from_js<T: Request>(value: JsValue) -> WasmResult<T> {
    let checked = sanitize(value, T::SHAPE, "")?;
    serde_wasm_bindgen::from_value(checked).map_err(WasmError::from)
}

/// The same, for an argument that is an **array** of `shape` objects.
///
/// Refuses a non-array outright rather than letting serde report it, because
/// `sanitize` passes a lone object straight through to the object branch and a
/// caller who meant to pass one UTXO instead of a list deserves to be told so.
///
/// Still takes its shape as an argument, unlike [`from_js`]: its one caller
/// passes [`JsUtxo`], which is a nested element type rather than a request, so
/// it is not — and must not be — in `request_list!`.
pub fn from_js_list<T: DeserializeOwned>(value: JsValue, shape: &Shape) -> WasmResult<Vec<T>> {
    if !js_sys::Array::is_array(&value) {
        return Err(WasmError::new(
            "InvalidArgument",
            "expected an array of outputs",
        ));
    }
    let checked = sanitize(value, shape, "")?;
    serde_wasm_bindgen::from_value(checked).map_err(WasmError::from)
}

/// A fresh, prototype-less copy of `value` carrying only `shape`'s fields.
///
/// `path` names the position for an error message — `""` at the top level,
/// then `utxos[1].` and so on.
///
/// # Why the recursion cannot follow the input
///
/// An earlier version of this recursed on whatever it found: an array element
/// that was itself an array went round the array branch again. That handed the
/// **caller** control of the recursion depth, and a request whose `utxos` was
/// an array nested a few thousand deep overflowed the wasm stack — not into a
/// catchable error, but into `RuntimeError: memory access out of bounds` that
/// left the stack pointer corrupt, so every later call to *any* export in the
/// module failed the same way. One malformed request bricked the instance for
/// the life of the page, taking already-imported keys with it. `utxos` and
/// `recipients` are exactly the fields a wallet fills from JSON it did not
/// author, so this was reachable from a hostile RPC reply.
///
/// The fix is not a depth limit — it is that an array's elements are read as
/// *objects*, never as arrays. Recursion now alternates array → object →
/// declared nested field, so its depth is bounded by [`Shape`], which is a
/// compile-time constant, whatever the input looks like. An element that turns
/// out to be an array is passed through untouched for serde to reject as the
/// type error it is.
fn sanitize(value: JsValue, shape: &Shape, path: &str) -> WasmResult<JsValue> {
    if js_sys::Array::is_array(&value) {
        let array = js_sys::Array::from(&value);
        let copy = js_sys::Array::new_with_length(array.length());
        for (index, element) in array.iter().enumerate() {
            let index = u32::try_from(index).map_err(|_| {
                WasmError::new("InvalidArgument", format!("{path} has too many entries"))
            })?;
            copy.set(
                index,
                sanitize_object(element, shape, &format!("{path}[{index}]."))?,
            );
        }
        return Ok(copy.into());
    }
    sanitize_object(value, shape, path)
}

/// The object half of [`sanitize`]. Never recurses into an array directly —
/// only through a declared nested field, which is what bounds the depth.
fn sanitize_object(value: JsValue, shape: &Shape, path: &str) -> WasmResult<JsValue> {
    use wasm_bindgen::JsCast;

    // A non-object — or an array where an object belongs — is left to serde,
    // which reports the type mismatch far better than a key walk could. `null`
    // and `undefined` land here too.
    if !value.is_object() || js_sys::Array::is_array(&value) {
        return Ok(value);
    }
    let object: &js_sys::Object = value.unchecked_ref();

    // Positions are spelled `utxos[0].` with a trailing separator; a nested
    // field arrives without one, so add it rather than reporting `utxos0`.
    let path = &if path.is_empty() || path.ends_with('.') {
        path.to_string()
    } else {
        format!("{path}.")
    };

    // A class instance, or anything else with its own prototype, is refused
    // rather than silently stripped: its accessors live on that prototype, and
    // copying own properties only would drop them without a word.
    let prototype = js_sys::Object::get_prototype_of(&value);
    let plain = js_sys::Object::get_prototype_of(&js_sys::Object::new().into());
    if prototype != plain && !prototype.is_null() {
        return Err(WasmError::new(
            "InvalidArgument",
            format!(
                "{}expected a plain object; a class instance or an object with a \
                 custom prototype cannot be read safely, because its fields may \
                 live on the prototype where they would be silently ignored",
                if path.is_empty() { "" } else { path }
            ),
        ));
    }

    let declared = shape.names();
    // `Object.create(null)` — nothing inherited can reach the deserializer.
    let copy: js_sys::Object = js_sys::Object::create(JsValue::NULL.unchecked_ref());

    for key in js_sys::Reflect::own_keys(&value)
        .map_err(|_| WasmError::new("InvalidArgument", "the request object cannot be read"))?
        .iter()
    {
        let Some(name) = key.as_string() else {
            return Err(WasmError::new(
                "UnknownField",
                format!("{path}a symbol key is not a field of this request"),
            ));
        };
        let Some((_, nested)) = shape.fields.iter().find(|(field, _)| *field == name) else {
            return Err(WasmError::new(
                "UnknownField",
                format!(
                    "unknown field {:?}; expected one of {}",
                    format!("{path}{name}"),
                    declared.join(", ")
                ),
            ));
        };
        let held = js_sys::Reflect::get(object, &key).map_err(|_| {
            WasmError::new("InvalidArgument", format!("{path}{name} cannot be read"))
        })?;
        let held = match nested {
            None => held,
            Some(nested) => sanitize(held, nested, &format!("{path}{name}"))?,
        };
        js_sys::Reflect::set(&copy, &key, &held).map_err(|_| {
            WasmError::new("InvalidArgument", format!("{path}{name} cannot be copied"))
        })?;
    }

    // The copy is built from own keys, but the deserializer *would* have read
    // through `Reflect.get`. Anything a declared field can still be reached by
    // that this copy did not pick up is a disagreement between the two views,
    // and it is refused rather than resolved. Two ways to get here, and
    // refusing is right for both:
    //
    //   * a `Proxy` whose `ownKeys` hides a field its `get` still returns —
    //     the field would be silently dropped;
    //   * `Object.prototype.expiryHeight = …`, where a field nobody wrote
    //     would otherwise be silently ignored. Loud is better: a page whose
    //     prototypes are polluted is a page whose transactions should stop,
    //     not one that should quietly build a different transaction.
    for (field, _) in shape.fields {
        if js_sys::Reflect::has(&copy, &JsValue::from_str(field)).unwrap_or(false) {
            continue;
        }
        let reachable =
            js_sys::Reflect::get(object, &JsValue::from_str(field)).unwrap_or(JsValue::UNDEFINED);
        if !reachable.is_undefined() {
            return Err(WasmError::new(
                "InvalidArgument",
                format!(
                    "{path}{field} is reachable on this object but is not one of its own \
                     properties — it comes from a prototype or a proxy, and reading it \
                     would mean building a transaction from a value the caller did not set"
                ),
            ));
        }
    }
    Ok(copy.into())
}

/// Read a `string` argument, refusing anything that is not one.
///
/// `wasm-bindgen` types a `&str` parameter as `string`, and in a **debug**
/// build it emits a `typeof` guard to back that up. A release build — the one
/// CI runs and the one that ships — has no guard: it reads `.length` off
/// whatever arrived and writes that many bytes, so `parseCoins(1.1)` traps the
/// module with `RuntimeError: memory access out of bounds`. That is the single
/// most likely mistake a JavaScript caller makes against this API, since
/// `parseCoins` exists precisely to stop people using numbers for money, and
/// it contradicts the crate's promise that failures are `Error`s naming their
/// cause. So every string parameter arrives as a `JsValue` and comes through
/// here.
pub fn text(field: &str, value: &JsValue) -> WasmResult<String> {
    value.as_string().ok_or_else(|| {
        WasmError::new(
            "InvalidArgument",
            format!(
                "{field} must be a string. Amounts are decimal strings rather than \
                 numbers — a float64 cannot hold every satoshi value — so pass \
                 `String(n)` or a bigint's `.toString()`."
            ),
        )
    })
}

/// Read a `string` argument that is key material — a WIF or a recovery
/// phrase — rather than the ordinary [`String`] `text` returns.
///
/// An ordinary `String`, dropped, is freed without being zeroed — wasm's
/// allocator does not zero freed memory — so a secret read this way would sit
/// in the module's linear memory for the lifetime of the page, the same
/// hazard [`crate::keys::Key::to_wif`] documents and fixes on the export
/// path. Wrapping it in [`zeroize::Zeroizing`] wipes it when the caller is
/// done with it instead. This only reaches the Rust-side copy: the
/// JavaScript string the caller passed in is the JS engine's own, and
/// nothing on this side can touch or wipe it.
pub fn secret_text(field: &str, value: &JsValue) -> WasmResult<zeroize::Zeroizing<String>> {
    text(field, value).map(zeroize::Zeroizing::new)
}

/// The same, for an optional secret — [`mnemonic_to_seed`](crate::mnemonic::mnemonic_to_seed)'s
/// `passphrase`, BIP-39's optional 25th word.
///
/// A wrong argument here is easy to miss precisely because it is quiet — the
/// seed is valid either way, and the wallet is simply empty — which is exactly
/// why the passphrase itself must not be treated as less sensitive than the
/// phrase it is combined with. `verus_keys::mnemonic_to_seed` already wraps
/// the salt it derives from this value in `Zeroizing`; leaving the raw
/// argument as a plain `String` on this side of that call would be the same
/// asymmetry [`secret_text`] exists to close, one layer up.
pub fn optional_secret_text(
    field: &str,
    value: &JsValue,
) -> WasmResult<Option<zeroize::Zeroizing<String>>> {
    optional_text(field, value).map(|text| text.map(zeroize::Zeroizing::new))
}

/// Read an optional `string` argument: absent, `null` or `undefined` give
/// `None`, and anything that is not a string is refused.
pub fn optional_text(field: &str, value: &JsValue) -> WasmResult<Option<String>> {
    if value.is_null() || value.is_undefined() {
        return Ok(None);
    }
    text(field, value).map(Some)
}

/// Read a decimal integer number of satoshis.
///
/// Rejects a leading `+`, a decimal point, whitespace and an empty string: this
/// is satoshis, and anything that looks like coins should go through
/// [`crate::money::parse_coins`] where the scaling is explicit.
pub fn sats(text: &str) -> WasmResult<Amount> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(WasmError::new(
            "InvalidAmount",
            format!("{text:?} is not a decimal number of satoshis"),
        ));
    }
    let value = text.parse::<u64>().map_err(|_| {
        WasmError::new(
            "InvalidAmount",
            format!("{text:?} does not fit in 64 bits of satoshis"),
        )
    })?;
    Ok(Amount::from_sat(value))
}

/// Render satoshis the way every DTO field here spells them.
pub fn sats_string(amount: Amount) -> String {
    amount.to_sat().to_string()
}

/// Decode a hex string of exactly `N` bytes.
pub fn fixed_hex<const N: usize>(field: &str, text: &str) -> WasmResult<[u8; N]> {
    let bytes = hex::decode(text)?;
    <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| {
        WasmError::new(
            "InvalidHex",
            format!("{field} must be {N} bytes of hex, got {} ", text.len() / 2),
        )
    })
}

/// Decode a hex string of any length.
pub fn bytes_hex(text: &str) -> WasmResult<Vec<u8>> {
    Ok(hex::decode(text)?)
}

/// Parse any Verus base58 address — `R…`, `i…` or a script hash.
pub fn address(text: &str) -> WasmResult<Address> {
    text.parse::<Address>().map_err(WasmError::from)
}

/// Parse an address that must be a spendable `R…`.
pub fn pubkey_hash_address(field: &str, text: &str) -> WasmResult<Address> {
    let parsed = address(text)?;
    if parsed.kind() != verus_keys::AddressKind::PubKeyHash {
        return Err(WasmError::new(
            "UnsupportedRecipient",
            format!("{field} must be an R-address; {text} is not"),
        ));
    }
    Ok(parsed)
}

/// Parse an `i…` identity address into the 20 bytes that name it.
pub fn identity_id(field: &str, text: &str) -> WasmResult<[u8; 20]> {
    let parsed = address(text)?;
    if parsed.kind() != verus_keys::AddressKind::Identity {
        return Err(WasmError::new(
            "NotAnIdentity",
            format!("{field} must be an i-address; {text} is not"),
        ));
    }
    Ok(parsed.hash())
}

/// Parse a currency, which is named by its i-address.
pub fn currency(field: &str, text: &str) -> WasmResult<CurrencyId> {
    Ok(CurrencyId::from_bytes(identity_id(field, text)?))
}

/// Render 20 bytes as the `R…` address that names a key hash.
///
/// The sibling of [`identity_address`], and the distinction matters: the same
/// twenty bytes spell a different address under each prefix, and paying the
/// wrong one pays somebody nobody controls.
#[must_use]
pub fn key_hash_address(hash: [u8; 20]) -> String {
    Address::new(verus_keys::AddressKind::PubKeyHash, hash).to_string()
}

/// Render 20 bytes as the i-address that names an identity or a currency.
pub fn identity_address(id: [u8; 20]) -> String {
    Address::new(verus_keys::AddressKind::Identity, id).to_string()
}

/// An unspent output, as a wallet holds it.
///
/// `txid` is display order — the same string `getaddressutxos` prints, which is
/// the reverse of the bytes in the transaction. Getting this backwards produces
/// a transaction that spends nothing and is rejected, so the field is named for
/// what a caller sees rather than for what goes on the wire.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JsUtxo {
    /// The transaction that created it, in display order.
    pub txid: String,
    /// Index of the output within that transaction.
    pub vout: u32,
    /// What it is worth, in satoshis, as a decimal string.
    pub satoshis: String,
    /// The scriptPubKey it pays to, as hex.
    ///
    /// Renamed explicitly rather than left to `rename_all`, which would spell
    /// it `scriptPubkey` — one capital away from the name every daemon, every
    /// wallet and every doc in this repo uses. With `deny_unknown_fields` that
    /// mismatch is a thrown error rather than a silently ignored field, but it
    /// would still be an error for no reason.
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: String,
}

impl JsUtxo {
    /// The keys a UTXO object may carry.
    pub const SHAPE: Shape = Shape {
        fields: &[
            ("txid", None),
            ("vout", None),
            ("satoshis", None),
            ("scriptPubKey", None),
        ],
    };

    /// Convert to the SDK's own type.
    pub fn to_utxo(&self) -> WasmResult<Utxo> {
        Ok(Utxo {
            txid: Txid::from_display_hex(&self.txid)?,
            vout: self.vout,
            satoshis: sats(&self.satoshis)?,
            script_pubkey: bytes_hex(&self.script_pubkey)?,
        })
    }
}

/// Convert a whole list, reporting which entry failed.
pub fn utxos(list: &[JsUtxo]) -> WasmResult<Vec<Utxo>> {
    utxos_named("utxos", list)
}

/// The same, naming the field the caller actually passed.
///
/// `tokenUtxos` reporting an error about `utxos[1]` sends a caller looking at
/// a field they never wrote.
pub fn utxos_named(field: &str, list: &[JsUtxo]) -> WasmResult<Vec<Utxo>> {
    list.iter()
        .enumerate()
        .map(|(index, utxo)| {
            utxo.to_utxo().map_err(|error| {
                WasmError::new(
                    error.code(),
                    format!("{field}[{index}]: {}", error.message()),
                )
            })
        })
        .collect()
}

/// Where value is going.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JsRecipient {
    /// The address being paid.
    pub address: String,
    /// How much, in satoshis, as a decimal string.
    pub satoshis: String,
}

impl JsRecipient {
    /// The keys a recipient object may carry.
    ///
    /// Small, and worth stating why it is checked at all: `currency` belongs
    /// to a *token* recipient, and a caller who reaches for `send` when they
    /// meant `sendToken` writes exactly this object. Dropping the stray key
    /// silently moved native coins instead.
    pub const SHAPE: Shape = Shape {
        fields: &[("address", None), ("satoshis", None)],
    };
}

/// When a transaction stops being minable.
///
/// `null` means never, and has to be written: an expiring transaction that
/// falls out of the mempool is recoverable, while `Never` is a transaction
/// that can be mined at any height for the rest of the chain's life. The SDK
/// makes the same distinction non-defaultable for the same reason.
///
/// `0` is **refused** rather than read as never. On the wire zero *is* how
/// never is spelled, and [`Expiry::from_height`] decodes it that way — but on
/// this boundary zero is overwhelmingly likely to be an accident rather than a
/// decision: an uninitialised counter, `Number(undefined) || 0`, or a
/// `getblockcount` that failed and returned nothing. Accepting it would give
/// the crate two spellings for never, one of them documented and one of them
/// the single most probable wrong value, which is exactly the shape of the
/// mistyped-field bug this module exists to stop.
pub fn expiry(height: Option<u32>) -> WasmResult<Expiry> {
    let expiry = match height {
        None => Expiry::Never,
        Some(0) => {
            return Err(WasmError::new(
                "InvalidExpiry",
                "expiryHeight 0 is not a height. Omit the field (or pass null) for a \
                 transaction that never expires — that has to be written, because it \
                 can be mined at any height for the rest of the chain's life.",
            ))
        }
        Some(height) => Expiry::from_height(height),
    };
    expiry.check()?;
    Ok(expiry)
}

/// A signed transaction, ready to broadcast.
///
/// `fee` and `change` are reported rather than left implicit because they are
/// the two numbers a caller cannot recover from the hex without also holding
/// every prevout — and the fee is the one an accidental unit slip destroys.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsSignedTransaction {
    /// The raw transaction, hex — what `sendrawtransaction` takes.
    pub hex: String,
    /// Its txid in display order, known before it is broadcast.
    pub txid: String,
    /// The miner fee paid, in satoshis, including any dust folded into it.
    pub fee: String,
    /// Change returned, in satoshis; `"0"` if it would have been dust.
    pub change: String,
    /// The outpoints spent, in input order.
    pub inputs_used: Vec<JsOutpoint>,
}

/// One outpoint: which output of which transaction.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JsOutpoint {
    /// The transaction, in display order.
    pub txid: String,
    /// The output index.
    pub vout: u32,
}

impl From<verus_tx::SignedTransaction> for JsSignedTransaction {
    fn from(signed: verus_tx::SignedTransaction) -> Self {
        Self {
            hex: signed.hex,
            txid: signed.txid,
            fee: sats_string(signed.fee),
            change: sats_string(signed.change),
            inputs_used: signed
                .inputs_used
                .into_iter()
                .map(|(txid, vout)| JsOutpoint {
                    txid: txid.to_display_hex(),
                    vout,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn satoshis_are_decimal_strings() {
        assert_eq!(sats("100000000").unwrap(), Amount::from_sat(100_000_000));
        assert_eq!(sats("0").unwrap(), Amount::ZERO);
    }

    /// `secret_text` reads the same values `text` does — the wipe is a
    /// difference in the *type*, not the behaviour, so there is nothing to
    /// exercise at runtime beyond what `text`'s own callers already cover
    /// (and `JsValue` cannot be constructed under `cargo test`'s host target
    /// in the first place — see the note on `Key`'s test module, which hits
    /// the same wall). Coercing the function item to this exact `fn` type is
    /// the assertion: it fails to *compile*, not just to pass, if the return
    /// type is ever widened back to a plain `String` — which is exactly the
    /// regression that would silently drop the wipe on the WIF and
    /// seed-phrase import paths again.
    ///
    /// This pins `secret_text`'s own signature, not that `from_wif` or
    /// `from_seed_phrase` still call it rather than `text` — a call-site
    /// swap back would still compile. `tests/node/differential.mjs` scans
    /// real linear memory after those calls, which is where that part is
    /// actually checked.
    #[test]
    fn secret_text_is_typed_to_return_a_zeroizing_string() {
        let _: fn(&str, &JsValue) -> WasmResult<zeroize::Zeroizing<String>> = secret_text;
    }

    /// Same reasoning as `secret_text_is_typed_to_return_a_zeroizing_string`,
    /// for the passphrase reader: it must return `Option<Zeroizing<String>>`,
    /// not `Option<String>`.
    #[test]
    fn optional_secret_text_is_typed_to_return_a_zeroizing_string() {
        let _: fn(&str, &JsValue) -> WasmResult<Option<zeroize::Zeroizing<String>>> =
            optional_secret_text;
    }

    /// The whole point of the string-typed money fields: the ways JavaScript
    /// would otherwise smuggle a float in must each fail loudly.
    #[test]
    fn anything_that_is_not_an_integer_of_satoshis_is_refused() {
        for bad in ["", "1.5", "1e8", " 100", "100 ", "+100", "-100", "0x64"] {
            let error = sats(bad).expect_err("{bad:?} must be refused");
            assert_eq!(error.code(), "InvalidAmount", "{bad:?} -> {error}");
        }
    }

    #[test]
    fn a_satoshi_count_beyond_64_bits_is_refused() {
        let error = sats("99999999999999999999999").expect_err("must not wrap");
        assert!(error.message().contains("64 bits"), "{error}");
    }

    #[test]
    fn an_i_address_is_not_accepted_where_an_r_address_is_required() {
        let identity = identity_address([0x11; 20]);
        let error = pubkey_hash_address("changeAddress", &identity).expect_err("i is not R");
        assert_eq!(error.code(), "UnsupportedRecipient");
    }

    #[test]
    fn an_r_address_is_not_accepted_where_an_identity_is_required() {
        let key = verus_keys::PrivateKey::from_bytes(&[0x22; 32], true).unwrap();
        let error =
            identity_id("parent", &key.address().to_string()).expect_err("R is not an identity");
        assert_eq!(error.code(), "NotAnIdentity");
    }

    #[test]
    fn a_utxo_round_trips_through_its_dto() {
        let js = JsUtxo {
            txid: "11".repeat(32),
            vout: 3,
            satoshis: "250000000".into(),
            script_pubkey: hex::encode(
                verus_keys::PrivateKey::from_bytes(&[0x33; 32], true)
                    .unwrap()
                    .address()
                    .p2pkh_script_pubkey()
                    .unwrap(),
            ),
        };
        let utxo = js.to_utxo().unwrap();
        assert_eq!(utxo.vout, 3);
        assert_eq!(utxo.satoshis, Amount::from_sat(250_000_000));
        assert_eq!(utxo.txid.to_display_hex(), js.txid);
    }

    /// A bad entry must name its index — a wallet passing forty outputs needs
    /// to know which one, and "invalid hex" alone does not say.
    #[test]
    fn a_bad_utxo_names_its_index() {
        let good = JsUtxo {
            txid: "11".repeat(32),
            vout: 0,
            satoshis: "1".into(),
            script_pubkey: "76a914".to_string() + &"22".repeat(20) + "88ac",
        };
        let mut bad = good.clone();
        bad.satoshis = "1.0".into();
        let error = utxos(&[good, bad]).expect_err("the second entry is bad");
        assert!(error.message().starts_with("utxos[1]:"), "{error}");
    }

    #[test]
    fn an_expiry_beyond_the_height_threshold_is_refused() {
        assert!(expiry(Some(500_000_001)).is_err());
        assert_eq!(expiry(None).unwrap(), Expiry::Never);
    }
}
