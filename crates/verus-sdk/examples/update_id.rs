//! Update a VerusID: read the current identity off the chain's own output,
//! change one thing, and republish the whole object.
//!
//! ```sh
//! cargo run -p verus-sdk --example update_id < spec.json
//! ```
//!
//! ```json
//! {
//!   "wif": "Uw…",
//!   "identity_output": { "txid": "…", "vout": 0, "satoshis": 0, "script_pubkey": "47040300…75" },
//!   "utxos": [{ "txid": "…", "vout": 1, "satoshis": 139999979600, "script_pubkey": "76a914…88ac" }],
//!   "change_address": "R…",
//!   "expiry_height": 0,
//!   "set_content_map": { "<40 hex>": "<64 hex>" }
//! }
//! ```
//!
//! `identity_output` is what `getidentity` reports as the identity's `txid` and
//! `vout`. Its `script_pubkey` is the authoritative copy of the identity — this
//! example decodes it rather than trusting anything in the spec, because an
//! update republishes the **entire** object and any field not carried over is
//! silently erased. Reconstructing an identity from a config file is how an
//! identity loses its content, or its authority.
//!
//! Only the content map is editable here. Changing `primary_addresses`,
//! `min_sigs`, or the revocation and recovery authorities is a change of
//! authority: get it wrong and the identity becomes unupdatable by anyone,
//! permanently. The builder refuses those unless
//! `UpdateParams::allow_authority_change` is set, and this example never sets
//! it.
//!
//! `extra_wifs` supplies the co-signers of a multisig identity. The builder
//! needs `min_sigs` keys from the identity's own primary addresses, all of them
//! signing into one fulfillment; the first `wif` also pays the fee.
//!
//! # Content-map key order
//!
//! The daemon prints and accepts these keys as uint160s, i.e. **byte-reversed**
//! from wire order, the same convention it uses for txids. This example takes
//! them in wire order and prints them the same way, so what goes in comes back
//! out; expect `getidentity` to show the reverse.

use std::io::Read;

use serde_json::{json, Value};
use verus_keys::{Address, PrivateKey};
use verus_sdk::verus_tx::update::{build_identity_update, UpdateParams};
use verus_sdk::verus_tx::{decode_output_script, Amount, Expiry, Identity, OutputKind, Txid, Utxo};

type Error = Box<dyn std::error::Error>;

fn main() -> Result<(), Error> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let spec: Value = serde_json::from_str(&input)?;

    let key = PrivateKey::from_wif(spec["wif"].as_str().ok_or("spec.wif")?)?;
    // Co-signers for a multisig identity; empty for the ordinary 1-of-1 case.
    let extra: Vec<PrivateKey> = match spec["extra_wifs"].as_array() {
        Some(wifs) => wifs
            .iter()
            .map(|w| -> Result<PrivateKey, Error> {
                Ok(PrivateKey::from_wif(w.as_str().ok_or("extra_wifs[]")?)?)
            })
            .collect::<Result<_, _>>()?,
        None => Vec::new(),
    };
    let mut identity_keys: Vec<&PrivateKey> = vec![&key];
    identity_keys.extend(extra.iter());
    let change_address: Address = spec["change_address"]
        .as_str()
        .ok_or("spec.change_address")?
        .parse()?;
    // 0 in a spec means Expiry::Never, which is what these examples have always
    // sent; a wallet should set a real height.
    let expiry = Expiry::from_height(u32::try_from(
        spec["expiry_height"].as_u64().ok_or("spec.expiry_height")?,
    )?);

    let identity_output = read_utxo(&spec["identity_output"])?;
    let utxos = spec["utxos"]
        .as_array()
        .ok_or("spec.utxos")?
        .iter()
        .map(read_utxo)
        .collect::<Result<Vec<_>, _>>()?;

    // The chain's copy is the only trustworthy starting point.
    let mut identity = match decode_output_script(&identity_output.script_pubkey)? {
        OutputKind::IdentityPrimary { identity } => *identity,
        other => return Err(format!("that output does not hold an identity: {other:?}").into()),
    };
    let before = summarize(&identity);

    if let Some(entries) = spec["set_content_map"].as_object() {
        for (key, value) in entries {
            let key: [u8; 20] = hex::decode(key)?
                .try_into()
                .map_err(|_| "content-map keys are 20 bytes")?;
            let value: [u8; 32] = hex::decode(value.as_str().ok_or("content-map value")?)?
                .try_into()
                .map_err(|_| "content-map values are 32 bytes")?;
            // Replace in place if the key is already published, so an update
            // does not silently accumulate duplicates of the same key.
            match identity.content_map.iter_mut().find(|(k, _)| *k == key) {
                Some(entry) => entry.1 = value,
                None => identity.content_map.push((key, value)),
            }
        }
    }

    let signed = build_identity_update(
        &key,
        &identity_keys,
        &UpdateParams::new(&identity_output, &identity, &utxos, change_address, expiry)
            .with_fee_per_kb(10_000),
    )?;

    println!(
        "{:#}",
        json!({
            "txid": signed.txid,
            "hex": signed.hex,
            "fee": signed.fee.to_sat(),
            "change": signed.change.to_sat(),
            "before": before,
            "after": summarize(&identity),
        })
    );
    Ok(())
}

/// The fields worth eyeballing before broadcasting — above all the ones an
/// accidental rebuild would drop.
fn summarize(identity: &Identity) -> Value {
    json!({
        "name": identity.name,
        "min_sigs": identity.min_sigs,
        "primary_addresses": identity.primary_addresses.len(),
        "content_map": identity.content_map.iter()
            .map(|(k, v)| json!({ "key": hex::encode(k), "value": hex::encode(v) }))
            .collect::<Vec<_>>(),
        "content_multimap_keys": identity.content_multimap.len(),
        "private_addresses": identity.private_addresses.len(),
    })
}

fn read_utxo(value: &Value) -> Result<Utxo, Error> {
    Ok(Utxo {
        txid: Txid::from_display_hex(value["txid"].as_str().ok_or("utxo.txid")?)?,
        vout: u32::try_from(value["vout"].as_u64().ok_or("utxo.vout")?)?,
        satoshis: Amount::from_sat(value["satoshis"].as_u64().ok_or("utxo.satoshis")?),
        script_pubkey: hex::decode(
            value["script_pubkey"]
                .as_str()
                .ok_or("utxo.script_pubkey")?,
        )?,
    })
}
