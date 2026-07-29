//! Revoke or recover a VerusID, from a JSON spec on stdin.
//!
//! ```sh
//! cargo run -p verus-sdk --example revoke_id < spec.json
//! ```
//!
//! ```json
//! {
//!   "action": "revoke",
//!   "wif": "Uw…",
//!   "authority_wifs": ["Uw…"],
//!   "identity_output": { "txid": "…", "vout": 0, "satoshis": 0, "script_pubkey": "4704…75" },
//!   "utxos": [{ "txid": "…", "vout": 1, "satoshis": 1000000, "script_pubkey": "76a914…88ac" }],
//!   "change_address": "R…",
//!   "expiry_height": 0
//! }
//! ```
//!
//! For `"action": "recover"` add `"primary_addresses": ["R…"]` to hand the
//! identity a new set of keys, which is usually the whole point — revocation
//! normally means the old ones are gone.
//!
//! `wif` funds the miner fee. `authority_wifs` are the keys of the *revocation*
//! or *recovery authority*, which is a different identity with its own primary
//! addresses. This example cannot check them: they belong to an object on the
//! chain that the identity being revoked does not contain. Wrong keys produce a
//! transaction the daemon rejects at script verification.
//!
//! # Revocation is not reversible by default
//!
//! A freshly registered identity is its own revocation and recovery authority.
//! In that shape it can never be revoked — the daemon refuses, because nobody
//! could then recover it — and the builder refuses first. Making revocation
//! usable means pointing recovery at another identity **at registration time**.

use std::io::Read;

use serde_json::{json, Value};
use verus_keys::{Address, PrivateKey};
use verus_sdk::verus_tx::revoke::{
    build_identity_recovery, build_identity_revocation, RecoveryParams, RevocationParams,
};
use verus_sdk::verus_tx::{
    decode_output_script, Amount, Destination, Expiry, OutputKind, Txid, Utxo,
};

type Error = Box<dyn std::error::Error>;

fn main() -> Result<(), Error> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let spec: Value = serde_json::from_str(&input)?;

    let key = PrivateKey::from_wif(spec["wif"].as_str().ok_or("spec.wif")?)?;
    let authority: Vec<PrivateKey> = spec["authority_wifs"]
        .as_array()
        .ok_or("spec.authority_wifs")?
        .iter()
        .map(|w| -> Result<PrivateKey, Error> {
            Ok(PrivateKey::from_wif(w.as_str().ok_or("authority_wifs[]")?)?)
        })
        .collect::<Result<_, _>>()?;
    let authority_keys: Vec<&PrivateKey> = authority.iter().collect();

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

    let current = match decode_output_script(&identity_output.script_pubkey)? {
        OutputKind::IdentityPrimary { identity } => *identity,
        other => return Err(format!("that output does not hold an identity: {other:?}").into()),
    };

    let signed = match spec["action"].as_str() {
        Some("revoke") => build_identity_revocation(
            &key,
            &authority_keys,
            &RevocationParams {
                identity_output: &identity_output,
                utxos: &utxos,
                change_address,
                expiry,
                fee_per_kb: 10_000,
            },
        )?,
        Some("recover") => {
            // Recovery restates the whole identity, like an update — but it is
            // also the one operation allowed to replace the primary addresses.
            let mut recovered = current.clone();
            recovered.flags &= !verus_sdk::verus_tx::identity::FLAG_REVOKED;
            if let Some(addresses) = spec["primary_addresses"].as_array() {
                recovered.primary_addresses = addresses
                    .iter()
                    .map(|a| -> Result<Destination, Error> {
                        let address: Address = a.as_str().ok_or("primary_addresses[]")?.parse()?;
                        Ok(Destination::PubKeyHash(address.hash()))
                    })
                    .collect::<Result<_, _>>()?;
                recovered.min_sigs = 1;
            }
            build_identity_recovery(
                &key,
                &authority_keys,
                &RecoveryParams {
                    identity_output: &identity_output,
                    identity: &recovered,
                    utxos: &utxos,
                    change_address,
                    expiry,
                    fee_per_kb: 10_000,
                },
            )?
        }
        _ => return Err("spec.action must be \"revoke\" or \"recover\"".into()),
    };

    println!(
        "{:#}",
        json!({
            "action": spec["action"].as_str(),
            "txid": signed.txid,
            "hex": signed.hex,
            "fee": signed.fee.to_sat(),
            "identity": current.name,
            "was_revoked": current.is_revoked(),
        })
    );
    Ok(())
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
