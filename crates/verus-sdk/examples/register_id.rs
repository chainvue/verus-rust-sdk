//! Register a VerusID: both halves of the commit/reveal, from a JSON spec.
//!
//! ```sh
//! cargo run -p verus-sdk --example register_id < step1.json
//! cargo run -p verus-sdk --example register_id < step2.json
//! ```
//!
//! Step 1 — claim the name behind a salt:
//!
//! ```json
//! {
//!   "step": 1,
//!   "wif": "Uw…",
//!   "name": "rustsdk",
//!   "parent": "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq",
//!   "utxos": [{ "txid": "…", "vout": 1, "satoshis": 150000000000, "script_pubkey": "76a914…88ac" }],
//!   "change_address": "R…",
//!   "expiry_height": 0
//! }
//! ```
//!
//! Step 2 — reveal it and publish the identity. `salt` comes from step 1's
//! output; without it the commitment cannot be redeemed and its fee is lost:
//!
//! ```json
//! {
//!   "step": 2,
//!   "wif": "Uw…", "name": "rustsdk", "parent": "iJhC…", "salt": "…64 hex…",
//!   "commitment": { "txid": "…", "vout": 0, "satoshis": 0, "script_pubkey": "1a0403…75" },
//!   "utxos": [ … ],
//!   "primary_addresses": ["R…"],
//!   "min_sigs": 1,
//!   "system_id": "iJhC…",
//!   "registration_fee": 10000000000,
//!   "change_address": "R…",
//!   "expiry_height": 0
//! }
//! ```
//!
//! Nothing here touches the network: it prints signed hex for the caller to
//! broadcast, and the two steps must be broadcast in order, with step 1
//! confirmed before step 2 spends it.
//!
//! # Two ways to lose the fee
//!
//! **The salt.** It is not on the chain in any recoverable form. Step 1's output
//! prints it; store it before broadcasting anything.
//!
//! **The registration fee.** `registration_fee` is chain policy — `getcurrency
//! VRSCTEST` reports it as `idregistrationfees`, 100 VRSCTEST at the time of
//! writing — and it is *burned*, appearing as an oversized miner fee rather than
//! an output. Get it wrong and the daemon rejects a transaction that has already
//! spent the commitment.

use std::fs::File;
use std::io::Read;

use serde_json::{json, Value};
use verus_keys::{Address, PrivateKey};
use verus_sdk::verus_tx::register::{
    build_identity_registration, build_name_commitment, CommitmentParams, NameReservation,
    ParentCurrencyFee, RegistrationParams,
};
use verus_sdk::verus_tx::{Txid, Utxo};

type Error = Box<dyn std::error::Error>;

fn main() -> Result<(), Error> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let spec: Value = serde_json::from_str(&input)?;

    let key = PrivateKey::from_wif(spec["wif"].as_str().ok_or("spec.wif")?)?;
    let name = spec["name"].as_str().ok_or("spec.name")?;
    let parent: Address = spec["parent"].as_str().ok_or("spec.parent")?.parse()?;
    let change_address: Address = spec["change_address"]
        .as_str()
        .ok_or("spec.change_address")?
        .parse()?;
    let expiry_height = u32::try_from(spec["expiry_height"].as_u64().ok_or("spec.expiry_height")?)?;
    let utxos = read_utxos(&spec["utxos"])?;

    // A salt from step 1 is in wire order already — this prints it in the same
    // order it reads it, and never in the daemon's reversed display order, so a
    // round trip through this example cannot silently flip it.
    let salt = match spec["salt"].as_str() {
        Some(text) => {
            let bytes = hex::decode(text)?;
            bytes
                .try_into()
                .map_err(|_| "spec.salt must be 32 bytes of hex")?
        }
        None => random_salt()?,
    };

    // A referral is committed to in step 1 and must be identical in step 2 —
    // it is inside the hash consensus re-derives.
    let referral = match spec["referral"].as_str() {
        Some(text) => Some(text.parse::<Address>()?.hash()),
        None => None,
    };
    let reservation = NameReservation::new(name, parent.hash(), referral, salt)?;

    match spec["step"].as_u64() {
        Some(1) => {
            let signed = build_name_commitment(
                &key,
                &CommitmentParams::new(&utxos, &reservation, change_address, expiry_height),
            )?;
            println!(
                "{:#}",
                json!({
                    "step": 1,
                    "txid": signed.txid,
                    "hex": signed.hex,
                    "fee": signed.fee,
                    "change": signed.change,
                    // KEEP THIS. Step 2 cannot be built without it.
                    "salt": hex::encode(reservation.salt),
                    "salt_daemon_display": hex::encode(reservation.salt_display()),
                    "commitment_hash": hex::encode(reservation.commitment_hash()?),
                    "referral": spec["referral"].as_str(),
                    "identity_address": identity_address(&reservation)?,
                })
            );
        }
        Some(2) => {
            let commitment = read_utxo(&spec["commitment"])?;
            // Only needed when the referrer was itself referred; the chain is
            // chain state, read from each referrer's getidentity output.
            let referral_chain: Vec<[u8; 20]> = spec["referral_chain"]
                .as_array()
                .map(|entries| {
                    entries
                        .iter()
                        .map(|e| -> Result<[u8; 20], Error> {
                            Ok(e.as_str()
                                .ok_or("referral_chain[]")?
                                .parse::<Address>()?
                                .hash())
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?
                .unwrap_or_default();
            let primary_addresses = spec["primary_addresses"]
                .as_array()
                .ok_or("spec.primary_addresses")?
                .iter()
                .map(|a| -> Result<Address, Error> {
                    Ok(a.as_str().ok_or("primary_addresses[]")?.parse()?)
                })
                .collect::<Result<Vec<_>, _>>()?;
            // A sub-identity under a parent CURRENCY: the fee is paid in the
            // parent's own currency, so it needs token-bearing inputs, and what
            // burns natively is the parent's idimportfees.
            let token_funding = match spec["parent_currency"].as_object() {
                Some(p) => read_utxos(&p["token_funding"])?,
                None => Vec::new(),
            };
            let parent_currency = match spec["parent_currency"].as_object() {
                Some(p) => Some(ParentCurrencyFee {
                    fee: p["fee"].as_u64().ok_or("parent_currency.fee")?,
                    native_import_fee: p["native_import_fee"]
                        .as_u64()
                        .ok_or("parent_currency.native_import_fee")?,
                    token_funding: &token_funding,
                    proof_protocol: u32::try_from(p["proof_protocol"].as_u64().unwrap_or(2))?,
                }),
                None => None,
            };
            let system_id: Address = spec["system_id"]
                .as_str()
                .ok_or("spec.system_id")?
                .parse()?;

            let registered = build_identity_registration(
                &key,
                &RegistrationParams {
                    commitment: &commitment,
                    reservation: &reservation,
                    utxos: &utxos,
                    primary_addresses: &primary_addresses,
                    min_sigs: u32::try_from(spec["min_sigs"].as_u64().unwrap_or(1))?,
                    system_id: system_id.hash(),
                    // Default to the identity itself. Pointing recovery at
                    // ANOTHER identity is what makes revocation usable later:
                    // an identity that is its own recovery authority cannot be
                    // recovered once revoked, and the daemon refuses to revoke
                    // it at all.
                    revocation_authority: authority(&spec["revocation_authority"])?,
                    recovery_authority: authority(&spec["recovery_authority"])?,
                    registration_fee: spec["registration_fee"]
                        .as_u64()
                        .ok_or("spec.registration_fee")?,
                    referral_levels: u32::try_from(spec["referral_levels"].as_u64().unwrap_or(3))?,
                    referral_chain: &referral_chain,
                    parent_currency,
                    change_address,
                    expiry_height,
                    fee_per_kb: 10_000,
                },
            )?;
            println!(
                "{:#}",
                json!({
                    "step": 2,
                    "txid": registered.transaction.txid,
                    "hex": registered.transaction.hex,
                    "fee_including_burn": registered.transaction.fee,
                    "change": registered.transaction.change,
                    "identity_address": registered.identity_address.to_string(),
                    "identity_name": registered.identity.name,
                    "min_sigs": registered.identity.min_sigs,
                    "primary_addresses": registered.identity.primary_addresses.len(),
                })
            );
        }
        _ => return Err("spec.step must be 1 or 2".into()),
    }
    Ok(())
}

/// An optional authority i-address from the spec.
fn authority(value: &Value) -> Result<Option<[u8; 20]>, Error> {
    match value.as_str() {
        Some(text) => Ok(Some(text.parse::<Address>()?.hash())),
        None => Ok(None),
    }
}

fn identity_address(reservation: &NameReservation) -> Result<String, Error> {
    use verus_keys::AddressKind;
    use verus_sdk::verus_tx::register::identity_id;
    let id = identity_id(&reservation.name, Some(reservation.parent));
    Ok(Address::new(AddressKind::Identity, id).to_string())
}

/// 32 bytes straight from the OS.
///
/// The library refuses to do this itself — see the `register` module docs — and
/// an example is the right place for it precisely because the choice of entropy
/// source belongs to the application, not to the signer.
fn random_salt() -> Result<[u8; 32], Error> {
    let mut salt = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut salt)?;
    Ok(salt)
}

fn read_utxos(value: &Value) -> Result<Vec<Utxo>, Error> {
    value
        .as_array()
        .ok_or("spec.utxos")?
        .iter()
        .map(read_utxo)
        .collect()
}

fn read_utxo(value: &Value) -> Result<Utxo, Error> {
    Ok(Utxo {
        txid: Txid::from_display_hex(value["txid"].as_str().ok_or("utxo.txid")?)?,
        vout: u32::try_from(value["vout"].as_u64().ok_or("utxo.vout")?)?,
        satoshis: value["satoshis"].as_u64().ok_or("utxo.satoshis")?,
        script_pubkey: hex::decode(
            value["script_pubkey"]
                .as_str()
                .ok_or("utxo.script_pubkey")?,
        )?,
    })
}
