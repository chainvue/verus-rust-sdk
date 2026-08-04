//! What is actually in this transaction?
//!
//! ```sh
//! cargo run -p verus-sdk --example decode_tx -- <hex>
//! cargo run -p verus-sdk --example decode_tx            # reads hex on stdin
//! ```
//!
//! Fully offline: no node, no key, no funds, no features beyond the default.
//! It is the one example in this directory that runs the moment the repository
//! is cloned, and the one to reach for when something on chain is not what it
//! was expected to be.
//!
//! To point it at a real testnet transaction, let a public node hand you the
//! bytes — it is only ever asked to read:
//!
//! ```sh
//! TXID=<txid>
//! curl -s --data-binary "{\"method\":\"getrawtransaction\",\"params\":[\"$TXID\"]}" \
//!   https://api.verustest.net | sed 's/.*"result":"\([0-9a-f]*\)".*/\1/' \
//!   | cargo run -q -p verus-sdk --example decode_tx
//! ```
//!
//! # Why an output needs decoding at all
//!
//! On Bitcoin an output is a script and a number of satoshis, and the number is
//! the value. On Verus that is true only for the plain ones. A token lives in
//! the *payload* of a CryptoCondition output whose satoshi field is zero, an
//! identity is an output, a conversion in flight is an output, and a name
//! commitment is an output. Reading the satoshi column of a Verus transaction
//! and calling it the value is how a wallet reports that an address holds
//! nothing while it holds a fortune in tokens.
//!
//! So this prints what each output *is*, and where it does not know, it says
//! so — including whether the thing it does not understand is able to hold
//! money. That last distinction is the one worth having: an undecodable output
//! that provably cannot carry currency is safe to ignore, and one that can is
//! not.
//!
//! # Every branch below is `decode_output_script` telling you something
//!
//! The program is a `match`. All the work is in the SDK, and the reason it is
//! worth an example is that the variants of [`OutputKind`] are a compact map of
//! what a Verus output can be.

use std::fmt::Write as _;
use std::io::Read;

use verus_sdk::decode::{decode_output_script, Destination, OutputKind};
use verus_sdk::money::Amount;
use verus_sdk::verus_keys::{Address, AddressKind};
use verus_sdk::verus_wire::TxV4;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hex = match std::env::args().nth(1) {
        Some(argument) => argument,
        None => {
            let mut buffer = String::new();
            std::io::stdin().read_to_string(&mut buffer)?;
            buffer
        }
    };
    let hex = hex.trim();
    if hex.is_empty() {
        return Err("give me a raw transaction (or an output script) as hex".into());
    }
    let bytes = hex::decode(hex)?;

    // A transaction first, because that is what a caller almost always has.
    // A bare script is the useful fallback: `decodescript`-shaped questions —
    // "what does this scriptPubKey do" — come up while debugging a builder,
    // and at that point there is no transaction to put it in yet.
    match TxV4::deserialize(&bytes) {
        Ok(tx) => print_transaction(&tx),
        Err(transaction_error) => match decode_output_script(&bytes) {
            Ok(kind) => {
                println!("not a transaction — reading it as a single output script\n");
                println!("  {}", describe(&kind));
            }
            // Report the transaction error, not the script one: the input was
            // far more likely meant to be a transaction, and "expected 4 bytes
            // of version" is a more useful sentence than "not a script".
            Err(_) => return Err(Box::new(transaction_error)),
        },
    }
    Ok(())
}

fn print_transaction(tx: &TxV4) {
    let total_out = tx.outputs.iter().map(|out| out.value).sum::<u64>();
    println!(
        "txid    {}",
        tx.txid().map_or("unknown".into(), hex_reversed)
    );
    println!(
        "expiry  {}",
        match tx.expiry_height {
            // Worth naming rather than printing as 0. An expiry of "never" is
            // a payment that can still be mined months later, against coins the
            // sender has since spent elsewhere.
            0 => "never — this transaction stays minable forever".to_string(),
            height => format!("height {height}"),
        }
    );
    if tx.is_shielded() {
        println!(
            "shielded {} spend(s), {} output(s), valueBalance {}",
            tx.shielded_spends.len(),
            tx.shielded_outputs.len(),
            Amount::from_sat(tx.value_balance.unsigned_abs()),
        );
    }

    println!("\ninputs ({})", tx.inputs.len());
    for (index, input) in tx.inputs.iter().enumerate() {
        let mut txid = input.txid_internal;
        txid.reverse();
        println!(
            "  #{index}  {}:{}{}",
            hex::encode(txid),
            input.vout,
            if input.script_sig.is_empty() {
                "  (unsigned)"
            } else {
                ""
            }
        );
    }

    println!(
        "\noutputs ({}) — {} in native satoshis",
        tx.outputs.len(),
        Amount::from_sat(total_out)
    );
    for (index, output) in tx.outputs.iter().enumerate() {
        let described = match decode_output_script(&output.script_pubkey) {
            Ok(kind) => describe(&kind),
            // Not fatal. An output this crate cannot read sits beside ones it
            // can, and refusing the whole transaction over it would throw away
            // the answer the caller came for.
            Err(error) => format!("undecodable: {error}"),
        };
        println!(
            "  #{index}  {:>16}  {described}",
            Amount::from_sat(output.value).to_string()
        );
    }
}

/// One line per output kind.
///
/// The satoshi value is printed by the caller; what this adds is everything the
/// satoshi value does not say.
fn describe(kind: &OutputKind) -> String {
    match kind {
        OutputKind::PubKeyHash { hash } => {
            format!("→ {}", address(AddressKind::PubKeyHash, *hash))
        }
        OutputKind::PubKey { pubkey, hash } => format!(
            "→ {} (pays a bare public key, {} bytes — a mined coinbase)",
            address(AddressKind::PubKeyHash, *hash),
            pubkey.len()
        ),
        OutputKind::IdentityPayment { identity } => format!(
            "→ {} (held for a VerusID, not a key)",
            address(AddressKind::Identity, *identity)
        ),
        OutputKind::ReserveOutput {
            destination,
            tokens,
        } => format!("→ {} holds {}", show(destination), currencies(tokens)),
        OutputKind::IdentityPrimary { identity } => {
            let mut line = format!(
                "the VerusID {}@ itself — {}-of-{} signature(s)",
                identity.name,
                identity.min_sigs,
                identity.primary_addresses.len()
            );
            for (label, authority) in [
                ("revocation", identity.revocation_authority),
                ("recovery", identity.recovery_authority),
            ] {
                // `write!` to a String cannot fail, and swallowing the Result
                // here keeps the example about outputs rather than about
                // formatting.
                let _ = write!(
                    line,
                    ", {label} {}",
                    address(AddressKind::Identity, authority)
                );
            }
            if !identity.content_multimap.is_empty() || !identity.content_map.is_empty() {
                let _ = write!(
                    line,
                    ", {} published content key(s)",
                    identity.content_multimap.len() + identity.content_map.len()
                );
            }
            line
        }
        OutputKind::IdentityCommitment {
            destination,
            commitment,
            tokens,
        } => format!(
            "a name commitment redeemable by {}, hash {}{}",
            show(destination),
            hex::encode(commitment),
            if tokens.is_empty() {
                String::new()
            } else {
                format!(", carrying {}", currencies(tokens))
            }
        ),
        OutputKind::ReserveDeposit {
            controlling_currency,
            tokens,
            ..
        } => format!(
            "reserves held for {controlling_currency}: {}",
            currencies(tokens)
        ),
        OutputKind::ReserveTransfer { transfer, .. } => format!(
            "value in flight → {} as {}, {} fee in {}, flags {:#x}",
            show(&transfer.destination.recipient),
            transfer.destination_currency,
            Amount::from_sat(transfer.fees),
            transfer.fee_currency,
            transfer.flags
        ),
        // The honest answer, and the one worth reading carefully. `false` here
        // means the output is undecodable *and* provably holds no currency, so
        // ignoring it costs nothing. `true` means something may be in there.
        OutputKind::UnsupportedCryptoCondition {
            eval_code,
            may_carry_currency,
        } => format!(
            "a CryptoCondition this SDK does not decode (eval {eval_code}) — {}",
            if *may_carry_currency {
                "IT MAY HOLD CURRENCY; do not treat this output as empty"
            } else {
                "it cannot hold currency"
            }
        ),
        // `OutputKind` is `#[non_exhaustive]`: a future variant should print
        // something honest here rather than fail to compile a consumer.
        other => format!("{other:?}"),
    }
}

fn show(destination: &Destination) -> String {
    match destination {
        Destination::PubKeyHash(hash) => address(AddressKind::PubKeyHash, *hash),
        Destination::Identity(hash) => address(AddressKind::Identity, *hash),
        Destination::ScriptHash(hash) => address(AddressKind::ScriptHash, *hash),
        Destination::PubKey(key) => format!("public key {}", hex::encode(key)),
    }
}

fn address(kind: AddressKind, hash: [u8; 20]) -> String {
    Address::new(kind, hash).to_string()
}

/// `(currency, amount)` pairs, which is where a token's value actually lives.
fn currencies(tokens: &[(verus_sdk::send::CurrencyId, u64)]) -> String {
    if tokens.is_empty() {
        return "no currency".to_string();
    }
    tokens
        .iter()
        .map(|(currency, amount)| format!("{} {currency}", Amount::from_sat(*amount)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A txid the way RPC prints it — the reverse of how it is serialized.
fn hex_reversed(mut bytes: [u8; 32]) -> String {
    bytes.reverse();
    hex::encode(bytes)
}
