//! `decode_output_script` against arbitrary bytes.
//!
//! Every output of every transaction a wallet looks at goes through here, and
//! those bytes are chosen by whoever built the transaction — which is anyone.
//! Not panicking is the floor. The two assertions below are the parts that
//! would still be wrong in a decoder that never panics.
//!
//! **A P2PKH that does not rebuild is not a P2PKH.** If the decoder reports
//! `PubKeyHash { hash }` for a script that is not exactly the standard P2PKH
//! encoding of that hash, a wallet has been told it holds an ordinary payment
//! to an address it controls, when the real script says something else.
//!
//! **The cached `may_carry_currency` must equal the function.** The
//! `UnsupportedCryptoCondition` variant carries that flag so the caller does
//! not have to look it up, and its own docs say `false` means the output is
//! "provably tokenless". A stale or wrong `false` is a wallet ignoring an
//! output that holds money.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verus_keys::Address;
use verus_tx_protocol::{decode_output_script, may_carry_currency, OutputKind};

fuzz_target!(|data: &[u8]| {
    let Ok(kind) = decode_output_script(data) else {
        return;
    };

    match kind {
        OutputKind::PubKeyHash { hash } => {
            let address = Address::from_p2pkh_script_pubkey(data)
                .expect("a script that decoded as P2PKH must be recognised as one");
            let rebuilt = address
                .p2pkh_script_pubkey()
                .expect("a recognised P2PKH address must re-encode");
            assert_eq!(
                rebuilt.as_slice(),
                data,
                "reported PubKeyHash({hash:?}) for a script that is not that P2PKH"
            );
        }
        OutputKind::UnsupportedCryptoCondition {
            eval_code,
            may_carry_currency: cached,
        } => {
            assert_eq!(
                cached,
                may_carry_currency(eval_code),
                "the cached may_carry_currency for eval {eval_code} disagrees with the function"
            );
        }
        _ => {}
    }
});
