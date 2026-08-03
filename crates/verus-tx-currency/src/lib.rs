//! Bringing a currency into existence.
//!
//! Two halves. [`currency_definition`] serializes a `CCurrencyDefinition` —
//! the object that says what a currency *is*: its reserves, weights, supply,
//! preallocations and fees. [`currency_launch`] builds the transaction that
//! registers one, which is the definition plus the notarization, export and
//! reserve-deposit outputs the chain requires alongside it.
//!
//! # Three amount encodings in one structure
//!
//! A definition picks its integer encoding per field — satoshi `VARINT` for
//! the block heights and fees, little-endian `int32` for the weights and
//! protocol ids, little-endian `int64` for supply and every amount vector.
//! Using one encoding throughout produces wrong money *without failing to
//! parse*, which is why [`currency_definition`] is written field by field
//! against captured daemon output rather than generically.

#![doc(html_no_source)]

pub mod currency_definition;
pub mod currency_launch;
