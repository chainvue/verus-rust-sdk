//! Transparent Verus transactions: coin selection, fees, change, signing.
//!
//! Builds and signs; it never broadcasts and never reaches the network. The
//! caller supplies UTXOs and takes the signed hex somewhere else.
//!
//! Fee estimation, coin selection and the dust rule are ported *literally* from
//! the TypeScript SDK rather than improved, because byte-for-byte agreement
//! with it is the correctness gate for this crate. A "better" fee heuristic
//! would change change-output values and silently break every vector.

#![doc(html_no_source)]

// Phase 3 lands the transparent builder here.
