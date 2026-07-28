# Security

## Status

**This software is in early development and has not been audited.** Do not use
it with mainnet funds. The crates are unpublished and the API is unstable.

## Reporting a vulnerability

Report suspected security issues **privately** to the maintainer — do not open a
public issue. Use GitHub's private security advisory flow ("Report a
vulnerability") on this repository.

## Trust model

These crates build and sign transactions offline. They hold spending keys in
process memory while signing and **never** open a network connection — the
consumer broadcasts.

That makes the host a security-critical component. The realistic threat is not
the cryptography; it is what else runs on the machine holding the key.

### What this software guarantees

- **No network.** No crate here opens a socket. Key material cannot leave by
  accident, because there is nowhere for it to go.
- **Deterministic signatures.** RFC6979 with low-S normalization. No RNG on the
  transparent path means no entropy-source failure mode, no nonce reuse from a
  bad `getrandom`, and reproducible output.
- **Integer money.** Satoshis are `u64`/`i128` throughout; there is no float in
  the value path and therefore no silent rounding of an amount.
- **Zeroization on drop** for decoded private key material.
- **Consensus bytes are verified against a real daemon**, not just against our
  own tests. See `fixtures/daemon/`.

### What it does NOT guarantee

- **Memory secrecy against the host.** `zeroize` shortens the window in which a
  key sits in memory; it does not protect against a process that can read your
  memory, a swap file, or a core dump. If the host is compromised, the key is.
- **Side-channel resistance.** `k256` is constant-time for scalar operations,
  but this crate makes no claim about the whole pipeline under an attacker with
  local timing or power measurement.
- **Protection against a malicious dependency.** The tree is kept small and
  checked with `cargo deny` in CI, but every dependency is code with key access.
- **Anything about how you store keys at rest.** That is the consumer's job.

### Guidance for integrators

- **Scan with a viewing key, not a spending key.** For shielded balances a
  Diversifiable Full Viewing Key is enough; load the spending key only to sign.
- **Never persist a spending key unencrypted.** Use the OS keychain, or an
  encrypted vault with a password-derived key.
- **Keep key operations away from your UI.** A narrow request/response boundary
  between "code that renders untrusted strings" (memos, VerusID names, currency
  names) and "code that holds keys" means a UI compromise costs you a bad
  approval prompt, not the wallet.
- **Review what you sign.** Most real wallet losses are approval and phishing
  failures, not broken cryptography.
