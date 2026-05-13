---
title: Message digest and TLS PRF
---

# Message digest and TLS PRF

## Algorithm

This module groups **HMAC**, **HKDF** (RFC 5869), and **TLS 1.2 PRF / Finished** helpers used when implementing or testing TLS key schedules outside the main `Connection` API.

## Purpose

HMAC, HKDF (SHA-256/384), TLS 1.2 PRF, Finished verify_data, and transcript helpers.

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::hash`
- **Primary symbols:**
  - `noxtls_hmac_sha256`
  - `noxtls_hmac_sha384`
  - `noxtls_hmac_sha512`
  - `noxtls_hkdf_extract_sha256`
  - `noxtls_hkdf_expand_sha256`
  - `noxtls_hkdf_extract_sha384`
  - `noxtls_hkdf_expand_sha384`
  - `noxtls_tls12_prf_sha256`
  - `noxtls_tls12_prf_sha384`
  - `noxtls_tls12_finished_verify_data_sha256`
  - `noxtls_tls12_finished_verify_data_sha384`
  - `TlsTranscriptSha256`
  - `TlsTranscriptSha384`

**Functions and types:**

- **`noxtls_hmac_sha256` / `noxtls_hmac_sha384` / `noxtls_hmac_sha512`** — Keyed MAC over a message; fixed tag sizes.
- **`noxtls_hkdf_extract_sha256` / `noxtls_hkdf_expand_sha256` / `noxtls_hkdf_extract_sha384` / `noxtls_hkdf_expand_sha384`** — Extract then expand key material with domain separation.
- **`noxtls_tls12_prf_sha256` / `noxtls_tls12_prf_sha384`** — TLS 1.2 PRF over `secret`, `label`, and `seed`.
- **`noxtls_tls12_finished_verify_data_sha256` / `noxtls_tls12_finished_verify_data_sha384`** - Parameters: master secret, Finished label, and handshake transcript bytes. Behavior: derives TLS 1.2 Finished-message verify data for handshake validation. Returns: 12-byte verify data output.
- **`TlsTranscriptSha256` / `TlsTranscriptSha384`** — Rolling handshake transcript hashes.

## Feature flags and policy

SHA-384 HKDF/PRF variants are used when the negotiated TLS profile uses SHA-384.

## Examples

### HKDF (SHA-256)

```rust
use noxtls_crypto::{noxtls_hkdf_extract_sha256, noxtls_hkdf_expand_sha256};

let salt = b"";
let ikm = b"input key material";
let prk = noxtls_hkdf_extract_sha256(salt, ikm);
let okm = noxtls_hkdf_expand_sha256(&prk, b"my-app-context-v1", 32)?;
assert_eq!(okm.len(), 32);
# Ok::<(), noxtls_core::Error>(())
```

### TLS 1.2 PRF

```rust
use noxtls_crypto::noxtls_tls12_prf_sha256;

let secret = b"master-secret-bytes";
let label = b"key expansion";
let seed = b"client_randomserver_random";
let key_block = noxtls_tls12_prf_sha256(secret, label, seed, 64)?;
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

Keep HKDF `info` and TLS labels distinct per protocol version; never reuse PRK across unrelated protocols.

## Related

- [Hash topic](./hash)
- [TLS topic](./tls)
