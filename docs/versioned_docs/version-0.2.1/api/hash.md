---
title: Crypto API - Hash/HMAC/HKDF
---

# Crypto API: Hash, HMAC, HKDF

Hash and key-derivation helpers are provided by `noxtls-crypto::hash` and re-exported at crate root. This page highlights the functions typically used by TLS and device control planes.

## Digest APIs

```rust
pub fn noxtls_sha1(data: &[u8]) -> [u8; 20]
pub fn noxtls_sha256(data: &[u8]) -> [u8; 32]
pub fn noxtls_sha384(data: &[u8]) -> [u8; 48]
pub fn noxtls_sha512(data: &[u8]) -> [u8; 64]
```

- **`data`**: input bytes to hash.
- Fixed-size return types make buffer sizing explicit in no_std code.

## HMAC APIs

```rust
pub fn noxtls_hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32]
```

- **`key`**: HMAC key bytes.
- **`data`**: authenticated message bytes.
- Returns 32-byte authentication tag.

## HKDF APIs

```rust
pub fn noxtls_hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> [u8; 32]
pub fn noxtls_hkdf_expand_sha256(prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>>
```

- **`salt`**: optional extract salt (empty salt is handled).
- **`ikm`**: input key material.
- **`prk`**: pseudorandom key from extract.
- **`info`**: context string/domain separation.
- **`len`**: output length (bounded by RFC HKDF limits).

## TLS 1.2 helper APIs

```rust
pub fn noxtls_tls12_prf_sha256(secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Result<Vec<u8>>
pub fn noxtls_tls12_finished_verify_data_sha256(
    master_secret: &[u8],
    finished_label: &[u8],
    transcript: &[u8],
) -> Result<[u8; 12]>
```

- `noxtls_tls12_prf_sha256` computes RFC 5246 PRF output.
- `noxtls_tls12_finished_verify_data_sha256` computes the 12-byte Finished `verify_data`.

## Guidance

- Use `noxtls_sha256` + `noxtls_hmac_sha256` for constrained-device interoperability defaults.
- Prefer HKDF functions over custom KDF composition in protocol code.
- Keep labels/info constants protocol-specific to avoid cross-protocol key reuse.
