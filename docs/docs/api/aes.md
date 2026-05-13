---
title: AES
---

# AES

## Algorithm

**AES** (Rijndael, FIPS 197) is a symmetric block cipher with 128-bit blocks and 128-, 192-, or 256-bit keys. NoxTLS expands the key once into an `AesCipher` value, then applies mode functions for CBC, CTR, GCM, CCM, CFB, OFB, and XTS.

## Purpose

Use `AesCipher` with mode helpers (`aes_cbc_*`, `aes_gcm_*`, â€¦) exported from `noxtls-crypto`.

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym (re-exported at crate root)`
- **Primary symbols:**
  - `AesCipher`
  - `noxtls_aes_cbc_encrypt`
  - `noxtls_aes_gcm_encrypt`
  - `noxtls_aes_ctr_apply`

**Functions and types:**

- **`AesCipher::new(key)`** - Parameters: `key` is AES key material of length 16, 24, or 32 bytes. Behavior: expands round keys and initializes an `AesCipher` context reused by mode helpers. Returns: initialized `AesCipher` wrapped in `Result`.
- **Mode functions** â€” Take `&AesCipher` plus mode-specific IV/nonce/AAD; see each mode page.

## Feature flags and policy

Standard `noxtls-crypto` build (ECB requires `hazardous-legacy-crypto`).

## Examples

```rust
use noxtls_crypto::AesCipher;

let key = [0x01u8; 32];
let cipher = AesCipher::new(&key)?;
let _ = cipher; // use with noxtls_aes_gcm_encrypt, noxtls_aes_cbc_encrypt, â€¦
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

Never reuse a nonce with the same AES key in GCM or CCM; prefer random IVs from a DRBG.

## Related

- [Symmetric topic](./sym)
- [AES-GCM](./aes_gcm)
