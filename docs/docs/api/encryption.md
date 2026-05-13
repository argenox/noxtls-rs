---
title: Encryption (symmetric)
---

# Encryption (symmetric)

## Algorithm

This page is a hub for symmetric primitives: block ciphers (AES/ARIA/Camellia), stream cipher (ChaCha20), and AEAD constructions.

## Purpose

Product-level map of symmetric primitives shipped in `noxtls-crypto`.

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym`
- **Primary symbols:**
  - `AesCipher`
  - `AriaCipher`
  - `CamelliaCipher`
  - `ChaCha20`
  - `noxtls_chacha20_poly1305_encrypt` / `noxtls_chacha20_poly1305_decrypt`

**Functions and types:**

- **Cipher constructors:** `AesCipher::new`, `AriaCipher::new`, `CamelliaCipher::new`
- **AEAD:** `noxtls_aes_gcm_encrypt` / `noxtls_aes_gcm_decrypt`, `noxtls_aes_ccm_encrypt` / `noxtls_aes_ccm_decrypt`, `noxtls_chacha20_poly1305_encrypt` / `noxtls_chacha20_poly1305_decrypt`
- **Streaming/block modes:** CBC/CTR/CFB/OFB helpers for compatibility profiles

## Feature flags and policy

Legacy: `hazardous-legacy-crypto` enables DES, RC4, and ECB family exports.

## Examples

```rust
use noxtls_crypto::{AesCipher, noxtls_aes_gcm_encrypt};

let cipher = AesCipher::new(&[0x01u8; 32])?;
let nonce = b"nonce-123456";
let aad = b"header";
let plaintext = b"payload";
let (_ciphertext, _tag) = noxtls_aes_gcm_encrypt(&cipher, nonce, aad, plaintext)?;
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

Use AEAD for new designs; isolate legacy algorithms behind policy.

## Related

- [Symmetric topic](./sym)
- [AES](./aes)
