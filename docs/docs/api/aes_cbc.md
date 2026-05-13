---
title: AES-CBC
---

# AES-CBC

## Algorithm

**CBC** encrypts 16-byte blocks; the IV must be unpredictable for many threat models (TLS 1.2 uses record IV construction rules). Padding and plaintext length must be block-aligned for these helpers.

## Purpose

Cipher block chaining: each block XORs with the previous ciphertext block (or IV).

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym (re-exported at crate root)`
- **Primary symbols:**
  - `AesCipher`
  - `noxtls_aes_cbc_encrypt`
  - `noxtls_aes_cbc_decrypt`

**Functions and types:**

- **`noxtls_aes_cbc_encrypt(cipher, iv, plaintext) -> Result<Vec<u8>>`** - Parameters: `cipher` is an initialized `AesCipher`, `iv` is a 16-byte initialization vector, and `plaintext` is the input buffer. Behavior: encrypts plaintext in CBC mode using the provided IV. Returns: `Result<Vec<u8>>` containing ciphertext bytes on success.
- **`noxtls_aes_cbc_decrypt(cipher, iv, ciphertext) -> Result<Vec<u8>>`** - Parameters: `cipher` is an initialized `AesCipher`, `iv` is the same 16-byte IV context used for that data unit, and `ciphertext` is encrypted input bytes. Behavior: decrypts CBC ciphertext back to plaintext. Returns: `Result<Vec<u8>>` containing plaintext bytes on success.

## Feature flags and policy

Standard `noxtls-crypto` build.

## Examples

```rust
use noxtls_crypto::{AesCipher, noxtls_aes_cbc_decrypt, noxtls_aes_cbc_encrypt};

let key = [0x03u8; 16];
let cipher = AesCipher::new(&key)?;
let iv = [0u8; 16];
let plaintext = [0x01u8; 16];
let ciphertext = noxtls_aes_cbc_encrypt(&cipher, &iv, &plaintext)?;
let roundtrip = noxtls_aes_cbc_decrypt(&cipher, &iv, &ciphertext)?;
assert_eq!(roundtrip, plaintext);
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

CBC does not provide authenticationâ€”pair with HMAC or use AEAD (GCM/CCM) for new designs.

## Related

- [Symmetric topic](./sym)
- [AES](./aes)
