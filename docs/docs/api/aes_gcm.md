---
title: AES-GCM
---

# AES-GCM

## Algorithm

**Galois/Counter Mode (GCM)** provides confidentiality and integrity. The caller supplies **additional authenticated data (AAD)** that is integrity-protected but not encryptedâ€”typical for record headers in TLS.

## Purpose

Authenticated encryption with associated data (AEAD) combining CTR mode and GHASH.

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym (re-exported at crate root)`
- **Primary symbols:**
  - `AesCipher`
  - `noxtls_aes_gcm_encrypt`
  - `noxtls_aes_gcm_decrypt`

**Functions and types:**

- **`noxtls_aes_gcm_encrypt(cipher, nonce, aad, plaintext) -> Result<(Vec<u8>, [u8; 16])>`** - Parameters: `cipher` is an initialized `AesCipher`, `nonce` is the per-message nonce, `aad` is additional authenticated data, and `plaintext` is input bytes. Behavior: performs AES-GCM authenticated encryption. Returns: `Result<(Vec<u8>, [u8; 16])>` with ciphertext and 16-byte authentication tag.
- **`noxtls_aes_gcm_decrypt(cipher, nonce, aad, ciphertext, tag) -> Result<Vec<u8>>`** - Parameters: `cipher` is an initialized `AesCipher`, `nonce` and `aad` must match encryption context, `ciphertext` is encrypted bytes, and `tag` is the 16-byte auth tag. Behavior: verifies tag and decrypts AES-GCM payload. Returns: `Result<Vec<u8>>` with plaintext bytes, or error when authentication fails.

## Feature flags and policy

Standard `noxtls-crypto` build.

## Examples

```rust
use noxtls_crypto::{AesCipher, noxtls_aes_gcm_decrypt, noxtls_aes_gcm_encrypt};

let key = [0x5Au8; 32];
let cipher = AesCipher::new(&key)?;
let nonce = b"unique-nonce"; // length per TLS/profile
let aad = b"metadata";
let plaintext = b"hello";
let (ct, tag) = noxtls_aes_gcm_encrypt(&cipher, nonce, aad, plaintext)?;
let pt = noxtls_aes_gcm_decrypt(&cipher, nonce, aad, &ct, &tag)?;
assert_eq!(pt, plaintext);
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

Use a fresh nonce for every encryption under a key; verify the 128-bit tag before using decrypted plaintext.

## Related

- [Symmetric topic](./sym)
- [TLS topic](./tls)
