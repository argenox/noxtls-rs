---
title: Camellia-CBC
---

# Camellia-CBC

## Algorithm

**Camellia** is a 128-bit block cipher (standardized internationally, widely deployed in Japan and other regions). **Cipher block chaining (CBC)** XORs each plaintext block with the previous **ciphertext** block before encryption; the first block uses a **16-byte IV**. Decryption walks the chain backward with the same IV.

These helpers require **block-aligned** buffers: plaintext and ciphertext lengths must be multiples of **16**. They do **not** add or strip PKCS padding; callers must pad or choose another mode if lengths are not already a whole number of blocks.

## Purpose

Use **Camellia-CBC** with a shared `CamelliaCipher` when a standard or deployment specifies Camellia in CBC (for example TLS cipher suite or national profile). For new designs that need integrity at the record layer, prefer an **AEAD** such as [AES-GCM](./aes_gcm) or [ChaCha20-Poly1305](./chacha20_poly1305) unless the protocol mandates Camellia-CBC plus a separate MAC.

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym` (re-exported at crate root)
- **Primary symbols:**
  - `CamelliaCipher`
  - `noxtls_camellia_cbc_encrypt`
  - `noxtls_camellia_cbc_decrypt`

**Functions and types:**

- **`noxtls_camellia_cbc_encrypt(cipher, iv, plaintext) -> Result<Vec<u8>>`** - Parameters: `cipher` is an initialized `CamelliaCipher` (128-, 192-, or 256-bit key via `CamelliaCipher::new`); `iv` is a **16-byte** initialization vector; `plaintext` must be **block-aligned** (length multiple of 16). Behavior: encrypts in Camellia-CBC. Returns: ciphertext `Vec<u8>` of the same length on success, or `InvalidLength` if the buffer is not a multiple of 16 bytes.
- **`noxtls_camellia_cbc_decrypt(cipher, iv, ciphertext) -> Result<Vec<u8>>`** - Parameters: same `cipher` and **16-byte** `iv` as used for that CBC stream; `ciphertext` must also be **block-aligned**. Behavior: decrypts Camellia-CBC. Returns: plaintext `Vec<u8>` of the same length on success, or `InvalidLength` if misaligned.

## Feature flags and policy

Camellia-CBC is in the **default** `noxtls-crypto` build. **Camellia-ECB** is only available with **`hazardous-legacy-crypto`**.

## Examples

```rust
use noxtls_crypto::{CamelliaCipher, noxtls_camellia_cbc_decrypt, noxtls_camellia_cbc_encrypt};

let cipher = CamelliaCipher::new(&[0x21u8; 16])?;
let iv = [0u8; 16];
let plaintext = [0x99u8; 16];
let ciphertext = noxtls_camellia_cbc_encrypt(&cipher, &iv, &plaintext)?;
let recovered = noxtls_camellia_cbc_decrypt(&cipher, &iv, &ciphertext)?;
assert_eq!(recovered, plaintext);
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

Use an unpredictable **unique IV per key and message** when your threat model requires semantic security (TLS defines how record IVs are formed). CBC does **not** authenticate ciphertext; ciphertext is **malleable** at the block level. Combine with a MAC or use AEAD where the protocol allows.

## Related

- [Camellia](./camellia)
- [Symmetric topic](./sym)
- [AES-CBC](./aes_cbc)
