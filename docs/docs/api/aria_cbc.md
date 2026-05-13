---
title: ARIA-CBC
---

# ARIA-CBC

## Algorithm

**ARIA** is a 128-bit block cipher (KR standard, roughly comparable role to AES in Korean profiles). **CBC** XORs each plaintext block with the previous **ciphertext** block before encryption (the first block uses the **IV**). Decryption inverts that chain using the same IV.

These helpers use a **16-byte IV** and require **block-aligned** buffers: `plaintext` and `ciphertext` lengths must be multiples of **16**. They do **not** apply or strip PKCS padding; callers must pad or choose another mode if payloads are not already a whole number of blocks.

## Purpose

Use **ARIA-CBC** with a shared `AriaCipher` key schedule when a protocol or deployment specifies ARIA in CBC (for example national or industry profiles). For new designs that need integrity, prefer an AEAD (for example [AES-GCM](./aes_gcm) or [ChaCha20-Poly1305](./chacha20_poly1305)) unless the profile mandates ARIA-CBC plus a separate MAC.

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym` (re-exported at crate root)
- **Primary symbols:**
  - `AriaCipher`
  - `noxtls_aria_cbc_encrypt`
  - `noxtls_aria_cbc_decrypt`

**Functions and types:**

- **`noxtls_aria_cbc_encrypt(cipher, iv, plaintext) -> Result<Vec<u8>>`** - Parameters: `cipher` is an initialized `AriaCipher` (128-, 192-, or 256-bit key via `AriaCipher::new`); `iv` is a **16-byte** initialization vector; `plaintext` must be **block-aligned** (length multiple of 16). Behavior: encrypts in ARIA-CBC. Returns: ciphertext `Vec<u8>` of the same length on success, or `InvalidLength` if the buffer is not a multiple of 16 bytes.
- **`noxtls_aria_cbc_decrypt(cipher, iv, ciphertext) -> Result<Vec<u8>>`** - Parameters: same `cipher` and **16-byte** `iv` as used for that CBC stream; `ciphertext` must also be **block-aligned**. Behavior: decrypts ARIA-CBC. Returns: plaintext `Vec<u8>` of the same length on success, or `InvalidLength` if misaligned.

## Feature flags and policy

Standard `noxtls-crypto` build (ARIA-CBC is always available; ARIA-ECB is behind `hazardous-legacy-crypto`).

## Examples

```rust
use noxtls_crypto::{AriaCipher, noxtls_aria_cbc_decrypt, noxtls_aria_cbc_encrypt};

let cipher = AriaCipher::new(&[0x22u8; 16])?;
let iv = [0u8; 16];
let plaintext = [0x44u8; 16];
let ciphertext = noxtls_aria_cbc_encrypt(&cipher, &iv, &plaintext)?;
let recovered = noxtls_aria_cbc_decrypt(&cipher, &iv, &ciphertext)?;
assert_eq!(recovered, plaintext);
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

Use an unpredictable **unique IV per key and message** when your threat model requires semantic security (TLS and similar standards define how IVs are formed). CBC does **not** authenticate ciphertext; bit flips propagate predictably at the block level. Combine with a MAC or use AEAD where the protocol allows.

## Related

- [ARIA](./aria)
- [Symmetric topic](./sym)
- [AES-CBC](./aes_cbc)
