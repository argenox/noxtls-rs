---
title: AES-XTS
---

# AES-XTS

## Algorithm

**XTS** (XEX-based tweaked-codebook mode with ciphertext stealing), standardized in **IEEE Std 1619**, is meant to encrypt **fixed data units** such as disk sectors: each unit gets a distinct **tweak** so equal plaintext blocks in different positions or sectors do not yield identical ciphertext. It is a poor fit for arbitrary network messages; use an IV or nonce with a conventional mode or an **AEAD** instead.

In this library, XTS uses **two** expanded AES keys: **`cipher_a`** (data key) encrypts or decrypts payload blocks, and **`cipher_b`** (tweak key) derives the running tweak from a **16-byte tweak input** `tweak`. The implementation first sets the working tweak to `E_K2(tweak)` (AES encrypt of the tweak block with the tweak key), then for each 16-byte block XORs the tweak, applies `cipher_a` in the appropriate direction, XORs the tweak again, and updates the tweak by **multiplication by x** in the binary field GF(2^128) (the usual XTS â€œalphaâ€ step) before the next block.

**Input length:** the data unit must be **at least 16 bytes**. If the length is **not** a multiple of 16, **ciphertext stealing** handles the trailing short segment so ciphertext length equals plaintext length (no external padding layer).

## Purpose

Document AES-XTS for **sector-style** encryption: callers supply the per-unit tweak (for example a sector index encoded in the tweak block), two `AesCipher` instances for the data and tweak keys, and a contiguous plaintext or ciphertext buffer.

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym (re-exported at crate root)`
- **Primary symbols:**
  - `AesCipher`
  - `noxtls_aes_xts_encrypt`
  - `noxtls_aes_xts_decrypt`

**Functions and types:**

- **`noxtls_aes_xts_encrypt(cipher_a, cipher_b, tweak, plaintext) -> Result<Vec<u8>>`** - Parameters: `cipher_a` is the **data** AES key schedule; `cipher_b` is the **tweak** AES key schedule; `tweak` is a **16-byte** perâ€“data-unit value (for example a sector index) that seeds the tweak chain via `E_K2(tweak)`; `plaintext` is the unit to encrypt, **length â‰¥ 16** (any length â‰¥ 16 is allowed; nonâ€“16-byte-aligned lengths use ciphertext stealing). Behavior: AES-XTS encryption over the whole buffer. Returns: ciphertext `Vec<u8>` of the same length as `plaintext`, or `InvalidLength` if shorter than one block.
- **`noxtls_aes_xts_decrypt(cipher_a, cipher_b, tweak, ciphertext) -> Result<Vec<u8>>`** - Parameters: same keys and `tweak` as used for that unitâ€™s encryption; `ciphertext` is the XTS ciphertext, **length â‰¥ 16**. Behavior: inverse XTS transform, including ciphertext stealing when length is not a multiple of 16. Returns: plaintext `Vec<u8>` of the same length, or errors on invalid length.

## Feature flags and policy

Standard `noxtls-crypto` build.

## Examples

```rust
use noxtls_crypto::{AesCipher, noxtls_aes_xts_decrypt, noxtls_aes_xts_encrypt};

let data_key = AesCipher::new(&[0x01u8; 32])?;
let tweak_key = AesCipher::new(&[0x02u8; 32])?;
let tweak = [0u8; 16];
let plaintext = [0xAAu8; 32];
let ciphertext = noxtls_aes_xts_encrypt(&data_key, &tweak_key, &tweak, &plaintext)?;
let recovered = noxtls_aes_xts_decrypt(&data_key, &tweak_key, &tweak, &ciphertext)?;
assert_eq!(recovered, plaintext);
// Lengths â‰¥ 16 that are not a multiple of 16 use ciphertext stealing (same length in/out).
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

Use a **fresh tweak** for each data unit you must distinguish (for example each sector index within a key scope). Reusing the same `(key pair, tweak)` for different units weakens the intended domain separation. XTS provides **confidentiality for whole-unit encryption**, not **authentication**; an attacker can still flip ciphertext bits in many threat models unless integrity is handled elsewhere.

Follow your platformâ€™s rules for how the tweak is derived (128-bit tweak field, endianness, and how partial sectors are handled). Typical XTS key bundles are **256-bit** (two 128-bit AES keys) or **512-bit** (two 256-bit keys), realized here as two separate `AesCipher` values from two key byte arrays.

## Related

- [Symmetric topic](./sym)
- [AES-GCM](./aes_gcm)
- [TLS topic](./tls)
