---
title: Camellia-ECB
---

# Camellia-ECB

## Algorithm

**Camellia** is a 128-bit block cipher. **Electronic codebook (ECB)** encrypts each **16-byte block** with the same key and **no** initialization vector: identical plaintext blocks always yield **identical** ciphertext blocks, so message structure can leak.

These helpers require **block-aligned** input (length multiple of **16**). They do **not** add or remove padding; callers must pad or use another mode (for example [Camellia-CBC](./camellia_cbc)).

## Purpose

Expose **Camellia-ECB** only for **legacy interoperability**, tests, or as a primitive inside a higher-level construction. **Do not** use ECB as the sole protection for long or formatted messages; prefer [Camellia-CBC](./camellia_cbc), [Camellia-CTR](./camellia_ctr), or an AEAD where the protocol allows.

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym` (re-exported at crate root **only** when the feature below is enabled)
- **Primary symbols:**
  - `CamelliaCipher`
  - `noxtls_camellia_ecb_encrypt`
  - `noxtls_camellia_ecb_decrypt`

**Functions and types:**

- **`CamelliaCipher::new(key) -> Result<CamelliaCipher>`** - Parameters: `key` is **16, 24, or 32** bytes (128-, 192-, or 256-bit Camellia). Behavior: expands the Camellia key schedule. Returns: `CamelliaCipher` on success, or `InvalidLength` for unsupported key sizes.
- **`noxtls_camellia_ecb_encrypt(cipher, input) -> Result<Vec<u8>>`** - Parameters: `cipher` is an initialized `CamelliaCipher`; `input` must be **block-aligned**. Behavior: Camellia-ECB encryption block by block. Returns: ciphertext `Vec<u8>` of the same length, or `InvalidLength` if misaligned.
- **`noxtls_camellia_ecb_decrypt(cipher, input) -> Result<Vec<u8>>`** - Parameters: same `cipher`; `input` is ECB ciphertext, **block-aligned**. Behavior: Camellia-ECB decryption. Returns: plaintext `Vec<u8>` of the same length, or `InvalidLength` if misaligned.

## Feature flags and policy

`noxtls_camellia_ecb_encrypt` and `noxtls_camellia_ecb_decrypt` are compiled and exported only when **`hazardous-legacy-crypto`** is enabled on `noxtls-crypto`.

## Examples

```rust
// Requires `noxtls-crypto` with feature `hazardous-legacy-crypto`.
use noxtls_crypto::{CamelliaCipher, noxtls_camellia_ecb_decrypt, noxtls_camellia_ecb_encrypt};

let cipher = CamelliaCipher::new(&[0x61u8; 16])?;
let plaintext = [0xEEu8; 16];
let ciphertext = noxtls_camellia_ecb_encrypt(&cipher, &plaintext)?;
let recovered = noxtls_camellia_ecb_decrypt(&cipher, &ciphertext)?;
assert_eq!(recovered, plaintext);
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

ECB **does not hide** repeated plaintext blocks and provides **no integrity**. Keep usage narrow and reviewed; record **`hazardous-legacy-crypto`** in your SBOM when enabled.

## Related

- [Camellia](./camellia)
- [Symmetric topic](./sym)
- [AES-ECB](./aes_ecb)
- [Camellia-CBC](./camellia_cbc)
