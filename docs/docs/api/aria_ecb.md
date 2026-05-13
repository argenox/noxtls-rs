---
title: ARIA-ECB
---

# ARIA-ECB

## Algorithm

**ARIA** is a 128-bit block cipher (KR standard). **Electronic codebook (ECB)** encrypts each **16-byte block** with the same key and **no** initialization vector: identical plaintext blocks always produce **identical** ciphertext blocks, so structure in the message can leak.

These helpers require **block-aligned** input: length must be a multiple of **16**. They do **not** add or remove padding; callers must align payloads or use another mode (for example [ARIA-CBC](./aria_cbc)).

## Purpose

Expose **ARIA-ECB** only for **legacy interoperability**, test vectors, or as a primitive inside a higher-level construction. **Do not** use ECB as the sole protection for formatted or long messages; prefer [ARIA-CBC](./aria_cbc), [ARIA-CTR](./aria_ctr), or an AEAD elsewhere in the stack when the protocol allows.

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym` (re-exported at crate root **only** when the feature below is enabled)
- **Primary symbols:**
  - `AriaCipher`
  - `noxtls_aria_ecb_encrypt`
  - `noxtls_aria_ecb_decrypt`

**Functions and types:**

- **`AriaCipher::new(key) -> Result<AriaCipher>`** - Parameters: `key` is **16, 24, or 32** bytes (128-, 192-, or 256-bit ARIA). Behavior: expands the ARIA key schedule. Returns: `AriaCipher` on success, or `InvalidLength` for unsupported key sizes.
- **`noxtls_aria_ecb_encrypt(cipher, input) -> Result<Vec<u8>>`** - Parameters: `cipher` is an initialized `AriaCipher`; `input` must be **block-aligned** (length multiple of 16). Behavior: ARIA-ECB encryption block by block. Returns: ciphertext `Vec<u8>` of the same length, or `InvalidLength` if misaligned.
- **`noxtls_aria_ecb_decrypt(cipher, input) -> Result<Vec<u8>>`** - Parameters: same `cipher`; `input` is ECB ciphertext, **block-aligned**. Behavior: ARIA-ECB decryption. Returns: plaintext `Vec<u8>` of the same length, or `InvalidLength` if misaligned.

## Feature flags and policy

`noxtls_aria_ecb_encrypt` and `noxtls_aria_ecb_decrypt` are compiled and exported only when **`hazardous-legacy-crypto`** is enabled on `noxtls-crypto`.

## Examples

```rust
// Requires `noxtls-crypto` with feature `hazardous-legacy-crypto`.
use noxtls_crypto::{AriaCipher, noxtls_aria_ecb_decrypt, noxtls_aria_ecb_encrypt};

let key = [0x11u8; 16];
let cipher = AriaCipher::new(&key)?;
let plaintext = [0xA5u8; 16];
let ciphertext = noxtls_aria_ecb_encrypt(&cipher, &plaintext)?;
let roundtrip = noxtls_aria_ecb_decrypt(&cipher, &ciphertext)?;
assert_eq!(roundtrip, plaintext);
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

ECB **does not hide** repeated plaintext blocks and provides **no integrity**. It is inappropriate for typical “encrypt a payload” use. If you enable this API, keep usage narrow and reviewed.

## Related

- [ARIA](./aria)
- [Symmetric topic](./sym)
- [AES-ECB](./aes_ecb)
- [ARIA-CBC](./aria_cbc)
