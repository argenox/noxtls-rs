---
title: AES-ECB
---

# AES-ECB

## Algorithm

**Electronic codebook (ECB)** encrypts each **16-byte AES block** independently with the same key. There is **no** initialization vector: equal plaintext blocks under the same key always produce **equal** ciphertext blocks, which leaks structure (repeated blocks are visible in the ciphertext).

These helpers require **block-aligned** input: length must be a multiple of **16**. They do **not** add or remove padding; callers that need less than a full block must define padding or use another mode (for example [AES-CBC](./aes_cbc)).

## Purpose

Expose **AES-ECB** for rare interoperability, tests, or building blocks inside a higher-level construction. **Do not** use ECB as the sole protection for long or formatted messages; prefer [AES-CBC](./aes_cbc), [AES-CTR](./aes_ctr), or an **AEAD** such as [AES-GCM](./aes_gcm).

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym` (re-exported at crate root **only** when the feature below is enabled)
- **Primary symbols:**
  - `AesCipher`
  - `noxtls_aes_ecb_encrypt`
  - `noxtls_aes_ecb_decrypt`

**Functions and types:**

- **`noxtls_aes_ecb_encrypt(cipher, input) -> Result<Vec<u8>>`** - Parameters: `cipher` is an initialized `AesCipher`; `input` must be **block-aligned** (length multiple of 16). Behavior: AES-ECB encryption block by block. Returns: ciphertext `Vec<u8>` of the same length as `input`, or `InvalidLength` if `input` is not a multiple of 16 bytes.
- **`noxtls_aes_ecb_decrypt(cipher, input) -> Result<Vec<u8>>`** - Parameters: same `cipher`; `input` is ECB ciphertext, also **block-aligned**. Behavior: AES-ECB decryption block by block. Returns: plaintext `Vec<u8>` of the same length, or `InvalidLength` if misaligned.

## Feature flags and policy

The symbols `noxtls_aes_ecb_encrypt` and `noxtls_aes_ecb_decrypt` are compiled and exported only when **`hazardous-legacy-crypto`** is enabled on `noxtls-crypto` (for example `noxtls-crypto = { ..., features = ["hazardous-legacy-crypto"] }` in `Cargo.toml`).

## Examples

```rust
// Requires `noxtls-crypto` with feature `hazardous-legacy-crypto`.
use noxtls_crypto::{AesCipher, noxtls_aes_ecb_decrypt, noxtls_aes_ecb_encrypt};

let key = [0x0Fu8; 16];
let cipher = AesCipher::new(&key)?;
let plaintext = [0x01u8; 16]; // one block; longer data must stay 16-byte aligned
let ciphertext = noxtls_aes_ecb_encrypt(&cipher, &plaintext)?;
let roundtrip = noxtls_aes_ecb_decrypt(&cipher, &ciphertext)?;
assert_eq!(roundtrip, plaintext);
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

ECB **does not hide** repeated plaintext blocks and provides **no integrity**. It is unsuitable for typical â€œencrypt a file or protocol payloadâ€ use. Modern protocols use other modes or AEAD; if you use this API, confine it to narrow, reviewed cases and supply alignment and any padding at a higher layer yourself.

## Related

- [Symmetric topic](./sym)
- [AES-CBC](./aes_cbc)
- [AES-GCM](./aes_gcm)
- [TLS topic](./tls)
