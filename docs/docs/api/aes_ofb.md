---
title: AES-OFB
---

# AES-OFB

## Algorithm

**Output feedback (OFB)** builds a keystream by repeatedly applying AES **encryption** (forward direction) to a **16-byte internal register**. The initial register is the supplied **IV**. Each step: the register is replaced by `AES_encrypt(register)`; up to **16 bytes** of that output are XORed with the next segment of input. Encryption and decryption are the **same** XOR operation with the same starting IV.

Unlike [AES-CTR](./aes_ctr), the next keystream material depends on a **chain** of block encryptions on the evolving register, not on a simple counter increment. There is **no** authentication tag; OFB provides confidentiality only when the IV is never reused under a key in a way that repeats keystream.

## Purpose

Document **AES-OFB** on a shared `AesCipher` for legacy or interoperability. Prefer **AEAD** (for example [AES-GCM](./aes_gcm) or [AES-CCM](./aes_ccm)) for new designs that need integrity.

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym` (re-exported at crate root)
- **Primary symbols:**
  - `AesCipher`
  - `noxtls_aes_ofb_apply`

**Functions and types:**

- **`noxtls_aes_ofb_apply(cipher, iv, input) -> Vec<u8>`** - Parameters: `cipher` is an initialized `AesCipher`; `iv` is a **16-byte** initial OFB shift register; `input` is plaintext or ciphertext of any length. Behavior: generates the OFB keystream and XORs it with `input`. Returns: output bytes, same length as `input` (used identically for encrypt and decrypt).

## Feature flags and policy

Standard `noxtls-crypto` build.

## Examples

```rust
use noxtls_crypto::{AesCipher, noxtls_aes_ofb_apply};

let key = [0x33u8; 32];
let cipher = AesCipher::new(&key)?;
let iv = [0x5Au8; 16];
let plaintext = b"ofb: encrypt and decrypt are the same xor";
let ciphertext = noxtls_aes_ofb_apply(&cipher, &iv, plaintext);
let roundtrip = noxtls_aes_ofb_apply(&cipher, &iv, &ciphertext);
assert_eq!(roundtrip.as_slice(), plaintext.as_slice());
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

Use an unpredictable **unique IV per key and message** (or follow the profileâ€™s IV rules). Reusing `(key, iv)` for different messages exposes XOR of plaintexts, as in other stream modes. Ciphertext is **malleable**; use a MAC or AEAD if you need integrity.

## Related

- [Symmetric topic](./sym)
- [AES-CTR](./aes_ctr)
- [AES-CFB](./aes_cfb)
- [AES-GCM](./aes_gcm)
- [TLS topic](./tls)
