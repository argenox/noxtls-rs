---
title: ARIA-OFB
---

# ARIA-OFB

## Algorithm

**Output feedback (OFB)** with **ARIA** builds a keystream from a **16-byte register**. Each step replaces the register with **`ARIA_encrypt(register)`** (forward cipher only), then XORs up to **16 bytes** of that output with the next input segment. The **IV** seeds the register before the first encryption.

Encryption and decryption use the **same** XOR with the same IV-derived keystream. Unlike [ARIA-CTR](./aria_ctr), the next keystream block depends on a **chain** of ARIA encryptions on the register, not on incrementing a counter. There is **no** authentication tag.

## Purpose

Use **ARIA-OFB** when a legacy profile requires it. For new work that needs integrity, prefer an **AEAD** such as [AES-GCM](./aes_gcm) or [ChaCha20-Poly1305](./chacha20_poly1305).

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym` (re-exported at crate root)
- **Primary symbols:**
  - `AriaCipher`
  - `noxtls_aria_ofb_apply`
  - `noxtls_aria_ofb_encrypt`
  - `noxtls_aria_ofb_decrypt`

**Functions and types:**

- **`noxtls_aria_ofb_apply(cipher, iv, input) -> Vec<u8>`** - Parameters: `cipher` is an initialized `AriaCipher`; `iv` is a **16-byte** initial OFB register; `input` is plaintext or ciphertext of any length. Behavior: XORs `input` with the ARIA-OFB keystream. Returns: output `Vec<u8>` of the same length (encrypt and decrypt are the same operation).
- **`noxtls_aria_ofb_encrypt(cipher, iv, plaintext) -> Vec<u8>`** - Same as `noxtls_aria_ofb_apply` (naming for encryption).
- **`noxtls_aria_ofb_decrypt(cipher, iv, ciphertext) -> Vec<u8>`** - Same keystream XOR as encrypt; use the same `iv` as for encryption.

## Feature flags and policy

Standard `noxtls-crypto` build.

## Examples

```rust
use noxtls_crypto::{AriaCipher, noxtls_aria_ofb_decrypt, noxtls_aria_ofb_encrypt};

let cipher = AriaCipher::new(&[0x55u8; 16])?;
let iv = [0u8; 16];
let plaintext = b"ofb-mode";
let ciphertext = noxtls_aria_ofb_encrypt(&cipher, &iv, plaintext);
let recovered = noxtls_aria_ofb_decrypt(&cipher, &iv, &ciphertext);
assert_eq!(recovered.as_slice(), plaintext.as_slice());
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

Use an unpredictable **unique IV per key and message** (or follow the profile’s IV rules). Reusing `(key, iv)` for different messages exposes XOR of plaintexts. Ciphertext is **malleable**; add a MAC or AEAD if you need integrity.

## Related

- [ARIA](./aria)
- [Symmetric topic](./sym)
- [AES-OFB](./aes_ofb)
