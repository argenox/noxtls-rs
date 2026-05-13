---
title: Camellia-CFB
---

# Camellia-CFB

## Algorithm

**Cipher feedback (CFB)** with **Camellia** uses a **16-byte shift register**. Each step encrypts the register with **Camellia in the forward direction** to produce up to **16 bytes** of keystream, XORed with the next input segment. The register is then shifted and extended with **ciphertext** bytes: on **encryption** the feedback is the ciphertext segment just produced; on **decryption** the feedback is the ciphertext segment from the input (decryption still only runs the block cipher in the encrypt direction on the register).

This implementation is **Camellia-CFB-128** (128-bit block / segment size). Output length equals input length. There is **no** authentication tag.

## Purpose

Use **Camellia-CFB** with a shared `CamelliaCipher` when a profile requires Camellia in CFB. For new designs that need integrity, prefer an **AEAD** such as [AES-GCM](./aes_gcm) or [ChaCha20-Poly1305](./chacha20_poly1305) unless the standard mandates Camellia-CFB plus a separate MAC.

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym` (re-exported at crate root)
- **Primary symbols:**
  - `CamelliaCipher`
  - `noxtls_camellia_cfb_encrypt`
  - `noxtls_camellia_cfb_decrypt`
  - `noxtls_camellia_cfb_apply`

**Functions and types:**

- **`noxtls_camellia_cfb_encrypt(cipher, iv, plaintext) -> Vec<u8>`** - Parameters: `cipher` is an initialized `CamelliaCipher` (128-, 192-, or 256-bit key); `iv` is a **16-byte** initial register; `plaintext` is arbitrary length. Behavior: Camellia-CFB-128 encryption. Returns: ciphertext `Vec<u8>` of the same length as `plaintext`.
- **`noxtls_camellia_cfb_decrypt(cipher, iv, ciphertext) -> Vec<u8>`** - Parameters: same `cipher` and **16-byte** `iv` as used at the start of that stream; `ciphertext` is the CFB ciphertext. Behavior: inverts CFB-128. Returns: plaintext `Vec<u8>` of the same length.
- **`noxtls_camellia_cfb_apply(cipher, iv, input) -> Vec<u8>`** - Same behavior as `noxtls_camellia_cfb_encrypt` (convenience alias for the forward CFB transform).

## Feature flags and policy

Standard `noxtls-crypto` build.

## Examples

```rust
use noxtls_crypto::{CamelliaCipher, noxtls_camellia_cfb_decrypt, noxtls_camellia_cfb_encrypt};

let cipher = CamelliaCipher::new(&[0x31u8; 16])?;
let iv = [0u8; 16];
let plaintext = b"cam-cfb";
let ciphertext = noxtls_camellia_cfb_encrypt(&cipher, &iv, plaintext);
let recovered = noxtls_camellia_cfb_decrypt(&cipher, &iv, &ciphertext);
assert_eq!(recovered.as_slice(), plaintext.as_slice());
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

Use an unpredictable **unique IV (register seed) per key and message** unless your protocol fixes IV derivation. CFB ciphertext is **malleable** and provides **no integrity**; pair with a MAC or use AEAD where allowed.

## Related

- [Camellia](./camellia)
- [Symmetric topic](./sym)
- [AES-CFB](./aes_cfb)
