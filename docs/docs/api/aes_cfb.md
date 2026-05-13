---
title: AES-CFB
---

# AES-CFB

## Algorithm

**Cipher feedback (CFB)** turns a block cipher into a stream-like primitive: a **16-byte shift register** is encrypted with AES; up to **16 bytes** of keystream are taken from the front of that block and XORed with the next segment of input. After each segment, the register is shifted left and the last segmentâ€™s bytes are appended (CFB-128 style with segment size matching the AES block size in this implementation).

For **encryption**, the bytes fed back into the register are the **ciphertext** segments. For **decryption**, feedback uses **ciphertext** segments as well (so decryption still calls the block cipher in the â€œencryptâ€ direction on the register). Output length always equals input length; there is **no** authentication tagâ€”CFB provides confidentiality only when used correctly, not integrity.

## Purpose

Expose **AES-CFB-128** on a shared `AesCipher` key schedule for legacy or interoperability scenarios (for example protocols that specify CFB). Prefer an **AEAD** such as [AES-GCM](./aes_gcm) or [AES-CCM](./aes_ccm) for new designs that need integrity.

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym` (re-exported at crate root)
- **Primary symbols:**
  - `AesCipher`
  - `noxtls_aes_cfb_encrypt`
  - `noxtls_aes_cfb_decrypt`
  - `noxtls_aes_cfb_apply`

**Functions and types:**

- **`noxtls_aes_cfb_encrypt(cipher, iv, plaintext) -> Vec<u8>`** - Parameters: `cipher` is an initialized `AesCipher`; `iv` is a **16-byte** initial register (often called the IV); `plaintext` is arbitrary length. Behavior: runs AES-CFB-128 encryption segment by segment. Returns: ciphertext bytes, same length as `plaintext`.
- **`noxtls_aes_cfb_decrypt(cipher, iv, ciphertext) -> Vec<u8>`** - Parameters: same `cipher` and **16-byte** `iv` as used at the start of that ciphertext stream; `ciphertext` is the CFB ciphertext. Behavior: inverts CFB-128 to recover plaintext. Returns: plaintext bytes, same length as `ciphertext`.
- **`noxtls_aes_cfb_apply(cipher, iv, input) -> Vec<u8>`** - Same behavior as `noxtls_aes_cfb_encrypt` (convenience entry point for the CFB â€œforwardâ€ transform).

## Feature flags and policy

Standard `noxtls-crypto` build.

## Examples

```rust
use noxtls_crypto::{AesCipher, noxtls_aes_cfb_decrypt, noxtls_aes_cfb_encrypt};

let key = [0x11u8; 24];
let cipher = AesCipher::new(&key)?;
let iv = [0xAAu8; 16];
let plaintext = b"stream-style payload";
let ciphertext = noxtls_aes_cfb_encrypt(&cipher, &iv, plaintext);
let recovered = noxtls_aes_cfb_decrypt(&cipher, &iv, &ciphertext);
assert_eq!(recovered.as_slice(), plaintext.as_slice());
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

Use an unpredictable **unique IV (register seed) per key and message** (or follow the profileâ€™s IV construction rules). Ciphertext is **malleable**: an attacker flipping bits in the ciphertext causes predictable plaintext changes unless you add a separate MAC or use AEAD. Do not confuse CFB with authenticated encryption.

## Related

- [Symmetric topic](./sym)
- [AES-OFB](./aes_ofb)
- [AES-GCM](./aes_gcm)
- [TLS topic](./tls)
