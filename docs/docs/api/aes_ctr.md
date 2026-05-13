---
title: AES-CTR
---

# AES-CTR

## Algorithm

**Counter (CTR)** mode builds a keystream by encrypting a sequence of **16-byte counter blocks** with AES in the forward (encrypt) direction. Each keystream block is XORed with up to **16 bytes** of input. The next counter is the previous 128-bit value plus **one**, with carry from the low-order byte toward the high-order byte of the block.

Encryption and decryption are the **same** operation: XOR with the same keystream. This API takes a single **initial counter block** (`nonce_counter`); the caller is responsible for choosing its layout (for example a fixed nonce prefix with a running counter in the low bytes, per your protocol).

## Purpose

Document **AES-CTR** on a shared `AesCipher` for streaming-length data and interoperability. CTR provides **confidentiality only** when the counter is never reused under a key; it does **not** provide integrity. Prefer an **AEAD** such as [AES-GCM](./aes_gcm) or [AES-CCM](./aes_ccm) when you need authentication.

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym` (re-exported at crate root)
- **Primary symbols:**
  - `AesCipher`
  - `noxtls_aes_ctr_apply`

**Functions and types:**

- **`noxtls_aes_ctr_apply(cipher, nonce_counter, input) -> Vec<u8>`** - Parameters: `cipher` is an initialized `AesCipher`; `nonce_counter` is the **16-byte** initial counter block for this stream; `input` is plaintext or ciphertext of any length. Behavior: generates the CTR keystream from successive encrypted counter values and XORs it with `input`. Returns: output bytes, same length as `input` (used identically for encrypt and decrypt).

## Feature flags and policy

Standard `noxtls-crypto` build.

## Examples

```rust
use noxtls_crypto::{AesCipher, noxtls_aes_ctr_apply};

let key = [0x22u8; 16];
let cipher = AesCipher::new(&key)?;
// Initial counter block for this message (must be unique per key use)
let mut counter_block = [0u8; 16];
counter_block[0..8].copy_from_slice(b"fixedNce"); // illustrative layout
counter_block[15] = 1; // starting counter byte (protocol-specific)

let plaintext = b"same op for decrypt: xor twice with same stream";
let ciphertext = noxtls_aes_ctr_apply(&cipher, &counter_block, plaintext);
let roundtrip = noxtls_aes_ctr_apply(&cipher, &counter_block, &ciphertext);
assert_eq!(roundtrip.as_slice(), plaintext);
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

**Never reuse** `(key, initial counter block)` for two different messages: reuse leaks XOR of plaintexts. Choose counter width and nonce layout so counters cannot wrap within a keyâ€™s lifetime for your traffic model. CTR ciphertext is **malleable**; pair with a MAC or use AEAD if you need integrity.

## Related

- [Symmetric topic](./sym)
- [AES-CFB](./aes_cfb)
- [AES-GCM](./aes_gcm)
- [TLS topic](./tls)
