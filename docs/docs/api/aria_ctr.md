---
title: ARIA-CTR
---

# ARIA-CTR

## Algorithm

**Counter (CTR)** mode with **ARIA** builds a keystream by encrypting a sequence of **16-byte counter blocks** with ARIA in the **forward (encrypt)** direction. Each keystream block is XORed with up to **16 bytes** of input. After each segment, the counter is incremented by **one** as a 128-bit value, with carry from the low-order byte toward the high-order end of the block.

Encryption and decryption are the **same** XOR with the same starting counter block. The caller chooses how the initial **16-byte** `nonce_counter` is split between a fixed nonce prefix and a running counter, per protocol.

## Purpose

Use **ARIA-CTR** with a shared `AriaCipher` for streaming-length payloads or when a standard specifies ARIA in CTR. CTR gives **confidentiality only** if counters never repeat under a key; it does **not** authenticate. Prefer an **AEAD** such as [AES-GCM](./aes_gcm) or [ChaCha20-Poly1305](./chacha20_poly1305) when you need integrity unless the profile forbids it.

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym` (re-exported at crate root)
- **Primary symbols:**
  - `AriaCipher`
  - `noxtls_aria_ctr_apply`
  - `noxtls_aria_ctr_encrypt`
  - `noxtls_aria_ctr_decrypt`

**Functions and types:**

- **`noxtls_aria_ctr_apply(cipher, nonce_counter, input) -> Vec<u8>`** - Parameters: `cipher` is an initialized `AriaCipher`; `nonce_counter` is the **16-byte** initial counter block; `input` is plaintext or ciphertext of any length. Behavior: XORs `input` with the ARIA-CTR keystream. Returns: output `Vec<u8>` of the same length (used for both encrypt and decrypt).
- **`noxtls_aria_ctr_encrypt(cipher, nonce_counter, plaintext) -> Vec<u8>`** - Same as `noxtls_aria_ctr_apply` for encrypt naming.
- **`noxtls_aria_ctr_decrypt(cipher, nonce_counter, ciphertext) -> Vec<u8>`** - Same keystream XOR as encrypt; name reflects decrypt usage with the same `nonce_counter`.

## Feature flags and policy

Standard `noxtls-crypto` build.

## Examples

```rust
use noxtls_core::Error;
use noxtls_crypto::{AriaCipher, noxtls_aria_ctr_decrypt, noxtls_aria_ctr_encrypt};

fn aria_ctr_roundtrip(
    cipher: &AriaCipher,
    nonce_counter: &[u8; 16],
    plaintext: &[u8],
) -> Result<(), Error> {
    let ciphertext = noxtls_aria_ctr_encrypt(cipher, nonce_counter, plaintext);
    let decrypted = noxtls_aria_ctr_decrypt(cipher, nonce_counter, &ciphertext);
    assert_eq!(decrypted, plaintext);
    Ok(())
}

let cipher = AriaCipher::new(&[0x44u8; 16])?;
let mut nonce_counter = [0u8; 16];
nonce_counter[0..8].copy_from_slice(b"profileN"); // illustrative; layout is protocol-specific
nonce_counter[15] = 1;

aria_ctr_roundtrip(&cipher, &nonce_counter, b"ctr-payload")?;
# Ok::<(), Error>(())
```

## Security and compatibility

**Never reuse** `(key, initial counter block)` for two different messages. Reuse leaks XOR of plaintexts. Plan counter width so the counter does not wrap within the key lifetime for your traffic. CTR ciphertext is **malleable**; add a MAC or use AEAD if you need integrity.

## Related

- [ARIA](./aria)
- [Symmetric topic](./sym)
- [AES-CTR](./aes_ctr)
