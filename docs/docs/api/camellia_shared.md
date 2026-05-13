---
title: Camellia (cipher object)
---

# Camellia (cipher object)

## Algorithm

**Camellia** is a 128-bit block cipher with **128-, 192-, or 256-bit** keys. The **`CamelliaCipher`** type holds the expanded **round-key material** (internal `kw`, `ke`, and `k` tables derived from the raw key) so each **16-byte block** operation reuses that schedule instead of re-deriving keys on every call.

Block primitives run the full Camellia round structure for the configured key size (fewer rounds for 128-bit keys than for 192/256). Mode helpers ([CBC](./camellia_cbc), [CTR](./camellia_ctr), [CFB](./camellia_cfb), [OFB](./camellia_ofb), [ECB](./camellia_ecb)) all take **`&CamelliaCipher`** and call **`encrypt_block`** / **`decrypt_block`** internally as needed.

## Purpose

Build a **`CamelliaCipher` once** with **`CamelliaCipher::new`**, then pass **`&cipher`** into the `camellia_*` mode functions for the lifetime of that key. **`CamelliaCipher` is `Clone`**, so you can duplicate a cheap handle to the same schedule (for example one copy per task) without re-running the key schedule.

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym` (re-exported at crate root)
- **Primary symbols:**
  - `CamelliaCipher`

**Functions and types:**

- **`CamelliaCipher::new(key) -> Result<CamelliaCipher>`** - Parameters: `key` is **16, 24, or 32** bytes. Behavior: expands Camellia round keys. Returns: `CamelliaCipher` on success, or `InvalidLength` if the key size is not supported.
- **`encrypt_block(&self, block: &mut [u8; 16]) -> Result<()`>** - Parameters: one **16-byte** block buffer. Behavior: encrypts in place with the forward cipher. Returns: `Ok(())` on success (or an error if an internal invariant fails).
- **`decrypt_block(&self, block: &mut [u8; 16]) -> Result<()`>** - Parameters: one **16-byte** ciphertext block. Behavior: decrypts in place. Returns: `Ok(())` on success.

Use the mode pages for CBC/CTR/CFB/OFB/ECB entry points; ECB requires the **`hazardous-legacy-crypto`** feature on `noxtls-crypto`.

## Feature flags and policy

`CamelliaCipher` and non-ECB modes are in the **default** build. **Camellia-ECB** helpers are behind **`hazardous-legacy-crypto`**.

## Examples

```rust
use noxtls_crypto::{CamelliaCipher, noxtls_camellia_ctr_apply};

let key = [0x71u8; 16];
let cipher = CamelliaCipher::new(&key)?;
let nonce_counter = [0u8; 16];
let out = noxtls_camellia_ctr_apply(&cipher, &nonce_counter, b"data");
assert_eq!(out.len(), 4);
# Ok::<(), noxtls_core::Error>(())
```

Single-block use (custom protocol framing):

```rust
use noxtls_crypto::CamelliaCipher;

let cipher = CamelliaCipher::new(&[0x55u8; 32])?;
let mut block = *b"1234567890123456";
cipher.encrypt_block(&mut block)?;
cipher.decrypt_block(&mut block)?;
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

Protect raw key bytes like any symmetric key: zeroize copies when your platform policy requires it, and avoid logging `CamelliaCipher` contents. **`Clone` duplicates the schedule**, not a new key; every clone can encrypt or decrypt with the same key. IV, counter, and MAC rules are enforced by the **mode** you choose, not by `CamelliaCipher` itself.

## Related

- [Camellia](./camellia)
- [Symmetric topic](./sym)
- [AES (cipher object)](./aes_shared)
