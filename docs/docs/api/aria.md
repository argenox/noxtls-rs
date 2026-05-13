---
title: ARIA
---

# ARIA

## Algorithm

**ARIA** (block cipher specified in KS X 1213 and related profiles) operates on **128-bit blocks** with **128-, 192-, or 256-bit** keys. In NoxTLS, `AriaCipher::new` expands the key once into round keys; **`encrypt_block`** and **`decrypt_block`** run one 16-byte block at a time and return **`Result`** so callers can handle rare internal failures consistently.

Round counts follow the standard: **12** rounds for 128-bit keys, **14** for 192-bit, **16** for 256-bit. Modes (CBC, CTR, CFB, OFB) combine these primitives with IVs or counters; they are documented on the per-mode pages below.

## Purpose

This page is the **hub** for ARIA in `noxtls-crypto`: build an **`AriaCipher`**, then call the mode helpers that take **`&AriaCipher`**. Use ARIA when a Korean or regional standard names it explicitly; where the protocol allows a modern default, **AEAD** (for example [AES-GCM](./aes_gcm) or [ChaCha20-Poly1305](./chacha20_poly1305)) is usually simpler for integrity.

**Mode pages**

- [ARIA-CBC](./aria_cbc) · [ARIA-CTR](./aria_ctr) · [ARIA-CFB](./aria_cfb) · [ARIA-OFB](./aria_ofb)
- [ARIA-ECB](./aria_ecb) ( **`hazardous-legacy-crypto`** only )

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym` (re-exported at crate root)
- **Primary symbols:**
  - `AriaCipher`
  - `AriaCipher::encrypt_block` / `AriaCipher::decrypt_block`
  - Mode entry points (see mode pages above)

**Functions and types:**

- **`AriaCipher::new(key) -> Result<AriaCipher>`** - Parameters: `key` is **16, 24, or 32** bytes. Behavior: runs the ARIA key schedule. Returns: `AriaCipher` on success, or `InvalidLength` if the key size is not supported.
- **Block primitives** - **`encrypt_block(&self, block: &mut [u8; 16]) -> Result<()`>** and **`decrypt_block`** mutate one block in place; used internally by modes and available for custom constructions.
- **Mode helpers** - Take `&AriaCipher` plus a **16-byte** IV or initial counter (per mode); CBC requires **block-aligned** buffers with **no** automatic padding. See each linked mode page for signatures and `Result` / `Vec` return types.

## Feature flags and policy

CBC, CTR, CFB, and OFB are in the **default** `noxtls-crypto` build. **ARIA-ECB** is exported only with **`hazardous-legacy-crypto`**.

## Examples

```rust
use noxtls_crypto::{AriaCipher, noxtls_aria_ctr_apply};

let key = [0x10u8; 16];
let cipher = AriaCipher::new(&key)?;
let nonce_counter = [0u8; 16];
let plaintext = b"aria-stream-data";
let ciphertext = noxtls_aria_ctr_apply(&cipher, &nonce_counter, plaintext);
let recovered = noxtls_aria_ctr_apply(&cipher, &nonce_counter, &ciphertext);
assert_eq!(recovered, plaintext);
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

Treat **IVs, nonces, and counters** like any other stream or CBC mode: avoid reuse under the same key unless the standard defines a safe construction. Non-AEAD modes do **not** authenticate ciphertext; combine with a MAC or use AEAD where the protocol permits.

## Related

- [Symmetric topic](./sym)
- [AES](./aes)
