---
title: Camellia
---

# Camellia

## Algorithm

**Camellia** (ISO/IEC 18033-3, RFC 3713, and related national profiles) is a **128-bit block** cipher with **128-, 192-, or 256-bit** keys. In NoxTLS, **`CamelliaCipher::new`** expands the key once into internal round-key tables; **`encrypt_block`** and **`decrypt_block`** run one **16-byte** block at a time and return **`Result`** so callers can treat failures uniformly.

Round and FL-layer counts follow the Camellia definition for each key size (the `CamelliaCipher` implementation branches on 128-bit versus 192/256-bit material). Modes (CBC, CTR, CFB, OFB) layer IVs or counters on top of these primitives; see the per-mode pages below.

## Purpose

This page is the **hub** for Camellia in `noxtls-crypto`: build a **`CamelliaCipher`**, then pass **`&CamelliaCipher`** into the `camellia_*` mode helpers. Use Camellia when a Japanese or international standard or cipher suite names it; where the protocol allows a modern default, **AEAD** (for example [AES-GCM](./aes_gcm) or [ChaCha20-Poly1305](./chacha20_poly1305)) is often simpler for integrity.

**Mode pages**

- [Camellia-CBC](./camellia_cbc) · [Camellia-CTR](./camellia_ctr) · [Camellia-CFB](./camellia_cfb) · [Camellia-OFB](./camellia_ofb)
- [Camellia-ECB](./camellia_ecb) ( **`hazardous-legacy-crypto`** only )
- [Camellia (cipher object)](./camellia_shared) — `CamelliaCipher` and raw block APIs

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym` (re-exported at crate root)
- **Primary symbols:**
  - `CamelliaCipher`
  - `CamelliaCipher::encrypt_block` / `CamelliaCipher::decrypt_block`
  - Mode entry points (see mode pages above)

**Functions and types:**

- **`CamelliaCipher::new(key) -> Result<CamelliaCipher>`** - Parameters: `key` is **16, 24, or 32** bytes. Behavior: runs the Camellia key schedule. Returns: `CamelliaCipher` on success, or `InvalidLength` if the key size is not supported.
- **Block primitives** - **`encrypt_block(&self, block: &mut [u8; 16]) -> Result<()`>** and **`decrypt_block`** mutate one block in place; used by mode helpers and available for custom constructions.
- **Mode helpers** - Take `&CamelliaCipher` plus a **16-byte** IV or initial counter (per mode); CBC requires **block-aligned** buffers with **no** automatic padding. See each linked mode page for signatures and `Result` / `Vec` return types.

## Feature flags and policy

CBC, CTR, CFB, and OFB are in the **default** `noxtls-crypto` build. **Camellia-ECB** is exported only with **`hazardous-legacy-crypto`**.

## Examples

```rust
use noxtls_crypto::{CamelliaCipher, noxtls_camellia_ctr_apply};

let key = [0x12u8; 16];
let cipher = CamelliaCipher::new(&key)?;
let nonce_counter = [0u8; 16];
let plaintext = b"camellia-data";
let ciphertext = noxtls_camellia_ctr_apply(&cipher, &nonce_counter, plaintext);
let recovered = noxtls_camellia_ctr_apply(&cipher, &nonce_counter, &ciphertext);
assert_eq!(recovered, plaintext);
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

Treat **IVs, nonces, and counters** like other block-cipher modes: avoid reuse under the same key unless the standard defines a safe construction. Non-AEAD modes do **not** authenticate ciphertext; combine with a MAC or use AEAD where the protocol permits.

## Related

- [Symmetric topic](./sym)
- [AES](./aes)
