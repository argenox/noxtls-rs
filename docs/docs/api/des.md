---
title: DES (legacy)
---

# DES (legacy)

## Algorithm

**DES** (Data Encryption Standard) is a **64-bit block** cipher with an **8-byte (64-bit) key** including **parity**; the effective key space is **56 bits**, which is far too small for modern security margins.

In **`noxtls-crypto`**, **`DesCipher`** holds a **single-DES** 16-round Feistel schedule. **Block size is always 8 bytes.** Modes follow the usual patterns:

- **ECB** — Independent 8-byte blocks, **no IV** (pattern leakage).
- **CBC** — 8-byte IV, **block-aligned** plaintext/ciphertext, **no** automatic padding in these helpers.
- **CTR** — 8-byte initial counter/nonce block; keystream from **`encrypt_block`** on the register; counter incremented as a **64-bit** value with carry (see `increment_be_64` in the implementation).
- **CFB-64** and **OFB** — 8-byte IV/register, segment size tied to the **8-byte** DES block.

**Triple-DES (3DES / TDEA)** is **not** implemented as a separate key schedule or API in this repository: only **single DES** with **`DesCipher::new(&[u8; 8])`** is available. If your OEM document referred to 3DES, map that requirement to supported modern ciphers (for example **AES** or **ChaCha20-Poly1305**) unless you add a vetted 3DES implementation elsewhere.

## Purpose

Interoperate with **legacy** systems that still require DES in a controlled, reviewed context. **Do not** use DES for new confidentiality requirements; prefer **[AES](./aes)** or **[ChaCha20-Poly1305](./chacha20_poly1305)**.

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym` (re-exported at crate root **only** with the feature below)
- **Primary symbols:**
  - `DesCipher`
  - `noxtls_des_ecb_encrypt` / `noxtls_des_ecb_decrypt`
  - `noxtls_des_cbc_encrypt` / `noxtls_des_cbc_decrypt`
  - `noxtls_des_ctr_apply` / `noxtls_des_ctr_encrypt` / `noxtls_des_ctr_decrypt`
  - `noxtls_des_cfb_apply` / `noxtls_des_cfb_encrypt` / `noxtls_des_cfb_decrypt`
  - `noxtls_des_ofb_apply` / `noxtls_des_ofb_encrypt` / `noxtls_des_ofb_decrypt`

**`DesCipher`**

- **`DesCipher::new(key: &[u8; 8]) -> Result<DesCipher>`** — Builds the DES key schedule. Returns **`InvalidLength`** if the key is **all zero bytes** (otherwise parity is not otherwise validated here beyond that check). **`encrypt_block` / `decrypt_block`** operate on **`[u8; 8]`** in place and return **`Result<()>`**.

**Mode helpers (all use 8-byte blocks; ECB/CBC require length multiple of 8)**

- **`noxtls_des_ecb_encrypt` / `noxtls_des_ecb_decrypt`** — **`Result<Vec<u8>>`**, **`InvalidLength`** if not block-aligned.
- **`noxtls_des_cbc_encrypt` / `noxtls_des_cbc_decrypt`** — **`iv: &[u8; 8]`**, block-aligned buffers, **`Result<Vec<u8>>`**.
- **`noxtls_des_ctr_apply`**, **`noxtls_des_ctr_encrypt`**, **`noxtls_des_ctr_decrypt`** — **`nonce_counter: &[u8; 8]`**, arbitrary length, **`Vec<u8>`** (same XOR path for encrypt/decrypt).
- **`des_cfb_*`** — **DES-CFB-64**; **`noxtls_des_cfb_apply`** matches **`noxtls_des_cfb_encrypt`**.
- **`des_ofb_*`** — **DES-OFB** with 8-byte IV; encrypt/decrypt names share the same keystream XOR path.

None of the mode helpers add PKCS padding.

## Feature flags and policy

All **`DesCipher`** and **`des_*`** symbols are compiled and exported only when **`hazardous-legacy-crypto`** is enabled on **`noxtls-crypto`** (and thus on **`noxtls`** when you forward that feature). See [Build configuration](./build_config).

## Examples

```rust
// Requires `noxtls-crypto` with feature `hazardous-legacy-crypto`.
use noxtls_crypto::{DesCipher, noxtls_des_cbc_decrypt, noxtls_des_cbc_encrypt};

let key = [0x01u8, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
let cipher = DesCipher::new(&key).unwrap();
let iv = [0u8; 8];
let plaintext = [0x5Au8; 8]; // one DES block
let ciphertext = noxtls_des_cbc_encrypt(&cipher, &iv, &plaintext).unwrap();
let recovered = noxtls_des_cbc_decrypt(&cipher, &iv, &ciphertext).unwrap();
assert_eq!(recovered, plaintext);
```

## Security and compatibility

DES is **cryptographically obsolete** for general use (small key space, small block width enabling **sweet32**-class birthday issues on high-volume protocols). Use only behind explicit **risk acceptance**, narrow protocol scope, and migration plans. Non-AEAD modes provide **no integrity**. See [Security](../security).

## Related

- [Symmetric topic](./sym)
- [AES-CBC](./aes_cbc)
- [RC4](./rc4)
