---
title: AES (cipher object)
---

# AES (cipher object)

## Purpose

`AesCipher` holds expanded round keys for all AES modes.

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym (re-exported at crate root)`
- **Primary symbols:**
  - `AesCipher`

## Feature flags and policy

Standard `noxtls-crypto` build (no extra feature for these modes except ECB).

## Examples

```rust
use noxtls_crypto::{AesCipher, noxtls_aes_gcm_encrypt};
```

## Security and compatibility

Unique IV/nonce per key; AEAD tags must be verified before releasing plaintext.

## Related

- [Symmetric topic](./sym)
- [TLS topic](./tls)
