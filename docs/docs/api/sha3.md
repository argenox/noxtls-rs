---
title: SHA-3 / SHAKE256
---

# SHA-3 / SHAKE256

## Algorithm

**SHA-3** uses the Keccak-f[1600] permutation in sponge mode. It is structurally different from SHA-2, which helps when SHA-2 agility is a concern. **SHAKE256** is an XOF: you pick how many output bytes you need (within safe bounds enforced by the crate).

## Purpose

Keccak sponge-based digests (FIPS 202): SHA3-256/384/512 and extendable SHAKE256.

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::hash`
- **Primary symbols:**
  - `noxtls_sha3_256`
  - `noxtls_sha3_384`
  - `noxtls_sha3_512`
  - `noxtls_shake256`

**Functions and types:**

- **`noxtls_sha3_256` / `noxtls_sha3_384` / `noxtls_sha3_512`** — Fixed-length one-shot digests.
- **`noxtls_shake256(data, output_len) -> Vec<u8>`** - Parameters: `data` is input bytes and `output_len` is requested output length in bytes. Behavior: computes SHAKE256 extendable-output function output. Returns: `Vec<u8>` of exactly `output_len` bytes.

## Feature flags and policy

Default.

## Examples

```rust
use noxtls_crypto::{noxtls_sha3_256, noxtls_shake256};

let d = noxtls_sha3_256(b"abc");
assert_eq!(d.len(), 32);

let xof = noxtls_shake256(b"derive-me", 64);
assert_eq!(xof.len(), 64);
```

## Security and compatibility

Choose output length for SHAKE256 explicitly; domain-separate different uses with distinct `info` or prefixes.

## Related

- [Hash topic](./hash)
