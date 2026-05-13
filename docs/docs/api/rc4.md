---
title: RC4
---

# RC4

## Purpose

RC4 stream cipher (legacy).

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym`
- **Primary symbols:**
  - `Rc4`

## Feature flags and policy

**`hazardous-legacy-crypto`** required.

## Examples

```rust
use noxtls_crypto::Rc4;
```

## Security and compatibility

RC4 is not suitable for new protocols.

## Related

- [Symmetric topic](./sym)
