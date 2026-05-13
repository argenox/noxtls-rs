---
title: SHA-1
---

# SHA-1

## Algorithm

**SHA-1** produces a 160-bit digest. Collision attacks are practical for many use cases; modern protocols and PKIX profiles deprecate SHA-1 signatures.

## Purpose

Legacy 160-bit digest retained for interoperability only.

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::hash`
- **Primary symbols:**
  - `noxtls_sha1`

**Functions and types:**

- **`noxtls_sha1(data: &[u8]) -> [u8; 20]`** - Parameters: `data` is the full byte slice to hash. Behavior: computes SHA-1 in a single pass for compatibility paths. Returns: `[u8; 20]` digest bytes.

## Feature flags and policy

May interact with `policy-allow-sha1-signatures` in the full TLS stack.

## Examples

```rust
use noxtls_crypto::noxtls_sha1;

let digest = noxtls_sha1(b"legacy-only");
assert_eq!(digest.len(), 20);
```

## Security and compatibility

Do not use SHA-1 for new signatures or collision-sensitive integrity; use only under written policy.

## Related

- [Hash topic](./hash)
