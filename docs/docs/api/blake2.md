---
title: BLAKE2
---

# BLAKE2

## Algorithm

**BLAKE2** is a family of cryptographic hashes optimized for software performance while retaining a conservative security margin. The common variants are **BLAKE2b** (64-byte output, 128-byte block, suited to 64-bit platforms) and **BLAKE2s** (32-byte output, 64-byte block, suited to 32-bit and constrained targets). Both support optional **keyed** mode (treat the digest as a MAC when the key is secret and unique per use) and a **personalization** string to domain-separate different uses of the same key material.

BLAKE2 is standardized for the unkeyed digests in **RFC 7693**. It is widely used in applications and libraries (for example file integrity, authenticated storage, and some protocols), but it is **not** part of the TLS 1.3 mandatory cipher suite set the way SHA-256 is.

## Purpose

This page exists for **OEM documentation parity** and to record a deliberate **gap** in the public NoxTLS **Rust** API: **`noxtls-crypto` does not export BLAKE2** in the current release. If you need a portable digest from this workspace, use **SHA-256** / **SHA-512** / **SHA-3** (see [Hash](./hash), [SHA-256](./sha256), [SHA-512](./sha512), [SHA-3](./sha3)). See [OEM → Rust API mapping](./OEM-RUST-API-MAPPING) for how OEM C docs map to supported Rust entry points.

## Rust API (status)

| Item | Status |
| ---- | ------ |
| `BLAKE2b` / `BLAKE2s` / keyed BLAKE2 | **Not exposed** from `noxtls-crypto` in this tree |
| OEM C references to BLAKE2 | Documented here as **not supported** in the Rust product surface |

There is no `blake2_*` symbol to import from `noxtls-crypto` today.

## Examples

### Supported alternative in this workspace (SHA-256)

Use SHA-256 when you need a standard, exported digest API:

```rust
use noxtls_crypto::noxtls_sha256;

let digest: [u8; 32] = noxtls_sha256(b"payload to fingerprint");
assert_eq!(digest.len(), 32);
```

Streaming multi-chunk hashing:

```rust
use noxtls_crypto::{Digest, Sha256};

let mut hasher = Sha256::new();
hasher.update(b"part-a");
hasher.update(b"part-b");
let digest_vec = hasher.finalize();
assert_eq!(digest_vec.len(), 32);
```

### BLAKE2 itself

There is **no** BLAKE2 example against `noxtls-crypto` because the implementation is not shipped in the public API. If a product requirement mandates BLAKE2 (interoperability with an existing BLAKE2-only verifier), you must integrate a **separately vetted** BLAKE2 library and keep that boundary explicit in reviews and supply-chain tracking.

## Security and compatibility

- **Keyed BLAKE2** is only a MAC if the key is **high-entropy secret** and you never reuse `(key, message)` in ways that violate MAC assumptions; for password-derived keys, prefer a dedicated password hashing function (for example Argon2) rather than raw BLAKE2 on a short password.
- **Personalization** and **salt** fields exist precisely to reduce cross-protocol “digest reuse” attacks; use them when your format allows.
- **Output truncation**: BLAKE2 allows shorter digests; truncating increases collision risk in a birthday-bound way—only truncate when a standard specifies it.
- **Within NoxTLS Rust**: prefer **SHA-256** or **SHA-512** for new integrity and TLS-adjacent work unless an external standard names BLAKE2 and you add a vetted third-party implementation.

## Related

- [OEM → Rust mapping](./OEM-RUST-API-MAPPING)
- [API index](./api-index)
- [Hash topic](./hash)
- [SHA-256](./sha256)
