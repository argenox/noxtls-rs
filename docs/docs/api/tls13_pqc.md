---
title: TLS 1.3 post-quantum
---

# TLS 1.3 post-quantum

## Algorithm

TLS 1.3 PQ/hybrid support combines classical key exchange/signature flows with PQ-capable groups and algorithms, gated by build policy.

## Purpose

PQ / hybrid negotiation helpers and deterministic TLS 1.3 key-share math.

## Rust API

- **Crate:** `noxtls`
- **Module path (conceptual):** `noxtls`
- **Primary symbols:**
  - `noxtls_tls13_key_share_group_supported`
  - `noxtls_tls13_signature_algorithm_supported`
  - `noxtls_derive_tls13_x25519_shared_secret`
  - `noxtls_derive_tls13_p256_shared_secret`

**Functions and types:**

- **`noxtls_tls13_key_share_group_supported(group_id)`** - Parameters: `group_id`. Behavior: Check if a key-share group is available in this build. Returns: `unspecified output`.
- **`noxtls_tls13_signature_algorithm_supported(sig_alg)`** - Parameters: `sig_alg`. Behavior: Check signature algorithm availability. Returns: `unspecified output`.
- **`noxtls_derive_tls13_x25519_shared_secret(...)` / `noxtls_derive_tls13_p256_shared_secret(...)`** - Deterministic shared-secret helpers for protocol workflows/tests.

## Feature flags and policy

PQC features on `noxtls` / `noxtls-core` as enabled for your build.

## Examples

```rust
use noxtls::{noxtls_tls13_key_share_group_supported, noxtls_tls13_signature_algorithm_supported};

let x25519_enabled = noxtls_tls13_key_share_group_supported(0x001d);
let ed25519_enabled = noxtls_tls13_signature_algorithm_supported(0x0807);
let _ = (x25519_enabled, ed25519_enabled);
```

## Security and compatibility

NoxTLS validates supported TLS 1.3 key-share groups and signature algorithms through explicit capability checks, and keeps deterministic shared-secret derivation paths aligned with the core TLS 1.3 handshake model for interoperability testing.

## Related

- [ML-KEM](./mlkem)
- [ML-DSA](./mldsa)
- [Quantum crypto](../../quantum-crypto)
