---
title: TLS 1.0
---

# TLS 1.0

## Purpose

TLS 1.0 support in the modeled `Connection` API.

## Rust API

- **Crate:** `noxtls`
- **Module path (conceptual):** `noxtls`
- **Primary symbols:**
  - `Connection`
  - `TlsVersion`
  - `HandshakeState`
  - `CipherSuite`

## Feature flags and policy

`feature-tls10` on `noxtls-core` (with `feature-tls`).

## Examples

```rust
use noxtls::{Connection, TlsVersion};
```

## Security and compatibility

Disable legacy protocol versions in production unless required.

## Related

- [TLS topic](./tls)
- [Configuration guide](../../configuration-guide)
