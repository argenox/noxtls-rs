---
title: TLS 1.3
---

# TLS 1.3

## Purpose

TLS 1.3 support in the modeled `Connection` API.

## Rust API

- **Crate:** `noxtls`
- **Module path (conceptual):** `noxtls`
- **Primary symbols:**
  - `Connection`
  - `TlsVersion`
  - `HandshakeState`
  - `CipherSuite`

## Feature flags and policy

`feature-tls13` on `noxtls-core`.

## Examples

```rust
use noxtls::{Connection, TlsVersion};
```

## Security and compatibility

Disable legacy protocol versions in production unless required.

## Related

- [TLS topic](./tls)
- [Configuration guide](../../configuration-guide)
