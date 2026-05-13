---
title: Unified TLS API (OEM mapping)
---

# Unified TLS API (OEM mapping)

## Purpose

OEM C code used a single unified connection type. Rust exposes **`Connection`** for all negotiated versions.

## Rust API

- **Crate:** `noxtls`
- **Module path (conceptual):** `noxtls`
- **Primary symbols:**
  - `Connection`
  - `TlsVersion`
  - `HandshakeState`

## Feature flags and policy

Select `TlsVersion` at construction; use `HandshakeState` to drive lifecycle.

## Examples

See the linked topic pages and crate rustdoc for complete examples.

## Security and compatibility

Prefer explicit version policy instead of silent downgrade.

## Related

- [TLS topic](./tls)
- [TLS API overview](../../tls-api/overview)
