---
sidebar_position: 6
title: Configuration Guide
---

# Configuration Guide

NoxTLS Rust is configured at **build time** through Cargo features and `noxtls-core` **profiles**, not through a single C header. This page is the device-oriented map from “what we need on the product” to “what we enable in the firmware image.”

## Workspace and crate features

### `noxtls` (application-facing TLS/DTLS)

| Feature | When to enable |
| ------- | -------------- |
| `std` (default) | Host and RTOS builds with the standard library. |
| `alloc` (default) | Almost all TLS use; disable only for experimental no-alloc paths. |
| `adapter-embedded-io` | Blocking `embedded-io` traits for MCU stacks. |
| `adapter-embedded-io-async` | Async `embedded-io-async` when your stack is already async. |
| `adapter-tokio` | Linux daemons, gateways, or tools using Tokio. |
| `provider-psa` | Offload crypto to a PSA-style HAL while keeping the same protocol API. |
| `hazardous-legacy-crypto` | **Avoid on devices** unless you explicitly support legacy algorithms; gates weak or obsolete crypto in `noxtls-crypto`. |

### `noxtls-core` profiles

Profile flags compile **policy surfaces** into the binary (similar in intent to mbedTLS `MBEDTLS_*` toggles). Prefer starting from defaults and removing what you do not ship:

- **`profile-minimal-tls-client`** — smallest client-oriented surface when you control both peers.
- **`profile-tls-server-pki`** — server plus PKI write paths when issuing or rotating certs on-device.
- **`profile-crypto-only`** — hashing, AEAD, PKC without TLS protocol layers.

Consult `crates/noxtls-core/Cargo.toml` for the authoritative list of `feature-*` flags.

## Device policy recommendations

1. **Disable** `hazardous-legacy-crypto` on production firmware unless a written exception exists.
2. **Pin dependency versions** in your firmware manifest and record them in your SBOM.
3. **Separate** update keys from runtime TLS keys where your architecture allows it.
4. **Log minimally** on device; forward security events to a gateway when privacy policy allows.

## Cross-reference

- [Porting Guide](./porting-guide) — end-to-end porting flow.
- [Memory Usage](./memory-usage) — ROM/RAM impact of features.
- [Security](./security) — reporting and hardening expectations.
