---
sidebar_position: 1
---

# Introduction

NoxTLS Rust is a pure Rust workspace implementing cryptographic primitives and TLS/DTLS building blocks.

## Workspace crates

Crates live under `noxtls/crates/`:

- **`noxtls`**: TLS/DTLS protocol and connection state machine (user-facing).
- **`noxtls-core`**: Shared errors, configuration, and profile/policy primitives.
- **`noxtls-crypto`**: Hashing, HMAC, HKDF, symmetric ciphers, AEAD, public-key crypto, and DRBG.
- **`noxtls-pem`**: PEM encoding/decoding helpers.
- **`noxtls-x509`**: ASN.1/DER, certificates, and validation.
- **`noxtls-io`**: Transport traits and blocking/async adapters.
- **`noxtls-platform`**: Portable time hooks (extensible for RNG/storage).
- **`noxtls-test`**: Demo and integration binaries (`publish = false`).

## Goals

- Maintain a modular crate layout with clear dependency direction.
- Preserve strong security posture defaults.
- Provide API and implementation parity for the noxtls ecosystem where feasible.

See [Getting Started](./getting-started) for build commands, [Architecture](./architecture) for crate boundaries, and the [TLS API topic](./api/tls) (plus sibling topic pages under `api/`) for symbol-oriented references.
