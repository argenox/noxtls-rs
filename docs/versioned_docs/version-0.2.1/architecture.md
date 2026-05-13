---
sidebar_position: 3
---

# Architecture

The workspace separates cryptographic primitives, certificate handling, transport I/O, and protocol logic into focused crates—so **devices** can ship only the layers they need (for example crypto-only attestation tooling without pulling the full TLS state machine).

## Device view

- **Edge device (MCU)** — Typically `noxtls` + `noxtls-io` (embedded adapter) + minimal `noxtls-x509` trust material; optional `provider-psa` for secure element offload.
- **Gateway (host)** — `noxtls` with `std` and often `adapter-tokio`; may also terminate DTLS toward radios.
- **Crypto service** — `noxtls-crypto` alone or with `noxtls-pem` / `noxtls-x509` for parsing without live TLS sessions.

## Dependency direction

- `noxtls-core` is the foundational crate and should remain dependency-light.
- `noxtls-crypto` (hash, symmetric, PKC, DRBG) depends on `noxtls-core`.
- `noxtls-pem` depends on `noxtls-core`.
- `noxtls-x509` composes `noxtls-core`, `noxtls-crypto`, and `noxtls-pem`.
- `noxtls-io` depends on `noxtls-core` (transport adapters).
- `noxtls` composes `noxtls-core`, `noxtls-crypto`, `noxtls-x509`, `noxtls-io`, and `noxtls-platform`.
- `noxtls-test` sits at the top of the graph.

## Workspace structure

Rust packages are under `noxtls/crates/` (workspace members are `noxtls/crates/*` from the repository root):

- `noxtls-core/`
- `noxtls-crypto/`
- `noxtls-pem/`
- `noxtls-x509/`
- `noxtls-io/`
- `noxtls-platform/`
- `noxtls/`
- `noxtls-test/`

## Configuration model

`noxtls-core` includes a configuration layer for mbedTLS-style `#define` policy files:

- template: `noxtls_config.h`
- parser API: `LibraryConfig::from_mbedtls_style_file(...)`

The model lets consumers tune features and security policy at build/config time while keeping crate boundaries clear.
