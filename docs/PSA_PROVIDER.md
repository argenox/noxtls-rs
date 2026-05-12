# PSA Provider Integration Guide

This guide documents the first-class public PSA provider path in the `noxtls` workspace.

## Scope

The PSA integration is delivered through:

- `noxtls/crates/noxtls-psa` (public PSA crate)
- `noxtls` feature flag: `provider-psa`
- `noxtls::PsaExternalKeyProvider` adapter implementing `ExternalKeyProvider`

Current in-tree operation coverage:

- RSA PKCS#1 v1.5 sign (`RsaPkcs1Sha256`)
- RSA-PSS SHA-256 sign (`RsaPssSha256`)
- RSA PKCS#1 v1.5 decrypt
- RSA OAEP-SHA256 decrypt
- X25519 derive
- SHA-256 digest
- AES-GCM encrypt
- Random byte generation (software backend deterministic fixture behavior)

## Enable the PSA Path

Use the feature on `noxtls`:

```toml
[dependencies]
noxtls = { version = "0.1.0", features = ["std", "provider-psa"] }
```

For validation-only exports in local testing:

```toml
[dependencies]
noxtls = { version = "0.1.0", features = ["std", "provider-psa-test-export"] }
```

## Adapter Model

- `noxtls-psa` owns PSA request/algorithm types, backend trait, and policy checks.
- `PsaExternalKeyProvider` bridges noxtls `ExternalKeyProvider` requests to `noxtls-psa`.
- Decrypt errors are intentionally mapped to a uniform error surface:
  `psa cryptographic operation failed`.

## Handle and Policy Model

- Keys are referenced via opaque handles.
- Handle policy enforces per-operation permissions (`sign`, `decrypt`, `derive`).
- Unknown handles fail deterministically (`psa key handle invalid`).
- Raw private material is not exposed through the public provider API.

## Backends

- `PsaSoftwareBackend` is in-tree and used for deterministic test/validation coverage.
- `FfiPsaBackend` is present as the FFI-backed adapter boundary; platform-specific linkage is
  intentionally left to target integrations.

## Root-Level Validation Commands

Run from repository root:

```powershell
cargo test -p noxtls --features provider-psa
cargo test -p noxtls-oem-validation --test protocol_suite --features provider-psa
```

The `protocol_suite` path includes PSA root validation cases for:

- positive RSA sign/decrypt flow
- malformed input handling
- unknown handle rejection
- uniform decrypt failure mapping
