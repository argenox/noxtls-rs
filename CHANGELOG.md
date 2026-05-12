# Changelog

All notable changes to this workspace are documented in this file.

## [Unreleased] - 2026-05-11

- Standardized all Rust sources on the full NoxTLS C-style copyright and dual-license banner (GPLv2 text, commercial alternative, `noxtls/LICENSE` pointers, and `CONTACT: info@argenox.com`) while keeping SPDX `GPL-2.0-only OR LicenseRef-Argenox-Commercial-License`; added `scripts/update-rust-file-headers.ps1` for deterministic re-application.
- Security hardening and vulnerability-remediation sweep completed for tracked OpenSSL/WolfSSL-style classes, including parser-length hardening, RSA/OAEP uniform-failure posture, and stricter default-safe policy behavior.
- X448 implementation and exposure policy were tightened: hazardous-mode surface is explicitly feature-gated, and default-safe builds compile out hazardous operations.
- Added TLS 1.3 OCSP stapling primitives for `status_request`: client extension emit/parse, server staple attachment on Certificate messages, and client-side staple verification hook with policy regressions.
- Added QUIC/HTTP3 readiness automation artifacts: `scripts/run_quic_http3_interop_matrix.ps1`, `scripts/run_quic_http3_peer.ps1`, and `noxtls/docs/QUIC_HTTP3_INTEROP_MATRIX.md`.
- Added first-class public PSA provider integration in-tree: new `noxtls-psa` crate, `provider-psa` feature wiring, `PsaExternalKeyProvider` adapter, and root validation coverage for RSA/X25519 handle flows and uniform decrypt failures.
- Release-gate command bundle was refreshed and validated against current crate topology (`noxtls-test` smoke binaries and updated workspace package set).
- TLS 1.2/TLS 1.3 canonical verification checklists were refreshed with current named-test evidence and status alignment.

## [0.1.0] - 2026-04-17

- Initial public Rust workspace release for:
  - `noxtls`
  - `noxtls-core`
  - `noxtls-crypto`
  - `noxtls-pem`
  - `noxtls-x509`
  - `noxtls-io`
  - `noxtls-platform`
- Added repository metadata and initial packaging/readiness scaffolding.
