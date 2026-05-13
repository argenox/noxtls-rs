---
sidebar_position: 20
title: Documentation Parity Matrix
---

# Documentation Parity Matrix

This matrix tracks which OEM docs are applicable to NoxTLS Rust and how they map into this site.

## Scope baseline

- Source compared: `noxtls-oem/noxtls/docs/docs`
- Target: this repository (`noxtls-rs/noxtls/docs/docs`)
- Goal: keep Rust docs aligned with actual crate APIs, not C header/module layouts

## Mapping summary

| OEM area | Rust status | Mapping in this docs site |
| --- | --- | --- |
| Project/process pages (`project`, `contributing`, `security-reporting`) | Applicable | `project`, `contributing`, `security-reporting` |
| TLS component narrative (`tls.md`) | Applicable (adapted) | `tls-component`, `tls-api/overview`, `api/tls` |
| Crypto API index (`api-index.md`) | Applicable (adapted) | `api/api-index`, `crypto-api/overview` |
| Algorithm-per-file C API pages (`api/aes_*`, `api/sha*`, `api/rsa`, etc.) | Adapted to Rust | **Per-algorithm pages** under `docs/docs/api` (see [API index](./api/api-index) and [OEM → Rust mapping](./api/OEM-RUST-API-MAPPING)); topic hubs remain `api/hash`, `api/sym`, `api/pkc`, `api/drbg`, `api/x509`, `api/core` |
| C TLS-version split pages (`api/tls10`, …, `api/dtls`) | Adapted to Rust | Matching pages: `api/tls10` … `api/tls13`, `api/dtls`, `api/tls13_pqc`, `api/tls_unified`, plus `api/tls` and `tls-api/overview` |
| C utility/config pages (`api/common`, `api/build_config`, `api/version`, `api/utility`) | Partially applicable | Mapped to `api/core`, `configuration-guide`, generated crate-reference pages |
| C applications docs (`applications/app_*`) | Not directly applicable | Rust-focused app guidance in `applications/overview` + `api/apps` (`noxtls-test` binaries) |

## Notes on intentional differences

- Rust docs are organized by **crate and integration workflow**.
- OEM docs are organized by **C modules and Doxygen-generated per-header pages**.
- This is intentional: the Rust docs should optimize for firmware/gateway integration using Rust crates and features.

## Completion criteria

Documentation parity for NoxTLS Rust is considered complete when:

- Every shipped Rust crate has a discoverable narrative/API entry point.
- TLS, crypto, X.509, and applications pages match current exported Rust symbols.
- New feature flags or policy controls are reflected in docs and release notes.
