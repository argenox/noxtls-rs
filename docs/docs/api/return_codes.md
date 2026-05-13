---
title: Errors (return codes mapping)
---

# Errors (return codes mapping)

## Purpose

Rust uses `Result<T, noxtls_core::Error>` instead of integer error codes.

## Rust API

- **Crate:** `noxtls-core`
- **Module path (conceptual):** `noxtls_core`
- **Primary symbols:**
  - `Error`
  - `Result`

## Feature flags and policy

Variants include `UnsupportedFeature`, `CryptoFailure`, `ParseFailure`, â€¦

## Examples

See the linked topic pages and crate rustdoc for complete examples.

## Security and compatibility

Map errors to alerts and telemetry without leaking secrets.

## Related

- [Core topic](./core)
