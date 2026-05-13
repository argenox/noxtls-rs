---
title: Utility (PEM / files)
---

# Utility (PEM / files)

## Purpose

PEM/DER conversion and optional file helpers.

## Rust API

- **Crate:** `noxtls-pem`
- **Module path (conceptual):** `noxtls_pem`
- **Primary symbols:**
  - `noxtls_pem_to_der`
  - `noxtls_certificate_pem_to_der`
  - `noxtls_pem_file_to_der`

## Feature flags and policy

`std` may be required for filesystem helpers.

## Examples

See the linked topic pages and crate rustdoc for complete examples.

## Security and compatibility

Validate PEM labels; never log private keys.

## Related

- [X.509 topic](./x509)
