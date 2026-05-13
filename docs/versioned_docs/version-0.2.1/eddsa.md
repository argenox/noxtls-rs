---
sidebar_position: 9
title: EdDSA
---

# EdDSA on devices (Ed25519 / Ed448)

NoxTLS Rust exposes **Ed25519** for signatures and key agreement patterns used in modern TLS 1.3 cipher suites and certificate ecosystems. This chapter is the **device integration** view—how to enable, validate, and operate EdDSA safely next to ECDSA and ML-DSA.

## Where EdDSA appears

- **TLS 1.3** — signature algorithms negotiated in `CertificateVerify` and related handshake messages.
- **Certificates** — Subject / issuer keys may be Ed25519; validation flows through `noxtls-x509` and `noxtls-crypto` PKC paths.
- **Tooling** — Firmware signing or attestation workflows that reuse the same crypto crate.

## Enabling Ed25519 in a firmware build

1. Ensure **`noxtls-crypto`** is built with the PKC and signature profile you need (`noxtls-core` `feature-pkc`, `feature-cert`, TLS features).
2. Confirm **trust anchor** and **EE cert** algorithms match what your factory provisioning emits.
3. If you use **PSA offload**, map Ed25519 operations to your secure element’s PSA algorithm identifiers.

## Operational guidance

- **Key storage** — Prefer OTP / secure element for private keys; avoid long-lived test keys in production images.
- **Hybrid transitions** — When rotating from ECDSA to Ed25519, ship both chains until all peers accept the new roots.
- **Deterministic vs hedged** — Library defaults follow modern practice; do not fork low-level signing without cryptographic review.

## Cross-references

- [Crypto API overview](./crypto-api/overview) — how PKC topics map to crates.
- [PKC topic](./api/pkc) — public-key primitives and import rules.
- [Security](./security) — reporting and review expectations.

> **Ed448** and other curves may be gated or experimental depending on workspace version; confirm against your pinned release and [Release notes](./release-notes).
