---
sidebar_position: 12
title: Crypto API overview
---

# Crypto API overview

The **crypto API** in NoxTLS Rust is centered on **`noxtls-crypto`**, with **`noxtls-core`** supplying profile flags and shared types. On a **device**, you typically care about:

- which **primitives** are linked in (ROM),
- which **interfaces** you call from TLS versus from tooling (firmware signing, attestation),
- whether **PSA offload** replaces software implementations at selected call sites.

## Topic map (conceptual docs)

| Topic page | Covers |
| ---------- | ------ |
| [Core](../api/core) | Errors, profiles, configuration parsing |
| [Hash](../api/hash) | Digests, HMAC, HKDF |
| [Symmetric](../api/sym) | AEAD and block modes |
| [DRBG](../api/drbg) | Deterministic randomness hooks |
| [PKC](../api/pkc) | RSA, ECC, X25519, ML-KEM, ML-DSA, imports |
| [X.509](../api/x509) | Certificates, chains, validation |

Use these pages as the **product-facing** description; use **docs.rs** for per-type signatures when implementing.

## Crate reference (generated)

The sidebar includes **generated** pages under **Crate reference (generated)** for each workspace member. They exist so release engineering can audit **versions and features** quickly. They are **not** a substitute for the topic guides above or for **docs.rs** API detail.

## PSA provider path

When `provider-psa` is enabled on `noxtls`, selected operations can be delegated to a PSA-compatible backend while preserving protocol-layer types. Pair with your secure element vendor’s guidance for key slots and algorithm enablement.

## Safety and legacy surfaces

- Default builds aim at **modern, conservative** algorithm sets.
- **Legacy** or hazardous algorithms require explicit features (e.g. `hazardous-legacy-crypto`)—treat as **policy exceptions**, not defaults.

See [Security](../security) and [Configuration Guide](../configuration-guide) before enabling any legacy surface on a shipping device.
