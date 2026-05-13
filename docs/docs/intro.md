---
sidebar_position: 1
---

# Introduction

NoxTLS Rust is a **pure Rust** workspace for **TLS/DTLS**, **cryptography**, and **X.509**—designed for the same classes of **devices and gateways** served by the NoxTLS C library, with a modular layout suitable for host tools, RTOS firmware, and constrained MCU profiles.

## Who this documentation is for

- **Firmware engineers** porting TLS to new silicon or radio modules.
- **Security architects** aligning cipher policy, trust anchors, and update channels.
- **Application developers** shipping Rust services that terminate TLS on behalf of devices.

## How to read these docs

| Section | Purpose |
| ------- | ------- |
| [Getting Started](./getting-started) | Clone, build, test, and generate the doc site. |
| [Architecture](./architecture) | Crate graph and dependency direction. |
| [Security](./security) | Coordinated disclosure and policy flags. |
| [Porting Guide](./porting-guide) | End-to-end porting checklist for devices. |
| [Configuration Guide](./configuration-guide) | Cargo features and profiles as “device policy.” |
| [Memory Usage](./memory-usage) | ROM/RAM methodology. |
| [TLS component](./tls-component) / [TLS API](./tls-api/overview) | Protocol subsystem and API map. |
| [Crypto API](./crypto-api/overview) | Cryptography topic guides, **per-algorithm pages**, and generated crate reference. |
| [Applications](./applications/overview) | Product patterns: firmware, gateway, examples. |

## Workspace crates (reference)

Crates live under `crates/` in the repository:

- **`noxtls`** — User-facing TLS/DTLS protocol and connection API.
- **`noxtls-core`** — Errors, configuration, and profile/policy primitives.
- **`noxtls-crypto`** — Digests, MAC/HKDF, symmetric ciphers, PKC, DRBG.
- **`noxtls-pem`**, **`noxtls-x509`** — PEM handling and PKIX.
- **`noxtls-io`**, **`noxtls-platform`** — Transports and portable hooks.

The **topic guides** under TLS API and Crypto API explain how to use these pieces on a **product**. The **generated crate pages** summarize `Cargo.toml` metadata for release audits—they do not replace this narrative.

## Goals

- **Parity of intent** with NoxTLS (C) product documentation: device-first guidance, not only crate indexes.
- **Deterministic** crypto and protocol behavior suitable for embedded QA.
- **Clear upgrade path** between documentation versions using the site version dropdown.

Continue to [Getting Started](./getting-started) to build from source, then [Porting Guide](./porting-guide) when targeting hardware.
