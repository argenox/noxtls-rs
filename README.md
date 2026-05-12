<div align="center">
  <img src="docs/static/img/noxtls-rust-logo-256.webp" alt="NoxTLS Rust" width="200" />
</div>

# NoxTLS for Rust

**A pure Rust TLS/DTLS workspace for embedded and host systems.**  
Built for deterministic behavior, portable integrations, and modern cryptography.

[![Build](https://github.com/argenox/noxtls/actions/workflows/build-applications.yml/badge.svg)](https://github.com/argenox/noxtls/actions/workflows/build-applications.yml)
[![Tests](https://github.com/argenox/noxtls/actions/workflows/tests.yml/badge.svg)](https://github.com/argenox/noxtls/actions/workflows/tests.yml)
[![CodeQL](https://github.com/argenox/noxtls/actions/workflows/codeql.yml/badge.svg)](https://github.com/argenox/noxtls/actions/workflows/codeql.yml)

**Website:** https://argenox.com  
**Issues:** https://github.com/argenox/noxtls/issues  

## Why NoxTLS Rust?

NoxTLS Rust is built for teams that need Rust-native TLS/DTLS support with predictable resource use.

- Small and portable crate design
- Deterministic crypto and protocol behavior
- Embedded-friendly `no_std` + `alloc` support
- Configurable transport adapters (`embedded-io`, `embedded-io-async`, `tokio`)
- X.509 parsing, validation, and PEM tooling

## Features and cryptography

### Protocols (TLS / DTLS)

- **TLS 1.3** and **DTLS 1.3** — handshake, record layer, resumption and early-data policy hooks, OCSP stapling support, and QUIC-style packet protection helpers for HTTP/3-style stacks.
- **TLS 1.2** and **DTLS 1.2** — ECDHE-RSA with **AES-128-GCM** or **AES-256-GCM** (IANA `0xC02F` / `0xC030`).

### Negotiated cipher suites

| Protocol | Suites |
|----------|--------|
| TLS 1.3 / DTLS 1.3 | `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` |
| TLS 1.2 / DTLS 1.2 | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` |

### Key exchange and signatures (TLS 1.3)

- **Groups:** X25519, P-256 (secp256r1), ML-KEM-768 (standalone and hybrid with X25519).
- **Signature algorithms:** ECDSA with P-256, RSA-PSS (SHA-256 / SHA-384), Ed25519, ML-DSA-65.

### `noxtls-crypto` primitive suite

The **`noxtls-crypto`** crate supplies the underlying algorithms used by TLS and by tooling examples:

- **Digests and KDF:** SHA-256 / SHA-384 / SHA-512, SHA-3, SHAKE-256, HMAC, HKDF, TLS 1.2 PRF helpers; SHA-1 where legacy verification requires it.
- **Symmetric:** AES-GCM, ChaCha20-Poly1305, and additional AES / ARIA / Camellia modes (CBC, CCM, CTR, CFB, OFB, XTS, and more).
- **Public-key:** RSA (OAEP, PKCS#1 v1.5, PSS), P-256 ECDH and ECDSA, X25519, Ed25519, ML-KEM, ML-DSA.
- **Randomness:** HMAC-DRBG (SHA-256).

Legacy or hazardous algorithms (for example **DES**, **RC4**, **X448**, and some relaxed RSA key-generation paths) are gated behind the **`hazardous-legacy-crypto`** Cargo feature and are off by default.

### Certificates and PKIX

- **`noxtls-x509`** — X.509 parsing, chain validation, hostname checks, CSR and CRL handling (see `examples/` for PEM/DER workflows).
- **`noxtls-pem`** — PEM envelope encoding and decoding shared across the stack.

### Optional integrations

- **`provider-psa`** — offload signing, decryption, derivation, and AEAD to a PSA-style backend while keeping the same protocol API.
- **Transport adapters** — `embedded-io`, `embedded-io-async`, and **Tokio** (`noxtls-io`, enabled from `noxtls`).

## Workspace crates

Crates in `crates/`:

| Crate | Role |
|-------|------|
| `noxtls` | User-facing TLS/DTLS protocol and connection API |
| `noxtls-core` | Shared error, profile, and utility primitives |
| `noxtls-crypto` | Hash, MAC/HKDF, symmetric ciphers, PKC, and DRBG |
| `noxtls-pem` | PEM encoding/decoding helpers |
| `noxtls-x509` | ASN.1/DER, certificate handling, and validation |
| `noxtls-io` | Transport traits and blocking/async adapters |
| `noxtls-platform` | Platform time hooks (extensible for RNG/storage) |
| `noxtls-test` | Demo binaries and internal test helpers (`publish = false`) |
| `noxsight-integration` | Observability adapters (`publish = false`) |

## Getting started

### Clone

```powershell
git clone https://github.com/argenox/noxtls.git
cd noxtls
```

### Build and test

```powershell
cargo check --workspace
cargo test --workspace
```

### Run examples

```powershell
cargo run -p noxtls --example tls_client
cargo run -p noxtls --example parse_certificate
cargo run -p noxtls --example noxtls-rs -- dgst --alg sha256 --text "hello"
```

See `examples/README.md` for the full command list.

## Documentation

- Docs site: https://docs.noxtls.com
- Local docs server:

```powershell
cd docs
npm install
npm run docs:sync
npm run start
```

- Record-layer integration notes: `docs/TLS13_RECORD_POLICY.md`
- Interop verification matrices: `docs/TLS13_INTEROP_MATRIX.md`, `docs/TLS12_INTEROP_MATRIX.md`
- DTLS policy knobs: `docs/DTLS13_OPERATIONAL_POLICY.md`

## Formatting and linting

```powershell
cargo fmt --all
cargo clippy --workspace --all-targets
```

## Licensing

This project follows a dual-license model:

- GPLv2 for open-source usage
- Commercial license for proprietary usage

See `LICENSE.md` and `COPYING.md`.  
Commercial licensing: `info@argenox.com`.
