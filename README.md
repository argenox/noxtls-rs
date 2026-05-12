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
