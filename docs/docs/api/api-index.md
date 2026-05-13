---
title: API index
---

# API index

This API section is organized for the NoxTLS **Rust** workspace. It maps product concerns to crate-level APIs, **topic guides**, and **per-algorithm pages** (OEM-style parity, Rust-accurate). Use these pages for **function behavior** and **Cargo feature** notes; generated crate stubs in this site link to sources but do not replace the narrative API material here.

## OEM parity and mapping

- [OEM → Rust API mapping](./OEM-RUST-API-MAPPING) — how OEM C doc pages map to this tree
- [Documentation parity matrix](../documentation-parity-matrix) — high-level OEM vs Rust doc status

## Primary topic guides

| Topic | Page |
| ----- | ---- |
| Core (`noxtls-core`) | [Core](./core) |
| Hash / HMAC / HKDF | [Hash](./hash) |
| Symmetric ciphers | [Sym](./sym) |
| DRBG | [DRBG](./drbg) |
| Public-key crypto | [PKC](./pkc) |
| X.509 / PKIX | [X.509](./x509) |
| TLS / DTLS (`noxtls`) | [TLS](./tls) |

---

## Per-algorithm and support pages

### Core, build, errors, utility

- [Common (errors, helpers)](./common)
- [Build configuration](./build_config)
- [Version information](./version)
- [Errors / return-code mapping](./return_codes)
- [Utility (PEM, encoding)](./utility)

### Hash and digests

- [Message digest / TLS PRF hub](./mdigest)
- [SHA-256](./sha256) · [SHA-512](./sha512) · [SHA-3 / SHAKE256](./sha3) · [SHA-1](./sha1)
- [BLAKE2](./blake2) · [MD4](./md4) · [MD5](./md5) · [RIPEMD-160](./ripemd160) — *not supported in public Rust API (see each page)*

### Symmetric encryption

- [Encryption hub](./encryption) · [Symmetric topic](./sym)
- **AES:** [AES](./aes) · [CBC](./aes_cbc) · [CCM](./aes_ccm) · [CFB](./aes_cfb) · [CTR](./aes_ctr) · [ECB](./aes_ecb) · [GCM](./aes_gcm) · [OFB](./aes_ofb) · [cipher object](./aes_shared) · [XTS](./aes_xts)
- **ARIA:** [ARIA](./aria) · [CBC](./aria_cbc) · [CFB](./aria_cfb) · [CTR](./aria_ctr) · [ECB](./aria_ecb) · [OFB](./aria_ofb)
- **Camellia:** [Camellia](./camellia) · [CBC](./camellia_cbc) · [CFB](./camellia_cfb) · [CTR](./camellia_ctr) · [ECB](./camellia_ecb) · [OFB](./camellia_ofb) · [cipher object](./camellia_shared)
- **ChaCha20:** [ChaCha20](./chacha20) · [ChaCha20-Poly1305](./chacha20_poly1305)
- **Legacy:** [DES](./des) · [RC4](./rc4) — *`hazardous-legacy-crypto`*

### Public-key cryptography

- [PKC topic](./pkc)
- [RSA](./rsa) · [ECC / P-256](./ecc) · [Ed25519](./ed25519) · [X25519](./x25519) · [X448](./x448)
- [ML-KEM](./mlkem) · [ML-DSA](./mldsa)
- [Ed448](./ed448) · [DH](./dh) · [DSA](./dsa) — *see pages for Rust API status*

### Certificates

- [X.509 topic](./x509) · [Certificates](./certs)

### TLS / DTLS protocol versions

Use the **TLS API** sidebar group for the full list. Entry points:

- [TLS topic](./tls) · [DTLS](./dtls)
- [TLS 1.0](./tls10) · [TLS 1.1](./tls11) · [TLS 1.2](./tls12) · [TLS 1.3](./tls13)
- [TLS 1.3 PQC](./tls13_pqc) · [Unified connection (OEM mapping)](./tls_unified)

---

## Generated crate reference pages

Use **Crate reference (generated)** in the sidebar for `Cargo.toml` metadata and source links: `noxtls`, `noxtls-core`, `noxtls-crypto`, `noxtls-io`, `noxtls-pem`, `noxtls-platform`, `noxtls-psa`, `noxtls-x509`, `noxtls-test`.

## Why this differs from OEM C docs

OEM used Doxygen **per C module**. Here, **topic guides** stay the primary integration path; **per-algorithm pages** give OEM-style discoverability while still describing **Rust** crates and features.
