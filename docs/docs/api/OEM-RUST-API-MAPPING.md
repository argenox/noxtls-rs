---
title: OEM to Rust API mapping
---

# OEM to Rust API mapping

This table maps OEM C documentation pages under `noxtls-oem/.../docs/docs/api` to NoxTLS Rust (`noxtls-rs`). Pages listed here have a corresponding doc under `api/` unless noted.

| OEM page | Classification | Rust surface (crate / notes) |
| --- | --- | --- |
| `aes.md` … `aes_xts.md` | direct | `noxtls-crypto` — `AesCipher`, `noxtls_aes_*` mode helpers (ECB behind `hazardous-legacy-crypto`) |
| `aria.md` … `aria_ofb.md` | direct | `noxtls-crypto` — `AriaCipher`, `noxtls_aria_*` (ECB behind `hazardous-legacy-crypto`) |
| `camellia.md` … `camellia_shared.md` | direct | `noxtls-crypto` — `CamelliaCipher`, `noxtls_camellia_*` (ECB behind `hazardous-legacy-crypto`) |
| `chacha20.md` | adapted | `ChaCha20` stream cipher; Poly1305 helpers `noxtls_poly1305_*` at crate root |
| `chacha20_poly1305.md` | direct | `noxtls_chacha20_poly1305_encrypt` / `noxtls_chacha20_poly1305_decrypt` |
| `encryption.md` | adapted | Hub: symmetric overview; see `sym` topic and per-cipher pages |
| `des.md`, `rc4.md` | direct (legacy) | `noxtls-crypto` + feature `hazardous-legacy-crypto` — `DesCipher`, `Rc4`, `noxtls_des_*` APIs |
| `sha256.md`, `sha512.md`, `sha3.md`, `sha1.md` | direct | `noxtls-crypto` — `noxtls_sha256`, `noxtls_sha512`, `noxtls_sha384`, `noxtls_sha3_256` / `noxtls_sha3_384` / `noxtls_sha3_512`, `noxtls_shake256`, `noxtls_sha1`, HKDF/HMAC re-exports |
| `mdigest.md` | adapted | `Digest`, `Sha256`, `Sha512`, `TlsTranscriptSha256/384`, TLS PRF helpers |
| `blake2.md`, `md4.md`, `md5.md`, `ripemd160.md` | not supported | No public Rust API in this workspace; documented as gap |
| `drbg.md` | direct | [DRBG](./drbg) — `HmacDrbgSha256` in `noxtls-crypto::drbg` |
| `rsa.md`, `ecc.md`, `ed25519.md`, `x25519.md`, `mlkem.md`, `mldsa.md` | direct | `noxtls-crypto::pkc` re-exports |
| `x448.md` | direct (legacy) | `noxtls_x448`, `noxtls_x448_shared_secret`, … with `hazardous-legacy-crypto` |
| `ed448.md`, `dh.md`, `dsa.md` | not supported | No Ed448 / classical DH-DSA surface matching OEM split |
| `pkc.md` | adapted | [PKC topic](./pkc) — umbrella for all PKC pages |
| `hash.md` | adapted | [Hash topic](./hash) — umbrella for digest/HKDF/HMAC pages |
| `tls.md`, `dtls.md`, `tls10.md` … `tls13_pqc.md`, `tls_unified.md` | adapted | `noxtls` — `Connection`, DTLS helpers, version features on `noxtls-core`; no C unified connection type |
| `certs.md` | adapted | `noxtls-x509` + PEM helpers from `noxtls-pem`; see [X.509](./x509) |
| `common.md` | adapted | `noxtls-core` — `Error`, wire helpers, `noxtls_secure_zero`; see [Core](./core) |
| `version.md` | adapted | Crate `CARGO_PKG_VERSION` and crate metadata pages; no C-style version macros page |
| `build_config.md` | adapted | `noxtls-core` features + `LibraryConfig`; [Configuration guide](../../configuration-guide) |
| `return_codes.md` | adapted | Rust `noxtls_core::Error` and `Result<T>` instead of integer codes |
| `utility.md` | adapted | `noxtls-pem` for PEM; noxtls_decode_hex in `noxtls-crypto::hash` |
| `README.md` (OEM) | adapted | [API index](./api-index) — Rust module layout |

**Legend:** *direct* — call the listed Rust APIs. *adapted* — same product concern, different module layout. *not supported* — OEM had APIs; this Rust release does not expose them publicly.
