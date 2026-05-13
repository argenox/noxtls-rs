---
title: DSA
---

# DSA (FIPS 186 integer DSA)

## Algorithm

**DSA** (the original U.S. **Digital Signature Algorithm**, FIPS 186) signs messages using arithmetic modulo a large prime **`p`** with a **`q`**-order subgroup, a generator **`g`**, a long-term private key **`x`**, and a per-signature secret **`k`**. Verification uses the public key **`y = g^x mod p`**. Historically, **weak parameter choices** and **biased or repeated `k`** values led to catastrophic private-key recovery; modern deployments have largely moved to **ECDSA**, **EdDSA**, or **PQ** signatures.

**NoxTLS does not implement integer DSA** (no **`dsa_*`** APIs, no FIPS 186 **`(p, q, g)`** key objects, no ASN.1 DSA signature parsing for verification in **`noxtls-crypto`**).

## Purpose in NoxTLS

This page documents **policy and migration**, not an API surface. If OEM or legacy documentation refers to **“DSA”** in the FIPS 186 sense (finite-field, **`id-dsa-with-sha*`** style certificates, or TLS 1.2 cipher suites that implied DSA server certs in ancient stacks), map that requirement to a **supported** signature system:

| Typical legacy intent | Supported direction in NoxTLS |
| --- | --- |
| TLS / WebPKI-style server authentication with NIST P-256 | **[ECDSA on P-256](./ecc)** — `noxtls_p256_ecdsa_sign_sha256`, `noxtls_p256_ecdsa_verify_sha256`, digest variants; TLS 1.3 **`ecdsa_secp256r1_sha256`** (`0x0403`) in the connection layer |
| Compact signatures, same key for sign/verify in new designs | **[Ed25519](./ed25519)** |
| Post-quantum signing (experimental profiles) | **[ML-DSA](./mldsa)** |
| RSA-PSS chains | **[PKC / RSA](./pkc)** and certificate validation paths |

**X.509:** The PKIX layer in this repository is oriented toward **RSA**, **EC P-256**, **Ed25519**, and **ML-DSA** public keys and signature algorithms as exercised by the TLS and validation code paths—not toward **integer DSA** `SubjectPublicKeyInfo` or DSA `CertificateVerify` blobs.

## Rust API

- **Crate:** `noxtls-crypto` (and **`noxtls-x509`** for PKIX helpers)
- **Integer DSA:** **none**.
- **Closest functional replacements** (see linked pages for full signatures and error behavior):
  - **`noxtls_p256_ecdsa_sign_sha256`**, **`noxtls_p256_ecdsa_verify_sha256`**, **`noxtls_p256_ecdsa_sign_digest`**, **`noxtls_p256_ecdsa_verify_digest`**, plus **`_auto`** variants that draw nonce candidates from **`HmacDrbgSha256`**.
  - **`noxtls_ed25519_verify`**, **`noxtls_ed25519_generate_private_key_auto`**, etc.
  - **`noxtls_mldsa_verify`**, **`noxtls_mldsa_generate_keypair_auto`**, etc.

For **DER-encoded ECDSA signatures** (`SEQUENCE { r, s }`) as used in TLS **`CertificateVerify`**, the codebase uses helpers such as **`noxtls_parse_ecdsa_signature_der`** (see **[Certificates / PKIX](./certs)** and **`noxtls-x509`**) to obtain fixed-width **`(r, s)`** scalars for **`p256_ecdsa_verify_*`**.

## Feature flags and policy

There is **no** `hazardous-legacy-crypto` gate for DSA because DSA is **absent**. Enabling legacy features does **not** add integer DSA.

## Security and compatibility

- **Do not** add ad-hoc DSA without a full parameter-generation story, constant-time **`k`**, and strict **`(p, q, g)`** allow-lists; most new products should **standardize on P-256 ECDSA**, **Ed25519**, or **ML-DSA** per your PKI and TLS profile.
- If a peer **requires** DSA certificates or signatures, you need a **different cryptographic stack** or an external validator until product requirements explicitly add vetted DSA support.

## Related

- [ECC (P-256)](./ecc)
- [Ed25519](./ed25519)
- [ML-DSA](./mldsa)
- [PKC overview](./pkc)
- [Certificates](./certs)
- [TLS](./tls)
- [Hash](./hash)
- [OEM → Rust mapping](./OEM-RUST-API-MAPPING)
- [API index](./api-index)
