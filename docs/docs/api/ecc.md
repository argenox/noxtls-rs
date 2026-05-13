---
title: ECC (P-256 and generic ECC keys)
---

# ECC (P-256 and generic ECC keys)

## Algorithm

**NIST P-256** is the same curve as **ANSI X9.62 / SECG secp256r1**: a **256-bit prime field** short Weierstrass curve with a **256-bit** cofactor-1 group order **`n`**, widely used in **TLS 1.2 and 1.3** (`secp256r1` / `ECDSA_SECP256R1`), ** PKIX**, and **device attestation** stacks.

In **`noxtls-crypto`**, curve arithmetic is implemented in software over that field. Two standard uses are exposed on dedicated types:

- **ECDH (ECIES-style agreement)** — Multiply the peer’s **validated** public point by your private scalar and take the **affine x-coordinate** as a **32-byte big-endian** shared secret (same length as the field element). **`noxtls_p256_ecdh_shared_secret`** and **`P256PrivateKey::diffie_hellman`** reject **invalid points**, **points at infinity**, and an **all-zero** derived secret.
- **ECDSA with SHA-256** — The message is hashed with **SHA-256** to a **32-byte** digest **`e`**, then a **raw ECDSA** signature is returned as **`(r, s)`**, each **32-byte big-endian** scalars mod **`n`**. Verification helpers take the same **`r` / `s`** layout. **TLS `CertificateVerify`** and many PKIX profiles carry **`r` / `s`** wrapped in **ASN.1 DER**; use your PKIX layer (for example **`noxtls_parse_ecdsa_signature_der`** in **`noxtls-x509`**) to convert DER to fixed-width scalars before calling **`p256_ecdsa_verify_*`**.

**Deterministic signing path:** **`sign_digest`** / **`noxtls_p256_ecdsa_sign_digest`** derive the per-signature nonce **`k`** deterministically from **`SHA-256(private_scalar_be32 || digest || counter_be4)`** with an incrementing **`counter`** until a valid signature is found (not the full HMAC construction of **RFC 6979**, but the same *class* of idea: no RNG for **`k`** on that path).

**Randomized signing path:** **`sign_digest_auto`** / **`noxtls_p256_ecdsa_sign_sha256_auto`** draw **32-byte** nonce candidates from **`HmacDrbgSha256`** (label **`b"p256_ecdsa_nonce"`**) with a bounded retry loop.

**Public keys** are represented as **affine** points. **`P256PublicKey::from_uncompressed`** accepts only **65-byte SEC1 uncompressed** form **`0x04 || X || Y`** (each coordinate **32** bytes), and **`validate`** enforces **on-curve** and **range** checks. There is **no** compressed **`02`/`03`** public-key parser in this API surface.

## Purpose

- **TLS** — **`secp256r1`** key shares and **ECDSA-with-SHA256** server authentication in modeled handshake paths (see [TLS](./tls)).
- **Certificates and PKIX** — Parse SPKI / subject keys into **`P256PublicKey`**, verify chains, and map signature blobs to **`(r, s)`** (see [Certificates](./certs)).
- **Application crypto** — Agree keys, sign firmware manifests, or verify attestation quotes using the same primitives.
- **Dispatch** — **`EccPrivateKey`**, **`EccPublicKey`**, and **`noxtls_ecc_generate_keypair_auto`** let higher layers (PSA bridges, key stores, tests) hold **one of several** ECC-style algorithms behind a single enum. Besides **P-256**, the same enums can carry **X25519**, **Ed25519**, and optionally **X448** (see below).

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::pkc` (re-exported at crate root)

### `P256PrivateKey` / `P256PublicKey`

| API | Summary |
| --- | --- |
| **`P256PrivateKey::from_bytes([u8; 32])`** | Parse **big-endian** scalar; must satisfy **`0 < scalar < n`**. |
| **`P256PrivateKey::to_bytes()`** | Serialize scalar to **32** bytes. |
| **`P256PrivateKey::clear()`** / **`Drop`** | Zeroizes scalar limbs. |
| **`P256PrivateKey::public_key()`** | **`G * scalar`** → **`P256PublicKey`**. |
| **`P256PrivateKey::diffie_hellman(&P256PublicKey)`** | ECDH; validates peer; returns **`[u8; 32]`** x-coordinate secret. |
| **`P256PrivateKey::sign_sha256` / `sign_sha256_auto`** | Hash message with **SHA-256**, then **`sign_digest`** / **`sign_digest_auto`**. |
| **`P256PrivateKey::sign_digest` / `sign_digest_auto`** | Sign a **pre-hashed** **32-byte** digest (deterministic vs DRBG nonce). |
| **`P256PublicKey::from_uncompressed(&[u8])`** | **65** bytes, prefix **`0x04`**. |
| **`P256PublicKey::to_uncompressed()`** | Encode **`04||X||Y`**. |
| **`P256PublicKey::validate()`** | On-curve and coordinate checks (used by ECDH/verify). |

### Free functions (thin wrappers)

| Function | Notes |
| --- | --- |
| **`noxtls_p256_generate_private_key_auto(drbg)`** | Rejects invalid scalars from DRBG; loops until **`from_bytes`** succeeds. |
| **`noxtls_p256_ecdh_shared_secret`** | Same as **`diffie_hellman`**. |
| **`noxtls_p256_ecdsa_sign_sha256`**, **`noxtls_p256_ecdsa_sign_sha256_auto`** | Message in, **`(r, s)`** out. |
| **`noxtls_p256_ecdsa_sign_digest`**, **`noxtls_p256_ecdsa_sign_digest_auto`** | Digest in, **`(r, s)`** out. |
| **`noxtls_p256_ecdsa_verify_sha256`**, **`noxtls_p256_ecdsa_verify_digest`** | **`Ok(())`** or **`Err`**; rejects **zero `r`/`s`**. |

### Generic ECC key enums

- **`EccKeyAlgorithm`** — **`P256`**, **`X25519`**, **`X448`**, **`Ed25519`**.
- **`EccPrivateKey`** / **`EccPublicKey`** — One variant per algorithm.
- **`noxtls_ecc_generate_keypair_auto(algorithm, drbg)`** — Returns **`(EccPrivateKey, EccPublicKey)`** for the chosen variant.

**X448:** **`EccKeyAlgorithm::X448`** succeeds only with **`noxtls-crypto`** feature **`hazardous-legacy-crypto`** (calls **`noxtls_x448_generate_private_key_auto`**). Without it, the same selector returns **`StateError`** with a message that X448 is disabled (see [Build configuration](./build_config)). **X25519** and **Ed25519** branches are always available in default builds.

For algorithm-specific guides, see [X25519](./x25519), [Ed25519](./ed25519), and [X448](./x448).

## Feature flags and policy

**P-256** and **`noxtls_ecc_generate_keypair_auto`** for **P256 / X25519 / Ed25519** are part of default **PKC** exports. **X448** requires **`hazardous-legacy-crypto`**.

## Examples

```rust
use noxtls_crypto::{
    noxtls_p256_ecdh_shared_secret, noxtls_p256_generate_private_key_auto, HmacDrbgSha256,
};

let mut drbg = HmacDrbgSha256::new(b"0123456789abcdef", b"nonce", b"").unwrap();
let alice = noxtls_p256_generate_private_key_auto(&mut drbg).unwrap();
let bob = noxtls_p256_generate_private_key_auto(&mut drbg).unwrap();
let alice_pk = alice.public_key().unwrap();
let bob_pk = bob.public_key().unwrap();
let s_a = noxtls_p256_ecdh_shared_secret(&alice, &bob_pk).unwrap();
let s_b = noxtls_p256_ecdh_shared_secret(&bob, &alice_pk).unwrap();
assert_eq!(s_a, s_b);
```

## Security and compatibility

- **Always validate** peer **P-256** public keys (or parse from **vetted** SPKI) before ECDH; invalid curve points are a classic foot-gun.
- **Do not reuse** the raw **32-byte** ECDH output as an AEAD key without a **KDF** (TLS does transcript-based key derivation; applications should use **HKDF** or protocol-specific derivation—see [Hash](./hash)).
- Prefer **`sign_digest`** / **`sign_sha256`** when you want **no DRBG dependency** for signing; use **`*_auto`** when policy requires **randomized** nonces from **`HmacDrbgSha256`** (see [DRBG](./drbg)).
- **Interoperability:** Peers may send **compressed** points in TLS key exchanges; this stack’s **`P256PublicKey`** helpers are oriented to **uncompressed SEC1** at this layer—ensure your TLS/codec path expands or converts as required.

## Related

- [PKC](./pkc)
- [TLS](./tls)
- [Certificates](./certs)
- [DRBG](./drbg)
- [X25519](./x25519)
- [Ed25519](./ed25519)
- [X448](./x448)
- [Security](../security)
