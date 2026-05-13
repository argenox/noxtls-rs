---
title: RSA
---

# RSA

## Algorithm

**RSA** uses modular exponentiation. NoxTLS exposes key material as `RsaPrivateKey` / `RsaPublicKey` and provides high-level helpers for OAEP encryption and PSS signatures with SHA-256.

## Purpose

RSA key generation, OAEP encryption, PKCS#1 v1.5 (legacy), and RSASSA-PSS / PKCS#1 v1.5 signatures in `noxtls-crypto`.

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::pkc`
- **Primary symbols:**
  - `RsaPrivateKey`
  - `RsaPublicKey`
  - `RsaKeySizePolicy`
  - `noxtls_rsa_generate_keypair_secure_auto`
  - `noxtls_rsaes_oaep_sha256_encrypt_auto`
  - `noxtls_rsaes_oaep_sha256_decrypt`
  - `noxtls_rsassa_pss_sha256_sign_auto`
  - `noxtls_rsassa_pss_sha256_verify`

**Functions and types:**

- **`noxtls_rsa_generate_keypair_secure_auto(bits, policy, drbg)`** - Parameters: `bits` is target modulus length, `policy` enforces minimum key-size rules, and `drbg` provides random generation input. Behavior: generates RSA private/public key pair under secure policy checks. Returns: generated keypair in `Result`.
- **`rsaes_oaep_sha256_*`** - Parameters: OAEP encrypt/decrypt calls take RSA key material, plaintext/ciphertext, optional label, and RNG where required. Behavior: performs RSAES-OAEP with SHA-256/MGF1 padding. Returns: encrypted or decrypted byte buffers in `Result`.
- **`noxtls_rsassa_pss_sha256_sign_auto` / `noxtls_rsassa_pss_sha256_verify`** - Parameters: signer uses private key, message, DRBG, and `salt_len`; verifier uses public key, message, signature, and same `salt_len`. Behavior: produces and verifies RSASSA-PSS signatures. Returns: signature bytes for sign, and success/error for verify.

## Feature flags and policy

Some legacy RSA key-generation helpers require `hazardous-legacy-crypto` (see rustdoc).

## Examples

```rust
use noxtls_crypto::{
    noxtls_rsa_generate_keypair_secure_auto, noxtls_rsassa_pss_sha256_sign_auto,
    noxtls_rsassa_pss_sha256_verify, HmacDrbgSha256, RsaKeySizePolicy,
};

let mut drbg = HmacDrbgSha256::new(b"0123456789abcdef", b"nonce", b"")?;
let (private_key, public_key) =
    noxtls_rsa_generate_keypair_secure_auto(2048, RsaKeySizePolicy::Minimum2048, &mut drbg)?;
let message = b"firmware manifest bytes";
let salt_len = 32;
let signature =
    noxtls_rsassa_pss_sha256_sign_auto(&private_key, message, &mut drbg, salt_len)?;
noxtls_rsassa_pss_sha256_verify(&public_key, message, &signature, salt_len)?;
# Ok::<(), noxtls_core::Error>(())
```

Key generation can be CPU-heavy; run once at provisioning or in a background task on MCUs.

## Security and compatibility

Enforce minimum modulus via `RsaKeySizePolicy`; prefer RSASSA-PSS and RSAES-OAEP for new designs.

## Related

- [PKC topic](./pkc)
- [X.509](./x509)
