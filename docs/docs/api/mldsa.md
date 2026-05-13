---
title: ML-DSA
---

# ML-DSA

## Algorithm

ML-DSA (FIPS 204) is a lattice-based signature family; this page documents the ML-DSA-65 APIs exposed by `noxtls-crypto`.

## Purpose

Post-quantum signatures (FIPS 204) â€” generation and verification.

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::pkc`
- **Primary symbols:**
  - `MlDsaPrivateKey`
  - `MlDsaPublicKey`
  - `noxtls_mldsa_generate_keypair_auto`
  - `noxtls_mldsa_verify`
  - `noxtls_mldsa_public_key_from_subject_public_key_info`

**Functions and types:**

- **`noxtls_mldsa_generate_keypair_auto(drbg)`** - Parameters: `drbg`. Behavior: Generate private/public key pair. Returns: `unspecified output`.
- **`MlDsaPrivateKey::sign(message)`** - Parameters: `message`. Behavior: Create signature bytes. Returns: `unspecified output`.
- **`noxtls_mldsa_verify(public, message, signature)`** - Parameters: `public, message, signature`. Behavior: Verify detached signature. Returns: `unspecified output`.
- **`noxtls_mldsa_public_key_from_subject_public_key_info(der)`** - Parameters: `der`. Behavior: Parse public key from SPKI. Returns: `unspecified output`.

## Feature flags and policy

PQ signature OIDs and TLS extensions require matching crate features.

## Examples

```rust
use noxtls_crypto::{HmacDrbgSha256, noxtls_mldsa_generate_keypair_auto, noxtls_mldsa_verify};

let mut drbg = HmacDrbgSha256::new(b"0123456789abcdef", b"nonce", b"mldsa")?;
let (sk, pk) = noxtls_mldsa_generate_keypair_auto(&mut drbg)?;
let msg = b"pqc-signature-message";
let sig = sk.sign(msg);
noxtls_mldsa_verify(&pk, msg, &sig)?;
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

ML-DSA-65 uses fixed key/signature sizes; validate PKIX OIDs.

## Related

- [PKC topic](./pkc)
- [TLS 1.3 PQC](./tls13_pqc)
