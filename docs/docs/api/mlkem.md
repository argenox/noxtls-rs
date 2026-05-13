---
title: ML-KEM
---

# ML-KEM

## Algorithm

ML-KEM (FIPS 203) is a post-quantum key encapsulation mechanism (KEM): encapsulation yields a ciphertext plus shared secret, decapsulation recovers the same shared secret.

## Purpose

Post-quantum key encapsulation (FIPS 203).

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::pkc`
- **Primary symbols:**
  - `MlKemPrivateKey`
  - `MlKemPublicKey`
  - `noxtls_mlkem_generate_keypair_auto`
  - `noxtls_mlkem_encapsulate_auto`
  - `noxtls_mlkem_decapsulate`

**Functions and types:**

- **`noxtls_mlkem_generate_keypair_auto(drbg)`** - Parameters: `drbg`. Behavior: Generate `(private, public)` key pair. Returns: `unspecified output`.
- **`noxtls_mlkem_encapsulate_auto(public, drbg)`** - Parameters: `public, drbg`. Behavior: Produce `(ciphertext, shared_secret)`. Returns: `unspecified output`.
- **`noxtls_mlkem_decapsulate(private, ciphertext)`** - Parameters: `private, ciphertext`. Behavior: Recover shared secret from ciphertext. Returns: `unspecified output`.

## Feature flags and policy

Enable PQC-related features on `noxtls` / `noxtls-core` per product matrix.

## Examples

```rust
use noxtls_crypto::{
    HmacDrbgSha256, noxtls_mlkem_decapsulate, noxtls_mlkem_encapsulate_auto, noxtls_mlkem_generate_keypair_auto,
};

let mut drbg = HmacDrbgSha256::new(b"0123456789abcdef", b"nonce", b"mlkem")?;
let (sk, pk) = noxtls_mlkem_generate_keypair_auto(&mut drbg)?;
let (ct, ss_sender) = noxtls_mlkem_encapsulate_auto(&pk, &mut drbg)?;
let ss_receiver = noxtls_mlkem_decapsulate(&sk, &ct)?;
assert_eq!(ss_sender, ss_receiver);
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

Isolate PQ keys and ciphertext sizes in firmware buffer planning.

## Related

- [PKC topic](./pkc)
- [TLS 1.3 PQC](./tls13_pqc)
- [Quantum crypto](../../quantum-crypto)
