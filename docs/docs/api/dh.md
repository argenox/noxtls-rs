---
title: Finite-field DH
---

# Finite-field DH

## Algorithm

**Finite-field Diffie–Hellman** (sometimes written **FFDH** or classical **DH**) fixes a large prime **`p`**, a generator **`g`** of a large subgroup, and has each party pick a secret integer. The public values are **`g^a mod p`** and **`g^b mod p`**; both parties derive the same shared secret **`g^{ab} mod p`**. In practice you need **vetted domain parameters** (safe primes, subgroup checks, size policy), **constant-time** modular exponentiation, and almost always a **KDF** (for example HKDF) on the raw shared secret before using it as key material.

## Purpose in NoxTLS

**NoxTLS does not ship a standalone public API** for classical **`(p, g)`** Diffie–Hellman (no general-purpose modular-exponentiation DH key agreement in **`noxtls-crypto`** for arbitrary groups). OEM or legacy documentation that refers to **PKCS #3**-style DH, **TLS 1.2 `dh_anon` / `DHE_*` with explicit `p` and `g`**, or **RFC 7919 FFDHE** groups should be treated as **out of scope** for a direct one-to-one mapping unless you integrate an external vetted implementation.

For **key agreement inside this stack**, use **elliptic-curve** Diffie–Hellman instead:

| Goal | Where to look |
| --- | --- |
| **P-256 ECDH** | [`noxtls_p256_ecdh_shared_secret`](./ecc), **`P256PrivateKey::diffie_hellman`**, TLS 1.3 **`secp256r1`** key shares |
| **X25519** | [`noxtls_x25519_shared_secret`](./x25519), TLS 1.3 **`x25519`** key shares |
| **X448** (optional legacy curve) | [X448](./x448) — **`X448PrivateKey::diffie_hellman_checked`** behind **`hazardous-legacy-crypto`** |

TLS 1.3 key exchange in this codebase is built around **ECDHE** material (for example **`noxtls_derive_tls13_x25519_shared_secret`** / **`noxtls_derive_tls13_p256_shared_secret`** in the **`noxtls`** protocol layer), not finite-field **`g^ab mod p`**.

## TLS 1.2 note

Some TLS 1.2 code paths parse **`ServerKeyExchange`** with **named-curve (EC) DHE** shape expectations (for example **`named_curve`** parameter encoding), not classical finite-field **`p` / `g`** DH payloads. Do not assume that **FFDHE** or legacy **`DHE_RSA`** with explicit group parameters are supported just because “DH” appears in an OEM TLS profile name.

## Rust API (what exists instead)

- **Crate:** `noxtls-crypto` (re-exported from **`noxtls`** where applicable)
- **Module path (conceptual):** `noxtls_crypto::pkc`
- **Finite-field DH:** **no** dedicated types or **`dh_*`** agreement functions.
- **ECDH helpers** (typical replacement):
  - **`noxtls_p256_ecdh_shared_secret(private_key: &P256PrivateKey, peer_public_key: &P256PublicKey) -> Result<[u8; 32]>`** — validates the peer point and rejects degenerate shared secrets.
  - **`noxtls_x25519_shared_secret(local_private: X25519PrivateKey, peer_public: X25519PublicKey) -> Result<[u8; 32]>`** — checked X25519; local private key is taken **by value** (clone if you need to reuse it).

After any raw shared secret, combine with your protocol’s **KDF** and **transcript binding** (TLS does this in the handshake transcript); see [Hash](./hash) for primitives such as **SHA-256** / **HKDF** where applicable.

## Feature flags and policy

- **P-256** and **X25519** ECDH are part of the default PKC surface (see [PKC](./pkc)).
- **X448** agreement is gated by **`hazardous-legacy-crypto`** (see [Build configuration](./build_config)).

## Security and compatibility

Finite-field DH is easy to get wrong (weak or non-standard groups, small subgroups, **logjam**-class parameter choices, side channels). Modern protocols prefer **ECDHE** with standard curves (**X25519**, **P-256**) or **post-quantum** hybrids where applicable. If you must interoperate with a peer that insists on **FFDHE**, plan on a **separately reviewed** implementation and strict parameter allow-lists.

## Related

- [ECC (P-256)](./ecc)
- [X25519](./x25519)
- [PKC overview](./pkc)
- [TLS](./tls)
- [OEM → Rust mapping](./OEM-RUST-API-MAPPING)
- [API index](./api-index)
- [Hash](./hash)
