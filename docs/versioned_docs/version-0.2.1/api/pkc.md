---
title: Crypto API - Public Key
---

# Crypto API: Public-key cryptography

`noxtls-crypto::pkc` provides RSA, ECC (P-256), Ed25519, and post-quantum helpers used by TLS and PKI flows.

## P-256 APIs

```rust
pub fn noxtls_p256_generate_private_key_auto(drbg: &mut HmacDrbgSha256) -> Result<P256PrivateKey>
pub fn noxtls_p256_ecdh_shared_secret(
    private_key: &P256PrivateKey,
    peer_public_key: &P256PublicKey,
) -> Result<[u8; 32]>
pub fn noxtls_p256_ecdsa_sign_sha256(
    private_key: &P256PrivateKey,
    message: &[u8],
) -> Result<([u8; 32], [u8; 32])>
pub fn noxtls_p256_ecdsa_verify_sha256(
    public_key: &P256PublicKey,
    message: &[u8],
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<()>
```

- `noxtls_p256_generate_private_key_auto` draws scalar candidates from DRBG.
- ECDSA signatures are represented as raw `(r, s)` scalar arrays.

## Ed25519 APIs

```rust
pub fn noxtls_ed25519_generate_private_key_auto(drbg: &mut HmacDrbgSha256) -> Result<Ed25519PrivateKey>
pub fn noxtls_ed25519_verify(
    public_key: &Ed25519PublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<()>
```

- `signature` must be exactly 64 bytes.

## RSA APIs

```rust
pub fn noxtls_rsa_generate_keypair_secure_auto(
    modulus_bits: usize,
    policy: RsaKeySizePolicy,
    drbg: &mut HmacDrbgSha256,
) -> Result<(RsaPrivateKey, RsaPublicKey)>
```

- **`modulus_bits`**: key size request.
- **`policy`**: enforces minimum/allowed modulus rules.

```rust
pub fn noxtls_rsassa_pss_sha256_sign_auto(
    private: &RsaPrivateKey,
    msg: &[u8],
    drbg: &mut HmacDrbgSha256,
    salt_len: usize,
) -> Result<Vec<u8>>
pub fn noxtls_rsassa_pss_sha256_verify(
    public: &RsaPublicKey,
    msg: &[u8],
    signature: &[u8],
    salt_len: usize,
) -> Result<()>
```

- `salt_len` must match verifier expectation.

```rust
pub fn noxtls_rsaes_oaep_sha256_encrypt_auto(
    public: &RsaPublicKey,
    plaintext: &[u8],
    label: &[u8],
    drbg: &mut HmacDrbgSha256,
) -> Result<Vec<u8>>
pub fn noxtls_rsaes_oaep_sha256_decrypt(
    private: &RsaPrivateKey,
    ciphertext: &[u8],
    label: &[u8],
) -> Result<Vec<u8>>
```

- `label` must match on encrypt/decrypt.

## Security guidance

- Prefer PSS/OAEP over PKCS#1 v1.5 for new integrations.
- Keep DRBG health/reseed policy explicit for key generation paths.
- Consider `RsaKeySizePolicy` strict modes for long-lived credentials.
