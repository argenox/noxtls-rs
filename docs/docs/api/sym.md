---
title: Crypto API - Symmetric
---

# Crypto API: Symmetric ciphers and AEAD

`noxtls-crypto::sym` includes block/stream transforms and AEAD primitives used by TLS record protection and application payload encryption.

## Core cipher type

- `AesCipher` (initialized with key material once, reused per operation mode).

## AES block/stream modes

```rust
pub fn noxtls_aes_cbc_encrypt(cipher: &AesCipher, iv: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>>
pub fn noxtls_aes_cbc_decrypt(cipher: &AesCipher, iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>>
pub fn noxtls_aes_ctr_apply(cipher: &AesCipher, nonce_counter: &[u8; 16], input: &[u8]) -> Vec<u8>
```

- **CBC**: requires block-aligned input; returns `InvalidLength` otherwise.
- **CTR**: encryption/decryption use the same transform; `nonce_counter` must be unique per key.

## AEAD APIs

```rust
pub fn noxtls_aes_gcm_encrypt(
    cipher: &AesCipher,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16])>
pub fn noxtls_aes_gcm_decrypt(
    cipher: &AesCipher,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>>
```

- **`nonce`**: GCM nonce bytes.
- **`aad`**: additional authenticated data (not encrypted, but authenticated).
- **`tag`**: 16-byte authentication tag; decryption fails with `CryptoFailure` on mismatch.

```rust
pub fn noxtls_aes_ccm_encrypt(
    cipher: &AesCipher,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16])>
pub fn noxtls_aes_ccm_decrypt(
    cipher: &AesCipher,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>>
```

- CCM requires nonce length in `7..=13`; enforced by API.

## ChaCha20-Poly1305 APIs

```rust
pub fn noxtls_chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16])>
pub fn noxtls_chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>>
```

- Verifies tag before decrypt output is accepted.
- Enforces RFC 8439 counter-range bounds for large payloads.

## Integration notes

- Never reuse `(key, nonce)` pairs for AEAD functions.
- Keep AAD format stable and versioned across sender/receiver.
- For TLS record traffic, prefer `Connection::seal_record` / `open_record` wrappers instead of direct primitive calls.

## Per-algorithm pages

See [Encryption hub](./encryption) and the AES, ARIA, Camellia, ChaCha20, DES, and RC4 pages linked from [API index](./api-index) (symmetric section).
