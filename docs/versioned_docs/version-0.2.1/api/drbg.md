---
title: Crypto API - DRBG
---

# Crypto API: DRBG

NoxTLS uses `HmacDrbgSha256` as the deterministic random source for key generation, nonce material, and handshake randomness.

## Type

- `HmacDrbgSha256`

## Constructor and reseed APIs

### `HmacDrbgSha256::new`

```rust
pub fn new(entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Result<Self>
```

- **`entropy`**: seed entropy; must be at least 16 bytes.
- **`nonce`**: instance nonce.
- **`personalization`**: deployment/application domain separation.

### `HmacDrbgSha256::reseed`

```rust
pub fn reseed(&mut self, entropy: &[u8], additional_input: &[u8]) -> Result<()>
```

- **`entropy`**: fresh entropy (>=16 bytes).
- **`additional_input`**: optional mixed-in context.
- Resets reseed counter and internal state.

## Output API

### `HmacDrbgSha256::generate`

```rust
pub fn generate(&mut self, out_len: usize, additional_input: &[u8]) -> Result<Vec<u8>>
```

- **`out_len`**: number of pseudorandom bytes requested.
- **`additional_input`**: optional per-call context.
- Returns `Error::StateError` when reseed is required by counter policy.

## Typical call sites

- TLS randomness: `Connection::send_client_hello_auto`.
- PKC keygen helpers: `noxtls_p256_generate_private_key_auto`, `noxtls_ed25519_generate_private_key_auto`, RSA PSS salt generation.

## Operational guidance

- Keep DRBG state per-security-domain (do not share one instance across unrelated tenants).
- Reseed after boot entropy refresh, hardware TRNG events, or long-lived sessions.
- Persisting DRBG state is generally avoided on embedded devices; reseed on startup instead.
