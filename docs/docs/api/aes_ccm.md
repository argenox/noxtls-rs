---
title: AES-CCM
---

# AES-CCM

## Algorithm

**CCM** (Counter with CBC-MAC) combines AES-CTR confidentiality with CBC-MACâ€“style authentication in a single construction. In NoxTLS, AES-CCM is exposed as an AEAD pair: `noxtls_aes_ccm_encrypt` produces ciphertext plus a **16-byte** authentication tag; `noxtls_aes_ccm_decrypt` verifies that tag before returning plaintext.

The implementation follows the usual CCM encoding: a formatting block ties together nonce length, payload length bounds, and optional AAD presence. Nonce length fixes the maximum representable payload size for that `q` parameter (see code constraints below).

## Purpose

Document AES-CCM authenticated encryption and decryption using a shared `AesCipher` key schedule, for interoperability with profiles that require CCM (for example some constrained TLS or non-TLS uses).

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym` (re-exported at crate root)
- **Primary symbols:**
  - `AesCipher`
  - `noxtls_aes_ccm_encrypt`
  - `noxtls_aes_ccm_decrypt`

**Functions and types:**

- **`noxtls_aes_ccm_encrypt(cipher, nonce, aad, plaintext) -> Result<(Vec<u8>, [u8; 16])>`** - Parameters: `cipher` is an initialized `AesCipher`; `nonce` must be **7 to 13 bytes** inclusive (this sets CCM `L`/`Q` and caps maximum plaintext length); `aad` is additional authenticated data (may be empty); `plaintext` is the payload to encrypt. Behavior: runs AES-CCM encryption and computes a **16-byte** MAC tag. Returns: ciphertext bytes and `[u8; 16]` tag on success, or `InvalidLength` / other errors if nonce or length rules are violated.
- **`noxtls_aes_ccm_decrypt(cipher, nonce, aad, ciphertext, tag) -> Result<Vec<u8>>`** - Parameters: same `cipher`, `nonce`, and `aad` as used for encryption; `ciphertext` is encrypted payload without the tag; `tag` is the **16-byte** tag from encrypt. Behavior: verifies authenticity then decrypts. Returns: plaintext `Vec<u8>` on success, or `CryptoFailure` (or length errors) if verification fails or inputs are invalid.

## Feature flags and policy

Standard `noxtls-crypto` build. (ECB and other legacy modes are unrelated; see [AES-ECB](./aes_ecb) if needed.)

## Examples

Full round-trip: expand the key once, encrypt to `(ciphertext, tag)`, decrypt with the same `nonce` and `aad`. The tag is always **16 bytes**; the nonce slice must be **7 to 13 bytes**.

```rust
use noxtls_core::Error;
use noxtls_crypto::{AesCipher, noxtls_aes_ccm_decrypt, noxtls_aes_ccm_encrypt};

/// Encrypt then decrypt under the same key, nonce, and AAD; returns `Ok(())` if the tag verifies.
fn ccm_roundtrip(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(), Error> {
    let cipher = AesCipher::new(key)?;
    let (ciphertext, tag) = noxtls_aes_ccm_encrypt(&cipher, nonce, aad, plaintext)?;
    let decrypted = noxtls_aes_ccm_decrypt(&cipher, nonce, aad, &ciphertext, &tag)?;
    assert_eq!(decrypted.as_slice(), plaintext);
    Ok(())
}

// 128-, 192-, or 256-bit key
let key = [0x40u8; 32];
// Shortest allowed nonce (7 bytes); longer nonces are also valid up to 13 bytes
let nonce = [0xAAu8; 7];
let aad = b"record-header"; // may be empty: `&[]`
let plaintext = b"payload protected by CCM";

ccm_roundtrip(&key, &nonce, aad, plaintext)?;

// Empty AAD is fine: authentication still covers plaintext via the tag
let key16 = [0x3Cu8; 16];
let nonce12 = [0x01u8; 12];
ccm_roundtrip(&key16, &nonce12, &[], b"aad-free message")?;
# Ok::<(), Error>(())
```

## Security and compatibility

Use a fresh nonce for every encryption under the same key. Decryption must supply the exact same `nonce` and `aad` as encryption; the 16-byte tag must be verified before plaintext is used. Choosing a shorter nonce increases the maximum encodable payload length under CCMâ€™s length encoding; the implementation enforces consistency between nonce length and payload size.

## Related

- [Symmetric topic](./sym)
- [AES-GCM](./aes_gcm)
- [TLS topic](./tls)
