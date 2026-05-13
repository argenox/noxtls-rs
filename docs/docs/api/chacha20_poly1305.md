---
title: ChaCha20-Poly1305
---

# ChaCha20-Poly1305

## Algorithm

**ChaCha20-Poly1305** is an **AEAD** defined in **RFC 8439** (the same construction TLS 1.3 labels **`CHACHA20_POLY1305`**). It uses a **256-bit (32-byte)** key and a **96-bit (12-byte)** **nonce** that must be **unique for each message** under that key. **Poly1305** authenticates the **ciphertext** and **additional authenticated data (AAD)**; AAD is integrity-protected but not encrypted—typical for record headers or framing metadata.

In this implementation, the first ChaCha20 block (**counter = 0**) feeds **`noxtls_poly1305_key_gen`** to derive the **one-time Poly1305 key**. The keystream for the payload starts at **counter = 1**. The MAC input is **`AAD || pad16(AAD) || ciphertext || pad16(ciphertext) || len(AAD)_LE64 || len(ciphertext)_LE64`**, matching RFC 8439’s `pad16` and length encoding. The authentication tag is always **16 bytes**. Very large messages are rejected when length would exceed the RFC **ChaCha20 block counter** range (implementation limit on the order of **256 GiB** per message).

## Purpose

Use these helpers when you need **authenticated encryption with associated data** without AES (for example TLS 1.3 cipher suites, embedded stacks that prefer ChaCha20, or application framing). For ChaCha20 **without** Poly1305, see [ChaCha20](./chacha20).

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym` (re-exported at crate root)
- **Primary symbols:**
  - `noxtls_chacha20_poly1305_encrypt`
  - `noxtls_chacha20_poly1305_decrypt`
  - `noxtls_poly1305_mac`
  - `noxtls_poly1305_key_gen`

**Functions and types:**

- **`noxtls_chacha20_poly1305_encrypt(key, nonce, aad, plaintext) -> Result<(Vec<u8>, [u8; 16])>`** - Parameters: **`key`** is a **32-byte** secret; **`nonce`** is a **12-byte** per-message value unique under `key`; **`aad`** may be empty; **`plaintext`** is the payload (length bounded by the RFC counter range). Behavior: derives the Poly1305 key from block counter **0**, encrypts with ChaCha20 from counter **1** onward, computes the **16-byte** tag over RFC 8439 MAC data. Returns: ciphertext (same length as plaintext) and tag, or **`InvalidLength`** if the payload is too large for the counter space.
- **`noxtls_chacha20_poly1305_decrypt(key, nonce, aad, ciphertext, tag) -> Result<Vec<u8>>`** - Parameters: same **`key`**, **`nonce`**, and **`aad`** as encryption; **`ciphertext`** and **`tag`** from the sender. Behavior: recomputes the Poly1305 tag and compares in **constant time**; only if it matches does it XOR-decrypt the ciphertext. Returns: plaintext **`Vec<u8>`** on success, **`CryptoFailure`** if the tag is wrong, or **`InvalidLength`** if ciphertext length is out of range.
- **`noxtls_poly1305_key_gen` / `noxtls_poly1305_mac`** — Lower-level building blocks used by this AEAD; prefer **`noxtls_chacha20_poly1305_*`** unless you are implementing another RFC 8439-shaped construction.

## Feature flags and policy

Default features.

## Examples

```rust
use noxtls_crypto::{noxtls_chacha20_poly1305_decrypt, noxtls_chacha20_poly1305_encrypt};

let key = [0x11u8; 32];
let nonce = [0x22u8; 12];
let aad = b"header";
let plaintext = b"secret payload";
let (ciphertext, tag) = noxtls_chacha20_poly1305_encrypt(&key, &nonce, aad, plaintext)?;
let recovered = noxtls_chacha20_poly1305_decrypt(&key, &nonce, aad, &ciphertext, &tag)?;
assert_eq!(recovered, plaintext);
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

Never reuse a **`(key, nonce)`** pair for two different messages: nonce reuse typically breaks both confidentiality and authenticity for Poly1305 in this construction. Use a random nonce from a DRBG, or a **counter** nonce only if you can prove it cannot wrap within the key’s lifetime. Decryption **must** use the exact same **`aad`** bytes as encryption; verify the **128-bit tag** before acting on decrypted plaintext. Prefer **constant-time** tag comparison (this crate uses **`noxtls_poly1305_tags_equal`** on decrypt).

## Related

- [ChaCha20](./chacha20)
- [TLS topic](./tls)
- [Symmetric topic](./sym)
