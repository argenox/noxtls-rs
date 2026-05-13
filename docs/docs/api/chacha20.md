---
title: ChaCha20
---

# ChaCha20

## Algorithm

**ChaCha20** is a stream cipher specified in **RFC 8439** (IETF variant: **256-bit key**, **96-bit nonce**, **32-bit block counter** in word 12 of the state). The core is a **20-round** (10 double rounds) permutation on a 512-bit state; output is taken in **64-byte** blocks XORed with the data. **`ChaCha20::apply_keystream`** generates successive keystream blocks and **increments the block counter** after each full or partial block.

Encryption and decryption are the **same** operation: XOR with the same keystream. The initial **`counter`** argument selects the first block counter value; **RFC 8439 ChaCha20-Poly1305** in this library uses **counter 0** only for **`noxtls_poly1305_key_gen`** and starts the message keystream at **counter 1**, so raw ChaCha20 callers should pick counters consistently with any AEAD framing they interop with.

The block counter is a **`u32`** that **wraps on overflow**; extremely long single messages can therefore repeat keystream if you exceed the implied **64 × 2³²** byte bound (~**256 GiB**) without re-keying—avoid relying on wraparound.

## Purpose

Expose **standalone ChaCha20** for protocols or tests that need the stream cipher **without** Poly1305. For **authenticated** encryption, use **[ChaCha20-Poly1305](./chacha20_poly1305)** instead unless you combine ChaCha20 with a separate MAC in a reviewed construction.

## Rust API

- **Crate:** `noxtls-crypto`
- **Module path (conceptual):** `noxtls_crypto::sym` (re-exported at crate root)
- **Primary symbols:**
  - `ChaCha20`

**Functions and types:**

- **`ChaCha20::new(key, nonce, counter) -> ChaCha20`** - Parameters: **`key`** is **`[u8; 32]`**; **`nonce`** is **`[u8; 12]`**; **`counter`** is the initial **32-bit block counter** (word 12). Behavior: initializes the RFC 8439 “expand 32-byte k” constants, key words, counter, and nonce layout. Returns: cipher state (no `Result`; sizes are enforced by the type system).
- **`apply_keystream(&mut self, input, output) -> Result<()`>** - Parameters: **`input`** and **`output`** must have the **same length**. Behavior: XORs **`input`** with generated keystream, advancing the internal block counter for each 64-byte unit consumed. Returns: **`Ok(())`** or **`InvalidLength`** if buffer lengths differ.
- **`block_output(&self) -> [u8; 64]`** - Returns the current **64-byte** keystream block **without** advancing the counter (for inspection or custom stepping; normal streaming uses **`apply_keystream`**).

## Feature flags and policy

Standard `noxtls-crypto` build.

## Examples

```rust
use noxtls_crypto::ChaCha20;

let key = [0x01u8; 32];
let nonce = [0u8; 12];
// Match RFC 8439 AEAD message stream: first keystream block for data uses counter 1
let mut enc = ChaCha20::new(&key, &nonce, 1);
let plaintext = b"hello-chacha";
let mut ciphertext = vec![0u8; plaintext.len()];
enc.apply_keystream(plaintext, &mut ciphertext)?;

let mut dec = ChaCha20::new(&key, &nonce, 1);
let mut recovered = vec![0u8; ciphertext.len()];
dec.apply_keystream(&ciphertext, &mut recovered)?;
assert_eq!(recovered, plaintext);
# Ok::<(), noxtls_core::Error>(())
```

## Security and compatibility

**Never reuse `(key, nonce)`** for two different messages with the same counter progression: reuse exposes XOR of plaintexts. If you use a **random nonce** per message, size it to **12 bytes** from a DRBG; if you use a **counter nonce**, ensure it cannot collide under a key within the deployment lifetime. ChaCha20 alone provides **no integrity**—bit flips in ciphertext flip matching plaintext bits—so pair with **[ChaCha20-Poly1305](./chacha20_poly1305)** or another MAC unless a standard specifies otherwise.

## Related

- [ChaCha20-Poly1305](./chacha20_poly1305)
- [Symmetric topic](./sym)
