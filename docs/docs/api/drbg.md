---
title: Crypto API - DRBG
---

# Crypto API: DRBG

NoxTLS exposes **`HmacDrbgSha256`**, an **HMAC-DRBG** construction using **HMAC-SHA-256** in an **SP 800-90A–style** update and generate loop (see `noxtls-crypto` `drbg` module). It expands a **small seed** into arbitrary-length outputs for **key generation**, **nonces**, **TLS handshake random**, and other protocol needs.

The type is **deterministic given its inputs**: anyone who knows the full seed material and the sequence of **`generate`** / **`reseed`** calls can reproduce the byte stream. Security therefore rests entirely on **how you obtain and protect entropy**, not on the DRBG “hiding” a weak seed.

## Type

- **`HmacDrbgSha256`** — Holds internal **`K`** / **`V`** state (32-byte each) and a **`reseed_counter`**. **`Clone`** duplicates live state; treat cloned instances like forked RNG state (see [Forking and cloning](#forking-and-cloning)).

## Algorithm (what the implementation does)

On **`new`**, the implementation forms **`seed = entropy ‖ nonce ‖ personalization`**, runs the internal **`update(Some(&seed))`**, and sets **`reseed_counter`** to **`1`**.

On **`generate(out_len, additional_input)`** (with **`out_len > 0`**):

1. If **`reseed_counter > 1_000_000`**, returns **`Error::StateError("drbg reseed required")`** (see [Reseed policy](#reseed-policy)).
2. If **`additional_input`** is non-empty, **`update(Some(additional_input))`** runs first.
3. Keystream is produced by repeated **`V = HMAC-SHA256(K, V)`**, concatenating until **`out_len`** bytes exist, then truncating.
4. A final **`update`** step runs (with the same **`additional_input`** path as SP 800-90A style post-generation mixing).
5. **`reseed_counter`** is incremented by **one per `generate` call** (not per output byte).

If **`out_len == 0`**, **`generate`** returns an empty **`Vec`** immediately and **does not** advance **`reseed_counter`** (useful for tests; do not rely on this for “free” mixing—use **`reseed`** or non-empty **`generate`** when you intend to advance state).

## Entropy source (caller responsibility)

**This library does not read `/dev/urandom`, `getrandom`, or hardware TRNGs for you.** You must pass byte buffers into **`HmacDrbgSha256::new`** and **`reseed`**.

Typical sources, depending on platform:

- **OS CSPRNG** (e.g. **`getrandom`** on Linux, **`BCryptGenRandom`** on Windows, appropriate HAL on RTOS).
- **Hardware RNG** or **secure element** when available and audited for your product class.
- **HKDF or hash stretching** over multiple jitter / bootloader / chip-unique reads is **not** a substitute for an actual unpredictable entropy source unless your system design has already justified it as a CSPRNG seed.

**Minimum length enforced by this API:** **`entropy`** must be **at least 16 bytes** in **`new`** and **`reseed`**, or you get **`Error::InvalidLength`**. For new designs, prefer **≥ 32 bytes** (256 bits) of **full-entropy** seed material where your platform allows, so you are not pinned to the library’s floor.

## How to seed and instantiate

### `HmacDrbgSha256::new`

```rust
pub fn new(entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Result<Self>
```

| Argument | Role | Practical guidance |
| --- | --- | --- |
| **`entropy`** | Primary seed | High-entropy bytes from your platform RNG or HSM; **≥ 16 bytes** (prefer **≥ 32**). |
| **`nonce`** | Second distinct seeding field | Use **fresh** bytes per DRBG instance (often from the same RNG read as entropy, but **not** identical to **`entropy`** if you can avoid it—e.g. split one 48-byte draw into two parts, or two sequential draws). |
| **`personalization`** | Domain separation | Stable per use-case string (e.g. **`b"tls-client"`**, **`b"p256-keygen"`**) so two logical DRBGs instantiated from similar environmental randomness still diverge. |

**Uniqueness:** Create a **new** **`HmacDrbgSha256`** per long-lived security context (session, device identity, tenant) rather than one global object for unrelated keys.

### `HmacDrbgSha256::reseed`

```rust
pub fn reseed(&mut self, entropy: &[u8], additional_input: &[u8]) -> Result<()>
```

Mixes **`entropy ‖ additional_input`** through **`update`**, then resets **`reseed_counter`** to **`1`**. Use when:

- You hit **`StateError("drbg reseed required")`** (mandatory).
- You obtain **new** platform entropy (boot, wakeup, operator command).
- You want **prediction resistance**-style behavior relative to an old state (only meaningful if **`entropy`** is fresh and independent of the old DRBG state).

## Output API

### `HmacDrbgSha256::generate`

```rust
pub fn generate(&mut self, out_len: usize, additional_input: &[u8]) -> Result<Vec<u8>>
```

- **`additional_input`**: Optional per-call context (labels such as **`b"client_hello_random"`** in TLS helpers). Non-empty input triggers an **`update`** before and the prescribed path after generation.

## Reseed policy

After **`1_000_000`** successful invocations of **`generate`** with **`out_len > 0`** (i.e. when the internal counter would exceed **`1_000_000`** on the next call), further **`generate`** calls return **`Error::StateError("drbg reseed required")`** until you call **`reseed`** with **≥ 16 bytes** of fresh **`entropy`**.

**Handling:** On that error, obtain new entropy, call **`reseed(&fresh_entropy, additional_label)`**, then **retry** the failed **`generate`**. Do not reset the object by hand unless you intend to discard all forward secrecy properties of the old state.

## Failure modes and handling

| Error | When | What to do |
| --- | --- | --- |
| **`Error::InvalidLength`** (`"drbg entropy input must be at least 16 bytes"`) | **`new`** or **`reseed`** with **`entropy.len() < 16`** | Read more bytes from your RNG; **do not** pad low-entropy secrets to 16 bytes and assume safety. Fail closed if the platform cannot supply enough bytes. |
| **`Error::StateError`** (`"drbg reseed required"`) | **`generate`** after the internal counter limit | **`reseed`** with fresh **`entropy`**, then retry **`generate`**. |
| Upstream errors | Callers (TLS, PKC) propagate their own **`Result`** | Treat as fatal for the current handshake or keygen attempt; do not partially commit secrets on error paths. |

There is no **`try_generate`** split: either you receive **`Ok(Vec<u8>)`** or an **`Err`**. On **`Err`**, the DRBG may have advanced state depending on where the callee failed—when in doubt, **`reseed`** before continuing security-sensitive work.

## Forking and cloning

- **`#[derive(Clone)]`** copies **`K`**, **`V`**, and **`reseed_counter`**. Two clones produce **identical** streams if **`generate`** sequences match—dangerous if one copy is attacker-visible.
- After **`fork()`** (Unix) or similar process split, child and parent **must not** continue using the same DRBG state without **re-seeding one side** with fresh entropy (standard fork-safety guidance for user-space RNGs).

## Security properties and limits

- **Strength:** Output is keyed by the evolving **`K` / `V`** state; breaking prediction requires breaking HMAC-SHA-256 assumptions on the secret state, **provided** the seed was unpredictable.
- **Not a system RNG:** It does not replace the OS RNG; it is a **portable, testable** primitive for protocols that already take a **`&mut HmacDrbgSha256`**.
- **Prediction resistance** in the strict NIST sense requires **explicit reseed with fresh entropy** between outputs when your threat model demands it; automatic prediction resistance is **not** built in beyond the **`1_000_000`**-call limit.
- **Forward secrecy** for past outputs is **not** implied after **`reseed`** unless your protocol design uses the new state only for new keys.

For product-level randomness policy, see [Security](../security).

## Typical call sites

- **TLS:** `Connection::send_client_hello_auto` and related `*_auto` helpers call **`drbg.generate(32, b"client_hello_random")`** (and similar patterns elsewhere in the connection stack).
- **PKC:** `noxtls_p256_generate_private_key_auto`, `noxtls_ed25519_generate_private_key_auto`, `noxtls_x25519_generate_private_key_auto`, RSA PSS salt generation, ML-KEM / ML-DSA helpers, etc.

## Operational guidance

- Keep **one DRBG (or clearly separated instances)** per **security domain**; do not share **`&mut`** across unrelated tenants.
- **Reseed** after boot entropy refresh, long idle periods, or high-volume servers approaching the **`generate`** counter limit.
- On **embedded** devices, prefer **fresh entropy on boot** into **`new`** or **`reseed`** over persisting **`K`/`V`** to non-volatile storage (unless your threat model and key hierarchy explicitly allow it).

## Related

- [Security](../security)
- [Hash](./hash) (HMAC-SHA-256 underpins this DRBG)
- [PKC](./pkc)
- [TLS](./tls)
