---
title: Common (core)
---

# Common (core)

## Purpose

**`noxtls-core`** is the shared foundation for the whole NoxTLS Rust workspace. Every other crate depends on it for:

- **`Error`** and **`Result<T>`** — one consistent error surface for length, encoding, parse, crypto, state, and unsupported-feature failures.
- **Build-time profile metadata** — **`Profile`**, **`FeatureSet`**, and **`LibraryConfig`** / **`SecurityPolicy`** so binaries can align runtime behavior with Cargo features.
- **Small wire-format helpers** — for example **`noxtls_read_u16_be`** / **`noxtls_read_u24_be`** used when parsing TLS-length prefixes and similar blobs.
- **Memory hygiene helpers** — **`noxtls_secure_zero`** for clearing sensitive buffers when you are done with them.

This page summarizes the pieces most applications touch directly; the [Core](./core) topic links the wider story (timeouts, buffers, and protocol-facing types).

## Error model

**`Error`** is a non-exhaustive-style **enum of static-message variants** (good for `no_std` and for avoiding allocation on error paths):

| Variant | Typical cause |
| ------- | ------------- |
| **`InvalidLength`** | Buffer too short/long, wrong key size, misaligned CBC input, etc. |
| **`InvalidEncoding`** | PEM/UTF-8/DER or other encoding rules violated. |
| **`ParseFailure`** | ASN.1 / certificate / wire structure could not be parsed. |
| **`UnsupportedFeature`** | Capability compiled out or policy forbids the operation. |
| **`CryptoFailure`** | MAC/tag verify failure, bad signature, RNG failure, etc. |
| **`StateError`** | API used in the wrong order or illegal protocol state. |

**`Result<T>`** is **`core::result::Result<T, Error>`**. With the **`std`** feature on **`noxtls-core`**, **`Error`** also implements **`std::error::Error`** for interoperability with host error handling.

**`Display`** prints the embedded static diagnostic string—safe to log at **high level**, but still avoid logging **payloads** or **secrets** alongside errors.

## Profiles and feature sets

**`Profile`** names coarse **product shapes** (default TLS client/server, crypto-only, and so on). Call **`profile.features()`** to obtain a **`FeatureSet`** of booleans (`tls12`, `tls13`, `dtls`, `cert`, `hash`, `encryption`, …) for documentation or runtime gating in your own code.

Which profile is active in a given binary is selected through **`noxtls-core`** Cargo **features** (`profile-default`, `profile-minimal-tls-client`, …). See [Build configuration](./build_config) and the [Configuration guide](../../configuration-guide).

## Library configuration and policy

From **`noxtls_core::config`** (re-exported at the **`noxtls_core`** crate root):

- **`LibraryConfig`** — bundles **`Profile`** with **`SecurityPolicy`**; **`LibraryConfig::compiled()`** builds the default configuration from **Cargo `cfg!(feature = …)`** policy flags and runs validation.
- **`SecurityPolicy`** — **`ConstantTimePolicy`** (`BestEffort` vs **`Strict`**), **`allow_legacy_algorithms`**, **`allow_sha1_signatures`**, derived from **`noxtls_compiled_strict_constant_time`**, **`noxtls_compiled_allow_legacy_algorithms`**, **`noxtls_compiled_allow_sha1_signatures`**.
- **`SecurityPolicy::validate`** — rejects incompatible combinations (for example **strict constant-time** together with legacy or SHA-1 policy flags); see **`noxtls-core`** `compile_error!` guards in `lib.rs` as well.

Use these when you need to **assert** or **log** what was compiled into firmware, or when writing tests that must respect the same policy matrix as production.

## Binary helpers

- **`noxtls_read_u16_be(input: &[u8]) -> Result<u16>`** — Reads the first **two** bytes as **big-endian** `u16`. Errors with **`InvalidLength`** if `input.len() < 2`.
- **`noxtls_read_u24_be(input: &[u8]) -> Result<u32>`** — Reads the first **three** bytes as a **24-bit big-endian** value in the low bits of **`u32`**. Errors if `input.len() < 3`.

These are intentionally minimal; TLS record parsers and similar code paths use them to avoid duplicating endian logic.

## `noxtls_secure_zero`

**`noxtls_secure_zero(data: &mut [u8])`** fills the slice with **zero bytes** in place so callers can shorten the lifetime of sensitive intermediates (password buffers, exported key material, copied nonces, etc.).

It is a **best-effort** clear: it does not by itself defeat all compiler optimizations or platform caching. For the strongest guarantees on a given CPU, combine with platform-specific **volatile** or **locked** memory APIs where your threat model requires them.

## Feature flags and policy

**`noxtls-core`** drives **compile-time** surface area:

- **`profile-*`** — bundle **`feature-hash`**, **`feature-tls`**, **`feature-cert`**, **`feature-dtls`**, etc.
- **`feature-*`** — fine-grained toggles; some combinations are **disallowed** with **`compile_error!`** (for example **`feature-tls`** without at least one TLS version feature, or **`feature-dtls`** without **`feature-tls`**).
- **`policy-*`** — security policy switches mirrored in **`SecurityPolicy::compiled()`**; incompatible pairs are rejected at **compile time** or by **`SecurityPolicy::validate`**.

Authoritative lists live in **`crates/noxtls-core/Cargo.toml`**. See [Build configuration](./build_config).

## Examples

### Parse a length prefix

```rust
use noxtls_core::{noxtls_read_u16_be, Result};

fn length_prefix(buf: &[u8]) -> Result<u16> {
    noxtls_read_u16_be(buf)
}
# fn main() { assert_eq!(length_prefix(&[0x00, 0x42]).unwrap(), 0x42); }
```

### Clear a sensitive buffer

```rust
use noxtls_core::noxtls_secure_zero;

fn consume_secret(mut key: [u8; 32]) {
    // ... use key ...
    noxtls_secure_zero(&mut key);
}
# fn main() { consume_secret([7u8; 32]); }
```

### Inspect compiled policy

```rust
use noxtls_core::{noxtls_compiled_strict_constant_time, LibraryConfig};

fn main() -> noxtls_core::Result<()> {
    let _strict = noxtls_compiled_strict_constant_time();
    let _cfg = LibraryConfig::compiled()?;
    Ok(())
}
```

### Map an error for logging

```rust
use noxtls_core::Error;

fn describe(err: &Error) -> &'static str {
    match err {
        Error::CryptoFailure(_) => "crypto",
        Error::InvalidLength(_) => "length",
        _ => "other",
    }
}
# fn main() {}
```

## Security and compatibility

- **Logging** — **`Error`** messages are static; still **never** append raw keys, PEM, or session secrets to log lines.
- **`noxtls_secure_zero`** — Use after you're finished with copies of key material; pair with good **key lifecycle** design (short-lived buffers, minimal copies).
- **Profiles** — Ship the **smallest** `noxtls-core` profile that meets your product needs; document the choice in your SBOM (see [Security](../../security)).

## Related

- [Core topic](./core)
- [Build configuration](./build_config)
- [Errors / return-code mapping](./return_codes)
