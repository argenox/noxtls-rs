---
title: Build configuration
---

# Build configuration

## Purpose

Cargo feature matrix equivalent to OEM build-config headers.

## Rust API

- **Crate:** `noxtls-core`
- **Module path (conceptual):** `noxtls_core::config`
- **Primary symbols:**
  - `LibraryConfig`
  - `noxtls_compiled_strict_constant_time`
  - `noxtls_compiled_allow_legacy_algorithms`

## Feature flags and policy

Configuration is **Cargo-driven**: each crate’s `[features]` in the repository is authoritative. High-level groupings:

### `noxtls` (TLS/DTLS application crate)

| Feature | Role |
| ------- | ---- |
| `std`, `alloc` (defaults) | Standard library and heap-backed buffers for typical host and RTOS builds. |
| `adapter-embedded-io` | Blocking `embedded-io` transport integration. |
| `adapter-embedded-io-async` | Async `embedded-io-async` integration. |
| `adapter-tokio` | Tokio-based async I/O for gateways and daemons. |
| `provider-psa` | Optional PSA-style crypto provider (`noxtls-psa`); use when offloading crypto to a HAL. |
| `provider-psa-test-export` | Test-only re-exports when `provider-psa` is enabled. |
| `hazardous-legacy-crypto` | Forwards to `noxtls-crypto`; enables **legacy** symmetric and PKC symbols (ECB, DES, RC4, some RSA/X448 paths, and similar). **Keep off** in production unless you have an explicit compatibility requirement. |

See `crates/noxtls/Cargo.toml`.

### `noxtls-core` (profiles, TLS surface, policy)

**Profiles** (pick at most one style for your product; default is `profile-default`):

- `profile-default` — TLS 1.2/1.3, DTLS, certs, hash, encryption, DRBG, PKC.
- `profile-minimal-tls-client` — Same TLS 1.2/1.3 client stack **without** DTLS.
- `profile-tls-server-pki` — Default server profile plus **`feature-cert-write`** for on-device issuance/rotation helpers.
- `profile-crypto-only` — Hash, symmetric, DRBG, PKC **without** TLS/DTLS or cert stack.
- `profile-fips-like` — Conservative TLS 1.2/1.3 + certs (no DTLS in the feature list).

Fine-grained **`feature-*`** toggles (`feature-tls12`, `feature-tls13`, `feature-dtls`, `feature-cert`, …) are defined in `crates/noxtls-core/Cargo.toml`; profiles are convenience bundles over those flags.

**Policy** (orthogonal to profiles):

- `policy-strict-constant-time` — Compile-time preference for strict constant-time behavior where implemented.
- `policy-allow-legacy-algorithms` — Allows legacy algorithm policy at runtime where the build supports it.
- `policy-allow-sha1-signatures` — Allows SHA-1 signature acceptance where the build supports it.

`SecurityPolicy::validate` rejects **strict constant-time** together with **`policy-allow-legacy-algorithms`** or **`policy-allow-sha1-signatures`** (see `noxtls_core::config`).

### `noxtls-crypto`

| Feature | Role |
| ------- | ---- |
| `std`, `alloc` (defaults) | Normal builds; `alloc` needed for many helpers returning `Vec`. |
| `hazardous-legacy-crypto` | Gates **ARIA/AES/Camellia ECB**, **DES**, **RC4**, and other explicitly hazardous entry points. |

See `crates/noxtls-crypto/Cargo.toml`.

### `noxtls-io`, `noxtls-psa`

`noxtls-io` mirrors `std` / `alloc` and optional **adapter-** features for embedded-io and Tokio (`crates/noxtls-io/Cargo.toml`). `noxtls-psa` uses `alloc` by default and optional `std` and `mbedtls-psa-ffi` (`crates/noxtls-psa/Cargo.toml`).

For device-oriented tables and recommendations, see the [Configuration guide](../../configuration-guide).

## Examples

Inspect what was compiled into the library using **`noxtls_core`** helpers (they reflect `cfg!(feature = ...)` for policy flags):

```rust
use noxtls_core::{
    noxtls_compiled_allow_legacy_algorithms, noxtls_compiled_allow_sha1_signatures,
    noxtls_compiled_strict_constant_time, LibraryConfig,
};

let strict_ct = noxtls_compiled_strict_constant_time();
let allow_legacy = noxtls_compiled_allow_legacy_algorithms();
let allow_sha1 = noxtls_compiled_allow_sha1_signatures();
let _ = (strict_ct, allow_legacy, allow_sha1);

let config = LibraryConfig::compiled()?;
assert_eq!(config.profile, noxtls_core::Profile::Default);
# Ok::<(), noxtls_core::Error>(())
```

Typical **`Cargo.toml`** fragment when you need a **smaller TLS client** profile on `noxtls-core` (Cargo **unifies** one `noxtls-core` build across dependents; add this on the crate that pulls `noxtls-core` in, or list it explicitly next to `noxtls`):

```toml
noxtls = { version = "0.2.1", default-features = false, features = ["std", "alloc"] }
noxtls-core = { version = "0.2.1", default-features = false, features = ["std", "alloc", "profile-minimal-tls-client"] }
```

Use `path = "…/crates/noxtls"` in a monorepo instead of `version` when appropriate. Enable `noxtls` adapter or `provider-psa` features only when your transport or HAL requires them.

## Security and compatibility

Record in your release notes and SBOM **which `noxtls-core` profile** and **`noxtls` / `noxtls-crypto` features** ship on each SKU. Treat **`hazardous-legacy-crypto`** as a **compatibility opt-in**, not a default: it widens the attack surface and must be justified per product. Prefer **`policy-strict-constant-time`** on devices that handle long-lived private keys, and avoid combining it with legacy or SHA-1 policy flags unless you understand the validation errors from `SecurityPolicy::validate`. For end-to-end guidance, use the [Configuration guide](../../configuration-guide) and [Security](../../security).

## Related

- [Configuration guide](../../configuration-guide)
- [Core topic](./core)
