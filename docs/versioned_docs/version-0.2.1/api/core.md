---
title: Core API (noxtls-core)
---

# Core API (`noxtls-core`)

`noxtls-core` defines shared error/result types, profile/feature policies, and low-level utility helpers used by all higher-level crates.

## Foundational types

- `Error` — common error enum for parse/state/crypto/config issues.
- `Result<T>` — alias for `core::result::Result<T, Error>`.
- `Profile` and `FeatureSet` — high-level build profile feature mapping.
- `LibraryConfig`, `SecurityPolicy`, `ConstantTimePolicy` — compile/runtime policy representation.

## Feature and profile APIs

```rust
pub fn noxtls_compiled_strict_constant_time() -> bool
pub fn noxtls_compiled_allow_legacy_algorithms() -> bool
pub fn noxtls_compiled_allow_sha1_signatures() -> bool
```

- Report compile-time policy flags to diagnostics/telemetry.

```rust
pub fn from_mbedtls_style_str(input: &str) -> Result<Self>
pub fn validate(self) -> Result<()>
```

- `from_mbedtls_style_str` parses textual policy/profile config into typed settings.
- `validate` enforces compatible policy combinations.

## Binary parsing and safety helpers

```rust
pub fn noxtls_read_u16_be(input: &[u8]) -> Result<u16>
pub fn noxtls_read_u24_be(input: &[u8]) -> Result<u32>
pub fn noxtls_secure_zero(data: &mut [u8])
```

- `noxtls_read_u16_be` / `noxtls_read_u24_be` are wire-format helpers with length checks.
- `noxtls_secure_zero` clears sensitive buffers in place.

## Usage guidance

- Use `Error` variants directly for consistent cross-crate diagnostics.
- Prefer profile/policy parsing through `LibraryConfig` paths over ad hoc env parsing.
- Use `noxtls_secure_zero` for temporary keying material in integration code.
